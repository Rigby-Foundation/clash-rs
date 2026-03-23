mod uri;
pub use uri::RigbyUri;

use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    impl_default_connector,
    proxy::AnyOutboundDatagram,
    session::{Session, SocksAddr},
};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use quinn::{ClientConfig, Endpoint};
use std::{io, pin::Pin, sync::Arc, task::{Context, Poll}};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf, AsyncWriteExt}, sync::{Mutex, RwLock}};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[derive(Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub sni: Option<String>,
    pub udp: bool,
}

pub struct RigbyClientConnection {
    pub connection: quinn::Connection,
}

impl RigbyClientConnection {
    async fn connect(opts: HandlerOptions) -> io::Result<Self> {
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        crypto.alpn_protocols = vec![b"h3".to_vec()];

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| io::Error::other(e.to_string()))?;

        endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic_crypto)));

        let server_addr = format!("{}:{}", opts.server, opts.port).parse()
            .map_err(|e| io::Error::other(format!("Invalid address: {}", e)))?;

        let sni_str = opts.sni.unwrap_or_else(|| "www.google.com".to_string());

        tracing::info!("🚀 rigby: QUIC connecting to {} with SNI: {}", server_addr, sni_str);

        let connection = endpoint.connect(server_addr, &sni_str)
            .map_err(|e| io::Error::other(e.to_string()))?.await
            .map_err(|e| io::Error::other(e.to_string()))?;

        tracing::info!("✅ rigby: QUIC connection established!");
        Ok(Self { connection })
    }

    async fn open_stream(&self, target: SocksAddr) -> io::Result<AnyStream> {
        let (mut send, recv) = self.connection.open_bi().await.map_err(|e| io::Error::other(e.to_string()))?;
        let mut target_bytes = BytesMut::new();
        target.write_buf(&mut target_bytes);
        send.write_u16(target_bytes.len() as u16).await?;
        send.write_all(&target_bytes).await?;
        Ok(Box::new(QuicStream { send, recv }))
    }
}

pub struct QuicStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
impl AsyncWrite for QuicStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf).map_err(|e| io::Error::other(e.to_string()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx).map_err(|e| io::Error::other(e.to_string()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx).map_err(|e| io::Error::other(e.to_string()))
    }
}

pub struct Handler {
    opts: HandlerOptions,
    connector: RwLock<Option<Arc<dyn RemoteConnector>>>,
    conn: Mutex<Option<Arc<RigbyClientConnection>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rigby")
            .field("name", &self.opts.name)
            .field("server", &self.opts.server)
            .field("port", &self.opts.port)
            .finish()
    }
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
            conn: Mutex::new(None)
        }
    }

    async fn get_or_connect(&self) -> io::Result<Arc<RigbyClientConnection>> {
        let mut guard = self.conn.lock().await;
        if let Some(existing) = guard.as_ref() { return Ok(existing.clone()); }
        let conn = Arc::new(RigbyClientConnection::connect(self.opts.clone()).await?);
        *guard = Some(conn.clone());
        Ok(conn)
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str { &self.opts.name }
    fn proto(&self) -> OutboundType { OutboundType::Rigby }
    async fn support_udp(&self) -> bool { false }
    async fn support_connector(&self) -> ConnectorType { ConnectorType::All }

    async fn connect_stream(
        &self, sess: &Session, resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let dialer = self.connector.read().await;
        self.connect_stream_with_connector(sess, resolver, dialer.as_ref().unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone()).as_ref()).await
    }

    async fn connect_datagram(
        &self, sess: &Session, resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let dialer = self.connector.read().await;
        self.connect_datagram_with_connector(sess, resolver, dialer.as_ref().unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone()).as_ref()).await
    }

    async fn connect_stream_with_connector(
        &self, sess: &Session, _resolver: ThreadSafeDNSResolver, _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let conn = self.get_or_connect().await?;
        let stream = conn.open_stream(sess.destination.clone()).await?;
        let chained = ChainedStreamWrapper::new(stream);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self, _sess: &Session, _resolver: ThreadSafeDNSResolver, _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::other("UDP datagrams via QUIC not fully stubbed here yet"))
    }
}