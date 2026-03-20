use self::stream::{VisionStream, VlessStream};
use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType,
    transport::Transport,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagramWrapper, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::vless::datagram::{OutboundDatagramVless, OutboundDatagramVlessXudp},
    session::Session,
};
use async_trait::async_trait;
use std::{io, sync::Arc};
use tracing::debug;
use crate::app::dispatcher::{ChainedDatagram, ChainedStream};

mod datagram;
mod stream;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub udp: bool,
    pub transport: Option<Box<dyn Transport>>,
    pub tls: Option<Box<dyn Transport>>,
    pub flow: Option<String>,
    pub xudp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vless").field("name", &self.opts.name).finish()
    }
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self { opts, connector: Default::default() }
    }

    async fn inner_proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        is_udp: bool,
        use_xudp: bool,
    ) -> io::Result<AnyStream> {
        let s = if let Some(tls) = self.opts.tls.as_ref() { tls.proxy_stream(s).await? } else { s };
        let s = if let Some(transport) = self.opts.transport.as_ref() { transport.proxy_stream(s).await? } else { s };

        let vless_stream = VlessStream::new(
            s,
            &self.opts.uuid,
            &sess.destination,
            is_udp,
            use_xudp,
            self.opts.flow.clone(),
        )?;

        if matches!(self.opts.flow.as_deref(), Some("xtls-rprx-vision" | "xtls-rprx-vision-udp443")) {
            Ok(Box::new(VisionStream::new(vless_stream)))
        } else {
            Ok(Box::new(vless_stream))
        }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str { &self.opts.name }
    fn proto(&self) -> OutboundType { OutboundType::Vless }
    async fn support_udp(&self) -> bool { self.opts.udp }

    async fn connect_stream(&self, sess: &Session, resolver: ThreadSafeDNSResolver) -> io::Result<BoxedChainedStream> {
        let dialer = self.connector.read().await;
        self.connect_stream_with_connector(sess, resolver, dialer.as_ref().unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone()).as_ref()).await
    }

    async fn connect_datagram(&self, sess: &Session, resolver: ThreadSafeDNSResolver) -> io::Result<BoxedChainedDatagram> {
        let dialer = self.connector.read().await;
        self.connect_datagram_with_connector(sess, resolver, dialer.as_ref().unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone()).as_ref()).await
    }

    async fn support_connector(&self) -> ConnectorType { ConnectorType::All }

    async fn connect_stream_with_connector(
        &self, sess: &Session, resolver: ThreadSafeDNSResolver, connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let stream = connector.connect_stream(resolver, &self.opts.server, self.opts.port, sess.iface.as_ref(), #[cfg(target_os = "linux")] sess.so_mark).await?;
        let s = self.inner_proxy_stream(stream, sess, false, false).await?;
        let chained = ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self, sess: &Session, resolver: ThreadSafeDNSResolver, connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let stream = connector.connect_stream(resolver, &self.opts.server, self.opts.port, sess.iface.as_ref(), #[cfg(target_os = "linux")] sess.so_mark).await?;
        let use_xudp = self.opts.xudp;
        let stream = self.inner_proxy_stream(stream, sess, true, use_xudp).await?;
        let d: crate::proxy::AnyOutboundDatagram = if use_xudp {
            Box::new(OutboundDatagramVlessXudp::new(stream, sess.destination.clone()))
        } else {
            Box::new(OutboundDatagramVless::new(stream, sess.destination.clone()))
        };
        let chained = ChainedDatagramWrapper::new(d);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}