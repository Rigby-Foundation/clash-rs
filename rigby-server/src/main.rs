use clap::Parser;
use quinn::{Endpoint, ServerConfig};
use std::{net::SocketAddr, sync::Arc};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

// Новые импорты для rustls 0.23
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Parser)]
#[command(name = "rigby-server", about = "Rigby Protocol QUIC Server (h3 stealth)")]
struct Args {
    #[arg(short = 'b', long = "bind", default_value = "0.0.0.0:8444")]
    bind: String,

    #[arg(long = "sni", default_value = "www.google.com")]
    sni: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let cert = rcgen::generate_simple_self_signed(vec![args.sni.clone()])?;

    // Адаптация под rustls 0.23 (pki_types)
    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let priv_key = PrivateKeyDer::try_from(cert.serialize_private_key_der()).unwrap();

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.into_owned()], priv_key)?;

    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let bind_addr: SocketAddr = args.bind.parse()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;

    println!("🛡️ Rigby QUIC Server listening on {} (SNI: {})", bind_addr, args.sni);

    while let Some(conn) = endpoint.accept().await {
        tokio::spawn(async move {
            let connection = match conn.await {
                Ok(c) => c,
                Err(e) => { tracing::error!("Connection failed: {}", e); return; }
            };
            tracing::info!("✅ Client connected!");

            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                tokio::spawn(async move {
                    let target_len = match recv.read_u16().await {
                        Ok(l) => l as usize,
                        Err(_) => return,
                    };
                    let mut target_buf = vec![0u8; target_len];
                    if recv.read_exact(&mut target_buf).await.is_err() { return; }

                    let target_str = String::from_utf8_lossy(&target_buf[1..target_len-2]);
                    let port = u16::from_be_bytes([target_buf[target_len-2], target_buf[target_len-1]]);
                    let target = format!("{}:{}", target_str, port);

                    tracing::info!("🔗 Proxying to: {}", target);

                    if let Ok(mut upstream) = TcpStream::connect(&target).await {
                        let (mut up_read, mut up_write) = upstream.split();
                        let _ = tokio::try_join!(
                            tokio::io::copy(&mut recv, &mut up_write),
                            tokio::io::copy(&mut up_read, &mut send)
                        );
                    }
                });
            }
        });
    }
    Ok(())
}