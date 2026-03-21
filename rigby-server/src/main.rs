use clap::Parser;
use std::{net::SocketAddr, str::FromStr};
use base64::{engine::general_purpose, Engine as _};
use clash_lib::proxy::rigby::{RigbyServer, RigbyServerConfig};

/// Rigby Protocol Server with Reality TLS Steganography
#[derive(Parser)]
#[command(name = "rigby-server")]
#[command(about = "A rigby:3P protocol server that looks like Chrome HTTPS traffic")]
struct Args {
    /// Bind address and port (e.g., 0.0.0.0:8444)
    #[arg(short = 'b', long = "bind", default_value = "0.0.0.0:8444")]
    bind: String,

    /// Server private key (32 bytes, base64 encoded)
    #[arg(short = 's', long = "server-key")]
    server_key: Option<String>,

    /// Generate a new server key pair and exit
    #[arg(long = "generate-key")]
    generate_key: bool,

    /// Generate Reality TLS keys and exit
    #[arg(long = "generate-reality")]
    generate_reality: bool,

    /// Enable padding (default: true)
    #[arg(long = "padding", default_value = "true")]
    padding: bool,
}

fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    use rand::rngs::OsRng;
    let private_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public_key = x25519_dalek::PublicKey::from(&private_key);
    (private_key.to_bytes(), public_key.to_bytes())
}

fn generate_reality_config() -> (String, String) {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    // Generate Reality private/public keypair (also x25519)
    let (priv_key, pub_key) = generate_x25519_keypair();
    
    // Generate short ID (random hex string 2-16 chars)
    let short_id_len = rng.gen_range(8..=16);
    let short_id: String = (0..short_id_len)
        .map(|_| format!("{:x}", rng.gen::<u8>() & 0xf))
        .collect();
    
    let public_key_b64 = general_purpose::URL_SAFE_NO_PAD.encode(pub_key);
    let private_key_b64 = general_purpose::URL_SAFE_NO_PAD.encode(priv_key);
    
    println!("🔐 Generated Reality TLS Configuration:");
    println!();
    println!("Public Key (for clients):  {}", public_key_b64);
    println!("Private Key (for server):  {}", private_key_b64);
    println!("Short ID:                  {}", short_id);
    println!();
    println!("Client Reality URL:");
    println!("  rigby://RIGBY_PUBLIC_KEY@18.171.159.227:8444?reality_pk={}&reality_sid={}&fp=chrome&alpn=h2,http/1.1", 
             public_key_b64, short_id);
    println!();
    println!("Server Reality Config (save this):");
    println!("  reality_private_key: {}", private_key_b64);
    println!("  reality_short_id: {}", short_id);
    
    (public_key_b64, short_id)
}

fn decode_key(encoded: &str) -> Result<[u8; 32], String> {
    let candidates = [
        general_purpose::URL_SAFE_NO_PAD.decode(encoded).ok(),
        general_purpose::URL_SAFE.decode(encoded).ok(), 
        general_purpose::STANDARD_NO_PAD.decode(encoded).ok(),
        general_purpose::STANDARD.decode(encoded).ok(),
        hex::decode(encoded).ok(),
    ];

    for bytes in candidates.into_iter().flatten() {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
    }

    Err("Invalid key format. Must be 32-byte key encoded as base64/base64url/hex".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rigby_server=info".parse()?)
                .add_directive("clash_lib::proxy::rigby=debug".parse()?)
        )
        .init();

    if args.generate_key {
        let (private_key, public_key) = generate_x25519_keypair();
        let private_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&private_key);
        let public_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&public_key);
        
        println!("Generated Rigby Server Keypair:");
        println!("Private Key: {}", private_b64);
        println!("Public Key:  {}", public_b64);
        println!();
        println!("Server command:");
        println!("  rigby-server --server-key {}", private_b64);
        println!();
        println!("Client URI:");
        println!("  rigby://{}@18.171.159.227:8444", public_b64);
        return Ok(());
    }

    if args.generate_reality {
        generate_reality_config();
        return Ok(());
    }

    let server_key = args.server_key
        .as_deref()
        .ok_or("Server key required. Use --generate-key to create one.")?;
    
    let private_key = decode_key(server_key)
        .map_err(|e| format!("Invalid server key: {}", e))?;

    let bind_addr = SocketAddr::from_str(&args.bind)
        .map_err(|e| format!("Invalid bind address '{}': {}", args.bind, e))?;

    let config = RigbyServerConfig {
        bind_addr,
        server_static_private_key: private_key,
        padding: args.padding,
    };

    let public_key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
    let public_b64 = general_purpose::URL_SAFE_NO_PAD.encode(public_key.to_bytes());

    println!("🐱 Starting Rigby Server (rigby:3P)");
    println!("Bind Address: {}", bind_addr);
    println!("Public Key:   {}", public_b64);
    println!("Padding:      {}", args.padding);
    println!();
    println!("Client URI:   rigby://{}@{}:{}", 
        public_b64, 
        bind_addr.ip(),
        bind_addr.port()
    );
    println!();
    println!("Server ready! Listening for Reality-masked UDP traffic...");

    let server = RigbyServer::new(config);
    server.run().await?;

    Ok(())
}