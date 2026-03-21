use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};

use crate::{
    Error,
    config::internal::proxy::OutboundRigby,
    proxy::{
        HandlerCommonOptions,
        rigby::{Handler, HandlerOptions},
    },
};

fn decode_key32(raw: &str, field: &str) -> Result<[u8; 32], Error> {
    let text = raw.trim();
    let candidates = [
        URL_SAFE_NO_PAD.decode(text).ok(),
        URL_SAFE.decode(text).ok(),
        STANDARD_NO_PAD.decode(text).ok(),
        STANDARD.decode(text).ok(),
        hex::decode(text).ok(),
    ];

    for bytes in candidates.into_iter().flatten() {
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }

    Err(Error::InvalidConfig(format!(
        "{field} must be a 32-byte key encoded as base64/base64url/hex"
    )))
}

impl TryFrom<OutboundRigby> for Handler {
    type Error = Error;

    fn try_from(value: OutboundRigby) -> Result<Self, Self::Error> {
        tracing::error!("🐛 RIGBY CONVERTER: Attempting to create handler for {}", value.common_opts.name);
        tracing::error!("🐛 RIGBY CONVERTER: Server={}:{}, has_reality={}", 
            value.common_opts.server, value.common_opts.port, value.reality_public_key.is_some());
        
        tracing::error!("🐛 RIGBY CONVERTER: Step 1 - Decoding server static pubkey");
        let server_static_pubkey =
            decode_key32(&value.server_static_pubkey, "rigby server-static-pubkey")?;
        
        tracing::error!("🐛 RIGBY CONVERTER: Step 2 - Decoding client private key");
        let client_private_key = value
            .client_private_key
            .as_deref()
            .map(|v| decode_key32(v, "rigby client-private-key"))
            .transpose()?;
        
        tracing::error!("🐛 RIGBY CONVERTER: Step 3 - Decoding reality public key");
        // Parse Reality public key if provided
        let reality_public_key = value
            .reality_public_key
            .as_deref()
            .map(|v| decode_key32(v, "rigby reality-public-key"))
            .transpose()?;
        
        tracing::error!("🐛 RIGBY CONVERTER: Step 4 - Decoding reality short ID");
        // Parse Reality short ID if provided
        let reality_short_id = value
            .reality_short_id
            .as_deref()
            .map(|v| hex::decode(v).map_err(|_| 
                Error::InvalidConfig("rigby reality-short-id must be hex string".to_string())))
            .transpose()?;

        tracing::error!("🐛 RIGBY CONVERTER: Step 5 - Creating handler");
        Ok(Handler::new(HandlerOptions {
            name: value.common_opts.name.clone(),
            common_opts: HandlerCommonOptions {
                connector: value.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: value.common_opts.server,
            port: value.common_opts.port,
            server_static_pubkey,
            client_private_key,
            sni: value.sni,
            padding: value.padding,
            mux: value.mux,
            udp: value.udp,
            reality_public_key,
            reality_short_id,
            client_fingerprint: value.client_fingerprint,
            alpn: value.alpn,
        }));
        tracing::error!("🐛 RIGBY CONVERTER: SUCCESS - Handler created!");
        Ok(handler)
    }
}
