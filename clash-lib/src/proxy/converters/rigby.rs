use crate::{
    Error,
    config::internal::proxy::OutboundRigby,
    proxy::{
        HandlerCommonOptions,
        rigby::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundRigby> for Handler {
    type Error = Error;

    fn try_from(value: OutboundRigby) -> Result<Self, Self::Error> {
        tracing::info!("🚀 RIGBY CONVERTER (QUIC Edition): Initializing {}", value.common_opts.name);

        Ok(Handler::new(HandlerOptions {
            name: value.common_opts.name.clone(),
            common_opts: HandlerCommonOptions {
                connector: value.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: value.common_opts.server,
            port: value.common_opts.port,
            sni: value.sni,
            udp: value.udp,
        }))
    }
}