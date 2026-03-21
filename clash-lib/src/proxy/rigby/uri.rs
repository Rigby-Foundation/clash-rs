use std::str::FromStr;
use url::Url;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RigbyUri {
    pub host: String,
    pub port: u16,
    pub sni: Option<String>,
    pub udp: bool,
}

impl RigbyUri {
    pub fn parse(input: &str) -> Result<Self, Error> {
        let url = Url::parse(input)
            .map_err(|e| Error::InvalidConfig(format!("invalid rigby URI: {e}")))?;
        if url.scheme() != "rigby" {
            return Err(Error::InvalidConfig("rigby URI must start with rigby://".to_string()));
        }

        let host = url.host_str().ok_or_else(|| Error::InvalidConfig("missing host".to_string()))?.to_string();
        let port = url.port().ok_or_else(|| Error::InvalidConfig("missing port".to_string()))?;

        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let sni = query.get("sni").cloned().filter(|v| !v.trim().is_empty());
        let udp = query.get("udp").map(|v| v == "true" || v == "1").unwrap_or(true);

        Ok(Self { host, port, sni, udp })
    }
}

impl FromStr for RigbyUri {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::parse(s) }
}