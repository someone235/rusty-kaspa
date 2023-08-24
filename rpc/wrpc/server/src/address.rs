use crate::service::WrpcEncoding;
use kaspa_consensus_core::networktype::NetworkType;
use kaspa_utils::networking::ContextualNetAddress;
use std::{net::AddrParseError, str::FromStr};

#[derive(Clone, Debug)]
pub enum WrpcNetAddress {
    Default,
    Public,
    Custom(ContextualNetAddress),
}

impl WrpcNetAddress {
    pub fn to_address(&self, network_type: &NetworkType, encoding: &WrpcEncoding) -> ContextualNetAddress {
        match self {
            WrpcNetAddress::Default => {
                let port = match encoding {
                    WrpcEncoding::Borsh => network_type.default_borsh_rpc_port(),
                    WrpcEncoding::SerdeJson => network_type.default_borsh_rpc_port(),
                };
                format!("127.0.0.1:{port}").parse().unwrap()
            }
            WrpcNetAddress::Public => {
                let port = match encoding {
                    WrpcEncoding::Borsh => network_type.default_borsh_rpc_port(),
                    WrpcEncoding::SerdeJson => network_type.default_borsh_rpc_port(),
                };
                format!("0.0.0.0:{port}").parse().unwrap()
            }
            WrpcNetAddress::Custom(address) => *address,
        }
    }
}

impl FromStr for WrpcNetAddress {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" => Ok(WrpcNetAddress::Default),
            "public" => Ok(WrpcNetAddress::Public),
            _ => {
                let addr: ContextualNetAddress = s.parse()?;
                Ok(Self::Custom(addr))
            }
        }
    }
}
