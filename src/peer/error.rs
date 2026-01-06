use std::fmt;

/// Errors that can occur while serializing or operating on LXMF peers.
#[derive(Debug)]
pub enum PeerError {
    Serialization(String),
    Deserialization(String),
    InvalidFormat(String),
    MissingField(&'static str),
    AddressHashLength(usize),
    TransientIdLength(usize),
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerError::Serialization(err) => write!(f, "Serialization error: {}", err),
            PeerError::Deserialization(err) => write!(f, "Deserialization error: {}", err),
            PeerError::InvalidFormat(err) => write!(f, "Invalid peer format: {}", err),
            PeerError::MissingField(field) => write!(f, "Missing required field: {}", field),
            PeerError::AddressHashLength(len) => {
                write!(f, "Invalid address hash length: {} bytes", len)
            }
            PeerError::TransientIdLength(len) => {
                write!(f, "Invalid transient id length: {} bytes", len)
            }
        }
    }
}

impl std::error::Error for PeerError {}

impl From<rmp_serde::encode::Error> for PeerError {
    fn from(err: rmp_serde::encode::Error) -> Self {
        PeerError::Serialization(err.to_string())
    }
}

impl From<rmp_serde::decode::Error> for PeerError {
    fn from(err: rmp_serde::decode::Error) -> Self {
        PeerError::Deserialization(err.to_string())
    }
}
