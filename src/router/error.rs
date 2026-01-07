use std::{error::Error, fmt};

use reticulum::error::RnsError;

/// Router-level errors.
#[derive(Debug)]
pub enum RouterError {
    MissingStoragePath,
    DuplicateDeliveryIdentity,
    StampCostOutOfRange(u32),
    InvalidHashLength { expected: usize, got: usize },
    RuntimeUnavailable(String),
    DispatchThreadPanicked,
    NoTransportAttached,
    Transport(RnsError),
    Io(std::io::Error),
    Serialization(String),
    Deserialization(String),
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterError::MissingStoragePath => write!(f, "Router requires a storage path"),
            RouterError::DuplicateDeliveryIdentity => {
                write!(
                    f,
                    "Only one delivery identity is supported per router instance"
                )
            }
            RouterError::StampCostOutOfRange(cost) => {
                write!(
                    f,
                    "Stamp cost {} is outside the supported 1-254 range",
                    cost
                )
            }
            RouterError::InvalidHashLength { expected, got } => write!(
                f,
                "Invalid hash length: expected {} bytes, got {} bytes",
                expected, got
            ),
            RouterError::RuntimeUnavailable(reason) => {
                write!(f, "Tokio runtime unavailable: {}", reason)
            }
            RouterError::DispatchThreadPanicked => {
                write!(f, "Outbound dispatch thread panicked")
            }
            RouterError::NoTransportAttached => {
                write!(f, "No Reticulum transport attached to router")
            }
            RouterError::Transport(err) => write!(f, "Transport error: {}", err),
            RouterError::Io(err) => write!(f, "I/O error: {}", err),
            RouterError::Serialization(err) => write!(f, "Serialization error: {}", err),
            RouterError::Deserialization(err) => write!(f, "Deserialization error: {}", err),
        }
    }
}

impl Error for RouterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RouterError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RouterError {
    fn from(err: std::io::Error) -> Self {
        RouterError::Io(err)
    }
}

impl From<rmp_serde::encode::Error> for RouterError {
    fn from(err: rmp_serde::encode::Error) -> Self {
        RouterError::Serialization(err.to_string())
    }
}

impl From<rmp_serde::decode::Error> for RouterError {
    fn from(err: rmp_serde::decode::Error) -> Self {
        RouterError::Deserialization(err.to_string())
    }
}
