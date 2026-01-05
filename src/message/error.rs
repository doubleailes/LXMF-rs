use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum LXMessageError {
    /// Serialization error
    SerializationError(String),
    /// Deserialization error
    DeserializationError(String),
    /// Invalid signature
    InvalidSignature,
    /// Invalid message format
    InvalidFormat(String),
    /// Signing error
    SigningError(String),
}

impl fmt::Display for LXMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LXMessageError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            LXMessageError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            LXMessageError::InvalidSignature => write!(f, "Invalid signature"),
            LXMessageError::InvalidFormat(e) => write!(f, "Invalid format: {}", e),
            LXMessageError::SigningError(e) => write!(f, "Signing error: {}", e),
        }
    }
}

impl Error for LXMessageError {}
