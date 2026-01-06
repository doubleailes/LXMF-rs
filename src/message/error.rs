use std::fmt;

#[derive(Debug)]
pub enum MessageError {
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
    /// Destination data missing
    MissingDestination,
    /// Source data missing
    MissingSource,
    /// Underlying IO issue
    Io(std::io::Error),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            MessageError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            MessageError::InvalidSignature => write!(f, "Invalid signature"),
            MessageError::InvalidFormat(e) => write!(f, "Invalid format: {}", e),
            MessageError::SigningError(e) => write!(f, "Signing error: {}", e),
            MessageError::MissingDestination => write!(f, "Destination is not configured"),
            MessageError::MissingSource => write!(f, "Source is not configured"),
            MessageError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for MessageError {}

impl From<std::io::Error> for MessageError {
    fn from(value: std::io::Error) -> Self {
        MessageError::Io(value)
    }
}
