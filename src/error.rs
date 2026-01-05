use thiserror::Error;

/// Result type alias for LXMF operations
pub type Result<T> = std::result::Result<T, LxmfError>;

/// Error types for LXMF operations
#[derive(Error, Debug)]
pub enum LxmfError {
    /// Invalid message format or structure
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Cryptographic operation error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Generic error
    #[error("{0}")]
    Other(String),
}
