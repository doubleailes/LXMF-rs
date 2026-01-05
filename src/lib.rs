//! # LXMF-rs
//!
//! A Rust implementation of LXMF (Lightweight Extensible Message Format),
//! fully compatible with the Python reference implementation.
//!
//! LXMF is a simple and flexible messaging format and delivery protocol built
//! on top of Reticulum. It provides zero-conf message routing, end-to-end
//! encryption, and Forward Secrecy.
//!
//! ## Message Structure
//!
//! An LXMF message consists of:
//! - **Destination Hash**: 16-byte Reticulum destination hash
//! - **Source Hash**: 16-byte Reticulum source hash
//! - **Signature**: 64-byte Ed25519 signature
//! - **Payload**: msgpack-encoded list containing:
//!   - Timestamp (f64, UNIX epoch seconds)
//!   - Title (bytes, optional but must be present)
//!   - Content (bytes, optional but must be present)
//!   - Fields (HashMap<u8, Vec<u8>>, optional but must be present)
//!
//! ## Example
//!
//! ```rust
//! use lxmf::{LxMessage, DESTINATION_LENGTH};
//! use ed25519_dalek::SigningKey;
//! use rand::rngs::OsRng;
//!
//! // Generate a keypair
//! let mut csprng = OsRng;
//! let signing_key = SigningKey::generate(&mut csprng);
//! let verifying_key = signing_key.verifying_key();
//!
//! // Create message with dummy hashes
//! let destination_hash = [0x01u8; DESTINATION_LENGTH];
//! let source_hash = [0x02u8; DESTINATION_LENGTH];
//!
//! let mut message = LxMessage::new(
//!     destination_hash,
//!     source_hash,
//!     b"Hello, LXMF!".to_vec(),
//!     b"Greeting".to_vec(),
//!     None,
//! );
//!
//! // Pack and sign the message
//! let packed = message.pack(&signing_key).expect("Failed to pack message");
//!
//! // Unpack and verify
//! let mut unpacked = LxMessage::unpack_from_bytes(&packed)
//!     .expect("Failed to unpack message");
//! let valid = unpacked.verify_signature(&verifying_key)
//!     .expect("Failed to verify signature");
//! assert!(valid);
//! ```

pub mod constants;
pub mod error;
pub mod message;

// Re-export commonly used types
pub use constants::*;
pub use error::{LxmfError, Result};
pub use message::{DeliveryMethod, LxMessage, MessageState, DESTINATION_LENGTH, SIGNATURE_LENGTH};
