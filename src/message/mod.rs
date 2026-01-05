//! LXMF Message module
//!
//! This module provides the core types for LXMF (Lightweight Extensible Message Format) messages.
//!
//! # Overview
//!
//! The main types are:
//! - [`LXMessage`]: The core message container with destination, source, signature, and payload
//! - [`LxPayload`]: The message payload containing timestamp, title, content, and fields
//!
//! # Wire Format
//!
//! The wire format matches the Python LXMF reference implementation:
//! - Destination hash (16 bytes)
//! - Source hash (16 bytes)
//! - Ed25519 signature (64 bytes)
//! - MessagePack encoded payload (variable length)
//!
//! The payload is encoded as a MessagePack list: `[timestamp, title, content, fields]`
//!
//! # Example
//!
//! ```rust
//! use LXMF_rs::message::{LXMessage, LxPayload};
//! use ed25519_dalek::SigningKey;
//!
//! // Create a payload
//! let mut payload = LxPayload::with_current_time();
//! payload.set_title_from_string("Hello");
//! payload.set_content_from_string("This is a test message");
//!
//! // Create destination and source hashes (normally from Reticulum identities)
//! let destination = [0xAA; 16];
//! let source = [0xBB; 16];
//!
//! // Create and sign the message
//! let mut message = LXMessage::new(destination, source, payload);
//! let signing_key = SigningKey::from_bytes(&[0x42; 32]);
//! message.sign(&signing_key).unwrap();
//!
//! // Pack the message for transmission
//! let packed = message.pack().unwrap();
//!
//! // Unpack and verify
//! let mut unpacked = LXMessage::unpack(&packed).unwrap();
//! let verifying_key = signing_key.verifying_key();
//! assert!(unpacked.verify(&verifying_key).unwrap());
//! ```

mod lx_message;
mod lx_payload;

pub use lx_message::{LXMessage, LXMessageError, DESTINATION_LENGTH, SIGNATURE_LENGTH};
pub use lx_payload::LxPayload;

