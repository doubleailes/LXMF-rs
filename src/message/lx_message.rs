use crate::message::LxPayload;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;

/// Size constants matching Python LXMF implementation
pub const DESTINATION_LENGTH: usize = 16; // RNS.Identity.TRUNCATED_HASHLENGTH//8
pub const SIGNATURE_LENGTH: usize = 64;   // RNS.Identity.SIGLENGTH//8

/// Errors that can occur during LXMessage operations
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

/// LXMessage is the core LXMF message container.
/// 
/// Wire format (matching Python LXMF):
/// - Destination hash (16 bytes)
/// - Source hash (16 bytes)  
/// - Ed25519 signature (64 bytes)
/// - Msgpacked payload (variable length)
///
/// The payload is a msgpack list: [timestamp, title, content, fields]
///
/// Message-id is computed as SHA-256(destination + source + msgpack(payload))
///
/// Signature is Ed25519 over: destination + source + msgpack(payload) + message-id
///
/// Python reference: LXMF/LXMessage.py
#[derive(Debug, Clone)]
pub struct LXMessage {
    /// Destination hash (16 bytes)
    pub destination_hash: [u8; DESTINATION_LENGTH],
    
    /// Source hash (16 bytes)
    pub source_hash: [u8; DESTINATION_LENGTH],
    
    /// Ed25519 signature (64 bytes)
    pub signature: [u8; SIGNATURE_LENGTH],
    
    /// Message payload
    pub payload: LxPayload,
    
    /// Cached message ID (SHA-256 hash)
    message_id: Option<[u8; 32]>,
    
    /// Whether signature has been validated
    signature_validated: bool,
}

impl LXMessage {
    /// Create a new LXMessage
    pub fn new(
        destination_hash: [u8; DESTINATION_LENGTH],
        source_hash: [u8; DESTINATION_LENGTH],
        payload: LxPayload,
    ) -> Self {
        Self {
            destination_hash,
            source_hash,
            signature: [0u8; SIGNATURE_LENGTH],
            payload,
            message_id: None,
            signature_validated: false,
        }
    }

    /// Compute the message ID
    /// 
    /// Python reference: LXMessage.pack() - computes hash as:
    /// ```python
    /// hashed_part = destination.hash + source.hash + msgpack.packb(payload)
    /// self.hash = RNS.Identity.full_hash(hashed_part)
    /// self.message_id = self.hash
    /// ```
    pub fn compute_message_id(&self) -> Result<[u8; 32], LXMessageError> {
        let mut hasher = Sha256::new();
        
        // Hash destination
        hasher.update(&self.destination_hash);
        
        // Hash source
        hasher.update(&self.source_hash);
        
        // Hash msgpacked payload
        // The payload must be serialized as a tuple/list: [timestamp, title, content, fields]
        let payload_tuple = (
            self.payload.timestamp,
            &self.payload.title,
            &self.payload.content,
            &self.payload.fields,
        );
        
        let packed_payload = rmp_serde::to_vec(&payload_tuple)
            .map_err(|e| LXMessageError::SerializationError(e.to_string()))?;
        
        hasher.update(&packed_payload);
        
        let result = hasher.finalize();
        let mut message_id = [0u8; 32];
        message_id.copy_from_slice(&result);
        
        Ok(message_id)
    }

    /// Get the message ID, computing it if necessary
    pub fn message_id(&mut self) -> Result<[u8; 32], LXMessageError> {
        if let Some(id) = self.message_id {
            Ok(id)
        } else {
            let id = self.compute_message_id()?;
            self.message_id = Some(id);
            Ok(id)
        }
    }

    /// Sign the message with a signing key
    /// 
    /// Python reference: LXMessage.pack() - signs:
    /// ```python
    /// signed_part = hashed_part + self.hash
    /// self.signature = self.__source.sign(signed_part)
    /// ```
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), LXMessageError> {
        // Compute message ID first
        let message_id = self.message_id()?;
        
        // Build signed part: destination + source + msgpacked_payload + message_id
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&self.destination_hash);
        signed_data.extend_from_slice(&self.source_hash);
        
        let payload_tuple = (
            self.payload.timestamp,
            &self.payload.title,
            &self.payload.content,
            &self.payload.fields,
        );
        
        let packed_payload = rmp_serde::to_vec(&payload_tuple)
            .map_err(|e| LXMessageError::SerializationError(e.to_string()))?;
        
        signed_data.extend_from_slice(&packed_payload);
        signed_data.extend_from_slice(&message_id);
        
        // Sign the data
        let signature = signing_key.sign(&signed_data);
        self.signature.copy_from_slice(&signature.to_bytes());
        self.signature_validated = true;
        
        Ok(())
    }

    /// Verify the message signature
    /// 
    /// Python reference: Similar to signing, verifies the same signed_part
    pub fn verify(&mut self, verifying_key: &VerifyingKey) -> Result<bool, LXMessageError> {
        // Compute message ID
        let message_id = self.message_id()?;
        
        // Build signed part
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&self.destination_hash);
        signed_data.extend_from_slice(&self.source_hash);
        
        let payload_tuple = (
            self.payload.timestamp,
            &self.payload.title,
            &self.payload.content,
            &self.payload.fields,
        );
        
        let packed_payload = rmp_serde::to_vec(&payload_tuple)
            .map_err(|e| LXMessageError::SerializationError(e.to_string()))?;
        
        signed_data.extend_from_slice(&packed_payload);
        signed_data.extend_from_slice(&message_id);
        
        // Parse signature
        let signature = Signature::from_bytes(&self.signature);
        
        // Verify signature
        match verifying_key.verify(&signed_data, &signature) {
            Ok(_) => {
                self.signature_validated = true;
                Ok(true)
            }
            Err(_) => {
                self.signature_validated = false;
                Ok(false)
            }
        }
    }

    /// Pack the message into wire format
    /// 
    /// Wire format:
    /// - Destination hash (16 bytes)
    /// - Source hash (16 bytes)
    /// - Signature (64 bytes)
    /// - Msgpacked payload (variable)
    pub fn pack(&self) -> Result<Vec<u8>, LXMessageError> {
        let mut packed = Vec::new();
        
        // Add destination hash
        packed.extend_from_slice(&self.destination_hash);
        
        // Add source hash
        packed.extend_from_slice(&self.source_hash);
        
        // Add signature
        packed.extend_from_slice(&self.signature);
        
        // Pack and add payload as tuple: [timestamp, title, content, fields]
        let payload_tuple = (
            self.payload.timestamp,
            &self.payload.title,
            &self.payload.content,
            &self.payload.fields,
        );
        
        let packed_payload = rmp_serde::to_vec(&payload_tuple)
            .map_err(|e| LXMessageError::SerializationError(e.to_string()))?;
        
        packed.extend_from_slice(&packed_payload);
        
        Ok(packed)
    }

    /// Unpack a message from wire format
    /// 
    /// Python reference: LXMessage would be unpacked by parsing the wire format
    pub fn unpack(data: &[u8]) -> Result<Self, LXMessageError> {
        // Check minimum length
        let min_len = DESTINATION_LENGTH + DESTINATION_LENGTH + SIGNATURE_LENGTH;
        if data.len() < min_len {
            return Err(LXMessageError::InvalidFormat(format!(
                "Data too short: {} bytes, need at least {}",
                data.len(),
                min_len
            )));
        }
        
        // Extract destination hash
        let mut destination_hash = [0u8; DESTINATION_LENGTH];
        destination_hash.copy_from_slice(&data[0..DESTINATION_LENGTH]);
        
        // Extract source hash
        let mut source_hash = [0u8; DESTINATION_LENGTH];
        source_hash.copy_from_slice(&data[DESTINATION_LENGTH..DESTINATION_LENGTH * 2]);
        
        // Extract signature
        let mut signature = [0u8; SIGNATURE_LENGTH];
        let sig_start = DESTINATION_LENGTH * 2;
        let sig_end = sig_start + SIGNATURE_LENGTH;
        signature.copy_from_slice(&data[sig_start..sig_end]);
        
        // Unpack payload
        let payload_data = &data[sig_end..];
        let payload_tuple: (f64, Vec<u8>, Vec<u8>, std::collections::HashMap<String, Vec<u8>>) =
            rmp_serde::from_slice(payload_data)
                .map_err(|e| LXMessageError::DeserializationError(e.to_string()))?;
        
        let payload = LxPayload {
            timestamp: payload_tuple.0,
            title: payload_tuple.1,
            content: payload_tuple.2,
            fields: payload_tuple.3,
        };
        
        Ok(Self {
            destination_hash,
            source_hash,
            signature,
            payload,
            message_id: None,
            signature_validated: false,
        })
    }

    /// Check if signature has been validated
    pub fn is_signature_validated(&self) -> bool {
        self.signature_validated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let dest = [1u8; DESTINATION_LENGTH];
        let src = [2u8; DESTINATION_LENGTH];
        let payload = LxPayload::new(1234567890.0);
        
        let msg = LXMessage::new(dest, src, payload);
        assert_eq!(msg.destination_hash, dest);
        assert_eq!(msg.source_hash, src);
        assert!(!msg.is_signature_validated());
    }

    #[test]
    fn test_message_id_computation() {
        let dest = [1u8; DESTINATION_LENGTH];
        let src = [2u8; DESTINATION_LENGTH];
        let mut payload = LxPayload::new(1234567890.0);
        payload.set_content_from_string("Test content");
        
        let mut msg = LXMessage::new(dest, src, payload);
        let msg_id = msg.message_id().unwrap();
        
        // Message ID should be deterministic
        let msg_id2 = msg.message_id().unwrap();
        assert_eq!(msg_id, msg_id2);
        
        // Message ID should be 32 bytes (SHA-256)
        assert_eq!(msg_id.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let dest = [1u8; DESTINATION_LENGTH];
        let src = [2u8; DESTINATION_LENGTH];
        let mut payload = LxPayload::new(1234567890.0);
        payload.set_content_from_string("Test content");
        
        let mut msg = LXMessage::new(dest, src, payload);
        
        // Generate a key pair
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        
        // Sign the message
        msg.sign(&signing_key).unwrap();
        assert!(msg.is_signature_validated());
        
        // Verify the signature
        let is_valid = msg.verify(&verifying_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let dest = [1u8; DESTINATION_LENGTH];
        let src = [2u8; DESTINATION_LENGTH];
        let mut payload = LxPayload::new(1234567890.0);
        payload.set_title_from_string("Test Title");
        payload.set_content_from_string("Test content");
        payload.set_field("key1".to_string(), b"value1".to_vec());
        
        let mut msg = LXMessage::new(dest, src, payload.clone());
        
        // Sign the message
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        msg.sign(&signing_key).unwrap();
        
        // Pack the message
        let packed = msg.pack().unwrap();
        
        // Unpack the message
        let mut unpacked = LXMessage::unpack(&packed).unwrap();
        
        // Verify all fields match
        assert_eq!(unpacked.destination_hash, dest);
        assert_eq!(unpacked.source_hash, src);
        assert_eq!(unpacked.signature, msg.signature);
        assert_eq!(unpacked.payload.timestamp, payload.timestamp);
        assert_eq!(unpacked.payload.title, payload.title);
        assert_eq!(unpacked.payload.content, payload.content);
        assert_eq!(unpacked.payload.fields, payload.fields);
        
        // Verify signature
        let verifying_key = signing_key.verifying_key();
        let is_valid = unpacked.verify(&verifying_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let dest = [1u8; DESTINATION_LENGTH];
        let src = [2u8; DESTINATION_LENGTH];
        let mut payload = LxPayload::new(1234567890.0);
        payload.set_content_from_string("Test content");
        
        let mut msg = LXMessage::new(dest, src, payload);
        
        // Sign with one key
        let signing_key1 = SigningKey::from_bytes(&[42u8; 32]);
        msg.sign(&signing_key1).unwrap();
        
        // Try to verify with different key
        let signing_key2 = SigningKey::from_bytes(&[99u8; 32]);
        let verifying_key2 = signing_key2.verifying_key();
        
        let is_valid = msg.verify(&verifying_key2).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_unpack_invalid_data() {
        let short_data = vec![0u8; 10];
        let result = LXMessage::unpack(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_wire_format_structure() {
        // This test verifies the wire format matches Python LXMF specification
        let dest = [0xAA; DESTINATION_LENGTH];
        let src = [0xBB; DESTINATION_LENGTH];
        let mut payload = LxPayload::new(1234567890.5);
        payload.set_title_from_string("Subject");
        payload.set_content_from_string("Message body");
        
        let mut msg = LXMessage::new(dest, src, payload);
        
        let signing_key = SigningKey::from_bytes(&[0xCC; 32]);
        msg.sign(&signing_key).unwrap();
        
        let packed = msg.pack().unwrap();
        
        // Verify wire format structure:
        // First 16 bytes: destination hash
        assert_eq!(&packed[0..16], &dest);
        
        // Next 16 bytes: source hash
        assert_eq!(&packed[16..32], &src);
        
        // Next 64 bytes: signature
        assert_eq!(&packed[32..96], &msg.signature);
        
        // Remaining bytes: msgpack payload
        // The payload should be decodable as [timestamp, title, content, fields]
        let payload_bytes = &packed[96..];
        let decoded: (f64, Vec<u8>, Vec<u8>, std::collections::HashMap<String, Vec<u8>>) =
            rmp_serde::from_slice(payload_bytes).unwrap();
        
        assert_eq!(decoded.0, 1234567890.5);
        assert_eq!(decoded.1, b"Subject");
        assert_eq!(decoded.2, b"Message body");
        assert!(decoded.3.is_empty());
    }

    #[test]
    fn test_message_id_determinism() {
        // Message ID should be deterministic for same inputs
        let dest = [0x11; DESTINATION_LENGTH];
        let src = [0x22; DESTINATION_LENGTH];
        let mut payload1 = LxPayload::new(1234567890.0);
        payload1.set_content_from_string("Test");
        
        let mut msg1 = LXMessage::new(dest, src, payload1.clone());
        let mut msg2 = LXMessage::new(dest, src, payload1);
        
        let id1 = msg1.message_id().unwrap();
        let id2 = msg2.message_id().unwrap();
        
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_empty_payload_fields() {
        // Test with all optional fields empty (as per Python behavior)
        let dest = [0xFF; DESTINATION_LENGTH];
        let src = [0xEE; DESTINATION_LENGTH];
        let payload = LxPayload::new(9999999.0);
        
        let mut msg = LXMessage::new(dest, src, payload);
        
        let signing_key = SigningKey::from_bytes(&[0x77; 32]);
        msg.sign(&signing_key).unwrap();
        
        // Pack and unpack
        let packed = msg.pack().unwrap();
        let mut unpacked = LXMessage::unpack(&packed).unwrap();
        
        // Verify empty fields are preserved
        assert!(unpacked.payload.title.is_empty());
        assert!(unpacked.payload.content.is_empty());
        assert!(unpacked.payload.fields.is_empty());
        
        // Signature should still be valid
        let verifying_key = signing_key.verifying_key();
        assert!(unpacked.verify(&verifying_key).unwrap());
    }

    #[test]
    fn test_message_with_fields() {
        // Test with complex fields structure
        let dest = [0x33; DESTINATION_LENGTH];
        let src = [0x44; DESTINATION_LENGTH];
        let mut payload = LxPayload::new(1111111.0);
        payload.set_content_from_string("Message with attachments");
        payload.set_field("attachment1".to_string(), b"file data 1".to_vec());
        payload.set_field("attachment2".to_string(), b"file data 2".to_vec());
        payload.set_field("metadata".to_string(), b"some metadata".to_vec());
        
        let mut msg = LXMessage::new(dest, src, payload.clone());
        
        let signing_key = SigningKey::from_bytes(&[0x55; 32]);
        msg.sign(&signing_key).unwrap();
        
        // Pack and unpack
        let packed = msg.pack().unwrap();
        let unpacked = LXMessage::unpack(&packed).unwrap();
        
        // Verify fields are preserved
        assert_eq!(unpacked.payload.fields.len(), 3);
        assert_eq!(unpacked.payload.get_field("attachment1"), Some(&b"file data 1".to_vec()));
        assert_eq!(unpacked.payload.get_field("attachment2"), Some(&b"file data 2".to_vec()));
        assert_eq!(unpacked.payload.get_field("metadata"), Some(&b"some metadata".to_vec()));
    }
}
