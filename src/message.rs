use crate::error::{LxmfError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rmp_serde::{decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Length of destination/source hash in bytes (Reticulum truncated hash)
pub const DESTINATION_LENGTH: usize = 16;

/// Length of Ed25519 signature in bytes
pub const SIGNATURE_LENGTH: usize = 64;

/// Size of timestamp field in bytes
pub const TIMESTAMP_SIZE: usize = 8;

/// Overhead for msgpack structure
pub const STRUCT_OVERHEAD: usize = 8;

/// Total LXMF overhead per message
/// 16 bytes destination + 16 bytes source + 64 bytes signature + 8 bytes timestamp + 8 bytes msgpack structure
pub const LXMF_OVERHEAD: usize = 2 * DESTINATION_LENGTH + SIGNATURE_LENGTH + TIMESTAMP_SIZE + STRUCT_OVERHEAD;

/// Message delivery methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryMethod {
    /// Opportunistic delivery
    Opportunistic = 0x01,
    /// Direct delivery
    Direct = 0x02,
    /// Propagated delivery via propagation nodes
    Propagated = 0x03,
    /// Paper message (QR code/URI)
    Paper = 0x05,
}

/// Message state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageState {
    /// Message is being generated
    Generating = 0x00,
    /// Message is ready for sending
    Outbound = 0x01,
    /// Message is currently being sent
    Sending = 0x02,
    /// Message has been sent
    Sent = 0x04,
    /// Message has been delivered
    Delivered = 0x08,
    /// Message was rejected
    Rejected = 0xFD,
    /// Message sending was cancelled
    Cancelled = 0xFE,
    /// Message sending failed
    Failed = 0xFF,
}

/// LXMF message payload structure
/// This is the msgpack-serializable payload component
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessagePayload {
    /// Timestamp (UNIX epoch as f64)
    timestamp: f64,
    /// Message title (optional, can be empty bytes)
    title: Vec<u8>,
    /// Message content/body (optional, can be empty bytes)
    content: Vec<u8>,
    /// Additional fields dictionary (optional, can be empty)
    fields: HashMap<u8, Vec<u8>>,
}

/// An LXMF message
#[derive(Debug, Clone)]
pub struct LxMessage {
    /// Destination hash (16 bytes)
    pub destination_hash: [u8; DESTINATION_LENGTH],
    /// Source hash (16 bytes)
    pub source_hash: [u8; DESTINATION_LENGTH],
    /// Ed25519 signature (64 bytes)
    pub signature: Option<[u8; SIGNATURE_LENGTH]>,
    /// Message timestamp (seconds since UNIX epoch)
    pub timestamp: f64,
    /// Message title
    pub title: Vec<u8>,
    /// Message content
    pub content: Vec<u8>,
    /// Additional fields
    pub fields: HashMap<u8, Vec<u8>>,
    /// Message hash (SHA-256 of destination + source + packed payload)
    pub message_id: Option<[u8; 32]>,
    /// Current message state
    pub state: MessageState,
    /// Desired delivery method
    pub desired_method: Option<DeliveryMethod>,
    /// Packed/serialized form of the message
    packed: Option<Vec<u8>>,
    /// Original packed payload (for signature verification)
    packed_payload: Option<Vec<u8>>,
    /// Whether signature has been validated
    pub signature_validated: bool,
}

impl LxMessage {
    /// Create a new LXMF message
    pub fn new(
        destination_hash: [u8; DESTINATION_LENGTH],
        source_hash: [u8; DESTINATION_LENGTH],
        content: Vec<u8>,
        title: Vec<u8>,
        fields: Option<HashMap<u8, Vec<u8>>>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs_f64();

        Self {
            destination_hash,
            source_hash,
            signature: None,
            timestamp,
            title,
            content,
            fields: fields.unwrap_or_default(),
            message_id: None,
            state: MessageState::Generating,
            desired_method: Some(DeliveryMethod::Direct),
            packed: None,
            packed_payload: None,
            signature_validated: false,
        }
    }

    /// Pack the message and sign it
    pub fn pack(&mut self, signing_key: &SigningKey) -> Result<Vec<u8>> {
        // Create the payload structure
        let payload = MessagePayload {
            timestamp: self.timestamp,
            title: self.title.clone(),
            content: self.content.clone(),
            fields: self.fields.clone(),
        };

        // Serialize the payload with msgpack
        let packed_payload =
            encode::to_vec(&payload).map_err(|e| LxmfError::SerializationError(e.to_string()))?;

        // Store the packed payload for later verification
        self.packed_payload = Some(packed_payload.clone());

        // Calculate message hash: SHA-256(destination_hash + source_hash + packed_payload)
        let mut hashed_part = Vec::new();
        hashed_part.extend_from_slice(&self.destination_hash);
        hashed_part.extend_from_slice(&self.source_hash);
        hashed_part.extend_from_slice(&packed_payload);

        let mut hasher = Sha256::new();
        hasher.update(&hashed_part);
        let hash = hasher.finalize();
        let mut message_id = [0u8; 32];
        message_id.copy_from_slice(&hash);
        self.message_id = Some(message_id);

        // Sign: destination_hash + source_hash + packed_payload + message_id
        let mut signed_part = hashed_part.clone();
        signed_part.extend_from_slice(&message_id);

        let signature = signing_key.sign(&signed_part);
        let mut sig_bytes = [0u8; SIGNATURE_LENGTH];
        sig_bytes.copy_from_slice(&signature.to_bytes());
        self.signature = Some(sig_bytes);

        // Build the complete packed message:
        // destination_hash (16) + source_hash (16) + signature (64) + packed_payload
        let mut packed = Vec::new();
        packed.extend_from_slice(&self.destination_hash);
        packed.extend_from_slice(&self.source_hash);
        packed.extend_from_slice(&sig_bytes);
        packed.extend_from_slice(&packed_payload);

        self.packed = Some(packed.clone());
        self.state = MessageState::Outbound;
        self.signature_validated = true;

        Ok(packed)
    }

    /// Get the packed form of the message
    pub fn get_packed(&self) -> Option<&[u8]> {
        self.packed.as_deref()
    }

    /// Unpack an LXMF message from bytes
    pub fn unpack_from_bytes(data: &[u8]) -> Result<Self> {
        // Verify minimum length
        if data.len() < 2 * DESTINATION_LENGTH + SIGNATURE_LENGTH {
            return Err(LxmfError::InvalidMessage(
                "Message too short".to_string(),
            ));
        }

        // Extract components
        let destination_hash: [u8; DESTINATION_LENGTH] =
            data[0..DESTINATION_LENGTH].try_into().unwrap();
        let source_hash: [u8; DESTINATION_LENGTH] = data[DESTINATION_LENGTH..2 * DESTINATION_LENGTH]
            .try_into()
            .unwrap();
        let signature: [u8; SIGNATURE_LENGTH] =
            data[2 * DESTINATION_LENGTH..2 * DESTINATION_LENGTH + SIGNATURE_LENGTH]
                .try_into()
                .unwrap();
        let packed_payload = &data[2 * DESTINATION_LENGTH + SIGNATURE_LENGTH..];

        // Deserialize the payload
        let payload: MessagePayload = decode::from_slice(packed_payload)
            .map_err(|e| LxmfError::SerializationError(e.to_string()))?;

        // Calculate message hash
        let mut hashed_part = Vec::new();
        hashed_part.extend_from_slice(&destination_hash);
        hashed_part.extend_from_slice(&source_hash);
        hashed_part.extend_from_slice(packed_payload);

        let mut hasher = Sha256::new();
        hasher.update(&hashed_part);
        let hash = hasher.finalize();
        let mut message_id = [0u8; 32];
        message_id.copy_from_slice(&hash);

        Ok(Self {
            destination_hash,
            source_hash,
            signature: Some(signature),
            timestamp: payload.timestamp,
            title: payload.title,
            content: payload.content,
            fields: payload.fields,
            message_id: Some(message_id),
            state: MessageState::Outbound,
            desired_method: None,
            packed: Some(data.to_vec()),
            packed_payload: Some(packed_payload.to_vec()),
            signature_validated: false,
        })
    }

    /// Verify the message signature
    pub fn verify_signature(&mut self, verifying_key: &VerifyingKey) -> Result<bool> {
        let signature = self
            .signature
            .ok_or_else(|| LxmfError::InvalidMessage("No signature present".to_string()))?;

        let message_id = self
            .message_id
            .ok_or_else(|| LxmfError::InvalidMessage("No message ID present".to_string()))?;

        // Use the stored packed_payload if available (for unpacked messages)
        // Otherwise reconstruct it (for newly created messages)
        let packed_payload = if let Some(ref pp) = self.packed_payload {
            pp.clone()
        } else {
            let payload = MessagePayload {
                timestamp: self.timestamp,
                title: self.title.clone(),
                content: self.content.clone(),
                fields: self.fields.clone(),
            };
            encode::to_vec(&payload).map_err(|e| LxmfError::SerializationError(e.to_string()))?
        };

        // Reconstruct signed part: destination_hash + source_hash + packed_payload + message_id
        let mut signed_part = Vec::new();
        signed_part.extend_from_slice(&self.destination_hash);
        signed_part.extend_from_slice(&self.source_hash);
        signed_part.extend_from_slice(&packed_payload);
        signed_part.extend_from_slice(&message_id);

        let sig = Signature::from_bytes(&signature);
        match verifying_key.verify(&signed_part, &sig) {
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

    /// Get message content as a UTF-8 string, if possible
    pub fn content_as_string(&self) -> Option<String> {
        String::from_utf8(self.content.clone()).ok()
    }

    /// Get message title as a UTF-8 string, if possible
    pub fn title_as_string(&self) -> Option<String> {
        String::from_utf8(self.title.clone()).ok()
    }

    /// Set content from a string
    pub fn set_content(&mut self, content: &str) {
        self.content = content.as_bytes().to_vec();
    }

    /// Set title from a string
    pub fn set_title(&mut self, title: &str) {
        self.title = title.as_bytes().to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_message_pack_unpack() {
        // Generate keypair for testing
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Create source and destination hashes (normally these would be Reticulum identity hashes)
        let destination_hash = [0x01u8; DESTINATION_LENGTH];
        let source_hash = [0x02u8; DESTINATION_LENGTH];

        // Create message
        let mut message = LxMessage::new(
            destination_hash,
            source_hash,
            b"Hello, LXMF!".to_vec(),
            b"Test Message".to_vec(),
            None,
        );

        // Pack the message
        let packed = message.pack(&signing_key).expect("Failed to pack message");

        // Unpack the message
        let mut unpacked =
            LxMessage::unpack_from_bytes(&packed).expect("Failed to unpack message");

        // Verify signature
        let valid = unpacked
            .verify_signature(&verifying_key)
            .expect("Failed to verify signature");
        assert!(valid, "Signature verification failed");

        // Verify content matches
        assert_eq!(unpacked.content, b"Hello, LXMF!");
        assert_eq!(unpacked.title, b"Test Message");
        assert_eq!(unpacked.destination_hash, destination_hash);
        assert_eq!(unpacked.source_hash, source_hash);
    }

    #[test]
    fn test_message_with_fields() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let destination_hash = [0xAAu8; DESTINATION_LENGTH];
        let source_hash = [0xBBu8; DESTINATION_LENGTH];

        let mut fields = HashMap::new();
        fields.insert(0x01, b"field_value".to_vec());

        let mut message = LxMessage::new(
            destination_hash,
            source_hash,
            b"Content with fields".to_vec(),
            b"Title".to_vec(),
            Some(fields.clone()),
        );

        let packed = message.pack(&signing_key).expect("Failed to pack message");
        let mut unpacked =
            LxMessage::unpack_from_bytes(&packed).expect("Failed to unpack message");

        let valid = unpacked
            .verify_signature(&verifying_key)
            .expect("Failed to verify signature");
        assert!(valid, "Signature verification failed");

        assert_eq!(unpacked.fields, fields);
    }
}
