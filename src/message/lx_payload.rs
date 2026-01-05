use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Payload structure for LXMF messages.
/// 
/// The payload is serialized as a msgpack list containing:
/// - Timestamp (f64, seconds since UNIX epoch)
/// - Title (optional, can be empty bytes)
/// - Content (optional, can be empty bytes)
/// - Fields (optional dictionary for metadata/attachments)
///
/// Python reference: LXMF/LXMessage.py - payload format in pack() method
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LxPayload {
    /// Timestamp in seconds since UNIX epoch (f64 for Python compatibility)
    pub timestamp: f64,
    
    /// Message title (e.g., email subject)
    #[serde(with = "serde_bytes")]
    pub title: Vec<u8>,
    
    /// Message content/body
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
    
    /// Additional structured data (attachments, metadata, etc.)
    pub fields: HashMap<String, Vec<u8>>,
}

impl LxPayload {
    /// Create a new payload with the given timestamp
    pub fn new(timestamp: f64) -> Self {
        Self {
            timestamp,
            title: Vec::new(),
            content: Vec::new(),
            fields: HashMap::new(),
        }
    }

    /// Create a new payload with current timestamp
    pub fn with_current_time() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs_f64();
        Self::new(timestamp)
    }

    /// Set title from string
    pub fn set_title_from_string(&mut self, title: &str) {
        self.title = title.as_bytes().to_vec();
    }

    /// Set title from bytes
    pub fn set_title_from_bytes(&mut self, title: &[u8]) {
        self.title = title.to_vec();
    }

    /// Get title as string (if valid UTF-8)
    pub fn title_as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.title.clone())
    }

    /// Set content from string
    pub fn set_content_from_string(&mut self, content: &str) {
        self.content = content.as_bytes().to_vec();
    }

    /// Set content from bytes
    pub fn set_content_from_bytes(&mut self, content: &[u8]) {
        self.content = content.to_vec();
    }

    /// Get content as string (if valid UTF-8)
    pub fn content_as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.content.clone())
    }

    /// Set a field value
    pub fn set_field(&mut self, key: String, value: Vec<u8>) {
        self.fields.insert(key, value);
    }

    /// Get a field value
    pub fn get_field(&self, key: &str) -> Option<&Vec<u8>> {
        self.fields.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_creation() {
        let payload = LxPayload::new(1234567890.0);
        assert_eq!(payload.timestamp, 1234567890.0);
        assert!(payload.title.is_empty());
        assert!(payload.content.is_empty());
        assert!(payload.fields.is_empty());
    }

    #[test]
    fn test_payload_with_current_time() {
        let payload = LxPayload::with_current_time();
        assert!(payload.timestamp > 0.0);
    }

    #[test]
    fn test_title_operations() {
        let mut payload = LxPayload::new(1234567890.0);
        payload.set_title_from_string("Test Title");
        assert_eq!(payload.title_as_string().unwrap(), "Test Title");
        
        payload.set_title_from_bytes(b"Binary Title");
        assert_eq!(payload.title, b"Binary Title");
    }

    #[test]
    fn test_content_operations() {
        let mut payload = LxPayload::new(1234567890.0);
        payload.set_content_from_string("Test Content");
        assert_eq!(payload.content_as_string().unwrap(), "Test Content");
        
        payload.set_content_from_bytes(b"Binary Content");
        assert_eq!(payload.content, b"Binary Content");
    }

    #[test]
    fn test_fields_operations() {
        let mut payload = LxPayload::new(1234567890.0);
        payload.set_field("key1".to_string(), b"value1".to_vec());
        payload.set_field("key2".to_string(), b"value2".to_vec());
        
        assert_eq!(payload.get_field("key1"), Some(&b"value1".to_vec()));
        assert_eq!(payload.get_field("key2"), Some(&b"value2".to_vec()));
        assert_eq!(payload.get_field("nonexistent"), None);
    }
}
