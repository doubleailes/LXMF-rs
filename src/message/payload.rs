use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

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
    pub title: Vec<u8>,

    /// Message content/body
    pub content: Vec<u8>,

    /// Additional structured data (attachments, metadata, etc.)
    pub fields: IndexMap<String, Vec<u8>>,
}

impl LxPayload {
    /// Create a new payload with the given timestamp
    pub fn new(timestamp: f64, title: String, content: String) -> Self {
        Self {
            timestamp,
            title: title.into_bytes(),
            content: content.into_bytes(),
            fields: IndexMap::new(),
        }
    }
    pub fn new_now(title: String, content: String) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs_f64();
        Self {
            timestamp,
            title: title.into_bytes(),
            content: content.into_bytes(),
            fields: IndexMap::new(),
        }
    }

    /// Construct a payload from fully specified components.
    pub fn from_parts(
        timestamp: f64,
        title: Vec<u8>,
        content: Vec<u8>,
        fields: IndexMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            timestamp,
            title,
            content,
            fields,
        }
    }

    /// Create a new payload with current timestamp
    pub fn with_current_time(&mut self) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs_f64();
        self.timestamp = timestamp;
        self.clone()
    }

    /// Set title from string
    pub fn set_title_from_string(&mut self, title: String) {
        self.title = title.into_bytes();
    }

    /// Set title from bytes
    pub fn set_title_from_bytes(&mut self, title: Vec<u8>) {
        self.title = title;
    }

    /// Get title as string (if valid UTF-8)
    pub fn title_as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.title.clone())
    }

    /// Set content from string
    pub fn set_content_from_string(&mut self, content: String) {
        self.content = content.into_bytes();
    }

    /// Set content from bytes
    pub fn set_content_from_bytes(&mut self, content: Vec<u8>) {
        self.content = content;
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
        let payload = LxPayload::new(1234567890.0, String::new(), String::new());
        assert_eq!(payload.timestamp, 1234567890.0);
        assert!(payload.title.is_empty());
        assert!(payload.content.is_empty());
        assert!(payload.fields.is_empty());
    }

    #[test]
    fn test_payload_with_current_time() {
        let mut payload = LxPayload::new(0.0, String::new(), String::new());
        let payload = payload.with_current_time();
        assert!(payload.timestamp > 0.0);
    }

    #[test]
    fn test_title_operations() {
        let mut payload = LxPayload::new(1234567890.0, String::new(), String::new());
        payload.set_title_from_string("Test Title".to_string());
        assert_eq!(payload.title_as_string().unwrap(), "Test Title");

        payload.set_title_from_bytes(b"Binary Title".to_vec());
        assert_eq!(payload.title, b"Binary Title".to_vec());
    }

    #[test]
    fn test_content_operations() {
        let mut payload = LxPayload::new(1234567890.0, String::new(), String::new());
        payload.set_content_from_string("Test Content".to_string());
        assert_eq!(payload.content_as_string().unwrap(), "Test Content");

        payload.set_content_from_bytes(b"Binary Content".to_vec());
        assert_eq!(payload.content, b"Binary Content".to_vec());
    }

    #[test]
    fn test_fields_operations() {
        let mut payload = LxPayload::new(1234567890.0, String::new(), String::new());
        payload.set_field("key1".to_string(), b"value1".to_vec());
        payload.set_field("key2".to_string(), b"value2".to_vec());

        assert_eq!(payload.get_field("key1"), Some(&b"value1".to_vec()));
        assert_eq!(payload.get_field("key2"), Some(&b"value2".to_vec()));
        assert_eq!(payload.get_field("nonexistent"), None);
    }
}
