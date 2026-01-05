use ed25519_dalek::SigningKey;
use lxmf::{LxMessage, DESTINATION_LENGTH};
use rand::rngs::OsRng;
use std::collections::HashMap;

#[test]
fn test_empty_message() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let destination_hash = [0xAAu8; DESTINATION_LENGTH];
    let source_hash = [0xBBu8; DESTINATION_LENGTH];

    let mut message = LxMessage::new(destination_hash, source_hash, vec![], vec![], None);

    let packed = message.pack(&signing_key).expect("Failed to pack message");
    let mut unpacked = LxMessage::unpack_from_bytes(&packed).expect("Failed to unpack message");

    assert!(
        unpacked
            .verify_signature(&verifying_key)
            .expect("Failed to verify"),
        "Signature verification failed"
    );
    assert_eq!(unpacked.content, vec![]);
    assert_eq!(unpacked.title, vec![]);
    assert_eq!(unpacked.fields.len(), 0);
}

#[test]
fn test_message_with_unicode() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let destination_hash = [0x01u8; DESTINATION_LENGTH];
    let source_hash = [0x02u8; DESTINATION_LENGTH];

    let content = "Hello 世界! 🌍";
    let title = "Unicode Test 测试";

    let mut message = LxMessage::new(
        destination_hash,
        source_hash,
        content.as_bytes().to_vec(),
        title.as_bytes().to_vec(),
        None,
    );

    let packed = message.pack(&signing_key).expect("Failed to pack message");
    let mut unpacked = LxMessage::unpack_from_bytes(&packed).expect("Failed to unpack message");

    assert!(
        unpacked
            .verify_signature(&verifying_key)
            .expect("Failed to verify"),
        "Signature verification failed"
    );
    assert_eq!(unpacked.content_as_string().unwrap(), content);
    assert_eq!(unpacked.title_as_string().unwrap(), title);
}

#[test]
fn test_message_with_multiple_fields() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let destination_hash = [0xCCu8; DESTINATION_LENGTH];
    let source_hash = [0xDDu8; DESTINATION_LENGTH];

    let mut fields = HashMap::new();
    fields.insert(0x01, b"field1".to_vec());
    fields.insert(0x02, b"field2".to_vec());
    fields.insert(0xFF, b"debug".to_vec());

    let mut message = LxMessage::new(
        destination_hash,
        source_hash,
        b"Content".to_vec(),
        b"Title".to_vec(),
        Some(fields.clone()),
    );

    let packed = message.pack(&signing_key).expect("Failed to pack message");
    let mut unpacked = LxMessage::unpack_from_bytes(&packed).expect("Failed to unpack message");

    assert!(
        unpacked
            .verify_signature(&verifying_key)
            .expect("Failed to verify"),
        "Signature verification failed"
    );
    assert_eq!(unpacked.fields.len(), 3);
    assert_eq!(unpacked.fields.get(&0x01).unwrap(), b"field1");
    assert_eq!(unpacked.fields.get(&0x02).unwrap(), b"field2");
    assert_eq!(unpacked.fields.get(&0xFF).unwrap(), b"debug");
}

#[test]
fn test_large_message() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let destination_hash = [0xEEu8; DESTINATION_LENGTH];
    let source_hash = [0xFFu8; DESTINATION_LENGTH];

    // Create a large content (10KB)
    let large_content = vec![0x42u8; 10 * 1024];
    let large_title = vec![0x54u8; 256];

    let mut message = LxMessage::new(
        destination_hash,
        source_hash,
        large_content.clone(),
        large_title.clone(),
        None,
    );

    let packed = message.pack(&signing_key).expect("Failed to pack message");
    let mut unpacked = LxMessage::unpack_from_bytes(&packed).expect("Failed to unpack message");

    assert!(
        unpacked
            .verify_signature(&verifying_key)
            .expect("Failed to verify"),
        "Signature verification failed"
    );
    assert_eq!(unpacked.content, large_content);
    assert_eq!(unpacked.title, large_title);
}

#[test]
fn test_message_id_consistency() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let destination_hash = [0x11u8; DESTINATION_LENGTH];
    let source_hash = [0x22u8; DESTINATION_LENGTH];

    let mut message1 = LxMessage::new(
        destination_hash,
        source_hash,
        b"Same content".to_vec(),
        b"Same title".to_vec(),
        None,
    );

    // Set the same timestamp for both messages to ensure consistent message ID
    let timestamp = 1234567890.0;
    message1.timestamp = timestamp;

    let _ = message1.pack(&signing_key).expect("Failed to pack message");
    let message_id1 = message1.message_id.unwrap();

    let mut message2 = LxMessage::new(
        destination_hash,
        source_hash,
        b"Same content".to_vec(),
        b"Same title".to_vec(),
        None,
    );
    message2.timestamp = timestamp;

    let _ = message2.pack(&signing_key).expect("Failed to pack message");
    let message_id2 = message2.message_id.unwrap();

    assert_eq!(
        message_id1, message_id2,
        "Message IDs should be identical for identical content"
    );
}

#[test]
fn test_invalid_signature_detection() {
    let mut csprng = OsRng;
    let signing_key1 = SigningKey::generate(&mut csprng);
    let signing_key2 = SigningKey::generate(&mut csprng);
    let verifying_key2 = signing_key2.verifying_key();

    let destination_hash = [0x33u8; DESTINATION_LENGTH];
    let source_hash = [0x44u8; DESTINATION_LENGTH];

    let mut message = LxMessage::new(
        destination_hash,
        source_hash,
        b"Content".to_vec(),
        b"Title".to_vec(),
        None,
    );

    // Pack with key1
    let packed = message.pack(&signing_key1).expect("Failed to pack message");

    // Try to verify with key2 (should fail)
    let mut unpacked = LxMessage::unpack_from_bytes(&packed).expect("Failed to unpack message");

    let is_valid = unpacked
        .verify_signature(&verifying_key2)
        .expect("Failed to verify");

    assert!(
        !is_valid,
        "Signature verification should fail with wrong key"
    );
}
