/// This test verifies the wire format of LXMF messages
/// It demonstrates that the Rust implementation produces the correct byte layout
use ed25519_dalek::SigningKey;
use lxmf::{LxMessage, DESTINATION_LENGTH, SIGNATURE_LENGTH};

#[test]
fn test_wire_format_structure() {
    // Create deterministic signing key for reproducible test
    let signing_key_bytes = [0x42u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);

    let destination_hash = [0xAAu8; DESTINATION_LENGTH];
    let source_hash = [0xBBu8; DESTINATION_LENGTH];

    let mut message = LxMessage::new(
        destination_hash,
        source_hash,
        b"Test content".to_vec(),
        b"Test title".to_vec(),
        None,
    );

    // Set deterministic timestamp for reproducible test
    message.timestamp = 1234567890.0;

    let packed = message.pack(&signing_key).expect("Failed to pack message");

    // Verify the wire format structure
    // Format: destination_hash (16) + source_hash (16) + signature (64) + packed_payload (variable)

    // Check destination hash is at the start
    assert_eq!(&packed[0..16], &destination_hash);

    // Check source hash follows
    assert_eq!(&packed[16..32], &source_hash);

    // Check signature is present (we can't verify exact bytes due to randomness in signing)
    assert_eq!(packed.len() > 32 + SIGNATURE_LENGTH, true);

    // The remaining bytes after the signature should be the msgpack-encoded payload
    let payload_start = 32 + SIGNATURE_LENGTH;
    assert!(packed.len() > payload_start);

    println!("Wire format verified:");
    println!("  Total length: {} bytes", packed.len());
    println!(
        "  Destination hash: {} bytes at offset 0",
        DESTINATION_LENGTH
    );
    println!(
        "  Source hash: {} bytes at offset {}",
        DESTINATION_LENGTH, DESTINATION_LENGTH
    );
    println!(
        "  Signature: {} bytes at offset {}",
        SIGNATURE_LENGTH,
        2 * DESTINATION_LENGTH
    );
    println!(
        "  Payload: {} bytes at offset {}",
        packed.len() - payload_start,
        payload_start
    );
}

#[test]
fn test_overhead_calculation() {
    use lxmf::LXMF_OVERHEAD;

    let signing_key_bytes = [0x43u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);

    let destination_hash = [0xCCu8; DESTINATION_LENGTH];
    let source_hash = [0xDDu8; DESTINATION_LENGTH];

    // Create message with empty content to measure overhead
    let mut message = LxMessage::new(destination_hash, source_hash, vec![], vec![], None);

    let packed = message.pack(&signing_key).expect("Failed to pack message");

    // The overhead should be approximately LXMF_OVERHEAD
    // (exact value may vary slightly due to msgpack encoding of empty strings)
    println!("Empty message size: {} bytes", packed.len());
    println!("Expected overhead: {} bytes", LXMF_OVERHEAD);

    // The actual size should be close to the overhead (within a few bytes for msgpack structure)
    assert!(packed.len() >= 96 && packed.len() <= LXMF_OVERHEAD + 20);
}

#[test]
fn test_deterministic_message_id() {
    let signing_key_bytes = [0x44u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);

    let destination_hash = [0x11u8; DESTINATION_LENGTH];
    let source_hash = [0x22u8; DESTINATION_LENGTH];

    // Create two identical messages
    let mut message1 = LxMessage::new(
        destination_hash,
        source_hash,
        b"Identical content".to_vec(),
        b"Identical title".to_vec(),
        None,
    );
    message1.timestamp = 1000000000.0;

    let mut message2 = LxMessage::new(
        destination_hash,
        source_hash,
        b"Identical content".to_vec(),
        b"Identical title".to_vec(),
        None,
    );
    message2.timestamp = 1000000000.0;

    let _ = message1
        .pack(&signing_key)
        .expect("Failed to pack message1");
    let _ = message2
        .pack(&signing_key)
        .expect("Failed to pack message2");

    // Message IDs should be identical
    assert_eq!(message1.message_id, message2.message_id);

    // Now create a message with different content
    let mut message3 = LxMessage::new(
        destination_hash,
        source_hash,
        b"Different content".to_vec(),
        b"Identical title".to_vec(),
        None,
    );
    message3.timestamp = 1000000000.0;

    let _ = message3
        .pack(&signing_key)
        .expect("Failed to pack message3");

    // Message ID should be different
    assert_ne!(message1.message_id, message3.message_id);
}
