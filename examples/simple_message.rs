use ed25519_dalek::SigningKey;
use lxmf::{LxMessage, DESTINATION_LENGTH, FIELD_DEBUG};
use rand::rngs::OsRng;
use std::collections::HashMap;

fn main() {
    println!("LXMF-rs Simple Message Example\n");

    // Generate keypairs for sender and receiver
    let mut csprng = OsRng;
    let sender_signing_key = SigningKey::generate(&mut csprng);
    let sender_verifying_key = sender_signing_key.verifying_key();

    // In a real application, these would be Reticulum identity hashes
    // For this example, we'll use dummy values
    let destination_hash = [0xAAu8; DESTINATION_LENGTH];
    let source_hash = [0xBBu8; DESTINATION_LENGTH];

    println!("Creating a simple LXMF message...");

    // Create a simple message
    let mut message = LxMessage::new(
        destination_hash,
        source_hash,
        b"This is a test message demonstrating LXMF-rs functionality.".to_vec(),
        b"Test Message".to_vec(),
        None,
    );

    println!("Title: {}", message.title_as_string().unwrap());
    println!("Content: {}", message.content_as_string().unwrap());

    // Pack and sign the message
    println!("\nPacking and signing message...");
    let packed = message
        .pack(&sender_signing_key)
        .expect("Failed to pack message");

    println!("Message packed successfully!");
    println!("Packed message size: {} bytes", packed.len());
    println!("Message ID: {}", hex::encode(message.message_id.unwrap()));

    // Simulate sending over network by unpacking
    println!("\nSimulating message transmission...");
    let mut received_message =
        LxMessage::unpack_from_bytes(&packed).expect("Failed to unpack message");

    println!("Message received and unpacked!");

    // Verify the signature
    println!("\nVerifying message signature...");
    let is_valid = received_message
        .verify_signature(&sender_verifying_key)
        .expect("Failed to verify signature");

    if is_valid {
        println!("✓ Signature is valid!");
    } else {
        println!("✗ Signature is invalid!");
    }

    // Display received message content
    println!("\nReceived message details:");
    println!("  Title: {}", received_message.title_as_string().unwrap());
    println!(
        "  Content: {}",
        received_message.content_as_string().unwrap()
    );
    println!("  Timestamp: {}", received_message.timestamp);

    // Example with custom fields
    println!("\n\nCreating a message with custom fields...");
    let mut fields = HashMap::new();
    fields.insert(FIELD_DEBUG, b"debug_data".to_vec());

    let mut message_with_fields = LxMessage::new(
        destination_hash,
        source_hash,
        b"Message with custom fields".to_vec(),
        b"Custom Fields Example".to_vec(),
        Some(fields),
    );

    let packed_with_fields = message_with_fields
        .pack(&sender_signing_key)
        .expect("Failed to pack message");

    println!(
        "Message with fields packed: {} bytes",
        packed_with_fields.len()
    );

    let mut received_with_fields =
        LxMessage::unpack_from_bytes(&packed_with_fields).expect("Failed to unpack message");

    let is_valid_2 = received_with_fields
        .verify_signature(&sender_verifying_key)
        .expect("Failed to verify signature");

    println!("Signature valid: {}", is_valid_2);
    println!(
        "Number of custom fields: {}",
        received_with_fields.fields.len()
    );

    if let Some(debug_data) = received_with_fields.fields.get(&FIELD_DEBUG) {
        println!(
            "Debug field content: {}",
            String::from_utf8_lossy(debug_data)
        );
    }

    println!("\nExample completed successfully!");
}
