# LXMF-rs

A Rust implementation of LXMF (Lightweight Extensible Message Format), fully compatible with the Python reference implementation.

## About LXMF

LXMF is a simple and flexible messaging format and delivery protocol that allows a wide variety of implementations, while using as little bandwidth as possible. It is built on top of [Reticulum](https://reticulum.network) and offers zero-conf message routing, end-to-end encryption and Forward Secrecy.

This Rust implementation aims to:
- Produce byte-identical protocol outputs where applicable
- Follow the same cryptographic, encoding, and message flow semantics as the Python reference
- Favor correctness and clarity over premature optimization
- Maintain full compatibility with the Python LXMF implementation

## Message Structure

An LXMF message consists of:

- **Destination Hash**: 16-byte Reticulum destination hash
- **Source Hash**: 16-byte Reticulum source hash  
- **Ed25519 Signature**: 64-byte signature over the message components
- **Payload**: msgpack-encoded list containing:
  - **Timestamp**: Double-precision floating point (UNIX epoch seconds)
  - **Title**: Optional title (bytes, can be empty)
  - **Content**: Optional message body (bytes, can be empty)
  - **Fields**: Optional dictionary for metadata (HashMap<u8, Vec<u8>>, can be empty)

The message-id is a SHA-256 hash of Destination + Source + Payload.

Total message overhead is **112 bytes** (16 + 16 + 64 + 8 + 8).

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
lxmf = "0.1.0"
```

## Usage

```rust
use lxmf::{LxMessage, DESTINATION_LENGTH};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

// Generate a keypair
let mut csprng = OsRng;
let signing_key = SigningKey::generate(&mut csprng);
let verifying_key = signing_key.verifying_key();

// Create message (in real usage, these would be Reticulum identity hashes)
let destination_hash = [0x01u8; DESTINATION_LENGTH];
let source_hash = [0x02u8; DESTINATION_LENGTH];

let mut message = LxMessage::new(
    destination_hash,
    source_hash,
    b"Hello, LXMF!".to_vec(),
    b"Greeting".to_vec(),
    None,
);

// Pack and sign the message
let packed = message.pack(&signing_key).expect("Failed to pack message");

// Unpack and verify
let mut unpacked = LxMessage::unpack_from_bytes(&packed)
    .expect("Failed to unpack message");
let valid = unpacked.verify_signature(&verifying_key)
    .expect("Failed to verify signature");

assert!(valid);
println!("Content: {}", unpacked.content_as_string().unwrap());
```

## Examples

Run the included example:

```bash
cargo run --example simple_message
```

## Testing

Run the test suite:

```bash
cargo test
```

## Features

- ✅ Core message structure (Destination, Source, Signature, Payload)
- ✅ MessagePack serialization/deserialization
- ✅ Ed25519 signature generation and verification
- ✅ SHA-256 message ID calculation
- ✅ Custom field support
- ✅ Byte-identical packing with Python reference implementation

## Compatibility

This implementation follows the [Python LXMF reference implementation](https://github.com/markqvist/LXMF) and produces compatible message formats. Messages packed by this library can be unpacked by the Python implementation and vice versa (when using the same cryptographic keys and identity hashes).

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please ensure that any changes maintain compatibility with the Python reference implementation.
