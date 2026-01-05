# LXMF-rs

A Rust implementation of LXMF (Lightweight Extensible Message Format), fully compatible with the Python reference implementation.

## Overview

LXMF is a simple and flexible messaging format for use over [Reticulum](https://github.com/markqvist/Reticulum) networks. This Rust implementation provides the core message types and wire format encoding/decoding.

## Features

- ✅ **LXMessage**: Core message container with destination, source, signature, and payload
- ✅ **Wire format compatibility**: Produces byte-identical protocol outputs matching Python LXMF
- ✅ **Message ID computation**: SHA-256 hash over destination, source, and payload
- ✅ **Ed25519 signatures**: Sign and verify messages using Ed25519 cryptography
- ✅ **MessagePack encoding**: Efficient binary serialization using MessagePack

## Usage

```rust
use LXMF_rs::{LXMessage, LxPayload};
use ed25519_dalek::SigningKey;

// Create a payload
let mut payload = LxPayload::with_current_time();
payload.set_title_from_string("Hello");
payload.set_content_from_string("This is a test message");

// Create destination and source hashes (normally from Reticulum identities)
let destination = [0xAA; 16];
let source = [0xBB; 16];

// Create and sign the message
let mut message = LXMessage::new(destination, source, payload);
let signing_key = SigningKey::from_bytes(&[0x42; 32]);
message.sign(&signing_key).unwrap();

// Pack the message for transmission
let packed = message.pack().unwrap();

// Unpack and verify
let mut unpacked = LXMessage::unpack(&packed).unwrap();
let verifying_key = signing_key.verifying_key();
assert!(unpacked.verify(&verifying_key).unwrap());
```

## Wire Format

The wire format matches the Python LXMF reference implementation:

- **Destination hash** (16 bytes)
- **Source hash** (16 bytes)
- **Ed25519 signature** (64 bytes)
- **MessagePack payload** (variable length)

The payload is encoded as a MessagePack list: `[timestamp, title, content, fields]`

## Implementation Status

- [x] LXMessage core type with encode/decode
- [x] Message ID computation (SHA-256)
- [x] Ed25519 signature generation and verification
- [x] Wire format pack/unpack
- [ ] Propagation stamps
- [ ] Delivery receipts
- [ ] Message state management
- [ ] Router integration

## Reference

This implementation follows the [Python LXMF reference](https://github.com/markqvist/LXMF) to ensure protocol compatibility.

## License

See LICENSE file.

