# LXMF-rs

A Rust implementation of the [LXMF](https://github.com/markqvist/LXMF) (Lightweight Extensible Message Format) protocol, fully interoperable with the Python reference implementation.

Built on [Leviculum](https://codeberg.org/Lew_Palm/leviculum) — a Rust implementation of the [Reticulum](https://reticulum.network/) network stack.

## Status

**Working.** Both delivery paths are tested end-to-end against Python LXMF 0.9.4 / RNS 1.1.3:

| Delivery Path | Payload | Status |
|---|---|---|
| Single-packet (opportunistic/direct) | ≤ 400 bytes | ✅ Confirmed |
| Link + Resource transfer | Any size | ✅ Confirmed (tested at 10KB+) |

17 unit tests validate wire-compatibility with Python LXMF: message hashes, payload encoding, HKDF output, stamp generation/validation, and msgpack round-trips all produce byte-identical results.

## Architecture

```
┌─────────────────────────────────────────────┐
│                  LXMF-rs                     │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │ LXMessage│  │  Stamp   │  │   Peer    │  │
│  │  pack()  │  │  PoW     │  │ tracking  │  │
│  │ unpack() │  │ validate │  │           │  │
│  └────┬─────┘  └──────────┘  └───────────┘  │
│       │                                      │
│  ┌────┴──────────────────────────────────┐   │
│  │            LxmRouter                  │   │
│  │  • Auto-routing (size-based)          │   │
│  │  • Event-driven announce handling     │   │
│  │  • Inbound delivery + callbacks       │   │
│  │  • Outbound queue + retry             │   │
│  └────┬──────────────────────────────────┘   │
│       │                                      │
│  ┌────┴──────────────────────────────────┐   │
│  │          LxmfTransport                │   │
│  │  Wraps leviculum ReticulumNode        │   │
│  │  • Path discovery                     │   │
│  │  • Link establishment                 │   │
│  │  • Resource transfer                  │   │
│  │  • Single-packet delivery             │   │
│  └───────────────────────────────────────┘   │
│                                              │
└──────────────────┬───────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │  leviculum (RNS)    │
        │  reticulum-core     │
        │  reticulum-std      │
        └─────────────────────┘
```

## Quick Start

### Dependencies

- Rust (stable, edition 2024)
- Tokio async runtime

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Integration Test (Rust → Python)

Start a Python LXMF receiver:

```bash
pip install lxmf
python3 tests/integration/python_receiver.py --port 14965 --timeout 60
```

Send a single-packet message:

```bash
cargo run --example integration_test -- <dest_hash> --port 14965
```

Send a large message via Link + Resource:

```bash
cargo run --example router_delivery_test -- <dest_hash> --port 14965 --size 10000
```

## Module Overview

| Module | Description |
|---|---|
| `message/` | LXMessage packing/unpacking, payload encoding, stamp (PoW) system |
| `router/` | LxmRouter — message routing, announce handling, delivery callbacks |
| `transport.rs` | LxmfTransport — async wrapper around leviculum's ReticulumNode |
| `compat.rs` | Type compatibility layer (Hash, AddressHash, Identity wrappers) |
| `peer/` | Peer tracking for propagation node sync |

## Protocol Compatibility

LXMF-rs matches the Python LXMF wire format exactly:

- **Message hash**: `SHA-256(dest_hash + src_hash + msgpack(payload))`
- **Signature**: Ed25519 over `hashed_part + message_hash`
- **Packed format**: `dest_hash(16) + src_hash(16) + signature(64) + msgpack(payload)`
- **Stamp system**: HKDF-based proof-of-work with configurable cost
- **Delivery**: Single-packet for small messages, Link + Resource for large

## Reticulum Transport

LXMF-rs uses [Leviculum](https://codeberg.org/Lew_Palm/leviculum) for the Reticulum network stack:

- **reticulum-core**: `no_std` protocol implementation (identity, destination, link, resource, ratchets)
- **reticulum-std**: Tokio-based async runtime with TCP/UDP/Auto interfaces

The transport layer uses an event-driven architecture: `NodeEvent`s from leviculum are dispatched to the router's announce handlers, link management, and resource transfer logic.

## Examples

| Example | Description |
|---|---|
| `sender.rs` | Direct message sender to a known destination |
| `integration_test.rs` | Single-packet delivery test (Rust → Python) |
| `resource_test.rs` | Link + Resource transfer test (Rust → Python) |
| `router_delivery_test.rs` | Full router auto-routing test (size-based path selection) |

## License

[AGPL-3.0-or-later](LICENSE)

This project depends on Leviculum which is also AGPL-3.0-or-later.
