# GitHub Contributions Guide (lxmf-rs)

This document provides guidance for contributors and AI coding assistants (e.g. GitHub Copilot) working on **lxmf-rs**, a Rust implementation of the [LXMF](https://github.com/markqvist/LXMF) protocol.

## 1. Project Goal

`lxmf-rs` is a **Rust implementation of LXMF**, fully compatible with the Python reference implementation.

The Rust version must:
- Produce byte-identical protocol outputs where applicable
- Follow the same cryptographic, encoding, and message flow semantics
- Favor correctness and clarity over premature optimization

When in doubt, **match Python behavior exactly**.

## 2. Reticulum Transport

LXMF-rs uses [Leviculum](https://codeberg.org/Lew_Palm/leviculum) for the Reticulum network stack:

```toml
[dependencies]
reticulum-core = { git = "https://codeberg.org/Lew_Palm/leviculum.git" }
reticulum-std = { git = "https://codeberg.org/Lew_Palm/leviculum.git" }
```

### Key architecture decisions:
- **Event-driven transport**: The router consumes `NodeEvent`s from leviculum's `mpsc::Receiver<NodeEvent>` — no trait-based callbacks
- **Async runtime**: Tokio. Transport operations (`connect`, `send_resource`, `request_path`) are `async fn`
- **Size-based routing**: Messages ≤ 400 bytes use single-packet delivery; larger messages use Link + Resource transfer
- **Compatibility layer**: `src/compat.rs` provides beetchat-like type wrappers over leviculum types (Hash, AddressHash, Identity). Use leviculum types directly in new code when possible

### Transport types:
- `LxmfTransport` (src/transport.rs) — wraps `ReticulumNode`
- `LxmRouter` (src/router/router.rs) — LXMF message routing, owns the event loop
- `EventDispatcher` — coordinates async outbound delivery via oneshot channels

## 3. Reference Implementation

The Python implementation is the **single source of truth**.

Before implementing or modifying functionality:
1. Locate the equivalent Python code in [LXMF](https://github.com/markqvist/LXMF)
2. Understand data flow and edge cases
3. Replicate behavior faithfully in Rust

Key Python files:
- `LXMF/LXMessage.py` — message packing, unpacking, send logic
- `LXMF/LXMRouter.py` — router, delivery callbacks, announce handlers, propagation

## 4. Code Style (Rust)

### General
- Use **stable Rust** (edition 2024)
- Prefer explicit types over inference in public APIs
- Avoid `unwrap()` and `expect()` outside of tests
- Favor `Result<T, Error>` with domain-specific error enums

### Formatting
- `rustfmt` default settings
- Max line length ~100 chars
- One item per line in imports

### Naming
- `snake_case` for functions, modules, variables
- `CamelCase` for structs, enums, traits
- Protocol terms should mirror Python naming when possible

## 5. Project Structure

```
src/
├── lib.rs              # Public API re-exports
├── compat.rs           # Type compatibility layer (leviculum ↔ LXMF types)
├── transport.rs        # LxmfTransport (wraps ReticulumNode)
├── error.rs            # Top-level error types
├── message/
│   ├── message.rs      # LXMessage: pack, unpack, sign, verify
│   ├── payload.rs      # Payload encoding (msgpack)
│   ├── stamp.rs        # Proof-of-work stamp system (HKDF-based)
│   └── error.rs        # Message-specific errors
├── router/
│   ├── router.rs       # LxmRouter: event loop, outbound/inbound delivery
│   ├── handlers.rs     # Announce handler functions (delivery, propagation)
│   └── error.rs        # Router-specific errors
└── peer/
    ├── peer.rs         # Peer tracking for propagation sync
    └── error.rs        # Peer-specific errors
```

## 6. Protocol Details

### Message format (packed)
```
dest_hash (16 bytes) + src_hash (16 bytes) + signature (64 bytes) + msgpack(payload)
```

### Message hash
```
SHA-256(dest_hash + src_hash + msgpack(payload_without_stamp))
```

### Destination hash (RNS compatible)
```
truncated_hash(name_hash_10 + identity_hash_16)
  where name_hash_10 = SHA-256("app_name.aspects")[..10]   (NAME_HASHBYTES = 10)
  where identity_hash_16 = identity hash                    (16 bytes)
```

### Delivery paths
- **Single-packet**: `send_single_packet(dest_hash, packed[16..])` — strips dest_hash prefix
- **Link + Resource**: `connect() → send_resource(link_id, full_packed, None, true)` — sends full packed bytes

## 7. Testing Requirements

Every protocol component must have tests.

### Tests should:
- Compare Rust output against known Python outputs (byte-identical)
- Include malformed input cases
- Avoid network dependencies (unit tests)

### Integration tests:
- `tests/integration/python_receiver.py` — Python LXMF receiver for interop testing
- `tests/integration/rns_resource_receiver.py` — Raw RNS resource receiver
- Run with: `cargo run --example <name> -- <dest_hash> --port <port>`

## 8. AI Coding Assistant Guidance

When generating code:
- Prefer clarity over cleverness
- Do not invent protocol behavior — check Python source
- Do not guess message formats — verify against test vectors
- Use leviculum types directly in new transport code (not compat wrappers)
- Insert TODOs when behavior is unclear
- Always assume the Python version is correct
- Use `async fn` for anything touching `LxmfTransport`

## 9. Non-Goals

- Performance tuning before correctness
- Feature extensions not present in Python LXMF
- API stabilization before protocol parity
- Supporting multiple Reticulum backends (leviculum only)

## 10. Contribution Checklist

Before submitting code:
- [ ] Behavior matches Python reference
- [ ] No `unwrap()` in non-test code
- [ ] Tests included
- [ ] Public APIs documented
- [ ] `cargo fmt` passes
- [ ] `cargo test` passes (17 unit tests + examples compile)
- [ ] Integration test passes against Python LXMF if touching transport/router

## License

AGPL-3.0-or-later (matching Leviculum dependency)
