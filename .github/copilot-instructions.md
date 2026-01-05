# GitHub Contributions Guide (lxmf-rs)

This document provides guidance for contributors and AI coding assistants (e.g. GitHub Copilot) working on **lxmf-rs**, a Rust reimplementation of the Python **LXMF** protocol.

The primary goals are:
- Protocol correctness vs the Python reference
- Idiomatic, safe Rust
- Clear modular structure
- Deterministic, testable behavior

---

## 1. Project Goal

`lxmf-rs` is a **Rust implementation of LXMF**, fully compatible with the Python reference implementation.

The Rust version must:
- Produce byte-identical protocol outputs where applicable
- Follow the same cryptographic, encoding, and message flow semantics
- Favor correctness and clarity over premature optimization

When in doubt, **match Python behavior exactly**.

---

## 2. Reference Implementation

The Python implementation is the **single source of truth**.

Before implementing or modifying functionality:
1. Locate the equivalent Python code
2. Understand data flow and edge cases
3. Replicate behavior faithfully in Rust

Comments may quote or paraphrase Python logic for clarity.

---

## 3. Code Style (Rust)

### General
- Use **stable Rust** only
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

---

## 4. Project Structure

Prefer small, focused modules.


---

## 5. Testing Requirements

Every protocol component must have tests.

### Tests should:
- Compare Rust output against known Python outputs
- Include malformed input cases
- Avoid network dependencies

---

## 6. Documentation

- Public structs, enums, and functions must have doc comments
- Document protocol fields with references to Python code
- Inline comments should explain *why*, not *what*

---

## 7. AI Coding Assistant Guidance

When generating code:
- Prefer clarity over cleverness
- Do not invent protocol behavior
- Do not guess message formats
- Insert TODOs when behavior is unclear
- Always assume the Python version is correct

---

## 8. Non-Goals

- Performance tuning before correctness
- Feature extensions not present in Python LXMF
- API stabilization before protocol parity

---

## 9. Contribution Checklist

Before submitting code:
- [ ] Behavior matches Python reference
- [ ] No `unwrap()` in non-test code
- [ ] Tests included
- [ ] Public APIs documented
- [ ] `cargo fmt` passes
- [ ] `cargo test` passes