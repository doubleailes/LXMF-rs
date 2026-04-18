//! Compatibility layer: beetchat API surface → leviculum types.
//!
//! This module provides thin wrappers that mirror the beetchat Reticulum-rs
//! API so the rest of the LXMF crate can migrate incrementally.

use std::fmt;

use sha2::{Digest, Sha256};

// ── Constants ────────────────────────────────────────────────────────

pub const HASH_SIZE: usize = 32;
pub const ADDRESS_HASH_SIZE: usize = 16;

// ── Hash (32-byte SHA-256 wrapper) ───────────────────────────────────

/// A 32-byte SHA-256 hash, API-compatible with beetchat `reticulum::hash::Hash`.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    /// Return a bare SHA-256 hasher (same as beetchat `Hash::generator()`).
    pub fn generator() -> Sha256 {
        Sha256::new()
    }

    /// Wrap an existing 32-byte array.
    pub const fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create an all-zero hash.
    pub const fn new_empty() -> Self {
        Self([0u8; HASH_SIZE])
    }

    /// Compute SHA-256 of `data` and return the result.
    ///
    /// **CRITICAL**: this *hashes* `data`, it does NOT copy bytes.
    /// Matches beetchat `Hash::new_from_slice` and leviculum `full_hash`.
    pub fn new_from_slice(data: &[u8]) -> Self {
        Self(reticulum_core::crypto::full_hash(data))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; HASH_SIZE] {
        self.0
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// ── AddressHash (16-byte truncated hash) ─────────────────────────────

/// A 16-byte truncated address hash, API-compatible with beetchat
/// `reticulum::hash::AddressHash`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash)]
pub struct AddressHash([u8; ADDRESS_HASH_SIZE]);

impl AddressHash {
    pub const fn new(bytes: [u8; ADDRESS_HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn new_empty() -> Self {
        Self([0u8; ADDRESS_HASH_SIZE])
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let full = reticulum_core::crypto::full_hash(data);
        let mut truncated = [0u8; ADDRESS_HASH_SIZE];
        truncated.copy_from_slice(&full[..ADDRESS_HASH_SIZE]);
        Self(truncated)
    }

    pub fn new_from_hash(hash: &Hash) -> Self {
        let mut truncated = [0u8; ADDRESS_HASH_SIZE];
        truncated.copy_from_slice(&hash.0[..ADDRESS_HASH_SIZE]);
        Self(truncated)
    }

    pub fn new_from_hex_string(hex_string: &str) -> Result<Self, RnsError> {
        if hex_string.len() < ADDRESS_HASH_SIZE * 2 {
            return Err(RnsError::IncorrectHash);
        }
        let mut bytes = [0u8; ADDRESS_HASH_SIZE];
        for i in 0..ADDRESS_HASH_SIZE {
            bytes[i] = u8::from_str_radix(&hex_string[i * 2..(i * 2) + 2], 16)
                .map_err(|_| RnsError::IncorrectHash)?;
        }
        Ok(Self(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub const fn len(&self) -> usize {
        ADDRESS_HASH_SIZE
    }

    pub fn to_hex_string(&self) -> String {
        let mut s = String::with_capacity(ADDRESS_HASH_SIZE * 2);
        for byte in &self.0 {
            // fmt::Write for String is infallible, but we avoid unwrap()
            // by using the `_` discard pattern instead.
            use fmt::Write;
            let _ = write!(&mut s, "{:02x}", byte);
        }
        s
    }
}

impl From<Hash> for AddressHash {
    fn from(hash: Hash) -> Self {
        Self::new_from_hash(&hash)
    }
}

impl fmt::Display for AddressHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "/")
    }
}

// ── Identity (public-only) ───────────────────────────────────────────

/// Public-only identity wrapper.  Mirrors beetchat `reticulum::identity::Identity`.
#[derive(Clone)]
pub struct Identity {
    inner: reticulum_core::Identity,
}

impl Identity {
    pub fn from_leviculum(inner: reticulum_core::Identity) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &reticulum_core::Identity {
        &self.inner
    }

    /// Verify `signature` over `data`.
    pub fn verify(
        &self,
        data: &[u8],
        signature: &ed25519_dalek::Signature,
    ) -> Result<(), RnsError> {
        let sig_bytes = signature.to_bytes();
        match self.inner.verify(data, &sig_bytes) {
            Ok(true) => Ok(()),
            _ => Err(RnsError::IncorrectSignature),
        }
    }

    /// Get the 16-byte identity/address hash.
    pub fn address_hash(&self) -> AddressHash {
        AddressHash::new(*self.inner.hash())
    }
}

// ── PrivateIdentity (has signing keys) ───────────────────────────────

/// Identity with private keys.  Mirrors beetchat `reticulum::identity::PrivateIdentity`.
#[derive(Clone)]
pub struct PrivateIdentity {
    inner: reticulum_core::Identity,
}

impl PrivateIdentity {
    pub fn from_leviculum(inner: reticulum_core::Identity) -> Result<Self, RnsError> {
        if !inner.has_private_keys() {
            return Err(RnsError::CryptoError);
        }
        Ok(Self { inner })
    }

    /// Deterministic identity derived from a name (matches beetchat `new_from_name`).
    pub fn new_from_name(name: &str) -> Self {
        // beetchat derives keys deterministically: SHA-256(name) → seed → keys.
        // It uses a deterministic RNG seeded from the hash. We replicate exactly
        // by seeding a ChaCha12Rng from the hash and using Identity::generate.
        let seed = reticulum_core::crypto::full_hash(name.as_bytes());
        use rand_chacha::ChaCha12Rng;
        use rand_core::SeedableRng;
        let mut rng = ChaCha12Rng::from_seed(seed);
        let identity = reticulum_core::Identity::generate(&mut rng);
        Self { inner: identity }
    }

    /// Random identity.
    pub fn new_from_rand<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        Self {
            inner: reticulum_core::Identity::generate(rng),
        }
    }

    /// Get the public-only view.
    pub fn as_identity(&self) -> Result<Identity, RnsError> {
        // Create a public-only copy
        let pub_bytes = self.inner.public_key_bytes();
        let pub_identity = reticulum_core::Identity::from_public_key_bytes(&pub_bytes)
            .map_err(|_| RnsError::CryptoError)?;
        Ok(Identity {
            inner: pub_identity,
        })
    }

    /// Sign `data` and return an ed25519_dalek `Signature`.
    pub fn sign(&self, data: &[u8]) -> Result<ed25519_dalek::Signature, RnsError> {
        let sig_bytes = self.inner.sign(data).map_err(|_| RnsError::CryptoError)?;
        Ok(ed25519_dalek::Signature::from_bytes(&sig_bytes))
    }

    pub fn verify(
        &self,
        data: &[u8],
        signature: &ed25519_dalek::Signature,
    ) -> Result<(), RnsError> {
        let sig_bytes = signature.to_bytes();
        match self.inner.verify(data, &sig_bytes) {
            Ok(true) => Ok(()),
            _ => Err(RnsError::IncorrectSignature),
        }
    }

    /// Get the underlying leviculum Identity.
    pub fn inner(&self) -> &reticulum_core::Identity {
        &self.inner
    }
}

// ── DestinationName ──────────────────────────────────────────────────

/// Simple (app_name, aspects) pair, mirrors beetchat `DestinationName`.
#[derive(Debug, Clone)]
pub struct DestinationName {
    pub app_name: String,
    pub aspects: String,
}

impl DestinationName {
    pub fn new(app_name: &str, aspects: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            aspects: aspects.to_string(),
        }
    }

    /// Full dot-separated name (e.g. "lxmf.delivery").
    pub fn full_name(&self) -> String {
        format!("{}.{}", self.app_name, self.aspects)
    }
}

// ── Destination descriptors ──────────────────────────────────────────

/// Mirrors the `desc` sub-struct that beetchat destinations expose.
pub struct DestinationDesc {
    pub address_hash: AddressHash,
}

/// Mirrors beetchat `SingleInputDestination` (private identity + destination name).
pub struct SingleInputDestination {
    pub identity: PrivateIdentity,
    pub name: DestinationName,
    pub desc: DestinationDesc,
}

impl SingleInputDestination {
    pub fn new(identity: PrivateIdentity, name: DestinationName) -> Self {
        // as_identity() can only fail if the public key bytes are invalid,
        // which should never happen for a valid PrivateIdentity.
        let pub_identity = identity
            .as_identity()
            .expect("PrivateIdentity should always yield valid public keys");
        let address_hash = compute_destination_hash(&pub_identity, &name);
        Self {
            identity,
            name,
            desc: DestinationDesc { address_hash },
        }
    }

    /// Low-level announce on a `SingleInputDestination`.
    ///
    /// Transport-level announcing is handled by `LxmRouter::announce()` which
    /// delegates to the attached `LxmfTransport`. This method remains as a
    /// standalone packet-generation stub for cases where a destination wants
    /// to produce an announce outside of the router/transport stack.
    ///
    /// TODO: Wire this to `LxmfTransport::announce_destination()` or remove
    /// in favour of the router-level announce exclusively.
    pub fn announce<R: rand_core::CryptoRngCore + Copy>(
        &mut self,
        _rng: R,
        _app_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, RnsError> {
        Err(RnsError::NotImplemented)
    }
}

/// Mirrors beetchat `SingleOutputDestination` (public identity + destination name).
pub struct SingleOutputDestination {
    pub identity: Identity,
    pub name: DestinationName,
    pub desc: DestinationDesc,
}

impl SingleOutputDestination {
    pub fn new(identity: Identity, name: DestinationName) -> Self {
        let address_hash = compute_destination_hash(&identity, &name);
        Self {
            identity,
            name,
            desc: DestinationDesc { address_hash },
        }
    }

    /// Return the destination type.  For Single destinations this is always
    /// `DestinationType::Single`.
    pub fn destination_type(&self) -> DestinationType {
        DestinationType::Single
    }
}

/// Compute the destination hash the same way as leviculum/RNS:
/// `truncated_hash(name_hash_10 + identity_hash_16)` where
/// `name_hash_10 = sha256(app_name.aspects)[..10]` (NAME_HASHBYTES = 10)
/// `identity_hash_16` is the 16-byte identity hash.
fn compute_destination_hash(identity: &Identity, name: &DestinationName) -> AddressHash {
    use reticulum_core::Destination;

    let full_name = name.full_name();
    let full_name_parts: Vec<&str> = full_name.splitn(2, '.').collect();
    let (app_name, aspects_str) = if full_name_parts.len() == 2 {
        (full_name_parts[0], full_name_parts[1])
    } else {
        (full_name_parts[0], "")
    };

    // Parse aspects from "delivery" or "propagation" etc.
    let aspects: Vec<&str> = if aspects_str.is_empty() {
        vec![]
    } else {
        aspects_str.split('.').collect()
    };

    let name_hash = Destination::compute_name_hash(app_name, &aspects);
    let identity_hash = identity.inner().hash();
    let dest_hash = Destination::compute_destination_hash(&name_hash, identity_hash);

    let truncated: [u8; ADDRESS_HASH_SIZE] = dest_hash.into();
    AddressHash::new(truncated)
}

// ── DestinationType ──────────────────────────────────────────────────

/// Re-export of destination types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationType {
    Single = 0x00,
    Group = 0x01,
    Plain = 0x02,
    Link = 0x03,
}

// ── PacketContext (stub) ─────────────────────────────────────────────

/// Stub for beetchat `reticulum::packet::PacketContext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketContext {
    None,
    Resource,
    ResourceAdv,
    ResourceReq,
    ResourceHmu,
    ResourceIcl,
    ResourceRcl,
    Channel,
    Keepalive,
    LinkIdentify,
    LinkClose,
    LinkProof,
    LinkRtt,
    RequestProof,
    Lxmf,
}

// ── HKDF ─────────────────────────────────────────────────────────────

/// HKDF wrapper matching beetchat's API and salt semantics.
///
/// When salt is `None` or empty, beetchat uses a 32-byte zero salt.
/// Leviculum's `derive_key` with `None` salt lets the hkdf crate use
/// a zero-filled salt of hash-length (32 for SHA-256), which is
/// equivalent.  We explicitly replicate beetchat's behavior.
pub fn hkdf(
    length: usize,
    derive_from: &[u8],
    salt: Option<&[u8]>,
    context: Option<&[u8]>,
) -> Vec<u8> {
    const HASH_LEN: usize = 32;

    // Match beetchat: empty or missing salt → 32 zero bytes
    let effective_salt: Option<&[u8]> = match salt {
        Some(s) if !s.is_empty() => Some(s),
        _ => Some(&[0u8; HASH_LEN]),
    };

    let mut output = vec![0u8; length];
    reticulum_core::crypto::derive_key(derive_from, effective_salt, context, &mut output);
    output
}

// ── RnsError ─────────────────────────────────────────────────────────

/// Simple error enum matching the beetchat errors LXMF actually uses.
#[derive(Debug)]
pub enum RnsError {
    IncorrectHash,
    IncorrectSignature,
    CryptoError,
    NotImplemented,
    Transport(String),
}

impl fmt::Display for RnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RnsError::IncorrectHash => write!(f, "Incorrect hash"),
            RnsError::IncorrectSignature => write!(f, "Incorrect signature"),
            RnsError::CryptoError => write!(f, "Crypto error"),
            RnsError::NotImplemented => write!(f, "Not implemented"),
            RnsError::Transport(msg) => write!(f, "Transport error: {}", msg),
        }
    }
}

impl std::error::Error for RnsError {}

// ── AddressHash ↔ DestinationHash conversion ────────────────────────

impl AddressHash {
    /// Convert to a leviculum `DestinationHash`.
    pub fn to_destination_hash(&self) -> reticulum_core::DestinationHash {
        reticulum_core::DestinationHash::new(self.0)
    }

    /// Create from a leviculum `DestinationHash`.
    pub fn from_destination_hash(dh: reticulum_core::DestinationHash) -> Self {
        Self(dh.into_bytes())
    }
}
