use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use reticulum::{
    crypt::hkdf,
    hash::{HASH_SIZE, Hash},
};

const HASH_BITS: u16 = (HASH_SIZE * 8) as u16;
const HKDF_BLOCK_SIZE: usize = 256;

pub const WORKBLOCK_EXPAND_ROUNDS: usize = 3000;
pub const WORKBLOCK_EXPAND_ROUNDS_PN: usize = 1000;
pub const WORKBLOCK_EXPAND_ROUNDS_PEERING: usize = 25;
pub const STAMP_SIZE: usize = HASH_SIZE;

#[derive(Debug, Clone, Copy)]
pub struct StampParameters {
    pub expand_rounds: usize,
}

impl Default for StampParameters {
    fn default() -> Self {
        Self {
            expand_rounds: WORKBLOCK_EXPAND_ROUNDS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StampResult {
    pub stamp: [u8; STAMP_SIZE],
    pub value: u16,
    pub rounds: u64,
}

#[derive(Debug, Error)]
pub enum StampError {
    #[error("stamp cost {0} is outside the supported 1..={1} range")]
    InvalidCost(u8, u16),
    #[error("stamp generation cancelled after {0} rounds without finding a solution")]
    Exhausted(u64),
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub fn generate_stamp<R: RngCore + CryptoRng>(
    rng: &mut R,
    message_id: &[u8],
    stamp_cost: u8,
    params: StampParameters,
    max_attempts: Option<u64>,
) -> Result<StampResult, StampError> {
    validate_cost(stamp_cost)?;
    let workblock = stamp_workblock(message_id, params)?;
    let mut candidate = [0u8; STAMP_SIZE];
    let mut rounds: u64 = 0;

    loop {
        rng.fill_bytes(&mut candidate);
        rounds += 1;

        if stamp_valid(&candidate, stamp_cost, &workblock) {
            let value = stamp_value(&candidate, &workblock);
            return Ok(StampResult {
                stamp: candidate,
                value,
                rounds,
            });
        }

        if let Some(limit) = max_attempts
            && rounds >= limit {
                return Err(StampError::Exhausted(rounds));
            }
    }
}

pub fn stamp_workblock(material: &[u8], params: StampParameters) -> Result<Vec<u8>, StampError> {
    let mut workblock = Vec::with_capacity(params.expand_rounds * HKDF_BLOCK_SIZE);
    for round in 0..params.expand_rounds {
        let salt = salt_for_round(material, round as u32)?;
        let block = hkdf(HKDF_BLOCK_SIZE, material, Some(&salt), None);
        workblock.extend_from_slice(&block);
    }
    Ok(workblock)
}

pub fn stamp_valid(stamp: &[u8], target_cost: u8, workblock: &[u8]) -> bool {
    if target_cost == 0 {
        return true;
    }
    match leading_zero_bits(work_material(workblock, stamp).as_slice()) {
        Some(bits) => bits >= target_cost as u16,
        None => false,
    }
}

pub fn stamp_value(stamp: &[u8], workblock: &[u8]) -> u16 {
    leading_zero_bits(work_material(workblock, stamp).as_slice()).unwrap_or(0)
}

fn validate_cost(cost: u8) -> Result<(), StampError> {
    if cost == 0 || cost as u16 >= HASH_BITS {
        return Err(StampError::InvalidCost(cost, HASH_BITS - 1));
    }
    Ok(())
}

fn salt_for_round(material: &[u8], round: u32) -> Result<[u8; HASH_SIZE], StampError> {
    let packed_round = msgpack_encode_u32(round);

    let mut hasher = Hash::generator();
    hasher.update(material);
    hasher.update(&packed_round);
    Ok(hasher.finalize().into())
}

fn msgpack_encode_u32(value: u32) -> Vec<u8> {
    match value {
        0x00..=0x7f => vec![value as u8],
        0x80..=0xff => vec![0xcc, value as u8],
        0x0100..=0xffff => vec![0xcd, (value >> 8) as u8, value as u8],
        _ => {
            let mut out = vec![0xce];
            out.extend_from_slice(&value.to_be_bytes());
            out
        }
    }
}

fn work_material(workblock: &[u8], stamp: &[u8]) -> Hash {
    let mut hasher = Hash::generator();
    hasher.update(workblock);
    hasher.update(stamp);
    Hash::new(hasher.finalize().into())
}

fn leading_zero_bits(bytes: &[u8]) -> Option<u16> {
    if bytes.is_empty() {
        return None;
    }
    let mut total = 0u16;
    for byte in bytes {
        if *byte == 0 {
            total += 8;
            continue;
        }
        let lz = byte.leading_zeros() as u16;
        total += lz;
        return Some(total);
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[test]
    fn generates_stamp_with_small_cost() {
        let mut rng = ChaCha12Rng::seed_from_u64(42);
        let params = StampParameters { expand_rounds: 2 };
        let message_id = [0u8; HASH_SIZE];
        let result = generate_stamp(&mut rng, &message_id, 8, params, Some(10_000)).expect("stamp");
        assert!(stamp_valid(
            &result.stamp,
            8,
            &stamp_workblock(&message_id, params).unwrap()
        ));
        assert!(result.rounds > 0);
    }

    #[test]
    fn msgpack_round_encoding_matches_reference() {
        let cases = [
            (0u32, vec![0x00]),
            (0x7f, vec![0x7f]),
            (0x80, vec![0xcc, 0x80]),
            (0xff, vec![0xcc, 0xff]),
            (0x0100, vec![0xcd, 0x01, 0x00]),
            (0xffff, vec![0xcd, 0xff, 0xff]),
            (0x0001_0000, vec![0xce, 0x00, 0x01, 0x00, 0x00]),
        ];

        for (value, expected) in cases {
            assert_eq!(msgpack_encode_u32(value), expected);
        }
    }

    /// Test that salt computation matches Python's implementation.
    ///
    /// Python reference (LXStamper.stamp_workblock):
    /// ```python
    /// salt = RNS.Identity.full_hash(material + msgpack.packb(n))
    /// ```
    ///
    /// For message_id=0x00*32, n=0:
    /// - packed_n = 0x00
    /// - salt = SHA256(message_id || 0x00) = 7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9
    #[test]
    fn salt_for_round_matches_python() {
        let message_id = [0u8; HASH_SIZE];

        // Test round 0
        let salt_0 = salt_for_round(&message_id, 0).unwrap();
        let expected_salt_0 = [
            0x7f, 0x9c, 0x9e, 0x31, 0xac, 0x82, 0x56, 0xca,
            0x2f, 0x25, 0x85, 0x83, 0xdf, 0x26, 0x2d, 0xbc,
            0x7d, 0x6f, 0x68, 0xf2, 0xa0, 0x30, 0x43, 0xd5,
            0xc9, 0x9a, 0x4a, 0xe5, 0xa7, 0x39, 0x6c, 0xe9,
        ];
        assert_eq!(
            salt_0, expected_salt_0,
            "Salt for round 0 mismatch.\nRust:   {:02x?}\nPython: {:02x?}",
            salt_0, expected_salt_0
        );

        // Test round 1
        let salt_1 = salt_for_round(&message_id, 1).unwrap();
        let expected_salt_1 = [
            0x1f, 0xd4, 0x24, 0x74, 0x43, 0xc9, 0x44, 0x0c,
            0xb3, 0xc4, 0x8c, 0x28, 0x85, 0x19, 0x37, 0x19,
            0x6b, 0xc1, 0x56, 0x03, 0x2d, 0x70, 0xa9, 0x6c,
            0x98, 0xe1, 0x27, 0xec, 0xb3, 0x47, 0xe4, 0x5f,
        ];
        assert_eq!(
            salt_1, expected_salt_1,
            "Salt for round 1 mismatch.\nRust:   {:02x?}\nPython: {:02x?}",
            salt_1, expected_salt_1
        );
    }

    /// Test that HKDF output matches Python's implementation.
    ///
    /// Python reference (using cryptography library HKDF):
    /// For message_id=0x00*32, round=0:
    /// - salt = 7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9
    /// - HKDF output (first 32 bytes) = 433b07ee12ddfca7b6f5409d310ff15ac7ff335fe6f6938da6c2d89faf77db98
    #[test]
    fn hkdf_output_matches_python() {
        let message_id = [0u8; HASH_SIZE];
        let salt = salt_for_round(&message_id, 0).unwrap();

        // Use the hkdf function from reticulum
        let hkdf_output = hkdf(HKDF_BLOCK_SIZE, &message_id, Some(&salt), None);

        // First 32 bytes from Python
        let expected_first_32: [u8; 32] = [
            0x43, 0x3b, 0x07, 0xee, 0x12, 0xdd, 0xfc, 0xa7,
            0xb6, 0xf5, 0x40, 0x9d, 0x31, 0x0f, 0xf1, 0x5a,
            0xc7, 0xff, 0x33, 0x5f, 0xe6, 0xf6, 0x93, 0x8d,
            0xa6, 0xc2, 0xd8, 0x9f, 0xaf, 0x77, 0xdb, 0x98,
        ];

        assert_eq!(
            &hkdf_output[..32], &expected_first_32,
            "HKDF output (first 32 bytes) mismatch.\nRust:   {:02x?}\nPython: {:02x?}",
            &hkdf_output[..32], &expected_first_32
        );
    }

    /// Comprehensive end-to-end test that verifies the stamp generation and
    /// validation flow matches Python's behavior exactly.
    ///
    /// This test:
    /// 1. Computes the message_id (hash of dest + src + payload_without_stamp)
    /// 2. Generates a valid stamp for that message_id
    /// 3. Simulates what Python's receiver would do to validate the stamp
    /// 4. Verifies that the stamp is valid
    ///
    /// This matches the validation done in Python's LXMessage.validate_stamp():
    /// ```python
    /// workblock = LXStamper.stamp_workblock(self.message_id)
    /// if LXStamper.stamp_valid(self.stamp, target_cost, workblock):
    ///     ...
    /// ```
    #[test]
    fn end_to_end_stamp_generation_and_validation() {
        use reticulum::hash::AddressHash;
        use rmp::encode;

        // Use the same test data as message_hash_matches_python
        let dest_hash = AddressHash::new([0u8; 16]);
        let src_hash = AddressHash::new([0u8; 16]);
        let timestamp: f64 = 1234567890.123456;
        let title = b"greet";
        let content = b"hello";

        // Encode payload without stamp (exactly as Python does)
        let mut payload_without_stamp = Vec::new();
        encode::write_array_len(&mut payload_without_stamp, 4).unwrap();
        encode::write_f64(&mut payload_without_stamp, timestamp).unwrap();
        encode::write_bin_len(&mut payload_without_stamp, title.len() as u32).unwrap();
        payload_without_stamp.extend_from_slice(title);
        encode::write_bin_len(&mut payload_without_stamp, content.len() as u32).unwrap();
        payload_without_stamp.extend_from_slice(content);
        encode::write_map_len(&mut payload_without_stamp, 0).unwrap(); // empty fields

        // Compute message_id = SHA256(dest + src + packed_payload_without_stamp)
        let mut hashed_part = Vec::new();
        hashed_part.extend_from_slice(dest_hash.as_slice());
        hashed_part.extend_from_slice(src_hash.as_slice());
        hashed_part.extend_from_slice(&payload_without_stamp);
        let message_id = Hash::new_from_slice(&hashed_part);

        // Verify the message_id matches the expected Python value
        let expected_message_id = "7dab36ed1047be956098ade44e1966b21ce8dd469648e711e43611c90790838f";
        let actual_message_id: String = message_id.as_slice().iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(actual_message_id, expected_message_id, "Message ID mismatch");

        // Generate a valid stamp
        let mut rng = ChaCha12Rng::seed_from_u64(42);
        let target_cost = 8u8;
        let params = StampParameters::default();
        
        let result = generate_stamp(&mut rng, message_id.as_slice(), target_cost, params, Some(100_000))
            .expect("should generate stamp");
        
        assert!(result.value >= target_cost as u16, "Stamp value {} is less than target cost {}", result.value, target_cost);

        // Now simulate what the Python receiver does:
        // 1. Extract the stamp from the message payload
        // 2. Re-pack the payload without stamp
        // 3. Compute message_id from dest + src + repacked_payload
        // 4. Generate workblock from message_id
        // 5. Validate stamp against workblock

        // For this test, we already have the message_id, so just validate the stamp
        let receiver_workblock = stamp_workblock(message_id.as_slice(), params)
            .expect("workblock generation should succeed");
        
        let is_valid = stamp_valid(&result.stamp, target_cost, &receiver_workblock);
        let computed_value = stamp_value(&result.stamp, &receiver_workblock);

        assert!(is_valid, 
            "Stamp validation FAILED!\n\
             Message ID:   {}\n\
             Stamp (hex):  {:02x?}\n\
             Target cost:  {}\n\
             Stamp value:  {}\n\
             Rounds used:  {}",
            expected_message_id,
            result.stamp,
            target_cost,
            computed_value,
            result.rounds
        );

        assert_eq!(result.value, computed_value,
            "Stamp value mismatch between generation ({}) and validation ({})",
            result.value, computed_value
        );
    }
}
