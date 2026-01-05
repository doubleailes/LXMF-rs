use crate::message::LxPayload;
use reticulum::hash::AddressHash;

#[derive(Debug, Clone)]
pub struct LXMessage {
    /// Destination hash (16 bytes)
    pub destination_hash: AddressHash,

    /// Source hash (16 bytes)
    pub source_hash: AddressHash,

    /// Ed25519 signature (64 bytes)
    pub signature: [u8; SIGNATURE_LENGTH],

    /// Message payload
    pub payload: LxPayload,

    /// Cached message ID (SHA-256 hash)
    message_id: Option<[u8; 32]>,

    /// Whether signature has been validated
    signature_validated: bool,

    state: State,

    representation: Representation,

    desired_method: ValideMathod,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum State {
    Generating = 0x00,
    Outbound = 0x01,
    Sending = 0x02,
    Sent = 0x04,
    Delivered = 0x08,
    Rejected = 0xFD,
    Cancelled = 0xFE,
    Failed = 0xFF,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum Representation {
    Unknown = 0x00,
    Packet = 0x01,
    Resource = 0x02,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum ValideMathod {
    Opportunistic = 0x01,
    Direct = 0x02,
    Propagated = 0x03,
    Paper = 0x05,
}

enum EncryptionMethod {
    ENCRYPTION_DESCRIPTION_AES = "AES-128",
    ENCRYPTION_DESCRIPTION_EC = "Curve25519",
    ENCRYPTION_DESCRIPTION_UNENCRYPTED = "Unencrypted",
}
