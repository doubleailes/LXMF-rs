use crate::message::LxPayload;
use reticulum::{destination::SingleOutputDestination, identity::Identity, identity};


const DESTINATION_LENGTH: usize = identity::PUBLIC_KEY_LENGTH/8; // place holder should check actual length
const SIGNATURE_LENGTH: usize = identity::PUBLIC_KEY_LENGTH/8; // place holder should check actual length
const TICKET_LENGTH: usize = identity::PUBLIC_KEY_LENGTH/8; // place holder should check actual length

/// LXMF overhead is 112 bytes per message:
/// 16  bytes for destination hash
/// 16  bytes for source hash
/// 8   bytes for timestamp
/// 1   byte  for desired method
/// 8   bytes for msgpack structure
const TIMESTAMP_SIZE: usize = 8;
const STRUCT_OVERHEAD: usize = 8;
const LXMF_OVERHEAD: usize = 2*DESTINATION_LENGTH + SIGNATURE_LENGTH + TIMESTAMP_SIZE + STRUCT_OVERHEAD;

const ENCRYPTION_DESCRIPTION_AES: &str = "AES-128";
const ENCRYPTION_DESCRIPTION_EC: &str  = "Curve25519";
const ENCRYPTION_DESCRIPTION_UNENCRYPTED: &str = "Unencrypted";

const URI_SCHEMA: &str = "lxm";
const QR_ERROR_CORRECTION: &str = "ERROR_CORRECT_L";
const QR_MAX_STORAGE: usize = 2953;
const PAPER_MDU: usize = ((QR_MAX_STORAGE-(URI_SCHEMA.len()+ "://".len()))*6)/8;

#[allow(non_snake_case)]
pub struct LXMessage {
    /// Destination hash (16 bytes)
    destination: SingleOutputDestination,

    /// Source hash (16 bytes)
    source: Identity,

    /// Message payload
    payload: LxPayload,

    /// Desired method of delivery
    desired_method: ValidMethod,

    include_ticket: bool,
}

impl LXMessage {
    pub fn new(
        destination: SingleOutputDestination,
        source: Identity,
        content: String,
        title: String,
        desired_method: ValidMethod,
        include_ticket: bool,
    ) -> Self {
        LXMessage {
            destination,
            source,
            payload: LxPayload::new_now(title, content),
            desired_method,
            include_ticket,
        }
    }
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
pub enum ValidMethod {
    Opportunistic = 0x01,
    Direct = 0x02,
    Propagated = 0x03,
    Paper = 0x05,
}
#[derive(Debug, Copy, Clone)]
enum EncryptionMethod {
    ENCRYPTION_DESCRIPTION_AES,
    ENCRYPTION_DESCRIPTION_EC,
    ENCRYPTION_DESCRIPTION_UNENCRYPTED,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum UnverifiedReason {
    SOURCE_UNKNOWN = 0x01,
    SIGNATURE_INVALID = 0x02,
}
