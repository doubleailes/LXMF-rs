use std::{
    fmt::Write as FmtWrite,
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::message::{LxPayload, MessageError};
use ed25519_dalek::{SIGNATURE_LENGTH, Signature};
use indexmap::IndexMap;
use reticulum::{
    destination::{SingleInputDestination, SingleOutputDestination},
    hash::{ADDRESS_HASH_SIZE, AddressHash, Hash},
    identity::Identity,
    packet::DestinationType,
};
use rmp::{decode, encode};

const DESTINATION_LENGTH: usize = ADDRESS_HASH_SIZE;
const ENCRYPTION_DESCRIPTION_AES: &str = "AES-128";
const ENCRYPTION_DESCRIPTION_EC: &str = "Curve25519";
const ENCRYPTION_DESCRIPTION_UNENCRYPTED: &str = "Unencrypted";

type SignatureBytes = [u8; SIGNATURE_LENGTH];

pub struct LXMessage {
    destination: Option<SingleOutputDestination>,
    destination_hash: AddressHash,
    source: Option<SingleInputDestination>,
    source_hash: AddressHash,
    payload: LxPayload,
    desired_method: Option<ValidMethod>,
    include_ticket: bool,
    stamp: Option<Vec<u8>>,
    stamp_cost: Option<u8>,
    stamp_value: Option<u16>,
    state: State,
    method: ValidMethod,
    representation: Representation,
    transport_encrypted: bool,
    transport_encryption: Option<String>,
    signature: Option<SignatureBytes>,
    signature_validated: bool,
    unverified_reason: Option<UnverifiedReason>,
    hash: Option<Hash>,
    packed: Option<Vec<u8>>,
    payload_bytes: Option<Vec<u8>>,
    packed_size: Option<usize>,
    incoming: bool,
}

impl LXMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new<T: Into<Vec<u8>>, U: Into<Vec<u8>>>(
        destination: SingleOutputDestination,
        source: SingleInputDestination,
        content: T,
        title: U,
        fields: Option<IndexMap<String, Vec<u8>>>,
        desired_method: Option<ValidMethod>,
        include_ticket: bool,
    ) -> Self {
        let timestamp = unix_time_f64();
        let payload = LxPayload::from_parts(
            timestamp,
            title.into(),
            content.into(),
            fields.unwrap_or_default(),
        );

        Self {
            destination_hash: destination.desc.address_hash,
            destination: Some(destination),
            source_hash: source.desc.address_hash,
            source: Some(source),
            payload,
            desired_method,
            include_ticket,
            stamp: None,
            stamp_cost: None,
            stamp_value: None,
            state: State::Generating,
            method: desired_method.unwrap_or_default(),
            representation: Representation::Unknown,
            transport_encrypted: false,
            transport_encryption: None,
            signature: None,
            signature_validated: false,
            unverified_reason: None,
            hash: None,
            packed: None,
            payload_bytes: None,
            packed_size: None,
            incoming: false,
        }
    }

    pub fn payload(&self) -> &LxPayload {
        &self.payload
    }

    pub fn payload_mut(&mut self) -> &mut LxPayload {
        self.invalidate_cache();
        &mut self.payload
    }

    pub fn set_title_from_string(&mut self, title: &str) {
        self.payload.title = title.as_bytes().to_vec();
        self.invalidate_cache();
    }

    pub fn set_title_from_bytes(&mut self, title: Vec<u8>) {
        self.payload.title = title;
        self.invalidate_cache();
    }

    pub fn title_as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.payload.title.clone())
    }

    pub fn set_content_from_string(&mut self, content: &str) {
        self.payload.content = content.as_bytes().to_vec();
        self.invalidate_cache();
    }

    pub fn set_content_from_bytes(&mut self, content: Vec<u8>) {
        self.payload.content = content;
        self.invalidate_cache();
    }

    pub fn content_as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.payload.content.clone())
    }

    pub fn set_fields(&mut self, fields: Option<IndexMap<String, Vec<u8>>>) {
        self.payload.fields = fields.unwrap_or_default();
        self.invalidate_cache();
    }

    pub fn fields(&self) -> &IndexMap<String, Vec<u8>> {
        &self.payload.fields
    }

    pub fn stamp(&self) -> Option<&[u8]> {
        self.stamp.as_deref()
    }

    pub fn set_stamp(&mut self, stamp: Option<Vec<u8>>) {
        if stamp.is_none() {
            self.stamp_value = None;
        }
        self.stamp = stamp;
        self.invalidate_cache();
    }

    pub fn stamp_cost(&self) -> Option<u8> {
        self.stamp_cost
    }

    pub fn set_stamp_cost(&mut self, cost: Option<u8>) {
        self.stamp_cost = cost;
    }

    pub fn stamp_value(&self) -> Option<u16> {
        self.stamp_value
    }

    pub fn set_stamp_value(&mut self, value: Option<u16>) {
        self.stamp_value = value;
    }

    pub fn destination_hash(&self) -> AddressHash {
        self.destination_hash
    }

    pub fn source_hash(&self) -> AddressHash {
        self.source_hash
    }

    pub fn message_hash(&self) -> Option<&Hash> {
        self.hash.as_ref()
    }

    pub fn method(&self) -> ValidMethod {
        self.method
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn transport_encrypted(&self) -> bool {
        self.transport_encrypted
    }

    pub fn transport_encryption(&self) -> Option<&str> {
        self.transport_encryption.as_deref()
    }

    pub fn include_ticket(&self) -> bool {
        self.include_ticket
    }

    pub fn packed_len(&self) -> Option<usize> {
        self.packed_size
    }

    pub fn pack(&mut self) -> Result<&[u8], MessageError> {
        if self.packed.is_some() {
            let slice = self
                .packed
                .as_ref()
                .map(|buf| buf.as_slice())
                .expect("packed present");
            return Ok(slice);
        }

        self.destination
            .as_ref()
            .ok_or(MessageError::MissingDestination)?;
        let source = self.source.as_ref().ok_or(MessageError::MissingSource)?;

        let payload_core = self.encode_payload_bytes(false)?;
        let mut hashed_part = hashed_part(&payload_core, &self.destination_hash, &self.source_hash);
        let message_hash = Hash::new_from_slice(&hashed_part);
        self.hash = Some(message_hash);

        hashed_part.extend_from_slice(message_hash.as_slice());

        let signature = source.identity.sign(&hashed_part);
        self.signature = Some(signature.to_bytes());
        self.signature_validated = true;
        self.unverified_reason = None;

        let mut payload_bytes = payload_core;
        if self.stamp.is_some() {
            payload_bytes = self.encode_payload_bytes(true)?;
        }

        let mut packed =
            Vec::with_capacity(DESTINATION_LENGTH * 2 + SIGNATURE_LENGTH + payload_bytes.len());
        packed.extend_from_slice(self.destination_hash.as_slice());
        packed.extend_from_slice(self.source_hash.as_slice());
        packed.extend_from_slice(self.signature.as_ref().expect("signature set"));
        packed.extend_from_slice(&payload_bytes);

        self.method = self.desired_method.unwrap_or_default();
        self.representation = if self.method == ValidMethod::Paper {
            Representation::Paper
        } else {
            Representation::Packet
        };
        self.state = State::Outbound;
        self.transport_encrypted = true;
        self.determine_transport_encryption();
        self.payload_bytes = Some(payload_bytes);
        self.packed_size = Some(packed.len());
        self.packed = Some(packed);

        Ok(self.packed.as_deref().expect("packed bytes"))
    }

    /// Return the bytes that should be handed to the underlying Reticulum transport.
    ///
    /// Opportunistic deliveries reserve the destination hash for the packet header,
    /// so we strip it before transmission to mirror the Python implementation.
    pub fn transport_payload(&mut self) -> Result<Vec<u8>, MessageError> {
        let mut packed = self.pack()?.to_vec();
        match self.method {
            ValidMethod::Opportunistic => {
                if packed.len() <= DESTINATION_LENGTH {
                    return Err(MessageError::InvalidFormat(
                        "Packed LXMF shorter than destination prefix".into(),
                    ));
                }
                Ok(packed.split_off(DESTINATION_LENGTH))
            }
            _ => Ok(packed),
        }
    }

    pub fn packed_container(&mut self) -> Result<Vec<u8>, MessageError> {
        let packed = self.pack()?.to_vec();
        let mut buf = Vec::new();
        encode::write_map_len(&mut buf, 5)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        encode::write_str(&mut buf, "state")
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        encode::write_u32(&mut buf, self.state as u32)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        encode::write_str(&mut buf, "lxmf_bytes")
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        write_bin(&mut buf, &packed)?;
        encode::write_str(&mut buf, "transport_encrypted")
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        encode::write_bool(&mut buf, self.transport_encrypted)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        encode::write_str(&mut buf, "transport_encryption")
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        let enc = self
            .transport_encryption
            .as_deref()
            .unwrap_or(ENCRYPTION_DESCRIPTION_UNENCRYPTED);
        encode::write_str(&mut buf, enc)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        encode::write_str(&mut buf, "method")
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        encode::write_u32(&mut buf, self.method as u32)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        Ok(buf)
    }

    pub fn write_to_directory<P: AsRef<Path>>(
        &mut self,
        directory: P,
    ) -> Result<PathBuf, MessageError> {
        let container = self.packed_container()?;
        let hash = self
            .hash
            .ok_or_else(|| MessageError::InvalidFormat("Message hash missing".into()))?;
        fs::create_dir_all(&directory)?;
        let mut name = String::with_capacity(hash.as_slice().len() * 2);
        for byte in hash.as_slice() {
            write!(&mut name, "{:02x}", byte).expect("hex write");
        }
        let path = directory.as_ref().join(name);
        fs::write(&path, container)?;
        Ok(path)
    }

    pub fn unpack_from_bytes(lxmf_bytes: &[u8]) -> Result<Self, MessageError> {
        if lxmf_bytes.len() < DESTINATION_LENGTH * 2 + SIGNATURE_LENGTH {
            return Err(MessageError::InvalidFormat("LXMF payload too short".into()));
        }

        let destination_hash = AddressHash::new(copy_hash(&lxmf_bytes[..DESTINATION_LENGTH]));
        let source_hash = AddressHash::new(copy_hash(
            &lxmf_bytes[DESTINATION_LENGTH..DESTINATION_LENGTH * 2],
        ));
        let signature_offset = DESTINATION_LENGTH * 2;
        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature
            .copy_from_slice(&lxmf_bytes[signature_offset..signature_offset + SIGNATURE_LENGTH]);
        let payload_bytes = lxmf_bytes[signature_offset + SIGNATURE_LENGTH..].to_vec();

        let decoded = Self::decode_payload_bytes(&payload_bytes)?;
        let payload = LxPayload::from_parts(
            decoded.timestamp,
            decoded.title.clone(),
            decoded.content.clone(),
            decoded.fields.clone(),
        );

        // For hash computation, we need to use the payload WITHOUT the stamp,
        // exactly matching Python's behavior which re-packs the payload array
        // without the stamp element before computing the hash.
        // See LXMessage.unpack_from_bytes in Python LXMF.
        let payload_bytes_for_hash = if decoded.stamp.is_some() {
            // Re-encode payload without stamp (4 elements)
            encode_payload_without_stamp(
                decoded.timestamp,
                &decoded.title,
                &decoded.content,
                &decoded.fields,
            )?
        } else {
            // No stamp, use original bytes
            payload_bytes.clone()
        };

        let mut hashed_part = hashed_part(&payload_bytes_for_hash, &destination_hash, &source_hash);
        let message_hash = Hash::new_from_slice(&hashed_part);
        hashed_part.extend_from_slice(message_hash.as_slice());

        let mut message = Self {
            destination: None,
            destination_hash,
            source: None,
            source_hash,
            payload,
            desired_method: None,
            include_ticket: false,
            stamp: decoded.stamp,
            stamp_cost: None,
            stamp_value: None,
            state: State::Generating,
            method: ValidMethod::Direct,
            representation: Representation::Packet,
            transport_encrypted: false,
            transport_encryption: None,
            signature: Some(signature),
            signature_validated: false,
            unverified_reason: Some(UnverifiedReason::SourceUnknown),
            hash: Some(message_hash),
            packed: Some(lxmf_bytes.to_vec()),
            payload_bytes: Some(payload_bytes),
            packed_size: Some(lxmf_bytes.len()),
            incoming: true,
        };
        message.determine_transport_encryption();
        Ok(message)
    }

    pub fn unpack_from_file(mut reader: impl Read) -> Result<Self, MessageError> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        Self::unpack_from_container(&buffer)
    }

    pub fn unpack_from_container(data: &[u8]) -> Result<Self, MessageError> {
        let mut cursor = Cursor::new(data);
        let map_len = decode::read_map_len(&mut cursor)
            .map_err(|e| MessageError::DeserializationError(e.to_string()))?;

        let mut state = None;
        let mut lxmf_bytes = None;
        let mut transport_encrypted = None;
        let mut transport_encryption = None;
        let mut method = None;

        for _ in 0..map_len {
            let key = read_string(&mut cursor)?;
            match key.as_str() {
                "state" => {
                    state = Some(
                        decode::read_u32(&mut cursor)
                            .map_err(|e| MessageError::DeserializationError(e.to_string()))?
                            as u8,
                    );
                }
                "lxmf_bytes" => lxmf_bytes = Some(read_bin(&mut cursor)?),
                "transport_encrypted" => {
                    transport_encrypted = Some(
                        decode::read_bool(&mut cursor)
                            .map_err(|e| MessageError::DeserializationError(e.to_string()))?,
                    );
                }
                "transport_encryption" => transport_encryption = Some(read_string(&mut cursor)?),
                "method" => {
                    method = Some(
                        decode::read_u32(&mut cursor)
                            .map_err(|e| MessageError::DeserializationError(e.to_string()))?
                            as u8,
                    );
                }
                other => {
                    return Err(MessageError::InvalidFormat(format!(
                        "Unexpected container key {}",
                        other
                    )));
                }
            }
        }

        let lxmf_bytes =
            lxmf_bytes.ok_or_else(|| MessageError::InvalidFormat("Missing lxmf_bytes".into()))?;
        let mut message = Self::unpack_from_bytes(&lxmf_bytes)?;
        if let Some(state_value) = state {
            message.state = State::try_from(state_value)?;
        }
        if let Some(encrypted) = transport_encrypted {
            message.transport_encrypted = encrypted;
        }
        if let Some(enc_desc) = transport_encryption {
            message.transport_encryption = Some(enc_desc);
        }
        if let Some(method_value) = method {
            message.method = ValidMethod::try_from(method_value)?;
        }

        Ok(message)
    }

    pub fn validate_signature(&mut self, identity: &Identity) -> Result<bool, MessageError> {
        let signature_bytes = self
            .signature
            .ok_or_else(|| MessageError::InvalidFormat("Missing signature".into()))?;
        let payload_bytes = self.encode_payload_bytes(false)?;
        let mut hashed_part =
            hashed_part(&payload_bytes, &self.destination_hash, &self.source_hash);
        let message_hash = Hash::new_from_slice(&hashed_part);
        hashed_part.extend_from_slice(message_hash.as_slice());
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| MessageError::InvalidSignature)?;
        identity
            .verify(&hashed_part, &signature)
            .map_err(|_| MessageError::InvalidSignature)?;
        self.signature_validated = true;
        self.hash = Some(message_hash);
        self.unverified_reason = None;
        Ok(true)
    }

    fn encode_payload_bytes(&self, include_stamp: bool) -> Result<Vec<u8>, MessageError> {
        let mut buf = Vec::new();
        let include_stamp_entry = include_stamp && self.stamp.is_some();
        let len = if include_stamp_entry { 5 } else { 4 };
        encode::write_array_len(&mut buf, len)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        encode::write_f64(&mut buf, self.payload.timestamp)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        write_bin(&mut buf, &self.payload.title)?;
        write_bin(&mut buf, &self.payload.content)?;
        encode::write_map_len(&mut buf, self.payload.fields.len() as u32)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        for (key, value) in &self.payload.fields {
            encode::write_str(&mut buf, key)
                .map_err(|e| MessageError::SerializationError(e.to_string()))?;
            write_bin(&mut buf, value)?;
        }
        if include_stamp_entry {
            if let Some(stamp) = &self.stamp {
                write_bin(&mut buf, stamp)?;
            }
        }
        Ok(buf)
    }

    fn decode_payload_bytes(bytes: &[u8]) -> Result<DecodedPayload, MessageError> {
        let mut cursor = Cursor::new(bytes);
        let len = decode::read_array_len(&mut cursor)
            .map_err(|e| MessageError::DeserializationError(e.to_string()))?;
        if len < 4 {
            return Err(MessageError::InvalidFormat(
                "Payload missing required fields".into(),
            ));
        }
        let timestamp = decode::read_f64(&mut cursor)
            .map_err(|e| MessageError::DeserializationError(e.to_string()))?;
        let title = read_bin(&mut cursor)?;
        let content = read_bin(&mut cursor)?;
        let fields_len = decode::read_map_len(&mut cursor)
            .map_err(|e| MessageError::DeserializationError(e.to_string()))?;
        let fields = decode_fields(&mut cursor, fields_len)?;
        let stamp = if len > 4 {
            Some(read_bin(&mut cursor)?)
        } else {
            None
        };
        Ok(DecodedPayload {
            timestamp,
            title,
            content,
            fields,
            stamp,
        })
    }

    fn determine_transport_encryption(&mut self) {
        let descriptor = if let Some(destination) = &self.destination {
            match destination.destination_type() {
                DestinationType::Plain => {
                    self.transport_encrypted = false;
                    ENCRYPTION_DESCRIPTION_UNENCRYPTED
                }
                DestinationType::Group => {
                    self.transport_encrypted = true;
                    ENCRYPTION_DESCRIPTION_AES
                }
                _ => {
                    self.transport_encrypted = true;
                    ENCRYPTION_DESCRIPTION_EC
                }
            }
        } else {
            self.transport_encrypted = false;
            ENCRYPTION_DESCRIPTION_UNENCRYPTED
        };
        self.transport_encryption = Some(descriptor.to_string());
    }

    fn invalidate_cache(&mut self) {
        self.packed = None;
        self.payload_bytes = None;
        self.packed_size = None;
        self.hash = None;
        self.signature = None;
        self.signature_validated = false;
    }
}

fn unix_time_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn hashed_part(
    payload_bytes: &[u8],
    destination_hash: &AddressHash,
    source_hash: &AddressHash,
) -> Vec<u8> {
    let mut data =
        Vec::with_capacity(destination_hash.len() + source_hash.len() + payload_bytes.len());
    data.extend_from_slice(destination_hash.as_slice());
    data.extend_from_slice(source_hash.as_slice());
    data.extend_from_slice(payload_bytes);
    data
}

/// Encode a payload array without the stamp element (4 elements only).
/// This is used when unpacking a message with a stamp to compute the hash,
/// matching Python's behavior which re-packs the payload without the stamp.
fn encode_payload_without_stamp(
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    fields: &IndexMap<String, Vec<u8>>,
) -> Result<Vec<u8>, MessageError> {
    let mut buf = Vec::new();
    encode::write_array_len(&mut buf, 4)
        .map_err(|e| MessageError::SerializationError(e.to_string()))?;
    encode::write_f64(&mut buf, timestamp)
        .map_err(|e| MessageError::SerializationError(e.to_string()))?;
    write_bin(&mut buf, title)?;
    write_bin(&mut buf, content)?;
    encode::write_map_len(&mut buf, fields.len() as u32)
        .map_err(|e| MessageError::SerializationError(e.to_string()))?;
    for (key, value) in fields {
        encode::write_str(&mut buf, key)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        write_bin(&mut buf, value)?;
    }
    Ok(buf)
}

fn write_bin<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), MessageError> {
    encode::write_bin_len(writer, data.len() as u32)
        .map_err(|e| MessageError::SerializationError(e.to_string()))?;
    writer
        .write_all(data)
        .map_err(|e| MessageError::SerializationError(e.to_string()))
}

fn read_bin<R: Read>(reader: &mut R) -> Result<Vec<u8>, MessageError> {
    let len = decode::read_bin_len(reader)
        .map_err(|e| MessageError::DeserializationError(e.to_string()))? as usize;
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| MessageError::DeserializationError(e.to_string()))?;
    Ok(buf)
}

fn read_string<R: Read>(reader: &mut R) -> Result<String, MessageError> {
    let len = decode::read_str_len(reader)
        .map_err(|e| MessageError::DeserializationError(e.to_string()))? as usize;
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| MessageError::DeserializationError(e.to_string()))?;
    String::from_utf8(buf).map_err(|e| MessageError::DeserializationError(e.to_string()))
}

fn decode_fields<R: Read>(
    reader: &mut R,
    len: u32,
) -> Result<IndexMap<String, Vec<u8>>, MessageError> {
    let mut fields = IndexMap::with_capacity(len as usize);
    for _ in 0..len {
        let key = read_string(reader)?;
        let value = read_bin(reader)?;
        fields.insert(key, value);
    }
    Ok(fields)
}

fn copy_hash(bytes: &[u8]) -> [u8; ADDRESS_HASH_SIZE] {
    let mut out = [0u8; ADDRESS_HASH_SIZE];
    out.copy_from_slice(&bytes[..ADDRESS_HASH_SIZE]);
    out
}

struct DecodedPayload {
    timestamp: f64,
    title: Vec<u8>,
    content: Vec<u8>,
    fields: IndexMap<String, Vec<u8>>,
    stamp: Option<Vec<u8>>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum State {
    Generating = 0x00,
    Outbound = 0x01,
    Sending = 0x02,
    Sent = 0x04,
    Delivered = 0x08,
    Rejected = 0xFD,
    Cancelled = 0xFE,
    Failed = 0xFF,
}

impl TryFrom<u8> for State {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00 => State::Generating,
            0x01 => State::Outbound,
            0x02 => State::Sending,
            0x04 => State::Sent,
            0x08 => State::Delivered,
            0xFD => State::Rejected,
            0xFE => State::Cancelled,
            0xFF => State::Failed,
            other => {
                return Err(MessageError::InvalidFormat(format!(
                    "Unknown state {:02x}",
                    other
                )));
            }
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
enum Representation {
    Unknown = 0x00,
    Packet = 0x01,
    Resource = 0x02,
    Paper = 0x03,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum ValidMethod {
    Opportunistic = 0x01,
    Direct = 0x02,
    Propagated = 0x03,
    Paper = 0x05,
}

impl Default for ValidMethod {
    fn default() -> Self {
        ValidMethod::Direct
    }
}

impl TryFrom<u8> for ValidMethod {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => ValidMethod::Opportunistic,
            0x02 => ValidMethod::Direct,
            0x03 => ValidMethod::Propagated,
            0x05 => ValidMethod::Paper,
            other => {
                return Err(MessageError::InvalidFormat(format!(
                    "Unknown delivery method {:02x}",
                    other
                )));
            }
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum UnverifiedReason {
    SourceUnknown = 0x01,
    SignatureInvalid = 0x02,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum::{destination::DestinationName, hash::HASH_SIZE, identity::PrivateIdentity};

    fn sample_message() -> LXMessage {
        let sender = PrivateIdentity::new_from_name("sender");
        let receiver = PrivateIdentity::new_from_name("receiver");
        let source_destination =
            SingleInputDestination::new(sender, DestinationName::new("lxmf", "delivery"));
        let destination = SingleOutputDestination::new(
            receiver.as_identity().clone(),
            DestinationName::new("lxmf", "delivery"),
        );

        let mut fields = IndexMap::new();
        fields.insert("lang".into(), b"rust".to_vec());

        LXMessage::new(
            destination,
            source_destination,
            "hello".as_bytes(),
            "greet".as_bytes(),
            Some(fields),
            Some(ValidMethod::Direct),
            false,
        )
    }

    /// Test that payload encoding matches Python's msgpack exactly.
    ///
    /// Python reference (LXMF/LXMessage.py pack() method):
    /// ```python
    /// payload = [timestamp, title, content, fields]
    /// msgpack.packb(payload)
    /// ```
    ///
    /// For timestamp=1234567890.123456, title=b"greet", content=b"hello", fields={}:
    /// Python produces: 94cb41d26580b487e6b4c4056772656574c40568656c6c6f80
    ///
    /// For same with fields={"lang": b"rust"}:
    /// Python produces: 94cb41d26580b487e6b4c4056772656574c40568656c6c6f81a46c616e67c40472757374
    #[test]
    fn payload_encoding_matches_python() {
        // Create a message with specific timestamp
        let mut message = sample_message();

        // Set empty fields and specific timestamp to match Python test case
        message.payload.fields = IndexMap::new();
        message.payload.timestamp = 1234567890.123456;
        message.payload.title = b"greet".to_vec();
        message.payload.content = b"hello".to_vec();

        let encoded = message.encode_payload_bytes(false).unwrap();
        let expected: Vec<u8> = vec![
            0x94, // fixarray(4)
            0xcb, 0x41, 0xd2, 0x65, 0x80, 0xb4, 0x87, 0xe6, 0xb4, // float64 timestamp
            0xc4, 0x05, 0x67, 0x72, 0x65, 0x65, 0x74, // bin8 "greet"
            0xc4, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, // bin8 "hello"
            0x80, // fixmap(0) - empty dict
        ];

        assert_eq!(
            encoded, expected,
            "Empty fields payload mismatch.\nRust:   {:02x?}\nPython: {:02x?}",
            encoded, expected
        );

        // Test with field entry
        let mut fields = IndexMap::new();
        fields.insert("lang".into(), b"rust".to_vec());
        message.payload.fields = fields;

        let encoded_with_field = message.encode_payload_bytes(false).unwrap();
        let expected_with_field: Vec<u8> = vec![
            0x94, // fixarray(4)
            0xcb, 0x41, 0xd2, 0x65, 0x80, 0xb4, 0x87, 0xe6, 0xb4, // float64 timestamp
            0xc4, 0x05, 0x67, 0x72, 0x65, 0x65, 0x74, // bin8 "greet"
            0xc4, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, // bin8 "hello"
            0x81, // fixmap(1)
            0xa4, 0x6c, 0x61, 0x6e, 0x67, // fixstr "lang"
            0xc4, 0x04, 0x72, 0x75, 0x73, 0x74, // bin8 "rust"
        ];

        assert_eq!(
            encoded_with_field, expected_with_field,
            "Fields payload mismatch.\nRust:   {:02x?}\nPython: {:02x?}",
            encoded_with_field, expected_with_field
        );
    }

    #[test]
    fn pack_and_unpack_roundtrip() {
        let mut message = sample_message();
        let packed = message.pack().expect("pack successful").to_vec();
        assert!(packed.len() > 0);

        let unpacked = LXMessage::unpack_from_bytes(&packed).expect("unpack");
        assert_eq!(unpacked.payload.content, b"hello".to_vec());
        assert_eq!(unpacked.payload.title, b"greet".to_vec());
        assert_eq!(unpacked.payload.fields.get("lang"), Some(&b"rust".to_vec()));
    }

    #[test]
    fn stamping_preserves_message_hash() {
        let mut message = sample_message();
        message.pack().expect("pack");
        let first_hash = message.message_hash().expect("hash").as_slice().to_vec();

        message.set_stamp(Some(vec![0xAA; HASH_SIZE]));
        message.pack().expect("repack");
        let second_hash = message.message_hash().expect("hash").as_slice().to_vec();

        assert_eq!(first_hash, second_hash);
    }

    #[test]
    fn stamp_is_encoded_in_payload() {
        let mut message = sample_message();
        message.pack().expect("initial pack");
        message.set_stamp(Some(vec![0x55; HASH_SIZE]));
        message.pack().expect("repack with stamp");
        let packed = message.pack().expect("final pack").to_vec();

        let decoded = LXMessage::unpack_from_bytes(&packed).expect("unpack");
        assert!(decoded.stamp().is_some());
        assert_eq!(decoded.stamp().unwrap().len(), HASH_SIZE);
    }

    /// Test that message hash computation matches Python's RNS.Identity.full_hash.
    ///
    /// Python reference:
    /// ```python
    /// hashed_part = b"" + destination_hash + source_hash + msgpack.packb(payload)
    /// self.hash = RNS.Identity.full_hash(hashed_part)  # SHA-256
    /// ```
    ///
    /// For destination_hash=0x00*16, source_hash=0x00*16,
    /// payload=[1234567890.123456, b"greet", b"hello", {}]:
    /// Python produces: 7dab36ed1047be956098ade44e1966b21ce8dd469648e711e43611c90790838f
    #[test]
    fn message_hash_matches_python() {
        use reticulum::hash::Hash;

        // Use known input data
        let destination_hash = AddressHash::new([0u8; 16]);
        let source_hash = AddressHash::new([0u8; 16]);

        let timestamp = 1234567890.123456;
        let title = b"greet".to_vec();
        let content = b"hello".to_vec();
        let fields = IndexMap::new();

        let payload = LxPayload::from_parts(timestamp, title, content, fields);

        // Encode payload
        let mut buf = Vec::new();
        encode::write_array_len(&mut buf, 4).unwrap();
        encode::write_f64(&mut buf, payload.timestamp).unwrap();
        write_bin(&mut buf, &payload.title).unwrap();
        write_bin(&mut buf, &payload.content).unwrap();
        encode::write_map_len(&mut buf, payload.fields.len() as u32).unwrap();

        // Build hashed_part
        let mut hashed_part_data = Vec::new();
        hashed_part_data.extend_from_slice(destination_hash.as_slice());
        hashed_part_data.extend_from_slice(source_hash.as_slice());
        hashed_part_data.extend_from_slice(&buf);

        // Compute hash using the same method as pack()
        let message_hash = Hash::new_from_slice(&hashed_part_data);

        // Python reference hash
        let expected_hex = "7dab36ed1047be956098ade44e1966b21ce8dd469648e711e43611c90790838f";
        let expected: Vec<u8> = (0..expected_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected_hex[i..i + 2], 16).unwrap())
            .collect();

        assert_eq!(
            message_hash.as_slice(),
            expected.as_slice(),
            "Message hash mismatch.\nRust:   {:02x?}\nPython: {:02x?}",
            message_hash.as_slice(),
            expected.as_slice()
        );
    }

    /// Test that unpacking a message with stamp produces the same hash as without stamp.
    ///
    /// This is critical for stamp validation: Python's receiver extracts the stamp,
    /// re-packs the payload without the stamp, and computes the hash from that.
    /// The Rust implementation must produce the same message_id.
    ///
    /// Python reference (LXMessage.unpack_from_bytes):
    /// ```python
    /// if len(unpacked_payload) > 4:
    ///     stamp = unpacked_payload[4]
    ///     unpacked_payload = unpacked_payload[:4]
    ///     packed_payload = msgpack.packb(unpacked_payload)  # Re-pack without stamp
    /// hashed_part = b"" + destination_hash + source_hash + packed_payload
    /// message_hash = RNS.Identity.full_hash(hashed_part)
    /// ```
    #[test]
    fn unpack_message_with_stamp_produces_same_hash() {
        use reticulum::hash::HASH_SIZE;

        // Build a packed message: dest_hash + src_hash + signature + payload_with_stamp
        let destination_hash = [0u8; 16];
        let source_hash = [0u8; 16];
        let fake_signature = [0u8; 64];

        // Known payload values
        let timestamp = 1234567890.123456;
        let title = b"greet";
        let content = b"hello";
        let stamp = [0xab_u8; HASH_SIZE]; // Dummy stamp

        // Encode payload WITH stamp (5 elements)
        let mut payload_with_stamp = Vec::new();
        encode::write_array_len(&mut payload_with_stamp, 5).unwrap();
        encode::write_f64(&mut payload_with_stamp, timestamp).unwrap();
        write_bin(&mut payload_with_stamp, title).unwrap();
        write_bin(&mut payload_with_stamp, content).unwrap();
        encode::write_map_len(&mut payload_with_stamp, 0).unwrap(); // empty fields
        write_bin(&mut payload_with_stamp, &stamp).unwrap();

        // Build full LXMF message bytes
        let mut lxmf_bytes = Vec::new();
        lxmf_bytes.extend_from_slice(&destination_hash);
        lxmf_bytes.extend_from_slice(&source_hash);
        lxmf_bytes.extend_from_slice(&fake_signature);
        lxmf_bytes.extend_from_slice(&payload_with_stamp);

        // Unpack the message
        let unpacked = LXMessage::unpack_from_bytes(&lxmf_bytes).expect("unpack should succeed");

        // Verify stamp was extracted
        assert!(unpacked.stamp().is_some());
        assert_eq!(unpacked.stamp().unwrap(), &stamp);

        // Compute expected hash: same as payload WITHOUT stamp
        // This is what Python would compute
        let mut payload_without_stamp = Vec::new();
        encode::write_array_len(&mut payload_without_stamp, 4).unwrap();
        encode::write_f64(&mut payload_without_stamp, timestamp).unwrap();
        write_bin(&mut payload_without_stamp, title).unwrap();
        write_bin(&mut payload_without_stamp, content).unwrap();
        encode::write_map_len(&mut payload_without_stamp, 0).unwrap();

        let mut hashed_part_expected = Vec::new();
        hashed_part_expected.extend_from_slice(&destination_hash);
        hashed_part_expected.extend_from_slice(&source_hash);
        hashed_part_expected.extend_from_slice(&payload_without_stamp);

        use reticulum::hash::Hash;
        let expected_hash = Hash::new_from_slice(&hashed_part_expected);

        // Verify the unpacked message has the correct hash
        let actual_hash = unpacked.message_hash().expect("should have hash");
        assert_eq!(
            actual_hash.as_slice(),
            expected_hash.as_slice(),
            "Unpacked message hash should match hash of payload without stamp.\nActual:   {:02x?}\nExpected: {:02x?}",
            actual_hash.as_slice(),
            expected_hash.as_slice()
        );
    }
}
