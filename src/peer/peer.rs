use std::collections::VecDeque;

use indexmap::{IndexMap, IndexSet};
use reticulum::hash::{ADDRESS_HASH_SIZE, AddressHash};
use serde::{Deserialize, Serialize};

use super::PeerError;

pub const OFFER_REQUEST_PATH: &str = "/offer";
pub const MESSAGE_GET_PATH: &str = "/get";

pub const MAX_UNREACHABLE_S: f64 = 14.0 * 24.0 * 60.0 * 60.0;
pub const SYNC_BACKOFF_STEP_S: f64 = 12.0 * 60.0;
pub const PATH_REQUEST_GRACE_S: f64 = 7.5;

pub const PN_META_NAME: u8 = 0x01;

pub const TRANSIENT_ID_LEN: usize = 32;
pub type TransientId = [u8; TRANSIENT_ID_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Idle = 0x00,
    LinkEstablishing = 0x01,
    LinkReady = 0x02,
    RequestSent = 0x03,
    ResponseReceived = 0x04,
    ResourceTransferring = 0x05,
}

impl Default for PeerState {
    fn default() -> Self {
        PeerState::Idle
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerErrorCode {
    NoIdentity = 0xf0,
    NoAccess = 0xf1,
    InvalidKey = 0xf3,
    InvalidData = 0xf4,
    InvalidStamp = 0xf5,
    Throttled = 0xf6,
    NotFound = 0xfd,
    Timeout = 0xfe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStrategy {
    Lazy = 0x01,
    Persistent = 0x02,
}

impl SyncStrategy {
    pub const DEFAULT: SyncStrategy = SyncStrategy::Persistent;

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0x01 => SyncStrategy::Lazy,
            0x02 => SyncStrategy::Persistent,
            _ => SyncStrategy::DEFAULT,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            SyncStrategy::Lazy => 0x01,
            SyncStrategy::Persistent => 0x02,
        }
    }
}

impl Default for SyncStrategy {
    fn default() -> Self {
        SyncStrategy::DEFAULT
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeeringKey {
    pub stamp: Vec<u8>,
    pub value: u32,
}

impl PeeringKey {
    pub fn new(stamp: Vec<u8>, value: u32) -> Self {
        Self { stamp, value }
    }

    pub fn is_sufficient(&self, required: u32) -> bool {
        self.value >= required
    }
}

pub type PeerMetadata = IndexMap<u8, Vec<u8>>;

#[derive(Debug, Clone)]
pub struct LxmPeer {
    destination_hash: AddressHash,
    alive: bool,
    last_heard: f64,
    sync_strategy: SyncStrategy,
    peering_key: Option<PeeringKey>,
    peering_cost: Option<u32>,
    metadata: Option<PeerMetadata>,

    next_sync_attempt: f64,
    last_sync_attempt: f64,
    sync_backoff: f64,
    peering_timebase: f64,
    link_establishment_rate: f64,
    sync_transfer_rate: f64,

    propagation_transfer_limit: Option<f64>,
    propagation_sync_limit: Option<f64>,
    propagation_stamp_cost: Option<u32>,
    propagation_stamp_cost_flexibility: Option<u32>,

    currently_transferring_messages: Option<Vec<TransientId>>,
    handled_messages: IndexSet<TransientId>,
    unhandled_messages: IndexSet<TransientId>,
    handled_messages_queue: VecDeque<TransientId>,
    unhandled_messages_queue: VecDeque<TransientId>,

    offered: u64,
    outgoing: u64,
    incoming: u64,
    rx_bytes: u64,
    tx_bytes: u64,

    hm_count: usize,
    um_count: usize,
    hm_counts_synced: bool,
    um_counts_synced: bool,

    state: PeerState,
    last_offer: Vec<TransientId>,
}

impl LxmPeer {
    pub fn new(destination_hash: AddressHash, sync_strategy: SyncStrategy) -> Self {
        Self {
            destination_hash,
            alive: false,
            last_heard: 0.0,
            sync_strategy,
            peering_key: None,
            peering_cost: None,
            metadata: None,
            next_sync_attempt: 0.0,
            last_sync_attempt: 0.0,
            sync_backoff: 0.0,
            peering_timebase: 0.0,
            link_establishment_rate: 0.0,
            sync_transfer_rate: 0.0,
            propagation_transfer_limit: None,
            propagation_sync_limit: None,
            propagation_stamp_cost: None,
            propagation_stamp_cost_flexibility: None,
            currently_transferring_messages: None,
            handled_messages: IndexSet::new(),
            unhandled_messages: IndexSet::new(),
            handled_messages_queue: VecDeque::new(),
            unhandled_messages_queue: VecDeque::new(),
            offered: 0,
            outgoing: 0,
            incoming: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            hm_count: 0,
            um_count: 0,
            hm_counts_synced: true,
            um_counts_synced: true,
            state: PeerState::Idle,
            last_offer: Vec::new(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PeerError> {
        let snapshot: PeerSnapshot = rmp_serde::from_slice(bytes)?;
        let destination_hash = vec_to_address_hash(snapshot.destination_hash)?;
        let handled_messages = decode_transient_ids(snapshot.handled_ids)?;
        let unhandled_messages = decode_transient_ids(snapshot.unhandled_ids)?;

        let sync_strategy = snapshot
            .sync_strategy
            .map(SyncStrategy::from_u8)
            .unwrap_or(SyncStrategy::DEFAULT);

        let peering_key = snapshot
            .peering_key
            .map(|(stamp, value)| PeeringKey::new(stamp, value));

        let propagation_sync_limit = snapshot
            .propagation_sync_limit
            .or(snapshot.propagation_transfer_limit);

        let mut peer = Self {
            destination_hash,
            alive: snapshot.alive,
            last_heard: snapshot.last_heard,
            sync_strategy,
            peering_key,
            peering_cost: snapshot.peering_cost,
            metadata: snapshot.metadata,
            next_sync_attempt: 0.0,
            last_sync_attempt: snapshot.last_sync_attempt,
            sync_backoff: 0.0,
            peering_timebase: snapshot.peering_timebase,
            link_establishment_rate: snapshot.link_establishment_rate,
            sync_transfer_rate: snapshot.sync_transfer_rate,
            propagation_transfer_limit: snapshot.propagation_transfer_limit,
            propagation_sync_limit,
            propagation_stamp_cost: snapshot.propagation_stamp_cost,
            propagation_stamp_cost_flexibility: snapshot.propagation_stamp_cost_flexibility,
            currently_transferring_messages: None,
            handled_messages,
            unhandled_messages,
            handled_messages_queue: VecDeque::new(),
            unhandled_messages_queue: VecDeque::new(),
            offered: snapshot.offered,
            outgoing: snapshot.outgoing,
            incoming: snapshot.incoming,
            rx_bytes: snapshot.rx_bytes,
            tx_bytes: snapshot.tx_bytes,
            hm_count: 0,
            um_count: 0,
            hm_counts_synced: false,
            um_counts_synced: false,
            state: PeerState::Idle,
            last_offer: Vec::new(),
        };

        peer.recompute_counts();
        Ok(peer)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PeerError> {
        let snapshot = PeerSnapshot {
            destination_hash: self.destination_hash.as_slice().to_vec(),
            peering_timebase: self.peering_timebase,
            alive: self.alive,
            last_heard: self.last_heard,
            metadata: self.metadata.clone(),
            sync_strategy: Some(self.sync_strategy.as_u8()),
            peering_key: self
                .peering_key
                .as_ref()
                .map(|key| (key.stamp.clone(), key.value)),
            link_establishment_rate: self.link_establishment_rate,
            sync_transfer_rate: self.sync_transfer_rate,
            propagation_transfer_limit: self.propagation_transfer_limit,
            propagation_sync_limit: self.propagation_sync_limit,
            propagation_stamp_cost: self.propagation_stamp_cost,
            propagation_stamp_cost_flexibility: self.propagation_stamp_cost_flexibility,
            peering_cost: self.peering_cost,
            last_sync_attempt: self.last_sync_attempt,
            offered: self.offered,
            outgoing: self.outgoing,
            incoming: self.incoming,
            rx_bytes: self.rx_bytes,
            tx_bytes: self.tx_bytes,
            handled_ids: self.handled_messages.iter().map(|id| id.to_vec()).collect(),
            unhandled_ids: self
                .unhandled_messages
                .iter()
                .map(|id| id.to_vec())
                .collect(),
        };

        Ok(rmp_serde::to_vec_named(&snapshot)?)
    }

    pub fn destination_hash(&self) -> &AddressHash {
        &self.destination_hash
    }

    pub fn state(&self) -> PeerState {
        self.state
    }

    pub fn set_state(&mut self, state: PeerState) {
        self.state = state;
    }

    pub fn sync_strategy(&self) -> SyncStrategy {
        self.sync_strategy
    }

    pub fn set_sync_strategy(&mut self, strategy: SyncStrategy) {
        self.sync_strategy = strategy;
    }

    pub fn metadata(&self) -> Option<&PeerMetadata> {
        self.metadata.as_ref()
    }

    pub fn metadata_mut(&mut self) -> &mut Option<PeerMetadata> {
        &mut self.metadata
    }

    pub fn set_metadata(&mut self, metadata: Option<PeerMetadata>) {
        self.metadata = metadata;
    }

    pub fn display_name(&self) -> Option<String> {
        self.metadata
            .as_ref()
            .and_then(|meta| meta.get(&PN_META_NAME))
            .and_then(|value| String::from_utf8(value.clone()).ok())
    }

    pub fn alive(&self) -> bool {
        self.alive
    }

    pub fn set_alive(&mut self, alive: bool) {
        self.alive = alive;
    }

    pub fn last_heard(&self) -> f64 {
        self.last_heard
    }

    pub fn set_last_heard(&mut self, ts: f64) {
        self.last_heard = ts;
    }

    pub fn peering_cost(&self) -> Option<u32> {
        self.peering_cost
    }

    pub fn set_peering_cost(&mut self, cost: Option<u32>) {
        self.peering_cost = cost;
    }

    pub fn peering_key(&self) -> Option<&PeeringKey> {
        self.peering_key.as_ref()
    }

    pub fn set_peering_key(&mut self, key: Option<PeeringKey>) {
        self.peering_key = key;
    }

    pub fn reset_sync_backoff(&mut self) {
        self.sync_backoff = 0.0;
        self.next_sync_attempt = 0.0;
    }

    pub fn increase_sync_backoff(&mut self) {
        self.sync_backoff += SYNC_BACKOFF_STEP_S;
        self.next_sync_attempt = self.last_sync_attempt + self.sync_backoff;
    }

    pub fn next_sync_attempt(&self) -> f64 {
        self.next_sync_attempt
    }

    pub fn set_next_sync_attempt(&mut self, ts: f64) {
        self.next_sync_attempt = ts;
    }

    pub fn queue_unhandled_message(&mut self, transient_id: TransientId) {
        self.unhandled_messages_queue.push_back(transient_id);
    }

    pub fn queue_handled_message(&mut self, transient_id: TransientId) {
        self.handled_messages_queue.push_back(transient_id);
    }

    pub fn queued_items(&self) -> bool {
        !(self.handled_messages_queue.is_empty() && self.unhandled_messages_queue.is_empty())
    }

    pub fn process_queues(&mut self) {
        while let Some(id) = self.handled_messages_queue.pop_front() {
            self.add_handled_message(id);
        }

        while let Some(id) = self.unhandled_messages_queue.pop_front() {
            if !self.handled_messages.contains(&id) {
                self.add_unhandled_message(id);
            }
        }
    }

    pub fn handled_ids(&self) -> impl Iterator<Item = &TransientId> {
        self.handled_messages.iter()
    }

    pub fn unhandled_ids(&self) -> impl Iterator<Item = &TransientId> {
        self.unhandled_messages.iter()
    }

    pub fn handled_message_count(&self) -> usize {
        if self.hm_counts_synced {
            self.hm_count
        } else {
            self.handled_messages.len()
        }
    }

    pub fn unhandled_message_count(&self) -> usize {
        if self.um_counts_synced {
            self.um_count
        } else {
            self.unhandled_messages.len()
        }
    }

    pub fn acceptance_rate(&self) -> f64 {
        if self.offered == 0 {
            0.0
        } else {
            self.outgoing as f64 / self.offered as f64
        }
    }

    pub fn add_handled_message(&mut self, transient_id: TransientId) {
        let inserted = self.handled_messages.insert(transient_id);
        let removed = self.unhandled_messages.swap_remove(&transient_id);
        if inserted || removed {
            self.recompute_counts();
        }
    }

    pub fn add_unhandled_message(&mut self, transient_id: TransientId) {
        if self.handled_messages.contains(&transient_id) {
            return;
        }
        if self.unhandled_messages.insert(transient_id) {
            self.recompute_counts();
        }
    }

    pub fn remove_unhandled_message(&mut self, transient_id: &TransientId) {
        if self.unhandled_messages.swap_remove(transient_id) {
            self.recompute_counts();
        }
    }

    pub fn remove_handled_message(&mut self, transient_id: &TransientId) {
        if self.handled_messages.swap_remove(transient_id) {
            self.recompute_counts();
        }
    }

    pub fn last_offer(&self) -> &[TransientId] {
        &self.last_offer
    }

    pub fn set_last_offer(&mut self, offer: Vec<TransientId>) {
        self.last_offer = offer;
    }

    pub fn currently_transferring(&self) -> Option<&[TransientId]> {
        self.currently_transferring_messages
            .as_ref()
            .map(|ids| ids.as_slice())
    }

    pub fn set_currently_transferring(&mut self, ids: Option<Vec<TransientId>>) {
        self.currently_transferring_messages = ids;
    }

    fn recompute_counts(&mut self) {
        self.hm_count = self.handled_messages.len();
        self.um_count = self.unhandled_messages.len();
        self.hm_counts_synced = true;
        self.um_counts_synced = true;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerSnapshot {
    destination_hash: Vec<u8>,
    #[serde(default)]
    peering_timebase: f64,
    #[serde(default)]
    alive: bool,
    #[serde(default)]
    last_heard: f64,
    #[serde(default)]
    metadata: Option<PeerMetadata>,
    #[serde(default)]
    sync_strategy: Option<u8>,
    #[serde(default)]
    peering_key: Option<(Vec<u8>, u32)>,
    #[serde(default)]
    link_establishment_rate: f64,
    #[serde(default)]
    sync_transfer_rate: f64,
    #[serde(default)]
    propagation_transfer_limit: Option<f64>,
    #[serde(default)]
    propagation_sync_limit: Option<f64>,
    #[serde(default)]
    propagation_stamp_cost: Option<u32>,
    #[serde(default)]
    propagation_stamp_cost_flexibility: Option<u32>,
    #[serde(default)]
    peering_cost: Option<u32>,
    #[serde(default)]
    last_sync_attempt: f64,
    #[serde(default)]
    offered: u64,
    #[serde(default)]
    outgoing: u64,
    #[serde(default)]
    incoming: u64,
    #[serde(default)]
    rx_bytes: u64,
    #[serde(default)]
    tx_bytes: u64,
    #[serde(default)]
    handled_ids: Vec<Vec<u8>>,
    #[serde(default)]
    unhandled_ids: Vec<Vec<u8>>,
}

fn vec_to_address_hash(bytes: Vec<u8>) -> Result<AddressHash, PeerError> {
    if bytes.len() != ADDRESS_HASH_SIZE {
        return Err(PeerError::AddressHashLength(bytes.len()));
    }
    let mut arr = [0u8; ADDRESS_HASH_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(AddressHash::new(arr))
}

fn decode_transient_ids(values: Vec<Vec<u8>>) -> Result<IndexSet<TransientId>, PeerError> {
    let mut set = IndexSet::with_capacity(values.len());
    for bytes in values {
        if bytes.len() != TRANSIENT_ID_LEN {
            return Err(PeerError::TransientIdLength(bytes.len()));
        }
        let mut id = [0u8; TRANSIENT_ID_LEN];
        id.copy_from_slice(&bytes);
        set.insert(id);
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash(byte: u8) -> AddressHash {
        let mut raw = [0u8; ADDRESS_HASH_SIZE];
        raw.fill(byte);
        AddressHash::new(raw)
    }

    fn sample_id(byte: u8) -> TransientId {
        let mut raw = [0u8; TRANSIENT_ID_LEN];
        raw.fill(byte);
        raw
    }

    #[test]
    fn peer_roundtrip() {
        let mut peer = LxmPeer::new(sample_hash(0xAA), SyncStrategy::Persistent);
        peer.set_last_heard(42.0);
        peer.set_alive(true);

        peer.add_unhandled_message(sample_id(0x01));
        peer.add_handled_message(sample_id(0x02));
        peer.set_peering_cost(Some(10));
        peer.set_peering_key(Some(PeeringKey::new(vec![0u8; 16], 11)));

        let mut metadata = PeerMetadata::new();
        metadata.insert(PN_META_NAME, b"Relay".to_vec());
        peer.set_metadata(Some(metadata));

        let encoded = peer.to_bytes().expect("serialize peer");
        let decoded = LxmPeer::from_bytes(&encoded).expect("deserialize peer");

        assert_eq!(decoded.destination_hash(), peer.destination_hash());
        assert!(decoded.alive());
        assert_eq!(decoded.display_name().as_deref(), Some("Relay"));
        assert_eq!(decoded.unhandled_message_count(), 1);
        assert_eq!(decoded.handled_message_count(), 1);
        assert_eq!(decoded.peering_cost(), Some(10));
        assert_eq!(decoded.peering_key().unwrap().value, 11);
    }
}
