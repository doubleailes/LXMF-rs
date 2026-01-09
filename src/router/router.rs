//! LXMRouter — structural port of the Python LXMF router.
//!
//! This implementation focuses on mirroring Python's stateful behaviour:
//! * persistent caches (delivered IDs, tickets, stamp costs)
//! * peer bookkeeping, including on-disk snapshots
//! * configurable limits and policy toggles
//! * periodic background work similar to the original job loop
//!
//! The actual Reticulum integrations (announce handlers, link callbacks,
//! propagation transfers) are intentionally left as TODOs so that the
//! state layer can stabilise first.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::{debug, error, info, trace, warn};
use rand_core::OsRng;
use reticulum::{
    destination::link::LinkEvent,
    destination::{DestinationName, SingleInputDestination},
    error::RnsError,
    hash::{ADDRESS_HASH_SIZE, AddressHash},
    identity::PrivateIdentity,
    packet::PacketContext,
    transport::Transport,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use crate::{
    LXMessage, LxmPeer, PeerMetadata, SyncStrategy,
    message::{
        MessageError,
        message::State,
        stamp::{StampError, StampParameters, generate_stamp},
    },
};

use super::error::RouterError;
use super::handlers::{
    LXMFDeliveryAnnounceHandler, LXMFPropagationAnnounceHandler, PropagationNodeAnnounceData,
};

pub const APP_NAME: &str = "lxmf";
pub const DELIVERY_ASPECT: &str = "delivery";
pub const PROPAGATION_ASPECT: &str = "propagation";

pub const MAX_DELIVERY_ATTEMPTS: u8 = 5;
pub const PROCESSING_INTERVAL: Duration = Duration::from_secs(4);
pub const DELIVERY_RETRY_WAIT: Duration = Duration::from_secs(10);
pub const PATH_REQUEST_WAIT: Duration = Duration::from_secs(7);
pub const MESSAGE_EXPIRY_S: f64 = 30.0 * 24.0 * 60.0 * 60.0;
pub const STAMP_COST_EXPIRY_S: f64 = 45.0 * 24.0 * 60.0 * 60.0;

pub const JOB_OUTBOUND_INTERVAL: u64 = 1;
pub const JOB_TRANSIENT_INTERVAL: u64 = 60;
pub const JOB_STORE_INTERVAL: u64 = 120;
pub const JOB_PEERSYNC_INTERVAL: u64 = 6;
pub const JOB_ROTATE_INTERVAL: u64 = 56 * JOB_PEERSYNC_INTERVAL;

pub const PN_META_NAME: u8 = 0x01;
const TRANSIENT_ID_LEN: usize = 32;

type TransientId = [u8; TRANSIENT_ID_LEN];
type Timestamp = f64;

/// Extract stamp_cost from LXMF delivery announce app_data.
///
/// Decodes Python LXMF 0.5.0+ format: msgpack array [display_name, stamp_cost]
/// Returns None if app_data is empty, invalid, or uses the legacy format.
///
/// References Python LXMF/LXMF.py stamp_cost_from_app_data()
pub fn stamp_cost_from_app_data(app_data: &[u8]) -> Option<u8> {
    if app_data.is_empty() {
        return None;
    }

    // Version 0.5.0+ announce format uses msgpack fixarray (0x90-0x9f) or array16 (0xdc)
    let first_byte = app_data[0];
    if !((0x90..=0x9f).contains(&first_byte) || first_byte == 0xdc) {
        // Legacy format (raw display name string), no stamp cost
        return None;
    }

    // Decode msgpack array using rmpv
    let mut cursor = std::io::Cursor::new(app_data);
    let peer_data = rmpv::decode::read_value(&mut cursor).ok()?;

    if let rmpv::Value::Array(arr) = peer_data {
        if arr.len() < 2 {
            return None;
        }
        // slot 1 is stamp_cost
        match &arr[1] {
            rmpv::Value::Integer(n) => n.as_u64().and_then(|v| u8::try_from(v).ok()),
            _ => None,
        }
    } else {
        None
    }
}

/// Extract display_name from LXMF delivery announce app_data.
///
/// Decodes both Python LXMF 0.5.0+ format (msgpack array) and legacy format (raw string).
///
/// References Python LXMF/LXMF.py display_name_from_app_data()
pub fn display_name_from_app_data(app_data: &[u8]) -> Option<String> {
    if app_data.is_empty() {
        return None;
    }

    let first_byte = app_data[0];
    if (0x90..=0x9f).contains(&first_byte) || first_byte == 0xdc {
        // Version 0.5.0+ announce format
        let mut cursor = std::io::Cursor::new(app_data);
        let peer_data = rmpv::decode::read_value(&mut cursor).ok()?;

        if let rmpv::Value::Array(arr) = peer_data {
            if arr.is_empty() {
                return None;
            }
            match &arr[0] {
                rmpv::Value::Binary(bytes) => String::from_utf8(bytes.clone()).ok(),
                rmpv::Value::String(s) => Some(s.as_str()?.to_string()),
                _ => None,
            }
        } else {
            None
        }
    } else {
        // Legacy format: raw UTF-8 display name
        String::from_utf8(app_data.to_vec()).ok()
    }
}

/// Validate and extract data from a propagation node announce.
///
/// Returns `Some(PropagationNodeAnnounceData)` if the announce data is valid,
/// `None` otherwise.
///
/// References Python LXMF/LXMF.py pn_announce_data_is_valid()
pub fn pn_announce_data_is_valid(app_data: &[u8]) -> Option<PropagationNodeAnnounceData> {
    if app_data.is_empty() {
        return None;
    }

    // Decode msgpack array
    let mut cursor = std::io::Cursor::new(app_data);
    let data = rmpv::decode::read_value(&mut cursor).ok()?;

    let arr = match data {
        rmpv::Value::Array(arr) => arr,
        _ => return None,
    };

    // Must have at least 7 elements for v0.5.0+ format
    if arr.len() < 7 {
        trace!(
            "Invalid announce data: Insufficient peer data, likely from deprecated LXMF version"
        );
        return None;
    }

    // slot 1: timebase (integer) - convert to f64
    let timebase = match &arr[1] {
        rmpv::Value::Integer(n) => n.as_i64()? as f64,
        _ => return None,
    };

    // slot 2: propagation node state (boolean)
    let node_state = match &arr[2] {
        rmpv::Value::Boolean(b) => *b,
        _ => return None,
    };

    // slot 3: transfer limit (integer) - convert to f64 bytes
    // Python stores this in kilobytes, so multiply by 1000
    let transfer_limit = match &arr[3] {
        rmpv::Value::Integer(n) => Some((n.as_u64()? as f64) * 1000.0),
        rmpv::Value::Nil => None,
        _ => return None,
    };

    // slot 4: sync limit (integer) - convert to f64 bytes
    let sync_limit = match &arr[4] {
        rmpv::Value::Integer(n) => Some((n.as_u64()? as f64) * 1000.0),
        rmpv::Value::Nil => None,
        _ => return None,
    };

    // slot 5: stamp costs array [stamp_cost, stamp_flexibility, peering_cost]
    let stamp_costs = match &arr[5] {
        rmpv::Value::Array(costs) if costs.len() >= 3 => costs,
        _ => return None,
    };

    let stamp_cost = match &stamp_costs[0] {
        rmpv::Value::Integer(n) => Some(n.as_u64()? as u32),
        rmpv::Value::Nil => None,
        _ => return None,
    };

    let stamp_flexibility = match &stamp_costs[1] {
        rmpv::Value::Integer(n) => Some(n.as_u64()? as u32),
        rmpv::Value::Nil => None,
        _ => return None,
    };

    let peering_cost = match &stamp_costs[2] {
        rmpv::Value::Integer(n) => Some(n.as_u64()? as u32),
        rmpv::Value::Nil => None,
        _ => return None,
    };

    // slot 6: metadata (map) - use IndexMap for PeerMetadata compatibility
    let metadata = match &arr[6] {
        rmpv::Value::Map(map) => {
            let mut result = indexmap::IndexMap::new();
            for (k, v) in map {
                if let (rmpv::Value::Integer(key), rmpv::Value::Binary(val)) = (k, v)
                    && let Some(key_u8) = key.as_u64().and_then(|n| u8::try_from(n).ok())
                {
                    result.insert(key_u8, val.clone());
                }
            }
            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        }
        _ => None,
    };

    Some(PropagationNodeAnnounceData {
        timebase,
        node_state,
        transfer_limit,
        sync_limit,
        stamp_cost,
        stamp_flexibility,
        peering_cost,
        metadata,
    })
}

/// Extract propagation node name from metadata.
///
/// References Python LXMF/LXMF.py pn_name_from_app_data()
pub fn pn_name_from_app_data(app_data: &[u8]) -> Option<String> {
    let pn_data = pn_announce_data_is_valid(app_data)?;
    let metadata = pn_data.metadata.as_ref()?;
    let name_bytes = metadata.get(&PN_META_NAME)?;
    String::from_utf8(name_bytes.clone()).ok()
}

/// Router configuration mirrors the Python arguments.
#[derive(Clone)]
pub struct RouterConfig {
    pub storage_root: PathBuf,
    pub identity: Option<PrivateIdentity>,
    pub autopeer: bool,
    pub autopeer_maxdepth: u8,
    pub propagation_limit_kb: u32,
    pub delivery_limit_kb: u32,
    pub sync_limit_kb: u32,
    pub enforce_ratchets: bool,
    pub enforce_stamps: bool,
    pub static_peers: Vec<AddressHash>,
    pub max_peers: usize,
    pub from_static_only: bool,
    pub default_sync_strategy: SyncStrategy,
    pub propagation_cost: u32,
    pub propagation_cost_flex: u32,
    pub peering_cost: u32,
    pub max_peering_cost: u32,
    pub name: Option<String>,
}

impl fmt::Debug for RouterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterConfig")
            .field("storage_root", &self.storage_root)
            .field("identity_set", &self.identity.is_some())
            .field("autopeer", &self.autopeer)
            .field("autopeer_maxdepth", &self.autopeer_maxdepth)
            .field("propagation_limit_kb", &self.propagation_limit_kb)
            .field("delivery_limit_kb", &self.delivery_limit_kb)
            .field("sync_limit_kb", &self.sync_limit_kb)
            .field("enforce_ratchets", &self.enforce_ratchets)
            .field("enforce_stamps", &self.enforce_stamps)
            .field("static_peers", &self.static_peers)
            .field("max_peers", &self.max_peers)
            .field("from_static_only", &self.from_static_only)
            .field("default_sync_strategy", &self.default_sync_strategy)
            .field("propagation_cost", &self.propagation_cost)
            .field("propagation_cost_flex", &self.propagation_cost_flex)
            .field("peering_cost", &self.peering_cost)
            .field("max_peering_cost", &self.max_peering_cost)
            .field("name", &self.name)
            .finish()
    }
}

impl RouterConfig {
    pub fn new(storage_root: impl Into<PathBuf>) -> Self {
        Self {
            storage_root: storage_root.into(),
            identity: None,
            autopeer: true,
            autopeer_maxdepth: 4,
            propagation_limit_kb: 256,
            delivery_limit_kb: 1000,
            sync_limit_kb: 256 * 40,
            enforce_ratchets: false,
            enforce_stamps: false,
            static_peers: Vec::new(),
            max_peers: 20,
            from_static_only: false,
            default_sync_strategy: SyncStrategy::Persistent,
            propagation_cost: 16,
            propagation_cost_flex: 3,
            peering_cost: 18,
            max_peering_cost: 26,
            name: None,
        }
    }

    fn validate(&self) -> Result<(), RouterError> {
        if self.storage_root.as_os_str().is_empty() {
            return Err(RouterError::MissingStoragePath);
        }

        for peer in &self.static_peers {
            if peer.as_slice().len() != ADDRESS_HASH_SIZE {
                return Err(RouterError::InvalidHashLength {
                    expected: ADDRESS_HASH_SIZE,
                    got: peer.as_slice().len(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RouterPaths {
    root: PathBuf,
}

impl RouterPaths {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn lxmf_root(&self) -> PathBuf {
        self.root.join("lxmf")
    }

    fn ratchet_dir(&self) -> PathBuf {
        self.lxmf_root().join("ratchets")
    }

    fn message_store(&self) -> PathBuf {
        self.lxmf_root().join("messagestore")
    }

    fn local_deliveries_file(&self) -> PathBuf {
        self.lxmf_root().join("local_deliveries")
    }

    fn locally_processed_file(&self) -> PathBuf {
        self.lxmf_root().join("locally_processed")
    }

    fn outbound_stamp_costs_file(&self) -> PathBuf {
        self.lxmf_root().join("outbound_stamp_costs")
    }

    fn available_tickets_file(&self) -> PathBuf {
        self.lxmf_root().join("available_tickets")
    }

    fn peers_file(&self) -> PathBuf {
        self.lxmf_root().join("peers")
    }
}

struct DeliveryDestination {
    identity: PrivateIdentity,
    input_destination: Option<Arc<tokio::sync::Mutex<SingleInputDestination>>>,
    display_name: Option<String>,
    inbound_stamp_cost: Option<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct StampCostEntry {
    recorded_at: Timestamp,
    cost: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TicketEntry {
    expires_at: Timestamp,
    ticket: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedTicketCache {
    outbound: Vec<(Vec<u8>, TicketEntry)>,
    inbound: Vec<(Vec<u8>, Vec<(Vec<u8>, Timestamp)>)>,
    last_deliveries: Vec<(Vec<u8>, Timestamp)>,
}

#[derive(Debug, Default, Clone)]
struct TicketCache {
    outbound: HashMap<AddressHash, TicketEntry>,
    inbound: HashMap<AddressHash, HashMap<Vec<u8>, Timestamp>>,
    last_deliveries: HashMap<AddressHash, Timestamp>,
}

impl TicketCache {
    fn to_persisted(&self) -> PersistedTicketCache {
        let outbound = self
            .outbound
            .iter()
            .map(|(hash, entry)| (hash.as_slice().to_vec(), entry.clone()))
            .collect();

        let inbound = self
            .inbound
            .iter()
            .map(|(hash, tickets)| {
                let entries = tickets
                    .iter()
                    .map(|(ticket, expires)| (ticket.clone(), *expires))
                    .collect();
                (hash.as_slice().to_vec(), entries)
            })
            .collect();

        let last_deliveries = self
            .last_deliveries
            .iter()
            .map(|(hash, ts)| (hash.as_slice().to_vec(), *ts))
            .collect();

        PersistedTicketCache {
            outbound,
            inbound,
            last_deliveries,
        }
    }

    fn from_persisted(data: PersistedTicketCache) -> Self {
        let mut cache = TicketCache::default();

        for (raw_hash, entry) in data.outbound {
            if let Some(hash) = address_from_vec(&raw_hash) {
                cache.outbound.insert(hash, entry);
            }
        }

        for (raw_hash, entries) in data.inbound {
            if let Some(hash) = address_from_vec(&raw_hash) {
                let mut ticket_map = HashMap::new();
                for (ticket, expires) in entries {
                    ticket_map.insert(ticket, expires);
                }
                cache.inbound.insert(hash, ticket_map);
            }
        }

        for (raw_hash, ts) in data.last_deliveries {
            if let Some(hash) = address_from_vec(&raw_hash) {
                cache.last_deliveries.insert(hash, ts);
            }
        }

        cache
    }

    fn clean(&mut self, now: Timestamp) {
        self.outbound.retain(|_, entry| entry.expires_at > now);

        for tickets in self.inbound.values_mut() {
            tickets.retain(|_, expires| *expires > now);
        }
        self.last_deliveries
            .retain(|_, ts| *ts > now - MESSAGE_EXPIRY_S);
    }
}

#[derive(Debug, Clone)]
pub struct PropagationEntry {
    pub destination_hash: AddressHash,
    pub filepath: PathBuf,
    pub received: Timestamp,
    pub size: u64,
    pub handled_peers: Vec<AddressHash>,
    pub unhandled_peers: Vec<AddressHash>,
    pub stamp_value: Option<u32>,
}

type DeliveryCallback = Arc<dyn Fn(&LXMessage) + Send + Sync + 'static>;

#[derive(Clone)]
pub struct LxmRouter {
    pub(crate) inner: Arc<RouterInner>,
}

pub(crate) struct RouterInner {
    identity: PrivateIdentity,
    cfg: RouterConfig,
    paths: RouterPaths,
    transport: Mutex<Option<Arc<Transport>>>,
    runtime_handle: Mutex<Option<Handle>>,

    pending_inbound: Mutex<VecDeque<Vec<u8>>>,
    pub(crate) pending_outbound: Mutex<VecDeque<LXMessage>>,
    failed_outbound: Mutex<VecDeque<LXMessage>>,

    direct_links: Mutex<HashMap<AddressHash, ()>>,
    backchannel_links: Mutex<HashMap<AddressHash, ()>>,

    delivery_destinations: Mutex<HashMap<AddressHash, DeliveryDestination>>,

    prioritised: Mutex<HashSet<AddressHash>>,
    ignored: Mutex<HashSet<AddressHash>>,
    allowed: Mutex<HashSet<AddressHash>>,
    control_allowed: Mutex<HashSet<AddressHash>>,
    auth_required: Mutex<bool>,
    retain_synced_on_node: Mutex<bool>,

    propagation_node: Mutex<bool>,
    propagation_node_start_time: Mutex<Option<Timestamp>>,

    message_storage_limit: Mutex<Option<u64>>,
    information_storage_limit: Mutex<Option<u64>>,
    propagation_per_transfer_limit: Mutex<u32>,
    propagation_per_sync_limit: Mutex<u32>,
    delivery_per_transfer_limit: Mutex<u32>,
    propagation_stamp_cost: Mutex<u32>,
    propagation_stamp_cost_flexibility: Mutex<u32>,
    peering_cost: Mutex<u32>,
    max_peering_cost: Mutex<u32>,
    enforce_ratchets: bool,
    enforce_stamps: Mutex<bool>,

    outbound_propagation_node: Mutex<Option<AddressHash>>,

    propagation_transfer_state: Mutex<PropagationTransferState>,
    propagation_transfer_progress: Mutex<f32>,
    propagation_transfer_last_result: Mutex<Option<usize>>,
    propagation_transfer_last_duplicates: Mutex<Option<usize>>,
    propagation_transfer_max_messages: Mutex<Option<usize>>,

    prioritise_rotating_unreachable_peers: Mutex<bool>,

    locally_delivered_transient_ids: Mutex<HashMap<TransientId, Timestamp>>,
    locally_processed_transient_ids: Mutex<HashMap<TransientId, Timestamp>>,

    outbound_stamp_costs: Mutex<HashMap<AddressHash, StampCostEntry>>,
    available_tickets: Mutex<TicketCache>,

    peers: Mutex<HashMap<AddressHash, LxmPeer>>,
    propagation_entries: Mutex<HashMap<TransientId, PropagationEntry>>,
    peer_distribution_queue: Mutex<VecDeque<(TransientId, Option<AddressHash>)>>,

    throttled_peers: Mutex<HashMap<AddressHash, Timestamp>>,
    delivery_callback: Mutex<Option<DeliveryCallback>>,
    exit_handler_running: Mutex<bool>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum PropagationTransferState {
    Idle = 0x00,
    PathRequested = 0x01,
    LinkEstablishing = 0x02,
    LinkEstablished = 0x03,
    RequestSent = 0x04,
    Receiving = 0x05,
    ResponseReceived = 0x06,
    Complete = 0x07,
    NoPath = 0xF0,
    LinkFailed = 0xF1,
    TransferFailed = 0xF2,
    NoIdentityRcvd = 0xF3,
    NoAccess = 0xF4,
    Failed = 0xFE,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum DispatchOutcome {
    Sent,
    AwaitingPath,
}

impl LxmRouter {
    pub fn new(config: RouterConfig) -> Result<Self, RouterError> {
        config.validate()?;

        let identity = config
            .identity
            .clone()
            .unwrap_or_else(|| PrivateIdentity::new_from_name("lxmf.router"));

        let paths = RouterPaths::new(config.storage_root.clone());
        fs::create_dir_all(paths.lxmf_root())?;
        fs::create_dir_all(paths.ratchet_dir())?;
        fs::create_dir_all(paths.message_store())?;

        let inner = RouterInner::new(identity, config, paths)?;
        let router = Self {
            inner: Arc::new(inner),
        };
        router.spawn_jobloop();
        Ok(router)
    }

    pub fn identity(&self) -> PrivateIdentity {
        self.inner.identity.clone()
    }

    pub fn register_delivery_identity(
        &self,
        identity: Option<PrivateIdentity>,
        display_name: Option<String>,
        stamp_cost: Option<u8>,
    ) -> Result<AddressHash, RouterError> {
        let identity = identity.unwrap_or_else(|| self.inner.identity.clone());
        let dest_hash = SingleInputDestination::new(
            identity.clone(),
            DestinationName::new(APP_NAME, DELIVERY_ASPECT),
        )
        .desc
        .address_hash;

        {
            let mut map = self.inner.delivery_destinations.lock().unwrap();
            if !map.is_empty() {
                return Err(RouterError::DuplicateDeliveryIdentity);
            }

            map.insert(
                dest_hash,
                DeliveryDestination {
                    identity,
                    input_destination: None,
                    display_name,
                    inbound_stamp_cost: stamp_cost,
                },
            );
        }

        self.spawn_destination_registration(dest_hash);

        Ok(dest_hash)
    }

    pub fn register_delivery_callback<F>(&self, callback: F)
    where
        F: Fn(&LXMessage) + Send + Sync + 'static,
    {
        *self.inner.delivery_callback.lock().unwrap() = Some(Arc::new(callback));
    }

    /// Trigger the delivery callback with a received message.
    ///
    /// This should be called when an LXMF message is received for a registered
    /// delivery destination. It will invoke the callback registered via
    /// `register_delivery_callback()`.
    pub fn trigger_delivery_callback(&self, message: &LXMessage) {
        if let Some(callback) = self.inner.delivery_callback.lock().unwrap().as_ref() {
            callback(message);
        } else {
            log::warn!("No delivery callback registered");
        }
    }

    /// Build the announce app_data for a delivery destination.
    ///
    /// Format matches Python LXMF 0.5.0+: msgpack array [display_name, stamp_cost]
    /// - slot 0: display_name as bytes (UTF-8) or None
    /// - slot 1: stamp_cost as integer or None
    pub fn get_announce_app_data(&self, destination_hash: AddressHash) -> Option<Vec<u8>> {
        let map = self.inner.delivery_destinations.lock().unwrap();
        let dest = map.get(&destination_hash)?;

        let display_name: rmpv::Value = match &dest.display_name {
            Some(name) => rmpv::Value::Binary(name.as_bytes().to_vec()),
            None => rmpv::Value::Nil,
        };

        let stamp_cost: rmpv::Value = match dest.inbound_stamp_cost {
            Some(cost) if cost > 0 && cost < 255 => rmpv::Value::Integer(rmpv::Integer::from(cost)),
            _ => rmpv::Value::Nil,
        };

        let peer_data = rmpv::Value::Array(vec![display_name, stamp_cost]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &peer_data).ok()?;
        Some(buf)
    }

    /// Announce a registered delivery destination.
    ///
    /// This sends an announce via the attached Reticulum transport with app_data
    /// containing the display_name and stamp_cost (msgpack encoded).
    pub async fn announce(&self, destination_hash: AddressHash) -> Result<(), RouterError> {
        let transport = self
            .inner
            .transport
            .lock()
            .unwrap()
            .clone()
            .ok_or(RouterError::NoTransportAttached)?;

        let input_destination = self
            .ensure_registered_destination(&transport, destination_hash)
            .await?;

        let app_data = self.get_announce_app_data(destination_hash);
        transport
            .send_announce(&input_destination, app_data.as_deref())
            .await;

        info!(
            "Announced delivery destination {}",
            hex::encode(destination_hash.as_slice())
        );
        Ok(())
    }

    async fn register_delivery_destinations_with_transport(
        &self,
        transport: Arc<Transport>,
    ) -> Result<(), RouterError> {
        let destination_hashes: Vec<AddressHash> = {
            let map = self.inner.delivery_destinations.lock().unwrap();
            map.keys().cloned().collect()
        };

        trace!(
            "Registering {} delivery destinations with transport",
            destination_hashes.len()
        );

        for hash in destination_hashes {
            trace!(
                "Registering delivery destination {} with transport",
                hex::encode(hash.as_slice())
            );
            self.ensure_registered_destination(&transport, hash).await?;
        }

        Ok(())
    }

    async fn ensure_registered_destination(
        &self,
        transport: &Arc<Transport>,
        destination_hash: AddressHash,
    ) -> Result<Arc<tokio::sync::Mutex<SingleInputDestination>>, RouterError> {
        if let Some(existing) = self
            .inner
            .delivery_destinations
            .lock()
            .unwrap()
            .get(&destination_hash)
            .and_then(|dest| dest.input_destination.clone())
        {
            trace!(
                "Destination {} already registered with transport",
                hex::encode(destination_hash.as_slice())
            );
            return Ok(existing);
        }

        let identity = {
            let map = self.inner.delivery_destinations.lock().unwrap();
            let dest = map
                .get(&destination_hash)
                .ok_or(RouterError::UnknownDeliveryDestination(destination_hash))?;
            dest.identity.clone()
        };

        debug!(
            "Registering destination {} with transport (identity: {})",
            hex::encode(destination_hash.as_slice()),
            hex::encode(identity.as_identity().verifying_key.as_bytes())
        );

        let mut transport_handle = transport.as_ref().clone();
        let registered = transport_handle
            .add_destination(
                identity.clone(),
                DestinationName::new(APP_NAME, DELIVERY_ASPECT),
            )
            .await;

        // Log the actual address hash that was registered
        let registered_hash = registered.lock().await.desc.address_hash;
        info!(
            "Destination registered with transport: expected={}, actual={}",
            hex::encode(destination_hash.as_slice()),
            hex::encode(registered_hash.as_slice())
        );

        let mut map = self.inner.delivery_destinations.lock().unwrap();
        let dest = map
            .get_mut(&destination_hash)
            .ok_or(RouterError::UnknownDeliveryDestination(destination_hash))?;
        dest.input_destination = Some(registered.clone());
        Ok(registered)
    }

    fn spawn_destination_registration(&self, destination_hash: AddressHash) {
        let transport = { self.inner.transport.lock().unwrap().clone() };
        let Some(transport) = transport else {
            return;
        };

        let Some(handle) = self.inner.runtime_handle.lock().unwrap().clone() else {
            return;
        };

        let router = self.clone();
        handle.spawn(async move {
            if let Err(err) = router
                .ensure_registered_destination(&transport, destination_hash)
                .await
            {
                warn!(
                    "Failed to register delivery destination {}: {}",
                    hex::encode(destination_hash.as_slice()),
                    err
                );
            }
        });
    }

    /// Attach a Reticulum transport so queued LXMs can be forwarded automatically.
    ///
    /// This also registers the LXMF announce handlers with the transport:
    /// - `LXMFDeliveryAnnounceHandler` for "lxmf.delivery" announces
    /// - `LXMFPropagationAnnounceHandler` for "lxmf.propagation" announces
    ///
    /// Additionally, this registers all delivery destinations with the transport
    /// so they can receive incoming LXMF messages.
    ///
    /// References Python LXMF/LXMF.py LXMRouter.__init__() handler registration
    pub async fn attach_transport(&self, transport: Arc<Transport>) -> Result<(), RouterError> {
        let handle = Handle::try_current()
            .map_err(|err| RouterError::RuntimeUnavailable(err.to_string()))?;

        // Store transport and runtime handle
        *self.inner.transport.lock().unwrap() = Some(transport.clone());
        *self.inner.runtime_handle.lock().unwrap() = Some(handle.clone());

        // Register announce handlers like Python LXMF does in __init__
        let delivery_handler = LXMFDeliveryAnnounceHandler::new(self.clone());
        let propagation_handler = LXMFPropagationAnnounceHandler::new(self.clone());

        transport.register_announce_handler(delivery_handler).await;
        transport
            .register_announce_handler(propagation_handler)
            .await;

        debug!("Registered LXMF announce handlers with transport");

        self.register_delivery_destinations_with_transport(transport.clone())
            .await?;

        // Start background task to process incoming LXMF messages (single packets)
        let router = self.clone();
        let transport_clone = transport.clone();
        handle.spawn(async move {
            router.process_incoming_messages(transport_clone).await;
        });

        // Start background task to process incoming link events (LXMF over links)
        // This mirrors Python LXMF's delivery_link_established + delivery_packet callbacks
        let router = self.clone();
        let transport_clone = transport.clone();
        handle.spawn(async move {
            router.process_incoming_link_events(transport_clone).await;
        });

        Ok(())
    }

    /// Process incoming LXMF messages from the transport.
    ///
    /// This method subscribes to the transport's received_data events and processes
    /// any packets destined for registered LXMF delivery destinations.
    async fn process_incoming_messages(&self, transport: Arc<Transport>) {
        let mut data_receiver = transport.received_data_events();

        trace!("Started listening for incoming data packets");

        while let Ok(received_data) = data_receiver.recv().await {
            trace!(
                "Received data packet for destination {}: {} bytes",
                hex::encode(received_data.destination.as_slice()),
                received_data.data.len()
            );

            // Check if this packet is for one of our delivery destinations
            let delivery_destinations = self.inner.delivery_destinations.lock().unwrap();
            if delivery_destinations.contains_key(&received_data.destination) {
                drop(delivery_destinations);

                log::debug!(
                    "Received LXMF packet for destination {}: {} bytes",
                    hex::encode(received_data.destination.as_slice()),
                    received_data.data.len()
                );

                // Process the LXMF message
                if let Err(e) = self.process_inbound_lxmf_packet(received_data) {
                    log::error!("Error processing LXMF packet: {}", e);
                }
            }
        }
    }

    /// Process incoming LXMF messages delivered over links.
    ///
    /// This mirrors Python LXMF's delivery_link_established() and delivery_packet() callbacks.
    /// When a link is established to our delivery destination, this handler receives
    /// data sent over that link and processes it as LXMF messages.
    ///
    /// References Python LXMF/LXMF.py:
    /// - LXMRouter.delivery_link_established() - sets up packet callback on link
    /// - LXMRouter.delivery_packet() - processes incoming LXMF packets over link
    async fn process_incoming_link_events(&self, transport: Arc<Transport>) {
        let mut link_receiver = transport.in_link_events();

        trace!("Started listening for incoming link events");

        while let Ok(link_event_data) = link_receiver.recv().await {
            trace!(
                "Received link event: link_id={}, dest={}, event_type={:?}",
                link_event_data.id,
                hex::encode(link_event_data.address_hash.as_slice()),
                match &link_event_data.event {
                    LinkEvent::Activated => "Activated",
                    LinkEvent::Data(_) => "Data",
                    LinkEvent::Closed => "Closed",
                    LinkEvent::Resource(_) => "Resource",
                }
            );

            match link_event_data.event {
                LinkEvent::Activated => {
                    log::info!(
                        "Incoming link {} activated for destination {}",
                        link_event_data.id,
                        hex::encode(link_event_data.address_hash.as_slice())
                    );

                    // Check if this link is for one of our delivery destinations
                    let delivery_destinations = self.inner.delivery_destinations.lock().unwrap();
                    if delivery_destinations.contains_key(&link_event_data.address_hash) {
                        log::debug!(
                            "Link {} is for registered LXMF delivery destination",
                            link_event_data.id
                        );
                    }
                }
                LinkEvent::Data(payload) => {
                    // Check if this link is for one of our delivery destinations
                    let delivery_destinations = self.inner.delivery_destinations.lock().unwrap();
                    if delivery_destinations.contains_key(&link_event_data.address_hash) {
                        drop(delivery_destinations);

                        log::debug!(
                            "Received LXMF data over link {} for destination {}: {} bytes",
                            link_event_data.id,
                            hex::encode(link_event_data.address_hash.as_slice()),
                            payload.len()
                        );

                        // Process the LXMF message from link data
                        // For link delivery, the payload contains the full LXMF message
                        // (destination hash prepended, like single packet delivery)
                        if let Err(e) = self.process_inbound_lxmf_link_data(
                            link_event_data.address_hash,
                            payload.as_slice(),
                        ) {
                            log::error!("Error processing LXMF link data: {}", e);
                        }
                    }
                }
                LinkEvent::Closed => {
                    log::debug!("Link {} closed", link_event_data.id);
                }
                LinkEvent::Resource(_) => {
                    // TODO: Handle resource transfers over links
                    // This is used for larger LXMF messages that don't fit in a single packet
                    log::debug!(
                        "Link {} resource event (not yet implemented)",
                        link_event_data.id
                    );
                }
            }
        }
    }

    /// Process inbound LXMF data received over a link.
    ///
    /// References Python LXMF/LXMF.py LXMRouter.delivery_packet()
    fn process_inbound_lxmf_link_data(
        &self,
        destination_hash: AddressHash,
        payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use reticulum::hash::ADDRESS_HASH_SIZE;

        // For link delivery, we reconstruct the full LXMF bytes by prepending destination hash
        // (same as single packet delivery - the destination hash identifies the recipient)
        let mut lxmf_bytes = Vec::with_capacity(ADDRESS_HASH_SIZE + payload.len());
        lxmf_bytes.extend_from_slice(destination_hash.as_slice());
        lxmf_bytes.extend_from_slice(payload);

        log::debug!(
            "Unpacking LXMF message from link ({} bytes)",
            lxmf_bytes.len()
        );

        // Unpack the LXMF message
        let message = LXMessage::unpack_from_bytes(&lxmf_bytes)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

        log::info!(
            "Successfully unpacked LXMF message from {} (via link)",
            hex::encode(message.source_hash().as_slice())
        );

        // Trigger the delivery callback
        self.trigger_delivery_callback(&message);

        Ok(())
    }

    /// Process an inbound LXMF packet.
    ///
    /// Unpacks the LXMF message and triggers the delivery callback.
    fn process_inbound_lxmf_packet(
        &self,
        received_data: reticulum::transport::ReceivedData,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use reticulum::hash::ADDRESS_HASH_SIZE;

        // The received data should be an LXMF message payload
        // For Direct/Opportunistic delivery, the destination hash is already stripped by transport
        // We need to reconstruct the full LXMF bytes by prepending the destination hash

        let destination_hash = received_data.destination;
        let payload = received_data.data.as_slice();

        // Reconstruct full LXMF message bytes: destination_hash + payload
        let mut lxmf_bytes = Vec::with_capacity(ADDRESS_HASH_SIZE + payload.len());
        lxmf_bytes.extend_from_slice(destination_hash.as_slice());
        lxmf_bytes.extend_from_slice(payload);

        log::debug!("Unpacking LXMF message ({} bytes)", lxmf_bytes.len());

        // Unpack the LXMF message
        let message = LXMessage::unpack_from_bytes(&lxmf_bytes)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

        log::info!(
            "Successfully unpacked LXMF message from {}",
            hex::encode(message.source_hash().as_slice())
        );

        // Trigger the delivery callback
        self.trigger_delivery_callback(&message);

        Ok(())
    }

    /// Attach a transport using an explicit Tokio runtime handle (sync version).
    ///
    /// This spawns handler registration asynchronously without waiting.
    /// For guaranteed handler registration before use, prefer `attach_transport()`.
    ///
    /// References Python LXMF/LXMF.py LXMRouter.__init__() handler registration
    pub fn attach_transport_with_handle(&self, transport: Arc<Transport>, handle: Handle) {
        // Store transport and runtime handle
        *self.inner.transport.lock().unwrap() = Some(transport.clone());
        *self.inner.runtime_handle.lock().unwrap() = Some(handle.clone());

        // Register announce handlers like Python LXMF does in __init__
        // NOTE: This spawns asynchronously, handlers may not be registered immediately
        let delivery_handler = LXMFDeliveryAnnounceHandler::new(self.clone());
        let propagation_handler = LXMFPropagationAnnounceHandler::new(self.clone());

        handle.spawn({
            let transport = transport.clone();
            async move {
                transport.register_announce_handler(delivery_handler).await;
            }
        });

        handle.spawn({
            let transport = transport.clone();
            async move {
                transport
                    .register_announce_handler(propagation_handler)
                    .await;
            }
        });

        handle.spawn({
            let router = self.clone();
            let transport = transport.clone();
            async move {
                if let Err(err) = router
                    .register_delivery_destinations_with_transport(transport)
                    .await
                {
                    error!("Failed to register delivery destinations: {}", err);
                }
            }
        });

        // Start background task to process incoming LXMF messages (single packets)
        handle.spawn({
            let router = self.clone();
            let transport = transport.clone();
            async move {
                router.process_incoming_messages(transport).await;
            }
        });

        // Start background task to process incoming link events (LXMF over links)
        handle.spawn({
            let router = self.clone();
            let transport = transport.clone();
            async move {
                router.process_incoming_link_events(transport).await;
            }
        });

        debug!("Registered LXMF announce handlers with transport");
    }

    /// Queue an outbound LXMF message for later processing.
    pub fn enqueue_outbound(&self, message: LXMessage) {
        self.inner
            .pending_outbound
            .lock()
            .unwrap()
            .push_back(message);
    }

    /// Run outbound processing immediately on a helper thread and wait for completion.
    pub fn flush_outbound_blocking(&self) -> Result<(), RouterError> {
        let this = self.clone();
        thread::spawn(move || {
            this.process_outbound();
        })
        .join()
        .map_err(|_| RouterError::DispatchThreadPanicked)
    }

    pub fn set_inbound_stamp_cost(
        &self,
        destination_hash: AddressHash,
        stamp_cost: Option<u8>,
    ) -> Result<(), RouterError> {
        let mut map = self.inner.delivery_destinations.lock().unwrap();
        if let Some(dest) = map.get_mut(&destination_hash) {
            if let Some(cost) = stamp_cost
                && (cost == 0 || cost == 255)
            {
                return Err(RouterError::StampCostOutOfRange(cost as u32));
            }
            dest.inbound_stamp_cost = stamp_cost;
            Ok(())
        } else {
            Err(RouterError::UnknownDeliveryDestination(destination_hash))
        }
    }

    pub fn get_outbound_stamp_cost(&self, destination_hash: AddressHash) -> Option<u8> {
        self.inner
            .outbound_stamp_costs
            .lock()
            .unwrap()
            .get(&destination_hash)
            .map(|entry| entry.cost)
    }

    pub fn update_outbound_stamp_cost(
        &self,
        destination_hash: AddressHash,
        cost: u8,
    ) -> Result<(), RouterError> {
        let entry = StampCostEntry {
            recorded_at: unix_time_f64(),
            cost,
        };
        self.inner
            .outbound_stamp_costs
            .lock()
            .unwrap()
            .insert(destination_hash, entry);
        self.save_outbound_stamp_costs()
    }

    pub fn set_outbound_propagation_node(&self, node: Option<AddressHash>) {
        *self.inner.outbound_propagation_node.lock().unwrap() = node;
    }

    pub fn get_outbound_propagation_node(&self) -> Option<AddressHash> {
        *self.inner.outbound_propagation_node.lock().unwrap()
    }

    pub fn enable_propagation(&self) -> Result<(), RouterError> {
        {
            let mut flag = self.inner.propagation_node.lock().unwrap();
            if *flag {
                return Ok(());
            }
            *flag = true;
        }

        *self.inner.propagation_node_start_time.lock().unwrap() = Some(unix_time_f64());

        self.rebuild_message_store()?;
        self.rebuild_peers_from_disk()?;

        info!("Propagation mode enabled");
        Ok(())
    }

    pub fn disable_propagation(&self) {
        let mut flag = self.inner.propagation_node.lock().unwrap();
        *flag = false;
    }

    pub fn allow(&self, identity_hash: AddressHash) {
        self.inner.allowed.lock().unwrap().insert(identity_hash);
    }

    pub fn disallow(&self, identity_hash: &AddressHash) {
        self.inner.allowed.lock().unwrap().remove(identity_hash);
    }

    pub fn allow_control(&self, identity_hash: AddressHash) {
        self.inner
            .control_allowed
            .lock()
            .unwrap()
            .insert(identity_hash);
    }

    pub fn disallow_control(&self, identity_hash: &AddressHash) {
        self.inner
            .control_allowed
            .lock()
            .unwrap()
            .remove(identity_hash);
    }

    pub fn prioritise(&self, destination_hash: AddressHash) {
        self.inner
            .prioritised
            .lock()
            .unwrap()
            .insert(destination_hash);
    }

    pub fn unprioritise(&self, destination_hash: &AddressHash) {
        self.inner
            .prioritised
            .lock()
            .unwrap()
            .remove(destination_hash);
    }

    pub fn ignore_destination(&self, destination_hash: AddressHash) {
        self.inner.ignored.lock().unwrap().insert(destination_hash);
    }

    pub fn unignore_destination(&self, destination_hash: &AddressHash) {
        self.inner.ignored.lock().unwrap().remove(destination_hash);
    }

    pub fn set_message_storage_limit(
        &self,
        kilobytes: Option<u64>,
        megabytes: Option<u64>,
        gigabytes: Option<u64>,
    ) {
        let limit = bytes_from_units(kilobytes, megabytes, gigabytes);
        *self.inner.message_storage_limit.lock().unwrap() = limit;
    }

    pub fn set_information_storage_limit(
        &self,
        kilobytes: Option<u64>,
        megabytes: Option<u64>,
        gigabytes: Option<u64>,
    ) {
        let limit = bytes_from_units(kilobytes, megabytes, gigabytes);
        *self.inner.information_storage_limit.lock().unwrap() = limit;
    }

    pub fn set_retain_node_lxms(&self, retain: bool) {
        *self.inner.retain_synced_on_node.lock().unwrap() = retain;
    }

    pub fn set_authentication(&self, required: Option<bool>) {
        if let Some(flag) = required {
            *self.inner.auth_required.lock().unwrap() = flag;
        }
    }

    pub fn requires_authentication(&self) -> bool {
        *self.inner.auth_required.lock().unwrap()
    }

    pub fn enforce_stamps(&self) {
        *self.inner.enforce_stamps.lock().unwrap() = true;
    }

    pub fn ignore_stamps(&self) {
        *self.inner.enforce_stamps.lock().unwrap() = false;
    }

    pub fn stamps_enforced(&self) -> bool {
        *self.inner.enforce_stamps.lock().unwrap()
    }

    pub fn delivery_link_available(&self, destination_hash: &AddressHash) -> bool {
        if self
            .inner
            .direct_links
            .lock()
            .unwrap()
            .contains_key(destination_hash)
        {
            return true;
        }

        self.inner
            .backchannel_links
            .lock()
            .unwrap()
            .contains_key(destination_hash)
    }

    pub fn save_state(&self) -> Result<(), RouterError> {
        self.save_locally_delivered_transient_ids()?;
        self.save_locally_processed_transient_ids()?;
        self.save_outbound_stamp_costs()?;
        self.save_available_tickets()?;
        self.save_peers_to_disk()?;
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), RouterError> {
        let mut running = self.inner.exit_handler_running.lock().unwrap();
        if *running {
            return Ok(());
        }
        *running = true;

        info!("Persisting LXMF router state ...");
        self.flush_peer_distribution_queue();
        self.save_state()
    }

    fn spawn_jobloop(&self) {
        let this = self.clone();
        thread::spawn(move || {
            let mut tick: u64 = 0;
            loop {
                tick = tick.wrapping_add(1);
                if let Err(err) = this.run_jobs(tick) {
                    error!("Router job loop error: {}", err);
                }
                thread::sleep(PROCESSING_INTERVAL);
            }
        });
    }

    fn run_jobs(&self, tick: u64) -> Result<(), RouterError> {
        if tick.is_multiple_of(JOB_TRANSIENT_INTERVAL) {
            self.clean_transient_id_caches();
            self.clean_outbound_stamp_costs();
        }

        if tick.is_multiple_of(JOB_PEERSYNC_INTERVAL) {
            self.clean_throttled_peers();
            self.clean_available_tickets();
        }

        if tick.is_multiple_of(JOB_STORE_INTERVAL) {
            self.clean_message_store();
        }

        if tick.is_multiple_of(JOB_OUTBOUND_INTERVAL) {
            self.process_outbound();
        }

        Ok(())
    }

    pub(crate) fn process_outbound(&self) {
        let mut pending = self.inner.pending_outbound.lock().unwrap();
        pending.retain(|msg| msg.state() != State::Delivered);
        if pending.is_empty() {
            return;
        }

        let transport = match self.inner.transport.lock().unwrap().clone() {
            Some(tp) => tp,
            None => {
                warn!("Outbound queue has entries but no transport is attached");
                return;
            }
        };

        let runtime = match self.inner.runtime_handle.lock().unwrap().clone() {
            Some(handle) => handle,
            None => {
                warn!("Outbound queue has entries but no Tokio runtime handle is registered");
                return;
            }
        };

        let mut queue: Vec<LXMessage> = pending.drain(..).collect();
        drop(pending);

        let mut retry = Vec::new();

        for mut message in queue.drain(..) {
            let destination = message.destination_hash();
            if let Err(err) = self.prepare_outbound_message(&mut message) {
                warn!(
                    "Failed to prepare LXMF message for {:?}: {}",
                    destination, err
                );
                self.inner
                    .failed_outbound
                    .lock()
                    .unwrap()
                    .push_back(message);
                continue;
            }
            let payload = match message.transport_payload() {
                Ok(bytes) => bytes,
                Err(err) => {
                    warn!(
                        "Failed to serialise LXMF message for {:?}: {}",
                        destination, err
                    );
                    self.inner
                        .failed_outbound
                        .lock()
                        .unwrap()
                        .push_back(message);
                    continue;
                }
            };

            match runtime.block_on(Self::send_outbound_message(
                transport.clone(),
                destination,
                payload,
            )) {
                Ok(DispatchOutcome::Sent) => {
                    trace!(
                        "Dispatched LXMF message toward {:?} via Reticulum transport",
                        destination
                    );
                }
                Ok(DispatchOutcome::AwaitingPath) => {
                    trace!(
                        "Path missing for {:?}, keeping LXMF message queued",
                        destination
                    );
                    retry.push(message);
                }
                Err(err) => {
                    warn!(
                        "Transport error while sending LXMF message to {:?}: {}",
                        destination, err
                    );
                    self.inner
                        .failed_outbound
                        .lock()
                        .unwrap()
                        .push_back(message);
                }
            }
        }

        if !retry.is_empty() {
            let mut pending = self.inner.pending_outbound.lock().unwrap();
            pending.extend(retry);
        }
    }

    fn prepare_outbound_message(
        &self,
        message: &mut LXMessage,
    ) -> Result<(), OutboundPreparationError> {
        let dest_hash = message.destination_hash();

        if message.stamp_cost().is_none() {
            if let Some(cost) = self.get_outbound_stamp_cost(dest_hash) {
                info!(
                    "Auto-applied stamp cost {} from router cache for {}",
                    cost, dest_hash
                );
                message.set_stamp_cost(Some(cost));
            } else {
                debug!("No cached stamp cost found for {}", dest_hash);
            }
        }

        message.pack().map_err(OutboundPreparationError::Message)?;

        let Some(cost) = message.stamp_cost() else {
            return Ok(());
        };

        if cost == 0 || message.stamp().is_some() {
            return Ok(());
        }

        let message_id = *message
            .message_hash()
            .ok_or(OutboundPreparationError::MissingMessageId)?;

        let mut rng = OsRng;
        let params = StampParameters::default();
        let stamp = generate_stamp(&mut rng, message_id.as_slice(), cost, params, None)
            .map_err(OutboundPreparationError::Stamp)?;

        message.set_stamp(Some(stamp.stamp.to_vec()));
        message.set_stamp_value(Some(stamp.value));
        trace!(
            "Generated stamp (value {}) for {:?} after {} rounds",
            stamp.value,
            message.destination_hash(),
            stamp.rounds
        );

        message.pack().map_err(OutboundPreparationError::Message)?;
        Ok(())
    }

    async fn send_outbound_message(
        transport: Arc<Transport>,
        destination: AddressHash,
        payload: Vec<u8>,
    ) -> Result<DispatchOutcome, RnsError> {
        if !transport.has_path(&destination).await {
            transport.request_path(&destination, None).await;
            return Ok(DispatchOutcome::AwaitingPath);
        }

        transport
            .send_to_destination(&destination, &payload, PacketContext::None)
            .await?;
        Ok(DispatchOutcome::Sent)
    }

    fn clean_message_store(&self) {
        if !*self.inner.propagation_node.lock().unwrap() {
            return;
        }

        let limit = *self.inner.message_storage_limit.lock().unwrap();
        if limit.is_none() {
            return;
        }

        let entries = self.inner.propagation_entries.lock().unwrap();
        let total: u64 = entries.values().map(|entry| entry.size).sum();
        if let Some(limit) = limit
            && total > limit
        {
            warn!(
                "Message store exceeds limit ({} > {} bytes), culling not yet implemented",
                total, limit
            );
        }
    }

    fn clean_available_tickets(&self) {
        let now = unix_time_f64();
        self.inner.available_tickets.lock().unwrap().clean(now);
    }

    fn clean_outbound_stamp_costs(&self) {
        let now = unix_time_f64();
        self.inner
            .outbound_stamp_costs
            .lock()
            .unwrap()
            .retain(|_, entry| entry.recorded_at + STAMP_COST_EXPIRY_S > now);
    }

    fn flush_peer_distribution_queue(&self) {
        let mut queue = self.inner.peer_distribution_queue.lock().unwrap();
        if queue.is_empty() {
            return;
        }
        let entries: Vec<_> = queue.drain(..).collect();
        drop(queue);

        let mut peers = self.inner.peers.lock().unwrap();
        for peer in peers.values_mut() {
            for (transient_id, from_peer) in &entries {
                if from_peer.is_none_or(|hash| hash != *peer.destination_hash()) {
                    peer.queue_unhandled_message(*transient_id);
                }
            }
            peer.process_queues();
        }
    }

    fn clean_transient_id_caches(&self) {
        let now = unix_time_f64();
        let expiry = MESSAGE_EXPIRY_S * 6.0;

        self.inner
            .locally_delivered_transient_ids
            .lock()
            .unwrap()
            .retain(|_, ts| now <= *ts + expiry);
        self.inner
            .locally_processed_transient_ids
            .lock()
            .unwrap()
            .retain(|_, ts| now <= *ts + expiry);
    }

    fn clean_throttled_peers(&self) {
        let now = unix_time_f64();
        self.inner
            .throttled_peers
            .lock()
            .unwrap()
            .retain(|_, ts| *ts > now);
    }

    fn rebuild_message_store(&self) -> Result<(), RouterError> {
        let entries = HashMap::new();
        let message_dir = self.inner.paths.message_store();
        if !message_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&message_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            let metadata = fs::metadata(&path)?;
            let received = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs_f64())
                .unwrap_or_else(unix_time_f64);

            let size = metadata.len();
            trace!(
                "Skipping propagation entry indexing for {:?}, parsing not implemented",
                path
            );

            let _ = (received, size);
        }

        *self.inner.propagation_entries.lock().unwrap() = entries;
        Ok(())
    }

    fn rebuild_peers_from_disk(&self) -> Result<(), RouterError> {
        let peers_path = self.inner.paths.peers_file();
        if !peers_path.exists() {
            return Ok(());
        }

        let data = fs::read(peers_path)?;
        if data.is_empty() {
            return Ok(());
        }

        let serialised: Vec<Vec<u8>> = rmp_serde::from_slice(&data)?;
        let mut peers = HashMap::new();
        for snapshot in serialised {
            match LxmPeer::from_bytes(&snapshot) {
                Ok(peer) => {
                    peers.insert(*peer.destination_hash(), peer);
                }
                Err(err) => {
                    warn!("Could not load peer snapshot: {}", err);
                }
            }
        }

        for peer in &self.inner.cfg.static_peers {
            peers.entry(*peer).or_insert_with(|| {
                let mut p = LxmPeer::new(*peer, self.inner.cfg.default_sync_strategy);
                p.set_alive(false);
                p
            });
        }

        *self.inner.peers.lock().unwrap() = peers;
        Ok(())
    }

    fn save_locally_delivered_transient_ids(&self) -> Result<(), RouterError> {
        let path = self.inner.paths.local_deliveries_file();
        let map = self.inner.locally_delivered_transient_ids.lock().unwrap();
        save_transient_cache(&path, &map)
    }

    fn save_locally_processed_transient_ids(&self) -> Result<(), RouterError> {
        let path = self.inner.paths.locally_processed_file();
        let map = self.inner.locally_processed_transient_ids.lock().unwrap();
        save_transient_cache(&path, &map)
    }

    fn save_outbound_stamp_costs(&self) -> Result<(), RouterError> {
        let path = self.inner.paths.outbound_stamp_costs_file();
        let map = self.inner.outbound_stamp_costs.lock().unwrap();
        let mut serialised = Vec::with_capacity(map.len());
        for (hash, entry) in map.iter() {
            serialised.push((hash.as_slice().to_vec(), *entry));
        }
        let bytes = rmp_serde::to_vec_named(&serialised)?;
        fs::write(path, bytes)?;
        Ok(())
    }

    fn save_available_tickets(&self) -> Result<(), RouterError> {
        let path = self.inner.paths.available_tickets_file();
        let cache = self.inner.available_tickets.lock().unwrap();
        let serialised = cache.to_persisted();
        let bytes = rmp_serde::to_vec_named(&serialised)?;
        fs::write(path, bytes)?;
        Ok(())
    }

    fn save_peers_to_disk(&self) -> Result<(), RouterError> {
        let peers_path = self.inner.paths.peers_file();
        let peers = self.inner.peers.lock().unwrap();
        let mut snapshots = Vec::with_capacity(peers.len());
        for peer in peers.values() {
            match peer.to_bytes() {
                Ok(bytes) => snapshots.push(bytes),
                Err(err) => warn!(
                    "Could not serialise peer {}: {}",
                    peer.display_name().unwrap_or_else(|| "unknown".to_string()),
                    err
                ),
            }
        }
        let bytes = rmp_serde::to_vec_named(&snapshots)?;
        fs::write(peers_path, bytes)?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Helper methods for LXMFPropagationAnnounceHandler
    // -------------------------------------------------------------------------

    /// Check if this router is running as a propagation node.
    ///
    /// Returns `true` if propagation mode has been enabled via `enable_propagation()`.
    pub fn is_propagation_node(&self) -> bool {
        *self.inner.propagation_node.lock().unwrap()
    }

    /// Check if the given destination hash is a configured static peer.
    ///
    /// Static peers are those configured via `RouterConfig::static_peers` and
    /// are always maintained regardless of announce activity.
    pub fn is_static_peer(&self, destination_hash: &AddressHash) -> bool {
        self.inner.cfg.static_peers.contains(destination_hash)
    }

    /// Get the last heard timestamp for a peer.
    ///
    /// Returns `0.0` if the peer is not known.
    pub fn peer_last_heard(&self, destination_hash: &AddressHash) -> f64 {
        self.inner
            .peers
            .lock()
            .unwrap()
            .get(destination_hash)
            .map(|peer| peer.last_heard())
            .unwrap_or(0.0)
    }

    /// Check if auto-peering is enabled.
    ///
    /// When enabled, the router will automatically peer with propagation nodes
    /// that announce themselves within the configured hop depth.
    pub fn autopeer_enabled(&self) -> bool {
        self.inner.cfg.autopeer
    }

    /// Create or update a peering with a propagation node.
    ///
    /// This method creates a new `LxmPeer` entry or updates an existing one
    /// with the provided configuration from the propagation node's announce.
    ///
    /// # Arguments
    /// * `destination_hash` - The address hash of the propagation node
    /// * `timebase` - The node's peering timebase
    /// * `transfer_limit` - Maximum bytes per transfer (None = unlimited)
    /// * `sync_limit` - Maximum bytes per sync (None = unlimited)
    /// * `stamp_cost` - Required stamp cost for propagation
    /// * `stamp_flexibility` - Flexibility in stamp cost acceptance
    /// * `peering_cost` - Required peering key cost
    /// * `metadata` - Node metadata (name, etc.)
    ///
    /// References Python LXMF/LXMRouter.py peer() method
    #[allow(clippy::too_many_arguments)]
    pub fn peer(
        &self,
        destination_hash: AddressHash,
        timebase: f64,
        transfer_limit: Option<f64>,
        sync_limit: Option<f64>,
        _stamp_cost: Option<u32>,
        _stamp_flexibility: Option<u32>,
        peering_cost: Option<u32>,
        metadata: Option<PeerMetadata>,
    ) -> Result<(), RouterError> {
        let mut peers = self.inner.peers.lock().unwrap();

        if let Some(peer) = peers.get_mut(&destination_hash) {
            // Update existing peer
            peer.set_last_heard(unix_time_f64());
            peer.set_alive(true);
            peer.set_peering_cost(peering_cost);
            peer.set_metadata(metadata);
            // Update propagation limits via peer methods
            // Note: LxmPeer would need setters for these if not already present
            debug!(
                "Updated peer {} (timebase: {}, transfer_limit: {:?}, sync_limit: {:?})",
                hex::encode(destination_hash.as_slice()),
                timebase,
                transfer_limit,
                sync_limit
            );
        } else {
            // Check if we've reached max peers (excluding static peers)
            let current_dynamic_peers = peers
                .keys()
                .filter(|h| !self.inner.cfg.static_peers.contains(h))
                .count();

            if current_dynamic_peers >= self.inner.cfg.max_peers {
                debug!(
                    "Max peers ({}) reached, not adding {}",
                    self.inner.cfg.max_peers,
                    hex::encode(destination_hash.as_slice())
                );
                return Ok(());
            }

            // Create new peer
            let mut peer = LxmPeer::new(destination_hash, self.inner.cfg.default_sync_strategy);
            peer.set_last_heard(unix_time_f64());
            peer.set_alive(true);
            peer.set_peering_cost(peering_cost);
            peer.set_metadata(metadata);
            // TODO: Set propagation limits when LxmPeer supports it

            info!(
                "Added new peer {} (timebase: {}, transfer_limit: {:?}, sync_limit: {:?})",
                hex::encode(destination_hash.as_slice()),
                timebase,
                transfer_limit,
                sync_limit
            );
            peers.insert(destination_hash, peer);
        }

        Ok(())
    }

    /// Remove a peering with a propagation node.
    ///
    /// This removes the peer from the active peer list. Static peers
    /// are not removed but marked as inactive.
    ///
    /// References Python LXMF/LXMRouter.py unpeer() method
    pub fn unpeer(&self, destination_hash: &AddressHash) {
        let mut peers = self.inner.peers.lock().unwrap();

        if self.inner.cfg.static_peers.contains(destination_hash) {
            // For static peers, mark as not alive but don't remove
            if let Some(peer) = peers.get_mut(destination_hash) {
                peer.set_alive(false);
                debug!(
                    "Marked static peer {} as inactive",
                    hex::encode(destination_hash.as_slice())
                );
            }
        } else {
            // Remove dynamic peers
            if peers.remove(destination_hash).is_some() {
                info!("Removed peer {}", hex::encode(destination_hash.as_slice()));
            }
        }
    }

    /// Get a list of all current peer destination hashes.
    pub fn peer_destinations(&self) -> Vec<AddressHash> {
        self.inner.peers.lock().unwrap().keys().copied().collect()
    }

    /// Get the number of active peers.
    pub fn peer_count(&self) -> usize {
        self.inner.peers.lock().unwrap().len()
    }
}

impl RouterInner {
    fn new(
        identity: PrivateIdentity,
        cfg: RouterConfig,
        paths: RouterPaths,
    ) -> Result<Self, RouterError> {
        let propagation_per_sync_limit =
            if cfg.sync_limit_kb == 0 || cfg.sync_limit_kb < cfg.propagation_limit_kb {
                cfg.propagation_limit_kb
            } else {
                cfg.sync_limit_kb
            };

        let delivered = load_transient_cache(&paths.local_deliveries_file())?;
        let processed = load_transient_cache(&paths.locally_processed_file())?;
        let stamp_costs = load_stamp_costs(&paths.outbound_stamp_costs_file())?;
        let tickets = load_ticket_cache(&paths.available_tickets_file())?;

        let cfg_clone = cfg.clone();

        Ok(Self {
            identity,
            cfg,
            paths,
            transport: Mutex::new(None),
            runtime_handle: Mutex::new(None),

            pending_inbound: Mutex::new(VecDeque::new()),
            pending_outbound: Mutex::new(VecDeque::new()),
            failed_outbound: Mutex::new(VecDeque::new()),

            direct_links: Mutex::new(HashMap::new()),
            backchannel_links: Mutex::new(HashMap::new()),

            delivery_destinations: Mutex::new(HashMap::new()),

            prioritised: Mutex::new(HashSet::new()),
            ignored: Mutex::new(HashSet::new()),
            allowed: Mutex::new(HashSet::new()),
            control_allowed: Mutex::new(HashSet::new()),
            auth_required: Mutex::new(false),
            retain_synced_on_node: Mutex::new(false),

            propagation_node: Mutex::new(false),
            propagation_node_start_time: Mutex::new(None),

            message_storage_limit: Mutex::new(None),
            information_storage_limit: Mutex::new(None),
            propagation_per_transfer_limit: Mutex::new(cfg_clone.propagation_limit_kb),
            propagation_per_sync_limit: Mutex::new(propagation_per_sync_limit),
            delivery_per_transfer_limit: Mutex::new(cfg_clone.delivery_limit_kb),
            propagation_stamp_cost: Mutex::new(cfg_clone.propagation_cost),
            propagation_stamp_cost_flexibility: Mutex::new(cfg_clone.propagation_cost_flex),
            peering_cost: Mutex::new(cfg_clone.peering_cost),
            max_peering_cost: Mutex::new(cfg_clone.max_peering_cost),
            enforce_ratchets: cfg_clone.enforce_ratchets,
            enforce_stamps: Mutex::new(cfg_clone.enforce_stamps),

            outbound_propagation_node: Mutex::new(None),

            propagation_transfer_state: Mutex::new(PropagationTransferState::Idle),
            propagation_transfer_progress: Mutex::new(0.0),
            propagation_transfer_last_result: Mutex::new(None),
            propagation_transfer_last_duplicates: Mutex::new(None),
            propagation_transfer_max_messages: Mutex::new(None),

            prioritise_rotating_unreachable_peers: Mutex::new(false),

            locally_delivered_transient_ids: Mutex::new(delivered),
            locally_processed_transient_ids: Mutex::new(processed),

            outbound_stamp_costs: Mutex::new(stamp_costs),
            available_tickets: Mutex::new(tickets),

            peers: Mutex::new(HashMap::new()),
            propagation_entries: Mutex::new(HashMap::new()),
            peer_distribution_queue: Mutex::new(VecDeque::new()),

            throttled_peers: Mutex::new(HashMap::new()),
            delivery_callback: Mutex::new(None),
            exit_handler_running: Mutex::new(false),
        })
    }
}

impl Drop for LxmRouter {
    fn drop(&mut self) {
        if let Err(err) = self.shutdown() {
            warn!("Failed to persist LXMF router state on drop: {}", err);
        }
    }
}

fn unix_time_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs_f64()
}

fn address_from_vec(bytes: &[u8]) -> Option<AddressHash> {
    if bytes.len() != ADDRESS_HASH_SIZE {
        return None;
    }
    let mut raw = [0u8; ADDRESS_HASH_SIZE];
    raw.copy_from_slice(bytes);
    Some(AddressHash::new(raw))
}

fn bytes_from_units(kb: Option<u64>, mb: Option<u64>, gb: Option<u64>) -> Option<u64> {
    let mut total = 0u64;
    if let Some(kb) = kb {
        total = total.saturating_add(kb * 1000);
    }
    if let Some(mb) = mb {
        total = total.saturating_add(mb * 1000 * 1000);
    }
    if let Some(gb) = gb {
        total = total.saturating_add(gb * 1000 * 1000 * 1000);
    }
    if total == 0 { None } else { Some(total) }
}

fn load_transient_cache(path: &Path) -> Result<HashMap<TransientId, Timestamp>, RouterError> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(HashMap::new());
    }
    let raw: Vec<(Vec<u8>, Timestamp)> = rmp_serde::from_slice(&bytes)?;
    let mut map = HashMap::new();
    for (key, ts) in raw {
        if key.len() == TRANSIENT_ID_LEN {
            let mut id = [0u8; TRANSIENT_ID_LEN];
            id.copy_from_slice(&key);
            map.insert(id, ts);
        }
    }
    Ok(map)
}

fn save_transient_cache(
    path: &Path,
    cache: &HashMap<TransientId, Timestamp>,
) -> Result<(), RouterError> {
    if cache.is_empty() {
        return Ok(());
    }
    let serialisable: Vec<(Vec<u8>, Timestamp)> =
        cache.iter().map(|(id, ts)| (id.to_vec(), *ts)).collect();
    let bytes = rmp_serde::to_vec_named(&serialisable)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn load_stamp_costs(path: &Path) -> Result<HashMap<AddressHash, StampCostEntry>, RouterError> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(HashMap::new());
    }
    let raw: Vec<(Vec<u8>, StampCostEntry)> = rmp_serde::from_slice(&bytes)?;
    let mut map = HashMap::new();
    for (key, entry) in raw {
        if let Some(hash) = address_from_vec(&key) {
            map.insert(hash, entry);
        }
    }
    Ok(map)
}

fn load_ticket_cache(path: &Path) -> Result<TicketCache, RouterError> {
    if !path.exists() {
        return Ok(TicketCache::default());
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(TicketCache::default());
    }
    let persisted: PersistedTicketCache = rmp_serde::from_slice(&bytes)?;
    Ok(TicketCache::from_persisted(persisted))
}

#[derive(Debug)]
enum OutboundPreparationError {
    MissingMessageId,
    Message(MessageError),
    Stamp(StampError),
}

impl fmt::Display for OutboundPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutboundPreparationError::MissingMessageId => {
                write!(f, "message hash not available during stamp generation")
            }
            OutboundPreparationError::Message(err) => {
                write!(f, "message serialization failed: {}", err)
            }
            OutboundPreparationError::Stamp(err) => {
                write!(f, "stamp generation failed: {}", err)
            }
        }
    }
}

impl From<MessageError> for OutboundPreparationError {
    fn from(err: MessageError) -> Self {
        OutboundPreparationError::Message(err)
    }
}

impl From<StampError> for OutboundPreparationError {
    fn from(err: StampError) -> Self {
        OutboundPreparationError::Stamp(err)
    }
}
