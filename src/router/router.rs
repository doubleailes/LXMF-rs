//! LXMRouter (Rust) — structural port of LXMF's Python LXMRouter,
//! adapted to Reticulum-rs concepts (Identity/Destination/Transport).
//!
//! Notes:
//! - This is intentionally “scaffolding-first”: it mirrors Python fields/states and job-loop shape,
//!   but leaves several Reticulum-rs integration points as TODOs until the exact APIs you want to use
//!   are finalized (e.g. announce handlers, link callbacks, request handlers).
//! - Reticulum-rs is organized around core modules like identity/destination/transport/packet, which
//!   is what this router expects to integrate with. :contentReference[oaicite:0]{index=0}

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use reticulum::{
    destination::{DestinationName, SingleOutputDestination},
    hash::AddressHash,
    identity::PrivateIdentity,
    // transport::Transport,  // TODO: integrate once you decide how LXMF-rs drives Reticulum-rs
};

use crate::{router::error::RouterError};

pub const APP_NAME: &str = "lxmf";

fn unix_time_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}



/// Propagation transfer states (mirrors Python constants PR_*).
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

/// Router config (mirrors __init__ parameters & defaults).
#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub name: Option<String>,
    pub storage_root: PathBuf,

    // Peering / discovery
    pub autopeer: bool,
    pub autopeer_maxdepth: u8,
    pub max_peers: usize,
    pub from_static_only: bool,
    pub static_peers: Vec<AddressHash>,

    // Limits / costs
    pub propagation_limit_kb: u32,
    pub delivery_limit_kb: u32,
    pub sync_limit_kb: u32,
    pub propagation_stamp_cost: u8,
    pub propagation_stamp_cost_flex: u8,
    pub peering_cost: u8,
    pub max_peering_cost: u8,

    // Security / enforcement
    pub enforce_ratchets: bool,
    pub enforce_stamps: bool,
}

impl RouterConfig {
    pub fn new(storage_root: impl Into<PathBuf>) -> Self {
        Self {
            name: None,
            storage_root: storage_root.into(),

            autopeer: true,
            autopeer_maxdepth: 4,
            max_peers: 20,
            from_static_only: false,
            static_peers: vec![],

            propagation_limit_kb: 256,
            sync_limit_kb: 256 * 40,
            delivery_limit_kb: 1000,
            propagation_stamp_cost: 16,
            propagation_stamp_cost_flex: 3,
            peering_cost: 18,
            max_peering_cost: 26,

            enforce_ratchets: false,
            enforce_stamps: false,
        }
    }

    pub fn storagepath_lxmf(&self) -> PathBuf {
        self.storage_root.join("lxmf")
    }

    pub fn ratchet_path(&self) -> PathBuf {
        self.storagepath_lxmf().join("ratchets")
    }

    pub fn messagestore_path(&self) -> PathBuf {
        self.storagepath_lxmf().join("messagestore")
    }
}

/// Mirrors Python: self.available_tickets = {"outbound": {}, "inbound": {}, "last_deliveries": {}}
#[derive(Debug, Default, Clone)]
pub struct TicketCache {
    pub outbound: HashMap<AddressHash, (u64 /*expires*/, Vec<u8> /*ticket*/)>,

    /// inbound[destination_hash][ticket] = expires
    pub inbound: HashMap<AddressHash, HashMap<Vec<u8>, u64>>,

    pub last_deliveries: HashMap<AddressHash, u64>,
}

/// Minimal “delivery destination” record (Python stores actual RNS.Destination objects).
///
/// In Reticulum-rs you’ll likely store a Destination handle that can:
/// - set callbacks (packet/link/resource)
/// - announce with app_data
/// - decrypt inbound
#[derive(Debug, Clone)]
pub struct DeliveryDestination {
    pub dest: SingleOutputDestination,
    pub display_name: Option<String>,
    pub inbound_stamp_cost: Option<u8>,
    // pub ratchet_enabled: bool,
}

/// Propagation-node local entry (Python: self.propagation_entries[transient_id] = [...])
#[derive(Debug, Clone)]
pub struct PropagationEntry {
    pub destination_hash: AddressHash,
    pub filepath: PathBuf,
    pub received_at: u64,
    pub msg_size: u64,
    pub handled_peers: Vec<AddressHash>,
    pub unhandled_peers: Vec<AddressHash>,
    pub stamp_value: u32,
}

/// Core router struct.
pub struct LxmRouter {
    // Identity
    pub identity: PrivateIdentity,

    // Config / storage
    pub cfg: RouterConfig,

    // Queues
    pending_inbound: Mutex<VecDeque<Vec<u8>>>,
    pending_outbound: Mutex<VecDeque<Arc<Mutex<crate::message::LXMessage>>>>, // align with your existing LXMessage
    failed_outbound: Mutex<VecDeque<Arc<Mutex<crate::message::LXMessage>>>>,

    // Links (shape only — decide Reticulum-rs link types later)
    direct_links: Mutex<HashMap<AddressHash, ()>>,
    backchannel_links: Mutex<HashMap<AddressHash, ()>>,

    // Delivery destinations
    delivery_destinations: Mutex<HashMap<AddressHash, DeliveryDestination>>,

    // Lists (auth/priorities)
    prioritised: Mutex<HashSet<AddressHash>>,
    ignored: Mutex<HashSet<AddressHash>>,
    allowed: Mutex<HashSet<AddressHash>>,
    control_allowed: Mutex<HashSet<AddressHash>>,
    auth_required: Mutex<bool>,

    // Propagation node state
    propagation_node: Mutex<bool>,
    propagation_node_start_time: Mutex<Option<u64>>,
    retain_synced_on_node: Mutex<bool>,

    // Outbound propagation target
    outbound_propagation_node: Mutex<Option<AddressHash>>,
    outbound_propagation_link: Mutex<Option<()>>, // TODO link handle

    // Propagation transfer progress
    propagation_transfer_state: Mutex<PropagationTransferState>,
    propagation_transfer_progress: Mutex<f32>,
    propagation_transfer_last_result: Mutex<Option<usize>>,
    propagation_transfer_last_duplicates: Mutex<Option<usize>>,
    propagation_transfer_max_messages: Mutex<Option<usize>>,

    // Local transient caches (delivered/processed)
    locally_delivered_transient_ids: Mutex<HashMap<[u8; 32], u64>>,
    locally_processed_transient_ids: Mutex<HashMap<[u8; 32], u64>>,

    // Costs & tickets
    outbound_stamp_costs: Mutex<HashMap<AddressHash, (u64 /*ts*/, u8 /*cost*/)>>, // mirrors Python [timestamp, cost]
    available_tickets: Mutex<TicketCache>,

    // Peers & propagation entries
    peers: Mutex<HashMap<AddressHash, crate::peer::LxmPeer>>,
    propagation_entries: Mutex<HashMap<[u8; 32], PropagationEntry>>,
    peer_distribution_queue: Mutex<VecDeque<([u8; 32], Option<AddressHash>)>>,

    // Job loop
    exit_handler_running: Mutex<bool>,
}

impl LxmRouter {
    // ---- constants mirroring Python (subset) ----
    pub const PROCESSING_INTERVAL: Duration = Duration::from_secs(4);
    pub const JOB_OUTBOUND_INTERVAL: u64 = 1;
    pub const JOB_LINKS_INTERVAL: u64 = 1;
    pub const JOB_TRANSIENT_INTERVAL: u64 = 60;
    pub const JOB_STORE_INTERVAL: u64 = 120;
    pub const JOB_PEERSYNC_INTERVAL: u64 = 6;
    pub const JOB_ROTATE_INTERVAL: u64 = 56 * Self::JOB_PEERSYNC_INTERVAL;

    pub const MESSAGE_EXPIRY_S: u64 = 30 * 24 * 60 * 60;
    pub const STAMP_COST_EXPIRY_S: u64 = 45 * 24 * 60 * 60;

    pub fn new(identity: Option<PrivateIdentity>, cfg: RouterConfig) -> Result<Arc<Self>, RouterError> {
        if cfg.storage_root.as_os_str().is_empty() {
            return Err(RouterError::MissingStoragePath);
        }

        let identity = identity.unwrap_or_else(|| PrivateIdentity::new_from_name("toto"));

        // Ensure base dirs exist.
        std::fs::create_dir_all(cfg.storagepath_lxmf())?;
        std::fs::create_dir_all(cfg.ratchet_path())?;

        let router = Arc::new(Self {
            identity,
            cfg,

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

            propagation_node: Mutex::new(false),
            propagation_node_start_time: Mutex::new(None),
            retain_synced_on_node: Mutex::new(false),

            outbound_propagation_node: Mutex::new(None),
            outbound_propagation_link: Mutex::new(None),

            propagation_transfer_state: Mutex::new(PropagationTransferState::Idle),
            propagation_transfer_progress: Mutex::new(0.0),
            propagation_transfer_last_result: Mutex::new(None),
            propagation_transfer_last_duplicates: Mutex::new(None),
            propagation_transfer_max_messages: Mutex::new(None),

            locally_delivered_transient_ids: Mutex::new(HashMap::new()),
            locally_processed_transient_ids: Mutex::new(HashMap::new()),

            outbound_stamp_costs: Mutex::new(HashMap::new()),
            available_tickets: Mutex::new(TicketCache::default()),

            peers: Mutex::new(HashMap::new()),
            propagation_entries: Mutex::new(HashMap::new()),
            peer_distribution_queue: Mutex::new(VecDeque::new()),

            exit_handler_running: Mutex::new(false),
        });

        // Start the job loop (Tokio is recommended because Reticulum-rs commonly uses async runtimes).
        // You can swap this to std::thread if LXMF-rs is sync.
        LxmRouter::spawn_jobloop(router.clone());

        Ok(router)
    }

    fn spawn_jobloop(this: Arc<Self>) {
        std::thread::spawn(move || {
            let mut tick: u64 = 0;
            loop {
                tick = tick.wrapping_add(1);
                // Best-effort: never panic the loop.
                let _ = this.jobs(tick);
                std::thread::sleep(Self::PROCESSING_INTERVAL);
            }
        });
    }

    fn jobs(&self, tick: u64) -> Result<(), RouterError> {
        if *self.exit_handler_running.lock().unwrap() {
            return Ok(());
        }

        if tick % Self::JOB_OUTBOUND_INTERVAL == 0 {
            self.process_outbound();
        }
        if tick % Self::JOB_LINKS_INTERVAL == 0 {
            self.clean_links();
        }
        if tick % Self::JOB_TRANSIENT_INTERVAL == 0 {
            self.clean_transient_id_caches();
        }
        if tick % Self::JOB_STORE_INTERVAL == 0 {
            if *self.propagation_node.lock().unwrap() {
                self.clean_message_store();
            }
        }
        if tick % Self::JOB_PEERSYNC_INTERVAL == 0 {
            if *self.propagation_node.lock().unwrap() {
                self.flush_queues();
                self.sync_peers();
            }
            self.clean_throttled_peers();
        }
        if tick % Self::JOB_ROTATE_INTERVAL == 0 {
            if *self.propagation_node.lock().unwrap() {
                self.rotate_peers();
            }
        }

        Ok(())
    }

    // ---- Developer-facing API equivalents ----

    pub fn announce(&self, destination_hash: &AddressHash) {
        let map = self.delivery_destinations.lock().unwrap();
        if let Some(dd) = map.get(destination_hash) {
            // TODO: dd.dest.announce(app_data, attached_interface)
            let _ = &dd;
        }
    }

    pub fn get_propagation_node_announce_metadata(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        let mut md = HashMap::new();
        if let Some(name) = &self.cfg.name {
            md.insert(b"name".to_vec(), name.as_bytes().to_vec());
        }
        md
    }

    pub fn register_delivery_identity(
        &self,
        // Python takes RNS.Identity; here we keep using router.identity by default,
        // but you can make this accept a separate identity if needed.
        display_name: Option<String>,
        inbound_stamp_cost: Option<u8>,
    ) -> Result<AddressHash, RouterError> {
        let mut dests = self.delivery_destinations.lock().unwrap();
        if !dests.is_empty() {
            // Python: only one delivery identity supported per router instance.
            // Keep this invariant for now.
            // (If you want multi-identity later, adjust map usage and callbacks.)
        }

        // TODO: in Reticulum-rs, create an inbound SINGLE destination with app name "lxmf" and aspect "delivery".
        // Example placeholder:
        let destination_name = DestinationName::new(APP_NAME, "delivery");
        let delivery_dest = SingleOutputDestination::new(self.identity.clone(), destination_name);

        let dest_hash = delivery_dest.hash();

        dests.insert(
            dest_hash,
            DeliveryDestination {
                dest: delivery_dest,
                display_name,
                inbound_stamp_cost,
            },
        );

        Ok(dest_hash)
    }

    pub fn set_outbound_propagation_node(&self, node: AddressHash) {
        *self.outbound_propagation_node.lock().unwrap() = Some(node);
        // If existing link targets different node, teardown in real impl.
        *self.outbound_propagation_link.lock().unwrap() = None;
    }

    pub fn get_outbound_propagation_node(&self) -> Option<AddressHash> {
        *self.outbound_propagation_node.lock().unwrap()
    }

    pub fn enable_propagation(&self) -> Result<(), RouterError> {
        std::fs::create_dir_all(self.cfg.messagestore_path())?;

        *self.propagation_node.lock().unwrap() = true;
        *self.propagation_node_start_time.lock().unwrap() = Some(unix_time_s());

        // TODO:
        // - create propagation destination: IN/SINGLE "lxmf","propagation"
        // - set default app_data provider
        // - register request handlers (offer, message_get, stats, sync, unpeer)
        // - set packet/link/resource callbacks

        Ok(())
    }

    pub fn disable_propagation(&self) {
        *self.propagation_node.lock().unwrap() = false;
        // TODO: announce PN state changed
    }

    pub fn set_authentication_required(&self, required: bool) {
        *self.auth_required.lock().unwrap() = required;
    }

    pub fn allow(&self, identity_hash: AddressHash) {
        self.allowed.lock().unwrap().insert(identity_hash);
    }

    pub fn disallow(&self, identity_hash: &AddressHash) {
        self.allowed.lock().unwrap().remove(identity_hash);
    }

    pub fn prioritise(&self, dest_hash: AddressHash) {
        self.prioritised.lock().unwrap().insert(dest_hash);
    }

    pub fn unprioritise(&self, dest_hash: &AddressHash) {
        self.prioritised.lock().unwrap().remove(dest_hash);
    }

    pub fn ignore_destination(&self, dest_hash: AddressHash) {
        self.ignored.lock().unwrap().insert(dest_hash);
    }

    pub fn unignore_destination(&self, dest_hash: &AddressHash) {
        self.ignored.lock().unwrap().remove(dest_hash);
    }

    // ---- Core maintenance (mirrors Python jobs) ----

    fn process_outbound(&self) {
        // Mirrors Python process_outbound: walk pending_outbound and advance each message state
        // (opportunistic/direct/propagated), handle retries, link establishment, teardown, fail.
        //
        // TODO: integrate with your existing LXMessage state machine and reticulum-rs send primitives.

        let _q_len = self.pending_outbound.lock().unwrap().len();
    }

    fn clean_links(&self) {
        // Mirrors Python clean_links: remove inactive direct/backchannel links, teardown propagation link.
        // TODO once you have actual link handles stored.
    }

    fn clean_transient_id_caches(&self) {
        let now = unix_time_s();
        let expiry = Self::MESSAGE_EXPIRY_S * 6;

        {
            let mut delivered = self.locally_delivered_transient_ids.lock().unwrap();
            delivered.retain(|_, ts| now <= *ts + expiry);
        }
        {
            let mut processed = self.locally_processed_transient_ids.lock().unwrap();
            processed.retain(|_, ts| now <= *ts + expiry);
        }
    }

    fn clean_message_store(&self) {
        // Mirrors Python clean_message_store:
        // - purge expired entries and invalid file naming
        // - enforce storage limit by removing highest-weight entries
        //
        // TODO: implement once you finalize:
        // - how transient_id is computed (likely full hash of raw LXMF bytes)
        // - file naming convention (Python: hex_transientid_timestamp_stampvalue)
        // - weight function (age * size * priority)
    }

    fn flush_queues(&self) {
        // Mirrors Python flush_queues:
        // - flush peer distribution queue -> queue unhandled messages on peers
        // - ask each peer to process its queues
        //
        // TODO: depends on LxmPeer API.
    }

    fn sync_peers(&self) {
        // Mirrors Python sync_peers:
        // - select peer from waiting/unresponsive pools, request sync transfer
        // TODO: depends on LxmPeer API + reticulum-rs request/transfer primitives.
    }

    fn rotate_peers(&self) {
        // Mirrors Python rotate_peers:
        // - drop low acceptance-rate peers to create headroom
        // TODO: depends on LxmPeer stats tracking.
    }

    fn clean_throttled_peers(&self) {
        // Python keeps a throttled_peers map with timestamps.
        // If you add it, clean expired entries here.
    }
}

// ---- Reticulum-rs destination construction helper (placeholder) ----
//
// You will likely replace this with the real constructor once you’ve chosen
// how LXMF-rs should create destinations under Reticulum-rs.
trait SingleOutputDestinationExt {
    fn new(identity: PrivateIdentity, app: &str, aspect: &str) -> Self;
    fn hash(&self) -> AddressHash;
}

impl SingleOutputDestinationExt for SingleOutputDestination {
    fn new(_identity: PrivateIdentity, _app: &str, _aspect: &str) -> Self {
        // TODO: replace with actual reticulum-rs API.
        unimplemented!("wire this to reticulum-rs destination creation")
    }
    fn hash(&self) -> AddressHash {
        // TODO: replace with actual reticulum-rs API.
        unimplemented!("wire this to reticulum-rs destination hash accessor")
    }
}
