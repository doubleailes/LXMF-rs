//! LXMF Announce Handlers
//!
//! This module contains the announce handler implementations for LXMF:
//! - `LXMFDeliveryAnnounceHandler`: Handles delivery announces ("lxmf.delivery")
//! - `LXMFPropagationAnnounceHandler`: Handles propagation node announces ("lxmf.propagation")
//!
//! These handlers implement the Reticulum `AnnounceHandler` trait and can be
//! registered with the transport using `transport.register_announce_handler()`.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use log::{error, trace, warn};
use reticulum::{hash::AddressHash, packet::PacketDataBuffer, transport::AnnounceHandler};

use crate::{PeerMetadata, ValidMethod};

use super::router::{
    APP_NAME, DELIVERY_ASPECT, LxmRouter, PROPAGATION_ASPECT, pn_announce_data_is_valid,
    stamp_cost_from_app_data,
};

/// LXMF Delivery Announce Handler
///
/// Handles incoming announces for the "lxmf.delivery" aspect.
/// When an announce is received, it:
/// 1. Extracts the stamp_cost from the app_data and stores it in the handler's cache
/// 2. Triggers immediate delivery attempts for matching pending outbound messages
///
/// The stamp cost cache can be queried using `get_stamp_cost()`.
///
/// References Python LXMF/LXMF.py class LXMFDeliveryAnnounceHandler
pub struct LXMFDeliveryAnnounceHandler {
    /// The aspect filter for this handler: "lxmf.delivery"
    pub aspect_filter: String,
    /// Whether to receive path responses (always true for LXMF delivery)
    pub receive_path_responses: bool,
    /// Reference to the LXMF router
    lxmrouter: LxmRouter,
    /// Cache of stamp costs indexed by destination hash
    /// References Python LXMF/LXMF.py LXMFDeliveryAnnounceHandler.stamp_costs
    stamp_costs: Arc<Mutex<HashMap<AddressHash, u8>>>,
}

impl LXMFDeliveryAnnounceHandler {
    /// Create a new delivery announce handler for the given router.
    pub fn new(lxmrouter: LxmRouter) -> Self {
        trace!("Creating LXMFDeliveryAnnounceHandler");
        Self {
            aspect_filter: format!("{}.{}", APP_NAME, DELIVERY_ASPECT),
            receive_path_responses: true,
            lxmrouter,
            stamp_costs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get the stamp cost for a destination from the handler's cache.
    ///
    /// Returns `Some(cost)` if a stamp cost has been discovered for this destination
    /// via an announce, or `None` if no stamp cost is known.
    ///
    /// References Python LXMF/LXMF.py LXMFDeliveryAnnounceHandler.stamp_costs
    pub fn get_stamp_cost(&self, destination_hash: &AddressHash) -> Option<u8> {
        trace!("Getting stamp cost for {}", destination_hash);
        self.stamp_costs
            .lock()
            .unwrap()
            .get(destination_hash)
            .copied()
    }

    /// Handle a received announce.
    ///
    /// This method should be called when an announce is received for a destination
    /// matching the aspect filter. It will:
    /// 1. Extract and cache the stamp_cost from the announce app_data
    /// 2. Trigger immediate delivery for any pending outbound messages to this destination
    ///
    /// # Arguments
    /// * `destination_hash` - The hash of the announcing destination
    /// * `app_data` - The application data from the announce (contains display_name and stamp_cost)
    ///
    /// References Python LXMF/LXMF.py LXMFDeliveryAnnounceHandler.received_announce()
    pub fn received_announce(&self, destination_hash: AddressHash, app_data: &[u8]) {
        log::debug!(
            "received_announce: processing announce from {} with app_data: {:?}",
            hex::encode(destination_hash.as_slice()),
            hex::encode(app_data)
        );

        // Extract and store stamp_cost from app_data in the handler's cache
        // References Python LXMF/LXMF.py LXMFDeliveryAnnounceHandler.stamp_costs[destination_hash]
        match std::panic::catch_unwind(|| stamp_cost_from_app_data(app_data)) {
            Ok(stamp_cost_opt) => {
                log::debug!("stamp_cost_from_app_data returned: {:?}", stamp_cost_opt);
                if let Some(stamp_cost) = stamp_cost_opt {
                    // Store in handler's stamp_costs cache
                    self.stamp_costs
                        .lock()
                        .unwrap()
                        .insert(destination_hash, stamp_cost);
                    log::info!(
                        "Stored stamp cost {} for {} in handler cache",
                        stamp_cost,
                        hex::encode(destination_hash.as_slice())
                    );

                    // Also update router's cache for backward compatibility
                    if let Err(e) = self
                        .lxmrouter
                        .update_outbound_stamp_cost(destination_hash, stamp_cost)
                    {
                        error!(
                            "Failed to update stamp cost in router for {}: {}",
                            hex::encode(destination_hash.as_slice()),
                            e
                        );
                    }
                } else {
                    log::debug!(
                        "No stamp cost found in app_data for {}",
                        hex::encode(destination_hash.as_slice())
                    );
                }
            }
            Err(_) => {
                error!(
                    "An error occurred while trying to decode announced stamp cost for {}",
                    hex::encode(destination_hash.as_slice())
                );
            }
        }

        // Check pending outbound messages and trigger delivery for matching destinations
        // with DIRECT or OPPORTUNISTIC methods
        self.trigger_outbound_for_destination(destination_hash);
    }

    /// Trigger immediate delivery attempts for pending outbound messages to the given destination.
    ///
    /// Only triggers for messages with DIRECT or OPPORTUNISTIC delivery methods.
    fn trigger_outbound_for_destination(&self, destination_hash: AddressHash) {
        trace!(
            "Checking pending outbound messages for destination {}",
            hex::encode(destination_hash.as_slice())
        );
        let should_trigger = {
            let pending = self.lxmrouter.inner.pending_outbound.lock().unwrap();
            pending.iter().any(|msg| {
                msg.destination_hash() == destination_hash
                    && (msg.method() == ValidMethod::Direct
                        || msg.method() == ValidMethod::Opportunistic)
            })
        };

        if should_trigger {
            trace!(
                "Announce received for {}, triggering outbound processing",
                hex::encode(destination_hash.as_slice())
            );
            // Trigger outbound processing in a separate thread to avoid blocking
            let router = self.lxmrouter.clone();
            thread::spawn(move || {
                // Small delay to ensure any processing locks are released
                thread::sleep(Duration::from_millis(100));
                router.process_outbound();
            });
        }
    }

    /// Get a reference to the underlying router.
    pub fn router(&self) -> &LxmRouter {
        &self.lxmrouter
    }
}

/// Implementation of the Reticulum AnnounceHandler trait for LXMF delivery announces.
///
/// This allows the handler to be registered with the transport using
/// `transport.register_announce_handler()`.
impl AnnounceHandler for LXMFDeliveryAnnounceHandler {
    fn handle_announce(
        &self,
        destination: Arc<tokio::sync::Mutex<reticulum::destination::SingleOutputDestination>>,
        app_data: PacketDataBuffer,
    ) {
        trace!("LXMFDeliveryAnnounceHandler: handle_announce called for destination");
        // Clone what we need for the spawned task
        let lxmrouter = self.lxmrouter.clone();
        let stamp_costs = self.stamp_costs.clone();

        // Spawn a task to handle the announce asynchronously
        tokio::spawn(async move {
            let destination_hash = {
                let dest = destination.lock().await;
                dest.desc.address_hash
            };

            log::info!(
                "AnnounceHandler: received delivery announce from {} with {} bytes of app_data",
                hex::encode(destination_hash.as_slice()),
                app_data.len()
            );

            // Extract stamp cost from app_data
            if let Some(stamp_cost) = stamp_cost_from_app_data(app_data.as_slice()) {
                log::info!(
                    "Caching stamp cost {} for destination {}",
                    stamp_cost,
                    destination_hash
                );

                // Cache in handler's stamp_costs map
                stamp_costs
                    .lock()
                    .unwrap()
                    .insert(destination_hash, stamp_cost);

                // Also update router's outbound stamp cost cache
                #[allow(unused_must_use)]
                lxmrouter.update_outbound_stamp_cost(destination_hash, stamp_cost);
            }

            // TODO: Trigger immediate delivery attempts for matching pending outbound messages
            // References Python LXMF/LXMF.py LXMFDeliveryAnnounceHandler.received_announce()
        });
    }

    fn aspect_filter(&self) -> Option<&str> {
        Some(&self.aspect_filter)
    }

    fn receive_path_responses(&self) -> bool {
        self.receive_path_responses
    }
}

/// A shared, cloneable wrapper for LXMFDeliveryAnnounceHandler.
///
/// This wrapper allows the handler to be shared between the registration
/// with transport and direct queries for stamp_cost.
///
/// Usage:
/// ```ignore
/// let handler = SharedDeliveryAnnounceHandler::new(router.clone());
/// transport.register_announce_handler(handler.clone()).await;
/// // Later, query stamp cost:
/// let cost = handler.get_stamp_cost(&destination_hash);
/// ```
#[derive(Clone)]
pub struct SharedDeliveryAnnounceHandler {
    inner: Arc<LXMFDeliveryAnnounceHandler>,
}

impl SharedDeliveryAnnounceHandler {
    /// Create a new shared delivery announce handler.
    pub fn new(lxmrouter: LxmRouter) -> Self {
        trace!("Creating SharedDeliveryAnnounceHandler");
        Self {
            inner: Arc::new(LXMFDeliveryAnnounceHandler::new(lxmrouter)),
        }
    }

    /// Get the stamp cost for a destination from the handler's cache.
    ///
    /// Returns `Some(cost)` if a stamp cost has been discovered for this destination
    /// via an announce, or `None` if no stamp cost is known.
    pub fn get_stamp_cost(&self, destination_hash: &AddressHash) -> Option<u8> {
        trace!(
            "SharedDeliveryAnnounceHandler: get_stamp_cost called for {}",
            hex::encode(destination_hash.as_slice())
        );
        self.inner.get_stamp_cost(destination_hash)
    }

    /// Get a reference to the underlying router.
    pub fn router(&self) -> &LxmRouter {
        self.inner.router()
    }

    /// Get the aspect filter for this handler.
    pub fn aspect_filter(&self) -> &str {
        &self.inner.aspect_filter
    }
}

impl AnnounceHandler for SharedDeliveryAnnounceHandler {
    fn handle_announce(
        &self,
        destination: Arc<tokio::sync::Mutex<reticulum::destination::SingleOutputDestination>>,
        app_data: PacketDataBuffer,
    ) {
        trace!("SharedDeliveryAnnounceHandler: handle_announce called");
        self.inner.handle_announce(destination, app_data);
    }

    fn aspect_filter(&self) -> Option<&str> {
        Some(&self.inner.aspect_filter)
    }

    fn receive_path_responses(&self) -> bool {
        self.inner.receive_path_responses()
    }
}

/// LXMF Propagation Node Announce Handler
///
/// Handles incoming announces for the "lxmf.propagation" aspect.
/// When an announce is received from a propagation node, it:
/// 1. Validates the propagation node announce data format
/// 2. Extracts peer configuration (timebase, transfer limits, stamp costs, etc.)
/// 3. Manages automatic peering with other propagation nodes
/// 4. Updates peer state for existing peers
///
/// References Python LXMF/Handlers.py class LXMFPropagationAnnounceHandler
pub struct LXMFPropagationAnnounceHandler {
    /// The aspect filter for this handler: "lxmf.propagation"
    pub aspect_filter: String,
    /// Whether to receive path responses (always true for LXMF propagation)
    pub receive_path_responses: bool,
    /// Reference to the LXMF router
    lxmrouter: LxmRouter,
}

impl LXMFPropagationAnnounceHandler {
    /// Create a new propagation announce handler for the given router.
    pub fn new(lxmrouter: LxmRouter) -> Self {
        Self {
            aspect_filter: format!("{}.{}", APP_NAME, PROPAGATION_ASPECT),
            receive_path_responses: true,
            lxmrouter,
        }
    }

    /// Handle a received propagation node announce.
    ///
    /// This method should be called when an announce is received for a destination
    /// matching the propagation aspect filter. It will:
    /// 1. Validate the propagation node announce data format
    /// 2. Extract peer configuration and update peer state
    /// 3. Manage automatic peering if enabled
    ///
    /// # Arguments
    /// * `destination_hash` - The hash of the announcing propagation node
    /// * `app_data` - The application data from the announce (propagation node config)
    /// * `is_path_response` - Whether this announce is a path response
    ///
    /// References Python LXMF/Handlers.py LXMFPropagationAnnounceHandler.received_announce()
    pub fn received_announce(
        &self,
        destination_hash: AddressHash,
        app_data: &[u8],
        is_path_response: bool,
    ) {
        // Only process if we're running as a propagation node
        if !self.lxmrouter.is_propagation_node() {
            return;
        }

        // Validate propagation node announce data
        let pn_data = match pn_announce_data_is_valid(app_data) {
            Some(data) => data,
            None => {
                trace!(
                    "Ignoring invalid propagation node announce from {}",
                    hex::encode(destination_hash.as_slice())
                );
                return;
            }
        };

        let node_timebase = pn_data.timebase;
        let propagation_enabled = pn_data.node_state;
        let propagation_transfer_limit = pn_data.transfer_limit;
        let propagation_sync_limit = pn_data.sync_limit;
        let propagation_stamp_cost = pn_data.stamp_cost;
        let propagation_stamp_cost_flexibility = pn_data.stamp_flexibility;
        let peering_cost = pn_data.peering_cost;
        let metadata = pn_data.metadata.clone();

        // Check if this is a static peer
        let is_static_peer = self.lxmrouter.is_static_peer(&destination_hash);

        if is_static_peer {
            // Always update static peers
            if (!is_path_response || self.lxmrouter.peer_last_heard(&destination_hash) == 0.0)
                && let Err(e) = self.lxmrouter.peer(
                    destination_hash,
                    node_timebase,
                    propagation_transfer_limit,
                    propagation_sync_limit,
                    propagation_stamp_cost,
                    propagation_stamp_cost_flexibility,
                    peering_cost,
                    metadata.clone(),
                )
            {
                warn!("Failed to update static peer {}: {}", destination_hash, e);
            }
        } else {
            // Auto-peering logic for non-static peers
            if self.lxmrouter.autopeer_enabled() && !is_path_response {
                if propagation_enabled {
                    // TODO: Check hops_to when transport provides this info
                    // For now, auto-peer with all propagation nodes within range
                    if let Err(e) = self.lxmrouter.peer(
                        destination_hash,
                        node_timebase,
                        propagation_transfer_limit,
                        propagation_sync_limit,
                        propagation_stamp_cost,
                        propagation_stamp_cost_flexibility,
                        peering_cost,
                        metadata,
                    ) {
                        warn!("Failed to auto-peer with {}: {}", destination_hash, e);
                    }
                } else {
                    // Propagation node disabled, unpeer if we had a peering
                    self.lxmrouter.unpeer(&destination_hash);
                }
            }
        }
    }

    /// Get a reference to the underlying router.
    pub fn router(&self) -> &LxmRouter {
        &self.lxmrouter
    }
}

/// Implementation of the Reticulum AnnounceHandler trait for LXMF propagation announces.
///
/// This allows the handler to be registered with the transport using
/// `transport.register_announce_handler()`.
impl AnnounceHandler for LXMFPropagationAnnounceHandler {
    fn handle_announce(
        &self,
        destination: Arc<tokio::sync::Mutex<reticulum::destination::SingleOutputDestination>>,
        app_data: PacketDataBuffer,
    ) {
        // Clone data needed for the spawned task
        let lxmrouter = self.lxmrouter.clone();
        let app_data_vec = app_data.as_slice().to_vec();

        // Spawn an async task to avoid blocking the runtime
        tokio::spawn(async move {
            // Get destination hash using async lock
            let destination_hash = {
                let dest = destination.lock().await;
                dest.desc.address_hash
            };

            trace!(
                "AnnounceHandler: received propagation announce from {}",
                hex::encode(destination_hash.as_slice())
            );

            // Create a temporary handler instance to call received_announce
            let handler = LXMFPropagationAnnounceHandler::new(lxmrouter);
            // For now, assume non-path-response announces
            // TODO: Track path response state when available from transport
            handler.received_announce(destination_hash, &app_data_vec, false);
        });
    }

    fn aspect_filter(&self) -> Option<&str> {
        Some(&self.aspect_filter)
    }

    fn receive_path_responses(&self) -> bool {
        self.receive_path_responses
    }
}

/// Validated propagation node announce data.
///
/// References Python LXMF/LXMF.py pn_announce_data_is_valid()
#[derive(Debug, Clone)]
pub struct PropagationNodeAnnounceData {
    /// Current node timebase (Unix timestamp)
    pub timebase: f64,
    /// Whether the propagation node is active
    pub node_state: bool,
    /// Per-transfer limit for message propagation in bytes (None = unlimited)
    pub transfer_limit: Option<f64>,
    /// Limit for incoming propagation node syncs in bytes (None = unlimited)
    pub sync_limit: Option<f64>,
    /// Propagation stamp cost for this node
    pub stamp_cost: Option<u32>,
    /// Stamp cost flexibility
    pub stamp_flexibility: Option<u32>,
    /// Peering cost
    pub peering_cost: Option<u32>,
    /// Node metadata (uses IndexMap to match PeerMetadata type)
    pub metadata: Option<PeerMetadata>,
}
