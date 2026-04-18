//! LXMF Announce Handlers
//!
//! This module contains the announce handling functions for LXMF:
//! - `handle_delivery_announce`: Handles delivery announces ("lxmf.delivery")
//! - `handle_propagation_announce`: Handles propagation node announces ("lxmf.propagation")
//!
//! These are plain functions called from the router's event loop when an
//! `AnnounceReceived` event matches the relevant aspect.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use log::{debug, error, info, trace, warn};
// ReceivedAnnounce is used for type-level documentation but handling
// is done via event-loop functions that receive raw app_data bytes.
use crate::compat::AddressHash;

use crate::{PeerMetadata, ValidMethod};

use super::router::{
    APP_NAME, DELIVERY_ASPECT, LxmRouter, PROPAGATION_ASPECT, pn_announce_data_is_valid,
    stamp_cost_from_app_data,
};

/// LXMF Delivery Announce Handler
///
/// Maintains a stamp_cost cache and provides `received_announce()` to be
/// called from the router event loop when an announce with aspect
/// "lxmf.delivery" arrives.
///
/// References Python LXMF/LXMF.py class LXMFDeliveryAnnounceHandler
pub struct LXMFDeliveryAnnounceHandler {
    /// The aspect filter for this handler: "lxmf.delivery"
    pub aspect_filter: String,
    /// Reference to the LXMF router
    lxmrouter: LxmRouter,
    /// Cache of stamp costs indexed by destination hash
    stamp_costs: Arc<Mutex<HashMap<AddressHash, u8>>>,
}

impl LXMFDeliveryAnnounceHandler {
    /// Create a new delivery announce handler for the given router.
    pub fn new(lxmrouter: LxmRouter) -> Self {
        Self {
            aspect_filter: format!("{}.{}", APP_NAME, DELIVERY_ASPECT),
            lxmrouter,
            stamp_costs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get the stamp cost for a destination from the handler's cache.
    pub fn get_stamp_cost(&self, destination_hash: &AddressHash) -> Option<u8> {
        self.stamp_costs
            .lock()
            .unwrap()
            .get(destination_hash)
            .copied()
    }

    /// Handle a received delivery announce.
    ///
    /// Called from the router event loop when a `NodeEvent::AnnounceReceived`
    /// matches aspect "lxmf.delivery".
    pub fn received_announce(&self, destination_hash: AddressHash, app_data: &[u8]) {
        debug!(
            "received_announce: processing delivery announce from {} with {} bytes app_data",
            hex::encode(destination_hash.as_slice()),
            app_data.len()
        );

        match std::panic::catch_unwind(|| stamp_cost_from_app_data(app_data)) {
            Ok(stamp_cost_opt) => {
                if let Some(stamp_cost) = stamp_cost_opt {
                    self.stamp_costs
                        .lock()
                        .unwrap()
                        .insert(destination_hash, stamp_cost);
                    info!(
                        "Stored stamp cost {} for {} in handler cache",
                        stamp_cost,
                        hex::encode(destination_hash.as_slice())
                    );

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
                }
            }
            Err(_) => {
                error!(
                    "Error decoding announced stamp cost for {}",
                    hex::encode(destination_hash.as_slice())
                );
            }
        }

        self.trigger_outbound_for_destination(destination_hash);
    }

    fn trigger_outbound_for_destination(&self, destination_hash: AddressHash) {
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
            let router = self.lxmrouter.clone();
            thread::spawn(move || {
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

/// Handle a delivery announce from the event loop.
///
/// This is a standalone function that can be called directly from the
/// router's event loop task when a `NodeEvent::AnnounceReceived` matches
/// the "lxmf.delivery" aspect.
pub fn handle_delivery_announce(
    router: &LxmRouter,
    destination_hash: AddressHash,
    app_data: &[u8],
) {
    debug!(
        "handle_delivery_announce: {} with {} bytes app_data",
        hex::encode(destination_hash.as_slice()),
        app_data.len()
    );

    if let Some(stamp_cost) = stamp_cost_from_app_data(app_data) {
        info!(
            "Caching stamp cost {} for destination {}",
            stamp_cost,
            hex::encode(destination_hash.as_slice())
        );
        if let Err(e) = router.update_outbound_stamp_cost(destination_hash, stamp_cost) {
            error!(
                "Failed to update stamp cost for {}: {}",
                hex::encode(destination_hash.as_slice()),
                e
            );
        }
    }

    // Check pending outbound messages and trigger delivery
    let should_trigger = {
        let pending = router.inner.pending_outbound.lock().unwrap();
        pending.iter().any(|msg| {
            msg.destination_hash() == destination_hash
                && (msg.method() == ValidMethod::Direct
                    || msg.method() == ValidMethod::Opportunistic)
        })
    };

    if should_trigger {
        trace!(
            "Delivery announce for {}, triggering outbound processing",
            hex::encode(destination_hash.as_slice())
        );
        let router = router.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            router.process_outbound();
        });
    }
}

/// A shared, cloneable wrapper for LXMFDeliveryAnnounceHandler.
#[derive(Clone)]
pub struct SharedDeliveryAnnounceHandler {
    inner: Arc<LXMFDeliveryAnnounceHandler>,
}

impl SharedDeliveryAnnounceHandler {
    pub fn new(lxmrouter: LxmRouter) -> Self {
        Self {
            inner: Arc::new(LXMFDeliveryAnnounceHandler::new(lxmrouter)),
        }
    }

    pub fn get_stamp_cost(&self, destination_hash: &AddressHash) -> Option<u8> {
        self.inner.get_stamp_cost(destination_hash)
    }

    pub fn router(&self) -> &LxmRouter {
        self.inner.router()
    }

    pub fn aspect_filter(&self) -> &str {
        &self.inner.aspect_filter
    }

    /// Handle a received announce (delegates to inner handler).
    pub fn received_announce(&self, destination_hash: AddressHash, app_data: &[u8]) {
        self.inner.received_announce(destination_hash, app_data);
    }
}

/// LXMF Propagation Node Announce Handler
///
/// Handles incoming announces for the "lxmf.propagation" aspect.
///
/// References Python LXMF/Handlers.py class LXMFPropagationAnnounceHandler
pub struct LXMFPropagationAnnounceHandler {
    /// The aspect filter for this handler: "lxmf.propagation"
    pub aspect_filter: String,
    /// Reference to the LXMF router
    lxmrouter: LxmRouter,
}

impl LXMFPropagationAnnounceHandler {
    pub fn new(lxmrouter: LxmRouter) -> Self {
        Self {
            aspect_filter: format!("{}.{}", APP_NAME, PROPAGATION_ASPECT),
            lxmrouter,
        }
    }

    pub fn received_announce(
        &self,
        destination_hash: AddressHash,
        app_data: &[u8],
        is_path_response: bool,
    ) {
        if !self.lxmrouter.is_propagation_node() {
            return;
        }

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

        let is_static_peer = self.lxmrouter.is_static_peer(&destination_hash);

        if is_static_peer {
            if (!is_path_response || self.lxmrouter.peer_last_heard(&destination_hash) == 0.0)
                && let Err(e) = self.lxmrouter.peer(
                    destination_hash,
                    pn_data.timebase,
                    pn_data.transfer_limit,
                    pn_data.sync_limit,
                    pn_data.stamp_cost,
                    pn_data.stamp_flexibility,
                    pn_data.peering_cost,
                    pn_data.metadata.clone(),
                )
            {
                warn!("Failed to update static peer {}: {}", destination_hash, e);
            }
        } else if self.lxmrouter.autopeer_enabled() && !is_path_response {
            if pn_data.node_state {
                if let Err(e) = self.lxmrouter.peer(
                    destination_hash,
                    pn_data.timebase,
                    pn_data.transfer_limit,
                    pn_data.sync_limit,
                    pn_data.stamp_cost,
                    pn_data.stamp_flexibility,
                    pn_data.peering_cost,
                    pn_data.metadata,
                ) {
                    warn!("Failed to auto-peer with {}: {}", destination_hash, e);
                }
            } else {
                self.lxmrouter.unpeer(&destination_hash);
            }
        }
    }

    pub fn router(&self) -> &LxmRouter {
        &self.lxmrouter
    }
}

/// Handle a propagation announce from the event loop.
///
/// Standalone function called from the router's event loop when a
/// `NodeEvent::AnnounceReceived` matches "lxmf.propagation".
pub fn handle_propagation_announce(
    router: &LxmRouter,
    destination_hash: AddressHash,
    app_data: &[u8],
    is_path_response: bool,
) {
    if !router.is_propagation_node() {
        return;
    }

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

    let is_static_peer = router.is_static_peer(&destination_hash);

    if is_static_peer {
        if (!is_path_response || router.peer_last_heard(&destination_hash) == 0.0)
            && let Err(e) = router.peer(
                destination_hash,
                pn_data.timebase,
                pn_data.transfer_limit,
                pn_data.sync_limit,
                pn_data.stamp_cost,
                pn_data.stamp_flexibility,
                pn_data.peering_cost,
                pn_data.metadata.clone(),
            )
        {
            warn!("Failed to update static peer {}: {}", destination_hash, e);
        }
    } else if router.autopeer_enabled() && !is_path_response {
        if pn_data.node_state {
            if let Err(e) = router.peer(
                destination_hash,
                pn_data.timebase,
                pn_data.transfer_limit,
                pn_data.sync_limit,
                pn_data.stamp_cost,
                pn_data.stamp_flexibility,
                pn_data.peering_cost,
                pn_data.metadata,
            ) {
                warn!("Failed to auto-peer with {}: {}", destination_hash, e);
            }
        } else {
            router.unpeer(&destination_hash);
        }
    }
}

/// Validated propagation node announce data.
///
/// References Python LXMF/LXMF.py pn_announce_data_is_valid()
#[derive(Debug, Clone)]
pub struct PropagationNodeAnnounceData {
    pub timebase: f64,
    pub node_state: bool,
    pub transfer_limit: Option<f64>,
    pub sync_limit: Option<f64>,
    pub stamp_cost: Option<u32>,
    pub stamp_flexibility: Option<u32>,
    pub peering_cost: Option<u32>,
    pub metadata: Option<PeerMetadata>,
}
