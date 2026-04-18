//! LXMF Transport layer — wraps leviculum's `ReticulumNode`.
//!
//! This module provides `LxmfTransport`, a thin async wrapper around
//! `reticulum_std::ReticulumNode` that exposes the operations LXMF needs:
//! announcing, path discovery, link establishment, resource transfer, and
//! single-packet delivery.
//!
//! The previous `compat::Transport` stub is replaced by this real implementation.

use std::net::SocketAddr;

use reticulum_core::{Destination, DestinationHash, Identity, LinkId};
use reticulum_core::node::NodeEvent;
use reticulum_core::resource::ResourceStrategy;
use reticulum_std::driver::{LinkHandle, ReticulumNode, ReticulumNodeBuilder};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::compat::RnsError;

/// LXMF transport — owns a `ReticulumNode` and provides LXMF-level helpers.
pub struct LxmfTransport {
    node: Mutex<ReticulumNode>,
    event_rx: Mutex<Option<mpsc::Receiver<NodeEvent>>>,
}

impl LxmfTransport {
    /// Create a new transport from an already-built (but not yet started) node.
    ///
    /// The caller is responsible for building the node with the desired interfaces
    /// via `ReticulumNodeBuilder`. This constructor takes the event receiver from
    /// the node before it is started.
    pub fn from_node(mut node: ReticulumNode) -> Self {
        let event_rx = node.take_event_receiver();
        Self {
            node: Mutex::new(node),
            event_rx: Mutex::new(event_rx),
        }
    }

    /// Build a transport with a single TCP client interface and start it.
    pub async fn with_tcp_client(
        identity: Identity,
        addr: SocketAddr,
    ) -> Result<Self, RnsError> {
        let node = ReticulumNodeBuilder::new()
            .identity(identity)
            .add_tcp_client(addr)
            .enable_transport(false)
            .build_sync()
            .map_err(|e| RnsError::Transport(format!("build failed: {}", e)))?;

        let transport = Self::from_node(node);
        transport.start().await?;
        Ok(transport)
    }

    /// Start the underlying node (spawns the event loop).
    pub async fn start(&self) -> Result<(), RnsError> {
        self.node
            .lock()
            .await
            .start()
            .await
            .map_err(|e| RnsError::Transport(format!("start failed: {}", e)))
    }

    /// Stop the underlying node.
    pub async fn stop(&self) -> Result<(), RnsError> {
        self.node
            .lock()
            .await
            .stop()
            .await
            .map_err(|e| RnsError::Transport(format!("stop failed: {}", e)))
    }

    /// Take the event receiver (can only be called once).
    pub async fn take_event_receiver(&self) -> Option<mpsc::Receiver<NodeEvent>> {
        self.event_rx.lock().await.take()
    }

    // ── Path discovery ───────────────────────────────────────────────

    /// Check if a path to the destination is known.
    pub async fn has_path(&self, dest_hash: &DestinationHash) -> bool {
        self.node.lock().await.has_path(dest_hash)
    }

    /// Request a path to the destination.
    pub async fn request_path(&self, dest_hash: &DestinationHash) -> Result<(), RnsError> {
        self.node
            .lock()
            .await
            .request_path(dest_hash)
            .await
            .map_err(|e| RnsError::Transport(format!("request_path failed: {}", e)))
    }

    /// Get hop count to a destination.
    pub async fn hops_to(&self, dest_hash: &DestinationHash) -> Option<u8> {
        self.node.lock().await.hops_to(dest_hash)
    }

    // ── Destination management ───────────────────────────────────────

    /// Register a destination for incoming links and announces.
    pub async fn register_destination(&self, destination: Destination) {
        self.node.lock().await.register_destination(destination);
    }

    /// Announce a registered destination with optional app_data.
    pub async fn announce_destination(
        &self,
        dest_hash: &DestinationHash,
        app_data: Option<&[u8]>,
    ) -> Result<(), RnsError> {
        self.node
            .lock()
            .await
            .announce_destination(dest_hash, app_data)
            .await
            .map_err(|e| RnsError::Transport(format!("announce failed: {}", e)))
    }

    // ── Identity management ──────────────────────────────────────────

    /// Look up a known identity for a destination hash.
    pub async fn get_identity(&self, dest_hash: &DestinationHash) -> Option<Identity> {
        self.node.lock().await.get_identity(dest_hash)
    }

    /// Remember an identity for a destination hash (out-of-band registration).
    pub async fn remember_identity(&self, dest_hash: DestinationHash, identity: Identity) {
        self.node
            .lock()
            .await
            .remember_identity(dest_hash, identity);
    }

    /// Get this node's identity hash (16 bytes).
    pub async fn identity_hash(&self) -> [u8; 16] {
        self.node.lock().await.identity_hash()
    }

    // ── Link operations ──────────────────────────────────────────────

    /// Connect to a remote destination (establish a Link).
    pub async fn connect(
        &self,
        dest_hash: &DestinationHash,
        dest_signing_key: &[u8; 32],
    ) -> Result<LinkHandle, RnsError> {
        self.node
            .lock()
            .await
            .connect(dest_hash, dest_signing_key)
            .await
            .map_err(|e| RnsError::Transport(format!("connect failed: {}", e)))
    }

    /// Accept an incoming link request.
    pub async fn accept_link(&self, link_id: &LinkId) -> Result<LinkHandle, RnsError> {
        self.node
            .lock()
            .await
            .accept_link(link_id)
            .await
            .map_err(|e| RnsError::Transport(format!("accept_link failed: {}", e)))
    }

    // ── Resource transfer ────────────────────────────────────────────

    /// Send a resource over an established link.
    pub async fn send_resource(
        &self,
        link_id: &LinkId,
        data: &[u8],
        metadata: Option<&[u8]>,
        auto_compress: bool,
    ) -> Result<[u8; 32], RnsError> {
        self.node
            .lock()
            .await
            .send_resource(link_id, data, metadata, auto_compress)
            .await
            .map_err(|e| RnsError::Transport(format!("send_resource failed: {}", e)))
    }

    /// Accept a pending resource advertisement.
    pub async fn accept_resource(&self, link_id: &LinkId) -> Result<(), RnsError> {
        self.node
            .lock()
            .await
            .accept_resource(link_id)
            .await
            .map_err(|e| RnsError::Transport(format!("accept_resource failed: {}", e)))
    }

    /// Set the resource acceptance strategy for a link.
    pub async fn set_resource_strategy(
        &self,
        link_id: &LinkId,
        strategy: ResourceStrategy,
    ) -> Result<(), RnsError> {
        self.node
            .lock()
            .await
            .set_resource_strategy(link_id, strategy)
            .map_err(|e| RnsError::Transport(format!("set_resource_strategy failed: {}", e)))
    }

    // ── Single-packet delivery ───────────────────────────────────────

    /// Send a single (fire-and-forget) packet to a destination.
    pub async fn send_single_packet(
        &self,
        dest_hash: &DestinationHash,
        data: &[u8],
    ) -> Result<[u8; 16], RnsError> {
        self.node
            .lock()
            .await
            .send_single_packet(dest_hash, data)
            .await
            .map_err(|e| RnsError::Transport(format!("send_single_packet failed: {}", e)))
    }
}
