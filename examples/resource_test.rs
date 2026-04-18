//! Integration test: Large LXMF message via Link + Resource transfer
//!
//! Rust sender → Link establishment → Resource transfer → Python receiver
//!
//! This tests the critical path that was impossible with beetchat:
//! messages too large for a single packet get sent via Link + Resource.
//!
//! Usage:
//!     1. Start Python receiver:
//!        python3 tests/integration/python_receiver.py --port 14966 --timeout 60
//!     2. Run this test:
//!        cargo run --example resource_test -- <dest_hash> --port 14966

use std::{env, net::SocketAddr, time::Duration};

use LXMF_rs::compat::{
    AddressHash, DestinationName, PrivateIdentity, SingleInputDestination,
    SingleOutputDestination, Identity as CompatIdentity,
};
use LXMF_rs::{LXMessage, ValidMethod};
use rand_core::OsRng;

use reticulum_core::node::NodeEvent;
use reticulum_core::resource::ResourceStrategy;
use reticulum_core::{Destination, DestinationType, Direction, Identity};
use reticulum_std::driver::ReticulumNodeBuilder;

const APP_NAME: &str = "lxmf";
const DELIVERY_ASPECT: &str = "delivery";

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <dest_hash_hex> [--port PORT] [--size BYTES]", args[0]);
        return;
    }

    let dest_hex = &args[1];
    let port: u16 = args.iter().position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse().ok())
        .unwrap_or(14966);
    let content_size: usize = args.iter().position(|a| a == "--size")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse().ok())
        .unwrap_or(10_000);

    let target_hash = match AddressHash::new_from_hex_string(dest_hex) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Invalid destination hash: {}", e);
            return;
        }
    };

    // Generate identity
    let our_identity = Identity::generate(&mut OsRng);
    let our_private = PrivateIdentity::from_leviculum(our_identity.clone());

    // Build node
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let mut node = ReticulumNodeBuilder::new()
        .identity(our_identity.clone())
        .add_tcp_client(addr)
        .enable_transport(false)
        .build_sync()
        .expect("failed to build node");

    let mut event_rx = node.take_event_receiver().expect("no event receiver");
    node.start().await.expect("failed to start node");
    log::info!("Connected to Python receiver at 127.0.0.1:{}", port);

    // Register our destination
    let our_dest = Destination::new(
        Some(our_identity.clone()),
        Direction::In,
        DestinationType::Single,
        APP_NAME,
        &[DELIVERY_ASPECT],
    ).expect("failed to create destination");
    let our_dest_hash = *our_dest.hash();
    node.register_destination(our_dest);

    // Announce
    node.announce_destination(&our_dest_hash, Some(b"LXMF-rs Resource Test"))
        .await.expect("announce failed");

    // Request path
    let target_dh = target_hash.to_destination_hash();
    node.request_path(&target_dh).await.expect("path request failed");
    log::info!("Requested path to {}", dest_hex);

    // Wait for path + identity
    let path_found = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if node.has_path(&target_dh) {
                return true;
            }
            match event_rx.recv().await {
                Some(NodeEvent::PathFound { destination_hash, hops, .. }) => {
                    log::info!("Path found: {:?} ({} hops)", destination_hash, hops);
                    if destination_hash == target_dh { return true; }
                }
                Some(NodeEvent::AnnounceReceived { announce, .. }) => {
                    log::info!("Announce from {:?}", announce.destination_hash());
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    if node.has_path(&target_dh) { return true; }
                }
                Some(_) => continue,
                None => return false,
            }
        }
    }).await;

    if !matches!(path_found, Ok(true)) {
        log::error!("Path not found within 15s");
        node.stop().await.ok();
        return;
    }
    log::info!("Path confirmed!");

    // Get target's identity and signing key
    let target_identity = match node.get_identity(&target_dh) {
        Some(id) => id,
        None => {
            log::error!("Target identity not known");
            node.stop().await.ok();
            return;
        }
    };

    // Ed25519 verifying key = last 32 bytes of the 64-byte public key
    let pub_bytes = target_identity.public_key_bytes();
    let mut signing_key = [0u8; 32];
    signing_key.copy_from_slice(&pub_bytes[32..64]);

    // Build large LXMF message
    let large_content = format!(
        "=== LXMF-rs Resource Transfer Test ===\n\
         Content size: {} bytes\n\
         Transport: leviculum (Link + Resource)\n\
         \n\
         {}",
        content_size,
        "The quick brown fox jumps over the lazy dog. ".repeat(content_size / 46 + 1)
    );
    let large_content = &large_content[..content_size.min(large_content.len())];

    let target_compat = CompatIdentity::from_leviculum(target_identity.clone());
    let dest_out = SingleOutputDestination::new(
        target_compat,
        DestinationName::new(APP_NAME, DELIVERY_ASPECT),
    );
    let src_in = SingleInputDestination::new(
        our_private.clone(),
        DestinationName::new(APP_NAME, DELIVERY_ASPECT),
    );

    let mut message = LXMessage::new(
        dest_out, src_in,
        large_content.to_string(),
        "Resource Transfer Test".to_string(),
        None,
        Some(ValidMethod::Direct),
        true,
    );

    let packed = match message.pack() {
        Ok(p) => p.to_vec(),
        Err(e) => {
            log::error!("Failed to pack message: {:?}", e);
            node.stop().await.ok();
            return;
        }
    };

    // For Link+Resource delivery, send the FULL packed bytes (including dest_hash).
    // Python's LXMRouter.delivery_resource_concluded() passes the raw resource data
    // to LXMessage.unpack_from_bytes() which expects: dest_hash + src_hash + sig + payload
    let payload = packed.clone();

    log::info!("Message packed: {} bytes (content: {} bytes)", payload.len(), content_size);
    log::info!("MDU is 464 bytes — this message REQUIRES Link + Resource transfer");

    // ── Step 1: Establish Link ──────────────────────────────────────
    log::info!("Establishing link to {}...", dest_hex);

    let link_handle = match node.connect(&target_dh, &signing_key).await {
        Ok(lh) => lh,
        Err(e) => {
            log::error!("Link establishment failed: {}", e);
            node.stop().await.ok();
            return;
        }
    };

    let link_id = *link_handle.link_id();
    log::info!("Link request sent (link_id: {:?})", link_id);

    // Wait for link establishment
    let link_established = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match event_rx.recv().await {
                Some(NodeEvent::LinkEstablished { link_id: lid, is_initiator }) => {
                    log::info!("Link established! (initiator: {}, link_id: {:?})", is_initiator, lid);
                    if lid == link_id {
                        return true;
                    }
                }
                Some(NodeEvent::LinkClosed { link_id: lid, reason, .. }) => {
                    if lid == link_id {
                        log::error!("Link closed before establishment: {:?}", reason);
                        return false;
                    }
                }
                Some(other) => {
                    log::debug!("Event while waiting for link: {:?}", other);
                }
                None => return false,
            }
        }
    }).await;

    if !matches!(link_established, Ok(true)) {
        log::error!("Link establishment timed out or failed");
        node.stop().await.ok();
        return;
    }

    // ── Step 2: Send Resource ───────────────────────────────────────
    log::info!("Sending {} bytes via Resource transfer...", payload.len());

    let resource_hash = match node.send_resource(&link_id, &payload, None, true).await {
        Ok(hash) => {
            log::info!("Resource queued (hash: {})", hex::encode(&hash));
            hash
        }
        Err(e) => {
            log::error!("send_resource failed: {}", e);
            node.stop().await.ok();
            return;
        }
    };

    // Wait for resource completion
    let transfer_complete = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match event_rx.recv().await {
                Some(NodeEvent::ResourceProgress { resource_hash: rh, progress, transfer_size, is_sender, .. }) => {
                    if rh == resource_hash {
                        log::info!("Resource progress: {:.1}% ({} bytes, sender: {})",
                            progress * 100.0, transfer_size, is_sender);
                    }
                }
                Some(NodeEvent::ResourceCompleted { resource_hash: rh, is_sender, .. }) => {
                    if rh == resource_hash {
                        log::info!("Resource transfer COMPLETE! (sender: {})", is_sender);
                        return true;
                    }
                }
                Some(NodeEvent::ResourceFailed { resource_hash: rh, error, .. }) => {
                    if rh == resource_hash {
                        log::error!("Resource transfer FAILED: {:?}", error);
                        return false;
                    }
                }
                Some(NodeEvent::LinkClosed { link_id: lid, reason, .. }) => {
                    if lid == link_id {
                        log::warn!("Link closed during transfer: {:?}", reason);
                        return false;
                    }
                }
                Some(_) => continue,
                None => return false,
            }
        }
    }).await;

    match transfer_complete {
        Ok(true) => {
            log::info!("══════════════════════════════════════════════════════");
            log::info!("  SUCCESS: {} byte LXMF message delivered via", payload.len());
            log::info!("  Link + Resource transfer (Rust → Python)");
            log::info!("══════════════════════════════════════════════════════");
        }
        Ok(false) => log::error!("Resource transfer failed"),
        Err(_) => log::error!("Resource transfer timed out after 30s"),
    }

    // Graceful shutdown
    tokio::time::sleep(Duration::from_secs(2)).await;
    node.close_link(&link_id).await.ok();
    tokio::time::sleep(Duration::from_secs(1)).await;
    node.stop().await.ok();
    log::info!("Done.");
}
