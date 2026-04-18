//! Integration test: Rust LXMF sender → Python LXMF receiver
//!
//! This example connects to a local Python LXMF receiver via TCP,
//! discovers its destination via announce, and sends an LXMF message.
//!
//! Usage:
//!     cargo run --example integration_test -- <dest_hash> [--port PORT]
//!
//! The Python receiver must be started first:
//!     python3 tests/integration/python_receiver.py --port 14965

use std::{env, net::SocketAddr, time::Duration};

use LXMF_rs::compat::{
    AddressHash, DestinationName, PrivateIdentity, SingleInputDestination,
    SingleOutputDestination,
};
use LXMF_rs::{LXMessage, ValidMethod};
use rand_core::OsRng;

use reticulum_core::node::NodeEvent;
use reticulum_core::{Destination, DestinationType, Direction, Identity};
use reticulum_std::driver::ReticulumNodeBuilder;

const APP_NAME: &str = "lxmf";
const DELIVERY_ASPECT: &str = "delivery";

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <dest_hash_hex> [--port PORT]", args[0]);
        eprintln!("  dest_hash_hex: 32-char hex from Python receiver's 'ready' output");
        eprintln!("  --port PORT: TCP port of Python receiver (default 14965)");
        return;
    }

    let dest_hex = &args[1];
    let port: u16 = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse().ok())
        .unwrap_or(14965);

    let target_hash = match AddressHash::new_from_hex_string(dest_hex) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Invalid destination hash: {}", e);
            return;
        }
    };

    // Generate our identity
    let our_identity = Identity::generate(&mut OsRng);
    let our_private = PrivateIdentity::from_leviculum(our_identity.clone());

    // Build node with TCP client pointing at the local Python receiver
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

    // Register our delivery destination
    let our_dest = Destination::new(
        Some(our_identity.clone()),
        Direction::In,
        DestinationType::Single,
        APP_NAME,
        &[DELIVERY_ASPECT],
    )
    .expect("failed to create destination");
    let our_dest_hash = *our_dest.hash();
    node.register_destination(our_dest);

    // Announce ourselves
    node.announce_destination(&our_dest_hash, Some(b"LXMF-rs Integration Test"))
        .await
        .expect("announce failed");
    log::info!("Announced ourselves");

    // Request path to target
    let target_dh = target_hash.to_destination_hash();
    node.request_path(&target_dh).await.expect("path request failed");
    log::info!("Requested path to {}", dest_hex);

    // Wait for path
    let path_found = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if node.has_path(&target_dh) {
                return true;
            }
            match event_rx.recv().await {
                Some(NodeEvent::AnnounceReceived { announce, .. }) => {
                    let ann_dest = announce.destination_hash();
                    log::info!("Announce received from {:?}", ann_dest);
                    if *ann_dest == target_dh {
                        // Small delay to let path table update
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        if node.has_path(&target_dh) {
                            return true;
                        }
                    }
                }
                Some(NodeEvent::PathFound { destination_hash, hops, .. }) => {
                    log::info!("Path found: {:?} ({} hops)", destination_hash, hops);
                    if destination_hash == target_dh {
                        return true;
                    }
                }
                Some(other) => {
                    log::debug!("Event: {:?}", other);
                }
                None => return false,
            }
        }
    })
    .await;

    if !matches!(path_found, Ok(true)) {
        log::error!("Could not find path to target within 15s");
        node.stop().await.ok();
        return;
    }
    log::info!("Path to target confirmed!");

    // Get the target's identity (should be known from announce)
    let target_identity = node.get_identity(&target_dh);
    let target_identity = match target_identity {
        Some(id) => id,
        None => {
            log::error!("Target identity not known after path found");
            node.stop().await.ok();
            return;
        }
    };

    // Build LXMF message
    let target_pub_identity =
        LXMF_rs::compat::Identity::from_leviculum(target_identity.clone());
    let dest_out = SingleOutputDestination::new(
        target_pub_identity,
        DestinationName::new(APP_NAME, DELIVERY_ASPECT),
    );
    let src_in = SingleInputDestination::new(
        our_private.clone(),
        DestinationName::new(APP_NAME, DELIVERY_ASPECT),
    );

    let message = LXMessage::new(
        dest_out,
        src_in,
        "Hello from Rust! This LXMF message was built with LXMF-rs and transported via leviculum."
            .to_string(),
        "Integration Test".to_string(),
        None,
        Some(ValidMethod::Direct),
        true,
    );

    // Pack the message to get the transport payload
    let mut msg = message;
    if let Err(e) = msg.pack() {
        log::error!("Failed to pack message: {:?}", e);
        node.stop().await.ok();
        return;
    }

    let payload = match msg.transport_payload() {
        Ok(p) => p,
        Err(e) => {
            log::error!("Failed to get transport payload: {:?}", e);
            node.stop().await.ok();
            return;
        }
    };

    log::info!("Message packed: {} bytes payload", payload.len());

    // Send via single packet (small message, fits in one packet)
    match node.send_single_packet(&target_dh, &payload).await {
        Ok(packet_hash) => {
            log::info!(
                "Message sent! Packet hash: {}",
                hex::encode(&packet_hash)
            );
        }
        Err(e) => {
            log::error!("Failed to send packet: {}", e);
        }
    }

    // Wait a moment for delivery
    tokio::time::sleep(Duration::from_secs(3)).await;

    log::info!("Done. Shutting down...");
    node.stop().await.ok();
}
