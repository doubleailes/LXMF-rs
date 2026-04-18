//! Integration test: LXMF Router delivery via Link + Resource
//!
//! Tests the router's automatic delivery path selection:
//! - Small messages → single-packet delivery
//! - Large messages → Link + Resource delivery
//!
//! Usage:
//!     1. Start Python receiver:
//!        python3 tests/integration/python_receiver.py --port 14967 --timeout 60
//!     2. Run this test:
//!        cargo run --example router_delivery_test -- <dest_hash> --port 14967 [--size BYTES]

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use LXMF_rs::compat::{
    AddressHash, DestinationName, Identity as CompatIdentity, PrivateIdentity,
    SingleInputDestination, SingleOutputDestination,
};
use LXMF_rs::transport::LxmfTransport;
use LXMF_rs::{LXMessage, LxmRouter, RouterConfig, ValidMethod};
use rand_core::OsRng;

use reticulum_core::{Destination, DestinationType, Direction, Identity};
use reticulum_std::driver::ReticulumNodeBuilder;

const APP_NAME: &str = "lxmf";
const DELIVERY_ASPECT: &str = "delivery";

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <dest_hash_hex> [--port PORT] [--size BYTES]",
            args[0]
        );
        return;
    }

    let dest_hex = &args[1];
    let port: u16 = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse().ok())
        .unwrap_or(14967);
    let content_size: usize = args
        .iter()
        .position(|a| a == "--size")
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
    let our_private =
        PrivateIdentity::from_leviculum(our_identity.clone()).expect("identity has private keys");

    // Build node
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let node = ReticulumNodeBuilder::new()
        .identity(our_identity.clone())
        .add_tcp_client(addr)
        .enable_transport(false)
        .build_sync()
        .expect("failed to build node");

    // Create transport and router
    let transport = Arc::new(LxmfTransport::from_node(node));
    transport.start().await.expect("failed to start transport");
    log::info!("Connected to Python receiver at 127.0.0.1:{}", port);

    // Register our destination with leviculum
    let our_dest = Destination::new(
        Some(our_identity.clone()),
        Direction::In,
        DestinationType::Single,
        APP_NAME,
        &[DELIVERY_ASPECT],
    )
    .expect("failed to create destination");
    let our_dest_hash = *our_dest.hash();
    transport.register_destination(our_dest).await;

    // Create router
    let tmp_dir = std::env::temp_dir().join(format!("lxmf_router_test_{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).expect("failed to create temp dir");
    let mut config = RouterConfig::new(&tmp_dir);
    config.identity = Some(our_private.clone());
    let router = LxmRouter::new(config).expect("failed to create router");

    // Register delivery identity
    let _local_dest = router
        .register_delivery_identity(
            Some(our_private.clone()),
            Some("LXMF-rs Router Test".to_string()),
            None,
        )
        .expect("failed to register delivery identity");

    // Attach transport to router
    router
        .attach_transport(transport.clone())
        .await
        .expect("failed to attach transport");

    // Announce ourselves
    transport
        .announce_destination(&our_dest_hash, Some(b"LXMF-rs Router Delivery Test"))
        .await
        .expect("announce failed");

    // Request path and wait
    let target_dh = target_hash.to_destination_hash();
    transport
        .request_path(&target_dh)
        .await
        .expect("path request failed");
    log::info!("Requested path to {}", dest_hex);

    // Wait for path
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !transport.has_path(&target_dh).await {
        if tokio::time::Instant::now() > deadline {
            log::error!("Path not found within 15s");
            transport.stop().await.ok();
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    log::info!("Path confirmed!");

    // Wait for identity to be known
    tokio::time::sleep(Duration::from_millis(500)).await;
    let target_identity = match transport.get_identity(&target_dh).await {
        Some(id) => id,
        None => {
            log::error!("Target identity not known");
            transport.stop().await.ok();
            return;
        }
    };

    // Build LXMF message
    let large_content = format!(
        "=== LXMF-rs Router Delivery Test ===\n\
         Content size: {} bytes\n\
         Transport: leviculum (Router auto-selects single-packet or Link+Resource)\n\
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

    let message = LXMessage::new(
        dest_out,
        src_in,
        large_content.to_string(),
        "Router Delivery Test".to_string(),
        None,
        Some(ValidMethod::Direct),
        true,
    );

    log::info!("Enqueueing {} byte message via router", content_size);

    // Enqueue message — the router will auto-select delivery path
    router.enqueue_outbound(message);

    // Wait for delivery (the job loop processes outbound every 4s)
    // Give it enough time for link establishment + resource transfer
    tokio::time::sleep(Duration::from_secs(20)).await;

    log::info!("══════════════════════════════════════════════════════");
    log::info!(
        "  Router delivery test complete for {} byte message",
        content_size
    );
    log::info!("══════════════════════════════════════════════════════");

    // Graceful shutdown
    router.shutdown().ok();
    transport.stop().await.ok();
    log::info!("Done.");
}
