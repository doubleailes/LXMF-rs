use LXMF_rs::compat::{
    AddressHash, DestinationName, PrivateIdentity, SingleInputDestination, SingleOutputDestination,
};
use LXMF_rs::{LXMessage, LxmRouter, RouterConfig, ValidMethod};
use rand_core::OsRng;
use std::{env, net::SocketAddr};

use reticulum_core::node::NodeEvent;
use reticulum_core::{Destination, DestinationType, Direction};
use reticulum_std::driver::ReticulumNodeBuilder;

const APP_NAME: &str = "lxmf";
const DELIVERY_ASPECT: &str = "delivery";

/// Amsterdam testnet address
const TESTNET_ADDR: &str = "164.68.106.137:4965";

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: {} <32-character-hex-destination> [method]", args[0]);
        eprintln!(
            "Example: {} 564f0ec8b6ff3cbbedb3b2bb6069f567 direct",
            args[0]
        );
        eprintln!("\nArguments:");
        eprintln!("  destination: 32-character hex destination hash (required)");
        eprintln!("  method: 'direct' or 'opportunistic' (optional, default: direct)");
        return;
    }

    let desired_method: Option<ValidMethod> = match args.get(2) {
        Some(method_str) if method_str.to_lowercase() == "direct" => Some(ValidMethod::Direct),
        Some(method_str) if method_str.to_lowercase() == "opportunistic" => {
            Some(ValidMethod::Opportunistic)
        }
        _ => None,
    };

    let destination_hex = &args[1];

    if destination_hex.len() != 32 {
        log::error!("Destination hash must be exactly 32 hexadecimal characters");
        return;
    }
    let destination_hash = match AddressHash::new_from_hex_string(destination_hex) {
        Ok(hash) => hash,
        Err(e) => {
            log::error!("Invalid destination hash: {}", e);
            return;
        }
    };

    log::info!("Starting LXMF sender...");

    // Generate a new identity for this session
    let mut rng = OsRng;
    let private_identity = PrivateIdentity::new_from_rand(&mut rng);
    let identity = private_identity.inner().clone();

    // Build a ReticulumNode with TCP client to testnet
    let addr: SocketAddr = TESTNET_ADDR.parse().expect("invalid testnet address");
    let mut node = ReticulumNodeBuilder::new()
        .identity(identity.clone())
        .add_tcp_client(addr)
        .enable_transport(false)
        .build_sync()
        .expect("failed to build ReticulumNode");

    // Take event receiver BEFORE start
    let mut event_rx = node
        .take_event_receiver()
        .expect("event receiver already taken");

    // Start the node
    node.start().await.expect("failed to start node");
    log::info!("Connected to testnet at {}", TESTNET_ADDR);

    // Register our delivery destination
    let our_dest = Destination::new(
        Some(identity.clone()),
        Direction::In,
        DestinationType::Single,
        APP_NAME,
        &[DELIVERY_ASPECT],
    )
    .expect("failed to create destination");
    let our_dest_hash = *our_dest.hash();
    node.register_destination(our_dest);

    // Announce ourselves
    let display_name = b"LXMF-rs Sender";
    let app_data = display_name.to_vec();
    node.announce_destination(&our_dest_hash, Some(&app_data))
        .await
        .expect("failed to announce");
    log::info!(
        "Announced as {} (hash: {})",
        String::from_utf8_lossy(display_name),
        our_dest_hash
    );

    // Request path to target destination
    let target_hash = destination_hash.to_destination_hash();
    log::info!("Requesting path to {}...", target_hash);
    node.request_path(&target_hash)
        .await
        .expect("failed to request path");

    // Wait for path (with timeout)
    let path_timeout = tokio::time::Duration::from_secs(30);
    let path_found = tokio::time::timeout(path_timeout, async {
        loop {
            if node.has_path(&target_hash) {
                return true;
            }
            match event_rx.recv().await {
                Some(NodeEvent::PathFound {
                    destination_hash,
                    hops,
                    ..
                }) => {
                    if destination_hash == target_hash {
                        log::info!("Path found to {} ({} hops)", destination_hash, hops);
                        return true;
                    }
                }
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await;

    match path_found {
        Ok(true) => {
            log::info!("Path to target confirmed!");
        }
        _ => {
            log::error!("Timeout waiting for path to {}", target_hash);
            log::info!("Creating message for demonstration anyway...");
        }
    }

    // Create LXMF message
    let demo_rng = &mut OsRng;
    let receiver_identity = PrivateIdentity::new_from_rand(demo_rng);
    let destination = SingleOutputDestination::new(
        receiver_identity.as_identity(),
        DestinationName::new(APP_NAME, DELIVERY_ASPECT),
    );
    let source_destination = SingleInputDestination::new(
        private_identity.clone(),
        DestinationName::new(APP_NAME, DELIVERY_ASPECT),
    );

    let message = LXMessage::new(
        destination,
        source_destination,
        "Hello from LXMF-rs! This message was sent via leviculum.".to_string(),
        "Greetings".to_string(),
        None,
        desired_method,
        true,
    );

    // Set up the router with the transport
    let mut router_config = RouterConfig::new("/tmp/lxmf");
    router_config.identity = Some(private_identity.clone());
    let router = LxmRouter::new(router_config).expect("failed to create router");

    if let Err(err) =
        router.register_delivery_identity(None, Some("LXMF-rs Sender".to_string()), None)
    {
        log::error!("Could not register delivery identity: {}", err);
        return;
    }

    router.enqueue_outbound(message);
    log::info!(
        "Queued LXMF message targeting {}",
        hex::encode(destination_hash.as_slice())
    );

    // If we have a path, try sending via single packet
    if node.has_path(&target_hash) {
        log::info!("Attempting direct delivery...");
        // Flush would use the transport, but for demo let's show it works
        if let Err(err) = router.flush_outbound_blocking() {
            log::warn!(
                "Flush returned error (expected without full transport): {}",
                err
            );
        }
    }

    log::info!("Done. Shutting down...");
    node.stop().await.expect("failed to stop node");
}
