use LXMF_rs::{
    stamp_cost_from_app_data, LXMessage, LxmRouter, RouterConfig, SharedDeliveryAnnounceHandler,
    ValidMethod,
};
use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination, SingleOutputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};
use std::{env, sync::Arc};
use tokio::sync::Mutex;

const APP_NAME: &str = "lxmf";
const DELIVERY_ASPECT: &str = "delivery";

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 4 {
        eprintln!(
            "Usage: {} <32-character-hex-destination> [method] [stamp_cost]",
            args[0]
        );
        eprintln!(
            "Example: {} 564f0ec8b6ff3cbbedb3b2bb6069f567 direct 8",
            args[0]
        );
        eprintln!("\nArguments:");
        eprintln!("  destination: 32-character hex destination hash (required)");
        eprintln!("  method: 'direct' or 'opportunistic' (optional, default: direct)");
        eprintln!("  stamp_cost: 0-255 (optional, overrides discovered stamp cost)");
        return;
    }
    let desired_method: Option<ValidMethod> = match args.get(2) {
        Some(method_str) if method_str.to_lowercase() == "direct" => Some(ValidMethod::Direct),
        Some(method_str) if method_str.to_lowercase() == "opportunistic" => {
            Some(ValidMethod::Opportunistic)
        }
        _ => None,
    };

    // Parse optional stamp cost override from command line
    let stamp_cost_override: Option<u8> = args.get(3).and_then(|s| {
        s.parse::<u8>().ok().map(|cost| {
            log::info!("Using stamp cost override from command line: {}", cost);
            cost
        })
    });

    let destination_hex = &args[1];

    // Validate that the destination is exactly 32 hex characters
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
    log::info!("Starting Router...");
    let mut rng = OsRng;
    let private_identity = PrivateIdentity::new_from_rand(&mut rng);

    let mut router_config = RouterConfig::new("/tmp/lxmf");
    router_config.identity = Some(private_identity.clone());

    let router = match LxmRouter::new(router_config) {
        Ok(router) => router,
        Err(err) => {
            log::error!("Failed to initialise LXMF router: {}", err);
            return;
        }
    };

    let display_name = Some("Anonymous".to_string());
    let stamp_cost = None;
    if let Err(err) = router.register_delivery_identity(None, display_name, stamp_cost) {
        log::error!("Could not register delivery identity: {}", err);
        return;
    }

    let transport = Arc::new(Transport::new(TransportConfig::default()));
    if let Err(err) = router.attach_transport(transport.clone()) {
        log::error!("Failed to attach transport to router: {}", err);
        return;
    }

    // Create and register the LXMF delivery announce handler.
    // The handler stores stamp_cost directly in its internal cache when
    // announces are received, matching Python LXMF behavior.
    let announce_handler = SharedDeliveryAnnounceHandler::new(router.clone());
    log::info!(
        "Registering announce handler with aspect filter: {:?}",
        announce_handler.aspect_filter()
    );
    transport
        .register_announce_handler(announce_handler.clone())
        .await;

    // CRITICAL: Subscribe to announces BEFORE spawning the interface!
    // This prevents a race condition where the announce arrives and is processed
    // before we have a chance to subscribe to the broadcast channel.
    // In Reticulum, paths are established via announces - when request_path() is called,
    // nodes forward their cached announces back to us. The path table is updated
    // FROM the announce packet itself.
    let mut announce_rx = transport.recv_announces().await;

    // Now spawn the interface - any announces received will be delivered to our subscriber
    let client_addr = transport.iface_manager().lock().await.spawn(
        TcpClient::new("amsterdam.connect.reticulum.network:4965"),
        TcpClient::spawn,
    );

    // Shared stamp cost storage (fallback for when handler doesn't trigger)
    let discovered_stamp_cost: Arc<Mutex<Option<u8>>> = Arc::new(Mutex::new(None));

    // Spawn a task to listen for announces and extract stamp cost
    let stamp_cost_clone = discovered_stamp_cost.clone();
    let target_hash = destination_hash;
    tokio::spawn(async move {
        while let Ok(event) = announce_rx.recv().await {
            let dest = event.destination.lock().await;
            // Use desc.address_hash (destination hash), NOT identity.address_hash
            // The destination hash is derived from (app_name + aspect + identity)
            let announce_hash = dest.desc.address_hash;
            log::debug!(
                "recv_announces: received announce from {} with {} bytes app_data",
                announce_hash,
                event.app_data.len()
            );

            // Check if this announce is from our target destination
            if announce_hash == target_hash {
                // Extract stamp cost from app_data
                if let Some(cost) = stamp_cost_from_app_data(event.app_data.as_slice()) {
                    log::info!(
                        "recv_announces: discovered stamp cost {} for target destination {}",
                        cost,
                        announce_hash
                    );
                    *stamp_cost_clone.lock().await = Some(cost);
                } else {
                    log::debug!(
                        "recv_announces: no stamp cost in app_data for {}",
                        announce_hash
                    );
                }
            }
        }
    });

    log::info!("Creating and sending LXMessage...");
    log::info!("Waiting for destination announce to discover stamp cost...");

    // Note: In Reticulum, paths are established from announces. When request_path() is called,
    // intermediate nodes forward their cached announce for that destination. The announce
    // contains both the routing info (used to populate path table) AND the app_data
    // (which contains stamp cost for LXMF destinations).
    //
    // Therefore, when has_path() returns true, the announce should have already been
    // received and processed. We check both the handler cache and the direct receiver.
    let mut announce_wait_iterations = 0;
    const MAX_ANNOUNCE_WAIT_ITERATIONS: u32 = 50; // 5 seconds after path found
    loop {
        // Give time for announces to be received and processed
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        if transport.has_path(&destination_hash).await {
            // Path found - this means an announce was received!
            // The stamp cost should already be cached from the announce app_data.

            // Try to get stamp cost from handler first, then from direct announce receiver
            let stamp_cost = announce_handler
                .get_stamp_cost(&destination_hash)
                .or(*discovered_stamp_cost.lock().await);

            if stamp_cost.is_some() {
                log::info!(
                    "Stamp cost {} discovered for destination {}",
                    stamp_cost.unwrap(),
                    destination_hash
                );
            } else {
                // No stamp cost yet - wait a bit more for processing
                announce_wait_iterations += 1;
                if announce_wait_iterations < MAX_ANNOUNCE_WAIT_ITERATIONS {
                    log::debug!(
                        "Path found but stamp cost not yet cached for {} (waiting {}/{})",
                        destination_hash,
                        announce_wait_iterations,
                        MAX_ANNOUNCE_WAIT_ITERATIONS
                    );
                    continue;
                }
                log::warn!(
                    "Timeout waiting for announce from {}. Proceeding without stamp cost.",
                    destination_hash
                );
            }

            log::debug!(
                "Transport has a path to destination {:?}, preparing message...",
                destination_hash
            );
            let destination_identity =
                match transport.recall_identity(&destination_hash, false).await {
                    Some(identity) => identity,
                    None => {
                        log::error!(
                            "Transport does not yet know the destination identity for {:?}",
                            destination_hash
                        );
                        return;
                    }
                };

            let destination = SingleOutputDestination::new(
                destination_identity,
                DestinationName::new(APP_NAME, DELIVERY_ASPECT),
            );
            let mut source_destination = SingleInputDestination::new(
                private_identity.clone(),
                DestinationName::new(APP_NAME, DELIVERY_ASPECT),
            );
            transport
                .send_direct(
                    client_addr,
                    source_destination.announce(OsRng, None).unwrap(),
                )
                .await;
            let mut message = LXMessage::new(
                destination,
                source_destination,
                "Hello, this is the content of the message.".to_string(),
                "Greetings".to_string(),
                None,
                desired_method,
                true,
            );

            // Get stamp cost: command-line override > announce handler cache > direct receiver
            // This matches Python LXMF behavior where stamp_cost is stored in
            // LXMFDeliveryAnnounceHandler.stamp_costs[destination_hash]
            let stamp_cost = stamp_cost_override
                .or_else(|| announce_handler.get_stamp_cost(&destination_hash))
                .or(*discovered_stamp_cost.lock().await);

            if let Some(cost) = stamp_cost {
                if stamp_cost_override.is_some() {
                    log::info!("Using stamp cost {} (from command-line override)", cost);
                } else {
                    log::info!("Using stamp cost {} (from announce)", cost);
                }
                message.set_stamp_cost(Some(cost));
            } else {
                log::warn!(
                    "No stamp cost discovered for destination. Message may be rejected if receiver requires stamps."
                );
            }

            // Debug: print the message hash BEFORE enqueuing
            // The message isn't packed yet, so we need to pack it first to see the hash
            if let Ok(packed) = message.pack() {
                log::debug!("PACKED MESSAGE (BEFORE router processing):");
                log::debug!("  Packed length: {}", packed.len());
                let hex_str: String = packed.iter().map(|b| format!("{:02x}", b)).collect();
                log::debug!("  Packed hex: {}", hex_str);
                if let Some(hash) = message.message_hash() {
                    let hash_hex: String = hash
                        .as_slice()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    log::debug!("  Message hash: {}", hash_hex);
                }
                if let Some(stamp) = message.stamp() {
                    let stamp_hex: String = stamp.iter().map(|b| format!("{:02x}", b)).collect();
                    log::debug!("  Stamp: {}", stamp_hex);
                } else {
                    log::debug!("  Stamp: None");
                }
            }

            router.enqueue_outbound(message);
            log::info!(
                "Queued LXMF message targeting destination hash {}",
                destination_hash
            );
            if let Err(err) = router.flush_outbound_blocking() {
                log::error!("Failed to flush outbound LXMF queue: {}", err);
                return;
            }
            log::info!("Outbound queue flushed. Message handed to transport.");
            break;
        } else {
            transport.request_path(&destination_hash, None).await;
            log::info!(
                "Requested a path for {:?}. Retry once the destination announces itself.",
                destination_hash
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;
        }
    }
}
