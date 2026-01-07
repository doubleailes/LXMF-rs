use LXMF_rs::{stamp_cost_from_app_data, LXMessage, LxmRouter, RouterConfig, ValidMethod};
use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination, SingleOutputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};
use std::{env, sync::Arc};

const APP_NAME: &str = "lxmf";
const DELIVERY_ASPECT: &str = "delivery";

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <32-character-hex-destination>", args[0]);
        eprintln!("Example: {} 564f0ec8b6ff3cbbedb3b2bb6069f567", args[0]);
        return;
    }

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
    let client_addr = transport
        .iface_manager()
        .lock()
        .await
        .spawn(
            TcpClient::new("amsterdam.connect.reticulum.network:4965"),
            TcpClient::spawn,
        );

    // Subscribe to announces to receive stamp_cost discovery
    let mut announce_rx = transport.recv_announces().await;

    log::info!("Creating and sending LXMessage...");
    log::info!("Waiting for destination announce to discover stamp cost...");

    // Track discovered stamp cost from announces
    let mut discovered_stamp_cost: Option<u8> = None;

    loop {
        // Check for incoming announces to discover stamp_cost
        // This implements Python LXMF's LXMFDeliveryAnnounceHandler behavior
        while let Ok(announce_event) = announce_rx.try_recv() {
            let dest = announce_event.destination.lock().await;
            let announce_dest_hash = dest.desc.address_hash;

            if announce_dest_hash == destination_hash {
                // Extract stamp_cost from the announce app_data
                let app_data = announce_event.app_data.as_slice();
                if let Some(cost) = stamp_cost_from_app_data(app_data) {
                    log::info!(
                        "Discovered stamp cost {} from announce for {}",
                        cost,
                        destination_hash
                    );
                    discovered_stamp_cost = Some(cost);

                    // Update the router's cached stamp cost for this destination
                    if let Err(err) = router.update_outbound_stamp_cost(destination_hash, cost) {
                        log::warn!("Failed to update cached stamp cost: {}", err);
                    }
                } else {
                    log::debug!(
                        "Announce from {} has no stamp cost requirement",
                        destination_hash
                    );
                }
            }
        }

        if transport.has_path(&destination_hash).await {
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
                Some(ValidMethod::Opportunistic),
                true,
            );

            // Use discovered stamp cost from announce, or check router's cache
            let stamp_cost = discovered_stamp_cost
                .or_else(|| router.get_outbound_stamp_cost(destination_hash));

            if let Some(cost) = stamp_cost {
                log::info!("Using stamp cost {} (from announce discovery)", cost);
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
                    let hash_hex: String =
                        hash.as_slice().iter().map(|b| format!("{:02x}", b)).collect();
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
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }
    }
}
