use LXMF_rs::{LXMessage, LxmRouter, RouterConfig, ValidMethod};
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
    if let Err(err) = router.register_delivery_identity(None, display_name, None) {
        log::error!("Could not register delivery identity: {}", err);
        return;
    }

    let transport = Arc::new(tokio::sync::Mutex::new(Transport::new(
        TransportConfig::default(),
    )));

    // attach_transport() automatically registers LXMF announce handlers that
    // cache stamp costs from incoming announces. The router's prepare_outbound_message()
    // will automatically apply these cached stamp costs to outbound messages.
    if let Err(err) = router.attach_transport(transport.clone()).await {
        log::error!("Failed to attach transport to router: {}", err);
        return;
    }

    // Spawn the network interface
    let client_addr = transport.lock().await.iface_manager().lock().await.spawn(
        TcpClient::new("amsterdam.connect.reticulum.network:4965"),
        TcpClient::spawn,
    );

    log::info!("Waiting for path to destination {}...", destination_hash);

    // Wait for path to destination (announce will be received and stamp cost cached automatically)
    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        if transport.lock().await.has_path(&destination_hash).await {
            log::info!("Path found to {}", destination_hash);

            // Small delay to ensure announce handler has processed the stamp cost
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

            let destination_identity = match transport
                .lock()
                .await
                .recall_identity(&destination_hash, false)
                .await
            {
                Some(identity) => identity,
                None => {
                    log::error!(
                        "Transport does not know the destination identity for {}",
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

            // Announce ourselves
            transport
                .lock()
                .await
                .send_direct(
                    client_addr,
                    source_destination.announce(OsRng, None).unwrap(),
                )
                .await;

            // Create the LXMF message
            let message = LXMessage::new(
                destination,
                source_destination,
                "Hello, this is the content of the message.".to_string(),
                "Greetings".to_string(),
                None,
                desired_method,
                true,
            );

            // The router's prepare_outbound_message() will auto-apply stamp cost from its cache
            // and generate the stamp work as needed.

            // Queue and send the message
            // The router's prepare_outbound_message() will:
            // 1. Auto-apply stamp cost from its cache (if not already set)
            // 2. Generate the stamp work
            // 3. Pack and send the message
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
            transport
                .lock()
                .await
                .request_path(&destination_hash, None)
                .await;
            log::info!(
                "Requested path for {}. Waiting for announce...",
                destination_hash
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }
    }
}
