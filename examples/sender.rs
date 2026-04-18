use LXMF_rs::compat::{
    AddressHash, DestinationName, PrivateIdentity, SingleInputDestination,
    SingleOutputDestination, Transport, TransportConfig,
};
use LXMF_rs::{LXMessage, LxmRouter, RouterConfig, ValidMethod};
use rand_core::OsRng;
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

    let transport = Arc::new(Transport::new(TransportConfig::default()));

    // TODO: attach_transport() needs to be updated for leviculum transport
    // For now, transport integration is stubbed
    if let Err(err) = router.attach_transport(transport.clone()).await {
        log::error!("Failed to attach transport to router: {}", err);
        return;
    }

    // TODO: Spawn network interface via leviculum
    // let client_addr = transport.iface_manager().lock().await.spawn(
    //     TcpClient::new("amsterdam.connect.reticulum.network:4965"),
    //     TcpClient::spawn,
    // );

    log::info!("Waiting for path to destination {}...", destination_hash);

    // TODO: Transport integration — this loop needs leviculum's path discovery
    // For now, demonstrate message creation without sending
    log::warn!("Transport integration not yet complete — creating message for demonstration");

    // Create a dummy destination identity for demonstration
    let mut demo_rng = OsRng;
    let receiver_identity = PrivateIdentity::new_from_rand(&mut demo_rng);

    let destination = SingleOutputDestination::new(
        receiver_identity.as_identity(),
        DestinationName::new(APP_NAME, DELIVERY_ASPECT),
    );
    let source_destination = SingleInputDestination::new(
        private_identity.clone(),
        DestinationName::new(APP_NAME, DELIVERY_ASPECT),
    );

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

    router.enqueue_outbound(message);
    log::info!(
        "Queued LXMF message targeting destination hash {}",
        hex::encode(destination_hash.as_slice())
    );

    if let Err(err) = router.flush_outbound_blocking() {
        log::error!("Failed to flush outbound LXMF queue: {}", err);
        return;
    }
    log::info!("Outbound queue flushed.");
}
