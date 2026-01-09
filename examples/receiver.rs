use LXMF_rs::{LXMessage, LxmRouter, RouterConfig};
use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};

// Configuration - mirrors Python example settings
const REQUIRED_STAMP_COST: u8 = 8;
const ENFORCE_STAMPS: bool = false;

fn delivery_callback(message: &LXMessage) {
    // Format timestamp
    let timestamp = message.payload().timestamp;
    let time_string = format_timestamp(timestamp);

    // Signature validation status
    let signature_string = if message.signature_validated() {
        "Validated".to_string()
    } else {
        match message.unverified_reason() {
            Some(reason) => format!("Unverified: {:?}", reason),
            None => "Signature is invalid, reason undetermined".to_string(),
        }
    };

    // Stamp validation status
    let stamp_string = if message.stamp_valid() {
        "Validated".to_string()
    } else {
        "Invalid".to_string()
    };

    // Print delivery information (matching Python format)
    log::info!("\t+--- LXMF Delivery ---------------------------------------------");
    log::info!(
        "\t| Source hash            : {}",
        hex::encode(message.source_hash().as_slice())
    );
    log::info!(
        "\t| Destination hash       : {}",
        hex::encode(message.destination_hash().as_slice())
    );
    log::info!(
        "\t| Transport Encryption   : {}",
        message.transport_encryption().unwrap_or("None")
    );
    log::info!("\t| Timestamp              : {}", time_string);
    log::info!(
        "\t| Title                  : {}",
        message
            .payload()
            .title_as_string()
            .unwrap_or_else(|_| "<invalid UTF-8>".to_string())
    );
    log::info!(
        "\t| Content                : {}",
        message
            .payload()
            .content_as_string()
            .unwrap_or_else(|_| "<invalid UTF-8>".to_string())
    );
    log::info!(
        "\t| Fields                 : {:?}",
        message.payload().fields
    );
    log::info!("\t| Message signature      : {}", signature_string);
    log::info!("\t| Stamp                  : {}", stamp_string);
    log::info!("\t+---------------------------------------------------------------");
}

fn format_timestamp(timestamp: f64) -> String {
    // Simple formatting - in production you'd use chrono or time crate
    let secs_since_epoch = timestamp as u64;

    // Basic date formatting
    let days = secs_since_epoch / 86400;
    let hours = (secs_since_epoch % 86400) / 3600;
    let minutes = (secs_since_epoch % 3600) / 60;
    let seconds = secs_since_epoch % 60;

    format!("{} days {:02}:{:02}:{:02}", days, hours, minutes, seconds)
}

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("LXMF Receiver Example");
    log::info!("=====================");

    // Create router with storage path
    let mut router_config = RouterConfig::new("/tmp/lxmf_receiver");
    router_config.enforce_stamps = ENFORCE_STAMPS;

    // Create a new identity for this receiver
    let mut rng = OsRng;
    let identity = PrivateIdentity::new_from_rand(&mut rng);
    router_config.identity = Some(identity.clone());

    let router = match LxmRouter::new(router_config) {
        Ok(router) => router,
        Err(err) => {
            log::error!("Failed to initialize LXMF router: {}", err);
            return;
        }
    };

    // Register delivery identity with display name and stamp cost
    let display_name = Some("Anonymous Peer".to_string());
    let my_lxmf_destination =
        match router.register_delivery_identity(None, display_name, Some(REQUIRED_STAMP_COST)) {
            Ok(dest_hash) => dest_hash,
            Err(err) => {
                log::error!("Could not register delivery identity: {}", err);
                return;
            }
        };

    // Register delivery callback
    router.register_delivery_callback(delivery_callback);

    log::info!(
        "Ready to receive on: {}",
        hex::encode(my_lxmf_destination.as_slice())
    );

    // Create and attach transport
    let transport = Arc::new(Transport::new(TransportConfig::default()));

    if let Err(err) = router.attach_transport(transport.clone()).await {
        log::error!("Failed to attach transport to router: {}", err);
        return;
    }

    log::info!("Attached transport to router - incoming message handling is active");

    // Spawn the network interface
    let _client_addr = transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);

    log::info!("Connected to Reticulum network");

    // The router's attach_transport already set up incoming message handling
    // via the process_incoming_messages background task

    // Interactive loop - press Enter to announce
    log::info!("\nPress Enter to announce delivery destination...");
    log::info!("Press Ctrl+C to exit\n");

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF
                break;
            }
            Ok(_) => {
                log::info!("Announcing lxmf.delivery destination...");
                if let Err(e) = router.announce(my_lxmf_destination).await {
                    log::error!("Failed to announce: {}", e);
                } else {
                    log::info!("Announce sent successfully");
                }
            }
            Err(e) => {
                log::error!("Error reading input: {}", e);
                break;
            }
        }
    }

    // Save router state on exit
    if let Err(e) = router.shutdown() {
        log::error!("Error shutting down router: {}", e);
    }
}
