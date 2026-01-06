use LXMF_rs::{LXMessage, LxmRouter, RouterConfig, ValidMethod};
use rand::rngs::OsRng;
use reticulum::destination::{self, DestinationName, SingleOutputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;

const APP_NAME: &str = "lxmf";

#[tokio::main]
async fn main() {
    println!("Creating and sending LXMessage...");
    let router_config = RouterConfig::default();
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let mut router: LxmRouter = LxmRouter::new(Some(identity.clone()), router_config)
        .await
        .unwrap();
    let _ = router.start().await;
    let source: AddressHash = router
        .register_delivery_identity(Some("Anonymous".to_string()), None)
        .await
        .unwrap()?;
    router.announce(&source);
    if transport.has_path(&destination_hash).await {
        let destination_name = DestinationName::new(APP_NAME, "delivery");
        let destination = SingleOutputDestination::new(identity, destination_name);
        let lxm = LXMessage::new(
            destination,
            identity,
            "Hello, this is the content of the message.".to_string(),
            "Greetings".to_string(),
            ValidMethod::Direct,
            true,
        );
    } else {
        transport.request_path(&destination_hash, None).await;
        log::info!("Added destination with hash: {}", destination_hash);
    }
}
