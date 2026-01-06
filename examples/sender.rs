use LXMF_rs::{LXMessage, ValidMethod};
use reticulum::destination::{self, SingleOutputDestination, DestinationName};
use reticulum::identity::PrivateIdentity;
use rand::rngs::OsRng;

const APP_NAME: &str = "lxmf";

#[tokio::main]
async fn main(){
    println!("Creating and sending LXMessage...");
    let identity = PrivateIdentity::new_from_rand(OsRng);
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
}