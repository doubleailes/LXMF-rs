mod error;
mod peer;

pub use error::PeerError;
pub use peer::{LxmPeer, PeerMetadata, PeerState, SyncStrategy};
