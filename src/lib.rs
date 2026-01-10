mod message;
pub use message::{LXMessage, UnverifiedReason, ValidMethod};
// Re-export LXMF field constants for convenience
pub use message::{
    FIELD_AUDIO, FIELD_COMMANDS, FIELD_CUSTOM_DATA, FIELD_CUSTOM_META, FIELD_CUSTOM_TYPE,
    FIELD_DEBUG, FIELD_EMBEDDED_LXMS, FIELD_EVENT, FIELD_FILE_ATTACHMENTS, FIELD_GROUP,
    FIELD_ICON_APPEARANCE, FIELD_IMAGE, FIELD_NON_SPECIFIC, FIELD_RENDERER, FIELD_RESULTS,
    FIELD_RNR_REFS, FIELD_TELEMETRY, FIELD_TELEMETRY_STREAM, FIELD_THREAD, FIELD_TICKET,
};
mod peer;
pub use peer::{LxmPeer, PeerError, PeerMetadata, PeerState, SyncStrategy};
pub mod router;
pub use router::{
    APP_NAME, LXMFDeliveryAnnounceHandler, LXMFPropagationAnnounceHandler, LxmRouter,
    PropagationNodeAnnounceData, RouterConfig, RouterError, STAMP_COST_EXPIRY_S,
    SharedDeliveryAnnounceHandler, display_name_from_app_data, pn_announce_data_is_valid,
    pn_name_from_app_data, stamp_cost_from_app_data,
};
mod error;
pub use error::LXMError;
