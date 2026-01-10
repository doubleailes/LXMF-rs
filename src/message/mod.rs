mod error;
pub mod message;
pub use error::MessageError;
pub use message::{LXMessage, UnverifiedReason, ValidMethod};
// Re-export LXMF field constants
pub use message::{
    FIELD_AUDIO, FIELD_COMMANDS, FIELD_CUSTOM_DATA, FIELD_CUSTOM_META, FIELD_CUSTOM_TYPE,
    FIELD_DEBUG, FIELD_EMBEDDED_LXMS, FIELD_EVENT, FIELD_FILE_ATTACHMENTS, FIELD_GROUP,
    FIELD_ICON_APPEARANCE, FIELD_IMAGE, FIELD_NON_SPECIFIC, FIELD_RENDERER, FIELD_RESULTS,
    FIELD_RNR_REFS, FIELD_TELEMETRY, FIELD_TELEMETRY_STREAM, FIELD_THREAD, FIELD_TICKET,
};
mod payload;
pub use payload::LxPayload;
pub mod stamp;
