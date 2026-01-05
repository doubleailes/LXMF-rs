/// LXMF application name
pub const APP_NAME: &str = "lxmf";

// Core field identifiers for LXMF messages
// These facilitate interoperability in data exchange between various LXMF clients

/// Embedded LXMF messages
pub const FIELD_EMBEDDED_LXMS: u8 = 0x01;
/// Telemetry data
pub const FIELD_TELEMETRY: u8 = 0x02;
/// Telemetry stream
pub const FIELD_TELEMETRY_STREAM: u8 = 0x03;
/// Icon appearance
pub const FIELD_ICON_APPEARANCE: u8 = 0x04;
/// File attachments
pub const FIELD_FILE_ATTACHMENTS: u8 = 0x05;
/// Image data
pub const FIELD_IMAGE: u8 = 0x06;
/// Audio data
pub const FIELD_AUDIO: u8 = 0x07;
/// Thread identifier
pub const FIELD_THREAD: u8 = 0x08;
/// Commands
pub const FIELD_COMMANDS: u8 = 0x09;
/// Results
pub const FIELD_RESULTS: u8 = 0x0A;
/// Group identifier
pub const FIELD_GROUP: u8 = 0x0B;
/// Ticket
pub const FIELD_TICKET: u8 = 0x0C;
/// Event data
pub const FIELD_EVENT: u8 = 0x0D;
/// RNR references
pub const FIELD_RNR_REFS: u8 = 0x0E;
/// Message renderer
pub const FIELD_RENDERER: u8 = 0x0F;

// Custom fields for embedding external protocols/data
/// Custom type identifier
pub const FIELD_CUSTOM_TYPE: u8 = 0xFB;
/// Custom data payload
pub const FIELD_CUSTOM_DATA: u8 = 0xFC;
/// Custom metadata
pub const FIELD_CUSTOM_META: u8 = 0xFD;

// Development and debugging fields
/// Non-specific field
pub const FIELD_NON_SPECIFIC: u8 = 0xFE;
/// Debug field
pub const FIELD_DEBUG: u8 = 0xFF;

// Audio mode constants
/// Codec2 450PWB mode
pub const AM_CODEC2_450PWB: u8 = 0x01;
/// Codec2 450 mode
pub const AM_CODEC2_450: u8 = 0x02;
/// Codec2 700C mode
pub const AM_CODEC2_700C: u8 = 0x03;
/// Codec2 1200 mode
pub const AM_CODEC2_1200: u8 = 0x04;
/// Codec2 1300 mode
pub const AM_CODEC2_1300: u8 = 0x05;
/// Codec2 1400 mode
pub const AM_CODEC2_1400: u8 = 0x06;
/// Codec2 1600 mode
pub const AM_CODEC2_1600: u8 = 0x07;
/// Codec2 2400 mode
pub const AM_CODEC2_2400: u8 = 0x08;
/// Codec2 3200 mode
pub const AM_CODEC2_3200: u8 = 0x09;

/// Opus OGG mode
pub const AM_OPUS_OGG: u8 = 0x10;
/// Opus low bandwidth mode
pub const AM_OPUS_LBW: u8 = 0x11;
/// Opus medium bandwidth mode
pub const AM_OPUS_MBW: u8 = 0x12;
/// Opus push-to-talk mode
pub const AM_OPUS_PTT: u8 = 0x13;
/// Opus real-time half-duplex mode
pub const AM_OPUS_RT_HDX: u8 = 0x14;
/// Opus real-time full-duplex mode
pub const AM_OPUS_RT_FDX: u8 = 0x15;
/// Opus standard mode
pub const AM_OPUS_STANDARD: u8 = 0x16;
/// Opus high quality mode
pub const AM_OPUS_HQ: u8 = 0x17;
/// Opus broadcast mode
pub const AM_OPUS_BROADCAST: u8 = 0x18;
/// Opus lossless mode
pub const AM_OPUS_LOSSLESS: u8 = 0x19;

/// Custom audio mode
pub const AM_CUSTOM: u8 = 0xFF;

// Message renderer specifications
/// Plain text renderer
pub const RENDERER_PLAIN: u8 = 0x00;
/// Micron markup renderer
pub const RENDERER_MICRON: u8 = 0x01;
/// Markdown renderer
pub const RENDERER_MARKDOWN: u8 = 0x02;
/// BBCode renderer
pub const RENDERER_BBCODE: u8 = 0x03;

// Propagation node metadata fields
/// Propagation node version
pub const PN_META_VERSION: u8 = 0x00;
/// Propagation node name
pub const PN_META_NAME: u8 = 0x01;
/// Sync stratum level
pub const PN_META_SYNC_STRATUM: u8 = 0x02;
/// Sync throttle setting
pub const PN_META_SYNC_THROTTLE: u8 = 0x03;
/// Authentication band
pub const PN_META_AUTH_BAND: u8 = 0x04;
/// Utilization pressure
pub const PN_META_UTIL_PRESSURE: u8 = 0x05;
/// Custom metadata
pub const PN_META_CUSTOM: u8 = 0xFF;
