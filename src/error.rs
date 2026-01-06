use crate::message::MessageError;
use crate::router::RouterError;
pub enum LXMError {
    RouterError,
    MessageError,
}
