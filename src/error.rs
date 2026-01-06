use crate::router::RouterError;
use crate::message::MessageError;
pub enum LXMError{
    RouterError,
    MessageError,
}