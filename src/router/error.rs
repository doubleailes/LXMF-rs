/// Router-level errors.
#[derive(Debug)]
pub enum RouterError {
    MissingStoragePath,

    InvalidDestinationHashLen { expected: usize, got: usize },

    Io(std::io::Error),
}

impl From<std::io::Error> for RouterError {
    fn from(err: std::io::Error) -> Self {
        RouterError::Io(err)
    }
}