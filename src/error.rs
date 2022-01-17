
#[derive(Debug)]
pub enum ErrorKind {
    NotImplemented,
    NoEntry,
    InsufficientSpace,
    InconsistentState,
    OutOfSpace,
    NotFormatted,
    OutOfBounds,
}
