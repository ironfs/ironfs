
#[derive(Debug)]
pub enum ErrorKind {
    NotImplemented,
    NoEntry,
    InconsistentState,
    OutOfSpace,
    NotFormatted,
    OutOfBounds,
}
