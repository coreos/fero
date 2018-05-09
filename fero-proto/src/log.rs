#[derive(Clone, Copy, Debug, DbEnum)]
#[repr(u8)]
pub enum OperationType {
    Sign,
    Threshold,
    Weight,
    AddSecret,
    AddUser,
}

#[derive(Clone, Copy, Debug, DbEnum)]
#[repr(u8)]
pub enum OperationResult {
    Success,
    Failure,
}
