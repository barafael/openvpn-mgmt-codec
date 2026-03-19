use thiserror::Error;

/// Describes why a line could not be classified into a known message type.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UnrecognizedKind {
    /// A line starting with `>` (notification prefix) but missing the
    /// required `:` separator between the notification type and payload.
    #[error("malformed notification: missing ':' separator")]
    MalformedNotification,

    /// The codec expected a `SUCCESS:` or `ERROR:` response based on the
    /// last command sent, but received a line with no recognizable prefix.
    /// This can occur with the initial connection banner or when the
    /// OpenVPN build doesn't match the expected response mapping.
    #[error("expected SUCCESS/ERROR response, got unrecognized line")]
    UnexpectedLine,
}
