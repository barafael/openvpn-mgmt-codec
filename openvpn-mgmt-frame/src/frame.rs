use std::collections::BTreeMap;

/// A classified line (or accumulated block) from the OpenVPN management
/// interface.
///
/// The frame decoder emits one `Frame` per logical unit. Most variants
/// map 1:1 to a wire line; [`ClientEnv`](Frame::ClientEnv) is the
/// exception — it accumulates the full `>CLIENT:` header + ENV block
/// before being emitted.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// `SUCCESS: [text]` — a command completed successfully.
    Success(String),

    /// `ERROR: [text]` — a command failed.
    Error(String),

    /// A `>` notification line (single-line).
    ///
    /// `kind` is the tag before the first `:` (e.g. `"STATE"`, `"LOG"`).
    /// `payload` is everything after the `:`.
    ///
    /// `>CLIENT:` lines with ENV blocks are **not** emitted as
    /// `Notification` — they become [`ClientEnv`](Frame::ClientEnv)
    /// instead.
    Notification {
        /// Notification type tag (e.g. `"STATE"`, `"LOG"`, `"BYTECOUNT"`).
        kind: String,
        /// Everything after `>KIND:`.
        payload: String,
    },

    /// A fully accumulated `>CLIENT:` notification with its ENV block.
    ///
    /// All `>CLIENT:ENV,key=value` lines have been collected; the
    /// terminating `>CLIENT:ENV,END` has been consumed.
    ClientEnv {
        /// Raw event string (e.g. `"CONNECT"`, `"REAUTH"`, `"ADDRESS"`).
        event: String,
        /// Everything after the event on the header line (CID, KID, etc.),
        /// as a raw comma-separated string.
        args: String,
        /// Accumulated ENV key-value pairs.
        env: BTreeMap<String, String>,
    },

    /// `ENTER PASSWORD:` prompt.
    PasswordPrompt,

    /// A bare `END` line — terminates a multi-line response block.
    End,

    /// The first `>INFO:` line (the connection banner).
    ///
    /// Subsequent `>INFO:` lines are emitted as
    /// [`Notification`](Frame::Notification) with `kind = "INFO"`.
    Info(String),

    /// Any line that is not self-describing (no `SUCCESS:`/`ERROR:`/`>`
    /// prefix, not `END`, not `ENTER PASSWORD:`).
    ///
    /// Higher layers use command-tracking state to decide whether this
    /// belongs to a multi-line response or is an unrecognized line.
    Line(String),
}
