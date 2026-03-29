//! Typed parsers for `SUCCESS:` payloads and multi-line responses.
//!
//! The management protocol's `SUCCESS:` line carries structured data as a
//! plain string (e.g. `SUCCESS: pid=12345`). These utilities parse common
//! payloads into typed values, saving every consumer from re-implementing
//! the same string splitting.
//!
//! # Examples
//!
//! ```
//! use openvpn_mgmt_codec::parsed_response::{parse_pid, parse_load_stats, LoadStats};
//!
//! assert_eq!(parse_pid("pid=12345"), Ok(12345));
//!
//! let stats = parse_load_stats("nclients=3,bytesin=100000,bytesout=50000").unwrap();
//! assert_eq!(stats.nclients, 3);
//! ```

use crate::{openvpn_state::OpenVpnState, timestamp::UtcTimestamp, version_info::VersionInfo};

/// Aggregated server statistics from `load-stats`.
///
/// Wire format: `SUCCESS: nclients=N,bytesin=N,bytesout=N`
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadStats {
    /// Number of currently connected clients.
    pub nclients: u64,

    /// Total bytes received by the server.
    pub bytesin: u64,

    /// Total bytes sent by the server.
    pub bytesout: u64,
}

/// Error returned when a `SUCCESS:` payload cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseResponseError {
    /// Expected `pid=N` but the prefix was missing.
    #[error("missing 'pid=' prefix in: {0:?}")]
    MissingPidPrefix(String),

    /// Expected `hold=0` or `hold=1` but the prefix was missing.
    #[error("missing 'hold=' prefix in: {0:?}")]
    MissingHoldPrefix(String),

    /// `hold=` value was not `0` or `1`.
    #[error("invalid hold value: {0:?}")]
    InvalidHoldValue(String),

    /// A numeric field could not be parsed.
    #[error("invalid integer for field {field:?}: {value:?}")]
    InvalidInteger {
        /// The field name that failed to parse.
        field: &'static str,
        /// The raw value that could not be parsed.
        value: String,
    },

    /// A required field was missing from the `load-stats` payload.
    #[error("missing field {0:?} in load-stats payload")]
    MissingField(&'static str),

    /// A state history line had too few fields.
    #[error("state entry has too few fields (need >= 2, got {0})")]
    StateTooFewFields(usize),

    /// The timestamp in a state entry was not a valid integer.
    #[error("invalid timestamp in state entry: {0:?}")]
    InvalidTimestamp(String),

    /// The state name could not be parsed.
    #[error("invalid state name: {0}")]
    InvalidStateName(#[from] crate::openvpn_state::ParseOpenVpnStateError),

    /// The state history was empty when a current state was requested.
    #[error("state history is empty")]
    EmptyStateHistory,

    /// The management version line contained a non-numeric value.
    #[error("non-numeric management version: {0:?}")]
    InvalidManagementVersion(String),
}

/// Parse the `SUCCESS:` payload from a `pid` command.
///
/// Expects the format `pid=N` and returns the PID as `u32`.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_pid;
/// assert_eq!(parse_pid("pid=12345"), Ok(12345));
/// assert!(parse_pid("garbage").is_err());
/// ```
pub fn parse_pid(payload: &str) -> Result<u32, ParseResponseError> {
    let val = payload
        .strip_prefix("pid=")
        .ok_or_else(|| ParseResponseError::MissingPidPrefix(payload.to_string()))?;
    val.parse().map_err(|_| ParseResponseError::InvalidInteger {
        field: "pid",
        value: val.to_string(),
    })
}

/// Parse the `SUCCESS:` payload from a `load-stats` command.
///
/// Expects the format `nclients=N,bytesin=N,bytesout=N`.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_load_stats;
/// let stats = parse_load_stats("nclients=5,bytesin=1000,bytesout=2000").unwrap();
/// assert_eq!(stats.nclients, 5);
/// assert_eq!(stats.bytesin, 1000);
/// assert_eq!(stats.bytesout, 2000);
/// ```
pub fn parse_load_stats(payload: &str) -> Result<LoadStats, ParseResponseError> {
    let mut nclients = None;
    let mut bytesin = None;
    let mut bytesout = None;

    for part in payload.split(',') {
        if let Some((key, val)) = part.split_once('=') {
            let parsed = |field| {
                val.parse().map_err(|_| ParseResponseError::InvalidInteger {
                    field,
                    value: val.to_string(),
                })
            };
            match key {
                "nclients" => nclients = Some(parsed("nclients")?),
                "bytesin" => bytesin = Some(parsed("bytesin")?),
                "bytesout" => bytesout = Some(parsed("bytesout")?),
                other => {
                    tracing::debug!(field = other, "ignoring unknown load-stats field");
                }
            }
        }
    }

    Ok(LoadStats {
        nclients: nclients.ok_or(ParseResponseError::MissingField("nclients"))?,
        bytesin: bytesin.ok_or(ParseResponseError::MissingField("bytesin"))?,
        bytesout: bytesout.ok_or(ParseResponseError::MissingField("bytesout"))?,
    })
}

/// Parse the `SUCCESS:` payload from a `hold` query.
///
/// Expects the format `hold=0` or `hold=1`. Returns `true` when the hold
/// flag is enabled (`--management-hold`). Note: this reflects the
/// **configuration**, not whether the server is currently blocked — after
/// `hold release` the flag stays on but the server is no longer waiting.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_hold;
/// assert_eq!(parse_hold("hold=1"), Ok(true));
/// assert_eq!(parse_hold("hold=0"), Ok(false));
/// ```
pub fn parse_hold(payload: &str) -> Result<bool, ParseResponseError> {
    let val = payload
        .strip_prefix("hold=")
        .ok_or_else(|| ParseResponseError::MissingHoldPrefix(payload.to_string()))?;
    match val {
        "1" => Ok(true),
        "0" => Ok(false),
        _ => Err(ParseResponseError::InvalidHoldValue(val.to_string())),
    }
}

/// Parse the multi-line response from a `version` command into a
/// [`VersionInfo`].
///
/// This is a convenience wrapper around [`VersionInfo::parse`].
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_version;
///
/// let lines = vec![
///     "OpenVPN Version: OpenVPN 2.6.9 x86_64-pc-linux-gnu".to_string(),
///     "Management Interface Version: 5".to_string(),
/// ];
/// let info = parse_version(&lines).unwrap();
/// assert_eq!(info.management_version(), Some(5));
/// ```
pub fn parse_version(lines: &[String]) -> Result<VersionInfo, ParseResponseError> {
    VersionInfo::parse(lines)
}

/// A single state history entry from the `state` command's multi-line response.
///
/// Wire format: `timestamp,state_name,description,local_ip,remote_ip,remote_port,local_addr,local_port,local_ipv6`
///
/// Fields mirror [`Notification::State`](crate::Notification::State) exactly.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_state_entry;
/// use openvpn_mgmt_codec::UtcTimestamp;
///
/// let entry = parse_state_entry("1711234567,CONNECTED,SUCCESS,10.8.0.6,198.51.100.1,1194,,").unwrap();
/// assert_eq!(entry.timestamp, UtcTimestamp(1711234567));
/// assert_eq!(entry.name.to_string(), "CONNECTED");
/// assert_eq!(entry.remote_ip, "198.51.100.1");
/// assert_eq!(entry.remote_port, Some(1194));
/// ```
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateEntry {
    /// Timestamp of the state change.
    pub timestamp: UtcTimestamp,
    /// State name (e.g. `Connected`, `Reconnecting`).
    pub name: OpenVpnState,
    /// Verbose description (mostly for RECONNECTING/EXITING).
    pub description: String,
    /// TUN/TAP local IPv4 address (may be empty).
    pub local_ip: String,
    /// Remote server address (may be empty).
    pub remote_ip: String,
    /// Remote server port (empty in many states).
    pub remote_port: Option<u16>,
    /// Local address (may be empty).
    pub local_addr: String,
    /// Local port (empty in many states).
    pub local_port: Option<u16>,
    /// TUN/TAP local IPv6 address (may be empty).
    pub local_ipv6: String,
}

/// Parse a single state history line.
///
/// The wire format is a comma-separated list of 2–9 fields. Fields beyond
/// the state name are optional and default to empty / `None`.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_state_entry;
///
/// // Minimal (just timestamp + state):
/// let entry = parse_state_entry("1711234567,CONNECTED").unwrap();
/// assert_eq!(entry.name.to_string(), "CONNECTED");
/// assert!(entry.description.is_empty());
///
/// // Invalid state name:
/// assert!(parse_state_entry("1711234567,BOGUS").is_err());
/// ```
pub fn parse_state_entry(line: &str) -> Result<StateEntry, ParseResponseError> {
    let fields: Vec<&str> = line.splitn(9, ',').collect();
    if fields.len() < 2 {
        return Err(ParseResponseError::StateTooFewFields(fields.len()));
    }

    let timestamp = fields[0]
        .parse::<u64>()
        .map(UtcTimestamp)
        .map_err(|_| ParseResponseError::InvalidTimestamp(fields[0].to_string()))?;
    let name = fields[1].parse::<OpenVpnState>()?;

    let get = |idx: usize| fields.get(idx).copied().unwrap_or("").to_string();
    let get_port = |idx: usize| {
        fields.get(idx).and_then(|field| {
            if field.is_empty() {
                None
            } else {
                field
                    .parse::<u16>()
                    .inspect_err(
                        |error| tracing::warn!(%error, field, "non-numeric port in state entry"),
                    )
                    .ok()
            }
        })
    };

    Ok(StateEntry {
        timestamp,
        name,
        description: get(2),
        local_ip: get(3),
        remote_ip: get(4),
        remote_port: get_port(5),
        local_addr: get(6),
        local_port: get_port(7),
        local_ipv6: get(8),
    })
}

/// Parse the full multi-line response from a `state` command.
///
/// Each line is parsed as a [`StateEntry`]. Lines that fail to parse are
/// returned as errors immediately.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_state_history;
///
/// let lines = vec![
///     "1711234560,CONNECTING,,,,,,,".to_string(),
///     "1711234567,CONNECTED,SUCCESS,10.8.0.6,198.51.100.1,1194,,".to_string(),
/// ];
/// let entries = parse_state_history(&lines).unwrap();
/// assert_eq!(entries.len(), 2);
/// assert_eq!(entries[1].name.to_string(), "CONNECTED");
/// ```
pub fn parse_state_history(lines: &[String]) -> Result<Vec<StateEntry>, ParseResponseError> {
    lines.iter().map(|line| parse_state_entry(line)).collect()
}

/// Extract the current (most recent) state from a `state` or `state on all`
/// multi-line response.
///
/// This is a convenience wrapper that parses all entries and returns the
/// last one.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_current_state;
///
/// let lines = vec![
///     "1711234560,CONNECTING,,,,,,,".to_string(),
///     "1711234567,CONNECTED,SUCCESS,10.8.0.6,,,".to_string(),
/// ];
/// let current = parse_current_state(&lines).unwrap();
/// assert_eq!(current.name.to_string(), "CONNECTED");
/// ```
pub fn parse_current_state(lines: &[String]) -> Result<StateEntry, ParseResponseError> {
    parse_state_history(lines)?
        .into_iter()
        .last()
        .ok_or(ParseResponseError::EmptyStateHistory)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_pid ---

    #[test]
    fn pid_normal() {
        assert_eq!(parse_pid("pid=42"), Ok(42));
    }

    #[test]
    fn pid_zero() {
        assert_eq!(parse_pid("pid=0"), Ok(0));
    }

    #[test]
    fn pid_missing_prefix() {
        assert!(parse_pid("42").is_err());
    }

    #[test]
    fn pid_not_a_number() {
        assert!(parse_pid("pid=abc").is_err());
    }

    // --- parse_load_stats ---

    #[test]
    fn load_stats_normal() {
        let stats = parse_load_stats("nclients=10,bytesin=123456,bytesout=789012").unwrap();
        assert_eq!(stats.nclients, 10);
        assert_eq!(stats.bytesin, 123456);
        assert_eq!(stats.bytesout, 789012);
    }

    #[test]
    fn load_stats_reordered() {
        let stats = parse_load_stats("bytesout=1,nclients=2,bytesin=3").unwrap();
        assert_eq!(stats.nclients, 2);
        assert_eq!(stats.bytesin, 3);
        assert_eq!(stats.bytesout, 1);
    }

    #[test]
    fn load_stats_missing_field() {
        let err = parse_load_stats("nclients=1,bytesin=2").unwrap_err();
        assert!(matches!(err, ParseResponseError::MissingField("bytesout")));
    }

    #[test]
    fn load_stats_non_numeric_value() {
        let err = parse_load_stats("nclients=abc,bytesin=2,bytesout=3").unwrap_err();
        assert!(matches!(
            err,
            ParseResponseError::InvalidInteger {
                field: "nclients",
                ..
            }
        ));
    }

    #[test]
    fn load_stats_unknown_field_tolerated() {
        let stats = parse_load_stats("nclients=1,bytesin=2,bytesout=3,extra=99").unwrap();
        assert_eq!(stats.nclients, 1);
        assert_eq!(stats.bytesin, 2);
        assert_eq!(stats.bytesout, 3);
    }

    // --- parse_hold ---

    #[test]
    fn hold_active() {
        assert_eq!(parse_hold("hold=1"), Ok(true));
    }

    #[test]
    fn hold_inactive() {
        assert_eq!(parse_hold("hold=0"), Ok(false));
    }

    #[test]
    fn hold_missing_prefix() {
        assert!(parse_hold("garbage").is_err());
    }

    #[test]
    fn hold_invalid_value() {
        assert!(parse_hold("hold=maybe").is_err());
    }

    // --- parse_state_entry ---

    #[test]
    fn state_entry_full() {
        let entry =
            parse_state_entry("1711234567,CONNECTED,SUCCESS,10.8.0.6,198.51.100.1,1194,0.0.0.0,0")
                .unwrap();
        assert_eq!(entry.timestamp, UtcTimestamp(1711234567));
        assert_eq!(entry.name.to_string(), "CONNECTED");
        assert_eq!(entry.description, "SUCCESS");
        assert_eq!(entry.local_ip, "10.8.0.6");
        assert_eq!(entry.remote_ip, "198.51.100.1");
        assert_eq!(entry.remote_port, Some(1194));
        assert_eq!(entry.local_addr, "0.0.0.0");
        assert_eq!(entry.local_port, Some(0));
    }

    #[test]
    fn state_entry_minimal() {
        let entry = parse_state_entry("0,CONNECTING").unwrap();
        assert_eq!(entry.timestamp, UtcTimestamp(0));
        assert!(entry.description.is_empty());
        assert!(entry.remote_port.is_none());
    }

    #[test]
    fn state_entry_optional_ports_empty() {
        let entry = parse_state_entry("100,WAIT,desc,10.0.0.1,1.2.3.4,,eth0,").unwrap();
        assert_eq!(entry.remote_ip, "1.2.3.4");
        assert_eq!(entry.remote_port, None);
        assert_eq!(entry.local_addr, "eth0");
        assert_eq!(entry.local_port, None);
    }

    #[test]
    fn state_entry_too_few_fields() {
        assert!(matches!(
            parse_state_entry("just_one"),
            Err(ParseResponseError::StateTooFewFields(1))
        ));
    }

    #[test]
    fn state_entry_bad_timestamp() {
        assert!(matches!(
            parse_state_entry("notanumber,CONNECTED"),
            Err(ParseResponseError::InvalidTimestamp(_))
        ));
    }

    #[test]
    fn state_entry_bad_state_name() {
        assert!(parse_state_entry("0,BOGUS_STATE").is_err());
    }

    // --- parse_state_history / parse_current_state ---

    #[test]
    fn state_history_roundtrip() {
        let lines = vec![
            "100,CONNECTING,,,,,,,".to_string(),
            "200,CONNECTED,SUCCESS,10.8.0.6,,,".to_string(),
        ];
        let entries = parse_state_history(&lines).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name.to_string(), "CONNECTING");
        assert_eq!(entries[1].name.to_string(), "CONNECTED");
    }

    #[test]
    fn current_state_returns_last() {
        let lines = vec![
            "100,CONNECTING,,,,,,,".to_string(),
            "200,CONNECTED,SUCCESS,,,,,".to_string(),
        ];
        let current = parse_current_state(&lines).unwrap();
        assert_eq!(current.timestamp, UtcTimestamp(200));
    }

    #[test]
    fn current_state_empty_history() {
        let empty: Vec<String> = vec![];
        assert!(matches!(
            parse_current_state(&empty),
            Err(ParseResponseError::EmptyStateHistory)
        ));
    }

    #[test]
    fn state_entry_non_numeric_port_degrades_to_none() {
        // A non-numeric port field should be silently ignored (returns None),
        // not cause a parse error.
        let entry =
            parse_state_entry("1700000000,CONNECTED,SUCCESS,10.0.0.1,1.2.3.4,abc,,,").unwrap();
        assert_eq!(entry.remote_port, None);
    }

    // --- parse_version ---

    #[test]
    fn version_roundtrip() {
        let lines = vec![
            "OpenVPN Version: OpenVPN 2.5.0".to_string(),
            "Management Interface Version: 4".to_string(),
        ];
        let info = parse_version(&lines).unwrap();
        assert_eq!(info.management_version(), Some(4));
    }
}
