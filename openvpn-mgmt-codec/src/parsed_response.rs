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
//! assert_eq!(parse_pid("pid=12345"), Some(12345));
//!
//! let stats = parse_load_stats("nclients=3,bytesin=100000,bytesout=50000").unwrap();
//! assert_eq!(stats.nclients, 3);
//! ```

use crate::version_info::VersionInfo;

/// Aggregated server statistics from `load-stats`.
///
/// Wire format: `SUCCESS: nclients=N,bytesin=N,bytesout=N`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadStats {
    /// Number of currently connected clients.
    pub nclients: u64,
    /// Total bytes received by the server.
    pub bytesin: u64,
    /// Total bytes sent by the server.
    pub bytesout: u64,
}

/// Parse the `SUCCESS:` payload from a `pid` command.
///
/// Expects the format `pid=N` and returns the PID as `u32`.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_pid;
/// assert_eq!(parse_pid("pid=12345"), Some(12345));
/// assert_eq!(parse_pid("garbage"), None);
/// ```
pub fn parse_pid(payload: &str) -> Option<u32> {
    payload.strip_prefix("pid=")?.parse().ok()
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
pub fn parse_load_stats(payload: &str) -> Option<LoadStats> {
    let mut nclients = None;
    let mut bytesin = None;
    let mut bytesout = None;

    for part in payload.split(',') {
        if let Some((key, val)) = part.split_once('=') {
            match key {
                "nclients" => nclients = val.parse().ok(),
                "bytesin" => bytesin = val.parse().ok(),
                "bytesout" => bytesout = val.parse().ok(),
                _ => {}
            }
        }
    }

    Some(LoadStats {
        nclients: nclients?,
        bytesin: bytesin?,
        bytesout: bytesout?,
    })
}

/// Parse the `SUCCESS:` payload from a `hold` query.
///
/// Expects the format `hold=0` or `hold=1`. Returns `true` when hold is
/// active.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_hold;
/// assert_eq!(parse_hold("hold=1"), Some(true));
/// assert_eq!(parse_hold("hold=0"), Some(false));
/// ```
pub fn parse_hold(payload: &str) -> Option<bool> {
    match payload.strip_prefix("hold=")? {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
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
/// let info = parse_version(&lines);
/// assert_eq!(info.management_version(), Some(5));
/// ```
pub fn parse_version(lines: &[String]) -> VersionInfo {
    VersionInfo::parse(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_normal() {
        assert_eq!(parse_pid("pid=42"), Some(42));
    }

    #[test]
    fn pid_zero() {
        assert_eq!(parse_pid("pid=0"), Some(0));
    }

    #[test]
    fn pid_missing_prefix() {
        assert_eq!(parse_pid("42"), None);
    }

    #[test]
    fn pid_not_a_number() {
        assert_eq!(parse_pid("pid=abc"), None);
    }

    #[test]
    fn load_stats_normal() {
        let s = parse_load_stats("nclients=10,bytesin=123456,bytesout=789012").unwrap();
        assert_eq!(s.nclients, 10);
        assert_eq!(s.bytesin, 123456);
        assert_eq!(s.bytesout, 789012);
    }

    #[test]
    fn load_stats_reordered() {
        let s = parse_load_stats("bytesout=1,nclients=2,bytesin=3").unwrap();
        assert_eq!(s.nclients, 2);
        assert_eq!(s.bytesin, 3);
        assert_eq!(s.bytesout, 1);
    }

    #[test]
    fn load_stats_missing_field() {
        assert!(parse_load_stats("nclients=1,bytesin=2").is_none());
    }

    #[test]
    fn hold_active() {
        assert_eq!(parse_hold("hold=1"), Some(true));
    }

    #[test]
    fn hold_inactive() {
        assert_eq!(parse_hold("hold=0"), Some(false));
    }

    #[test]
    fn hold_garbage() {
        assert_eq!(parse_hold("hold=maybe"), None);
    }

    #[test]
    fn version_roundtrip() {
        let lines = vec![
            "OpenVPN Version: OpenVPN 2.5.0".to_string(),
            "Management Interface Version: 4".to_string(),
        ];
        let info = parse_version(&lines);
        assert_eq!(info.management_version(), Some(4));
    }
}
