//! Typed parsers for `status` command responses.
//!
//! The `status` command returns a multi-line response whose format varies
//! by version (V1/V2/V3) and mode (server vs client). This module parses
//! the raw lines into typed structs.
//!
//! # Format overview
//!
//! | Version | Separator | Prefix lines | Notes |
//! |---------|-----------|-------------|-------|
//! | V1 | `,` | `OpenVPN CLIENT LIST` / `OpenVPN STATISTICS` | No `TITLE`/`TIME` prefix, no `time_t` fields in older versions |
//! | V2 | `,` | `TITLE,` / `TIME,` / `HEADER,` | Adds `time_t` columns |
//! | V3 | `\t` | `TITLE\t` / `TIME\t` / `HEADER\t` | Same as V2 but tab-delimited |
//!
//! # Client mode
//!
//! In client mode, `status` returns `OpenVPN STATISTICS` — a simple
//! key-value list of byte counters, not a client table. Use
//! [`parse_client_statistics`] for this case.
//!
//! # Examples
//!
//! ```
//! use openvpn_mgmt_codec::status::{parse_status, parse_client_statistics};
//!
//! // V3 server status (tab-separated)
//! let lines = vec![
//!     "TITLE\tOpenVPN 2.6.8".to_string(),
//!     "TIME\t2024-03-21 14:30:00\t1711031400".to_string(),
//!     "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher".to_string(),
//!     "CLIENT_LIST\tclient1\t203.0.113.10:52841\t10.8.0.6\t\t1548576\t984320\t2024-03-21 09:15:00\t1711012500\tUNDEF\t0\t0\tAES-256-GCM".to_string(),
//!     "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)".to_string(),
//!     "ROUTING_TABLE\t10.8.0.6\tclient1\t203.0.113.10:52841\t2024-03-21 14:29:50\t1711031390".to_string(),
//!     "GLOBAL_STATS\tMax bcast/mcast queue length\t3".to_string(),
//! ];
//! let status = parse_status(&lines).unwrap();
//! assert_eq!(status.clients.len(), 1);
//! assert_eq!(status.clients[0].common_name, "client1");
//! assert_eq!(status.routes.len(), 1);
//!
//! // Client statistics
//! let lines = vec![
//!     "OpenVPN STATISTICS".to_string(),
//!     "Updated,2024-03-21 14:30:00".to_string(),
//!     "TUN/TAP read bytes,1548576".to_string(),
//!     "TUN/TAP write bytes,984320".to_string(),
//!     "TCP/UDP read bytes,1600000".to_string(),
//!     "TCP/UDP write bytes,1020000".to_string(),
//!     "Auth read bytes,0".to_string(),
//! ];
//! let stats = parse_client_statistics(&lines).unwrap();
//! assert_eq!(stats.tun_tap_read_bytes, 1548576);
//! ```

/// Parsed server-mode status response.
///
/// Contains the connected client list, routing table, and global stats.
/// Works with V1 (comma-separated), V2 (comma with headers), and V3
/// (tab-delimited) formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusResponse {
    /// Title line (e.g. `"OpenVPN 2.6.8 x86_64-pc-linux-gnu"`).
    /// Present in V2/V3, absent in V1.
    pub title: Option<String>,

    /// Timestamp of the status snapshot.
    /// Present in V2/V3, absent in V1.
    pub timestamp: Option<crate::timestamp::UtcTimestamp>,

    /// Human-readable update time (e.g. `"2024-03-21 14:30:00"`).
    /// Present in V1 (`Updated,...`) and V2/V3 (`TIME,...,...`).
    pub updated: Option<String>,

    /// Connected clients.
    pub clients: Vec<ConnectedClient>,

    /// Routing table entries.
    pub routes: Vec<RoutingEntry>,

    /// Global stats as key-value pairs (e.g. `("Max bcast/mcast queue length", "3")`).
    pub global_stats: Vec<(String, String)>,
}

/// A connected client from the `CLIENT_LIST` section.
///
/// Field availability varies by OpenVPN version:
/// - OpenVPN 2.3 (V2): no `virtual_ipv6`, `peer_id`, or `cipher`
/// - OpenVPN 2.4+: all fields present
/// - V1: no `virtual_ipv6`, `connected_since_t`, `username`, `cid`, `peer_id`, `cipher`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedClient {
    /// Certificate common name.
    pub common_name: String,
    /// Real IP:port address.
    pub real_address: String,
    /// Virtual IPv4 address assigned by OpenVPN.
    pub virtual_address: String,
    /// Virtual IPv6 address (empty if not assigned). V2/V3 2.4+ only.
    pub virtual_ipv6: String,
    /// Bytes received from this client.
    pub bytes_in: u64,
    /// Bytes sent to this client.
    pub bytes_out: u64,
    /// Human-readable connection time.
    pub connected_since: String,
    /// Timestamp of connection. V2/V3 only.
    pub connected_since_t: Option<crate::timestamp::UtcTimestamp>,
    /// Username. `None` when not using `--auth-user-pass` (OpenVPN sends
    /// `"UNDEF"`, which the parser maps to `None`). V2/V3 only.
    pub username: Option<String>,
    /// Client ID. V2/V3 only.
    pub cid: Option<u64>,
    /// Peer ID. V2/V3 2.4+ only.
    pub peer_id: Option<u64>,
    /// Data channel cipher (e.g. `AES-256-GCM`). V2/V3 2.4+ only.
    pub cipher: Option<String>,
}

/// A routing table entry from the `ROUTING_TABLE` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingEntry {
    /// Virtual address (IPv4 or IPv6).
    pub virtual_address: String,
    /// Certificate common name.
    pub common_name: String,
    /// Real IP:port address.
    pub real_address: String,
    /// Human-readable last reference time.
    pub last_ref: String,
    /// Timestamp of last reference. V2/V3 only.
    pub last_ref_t: Option<crate::timestamp::UtcTimestamp>,
}

/// Client-mode statistics from `OpenVPN STATISTICS`.
///
/// Returned by `status` in client mode. The fields are byte counters.
/// Optional fields are absent in older OpenVPN versions or when
/// compression is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientStatistics {
    /// Bytes read from TUN/TAP device.
    pub tun_tap_read_bytes: u64,
    /// Bytes written to TUN/TAP device.
    pub tun_tap_write_bytes: u64,
    /// Bytes read from TCP/UDP socket.
    pub tcp_udp_read_bytes: u64,
    /// Bytes written to TCP/UDP socket.
    pub tcp_udp_write_bytes: u64,
    /// Auth read bytes (usually 0).
    pub auth_read_bytes: u64,
    /// Pre-compression bytes (if compression enabled).
    pub pre_compress_bytes: Option<u64>,
    /// Post-compression bytes (if compression enabled).
    pub post_compress_bytes: Option<u64>,
    /// Pre-decompression bytes (if compression enabled).
    pub pre_decompress_bytes: Option<u64>,
    /// Post-decompression bytes (if compression enabled).
    pub post_decompress_bytes: Option<u64>,
}

/// Error returned when a status response cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseStatusError {
    /// A numeric field could not be parsed.
    #[error("invalid integer for field {field:?}: {value:?}")]
    InvalidInteger {
        /// The field name that failed to parse.
        field: &'static str,
        /// The raw value that could not be parsed.
        value: String,
    },

    /// A CLIENT_LIST line had too few fields.
    #[error("CLIENT_LIST has too few fields (need >= 5, got {0})")]
    ClientListTooFewFields(usize),

    /// A ROUTING_TABLE line had too few fields.
    #[error("ROUTING_TABLE has too few fields (need >= 4, got {0})")]
    RoutingTableTooFewFields(usize),

    /// A required statistics key was missing.
    #[error("missing statistics key: {0:?}")]
    MissingStatisticsKey(&'static str),
}

/// Detect the separator used in the status output.
///
/// V3 uses tabs, V1/V2 use commas. We check the first line for a tab character.
fn detect_separator(lines: &[String]) -> char {
    for line in lines {
        if line.starts_with("TITLE\t")
            || line.starts_with("TIME\t")
            || line.starts_with("HEADER\t")
            || line.starts_with("CLIENT_LIST\t")
            || line.starts_with("ROUTING_TABLE\t")
            || line.starts_with("GLOBAL_STATS\t")
        {
            return '\t';
        }
    }
    ','
}

fn parse_u64(s: &str, field: &'static str) -> Result<u64, ParseStatusError> {
    s.parse().map_err(|_| ParseStatusError::InvalidInteger {
        field,
        value: s.to_string(),
    })
}

fn parse_optional_u64(s: &str) -> Option<u64> {
    if s.is_empty() || s == "UNDEF" {
        None
    } else {
        s.parse()
            .inspect_err(|error| {
                tracing::warn!(%error, value = s, "non-numeric optional u64 in status response")
            })
            .ok()
    }
}

fn parse_optional_timestamp(s: &str) -> Option<crate::timestamp::UtcTimestamp> {
    parse_optional_u64(s).map(crate::timestamp::UtcTimestamp)
}

/// Map OpenVPN's `"UNDEF"` sentinel to `None`.
fn parse_optional_string(s: &str) -> Option<String> {
    if s.is_empty() || s == "UNDEF" {
        None
    } else {
        Some(s.to_string())
    }
}

/// Parse a server-mode status response into typed structs.
///
/// Accepts V1 (comma-separated), V2 (comma with prefix lines), and V3
/// (tab-delimited) formats. The format is auto-detected.
///
/// V1 format starts with `"OpenVPN CLIENT LIST"` and has a fixed column
/// layout with fewer fields. V2/V3 use `TITLE`/`TIME`/`HEADER`/`CLIENT_LIST`
/// prefix markers.
///
/// # Examples
///
/// ```
/// use openvpn_mgmt_codec::status::parse_status;
///
/// let lines: Vec<String> = vec![
///     "TITLE\tOpenVPN 2.6.8",
///     "TIME\t2024-03-21 14:30:00\t1711031400",
///     "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher",
///     "CLIENT_LIST\tpeer1\t203.0.113.10:52841\t10.8.0.6\t\t1548576\t984320\t2024-03-21 09:15:00\t1711012500\tUNDEF\t0\t0\tAES-256-GCM",
///     "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)",
///     "ROUTING_TABLE\t10.8.0.6\tpeer1\t203.0.113.10:52841\t2024-03-21 14:29:50\t1711031390",
///     "GLOBAL_STATS\tMax bcast/mcast queue length\t3",
/// ].into_iter().map(String::from).collect();
///
/// let status = parse_status(&lines).unwrap();
/// assert_eq!(status.title.as_deref(), Some("OpenVPN 2.6.8"));
/// assert_eq!(status.clients.len(), 1);
/// assert_eq!(status.clients[0].common_name, "peer1");
/// assert_eq!(status.clients[0].bytes_in, 1548576);
/// assert_eq!(status.routes[0].virtual_address, "10.8.0.6");
/// ```
pub fn parse_status(lines: &[String]) -> Result<StatusResponse, ParseStatusError> {
    // Detect V1 by looking for the header line.
    if lines
        .first()
        .is_some_and(|line| line == "OpenVPN CLIENT LIST")
    {
        return parse_status_v1(lines);
    }

    let sep = detect_separator(lines);
    parse_status_v2v3(lines, sep)
}

/// Parse V1 format: `OpenVPN CLIENT LIST`, comma-separated, no prefix markers.
fn parse_status_v1(lines: &[String]) -> Result<StatusResponse, ParseStatusError> {
    let mut status = StatusResponse {
        title: None,
        timestamp: None,
        updated: None,
        clients: Vec::new(),
        routes: Vec::new(),
        global_stats: Vec::new(),
    };

    #[derive(PartialEq)]
    enum Section {
        Header,
        ClientList,
        RoutingTable,
        GlobalStats,
    }
    let mut section = Section::Header;

    for line in lines {
        // Section transitions
        if line == "OpenVPN CLIENT LIST" {
            section = Section::Header;
            continue;
        }
        if line.starts_with("Updated,") {
            status.updated = Some(line.strip_prefix("Updated,").unwrap_or("").to_string());
            continue;
        }
        if line == "ROUTING TABLE" {
            section = Section::RoutingTable;
            continue;
        }
        if line == "GLOBAL STATS" {
            section = Section::GlobalStats;
            continue;
        }

        let fields: Vec<&str> = line.split(',').collect();

        // Skip header rows (V1 has a "Common Name,Real Address,..." header)
        match section {
            Section::Header => {
                if fields.first() == Some(&"Common Name") {
                    section = Section::ClientList;
                    continue;
                }
            }
            Section::ClientList => {
                // V1 CLIENT_LIST: CN, Real Address, Bytes Received, Bytes Sent, Connected Since
                if fields.len() < 5 {
                    return Err(ParseStatusError::ClientListTooFewFields(fields.len()));
                }
                status.clients.push(ConnectedClient {
                    common_name: fields[0].to_string(),
                    real_address: fields[1].to_string(),
                    virtual_address: String::new(), // Not present in V1
                    virtual_ipv6: String::new(),
                    bytes_in: parse_u64(fields[2], "bytes_received")?,
                    bytes_out: parse_u64(fields[3], "bytes_sent")?,
                    connected_since: fields[4..].join(","), // May contain commas in date
                    connected_since_t: None,
                    username: None,
                    cid: None,
                    peer_id: None,
                    cipher: None,
                });
            }
            Section::RoutingTable => {
                // Skip header row
                if fields.first() == Some(&"Virtual Address") {
                    continue;
                }
                if fields.len() < 4 {
                    return Err(ParseStatusError::RoutingTableTooFewFields(fields.len()));
                }
                status.routes.push(RoutingEntry {
                    virtual_address: fields[0].to_string(),
                    common_name: fields[1].to_string(),
                    real_address: fields[2].to_string(),
                    last_ref: fields[3..].join(","),
                    last_ref_t: None,
                });
            }
            Section::GlobalStats => {
                if fields.len() >= 2 {
                    status
                        .global_stats
                        .push((fields[0].to_string(), fields[1..].join(",")));
                }
            }
        }
    }

    Ok(status)
}

/// Parse V2/V3 format: prefix markers, comma or tab separator.
fn parse_status_v2v3(lines: &[String], sep: char) -> Result<StatusResponse, ParseStatusError> {
    let mut status = StatusResponse {
        title: None,
        timestamp: None,
        updated: None,
        clients: Vec::new(),
        routes: Vec::new(),
        global_stats: Vec::new(),
    };

    for line in lines {
        let fields: Vec<&str> = line.split(sep).collect();
        let tag = fields.first().copied().unwrap_or("");

        match tag {
            "TITLE" => {
                status.title = fields.get(1).map(|val| val.to_string());
            }
            "TIME" => {
                status.updated = fields.get(1).map(|val| val.to_string());
                status.timestamp =
                    fields.get(2).and_then(|val| parse_optional_timestamp(val));
            }
            "HEADER" => {
                // Skip header rows — they describe columns, not data.
            }
            "CLIENT_LIST" => {
                // V2/V3 CLIENT_LIST columns (after the tag):
                // 0:CN 1:RealAddr 2:VirtAddr 3:VirtIPv6 4:BytesRecv 5:BytesSent
                // 6:ConnSince 7:ConnSince_t 8:Username 9:CID 10:PeerID 11:Cipher
                //
                // Older (2.3) layout omits VirtIPv6, PeerID, Cipher:
                // 0:CN 1:RealAddr 2:VirtAddr 3:BytesRecv 4:BytesSent
                // 5:ConnSince 6:ConnSince_t 7:Username
                let cols = &fields[1..]; // Skip the "CLIENT_LIST" tag
                let has_ipv6_column = cols.len() >= 12;

                if has_ipv6_column {
                    // has_ipv6_column requires cols.len() >= 12, so all
                    // indexed accesses (up to cols[7]) are in-bounds.
                    status.clients.push(ConnectedClient {
                        common_name: cols[0].to_string(),
                        real_address: cols[1].to_string(),
                        virtual_address: cols[2].to_string(),
                        virtual_ipv6: cols[3].to_string(),
                        bytes_in: parse_u64(cols[4], "bytes_received")?,
                        bytes_out: parse_u64(cols[5], "bytes_sent")?,
                        connected_since: cols[6].to_string(),
                        connected_since_t: parse_optional_timestamp(
                            cols.get(7).copied().unwrap_or(""),
                        ),
                        username: cols.get(8).and_then(|val| parse_optional_string(val)),
                        cid: cols.get(9).and_then(|val| parse_optional_u64(val)),
                        peer_id: cols.get(10).and_then(|val| parse_optional_u64(val)),
                        cipher: cols.get(11).and_then(|val| parse_optional_string(val)),
                    });
                } else {
                    // Older layout: no IPv6, no PeerID, no Cipher
                    if cols.len() < 5 {
                        return Err(ParseStatusError::ClientListTooFewFields(cols.len()));
                    }
                    status.clients.push(ConnectedClient {
                        common_name: cols[0].to_string(),
                        real_address: cols[1].to_string(),
                        virtual_address: cols[2].to_string(),
                        virtual_ipv6: String::new(),
                        bytes_in: parse_u64(cols[3], "bytes_received")?,
                        bytes_out: parse_u64(cols[4], "bytes_sent")?,
                        connected_since: cols.get(5).unwrap_or(&"").to_string(),
                        connected_since_t: cols.get(6).and_then(|val| parse_optional_timestamp(val)),
                        username: cols.get(7).and_then(|val| parse_optional_string(val)),
                        cid: None,
                        peer_id: None,
                        cipher: None,
                    });
                }
            }
            "ROUTING_TABLE" => {
                let cols = &fields[1..];
                if cols.len() < 4 {
                    return Err(ParseStatusError::RoutingTableTooFewFields(cols.len()));
                }
                status.routes.push(RoutingEntry {
                    virtual_address: cols[0].to_string(),
                    common_name: cols[1].to_string(),
                    real_address: cols[2].to_string(),
                    last_ref: cols[3].to_string(),
                    last_ref_t: cols.get(4).and_then(|val| parse_optional_timestamp(val)),
                });
            }
            "GLOBAL_STATS" if fields.len() >= 3 => {
                status
                    .global_stats
                    .push((fields[1].to_string(), fields[2..].join(&sep.to_string())));
            }
            _ => {
                // Unknown line — skip silently for forward compatibility.
            }
        }
    }

    Ok(status)
}

/// Parse a client-mode statistics response.
///
/// Client mode returns `OpenVPN STATISTICS` — a simple key-value list.
/// The first line is the header, the second is `Updated,...`.
///
/// # Examples
///
/// ```
/// use openvpn_mgmt_codec::status::parse_client_statistics;
///
/// let lines: Vec<String> = vec![
///     "OpenVPN STATISTICS",
///     "Updated,2024-03-21 14:30:00",
///     "TUN/TAP read bytes,1548576",
///     "TUN/TAP write bytes,984320",
///     "TCP/UDP read bytes,1600000",
///     "TCP/UDP write bytes,1020000",
///     "Auth read bytes,0",
/// ].into_iter().map(String::from).collect();
///
/// let stats = parse_client_statistics(&lines).unwrap();
/// assert_eq!(stats.tun_tap_read_bytes, 1548576);
/// assert_eq!(stats.tcp_udp_write_bytes, 1020000);
/// assert!(stats.pre_compress_bytes.is_none());
/// ```
pub fn parse_client_statistics(lines: &[String]) -> Result<ClientStatistics, ParseStatusError> {
    let mut stats = ClientStatistics::default();
    let mut found_tun_read = false;
    let mut found_tun_write = false;
    let mut found_tcp_read = false;
    let mut found_tcp_write = false;
    let mut found_auth_read = false;

    for line in lines {
        if line == "OpenVPN STATISTICS" || line.starts_with("Updated,") {
            continue;
        }
        let Some((key, val)) = line.split_once(',') else {
            continue;
        };
        match key {
            "TUN/TAP read bytes" => {
                stats.tun_tap_read_bytes = parse_u64(val, "tun_tap_read_bytes")?;
                found_tun_read = true;
            }
            "TUN/TAP write bytes" => {
                stats.tun_tap_write_bytes = parse_u64(val, "tun_tap_write_bytes")?;
                found_tun_write = true;
            }
            "TCP/UDP read bytes" => {
                stats.tcp_udp_read_bytes = parse_u64(val, "tcp_udp_read_bytes")?;
                found_tcp_read = true;
            }
            "TCP/UDP write bytes" => {
                stats.tcp_udp_write_bytes = parse_u64(val, "tcp_udp_write_bytes")?;
                found_tcp_write = true;
            }
            "Auth read bytes" => {
                stats.auth_read_bytes = parse_u64(val, "auth_read_bytes")?;
                found_auth_read = true;
            }
            "pre-compress bytes" => {
                stats.pre_compress_bytes = Some(parse_u64(val, "pre_compress_bytes")?);
            }
            "post-compress bytes" => {
                stats.post_compress_bytes = Some(parse_u64(val, "post_compress_bytes")?);
            }
            "pre-decompress bytes" => {
                stats.pre_decompress_bytes = Some(parse_u64(val, "pre_decompress_bytes")?);
            }
            "post-decompress bytes" => {
                stats.post_decompress_bytes = Some(parse_u64(val, "post_decompress_bytes")?);
            }
            _ => {} // Forward-compat: ignore unknown keys
        }
    }

    if !found_tun_read {
        return Err(ParseStatusError::MissingStatisticsKey("TUN/TAP read bytes"));
    }
    if !found_tun_write {
        return Err(ParseStatusError::MissingStatisticsKey(
            "TUN/TAP write bytes",
        ));
    }
    if !found_tcp_read {
        return Err(ParseStatusError::MissingStatisticsKey("TCP/UDP read bytes"));
    }
    if !found_tcp_write {
        return Err(ParseStatusError::MissingStatisticsKey(
            "TCP/UDP write bytes",
        ));
    }
    if !found_auth_read {
        return Err(ParseStatusError::MissingStatisticsKey("Auth read bytes"));
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load a fixture file's content into the `Vec<String>` format that
    /// `parse_status` / `parse_client_statistics` expect: one entry per
    /// non-empty line, with the `END` terminator stripped.
    fn fixture_lines(raw: &str) -> Vec<String> {
        raw.lines()
            .filter(|line| !line.is_empty() && *line != "END")
            .map(String::from)
            .collect()
    }

    // --- V3 (tab-separated) ---

    #[test]
    fn v3_single_client() {
        let lines = fixture_lines(include_str!("../tests/fixtures/status_v3.txt"));
        let status = parse_status(&lines).unwrap();
        assert_eq!(
            status.title.as_deref(),
            Some("OpenVPN 2.6.8 x86_64-pc-linux-gnu")
        );
        assert_eq!(status.timestamp, Some(crate::timestamp::UtcTimestamp(1711031400)));
        assert_eq!(status.updated.as_deref(), Some("2024-03-21 14:30:00"));
        assert_eq!(status.clients.len(), 1);
        let client = &status.clients[0];
        assert_eq!(client.common_name, "client1");
        assert_eq!(client.real_address, "203.0.113.10:52841");
        assert_eq!(client.virtual_address, "10.8.0.6");
        assert!(client.virtual_ipv6.is_empty());
        assert_eq!(client.bytes_in, 1548576);
        assert_eq!(client.bytes_out, 984320);
        assert_eq!(client.connected_since_t, Some(crate::timestamp::UtcTimestamp(1711012500)));
        assert_eq!(client.username, None); // "UNDEF" is mapped to None
        assert_eq!(client.cid, Some(0));
        assert_eq!(client.peer_id, Some(0));
        assert_eq!(client.cipher.as_deref(), Some("AES-256-GCM"));

        assert_eq!(status.routes.len(), 1);
        let route = &status.routes[0];
        assert_eq!(route.virtual_address, "10.8.0.6");
        assert_eq!(route.last_ref_t, Some(crate::timestamp::UtcTimestamp(1711031390)));

        assert_eq!(status.global_stats.len(), 1);
        assert_eq!(status.global_stats[0].0, "Max bcast/mcast queue length");
        assert_eq!(status.global_stats[0].1, "3");
    }

    // --- V2 (comma-separated, modern) ---

    #[test]
    fn v2_single_client() {
        let lines = fixture_lines(include_str!("../tests/fixtures/status_v2.txt"));
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.clients.len(), 1);
        assert_eq!(status.clients[0].common_name, "client1");
        assert_eq!(status.clients[0].cipher.as_deref(), Some("AES-256-GCM"));
        assert_eq!(status.routes.len(), 1);
    }

    #[test]
    fn v2_full_multiple_clients() {
        let lines = fixture_lines(include_str!("../tests/fixtures/status_v2_full.txt"));
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.clients.len(), 2);
        assert_eq!(status.clients[0].common_name, "ntafs");
        assert_eq!(status.clients[0].virtual_ipv6, "2002:232:324:12::8");
        assert_eq!(status.clients[1].common_name, "rdpuser");
        assert_eq!(status.clients[1].username.as_deref(), Some("rdpuser"));
        assert_eq!(
            status.clients[1].cipher.as_deref(),
            Some("CHACHA20-POLY1305")
        );

        assert_eq!(status.routes.len(), 3);
        assert_eq!(status.routes[0].virtual_address, "10.1.1.8");
        // IPv6 route
        assert_eq!(status.routes[1].virtual_address, "2002:232:324:12::8");

        // Multiple GLOBAL_STATS lines
        assert_eq!(status.global_stats.len(), 2);
    }

    #[test]
    fn v2_old_openvpn_23() {
        let lines = fixture_lines(include_str!("../tests/fixtures/status_v2_old.txt"));
        let status = parse_status(&lines).unwrap();
        assert_eq!(
            status.title.as_deref(),
            Some(
                "OpenVPN 2.3.2 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [EPOLL] [PKCS11] [eurephia] [MH] [IPv6] built on Dec  2 2014"
            ),
        );
        assert_eq!(status.clients.len(), 2);
        // Old format: no IPv6, no PeerID, no Cipher
        assert!(status.clients[0].virtual_ipv6.is_empty());
        assert_eq!(status.clients[0].peer_id, None);
        assert_eq!(status.clients[0].cipher, None);
        assert_eq!(status.clients[1].username.as_deref(), Some("admin"));
    }

    // --- V1 server ---

    #[test]
    fn v1_server_two_clients() {
        let lines = fixture_lines(include_str!("../tests/fixtures/status_v1_server.txt"));
        let status = parse_status(&lines).unwrap();
        assert!(status.title.is_none());
        assert!(status.timestamp.is_none());
        assert_eq!(status.updated.as_deref(), Some("2024-03-21 14:30:00"));
        assert_eq!(status.clients.len(), 2);
        assert_eq!(status.clients[0].common_name, "client1");
        assert_eq!(status.clients[0].bytes_in, 1548576);
        assert_eq!(status.clients[1].common_name, "client2");
        // V1 has no extra fields
        assert!(status.clients[0].cid.is_none());
        assert!(status.clients[0].cipher.is_none());

        assert_eq!(status.routes.len(), 2);
        assert_eq!(status.global_stats.len(), 1);
    }

    #[test]
    fn v1_server_empty() {
        let lines = fixture_lines(include_str!("../tests/fixtures/status_v1_server_empty.txt"));
        let status = parse_status(&lines).unwrap();
        assert!(status.clients.is_empty());
        assert!(status.routes.is_empty());
        assert_eq!(status.global_stats.len(), 1);
    }

    #[test]
    fn v1_server_many_clients() {
        let lines = fixture_lines(include_str!(
            "../tests/fixtures/status_v1_server_many_clients.txt"
        ));
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.clients.len(), 3);
        assert_eq!(status.routes.len(), 3);
    }

    // --- Client statistics ---

    #[test]
    fn client_statistics_basic() {
        let lines = fixture_lines(include_str!("../tests/fixtures/status_v1_client.txt"));
        let stats = parse_client_statistics(&lines).unwrap();
        assert_eq!(stats.tun_tap_read_bytes, 1548576);
        assert_eq!(stats.tun_tap_write_bytes, 984320);
        assert_eq!(stats.tcp_udp_read_bytes, 1600000);
        assert_eq!(stats.tcp_udp_write_bytes, 1020000);
        assert_eq!(stats.auth_read_bytes, 0);
        assert!(stats.pre_compress_bytes.is_none());
    }

    #[test]
    fn client_statistics_with_compression() {
        let lines = fixture_lines(include_str!("../tests/fixtures/status_v1_client_full.txt"));
        let stats = parse_client_statistics(&lines).unwrap();
        assert_eq!(stats.tun_tap_read_bytes, 153789941);
        assert_eq!(stats.pre_compress_bytes, Some(45388190));
        assert_eq!(stats.post_compress_bytes, Some(45446864));
        assert_eq!(stats.pre_decompress_bytes, Some(162596168));
        assert_eq!(stats.post_decompress_bytes, Some(216965355));
    }

    #[test]
    fn client_statistics_missing_key() {
        let lines = vec![
            "OpenVPN STATISTICS".to_string(),
            "Updated,now".to_string(),
            "TUN/TAP read bytes,100".to_string(),
        ];
        let err = parse_client_statistics(&lines).unwrap_err();
        assert!(matches!(
            err,
            ParseStatusError::MissingStatisticsKey("TUN/TAP write bytes")
        ));
    }

    #[test]
    fn client_statistics_invalid_number() {
        let lines = vec![
            "OpenVPN STATISTICS".to_string(),
            "Updated,now".to_string(),
            "TUN/TAP read bytes,abc".to_string(),
        ];
        let err = parse_client_statistics(&lines).unwrap_err();
        assert!(matches!(
            err,
            ParseStatusError::InvalidInteger {
                field: "tun_tap_read_bytes",
                ..
            }
        ));
    }

    // --- detect_separator ---

    #[test]
    fn detect_separator_each_tab_prefix() {
        for prefix in [
            "TITLE\t",
            "TIME\t",
            "HEADER\t",
            "CLIENT_LIST\t",
            "ROUTING_TABLE\t",
            "GLOBAL_STATS\t",
        ] {
            let lines = vec![format!("{prefix}data")];
            assert_eq!(
                detect_separator(&lines),
                '\t',
                "should detect tab for line starting with {prefix:?}",
            );
        }
    }

    #[test]
    fn detect_separator_falls_back_to_comma() {
        let lines = vec!["no tabs here".to_string()];
        assert_eq!(detect_separator(&lines), ',');
    }

    // --- parse_optional_u64 ---

    #[test]
    fn parse_optional_u64_empty() {
        assert_eq!(parse_optional_u64(""), None);
    }

    #[test]
    fn parse_optional_u64_undef() {
        assert_eq!(parse_optional_u64("UNDEF"), None);
    }

    #[test]
    fn parse_optional_u64_valid() {
        assert_eq!(parse_optional_u64("42"), Some(42));
    }

    // --- V1 routing table guards ---

    #[test]
    fn v1_routing_table_too_few_fields() {
        let lines = vec![
            "OpenVPN CLIENT LIST".to_string(),
            "Updated,2024-03-21 14:30:00".to_string(),
            "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since".to_string(),
            "client1,10.0.0.1,1000,2000,2024-03-21 10:00:00".to_string(),
            "ROUTING TABLE".to_string(),
            "Virtual Address,Common Name,Real Address,Last Ref".to_string(),
            // Only 2 fields — fewer than the required 4.
            "10.8.0.6,client1".to_string(),
        ];
        let err = parse_status(&lines).unwrap_err();
        assert!(
            matches!(err, ParseStatusError::RoutingTableTooFewFields(2)),
            "expected RoutingTableTooFewFields(2), got {err:?}",
        );
    }

    // --- V2/V3 GLOBAL_STATS guard ---

    #[test]
    fn v2v3_global_stats_with_only_key_is_ignored() {
        // GLOBAL_STATS with only 2 fields (tag + key, no value) — should be silently skipped.
        let lines = vec!["GLOBAL_STATS\torphan_key".to_string()];
        let status = parse_status(&lines).unwrap();
        assert!(
            status.global_stats.is_empty(),
            "GLOBAL_STATS with <3 fields should be ignored",
        );
    }

    #[test]
    fn v2v3_global_stats_exactly_three_fields() {
        // Exactly 3 fields (tag + key + value) — the minimum accepted by the guard.
        let lines = vec!["GLOBAL_STATS\tMax bcast/mcast queue length\t3".to_string()];
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.global_stats.len(), 1);
        assert_eq!(status.global_stats[0].0, "Max bcast/mcast queue length");
        assert_eq!(status.global_stats[0].1, "3");
    }

    // --- Edge cases ---

    #[test]
    fn empty_input() {
        let status = parse_status(&[]).unwrap();
        assert!(status.clients.is_empty());
        assert!(status.routes.is_empty());
    }

    #[test]
    fn v1_client_list_too_few_fields() {
        let lines = vec![
            "OpenVPN CLIENT LIST".to_string(),
            "Updated,2024-03-21 14:30:00".to_string(),
            "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since".to_string(),
            // Only 3 fields — fewer than the required 5.
            "client1,203.0.113.10:52841,1548576".to_string(),
        ];
        let err = parse_status(&lines).unwrap_err();
        assert!(
            matches!(err, ParseStatusError::ClientListTooFewFields(3)),
            "expected ClientListTooFewFields(3), got {err:?}",
        );
    }

    #[test]
    fn v1_client_list_exactly_five_fields() {
        // Exactly 5 fields — the minimum accepted by the `fields.len() < 5` guard.
        let lines = vec![
            "OpenVPN CLIENT LIST".to_string(),
            "Updated,2024-03-21 14:30:00".to_string(),
            "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since".to_string(),
            "client1,203.0.113.10:52841,1548576,984320,2024-03-21 10:00:00".to_string(),
        ];
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.clients.len(), 1);
        assert_eq!(status.clients[0].common_name, "client1");
        assert_eq!(status.clients[0].bytes_in, 1548576);
        assert_eq!(status.clients[0].bytes_out, 984320);
    }

    #[test]
    fn v1_routing_table_exactly_four_fields() {
        // Exactly 4 fields — the minimum accepted by the `fields.len() < 4` guard.
        let lines = vec![
            "OpenVPN CLIENT LIST".to_string(),
            "Updated,2024-03-21 14:30:00".to_string(),
            "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since".to_string(),
            "ROUTING TABLE".to_string(),
            "Virtual Address,Common Name,Real Address,Last Ref".to_string(),
            "10.8.0.6,client1,203.0.113.10:52841,2024-03-21 14:30:00".to_string(),
        ];
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.routes.len(), 1);
        assert_eq!(status.routes[0].virtual_address, "10.8.0.6");
        assert_eq!(status.routes[0].common_name, "client1");
    }

    #[test]
    fn v2v3_routing_table_too_few_fields() {
        // ROUTING_TABLE with only 2 data fields (need at least 4).
        let lines = vec!["ROUTING_TABLE\t10.8.0.6\tclient1".to_string()];
        let err = parse_status(&lines).unwrap_err();
        assert!(
            matches!(err, ParseStatusError::RoutingTableTooFewFields(2)),
            "expected RoutingTableTooFewFields(2), got {err:?}",
        );
    }

    #[test]
    fn v2v3_routing_table_exactly_four_fields() {
        // Exactly 4 data fields — the minimum accepted by the guard.
        let lines = vec![
            "ROUTING_TABLE\t10.8.0.6\tclient1\t203.0.113.10:52841\t2024-03-21 14:30:00".to_string(),
        ];
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.routes.len(), 1);
        assert_eq!(status.routes[0].virtual_address, "10.8.0.6");
        assert_eq!(status.routes[0].common_name, "client1");
    }

    #[test]
    fn v2v3_client_list_old_layout_too_few_fields() {
        // Old layout CLIENT_LIST with only 3 data fields (need at least 5).
        let lines = vec!["CLIENT_LIST\tclient1\t203.0.113.10:52841\t10.8.0.6".to_string()];
        let err = parse_status(&lines).unwrap_err();
        assert!(
            matches!(err, ParseStatusError::ClientListTooFewFields(3)),
            "expected ClientListTooFewFields(3), got {err:?}",
        );
    }

    #[test]
    fn v2v3_client_list_old_layout_exactly_five_fields() {
        // Exactly 5 data fields — the minimum accepted by the old-layout guard.
        let lines =
            vec!["CLIENT_LIST\tclient1\t203.0.113.10:52841\t10.8.0.6\t1548576\t984320".to_string()];
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.clients.len(), 1);
        assert_eq!(status.clients[0].common_name, "client1");
        assert_eq!(status.clients[0].bytes_in, 1548576);
        assert_eq!(status.clients[0].bytes_out, 984320);
    }

    #[test]
    fn v2v3_unknown_lines_ignored() {
        let lines = vec![
            "TITLE\tTest".to_string(),
            "FUTURE_SECTION\tsomething\tnew".to_string(),
            "GLOBAL_STATS\tkey\tval".to_string(),
        ];
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.title.as_deref(), Some("Test"));
        assert_eq!(status.global_stats.len(), 1);
    }

    #[test]
    fn v2v3_non_numeric_timestamp_in_time_row() {
        let lines = vec![
            "TIME,not-a-timestamp,also-not".to_string(),
            "GLOBAL_STATS,key,val".to_string(),
        ];
        let status = parse_status(&lines).unwrap();
        assert!(status.timestamp.is_none());
        assert_eq!(status.updated.as_deref(), Some("not-a-timestamp"));
    }

    #[test]
    fn v2v3_non_numeric_optional_field_in_client_list() {
        // connected_since_t is an optional u64 — non-numeric should yield None.
        let lines = vec![
            "CLIENT_LIST,cn,10.0.0.1:1234,10.8.0.1,,100,200,2024-01-01,abc,UNDEF,1,0,AES-256-GCM"
                .to_string(),
        ];
        let status = parse_status(&lines).unwrap();
        assert_eq!(status.clients.len(), 1);
        assert_eq!(status.clients[0].connected_since_t, None);
    }

    #[test]
    fn client_statistics_missing_all_keys() {
        let lines = vec!["OpenVPN STATISTICS".to_string(), "Updated,now".to_string()];
        let err = parse_client_statistics(&lines).unwrap_err();
        assert!(matches!(
            err,
            ParseStatusError::MissingStatisticsKey("TUN/TAP read bytes")
        ));
    }

    #[test]
    fn client_statistics_unknown_keys_ignored() {
        let lines = vec![
            "OpenVPN STATISTICS".to_string(),
            "Updated,now".to_string(),
            "TUN/TAP read bytes,100".to_string(),
            "TUN/TAP write bytes,200".to_string(),
            "TCP/UDP read bytes,300".to_string(),
            "TCP/UDP write bytes,400".to_string(),
            "Auth read bytes,0".to_string(),
            "future-metric,999".to_string(),
        ];
        let stats = parse_client_statistics(&lines).unwrap();
        assert_eq!(stats.tun_tap_read_bytes, 100);
    }
}
