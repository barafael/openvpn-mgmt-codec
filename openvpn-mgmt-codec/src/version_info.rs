/// Error returned when a `version` response cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseVersionError {
    /// The management version line was found but contained a non-numeric value.
    #[error("non-numeric management version: {0:?}")]
    InvalidManagementVersion(String),
}

/// Parsed output from the `version` command's multi-line response.
///
/// The response from OpenVPN looks like:
///
/// ```text
/// OpenVPN Version: OpenVPN 2.6.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] ...
/// Management Interface Version: 5
/// END
/// ```
///
/// Note: OpenVPN ≥ 2.6.16 shortened the header to `Management Version: 5`
/// (without "Interface"). Both forms are accepted.
///
/// This struct extracts the management interface version (which is the
/// field most consumers need for feature-gating) and keeps the raw lines
/// for anything else.
///
/// # Examples
///
/// ```
/// use openvpn_mgmt_codec::VersionInfo;
///
/// let lines = vec![
///     "OpenVPN Version: OpenVPN 2.6.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD]".to_string(),
///     "Management Interface Version: 5".to_string(),
/// ];
/// let info = VersionInfo::parse(&lines).unwrap();
/// assert_eq!(info.management_version(), Some(5));
/// assert!(info.openvpn_version_line().unwrap().contains("2.6.9"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// The management interface version number, if found.
    management_version: Option<u32>,
    /// The full OpenVPN version line, if found.
    openvpn_version_line: Option<String>,
    /// All raw lines from the response, for forward compatibility.
    raw_lines: Vec<String>,
}

impl VersionInfo {
    /// Parse a `version` command's multi-line response into structured data.
    ///
    /// Returns [`ParseVersionError::InvalidManagementVersion`] if a
    /// management version line is found but its value is not a valid `u32`.
    /// Missing lines are not an error — the corresponding accessor returns
    /// `None`.
    pub fn parse(lines: &[String]) -> Result<Self, ParseVersionError> {
        let mut management_version = None;
        let mut openvpn_version_line = None;

        for line in lines {
            let lower = line.to_ascii_lowercase();

            // Match the management version line regardless of exact
            // wording. Known variants:
            //   "Management Interface Version: 5"  (OpenVPN ≤ 2.6.9)
            //   "Management Version: 5"            (OpenVPN ≥ 2.6.16)
            // Future-proof: accept any line starting with "management"
            // that contains "version" followed by a number.
            if management_version.is_none()
                && lower.starts_with("management")
                && lower.contains("version")
            {
                let trailing = line
                    .rsplit(|chr: char| !chr.is_ascii_digit())
                    .find(|part| !part.is_empty());

                management_version = match trailing {
                    Some(part) => Some(Some(part.parse::<u32>().map_err(|_| {
                        ParseVersionError::InvalidManagementVersion(part.to_string())
                    })?)),
                    None => Some(None),
                };
            } else if lower.starts_with("openvpn version") {
                openvpn_version_line = Some(line.clone());
            }
        }

        Ok(Self {
            management_version: management_version.flatten(),
            openvpn_version_line,
            raw_lines: lines.to_vec(),
        })
    }

    /// The management interface protocol version (e.g. `5`).
    ///
    /// Returns `None` if the line was missing or had no trailing digits.
    /// Use this to gate features: for instance, `client-pending-auth`
    /// requires management version >= 5 (OpenVPN 2.5+).
    pub fn management_version(&self) -> Option<u32> {
        self.management_version
    }

    /// The full `OpenVPN Version:` line (e.g. `"OpenVPN Version: OpenVPN 2.6.9 ..."`).
    pub fn openvpn_version_line(&self) -> Option<&str> {
        self.openvpn_version_line.as_deref()
    }

    /// All raw lines from the response, for anything not explicitly parsed.
    pub fn raw_lines(&self) -> &[String] {
        &self.raw_lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typical_version_output() {
        let lines = vec![
            "OpenVPN Version: OpenVPN 2.6.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD]".to_string(),
            "Management Interface Version: 5".to_string(),
        ];
        let info = VersionInfo::parse(&lines).unwrap();
        assert_eq!(info.management_version(), Some(5));
        assert!(info.openvpn_version_line().unwrap().contains("2.6.9"));
        assert_eq!(info.raw_lines().len(), 2);
    }

    #[test]
    fn parse_short_management_version_header() {
        // OpenVPN ≥ 2.6.16 uses "Management Version:" without "Interface".
        let lines = vec![
            "OpenVPN Version: OpenVPN 2.6.16 x86_64-alpine-linux-musl [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD]".to_string(),
            "Management Version: 5".to_string(),
        ];
        let info = VersionInfo::parse(&lines).unwrap();
        assert_eq!(info.management_version(), Some(5));
        assert!(info.openvpn_version_line().unwrap().contains("2.6.16"));
    }

    #[test]
    fn parse_old_version_without_management_line() {
        let lines = vec!["OpenVPN Version: OpenVPN 2.3.2 i686-pc-linux-gnu".to_string()];
        let info = VersionInfo::parse(&lines).unwrap();
        assert_eq!(info.management_version(), None);
        assert!(info.openvpn_version_line().is_some());
    }

    #[test]
    fn parse_empty_response() {
        let info = VersionInfo::parse(&[]).unwrap();
        assert_eq!(info.management_version(), None);
        assert_eq!(info.openvpn_version_line(), None);
        assert!(info.raw_lines().is_empty());
    }

    #[test]
    fn parse_hypothetical_future_format() {
        // Resilient to wording changes as long as "management" and
        // "version" appear and a trailing number is present.
        let lines = vec!["Management Protocol Version: 6".to_string()];
        let info = VersionInfo::parse(&lines).unwrap();
        assert_eq!(info.management_version(), Some(6));
    }

    #[test]
    fn parse_non_numeric_management_version() {
        // "Management Version: abc" — no trailing digits, so version is None.
        let lines = vec!["Management Version: abc".to_string()];
        let info = VersionInfo::parse(&lines).unwrap();
        assert_eq!(info.management_version(), None);
    }

    #[test]
    fn parse_overflow_management_version() {
        // A number too large for u32 returns an error.
        let lines = vec!["Management Version: 99999999999999999999".to_string()];
        let err = VersionInfo::parse(&lines).unwrap_err();
        assert!(matches!(
            err,
            ParseVersionError::InvalidManagementVersion(_)
        ));
    }
}
