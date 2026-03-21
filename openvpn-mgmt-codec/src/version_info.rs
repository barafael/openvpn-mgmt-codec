use std::fmt;

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
/// let info = VersionInfo::parse(&lines);
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
    /// Lines that don't match known prefixes are preserved in
    /// [`raw_lines`](Self::raw_lines) for forward compatibility.
    pub fn parse(lines: &[String]) -> Self {
        let mut management_version = None;
        let mut openvpn_version_line = None;

        for line in lines {
            if let Some(rest) = line.strip_prefix("Management Interface Version:") {
                management_version = rest.trim().parse().ok();
            } else if line.starts_with("OpenVPN Version:") {
                openvpn_version_line = Some(line.clone());
            }
        }

        Self {
            management_version,
            openvpn_version_line,
            raw_lines: lines.to_vec(),
        }
    }

    /// The management interface protocol version (e.g. `5`).
    ///
    /// Returns `None` if the line was missing or unparseable. Use this to
    /// gate features: for instance, `client-pending-auth` requires
    /// management version >= 5 (OpenVPN 2.5+).
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

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = &self.openvpn_version_line {
            write!(f, "{line}")?;
            if let Some(v) = self.management_version {
                write!(f, " (management v{v})")?;
            }
        } else if let Some(v) = self.management_version {
            write!(f, "Management Interface Version: {v}")?;
        } else {
            f.write_str("(unknown version)")?;
        }
        Ok(())
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
        let info = VersionInfo::parse(&lines);
        assert_eq!(info.management_version(), Some(5));
        assert!(info.openvpn_version_line().unwrap().contains("2.6.9"));
        assert_eq!(info.raw_lines().len(), 2);
    }

    #[test]
    fn parse_old_version_without_management_line() {
        let lines = vec!["OpenVPN Version: OpenVPN 2.3.2 i686-pc-linux-gnu".to_string()];
        let info = VersionInfo::parse(&lines);
        assert_eq!(info.management_version(), None);
        assert!(info.openvpn_version_line().is_some());
    }

    #[test]
    fn parse_empty_response() {
        let info = VersionInfo::parse(&[]);
        assert_eq!(info.management_version(), None);
        assert_eq!(info.openvpn_version_line(), None);
        assert!(info.raw_lines().is_empty());
    }

    #[test]
    fn display_typical() {
        let lines = vec![
            "OpenVPN Version: OpenVPN 2.6.9".to_string(),
            "Management Interface Version: 5".to_string(),
        ];
        let info = VersionInfo::parse(&lines);
        let s = info.to_string();
        assert!(s.contains("2.6.9"));
        assert!(s.contains("management v5"));
    }

    #[test]
    fn display_unknown() {
        let info = VersionInfo::parse(&[]);
        assert_eq!(info.to_string(), "(unknown version)");
    }
}
