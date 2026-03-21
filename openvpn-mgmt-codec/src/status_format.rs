use std::fmt;
use std::str::FromStr;

/// Status output format version. Higher versions are more machine-parseable.
///
/// - V1: default human-readable format
/// - V2: adds header/footer markers for easier parsing
/// - V3: tab-delimited, ideal for programmatic consumption
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StatusFormat {
    /// Default human-readable format.
    #[default]
    V1,

    /// Adds header/footer markers for easier parsing.
    V2,

    /// Tab-delimited, ideal for programmatic consumption.
    V3,
}

impl fmt::Display for StatusFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => f.write_str("1"),
            Self::V2 => f.write_str("2"),
            Self::V3 => f.write_str("3"),
        }
    }
}

impl FromStr for StatusFormat {
    type Err = String;

    /// Parse a status format version: `1`, `2`, or `3`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1" => Ok(Self::V1),
            "2" => Ok(Self::V2),
            "3" => Ok(Self::V3),
            _ => Err(format!("invalid status format: {s} (use 1, 2, or 3)")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_roundtrip() {
        for fmt in [StatusFormat::V1, StatusFormat::V2, StatusFormat::V3] {
            let s = fmt.to_string();
            assert_eq!(s.parse::<StatusFormat>().unwrap(), fmt);
        }
    }

    #[test]
    fn display_values() {
        assert_eq!(StatusFormat::V1.to_string(), "1");
        assert_eq!(StatusFormat::V2.to_string(), "2");
        assert_eq!(StatusFormat::V3.to_string(), "3");
    }

    #[test]
    fn parse_invalid() {
        assert!("4".parse::<StatusFormat>().is_err());
        assert!("".parse::<StatusFormat>().is_err());
    }
}
