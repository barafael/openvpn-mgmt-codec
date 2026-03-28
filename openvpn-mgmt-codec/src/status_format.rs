use std::str::FromStr;

/// Error returned when a string is not a recognized status format.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized status format: {0:?}")]
pub struct ParseStatusFormatError(String);

/// Status output format version. Higher versions are more machine-parseable.
///
/// - V1: default human-readable format
/// - V2: adds header/footer markers for easier parsing
/// - V3: tab-delimited, ideal for programmatic consumption
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, strum::Display)]
pub enum StatusFormat {
    /// Default human-readable format.
    #[default]
    #[strum(to_string = "1")]
    V1,

    /// Adds header/footer markers for easier parsing.
    #[strum(to_string = "2")]
    V2,

    /// Tab-delimited, ideal for programmatic consumption.
    #[strum(to_string = "3")]
    V3,
}

impl FromStr for StatusFormat {
    type Err = ParseStatusFormatError;

    /// Parse a status format version: `1`, `2`, or `3`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "1" => Ok(Self::V1),
            "2" => Ok(Self::V2),
            "3" => Ok(Self::V3),
            other => Err(ParseStatusFormatError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(StatusFormat::V1)]
    #[test_case(StatusFormat::V2)]
    #[test_case(StatusFormat::V3)]
    fn display_roundtrip(fmt: StatusFormat) {
        let string = fmt.to_string();
        assert_eq!(string.parse::<StatusFormat>().unwrap(), fmt);
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
