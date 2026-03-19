use std::fmt;

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
