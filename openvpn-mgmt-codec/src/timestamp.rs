//! Lightweight UTC timestamp formatting without external dependencies.
//!
//! The OpenVPN management protocol uses Unix timestamps (seconds since epoch)
//! in `>STATE:`, `>LOG:`, `>ECHO:`, and `status` responses. This module
//! provides formatting without pulling in a datetime library.
//!
//! # Examples
//!
//! ```
//! use openvpn_mgmt_codec::timestamp::{days_to_ymd, format_utc};
//!
//! assert_eq!(format_utc(1_711_031_400), "2024-03-21T14:30:00Z");
//! assert_eq!(days_to_ymd(0), (1970, 1, 1));
//! ```

use std::fmt;

/// Decompose a Unix timestamp into `(year, month, day, hour, minute, second)`.
///
/// All values are UTC. No timezone handling is performed.
pub fn decompose(ts: u64) -> (u64, u64, u64, u64, u64, u64) {
    let secs = ts % 60;
    let mins_total = ts / 60;
    let mins = mins_total % 60;
    let hours_total = mins_total / 60;
    let hours = hours_total % 24;
    let days_total = hours_total / 24;
    let (year, month, day) = days_to_ymd(days_total);
    (year, month, day, hours, mins, secs)
}

/// Format a Unix timestamp as ISO 8601 UTC: `2024-03-21T14:30:00Z`.
///
/// Returns an empty string for timestamp `0` (unset).
pub fn format_utc(ts: u64) -> String {
    if ts == 0 {
        return String::new();
    }
    let (year, month, day, hours, mins, secs) = decompose(ts);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z")
}

/// Format a Unix timestamp with a space separator: `2024-03-21 14:30:00`.
///
/// Returns an empty string for timestamp `0` (unset).
pub fn format_local_style(ts: u64) -> String {
    if ts == 0 {
        return String::new();
    }
    let (year, month, day, hours, mins, secs) = decompose(ts);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{mins:02}:{secs:02}")
}

/// Convert days since Unix epoch to `(year, month, day)`.
///
/// Uses the [civil_from_days algorithm by Howard Hinnant][algo].
///
/// [algo]: http://howardhinnant.github.io/date_algorithms.html
pub fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    days += 719_468;
    let era = days / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_offset = (5 * doy + 2) / 153;
    let day = doy - (153 * month_offset + 2) / 5 + 1;
    let month = if month_offset < 10 {
        month_offset + 3
    } else {
        month_offset - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// A Unix timestamp that implements [`Display`](fmt::Display) using
/// [`format_utc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcTimestamp(pub u64);

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return Ok(());
        }
        let (year, month, day, hours, mins, secs) = decompose(self.0);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_utc_zero() {
        assert_eq!(format_utc(0), "");
    }

    #[test]
    fn format_utc_epoch_plus_one() {
        assert_eq!(format_utc(1), "1970-01-01T00:00:01Z");
    }

    #[test]
    fn format_utc_known_date() {
        assert_eq!(format_utc(1_711_031_400), "2024-03-21T14:30:00Z");
    }

    #[test]
    fn format_utc_y2k() {
        assert_eq!(format_utc(946_684_800), "2000-01-01T00:00:00Z");
    }

    #[test]
    fn format_utc_leap_day() {
        assert_eq!(format_utc(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn format_local_style_known_date() {
        assert_eq!(format_local_style(1_711_031_400), "2024-03-21 14:30:00");
    }

    #[test]
    fn days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        assert_eq!(days_to_ymd(19803), (2024, 3, 21));
    }

    #[test]
    fn days_to_ymd_leap_day() {
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
    }

    #[test]
    fn days_to_ymd_dec_31() {
        assert_eq!(days_to_ymd(19722), (2023, 12, 31));
    }

    #[test]
    fn days_to_ymd_jan_1_2000() {
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }

    #[test]
    fn utc_timestamp_display() {
        assert_eq!(
            UtcTimestamp(1_711_031_400).to_string(),
            "2024-03-21T14:30:00Z"
        );
        assert_eq!(UtcTimestamp(0).to_string(), "");
    }
}
