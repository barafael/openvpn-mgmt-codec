//! Encoder primitives for the OpenVPN management wire format.
//!
//! These are pure functions with no state — they serialize strings and
//! blocks into a `BytesMut` buffer.

use std::borrow::Cow;
use std::io;

use bytes::{BufMut, BytesMut};

/// Characters that are unsafe in the line-oriented management protocol:
/// `\n` and `\r` split commands; `\0` truncates at the C layer.
pub const WIRE_UNSAFE: &[char] = &['\n', '\r', '\0'];

/// Controls how the encoder handles characters that are unsafe for the
/// line-oriented management protocol (`\n`, `\r`, `\0`).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncoderMode {
    /// Silently strip unsafe characters (default, defensive).
    ///
    /// `\n`, `\r`, and `\0` are removed from all user-supplied strings.
    /// Block body lines equaling `"END"` are escaped to `" END"`.
    #[default]
    Sanitize,

    /// Reject inputs containing unsafe characters with an error.
    ///
    /// Returns `Err(io::Error)` if any field contains `\n`, `\r`, or
    /// `\0`, or if a block body line equals `"END"`. The inner error
    /// can be downcast to [`EncodeError`].
    Strict,
}

/// Structured error for encoder-side validation failures.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// A field contains `\n`, `\r`, or `\0`.
    #[error("{0} contains characters unsafe for the management protocol (\\n, \\r, or \\0)")]
    UnsafeCharacters(&'static str),

    /// A multi-line block body line equals `"END"`.
    #[error("block body line equals \"END\", which would terminate the block early")]
    EndInBlockBody,
}

/// Ensure a string is safe for the wire protocol.
///
/// In [`EncoderMode::Sanitize`]: strips `\n`, `\r`, and `\0`, returning
/// the cleaned string (or borrowing the original if already clean).
///
/// In [`EncoderMode::Strict`]: returns `Err` if any unsafe characters
/// are present.
pub fn wire_safe<'a>(
    s: &'a str,
    field: &'static str,
    mode: EncoderMode,
) -> Result<Cow<'a, str>, io::Error> {
    if !s.contains(WIRE_UNSAFE) {
        return Ok(Cow::Borrowed(s));
    }
    match mode {
        EncoderMode::Sanitize => Ok(Cow::Owned(
            s.chars().filter(|chr| !WIRE_UNSAFE.contains(chr)).collect(),
        )),
        EncoderMode::Strict => Err(io::Error::other(EncodeError::UnsafeCharacters(field))),
    }
}

/// Backslash-escape `\` and `"` per the OpenVPN config-file lexer rules.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

/// Wrap an already-escaped string in double quotes.
pub fn quote(s: &str) -> String {
    format!("\"{s}\"")
}

/// Write a single line followed by `\n`.
pub fn write_line(dst: &mut BytesMut, s: &str) {
    dst.reserve(s.len() + 1);
    dst.put_slice(s.as_bytes());
    dst.put_u8(b'\n');
}

/// Write a multi-line block: header line, body lines, and a terminating
/// `END`.
///
/// In [`EncoderMode::Sanitize`] mode, body lines have `\n`, `\r`, and
/// `\0` stripped, and any line that would be exactly `"END"` is escaped
/// to `" END"`.
///
/// In [`EncoderMode::Strict`] mode, body lines containing unsafe
/// characters or equaling `"END"` cause an error.
pub fn write_block(
    dst: &mut BytesMut,
    header: &str,
    lines: &[String],
    mode: EncoderMode,
) -> Result<(), io::Error> {
    let total: usize =
        header.len() + 1 + lines.iter().map(|line| line.len() + 2).sum::<usize>() + 4;
    dst.reserve(total);
    dst.put_slice(header.as_bytes());
    dst.put_u8(b'\n');
    for line in lines {
        let clean = wire_safe(line, "block body line", mode)?;
        if *clean == *"END" {
            match mode {
                EncoderMode::Sanitize => {
                    dst.put_slice(b" END");
                    dst.put_u8(b'\n');
                    continue;
                }
                EncoderMode::Strict => {
                    return Err(io::Error::other(EncodeError::EndInBlockBody));
                }
            }
        }
        dst.put_slice(clean.as_bytes());
        dst.put_u8(b'\n');
    }
    dst.put_slice(b"END\n");
    Ok(())
}

/// Controls how many items the decoder will accumulate before returning
/// an error.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccumulationLimit {
    /// No limit.
    Unlimited,

    /// At most this many items.
    Max(usize),
}
