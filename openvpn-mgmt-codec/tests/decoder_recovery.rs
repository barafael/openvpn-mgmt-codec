//! Decoder recovery tests.
//!
//! These tests verify that the decoder can recover from error conditions
//! (UTF-8 errors, accumulation limit violations) and continue to correctly
//! decode subsequent messages.

use bytes::BytesMut;
use openvpn_mgmt_codec::*;
use tokio_util::codec::{Decoder, Encoder};

// --- Helpers ---

fn codec() -> OvpnCodec {
    OvpnCodec::new()
}

// ---  ---
// UTF-8 error recovery
// ---  ---

#[test]
fn utf8_error_followed_by_valid_success() {
    let mut c = codec();
    let mut buf = BytesMut::new();

    // Invalid UTF-8 byte sequence followed by newline
    buf.extend_from_slice(&[0xFF, 0xFE, b'\n']);
    // Then a valid SUCCESS line
    buf.extend_from_slice(b"SUCCESS: recovered\n");

    // First decode: should error on invalid UTF-8
    let result = c.decode(&mut buf);
    assert!(result.is_err());

    // Second decode: should successfully parse the next line
    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(s) if s == "recovered"));
}

#[test]
fn utf8_error_during_multiline_accumulation_resets_state() {
    let mut c = codec();
    let mut enc_buf = BytesMut::new();
    c.encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    let mut buf = BytesMut::new();
    buf.extend_from_slice(b"line1\n");
    buf.extend_from_slice(&[0xFF, b'\n']);
    buf.extend_from_slice(b"SUCCESS: after reset\n");

    // decode() loops internally: processes "line1" (accumulates into
    // multi_line_buf), then hits invalid UTF-8 → error. The error handler
    // resets multi_line_buf, client_notification, and expected.
    let result = c.decode(&mut buf);
    assert!(result.is_err(), "should error on invalid UTF-8");

    // After error, multiline state is reset AND expected is SuccessOrError.
    // "SUCCESS: after reset" is self-describing, so it parses correctly.
    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(&msg, OvpnMessage::Success(s) if s == "after reset"));
}

#[test]
fn utf8_error_during_client_env_accumulation_resets_state() {
    let mut c = codec();
    let mut buf = BytesMut::new();

    // Start CLIENT notification
    buf.extend_from_slice(b">CLIENT:CONNECT,1,0\n");
    buf.extend_from_slice(b">CLIENT:ENV,name=alice\n");
    // Invalid UTF-8 in ENV line
    buf.extend_from_slice(b">CLIENT:ENV,");
    buf.extend_from_slice(&[0xFF, 0xFE]);
    buf.extend_from_slice(b"\n");
    // Valid notification after
    buf.extend_from_slice(b">BYTECOUNT:100,200\n");

    // First decode: starts CLIENT accumulation, parses ENV, hits invalid UTF-8 → error
    let result = c.decode(&mut buf);
    assert!(result.is_err());

    // After error, client_notificationstate should be reset.
    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(
        msg,
        OvpnMessage::Notification(Notification::ByteCount { .. })
    ));
}

#[test]
fn multiple_utf8_errors_then_recovery() {
    let mut c = codec();
    let mut buf = BytesMut::new();

    // Three invalid lines
    buf.extend_from_slice(&[0xFF, b'\n']);
    buf.extend_from_slice(&[0xFE, b'\n']);
    buf.extend_from_slice(&[0x80, b'\n']);
    // Then valid
    buf.extend_from_slice(b"SUCCESS: finally\n");

    for _ in 0..3 {
        assert!(c.decode(&mut buf).is_err());
    }

    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(s) if s == "finally"));
}

// ---  ---
// Accumulation limit error recovery
// ---  ---

#[test]
fn multiline_limit_error_leaves_multi_line_buf_active() {
    // After an accumulation limit error, the multi_line_buf is still Some
    // because the error is returned from within the accumulation loop.
    // The codec requires draining decode() before encoding a new command
    // (enforced by debug_assert). This test verifies we can still decode
    // self-describing messages (SUCCESS/ERROR/notifications) without
    // needing to encode a new command first.
    let mut c = OvpnCodec::new().with_max_multi_line_lines(AccumulationLimit::Max(2));

    let mut enc_buf = BytesMut::new();
    c.encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    let mut buf = BytesMut::from("line1\nline2\nline3\nEND\nSUCCESS: recovered\n");
    let result = c.decode(&mut buf);
    assert!(result.is_err());

    // Remaining buffer has "END\n" and "SUCCESS: recovered\n".
    // The decoder should be able to process self-describing lines.
    // Drain any remaining lines until we find the SUCCESS.
    let mut found_success = false;
    while !buf.is_empty() {
        match c.decode(&mut buf) {
            Ok(Some(OvpnMessage::Success(s))) if s == "recovered" => {
                found_success = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(found_success);
}

#[test]
fn client_env_limit_error_then_next_notification_works() {
    let mut c = OvpnCodec::new().with_max_client_env_entries(AccumulationLimit::Max(1));

    let mut buf = BytesMut::from(
        ">CLIENT:CONNECT,1,0\n\
         >CLIENT:ENV,key1=val1\n\
         >CLIENT:ENV,key2=val2\n\
         >CLIENT:ENV,END\n\
         >BYTECOUNT:100,200\n",
    );

    // First decode: starts CLIENT, accumulates one ENV, second ENV exceeds limit → error
    let result = c.decode(&mut buf);
    assert!(result.is_err());

    // Drain until we get the BYTECOUNT notification.
    let mut found_bytecount = false;
    while !buf.is_empty() {
        match c.decode(&mut buf) {
            Ok(Some(msg)) => {
                if matches!(
                    &msg,
                    OvpnMessage::Notification(Notification::ByteCount { .. })
                ) {
                    found_bytecount = true;
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(
        found_bytecount,
        "should eventually decode the BYTECOUNT notification"
    );
}

// ---  ---
// Unrecognized line recovery
// ---  ---

#[test]
fn unrecognized_line_does_not_break_subsequent_decoding() {
    let mut c = codec();
    let mut buf = BytesMut::from("this is garbage\nSUCCESS: pid=42\n");

    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Unrecognized { .. }));

    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(s) if s == "pid=42"));
}

#[test]
fn malformed_notification_does_not_break_subsequent_decoding() {
    let mut c = codec();
    let mut buf = BytesMut::from(">NO_COLON_HERE\n>BYTECOUNT:100,200\n");

    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Unrecognized { .. }));

    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(
        msg,
        OvpnMessage::Notification(Notification::ByteCount { .. })
    ));
}

#[test]
fn empty_line_does_not_break_subsequent_decoding() {
    let mut c = codec();
    let mut buf = BytesMut::from("\nSUCCESS: ok\n");

    // Empty lines are silently skipped — the decoder advances past them
    // and returns the next meaningful message.
    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

#[test]
fn error_response_does_not_break_subsequent_decoding() {
    let mut c = codec();
    let mut buf = BytesMut::from("ERROR: unknown command\nSUCCESS: ok\n");

    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Error(_)));

    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

// ---  ---
// Partial buffer recovery
// ---  ---

#[test]
fn partial_line_then_complete_line() {
    let mut c = codec();
    let mut buf = BytesMut::from("SUCCE");

    // Not enough data yet
    assert!(c.decode(&mut buf).unwrap().is_none());

    // Complete the line
    buf.extend_from_slice(b"SS: pid=42\n");

    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(s) if s == "pid=42"));
}

#[test]
fn partial_multiline_then_complete() {
    let mut c = codec();
    let mut enc_buf = BytesMut::new();
    c.encode(OvpnCommand::Version, &mut enc_buf).unwrap();

    let mut buf = BytesMut::from("OpenVPN 2.6.9\n");
    assert!(c.decode(&mut buf).unwrap().is_none()); // Accumulating

    buf.extend_from_slice(b"END\n");
    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::MultiLine(lines) if lines.len() == 1));
}

#[test]
fn partial_client_notification_then_complete() {
    let mut c = codec();
    let mut buf = BytesMut::from(">CLIENT:CONNECT,1,0\n");

    // Started accumulation — returns None (no complete message yet)
    assert!(c.decode(&mut buf).unwrap().is_none());

    buf.extend_from_slice(b">CLIENT:ENV,name=alice\n");
    assert!(c.decode(&mut buf).unwrap().is_none());

    buf.extend_from_slice(b">CLIENT:ENV,END\n");
    let msg = c.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(
        msg,
        OvpnMessage::Notification(Notification::Client { .. })
    ));
}

// ---  ---
// Stress: alternating errors and valid messages
// ---  ---

#[test]
fn alternating_utf8_errors_and_valid_messages() {
    let mut c = codec();
    let mut buf = BytesMut::new();

    for i in 0..10 {
        // Invalid
        buf.extend_from_slice(&[0xFF, b'\n']);
        // Valid
        buf.extend_from_slice(format!("SUCCESS: round={i}\n").as_bytes());
    }

    for i in 0..10 {
        // Error
        assert!(c.decode(&mut buf).is_err());
        // Success
        let msg = c.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(&msg, OvpnMessage::Success(s) if s == &format!("round={i}")));
    }
}
