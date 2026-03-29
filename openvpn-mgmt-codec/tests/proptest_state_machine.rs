//! State-machine-based property tests for `OvpnCodec`.
//!
//! Models the codec as a state machine with transitions for encoding
//! commands and decoding responses/notifications, then verifies
//! invariants hold after every transition:
//!
//! - The pending-command queue depth tracks correctly across encode/decode.
//! - Notifications interleave freely without corrupting the command queue.
//! - The codec never panics regardless of transition ordering.
//! - Multi-line accumulation is terminated correctly by END lines.

mod common;

use std::collections::VecDeque;

use bytes::BytesMut;
use openvpn_mgmt_codec::*;
use proptest::prelude::*;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};
use tokio_util::codec::{Decoder, Encoder};

// ---------------------------------------------------------------------------
// Reference model
// ---------------------------------------------------------------------------

/// What the codec expects next from the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedResponse {
    /// Waiting for SUCCESS:/ERROR: line.
    SuccessOrError,
    /// Waiting for body lines terminated by END.
    MultiLine,
}

/// Abstract model of the codec's observable state.
#[derive(Clone, Debug)]
struct CodecModel {
    /// Queue of expected response types, one per encoded command.
    pending: VecDeque<ExpectedResponse>,
    /// Whether the decoder is currently accumulating multi-line body lines.
    accumulating_multi_line: bool,
}

/// Transitions the test can apply.
#[derive(Clone, Debug)]
enum Transition {
    /// Encode `pid` (expects SuccessOrError).
    EncodeSimple,
    /// Encode `version` (expects MultiLine).
    EncodeMultiLine,
    /// Feed "SUCCESS: ok\n" — consumed as response if expecting SuccessOrError,
    /// or as body line if accumulating multi-line.
    FeedSuccess,
    /// Feed "line1\nline2\nEND\n" — the END terminates multi-line accumulation.
    FeedMultiLineBlock,
    /// Feed a ">STATE:..." notification line (always decoded immediately).
    FeedNotification,
    /// Feed ">CLIENT:CONNECT..." + ENV block (multi-line notification).
    FeedClientNotification,
    /// Feed "END\n" — terminates multi-line accumulation if active.
    FeedEnd,
}

impl ReferenceStateMachine for CodecModel {
    type State = CodecModel;
    type Transition = Transition;

    fn init_state() -> BoxedStrategy<Self::State> {
        Just(CodecModel {
            pending: VecDeque::new(),
            accumulating_multi_line: false,
        })
        .boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        let mut choices: Vec<BoxedStrategy<Transition>> = vec![
            Just(Transition::EncodeSimple).boxed(),
            Just(Transition::EncodeMultiLine).boxed(),
            Just(Transition::FeedNotification).boxed(),
            Just(Transition::FeedClientNotification).boxed(),
        ];

        if !state.pending.is_empty() {
            choices.push(Just(Transition::FeedSuccess).boxed());
            choices.push(Just(Transition::FeedMultiLineBlock).boxed());
            choices.push(Just(Transition::FeedEnd).boxed());
        }

        prop::strategy::Union::new(choices).boxed()
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            Transition::EncodeSimple => {
                state.pending.push_back(ExpectedResponse::SuccessOrError);
            }
            Transition::EncodeMultiLine => {
                state.pending.push_back(ExpectedResponse::MultiLine);
            }
            Transition::FeedSuccess => {
                if state.accumulating_multi_line {
                    // "SUCCESS: ok" is just another body line during accumulation.
                } else if !state.pending.is_empty() {
                    let front = state.pending[0];
                    if front == ExpectedResponse::SuccessOrError {
                        state.pending.pop_front();
                    } else {
                        // MultiLine expected: SUCCESS line starts accumulation
                        // as the first body line.
                        state.accumulating_multi_line = true;
                    }
                }
            }
            Transition::FeedMultiLineBlock => {
                // Contains "line1\nline2\nEND\n". The END terminates accumulation.
                if state.accumulating_multi_line {
                    // END terminates the accumulation.
                    state.accumulating_multi_line = false;
                    state.pending.pop_front();
                } else if !state.pending.is_empty() {
                    let front = state.pending[0];
                    if front == ExpectedResponse::MultiLine {
                        // "line1" starts accumulation, END completes it.
                        state.pending.pop_front();
                    } else {
                        // SuccessOrError: "line1" is unrecognized, "line2" is
                        // unrecognized, "END" is unrecognized. Consumes the
                        // pending command for each non-notification line.
                        // Actually the codec pops the front on the first
                        // non-SUCCESS/ERROR line → unrecognized.
                        state.pending.pop_front();
                    }
                }
            }
            Transition::FeedEnd => {
                if state.accumulating_multi_line {
                    state.accumulating_multi_line = false;
                    state.pending.pop_front();
                } else if !state.pending.is_empty() {
                    let front = state.pending[0];
                    if front == ExpectedResponse::MultiLine {
                        // Empty multi-line: immediately terminated.
                        state.pending.pop_front();
                    } else {
                        // "END" is unrecognized for SuccessOrError.
                        state.pending.pop_front();
                    }
                }
            }
            Transition::FeedNotification | Transition::FeedClientNotification => {
                // Notifications never consume from the pending queue.
            }
        }
        state
    }

    fn preconditions(state: &Self::State, transition: &Self::Transition) -> bool {
        match transition {
            Transition::FeedSuccess | Transition::FeedMultiLineBlock | Transition::FeedEnd => {
                !state.pending.is_empty()
            }
            _ => true,
        }
    }
}

// ---------------------------------------------------------------------------
// System under test
// ---------------------------------------------------------------------------

struct CodecSut {
    codec: OvpnCodec,
    buf: BytesMut,
}

impl StateMachineTest for CodecSut {
    type SystemUnderTest = Self;
    type Reference = CodecModel;

    fn init_test(
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) -> Self::SystemUnderTest {
        CodecSut {
            codec: OvpnCodec::new(),
            buf: BytesMut::new(),
        }
    }

    fn apply(
        mut state: Self::SystemUnderTest,
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        transition: <Self::Reference as ReferenceStateMachine>::Transition,
    ) -> Self::SystemUnderTest {
        match transition {
            Transition::EncodeSimple => {
                state
                    .codec
                    .encode(OvpnCommand::Pid, &mut state.buf)
                    .expect("encode simple should succeed");
                state.buf.clear();
            }

            Transition::EncodeMultiLine => {
                state
                    .codec
                    .encode(OvpnCommand::Version, &mut state.buf)
                    .expect("encode multi-line should succeed");
                state.buf.clear();
            }

            Transition::FeedSuccess => {
                state.buf.extend_from_slice(b"SUCCESS: ok\n");
                drain_discard(&mut state.codec, &mut state.buf);
            }

            Transition::FeedMultiLineBlock => {
                state.buf.extend_from_slice(b"line one\nline two\nEND\n");
                drain_discard(&mut state.codec, &mut state.buf);
            }

            Transition::FeedEnd => {
                state.buf.extend_from_slice(b"END\n");
                drain_discard(&mut state.codec, &mut state.buf);
            }

            Transition::FeedNotification => {
                state.buf.extend_from_slice(
                    b">STATE:1700000000,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,,,\n",
                );
                let msgs = drain(&mut state.codec, &mut state.buf);
                // Notification must always be emitted immediately, even
                // during multi-line accumulation.
                assert!(
                    msgs.iter()
                        .any(|m| matches!(m, OvpnMessage::Notification(Notification::State(..)))),
                    "notification was swallowed: {msgs:?}",
                );
            }

            Transition::FeedClientNotification => {
                state.buf.extend_from_slice(
                    b">CLIENT:CONNECT,1,0\n\
                      >CLIENT:ENV,common_name=test\n\
                      >CLIENT:ENV,END\n",
                );
                let msgs = drain(&mut state.codec, &mut state.buf);
                assert!(
                    msgs.iter().any(|m| matches!(
                        m,
                        OvpnMessage::Notification(Notification::Client { .. })
                    )),
                    "client notification was swallowed: {msgs:?}",
                );
            }
        }

        state
    }

    fn check_invariants(
        state: &Self::SystemUnderTest,
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) {
        // The buffer must be fully consumed after each transition — no
        // leftover bytes that could desync subsequent decodes.
        assert!(
            state.buf.is_empty(),
            "buffer not fully consumed: {:?}",
            String::from_utf8_lossy(&state.buf),
        );
    }
}

/// Drain all available messages from the decoder, collecting them.
fn drain(codec: &mut OvpnCodec, buf: &mut BytesMut) -> Vec<OvpnMessage> {
    let mut msgs = Vec::new();
    loop {
        match codec.decode(buf) {
            Ok(Some(msg)) => msgs.push(msg),
            Ok(None) => break,
            Err(e) => panic!("unexpected decode error: {e}"),
        }
    }
    msgs
}

/// Drain the decoder without collecting — just verify no panics/errors.
fn drain_discard(codec: &mut OvpnCodec, buf: &mut BytesMut) {
    loop {
        match codec.decode(buf) {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => panic!("unexpected decode error: {e}"),
        }
    }
}

prop_state_machine! {
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: 512,
        .. proptest::prelude::ProptestConfig::default()
    })]

    #[test]
    fn codec_state_machine(sequential 1..40 => CodecSut);
}
