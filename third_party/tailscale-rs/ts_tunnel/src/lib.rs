#![doc = include_str!("../README.md")]
// tsnx: no_std port. See VENDORED.md for the list of changes. In short: time is driver-supplied
// (`ts_time::Instant`), wall-clock time for TAI64N handshake timestamps is set with
// `Endpoint::set_wall_clock`, randomness comes from `ts_util::rng`, and tracing is an optional
// feature (off by default).
#![no_std]
// tsnx: with the `tracing` feature off, some variables only feed (now no-op) log macros.
#![cfg_attr(not(feature = "tracing"), allow(unused_variables))]

extern crate alloc;
#[cfg(test)]
extern crate std;

// tsnx: when the `tracing` feature is off, `tracing::foo!(...)` resolves to the no-op macros in
// `tracing_shim` via this self-alias, so call sites stay identical to upstream.
#[cfg(not(feature = "tracing"))]
extern crate self as tracing;
#[cfg(not(feature = "tracing"))]
mod tracing_shim;
#[cfg(not(feature = "tracing"))]
#[allow(unused_imports)]
pub(crate) use tracing_shim::{debug, error, info, trace, trace_span, warn};

mod config;
mod endpoint;
mod handshake;
mod ids;
mod macs;
mod messages;
mod queue;
mod replay;
mod session;
mod time;

pub use ts_keys::{NodeKeyPair, NodePrivateKey, NodePublicKey};

pub use crate::{
    config::{PeerConfig, PeerId, Psk},
    endpoint::{Endpoint, Event, EventResult, RecvResult, SendResult},
};
