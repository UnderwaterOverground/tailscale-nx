//! Sans-IO Tailscale engine core.
//!
//! This crate never performs I/O, reads clocks, or spawns threads. Drivers
//! (the host binary, the Switch app, the sysmodule) feed it bytes and time and
//! drain the work it wants done. That keeps every protocol path testable with
//! plain `cargo test` on the development machine.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// Gives back a buffer's spare capacity. Buffers that grew for a burst (a
/// full netmap, a backlog of TLS records) otherwise keep that size for the
/// connection's lifetime; on the Switch every such byte is sysmodule heap.
/// Called periodically ([`engine::Engine::handle_timeout`]), not per read, so
/// a busy stream doesn't reallocate on every packet.
pub(crate) fn trim_vec<T>(v: &mut alloc::vec::Vec<T>) {
    if v.capacity() > v.len() + 256 {
        v.shrink_to(v.len());
    }
}

pub mod bench;
pub mod control;
pub mod crypto;
pub mod derp;
pub mod disco;
pub mod engine;
pub mod http2;
pub mod netstack;
pub mod rng;
pub mod selftest;
pub mod stream;
pub mod stun;
pub mod time;
pub mod tls;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
