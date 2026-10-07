# Vendored tailscale-rs

- Upstream: https://github.com/tailscale/tailscale-rs
- Commit: `f4781c480e8d1376aed89f737beefe7425e8b866` ("netcore: bump to smoltcp 0.14, congestion ctrl on"), version 0.6.1
- License: BSD-3-Clause, see `LICENSE` and `PATENTS` in this directory (copied unmodified from upstream).
  All vendored crates keep their upstream `license = "BSD-3-Clause"` metadata and README files.

This directory is a standalone Cargo workspace, excluded from the tailscale-nx root workspace. The crates
were ported to `#![no_std]` + `alloc` so they build for `aarch64-nintendo-switch-freestanding`
(no OS clock, no OS RNG, no std). Every non-trivial source change is marked with a `// tsnx:` comment;
`grep -rn "tsnx:" .` lists them.

## Crates taken

| Crate | Purpose |
|---|---|
| `ts_keys` | Typed X25519 keys (machine, node, disco, network-lock, DERP, challenge) |
| `ts_packet` | `Packet` / `PacketMut` buffers |
| `ts_util` | `fmt` and `fn_` helpers, plus the new `rng` hook (the `futures` module was dropped) |
| `ts_control_serde` | Control-plane JSON types (`MapRequest`, `MapResponse`, `RegisterRequest`, `DerpMap`, `Node`, ...) |
| `ts_capabilityversion`, `ts_nodecapability`, `ts_packetfilter_serde`, `ts_peercapability` | Dependencies of `ts_control_serde` |
| `ts_disco_protocol` | Disco message encoding/decoding and NaCl-box encryption |
| `ts_noise` | Noise IK (control) and IKpsk2 (WireGuard) handshakes |
| `ts_tunnel` | Sans-IO WireGuard endpoint |
| `ts_time` | Event scheduler used by `ts_tunnel`, now also the `no_std` `Instant` type |

Not vendored (tokio/hyper/OS based): `ts_control`, `ts_control_noise`, `ts_derp`, `ts_runtime`, `ts_netcheck`,
`ts_http_util`, `ts_tls_util`, `ts_dataplane`, `ts_netstack_smoltcp` and the rest of the upstream workspace.
`ts_tunnel/examples/` (tokio/clap) was not vendored either.

## Workspace-level changes

- New `Cargo.toml` with only the vendored crates. Every `[workspace.dependencies]` entry uses
  `default-features = false` with no `std` features. Notable selections:
  - `x25519-dalek` 3.0.0-pre.6 **without** `getrandom` (features: `reusable_secrets`, `static_secrets`, `zeroize`).
  - `crypto_box` with `alloc,salsa20` only (no `getrandom`/`std`); `chacha20poly1305` with `alloc` only;
    `aead`, `hkdf` without `std`; `zeroize` with `alloc,zeroize_derive`.
  - `serde`/`serde_json`/`serde_with`/`base64`/`nom`/`chrono`/`yoke`/`stable_deref_trait` with `alloc` only.
  - `url`, `ipnet`, `bytes`, `heapless`, `num-traits`, `thiserror`, `zerocopy` without default features.
  - New dependencies: `hashbrown` 0.17 (replaces `std::collections::HashMap`), `spin` 0.9 (replaces `std::sync::Mutex`).
- Removed workspace lints that only apply to the full upstream workspace (`clippy::cargo`,
  `closure_returning_async_block`); `let-underscore` renamed to `let_underscore`.
- `publish = false`; `[profile.release]` uses `panic = "abort"` (Switch target).
- `Cargo.lock` started from upstream's lockfile, so dependency versions match upstream where possible.
- Dev-dependencies (host tests only) enable std features where tests need them (`serde_json/std`,
  `nom/std`, `zerocopy/std`) and `ts_util/insecure-test-rng`. With resolver 2+, these do not affect
  normal or Switch builds.

## Injected time, wall clock and randomness

- **Monotonic time**: `ts_time::Instant` is a newtype over `u64` nanoseconds since an arbitrary
  driver-chosen epoch, built with `Instant::from_nanos(u64)` (or `from_millis` / `from_duration`).
  It supports `core::time::Duration` arithmetic (`+`, `-`, `checked_add/sub`, `duration_since`, ...).
  `ts_time::Duration` re-exports `core::time::Duration`. Every API that upstream gave a
  `std::time::Instant` now takes `ts_time::Instant`; nothing reads a clock.
- **Wall clock** (WireGuard TAI64N handshake timestamps): `ts_tunnel::Endpoint::set_wall_clock(now: Instant,
  unix_time: Duration)` anchors the monotonic clock to Unix time. Later timestamps are extrapolated from
  `now`. Until it is set, the monotonic epoch is treated as the Unix epoch.
- **Randomness**: `ts_util::rng::set_fill_fn(fn(&mut [u8]))` registers a process-wide CSPRNG once at startup
  (a global `AtomicPtr` holding a function pointer). `ts_util::rng::{fill, array, u32, u64}` call it. It
  panics if nothing was registered. The `insecure-test-rng` feature falls back to a
  non-cryptographic SplitMix64 and is only enabled from dev-dependencies. A function hook was chosen
  instead of passing a `rand_core` RNG because it leaves upstream signatures such as `NodeKeyPair::random()`,
  `X25519KeyPair::random()`, `ik::SentHandshake::new` and `Endpoint::send` unchanged.

## Per-crate modifications

### ts_util
- Removed the tokio/futures-based `futures` module (`debounce`) and the `tokio`, `futures`,
  `pin-project-lite` and `futures-core` dependencies. The default features are now empty (they were `["tokio"]`).
- `fn_sync*` helpers are also compiled under `cfg(test)`, since `std` is no longer a default feature.
- New module `rng` (the injected RNG hook, see above) and feature `insecure-test-rng`.

### ts_keys
- `util::random_x25519_private/public` and `X25519KeyPair::random` build `StaticSecret::from(ts_util::rng::array())`
  instead of calling `StaticSecret::random()` (getrandom).
- Added `from_bytes([u8; 32])` to every private key type (`MachinePrivateKey`, `NodePrivateKey`,
  `DiscoPrivateKey`, `NetworkLockPrivateKey`), so callers can construct keys from their own random bytes or
  from storage.
- New dependency on `ts_util`.

### ts_noise
- Added `#![no_std]`, `extern crate alloc`, and `extern crate std` under `cfg(test)`. `std::marker::PhantomData` is now `core::marker::PhantomData`.
- `itertools` moved to dev-dependencies (only tests use it).

### ts_time
- `#![no_std]`. Replaced `pub use std::time::{Duration, Instant}` with `core::time::Duration` and the new
  `instant::Instant` (driver-supplied monotonic nanoseconds).
- `std::sync::{Arc, Weak, Mutex}` are now `alloc::sync::{Arc, Weak}` + `spin::Mutex`, so `.lock().unwrap()` became `.lock()`.
- Tests use fixed `Instant::from_nanos(..)` datums instead of `Instant::now()`. Added `Instant` arithmetic tests.

### ts_tunnel
- `#![no_std]` + `alloc`. Uses `alloc::{vec::Vec, boxed::Box, collections::VecDeque, sync}`, `core::*`,
  `hashbrown::HashMap` for `std::collections::HashMap`, and `spin::Mutex` for `std::sync::Mutex` (`ids.rs`, `session.rs`).
- `std::time::Instant` is now `ts_time::Instant`. `macs::MACSender::{write_macs, receive_cookie}` and
  `Handshake::cookie_reply` take an extra `now: Instant` instead of calling `Instant::now()` (cookie expiry).
- `time.rs`: `TAI64N::now()` (SystemTime) became `TAI64N::from_unix(Duration)`. `TAI64NClock` gained
  `set_wall_clock(now, unix_time)`, and `TAI64NClock::now(now: Instant)` takes the monotonic time.
  `From<SystemTime>` is kept for tests only. Added test `tai64n_clock_wall_anchor`.
- New public API: `Endpoint::set_wall_clock(now: Instant, unix_time: Duration)`.
- `SessionId::random()` uses `ts_util::rng::u32()`. Tests use `ts_util::rng::array()` instead of `rand::random()`.
- `Endpoint::recv` groups packets by receiver ID with a `hashbrown::HashMap` loop instead of
  `itertools::into_group_map_by` (which needs `itertools/use_std`). `itertools` and `rand` dependencies removed.
- `tracing` is now optional (`tracing` feature, off by default). With it off, `extern crate self as tracing`
  plus `src/tracing_shim.rs` turn `tracing::{trace,debug,info,warn,error,trace_span}!` into no-ops,
  so log call sites match upstream. `#[tracing::instrument]` became
  `#[cfg_attr(feature = "tracing", tracing::instrument(..))]`. `unused_variables` is allowed when the feature is off.
- `examples/` removed (tokio/clap). Dev-dependencies reduced to `proptest` and `ts_util/insecure-test-rng`.

### ts_control_serde
- `serde_with::DurationSeconds<f64>` is now `DurationSecondsWithFrac<f64>` (`Debug::sleep_seconds`,
  `ControlIpCandidate::{dial_start_delay_sec, dial_timeout_sec}`), because the rounding impl of the former requires
  `serde_with/std`. Fractional seconds are now kept instead of being rounded. These types are only deserialized.
- `serde_repr` now comes from the workspace. Added `serde_json/std` as a dev-dependency for the integration tests.

### ts_capabilityversion
- Added `#![no_std]`, `extern crate alloc`, and `extern crate std` under `cfg(test)`.

### ts_packet, ts_packetfilter_serde, ts_disco_protocol
- Manifest only: `stable_deref_trait`, `nom`, `num-traits` and `num-derive` now come from the workspace
  (no default features). Test-only `nom/std` (packetfilter) and `ts_util/insecure-test-rng` (disco) were added as dev-dependencies.
- Like upstream, `ts_disco_protocol` only enables `extern crate alloc` with its `alloc` feature (on by default).

### ts_nodecapability, ts_peercapability
- Unmodified (already `no_std`).

## Re-syncing with upstream

1. Check out the new upstream commit next to this tree.
2. For each crate, `diff -ru <upstream>/<crate> <crate>`. Every intentional difference is listed above and
   marked `tsnx:` in the source. Re-apply them to the new upstream files.
3. Run `cargo test --workspace` here, then the Switch build from the project root:
   `docker run --rm -v "$PWD":/src -v tsnx-cargo-registry:/opt/cargo/registry -e CARGO_TARGET_DIR=/src/target/switch-vendor -w /src/third_party/tailscale-rs tsnx-build cargo build --release --target aarch64-nintendo-switch-freestanding -Zbuild-std=core,alloc --workspace`
4. Update the commit hash at the top of this file.

## Later changes (by the tsnx engine work)

- `ts_control_serde`: re-export `derp_map::StunPort` as `DerpStunPort` (needed to locate STUN servers).
- ts_keys: gated serde-only helpers (ToString import, to_hex_string) on the serde feature (tsnx no longer enables it).
