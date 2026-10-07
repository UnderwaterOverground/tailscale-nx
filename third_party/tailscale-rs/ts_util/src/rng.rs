//! tsnx: injected randomness source for the vendored tailscale-rs crates.
//!
//! Upstream tailscale-rs draws randomness from `rand::random` / `getrandom` (via
//! `x25519_dalek::StaticSecret::random`). Neither exists on the `no_std` Nintendo Switch build, so
//! every vendored crate instead calls [`fill`], which forwards to a function pointer that the
//! embedding application registers once at startup with [`set_fill_fn`].
//!
//! The registered function **must** be a cryptographically secure RNG: it is used to generate
//! private keys, Noise ephemeral keys and WireGuard session IDs.
//!
//! ```ignore
//! // e.g. in tsnx-core, after seeding its CSPRNG:
//! ts_util::rng::set_fill_fn(|buf| tsnx_core::rng::fill(buf).expect("rng not seeded"));
//! ```
//!
//! Calling [`fill`] before a function is registered panics (unless the `insecure-test-rng`
//! feature is enabled, which is only meant for host unit tests).

use core::sync::atomic::{AtomicPtr, Ordering};

/// Signature of an RNG fill function: fill the whole buffer with random bytes.
pub type FillFn = fn(&mut [u8]);

static FILL: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the process-wide random byte source. May be called again to replace it.
pub fn set_fill_fn(f: FillFn) {
    FILL.store(f as *mut (), Ordering::Release);
}

/// Report whether a random byte source has been registered with [`set_fill_fn`].
pub fn is_set() -> bool {
    !FILL.load(Ordering::Acquire).is_null()
}

/// Fill `buf` with random bytes from the registered source.
///
/// # Panics
///
/// If no source was registered with [`set_fill_fn`] (and the `insecure-test-rng` feature is off).
pub fn fill(buf: &mut [u8]) {
    let p = FILL.load(Ordering::Acquire);
    if p.is_null() {
        #[cfg(feature = "insecure-test-rng")]
        {
            insecure_test_fill(buf);
            return;
        }
        #[cfg(not(feature = "insecure-test-rng"))]
        panic!("ts_util::rng: no RNG registered, call ts_util::rng::set_fill_fn first");
    }
    // SAFETY: the only non-null values ever stored in FILL are `FillFn` pointers cast to
    // `*mut ()` by `set_fill_fn`; function and data pointers have the same size on all supported
    // targets.
    let f = unsafe { core::mem::transmute::<*mut (), FillFn>(p) };
    f(buf)
}

/// Return an array of `N` random bytes.
pub fn array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill(&mut out);
    out
}

/// Return a random `u32`.
pub fn u32() -> u32 {
    u32::from_ne_bytes(array())
}

/// Return a random `u64`.
pub fn u64() -> u64 {
    u64::from_ne_bytes(array())
}

/// SplitMix64 over a global counter. NOT cryptographically secure; host tests only.
#[cfg(feature = "insecure-test-rng")]
fn insecure_test_fill(buf: &mut [u8]) {
    use core::sync::atomic::AtomicU64;

    static STATE: AtomicU64 = AtomicU64::new(0x853c_49e6_748f_ea9b);
    for chunk in buf.chunks_mut(8) {
        let mut z = STATE
            .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
            .wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_fn_is_used() {
        set_fill_fn(|buf| buf.fill(0xAB));
        assert!(is_set());
        assert_eq!(array::<4>(), [0xAB; 4]);
        assert_eq!(u32(), 0xABAB_ABAB);
    }
}
