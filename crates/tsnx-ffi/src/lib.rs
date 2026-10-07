//! C ABI over tsnx-core. See `include/tsnx.h` for the C side of this contract.
#![cfg_attr(target_os = "horizon", no_std)]

extern crate alloc;

#[cfg(target_os = "horizon")]
mod platform;

use core::ffi::c_char;

static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
pub extern "C" fn tsnx_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// Runs the crypto known-answer tests. Returns 0 on success, otherwise the
/// failing test's code (see `tsnx_selftest_failure` in the header).
#[no_mangle]
pub extern "C" fn tsnx_selftest() -> u32 {
    match tsnx_core::selftest::run() {
        Ok(()) => 0,
        Err(f) => f as u32,
    }
}

/// Seals `iterations` packets of `packet_len` bytes with ChaCha20-Poly1305.
#[no_mangle]
pub extern "C" fn tsnx_bench_aead(packet_len: usize, iterations: u32) -> u64 {
    let mut buf = alloc::vec![0u8; packet_len];
    tsnx_core::bench::aead_seal_loop(&mut buf, iterations)
}

/// Runs `iterations` X25519 scalar multiplications.
#[no_mangle]
pub extern "C" fn tsnx_bench_x25519(iterations: u32) -> u64 {
    tsnx_core::bench::x25519_loop(iterations)
}

/// Seeds the core's CSPRNG. Must be called before any key or TLS use.
#[no_mangle]
pub unsafe extern "C" fn tsnx_seed_rng(seed: *const u8) {
    let seed = &*(seed as *const [u8; 32]);
    tsnx_core::rng::seed(seed);
}

/// Sets wall-clock time (seconds since the Unix epoch) for certificate checks.
#[no_mangle]
pub extern "C" fn tsnx_set_unix_time(unix_secs: u64) {
    tsnx_core::tls::CLOCK.set(unix_secs);
}

mod engine_ffi;
mod logging;
mod tls_ffi;
pub use engine_ffi::*;
pub use logging::*;
pub use tls_ffi::*;

/// Rust heap accounting shared by the Horizon and host allocators: live
/// bytes, the high-water mark, and live bytes/allocations by size class (to
/// tell which kind of object holds memory).
pub(crate) mod heap_count {
    use core::sync::atomic::{AtomicUsize, Ordering};
    /// Upper bounds of the size classes; the last class is everything bigger.
    pub const CLASS_LIMITS: [usize; 7] = [64, 256, 1024, 2048, 4096, 16384, 65536];
    pub const CLASSES: usize = CLASS_LIMITS.len() + 1;
    pub static IN_USE: AtomicUsize = AtomicUsize::new(0);
    pub static PEAK: AtomicUsize = AtomicUsize::new(0);
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicUsize = AtomicUsize::new(0);
    pub static CLASS_BYTES: [AtomicUsize; CLASSES] = [ZERO; CLASSES];
    pub static CLASS_COUNT: [AtomicUsize; CLASSES] = [ZERO; CLASSES];

    fn class(n: usize) -> usize {
        CLASS_LIMITS.iter().position(|&l| n <= l).unwrap_or(CLASS_LIMITS.len())
    }
    pub fn alloc(n: usize) {
        let now = IN_USE.fetch_add(n, Ordering::Relaxed) + n;
        PEAK.fetch_max(now, Ordering::Relaxed);
        let c = class(n);
        CLASS_BYTES[c].fetch_add(n, Ordering::Relaxed);
        CLASS_COUNT[c].fetch_add(1, Ordering::Relaxed);
    }
    pub fn free(n: usize) {
        IN_USE.fetch_sub(n, Ordering::Relaxed);
        let c = class(n);
        CLASS_BYTES[c].fetch_sub(n, Ordering::Relaxed);
        CLASS_COUNT[c].fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counts Rust heap usage on hosts too, so memory behaviour seen on the
/// console can be reproduced in the Linux tests.
#[cfg(not(target_os = "horizon"))]
mod host_heap {
    use std::alloc::{GlobalAlloc, Layout, System};
    pub struct Counting;
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let p = System.alloc(l);
            if !p.is_null() {
                super::heap_count::alloc(l.size());
            }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            super::heap_count::free(l.size());
            System.dealloc(p, l)
        }
    }
    #[global_allocator]
    static ALLOC: Counting = Counting;
}

/// Rust heap usage in bytes (current, peak).
#[no_mangle]
pub unsafe extern "C" fn tsnx_heap_stats(current: *mut usize, peak: *mut usize) {
    use core::sync::atomic::Ordering::Relaxed;
    *current = heap_count::IN_USE.load(Relaxed);
    *peak = heap_count::PEAK.load(Relaxed);
}

/// Formats live Rust heap by allocation size class into `buf` (NUL-terminated,
/// e.g. "<=64:12K/310 <=256:..."). Returns the length written.
#[no_mangle]
pub unsafe extern "C" fn tsnx_heap_classes(buf: *mut u8, len: usize) -> usize {
    use core::fmt::Write;
    use core::sync::atomic::Ordering::Relaxed;
    if buf.is_null() || len == 0 {
        return 0;
    }
    struct Out<'a>(&'a mut [u8], usize);
    impl Write for Out<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.0.len().saturating_sub(self.1 + 1));
            self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
            self.1 += n;
            Ok(())
        }
    }
    let mut out = Out(core::slice::from_raw_parts_mut(buf, len), 0);
    for c in 0..heap_count::CLASSES {
        let (bytes, count) = (heap_count::CLASS_BYTES[c].load(Relaxed), heap_count::CLASS_COUNT[c].load(Relaxed));
        let sep = if c == 0 { "" } else { " " };
        let _ = match heap_count::CLASS_LIMITS.get(c) {
            Some(&l) if l < 1024 => write!(out, "{sep}<={l}:{}K/{count}", bytes / 1024),
            Some(&l) => write!(out, "{sep}<={}K:{}K/{count}", l / 1024, bytes / 1024),
            None => write!(out, "{sep}>64K:{}K/{count}", bytes / 1024),
        };
    }
    let n = out.1;
    out.0[n] = 0;
    n
}
