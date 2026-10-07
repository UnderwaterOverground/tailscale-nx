//! Process-wide CSPRNG.
//!
//! The core has no entropy source of its own: the driver seeds it once at
//! startup (getrandom on the host, `csrngGetRandomBytes` on Horizon) and may mix
//! in more later. Everything that needs randomness (key generation, TLS, disco
//! transaction IDs) draws from here.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use spin::Mutex;

static RNG: Mutex<Option<ChaCha20Rng>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotSeeded;

/// Seeds (or reseeds) the generator. A reseed mixes the new material with
/// output of the current state, so a weak later seed can't reduce strength.
pub fn seed(seed: &[u8; 32]) {
    let mut guard = RNG.lock();
    let mut material = *seed;
    if let Some(rng) = guard.as_mut() {
        let mut current = [0u8; 32];
        rng.fill_bytes(&mut current);
        for (m, c) in material.iter_mut().zip(current) {
            *m ^= c;
        }
    }
    *guard = Some(ChaCha20Rng::from_seed(material));
    drop(guard);
    // The vendored tailscale-rs crates draw from the same generator.
    ts_util::rng::set_fill_fn(|buf| fill(buf).expect("seeded above"));
}

pub fn is_seeded() -> bool {
    RNG.lock().is_some()
}

pub fn fill(buf: &mut [u8]) -> Result<(), NotSeeded> {
    match RNG.lock().as_mut() {
        Some(rng) => {
            rng.fill_bytes(buf);
            Ok(())
        }
        None => Err(NotSeeded),
    }
}

/// Returns 32 random bytes, for key generation.
pub fn bytes32() -> Result<[u8; 32], NotSeeded> {
    let mut out = [0u8; 32];
    fill(&mut out)?;
    Ok(out)
}

/// Seeds from the OS on hosts with std, for tests and the host driver.
#[cfg(feature = "std")]
pub fn seed_from_os() {
    extern crate std;
    use std::io::Read;
    let mut seed_bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed_bytes))
        .expect("reading /dev/urandom");
    seed(&seed_bytes);
}

#[cfg(test)]
mod tests {
    #[test]
    fn reseed_changes_stream() {
        super::seed(&[1; 32]);
        let a = super::bytes32().unwrap();
        super::seed(&[1; 32]);
        let b = super::bytes32().unwrap();
        assert_ne!(a, b, "reseeding with the same seed must still mix in prior state");
    }
}
