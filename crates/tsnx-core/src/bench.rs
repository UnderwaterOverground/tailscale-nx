//! CPU-bound workloads for measuring crypto throughput on the target. The
//! caller times them with its own clock, so this stays free of I/O.

use crate::crypto;

/// Seals `iterations` packets of `buf.len()` bytes, as the WireGuard data path
/// would. Returns a value derived from the output so the work can't be elided.
pub fn aead_seal_loop(buf: &mut [u8], iterations: u32) -> u64 {
    let key = [0x42u8; 32];
    let mut acc = 0u64;
    for i in 0..iterations {
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&i.to_le_bytes());
        let tag = crypto::aead_seal(&key, &nonce, &[], buf);
        acc = acc.wrapping_add(u64::from(tag[0]));
    }
    acc
}

/// Runs `iterations` X25519 scalar multiplications (roughly one per handshake
/// message on each side).
pub fn x25519_loop(iterations: u32) -> u64 {
    let mut point = crypto::x25519_public(&[0x09u8; 32]);
    for _ in 0..iterations {
        point = crypto::x25519(&[0x5au8; 32], &point);
    }
    u64::from(point[0])
}

#[cfg(test)]
mod tests {
    #[test]
    fn loops_run() {
        let mut buf = [0u8; 1400];
        super::aead_seal_loop(&mut buf, 4);
        super::x25519_loop(2);
    }
}
