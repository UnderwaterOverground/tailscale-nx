//! Known-answer tests that can run on the target itself. The Switch app calls
//! these at startup so a miscompiled or mislinked crypto backend is caught on
//! the device, not as a mysterious handshake failure later.

use crate::crypto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Failure {
    X25519 = 1,
    AeadSeal = 2,
    AeadOpen = 3,
    AeadTamper = 4,
    Blake2s = 5,
}

const X25519_SCALAR: [u8; 32] = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
const X25519_POINT: [u8; 32] = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
const X25519_OUT: [u8; 32] = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

// RFC 8439 section 2.8.2.
const AEAD_KEY: [u8; 32] = hex32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
const AEAD_NONCE: [u8; 12] = [0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
const AEAD_AAD: [u8; 12] = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
const AEAD_PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const AEAD_TAG: [u8; 16] = [
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
];

const BLAKE2S_ABC: [u8; 32] = hex32("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");

/// Runs every known-answer test, returning the first failure.
pub fn run() -> Result<(), Failure> {
    if crypto::x25519(&X25519_SCALAR, &X25519_POINT) != X25519_OUT {
        return Err(Failure::X25519);
    }

    let mut buf = [0u8; 114];
    buf.copy_from_slice(AEAD_PLAINTEXT);
    let tag = crypto::aead_seal(&AEAD_KEY, &AEAD_NONCE, &AEAD_AAD, &mut buf);
    if tag != AEAD_TAG {
        return Err(Failure::AeadSeal);
    }
    let sealed = buf;
    if crypto::aead_open(&AEAD_KEY, &AEAD_NONCE, &AEAD_AAD, &mut buf, &tag).is_err() || buf[..] != *AEAD_PLAINTEXT {
        return Err(Failure::AeadOpen);
    }
    let mut tampered = sealed;
    tampered[0] ^= 1;
    if crypto::aead_open(&AEAD_KEY, &AEAD_NONCE, &AEAD_AAD, &mut tampered, &tag).is_ok() {
        return Err(Failure::AeadTamper);
    }

    if crypto::blake2s256(b"abc") != BLAKE2S_ABC {
        return Err(Failure::Blake2s);
    }
    Ok(())
}

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("invalid hex"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_answers_pass() {
        assert_eq!(super::run(), Ok(()));
    }
}
