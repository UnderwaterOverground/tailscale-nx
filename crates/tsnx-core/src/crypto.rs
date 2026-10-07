//! Thin wrappers over the RustCrypto primitives used by WireGuard, DERP and
//! disco. Keeping them in one place makes it easy to swap a backend (e.g. for
//! a NEON-tuned implementation) without touching protocol code.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

/// Encrypts `buf` in place and returns the detached Poly1305 tag.
pub fn aead_seal(key: &[u8; KEY_LEN], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; TAG_LEN] {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buf)
        .expect("buffer length within ChaCha20Poly1305 limits");
    tag.into()
}

/// Decrypts `buf` in place, verifying `tag`. On failure `buf` is unspecified.
pub fn aead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, buf, Tag::from_slice(tag))
        .map_err(|_| AeadError)
}

/// X25519 scalar multiplication (RFC 7748).
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*scalar, *point)
}

/// Derives the X25519 public key for a private scalar.
pub fn x25519_public(scalar: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*scalar, x25519_dalek::X25519_BASEPOINT_BYTES)
}

pub fn blake2s256(data: &[u8]) -> [u8; 32] {
    Blake2s256::digest(data).into()
}
