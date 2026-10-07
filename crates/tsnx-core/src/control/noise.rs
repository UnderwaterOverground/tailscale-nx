//! The ts2021 control channel: Noise_IK_25519_ChaChaPoly_BLAKE2s with
//! Tailscale's framing (tailscale/control/controlbase).
//!
//! Wire format:
//! - initiation (client -> server): `version:u16be | type=1 | len:u16be | e(32) | enc(s)(48) | tag(16)`
//! - response   (server -> client): `type=2 | len:u16be | e(32) | tag(16)`
//! - error:  `type=3 | len:u16be | utf8 message` (unauthenticated)
//! - record: `type=4 | len:u16be | ciphertext` (nonce: 4 zero bytes | counter:u64be)

use alloc::string::String;
use alloc::vec::Vec;

use blake2::{Blake2s256, Digest};
use hmac::{Mac, SimpleHmac};

use crate::crypto;

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_PREFIX: &str = "Tailscale Control Protocol v";

const MSG_INITIATION: u8 = 1;
const MSG_RESPONSE: u8 = 2;
const MSG_ERROR: u8 = 3;
const MSG_RECORD: u8 = 4;

pub const INITIATION_LEN: usize = 101;
const RESPONSE_LEN: usize = 51;
const HEADER_LEN: usize = 3;
/// Largest frame on the wire, header included.
const MAX_MESSAGE: usize = 4096;
pub const MAX_PLAINTEXT: usize = MAX_MESSAGE - HEADER_LEN - crypto::TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseError {
    /// The server sent an (unauthenticated) error message.
    Server(String),
    UnexpectedMessage(u8),
    BadLength,
    Decrypt,
    LowOrderPoint,
    NonceExhausted,
}

/// Noise symmetric state (h, ck).
struct Symmetric {
    h: [u8; 32],
    ck: [u8; 32],
}

impl Symmetric {
    fn new() -> Self {
        // The protocol name is 33 bytes, longer than HASHLEN, so it is hashed.
        let h: [u8; 32] = Blake2s256::digest(PROTOCOL_NAME).into();
        Self { h, ck: h }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut d = Blake2s256::new();
        d.update(self.h);
        d.update(data);
        self.h = d.finalize().into();
    }

    /// MixKey(DH(priv, pub)), returning the single-use cipher key.
    fn mix_dh(&mut self, private: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], NoiseError> {
        let shared = crypto::x25519(private, public);
        if shared == [0u8; 32] {
            return Err(NoiseError::LowOrderPoint);
        }
        let [ck, k] = hkdf2(&self.ck, &shared);
        self.ck = ck;
        Ok(k)
    }

    fn encrypt_and_hash(&mut self, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let tag = crypto::aead_seal(key, &[0; 12], &self.h, &mut buf);
        buf.extend_from_slice(&tag);
        self.mix_hash(&buf);
        buf
    }

    fn decrypt_and_hash(&mut self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let split = ciphertext.len().checked_sub(crypto::TAG_LEN).ok_or(NoiseError::BadLength)?;
        let mut buf = ciphertext[..split].to_vec();
        let tag: [u8; 16] = ciphertext[split..].try_into().unwrap();
        crypto::aead_open(key, &[0; 12], &self.h, &mut buf, &tag).map_err(|_| NoiseError::Decrypt)?;
        self.mix_hash(ciphertext);
        Ok(buf)
    }

    fn split(&self) -> ([u8; 32], [u8; 32]) {
        let [k1, k2] = hkdf2(&self.ck, &[]);
        (k1, k2)
    }
}

/// HKDF with HMAC-BLAKE2s producing two 32-byte outputs (Noise's HKDF).
fn hkdf2(salt: &[u8; 32], ikm: &[u8]) -> [[u8; 32]; 2] {
    let hmac = |key: &[u8], parts: &[&[u8]]| -> [u8; 32] {
        let mut m = <SimpleHmac<Blake2s256> as Mac>::new_from_slice(key).expect("any key length");
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().into()
    };
    let prk = hmac(salt, &[ikm]);
    let t1 = hmac(&prk, &[&[1]]);
    let t2 = hmac(&prk, &[&t1, &[2]]);
    [t1, t2]
}

/// A client handshake in flight: the initiation has been produced and we
/// await the server's response.
pub struct Handshake {
    sym: Symmetric,
    machine_private: [u8; 32],
    ephemeral_private: [u8; 32],
}

impl Handshake {
    /// Builds the initiation message. `ephemeral_private` must be fresh
    /// randomness; `control_public` comes from the server's /key endpoint.
    pub fn start(
        machine_private: &[u8; 32],
        control_public: &[u8; 32],
        ephemeral_private: &[u8; 32],
        protocol_version: u16,
    ) -> Result<(Self, [u8; INITIATION_LEN]), NoiseError> {
        let mut sym = Symmetric::new();
        let mut prologue = String::from(PROLOGUE_PREFIX);
        prologue.push_str(itoa(protocol_version as u64).as_str());
        sym.mix_hash(prologue.as_bytes());
        sym.mix_hash(control_public);

        let mut msg = [0u8; INITIATION_LEN];
        msg[..2].copy_from_slice(&protocol_version.to_be_bytes());
        msg[2] = MSG_INITIATION;
        msg[3..5].copy_from_slice(&((INITIATION_LEN - 5) as u16).to_be_bytes());

        let ephemeral_public = crypto::x25519_public(ephemeral_private);
        msg[5..37].copy_from_slice(&ephemeral_public);
        sym.mix_hash(&ephemeral_public);
        let k = sym.mix_dh(ephemeral_private, control_public)?; // es
        let machine_public = crypto::x25519_public(machine_private);
        msg[37..85].copy_from_slice(&sym.encrypt_and_hash(&k, &machine_public));
        let k = sym.mix_dh(machine_private, control_public)?; // ss
        msg[85..101].copy_from_slice(&sym.encrypt_and_hash(&k, &[]));

        Ok((Self { sym, machine_private: *machine_private, ephemeral_private: *ephemeral_private }, msg))
    }

    /// Bytes of server response needed before [`Handshake::finish`] can run,
    /// given what has arrived so far (error frames have variable length).
    pub fn needed(buf: &[u8]) -> usize {
        if buf.len() < HEADER_LEN {
            return HEADER_LEN;
        }
        match buf[0] {
            MSG_ERROR => HEADER_LEN + u16::from_be_bytes([buf[1], buf[2]]) as usize,
            _ => RESPONSE_LEN,
        }
    }

    /// Consumes the server's response (exactly [`Handshake::needed`] bytes).
    pub fn finish(mut self, resp: &[u8]) -> Result<Transport, NoiseError> {
        match resp.first() {
            Some(&MSG_RESPONSE) => {}
            Some(&MSG_ERROR) => {
                return Err(NoiseError::Server(String::from_utf8_lossy(&resp[HEADER_LEN..]).into()));
            }
            Some(&t) => return Err(NoiseError::UnexpectedMessage(t)),
            None => return Err(NoiseError::BadLength),
        }
        if resp.len() != RESPONSE_LEN || u16::from_be_bytes([resp[1], resp[2]]) as usize != RESPONSE_LEN - HEADER_LEN {
            return Err(NoiseError::BadLength);
        }
        let server_ephemeral: [u8; 32] = resp[3..35].try_into().unwrap();
        self.sym.mix_hash(&server_ephemeral);
        self.sym.mix_dh(&self.ephemeral_private, &server_ephemeral)?; // ee
        let k = self.sym.mix_dh(&self.machine_private, &server_ephemeral)?; // se
        self.sym.decrypt_and_hash(&k, &resp[35..51])?;
        let (tx, rx) = self.sym.split();
        Ok(Transport { tx_key: tx, rx_key: rx, tx_nonce: 0, rx_nonce: 0, rx_buf: Vec::new() })
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.machine_private = [0; 32];
        self.ephemeral_private = [0; 32];
    }
}

/// An established ts2021 channel. Sans-IO: seal plaintext into frames,
/// feed received bytes to get plaintext back.
pub struct Transport {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_nonce: u64,
    rx_nonce: u64,
    rx_buf: Vec<u8>,
}

impl Transport {
    /// Encrypts `plaintext` into one or more record frames appended to `out`.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), NoiseError> {
        for chunk in plaintext.chunks(MAX_PLAINTEXT) {
            if self.tx_nonce == u64::MAX {
                return Err(NoiseError::NonceExhausted);
            }
            let mut buf = chunk.to_vec();
            let tag = crypto::aead_seal(&self.tx_key, &nonce(self.tx_nonce), &[], &mut buf);
            self.tx_nonce += 1;
            out.push(MSG_RECORD);
            out.extend_from_slice(&((buf.len() + crypto::TAG_LEN) as u16).to_be_bytes());
            out.extend_from_slice(&buf);
            out.extend_from_slice(&tag);
        }
        Ok(())
    }

    /// Feeds received bytes, appending any decrypted plaintext to `out`.
    pub fn open(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), NoiseError> {
        self.rx_buf.extend_from_slice(data);
        let mut consumed = 0;
        while self.rx_buf.len() - consumed >= HEADER_LEN {
            let frame = &self.rx_buf[consumed..];
            let len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
            if HEADER_LEN + len > MAX_MESSAGE {
                return Err(NoiseError::BadLength);
            }
            if frame.len() < HEADER_LEN + len {
                break;
            }
            match frame[0] {
                MSG_RECORD => {}
                MSG_ERROR => {
                    return Err(NoiseError::Server(String::from_utf8_lossy(&frame[HEADER_LEN..HEADER_LEN + len]).into()))
                }
                t => return Err(NoiseError::UnexpectedMessage(t)),
            }
            if len < crypto::TAG_LEN || self.rx_nonce == u64::MAX {
                return Err(NoiseError::BadLength);
            }
            let body = &frame[HEADER_LEN..HEADER_LEN + len];
            let (ct, tag) = body.split_at(len - crypto::TAG_LEN);
            let start = out.len();
            out.extend_from_slice(ct);
            crypto::aead_open(&self.rx_key, &nonce(self.rx_nonce), &[], &mut out[start..], tag.try_into().unwrap())
                .map_err(|_| NoiseError::Decrypt)?;
            self.rx_nonce += 1;
            consumed += HEADER_LEN + len;
        }
        self.rx_buf.drain(..consumed);
        Ok(())
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.tx_key = [0; 32];
        self.rx_key = [0; 32];
    }
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn itoa(mut v: u64) -> String {
    let mut digits = Vec::new();
    loop {
        digits.push(b'0' + (v % 10) as u8);
        v /= 10;
        if v == 0 {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server half of the handshake, mirroring controlbase.Server, so the
    /// client can be exercised without a network.
    fn server_respond(
        control_private: &[u8; 32],
        server_ephemeral: &[u8; 32],
        init: &[u8; INITIATION_LEN],
        version: u16,
    ) -> ([u8; 32], [u8; RESPONSE_LEN], Transport) {
        let mut sym = Symmetric::new();
        let mut prologue = String::from(PROLOGUE_PREFIX);
        prologue.push_str(&itoa(version as u64));
        sym.mix_hash(prologue.as_bytes());
        sym.mix_hash(&crypto::x25519_public(control_private));
        let client_e: [u8; 32] = init[5..37].try_into().unwrap();
        sym.mix_hash(&client_e);
        let k = sym.mix_dh(control_private, &client_e).unwrap();
        let machine_pub: [u8; 32] = sym.decrypt_and_hash(&k, &init[37..85]).unwrap().try_into().unwrap();
        let k = sym.mix_dh(control_private, &machine_pub).unwrap();
        sym.decrypt_and_hash(&k, &init[85..101]).unwrap();

        let mut resp = [0u8; RESPONSE_LEN];
        resp[0] = MSG_RESPONSE;
        resp[1..3].copy_from_slice(&48u16.to_be_bytes());
        let e_pub = crypto::x25519_public(server_ephemeral);
        resp[3..35].copy_from_slice(&e_pub);
        sym.mix_hash(&e_pub);
        sym.mix_dh(server_ephemeral, &client_e).unwrap(); // ee
        let k = sym.mix_dh(server_ephemeral, &machine_pub).unwrap(); // se
        resp[35..51].copy_from_slice(&sym.encrypt_and_hash(&k, &[]));
        let (c1, c2) = sym.split();
        // The server receives with c1 and sends with c2.
        (machine_pub, resp, Transport { tx_key: c2, rx_key: c1, tx_nonce: 0, rx_nonce: 0, rx_buf: Vec::new() })
    }

    #[test]
    fn handshake_and_records_roundtrip() {
        let machine = [1u8; 32];
        let control = [2u8; 32];
        let (hs, init) = Handshake::start(&machine, &crypto::x25519_public(&control), &[3u8; 32], 148).unwrap();
        assert_eq!(&init[..5], &[0, 148, MSG_INITIATION, 0, 96]);

        let (seen_machine, resp, mut server) = server_respond(&control, &[4u8; 32], &init, 148);
        assert_eq!(seen_machine, crypto::x25519_public(&machine));
        assert_eq!(Handshake::needed(&resp[..1]), HEADER_LEN);
        assert_eq!(Handshake::needed(&resp), RESPONSE_LEN);
        let mut client = hs.finish(&resp).unwrap();

        // Client -> server, including a message spanning several frames.
        let big = alloc::vec![9u8; 10_000];
        let mut wire = Vec::new();
        client.seal(&big, &mut wire).unwrap();
        let mut got = Vec::new();
        for chunk in wire.chunks(777) {
            server.open(chunk, &mut got).unwrap();
        }
        assert_eq!(got, big);

        // Server -> client.
        let mut wire = Vec::new();
        server.seal(b"hello", &mut wire).unwrap();
        let mut got = Vec::new();
        client.open(&wire, &mut got).unwrap();
        assert_eq!(got, b"hello");

        // Tampering is detected.
        let mut wire = Vec::new();
        server.seal(b"x", &mut wire).unwrap();
        wire[4] ^= 1;
        assert_eq!(client.open(&wire, &mut Vec::new()), Err(NoiseError::Decrypt));
    }

    #[test]
    fn server_error_frame_is_reported() {
        let (hs, _) = Handshake::start(&[1; 32], &crypto::x25519_public(&[2; 32]), &[3; 32], 148).unwrap();
        let mut resp = alloc::vec![MSG_ERROR, 0, 4];
        resp.extend_from_slice(b"nope");
        assert_eq!(Handshake::needed(&resp), 7);
        assert!(matches!(hs.finish(&resp), Err(NoiseError::Server(m)) if m == "nope"));
    }
}
