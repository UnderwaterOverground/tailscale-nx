//! A minimal pure-Rust rustls `CryptoProvider` built from RustCrypto crates.
//!
//! Scope is deliberately narrow: TLS 1.3 only, TLS_CHACHA20_POLY1305_SHA256,
//! X25519 key exchange, and the ECDSA/RSA signature algorithms needed to verify
//! Web PKI chains (Let's Encrypt and friends). That covers Tailscale's DERP
//! servers and keeps the Switch binary small and free of C/asm dependencies.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Mac, SimpleHmac};
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    hash, hmac as rhmac, ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider,
    SecureRandom, SharedSecret, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{alg_id, AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm};
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, NamedGroup, ProtocolVersion, SignatureScheme,
    SupportedCipherSuite, Tls13CipherSuite,
};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: alloc::vec![TLS13_CHACHA20_POLY1305_SHA256],
        kx_groups: alloc::vec![&X25519 as &dyn SupportedKxGroup],
        signature_verification_algorithms: SIG_ALGS,
        secure_random: &Rng,
        key_provider: &NoKeys,
    }
}

// ---------------------------------------------------------------------------
// Randomness and (absent) client keys

#[derive(Debug)]
struct Rng;

impl SecureRandom for Rng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        crate::rng::fill(buf).map_err(|_| GetRandomFailed)
    }
}

/// We never present client certificates.
#[derive(Debug)]
struct NoKeys;

impl KeyProvider for NoKeys {
    fn load_private_key(&self, _key: PrivateKeyDer<'static>) -> Result<Arc<dyn rustls::sign::SigningKey>, Error> {
        Err(Error::General("client certificates are not supported".into()))
    }
}

// ---------------------------------------------------------------------------
// Hashing and HMAC

struct Sha256Hash;

impl hash::Hash for Sha256Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&Sha256::digest(data)[..])
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        rustls::crypto::hash::HashAlgorithm::SHA256
    }
}

struct Sha256Context(Sha256);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

struct HmacSha256;

impl rhmac::Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn rhmac::Key> {
        Box::new(HmacSha256Key(
            <SimpleHmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct HmacSha256Key(SimpleHmac<Sha256>);

impl rhmac::Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> rhmac::Tag {
        let mut mac = self.0.clone();
        mac.update(first);
        for m in middle {
            mac.update(m);
        }
        mac.update(last);
        rhmac::Tag::new(&mac.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        32
    }
}

// ---------------------------------------------------------------------------
// Cipher suite and AEAD

pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &Sha256Hash,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HkdfUsingHmac(&HmacSha256),
    aead_alg: &ChaChaAead,
    quic: None,
});

struct ChaChaAead;

const TAG_LEN: usize = 16;

impl Tls13AeadAlgorithm for ChaChaAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(ChaChaRecord {
            cipher: ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key"),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(ChaChaRecord {
            cipher: ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key"),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(&self, key: AeadKey, iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

struct ChaChaRecord {
    cipher: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageEncrypter for ChaChaRecord {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);
        let tag = self
            .cipher
            .encrypt_in_place_detached((&nonce.0).into(), &aad, payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);

        // TLS 1.3 records always carry the legacy 1.2 version (RFC 8446 5.1).
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for ChaChaRecord {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let len = payload.len();
        if len < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(len);
        let (body, tag) = payload.split_at_mut(len - TAG_LEN);
        let tag = chacha20poly1305::Tag::clone_from_slice(tag);
        self.cipher
            .decrypt_in_place_detached((&nonce.0).into(), &aad, body, &tag)
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(len - TAG_LEN);
        msg.into_tls13_unpadded_message()
    }
}

// ---------------------------------------------------------------------------
// Key exchange

#[derive(Debug)]
struct X25519Group;

static X25519: X25519Group = X25519Group;

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = crate::rng::bytes32().map_err(|_| Error::FailedToGetRandomBytes)?;
        let public = crate::crypto::x25519_public(&secret);
        Ok(Box::new(X25519Exchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Exchange {
    secret: [u8; 32],
    public: [u8; 32],
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared = crate::crypto::x25519(&self.secret, &peer);
        // RFC 8446 7.4.2: reject the all-zero output of a small-order point.
        if shared.iter().all(|&b| b == 0) {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl Drop for X25519Exchange {
    fn drop(&mut self) {
        self.secret = [0; 32];
    }
}

// ---------------------------------------------------------------------------
// Signature verification

#[derive(Debug, Clone, Copy)]
enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug)]
struct EcdsaVerify {
    curve: AlgorithmIdentifier,
    hash: HashAlg,
    sig_id: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for EcdsaVerify {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let digest: Vec<u8> = match self.hash {
            HashAlg::Sha256 => Sha256::digest(message).to_vec(),
            HashAlg::Sha384 => Sha384::digest(message).to_vec(),
            HashAlg::Sha512 => Sha512::digest(message).to_vec(),
        };
        if self.curve == alg_id::ECDSA_P256 {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
            let sig = p256::ecdsa::DerSignature::try_from(signature).map_err(|_| InvalidSignature)?;
            key.verify_prehash(&digest, &sig).map_err(|_| InvalidSignature)
        } else {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
            let sig = p384::ecdsa::DerSignature::try_from(signature).map_err(|_| InvalidSignature)?;
            key.verify_prehash(&digest, &sig).map_err(|_| InvalidSignature)
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.curve
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.sig_id
    }
}

// RSA is required: Tailscale's servers present an RSA or an ECDSA
// certificate depending on which frontend answers.
#[derive(Debug)]
struct RsaVerify {
    pss: bool,
    hash: HashAlg,
    sig_id: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for RsaVerify {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::signature::Verifier;
        use rsa::traits::PublicKeyParts;

        let key = rsa::RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| InvalidSignature)?;
        // Same bounds as webpki: 2048..=8192 bit moduli.
        let bits = key.size() * 8;
        if !(2048..=8192).contains(&bits) {
            return Err(InvalidSignature);
        }

        macro_rules! verify {
            ($scheme:ident, $hash:ty) => {{
                let vk = rsa::$scheme::VerifyingKey::<$hash>::new(key);
                let sig = rsa::$scheme::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                vk.verify(message, &sig).map_err(|_| InvalidSignature)
            }};
        }
        match (self.pss, self.hash) {
            (false, HashAlg::Sha256) => verify!(pkcs1v15, Sha256),
            (false, HashAlg::Sha384) => verify!(pkcs1v15, Sha384),
            (false, HashAlg::Sha512) => verify!(pkcs1v15, Sha512),
            (true, HashAlg::Sha256) => verify!(pss, Sha256),
            (true, HashAlg::Sha384) => verify!(pss, Sha384),
            (true, HashAlg::Sha512) => verify!(pss, Sha512),
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.sig_id
    }
}

static ECDSA_P256_SHA256: EcdsaVerify =
    EcdsaVerify { curve: alg_id::ECDSA_P256, hash: HashAlg::Sha256, sig_id: alg_id::ECDSA_SHA256 };
static ECDSA_P256_SHA384: EcdsaVerify =
    EcdsaVerify { curve: alg_id::ECDSA_P256, hash: HashAlg::Sha384, sig_id: alg_id::ECDSA_SHA384 };
static ECDSA_P384_SHA256: EcdsaVerify =
    EcdsaVerify { curve: alg_id::ECDSA_P384, hash: HashAlg::Sha256, sig_id: alg_id::ECDSA_SHA256 };
static ECDSA_P384_SHA384: EcdsaVerify =
    EcdsaVerify { curve: alg_id::ECDSA_P384, hash: HashAlg::Sha384, sig_id: alg_id::ECDSA_SHA384 };
mod rsa_algs {
    use super::*;
    pub static RSA_PKCS1_SHA256: RsaVerify = RsaVerify { pss: false, hash: HashAlg::Sha256, sig_id: alg_id::RSA_PKCS1_SHA256 };
    pub static RSA_PKCS1_SHA384: RsaVerify = RsaVerify { pss: false, hash: HashAlg::Sha384, sig_id: alg_id::RSA_PKCS1_SHA384 };
    pub static RSA_PKCS1_SHA512: RsaVerify = RsaVerify { pss: false, hash: HashAlg::Sha512, sig_id: alg_id::RSA_PKCS1_SHA512 };
    pub static RSA_PSS_SHA256: RsaVerify = RsaVerify { pss: true, hash: HashAlg::Sha256, sig_id: alg_id::RSA_PSS_SHA256 };
    pub static RSA_PSS_SHA384: RsaVerify = RsaVerify { pss: true, hash: HashAlg::Sha384, sig_id: alg_id::RSA_PSS_SHA384 };
    pub static RSA_PSS_SHA512: RsaVerify = RsaVerify { pss: true, hash: HashAlg::Sha512, sig_id: alg_id::RSA_PSS_SHA512 };
}
use rsa_algs::*;

static SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &ECDSA_P256_SHA256,
        &ECDSA_P256_SHA384,
        &ECDSA_P384_SHA256,
        &ECDSA_P384_SHA384,
        &RSA_PKCS1_SHA256,
        &RSA_PKCS1_SHA384,
        &RSA_PKCS1_SHA512,
        &RSA_PSS_SHA256,
        &RSA_PSS_SHA384,
        &RSA_PSS_SHA512,
    ],
    mapping: &[
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[&ECDSA_P256_SHA256]),
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[&ECDSA_P384_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[&RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[&RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[&RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[&RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[&RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[&RSA_PKCS1_SHA512]),
    ],
};
