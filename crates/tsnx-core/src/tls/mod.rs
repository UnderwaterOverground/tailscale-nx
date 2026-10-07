//! Sans-IO TLS client (used for DERP, and the control plane's TLS fallback).
//!
//! Wraps rustls' unbuffered API into a byte-in/byte-out object: the caller
//! feeds ciphertext received from the socket, drains ciphertext to send, and
//! reads/writes plaintext. No sockets, no std.

mod provider;
mod roots;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError};
use rustls::{ClientConfig, RootCertStore};

pub use provider::provider;

/// Wall-clock source for certificate validity checks. The engine updates it
/// from the time the driver passes in; rustls reads it during handshakes.
#[derive(Debug, Default)]
pub struct UnixClock(AtomicU64);

impl UnixClock {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn set(&self, unix_secs: u64) {
        self.0.store(unix_secs, Ordering::Relaxed);
    }
}

/// The clock all TLS configs built by [`client_config`] consult.
pub static CLOCK: UnixClock = UnixClock::new();

#[derive(Debug)]
struct ClockProvider;

impl TimeProvider for ClockProvider {
    fn current_time(&self) -> Option<UnixTime> {
        match CLOCK.0.load(Ordering::Relaxed) {
            0 => None,
            secs => Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(secs))),
        }
    }
}

/// Builds a TLS 1.3 client config trusting a curated subset of the Mozilla
/// root set (see tools/gen-roots.py) plus any
/// `extra_roots` (DER), e.g. a self-signed DERP cert in a dev environment.
pub fn client_config(extra_roots: &[Vec<u8>]) -> Result<Arc<ClientConfig>, rustls::Error> {
    let mut roots = RootCertStore { roots: roots::ROOTS_EC.to_vec() };
    roots.roots.extend_from_slice(roots::ROOTS_RSA);
    for der in extra_roots {
        roots.add(CertificateDer::from(der.clone()))?;
    }
    let config = ClientConfig::builder_with_details(Arc::new(provider()), Arc::new(ClockProvider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    InvalidServerName,
    Rustls(String),
    Closed,
}

impl From<rustls::Error> for TlsError {
    fn from(e: rustls::Error) -> Self {
        TlsError::Rustls(e.to_string())
    }
}

/// A TLS client session over a byte stream the caller transports.
pub struct TlsClient {
    conn: UnbufferedClientConnection,
    /// Ciphertext received but not yet consumed by rustls.
    incoming: Vec<u8>,
    /// Ciphertext ready to be written to the transport.
    outgoing: Vec<u8>,
    /// Decrypted application data not yet read by the caller.
    plaintext_in: Vec<u8>,
    /// Application data written before it could be encrypted.
    plaintext_out: Vec<u8>,
    established: bool,
    peer_closed: bool,
    closed: bool,
    want_close: bool,
}

impl TlsClient {
    /// Releases spare buffer capacity (see [`crate::trim_vec`]).
    pub fn trim(&mut self) {
        crate::trim_vec(&mut self.incoming);
        crate::trim_vec(&mut self.outgoing);
        crate::trim_vec(&mut self.plaintext_in);
        crate::trim_vec(&mut self.plaintext_out);
    }

    pub fn new(config: Arc<ClientConfig>, server_name: &str) -> Result<Self, TlsError> {
        let name = ServerName::try_from(server_name.to_string()).map_err(|_| TlsError::InvalidServerName)?;
        let conn = UnbufferedClientConnection::new(config, name)?;
        let mut client = Self {
            conn,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            plaintext_in: Vec::new(),
            plaintext_out: Vec::new(),
            established: false,
            peer_closed: false,
            closed: false,
            want_close: false,
        };
        client.pump()?;
        Ok(client)
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    /// The peer sent close_notify; no more plaintext will arrive.
    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Feeds ciphertext received from the transport.
    pub fn feed(&mut self, ciphertext: &[u8]) -> Result<(), TlsError> {
        self.incoming.extend_from_slice(ciphertext);
        self.pump()
    }

    /// Queues plaintext; it is encrypted as soon as the handshake allows.
    pub fn write(&mut self, plaintext: &[u8]) -> Result<(), TlsError> {
        if self.closed || self.want_close {
            return Err(TlsError::Closed);
        }
        self.plaintext_out.extend_from_slice(plaintext);
        self.pump()
    }

    /// Queues a close_notify alert.
    pub fn close(&mut self) -> Result<(), TlsError> {
        self.want_close = true;
        self.pump()
    }

    /// Takes all ciphertext that should be written to the transport.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }

    pub fn has_outgoing(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Takes all decrypted application data received so far.
    pub fn take_plaintext(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.plaintext_in)
    }

    /// Drives rustls until it needs more input or has nothing left to do.
    fn pump(&mut self) -> Result<(), TlsError> {
        loop {
            let status = self.conn.process_tls_records(&mut self.incoming);
            let mut discard = status.discard;
            let mut progressed = false;
            let mut stop = false;

            match status.state? {
                ConnectionState::ReadTraffic(mut traffic) => {
                    while let Some(record) = traffic.next_record() {
                        let record = record?;
                        discard += record.discard;
                        self.plaintext_in.extend_from_slice(record.payload);
                    }
                    progressed = true;
                }
                ConnectionState::EncodeTlsData(mut state) => {
                    encode_into(&mut self.outgoing, |buf| state.encode(buf))?;
                    progressed = true;
                }
                ConnectionState::TransmitTlsData(mut state) => {
                    // Our caller transmits whatever accumulates in `outgoing`.
                    if let Some(mut traffic) = state.may_encrypt_app_data() {
                        if !self.plaintext_out.is_empty() {
                            let data = core::mem::take(&mut self.plaintext_out);
                            encrypt_into(&mut self.outgoing, |buf| traffic.encrypt(&data, buf))?;
                        }
                    }
                    state.done();
                    progressed = true;
                }
                ConnectionState::WriteTraffic(mut traffic) => {
                    self.established = true;
                    if !self.plaintext_out.is_empty() {
                        let data = core::mem::take(&mut self.plaintext_out);
                        encrypt_into(&mut self.outgoing, |buf| traffic.encrypt(&data, buf))?;
                    }
                    if self.want_close && !self.closed {
                        encrypt_into(&mut self.outgoing, |buf| traffic.queue_close_notify(buf))?;
                        self.closed = true;
                    }
                    // WriteTraffic is reported again on every call while idle;
                    // only keep going if rustls consumed input.
                    stop = discard == 0;
                }
                ConnectionState::BlockedHandshake => stop = true,
                ConnectionState::PeerClosed => {
                    self.peer_closed = true;
                    progressed = true;
                }
                ConnectionState::Closed => {
                    self.closed = true;
                    stop = true;
                }
                // Early data is server-side only; future variants: wait for input.
                _ => stop = true,
            }

            if discard > 0 {
                self.incoming.drain(..discard);
                progressed = true;
            }
            if stop || !progressed {
                return Ok(());
            }
        }
    }
}

fn encode_into(
    out: &mut Vec<u8>,
    mut f: impl FnMut(&mut [u8]) -> Result<usize, EncodeError>,
) -> Result<(), TlsError> {
    let start = out.len();
    let mut room = 4096;
    loop {
        out.resize(start + room, 0);
        match f(&mut out[start..]) {
            Ok(n) => {
                out.truncate(start + n);
                return Ok(());
            }
            Err(EncodeError::InsufficientSize(e)) => room = e.required_size,
            Err(e) => {
                out.truncate(start);
                return Err(TlsError::Rustls(e.to_string()));
            }
        }
    }
}

fn encrypt_into(
    out: &mut Vec<u8>,
    mut f: impl FnMut(&mut [u8]) -> Result<usize, EncryptError>,
) -> Result<(), TlsError> {
    let start = out.len();
    let mut room = 4096;
    loop {
        out.resize(start + room, 0);
        match f(&mut out[start..]) {
            Ok(n) => {
                out.truncate(start + n);
                return Ok(());
            }
            Err(EncryptError::InsufficientSize(e)) => room = e.required_size,
            Err(e) => {
                out.truncate(start);
                return Err(TlsError::Rustls(e.to_string()));
            }
        }
    }
}
