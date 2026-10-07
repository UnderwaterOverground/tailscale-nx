//! A ts2021 control connection over a byte stream (plain TCP to port 80, or
//! the plaintext side of a TLS session to 443):
//!
//! 1. HTTP/1.1 `POST /ts2021` upgrade carrying the Noise initiation in the
//!    `X-Tailscale-Handshake` header;
//! 2. the server's Noise response, then Noise records;
//! 3. inside them, an optional "early payload" (`\xff\xff\xffTS` + u32be len +
//!    JSON EarlyNoise), followed by prior-knowledge HTTP/2.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine;

use super::noise::{Handshake, NoiseError, Transport};
use crate::http2;

const EARLY_MAGIC: &[u8] = b"\xff\xff\xffTS";
const EARLY_HEADER_LEN: usize = 9;
const MAX_EARLY_PAYLOAD: usize = 64 << 10;
const MAX_UPGRADE_RESPONSE: usize = 16 << 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnError {
    Upgrade(String),
    Noise(NoiseError),
    Http2(http2::H2Error),
    EarlyPayloadTooLarge,
    NotReady,
}

impl From<NoiseError> for ConnError {
    fn from(e: NoiseError) -> Self {
        ConnError::Noise(e)
    }
}

impl From<http2::H2Error> for ConnError {
    fn from(e: http2::H2Error) -> Self {
        ConnError::Http2(e)
    }
}

enum State {
    /// Waiting for the HTTP 101 response.
    Upgrading(Handshake),
    /// Upgraded; waiting for the Noise handshake response.
    Handshaking(Handshake),
    /// Noise is up; deciding whether the first 9 bytes are an early payload.
    EarlyHeader,
    EarlyBody(usize),
    /// Plaintext is HTTP/2.
    Http2,
    /// Transient while moving between states.
    Poisoned,
}

pub struct ControlConn {
    state: State,
    /// Raw bytes from the stream not yet consumed (before Noise is up).
    raw: Vec<u8>,
    transport: Option<Transport>,
    /// Decrypted bytes not yet consumed by the early-payload parser.
    plain: Vec<u8>,
    h2: http2::Client,
    out: Vec<u8>,
    early_payload: Option<Vec<u8>>,
}

impl ControlConn {
    /// Releases spare buffer capacity (see [`crate::trim_vec`]).
    pub fn trim(&mut self) {
        crate::trim_vec(&mut self.raw);
        crate::trim_vec(&mut self.plain);
        crate::trim_vec(&mut self.out);
        self.h2.trim();
    }

    /// Starts a connection. `host` is the control server's hostname (used for
    /// the Host header and HTTP/2 :authority).
    pub fn new(
        host: &str,
        machine_private: &[u8; 32],
        control_public: &[u8; 32],
        ephemeral_private: &[u8; 32],
        protocol_version: u16,
    ) -> Result<Self, ConnError> {
        let (hs, init) = Handshake::start(machine_private, control_public, ephemeral_private, protocol_version)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(init);
        let request = format!(
            "POST /ts2021 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tailscale-nx\r\n\
             Upgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\
             X-Tailscale-Handshake: {b64}\r\nContent-Length: 0\r\n\r\n"
        );
        Ok(Self {
            state: State::Upgrading(hs),
            raw: Vec::new(),
            transport: None,
            plain: Vec::new(),
            h2: http2::Client::new(host, "https"),
            out: request.into_bytes(),
            early_payload: None,
        })
    }

    /// True once HTTP/2 requests can be issued.
    pub fn is_ready(&self) -> bool {
        matches!(self.state, State::Http2)
    }

    /// The server's EarlyNoise JSON, if it sent one.
    pub fn early_payload(&self) -> Option<&[u8]> {
        self.early_payload.as_deref()
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    /// Issues an HTTP/2 request. Only valid once [`Self::is_ready`].
    pub fn request(&mut self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<u32, ConnError> {
        if !self.is_ready() {
            return Err(ConnError::NotReady);
        }
        let id = self.h2.request(method, path, headers, body)?;
        self.flush_h2()?;
        Ok(id)
    }

    pub fn cancel(&mut self, stream: u32) -> Result<(), ConnError> {
        self.h2.cancel(stream);
        self.flush_h2()
    }

    pub fn ping(&mut self) -> Result<(), ConnError> {
        self.h2.ping(*b"tsnxping");
        self.flush_h2()
    }

    pub fn poll_event(&mut self) -> Option<http2::Event> {
        self.h2.poll_event()
    }

    /// Feeds bytes read from the underlying stream.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), ConnError> {
        if let Some(t) = self.transport.as_mut() {
            t.open(data, &mut self.plain)?;
        } else {
            self.raw.extend_from_slice(data);
        }
        loop {
            match core::mem::replace(&mut self.state, State::Poisoned) {
                State::Upgrading(hs) => {
                    let Some(end) = find(&self.raw, b"\r\n\r\n") else {
                        if self.raw.len() > MAX_UPGRADE_RESPONSE {
                            return Err(ConnError::Upgrade("oversized HTTP response".into()));
                        }
                        self.state = State::Upgrading(hs);
                        return Ok(());
                    };
                    let head = String::from_utf8_lossy(&self.raw[..end]).into_owned();
                    let status = head.lines().next().unwrap_or("");
                    if status.split(' ').nth(1) != Some("101") {
                        return Err(ConnError::Upgrade(format!("unexpected response: {status}")));
                    }
                    self.raw.drain(..end + 4);
                    self.state = State::Handshaking(hs);
                }
                State::Handshaking(hs) => {
                    let need = Handshake::needed(&self.raw);
                    if self.raw.len() < need {
                        self.state = State::Handshaking(hs);
                        return Ok(());
                    }
                    let mut transport = hs.finish(&self.raw[..need])?;
                    let rest: Vec<u8> = self.raw.drain(..).skip(need).collect();
                    transport.open(&rest, &mut self.plain)?;
                    self.transport = Some(transport);
                    self.state = State::EarlyHeader;
                    // The client speaks first in HTTP/2; send the preface now.
                    self.flush_h2()?;
                }
                State::EarlyHeader => {
                    if self.plain.len() < EARLY_HEADER_LEN {
                        self.state = State::EarlyHeader;
                        return Ok(());
                    }
                    if self.plain.starts_with(EARLY_MAGIC) {
                        let len = u32::from_be_bytes(self.plain[5..9].try_into().unwrap()) as usize;
                        if len > MAX_EARLY_PAYLOAD {
                            return Err(ConnError::EarlyPayloadTooLarge);
                        }
                        self.plain.drain(..EARLY_HEADER_LEN);
                        self.state = State::EarlyBody(len);
                    } else {
                        self.state = State::Http2;
                    }
                }
                State::EarlyBody(len) => {
                    if self.plain.len() < len {
                        self.state = State::EarlyBody(len);
                        return Ok(());
                    }
                    self.early_payload = Some(self.plain.drain(..len).collect());
                    self.state = State::Http2;
                }
                State::Http2 => {
                    self.state = State::Http2;
                    if !self.plain.is_empty() {
                        let data = core::mem::take(&mut self.plain);
                        self.h2.feed(&data)?;
                        self.flush_h2()?;
                    }
                    return Ok(());
                }
                State::Poisoned => unreachable!("ControlConn used after an error"),
            }
        }
    }

    fn flush_h2(&mut self) -> Result<(), ConnError> {
        let pending = self.h2.take_outgoing();
        if pending.is_empty() {
            return Ok(());
        }
        // Callers only reach here once Noise is up (see `request`).
        let t = self.transport.as_mut().ok_or(ConnError::NotReady)?;
        t.seal(&pending, &mut self.out)?;
        Ok(())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
