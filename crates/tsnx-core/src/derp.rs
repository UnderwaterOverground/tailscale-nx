//! DERP relay client (tailscale/derp), sans-IO.
//!
//! Over a TLS stream: `GET /derp` with `Upgrade: DERP`, then frames of
//! `type:u8 | len:u32be | payload`. Login is ServerKey -> ClientInfo (NaCl box
//! to the server key) -> ServerInfo. Afterwards packets travel in
//! SendPacket (dst key + bytes) and RecvPacket (src key + bytes) frames.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crypto_box::aead::Aead;
use crypto_box::SalsaBox;
use ts_keys::{NodePrivateKey, NodePublicKey};
// Raw byte views of key types.
use zerocopy::IntoBytes;

use crate::stream::SecureStream;

const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
const PROTOCOL_VERSION: u32 = 2;
const FRAME_HEADER_LEN: usize = 5;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const MAX_FRAME: usize = 1 << 20;
pub const MAX_PACKET: usize = 64 << 10;

mod frame {
    pub const SERVER_KEY: u8 = 0x01;
    pub const CLIENT_INFO: u8 = 0x02;
    pub const SERVER_INFO: u8 = 0x03;
    pub const SEND_PACKET: u8 = 0x04;
    pub const RECV_PACKET: u8 = 0x05;
    pub const KEEP_ALIVE: u8 = 0x06;
    pub const NOTE_PREFERRED: u8 = 0x07;
    pub const PEER_GONE: u8 = 0x08;
    pub const PING: u8 = 0x12;
    pub const PONG: u8 = 0x13;
    pub const HEALTH: u8 = 0x14;
    pub const RESTARTING: u8 = 0x15;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerpError {
    Tls(String),
    Upgrade(String),
    Protocol(&'static str),
    Crypto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerpEvent {
    /// Login complete; packets can be sent.
    Ready,
    /// A packet relayed from `src`.
    Recv { src: NodePublicKey, packet: Vec<u8> },
    /// The server has no (or lost its) route to `peer`.
    PeerGone { peer: NodePublicKey },
    /// Server-reported health problem (empty = cleared).
    Health(String),
    /// The server is restarting; reconnect after `reconnect_in_ms`.
    Restarting { reconnect_in_ms: u32 },
}

enum State {
    Upgrading,
    AwaitServerKey,
    AwaitServerInfo { server_key: NodePublicKey },
    Ready,
}

pub struct DerpClient {
    stream: SecureStream,
    state: State,
    node_private: NodePrivateKey,
    rx: Vec<u8>,
    out_plain: Vec<u8>,
    events: VecDeque<DerpEvent>,
}

impl DerpClient {
    /// Releases spare buffer capacity (see [`crate::trim_vec`]).
    pub fn trim(&mut self) {
        self.stream.trim();
        crate::trim_vec(&mut self.rx);
        crate::trim_vec(&mut self.out_plain);
        self.events.shrink_to_fit();
    }

    /// `host` is the DERP node's hostname (Host header; TLS name is the
    /// stream's business). `stream` is a fresh, not yet used stream.
    pub fn new(host: &str, stream: SecureStream, node_private: NodePrivateKey) -> Result<Self, DerpError> {
        let mut c = Self {
            stream,
            state: State::Upgrading,
            node_private,
            rx: Vec::new(),
            out_plain: Vec::new(),
            events: VecDeque::new(),
        };
        let req = format!(
            "GET /derp HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tailscale-nx\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
        );
        c.write_plain(req.as_bytes())?;
        Ok(c)
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.state, State::Ready)
    }

    pub fn poll_event(&mut self) -> Option<DerpEvent> {
        self.events.pop_front()
    }

    /// Bytes to write to the socket.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        self.stream.take_outgoing()
    }

    /// Bytes read from the socket.
    pub fn feed(&mut self, raw: &[u8]) -> Result<(), DerpError> {
        self.stream.feed(raw).map_err(|e| DerpError::Tls(format!("{e:?}")))?;
        self.rx.extend(self.stream.take_plaintext());
        self.process()
    }

    /// Relays `packet` to the node with public key `dst`.
    pub fn send_packet(&mut self, dst: &NodePublicKey, packet: &[u8]) -> Result<(), DerpError> {
        if packet.len() > MAX_PACKET {
            return Err(DerpError::Protocol("packet too large"));
        }
        let mut payload = Vec::with_capacity(KEY_LEN + packet.len());
        payload.extend_from_slice(dst.as_bytes());
        payload.extend_from_slice(packet);
        self.write_frame(frame::SEND_PACKET, &payload)
    }

    /// Tells the server whether this is our home DERP (affects routing).
    pub fn note_preferred(&mut self, preferred: bool) -> Result<(), DerpError> {
        self.write_frame(frame::NOTE_PREFERRED, &[preferred as u8])
    }

    /// Liveness probe; the server echoes it as a Pong.
    pub fn ping(&mut self, data: [u8; 8]) -> Result<(), DerpError> {
        self.write_frame(frame::PING, &data)
    }

    fn process(&mut self) -> Result<(), DerpError> {
        if matches!(self.state, State::Upgrading) {
            let Some(end) = self.rx.windows(4).position(|w| w == b"\r\n\r\n") else {
                if self.rx.len() > 16 << 10 {
                    return Err(DerpError::Upgrade("oversized HTTP response".into()));
                }
                return Ok(());
            };
            let head = String::from_utf8_lossy(&self.rx[..end]).into_owned();
            let status = head.lines().next().unwrap_or("");
            if status.split(' ').nth(1) != Some("101") {
                return Err(DerpError::Upgrade(status.into()));
            }
            self.rx.drain(..end + 4);
            self.state = State::AwaitServerKey;
        }
        let mut consumed = 0;
        while self.rx.len() - consumed >= FRAME_HEADER_LEN {
            let hdr = &self.rx[consumed..];
            let typ = hdr[0];
            let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
            if len > MAX_FRAME {
                return Err(DerpError::Protocol("frame too large"));
            }
            if hdr.len() < FRAME_HEADER_LEN + len {
                break;
            }
            let payload = hdr[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len].to_vec();
            consumed += FRAME_HEADER_LEN + len;
            self.handle_frame(typ, &payload)?;
        }
        self.rx.drain(..consumed);
        Ok(())
    }

    fn handle_frame(&mut self, typ: u8, payload: &[u8]) -> Result<(), DerpError> {
        match (&self.state, typ) {
            (State::AwaitServerKey, frame::SERVER_KEY) => {
                if payload.len() < MAGIC.len() + KEY_LEN || &payload[..8] != MAGIC {
                    return Err(DerpError::Protocol("bad server key frame"));
                }
                let server_key = NodePublicKey::from_bytes(payload[8..40].try_into().unwrap());
                self.send_client_info(&server_key)?;
                self.state = State::AwaitServerInfo { server_key };
            }
            (State::AwaitServerKey, _) => return Err(DerpError::Protocol("expected server key")),
            (State::AwaitServerInfo { server_key }, frame::SERVER_INFO) => {
                // The JSON inside (token bucket hints) is informational; just
                // verify it opens, which authenticates the server key.
                open_box(&self.node_private, server_key, payload)?;
                self.state = State::Ready;
                self.events.push_back(DerpEvent::Ready);
            }
            (_, frame::RECV_PACKET) => {
                if payload.len() < KEY_LEN {
                    return Err(DerpError::Protocol("short recv packet"));
                }
                let src = NodePublicKey::from_bytes(payload[..KEY_LEN].try_into().unwrap());
                self.events.push_back(DerpEvent::Recv { src, packet: payload[KEY_LEN..].to_vec() });
            }
            (_, frame::PEER_GONE) => {
                if payload.len() >= KEY_LEN {
                    let peer = NodePublicKey::from_bytes(payload[..KEY_LEN].try_into().unwrap());
                    self.events.push_back(DerpEvent::PeerGone { peer });
                }
            }
            (_, frame::PING) => {
                if payload.len() >= 8 {
                    let echo: [u8; 8] = payload[..8].try_into().unwrap();
                    self.write_frame(frame::PONG, &echo)?;
                }
            }
            (_, frame::HEALTH) => self.events.push_back(DerpEvent::Health(String::from_utf8_lossy(payload).into())),
            (_, frame::RESTARTING) => {
                let reconnect_in_ms = payload.get(..4).map(|b| u32::from_be_bytes(b.try_into().unwrap())).unwrap_or(0);
                self.events.push_back(DerpEvent::Restarting { reconnect_in_ms });
            }
            // Keep-alives, pongs, peer-present and unknown frames need no action.
            (_, frame::KEEP_ALIVE | frame::PONG) | _ => {}
        }
        Ok(())
    }

    fn send_client_info(&mut self, server_key: &NodePublicKey) -> Result<(), DerpError> {
        let info = format!(r#"{{"version":{PROTOCOL_VERSION},"CanAckPings":true}}"#);
        let sealed = seal_box(&self.node_private, server_key, info.as_bytes())?;
        let mut payload = Vec::with_capacity(KEY_LEN + sealed.len());
        payload.extend_from_slice(self.node_private.public_key().as_bytes());
        payload.extend_from_slice(&sealed);
        self.write_frame(frame::CLIENT_INFO, &payload)
    }

    fn write_frame(&mut self, typ: u8, payload: &[u8]) -> Result<(), DerpError> {
        self.out_plain.clear();
        self.out_plain.push(typ);
        self.out_plain.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        self.out_plain.extend_from_slice(payload);
        let buf = core::mem::take(&mut self.out_plain);
        let r = self.write_plain(&buf);
        self.out_plain = buf;
        r
    }

    fn write_plain(&mut self, data: &[u8]) -> Result<(), DerpError> {
        self.stream.write(data).map_err(|e| DerpError::Tls(format!("{e:?}")))
    }
}

/// NaCl box (Go's `key.NodePrivate.SealTo`): random nonce || box.
pub fn seal_box(from: &NodePrivateKey, to: &NodePublicKey, msg: &[u8]) -> Result<Vec<u8>, DerpError> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::rng::fill(&mut nonce).map_err(|_| DerpError::Crypto)?;
    let sb = SalsaBox::new(&to.to_crypto_box(), &from.to_crypto_box());
    let ct = sb.encrypt((&nonce).into(), msg).map_err(|_| DerpError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`seal_box`] (Go's `key.NodePrivate.OpenFrom`).
pub fn open_box(to: &NodePrivateKey, from: &NodePublicKey, sealed: &[u8]) -> Result<Vec<u8>, DerpError> {
    if sealed.len() < NONCE_LEN {
        return Err(DerpError::Crypto);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let sb = SalsaBox::new(&from.to_crypto_box(), &to.to_crypto_box());
    sb.decrypt(nonce.into(), ct).map_err(|_| DerpError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(typ: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = alloc::vec![typ];
        f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Splits client output (after the HTTP request) into frames.
    fn frames(mut b: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        while b.len() >= 5 {
            let len = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
            out.push((b[0], b[5..5 + len].to_vec()));
            b = &b[5 + len..];
        }
        out
    }

    #[test]
    fn login_and_relay() {
        crate::rng::seed(&[7; 32]);
        let client_key = NodePrivateKey::from_bytes([1; 32]);
        let server_key = NodePrivateKey::from_bytes([2; 32]);
        let mut c = DerpClient::new("derp.example", SecureStream::plain(), client_key.clone()).unwrap();
        let req = String::from_utf8(c.take_outgoing()).unwrap();
        assert!(req.starts_with("GET /derp HTTP/1.1\r\n") && req.contains("Upgrade: DERP"));

        // Server: 101, then ServerKey.
        let mut input = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n\r\n".to_vec();
        let mut sk = MAGIC.to_vec();
        sk.extend_from_slice(server_key.public_key().as_bytes());
        input.extend(frame(frame::SERVER_KEY, &sk));
        c.feed(&input).unwrap();

        // Client answered with ClientInfo sealed to the server.
        let sent = frames(&c.take_outgoing());
        assert_eq!(sent[0].0, frame::CLIENT_INFO);
        let (pubkey, sealed) = sent[0].1.split_at(32);
        assert_eq!(pubkey, client_key.public_key().as_bytes());
        let info = open_box(&server_key, &client_key.public_key(), sealed).unwrap();
        assert_eq!(info, br#"{"version":2,"CanAckPings":true}"#);

        // ServerInfo completes login.
        let si = seal_box(&server_key, &client_key.public_key(), b"{}").unwrap();
        c.feed(&frame(frame::SERVER_INFO, &si)).unwrap();
        assert_eq!(c.poll_event(), Some(DerpEvent::Ready));

        // Relay a packet each way; answer a ping.
        let peer = NodePrivateKey::from_bytes([3; 32]).public_key();
        c.send_packet(&peer, b"hello").unwrap();
        let sent = frames(&c.take_outgoing());
        assert_eq!(sent[0].0, frame::SEND_PACKET);
        assert_eq!(&sent[0].1[32..], b"hello");
        let mut rp = peer.as_bytes().to_vec();
        rp.extend_from_slice(b"world");
        let mut input = frame(frame::RECV_PACKET, &rp);
        input.extend(frame(frame::PING, b"12345678"));
        c.feed(&input).unwrap();
        assert_eq!(c.poll_event(), Some(DerpEvent::Recv { src: peer, packet: b"world".to_vec() }));
        assert_eq!(frames(&c.take_outgoing())[0], (frame::PONG, b"12345678".to_vec()));
    }
}
