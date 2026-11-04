//! Peer relays: paths through another tailnet node running Tailscale's UDP
//! relay server (Go: net/udprelay), for peers we can't reach directly.
//!
//! Only the joining side is implemented. A Go peer that may use a relay
//! allocates an endpoint on it for the two of us and sends a CallMeMaybeVia
//! over DERP. We bind to it (Bind, Challenge, Answer, sealed to the server's
//! disco key), then ping the peer through it; a pong makes it the path for
//! WireGuard until a direct path is confirmed. Everything through the server
//! carries an 8-byte Geneve header naming the endpoint (its VNI).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;

use ts_keys::DiscoPublicKey;

use super::magic::{Source, HEARTBEAT, PING_TIMEOUT, TRUST_UDP_ADDR};
use super::{Engine, Io};
use crate::disco::{self, BindStep, Message, RelayEndpoint};
use crate::time::Instant;

const GENEVE_LEN: usize = 8;
const PROTO_DISCO: u16 = 0x7A11;
const PROTO_WIREGUARD: u16 = 0x7A12;
/// Go gives up on a bind handshake after this long, whatever the server says.
const MAX_BIND_TIME: Duration = Duration::from_secs(30);
/// Bind messages are resent this often until the server answers.
const BIND_RETRY: Duration = Duration::from_secs(2);

/// Our side of an endpoint on a peer relay server.
pub(super) struct RelayPath {
    server_disco: DiscoPublicKey,
    vni: u32,
    addrs: Vec<SocketAddr>,
    generation: u32,
    offered: Instant,
    last_bind: Instant,
    bind_lifetime: Duration,
    steady_lifetime: Duration,
    /// The server address that challenged us: where the path goes.
    bound: Option<SocketAddr>,
    pings: Vec<(disco::TxId, Instant)>,
    /// The last pong through the relay, and its round trip.
    confirmed: Option<(Instant, Duration)>,
}

impl RelayPath {
    /// Where to send, while a pong has confirmed the path recently.
    pub(super) fn trusted(&self, now: Instant) -> Option<(SocketAddr, u32)> {
        let (at, _) = self.confirmed?;
        (now.saturating_duration_since(at) < TRUST_UDP_ADDR).then_some((self.bound?, self.vni))
    }

    fn expired(&self, now: Instant) -> bool {
        match self.confirmed {
            Some((at, _)) => now.saturating_duration_since(at) >= self.steady_lifetime,
            None => now.saturating_duration_since(self.offered) >= self.bind_lifetime.min(MAX_BIND_TIME),
        }
    }
}

/// Prefixes `payload` with a Geneve header.
pub(super) fn geneve(proto: u16, vni: u32, control: bool, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(GENEVE_LEN + payload.len());
    b.extend_from_slice(&[0, if control { 0x80 } else { 0 }]);
    b.extend_from_slice(&proto.to_be_bytes());
    b.extend_from_slice(&(vni << 8).to_be_bytes());
    b.extend_from_slice(payload);
    b
}

/// A Geneve header as relays send it: (protocol, VNI, control). Neither
/// WireGuard (bytes 2-3 are zero) nor disco (0xf09f) can look like one.
fn parse_geneve(b: &[u8]) -> Option<(u16, u32, bool)> {
    if b.len() < GENEVE_LEN || b[0] & 0xC0 != 0 || b[1] & 0x3F != 0 || b[7] != 0 {
        return None;
    }
    let proto = u16::from_be_bytes([b[2], b[3]]);
    if proto != PROTO_DISCO && proto != PROTO_WIREGUARD {
        return None;
    }
    let vni = u32::from_be_bytes(b[4..8].try_into().unwrap()) >> 8;
    Some((proto, vni, b[1] & 0x80 != 0))
}

pub(super) fn wrap_wireguard(vni: u32, data: &[u8]) -> Vec<u8> {
    geneve(PROTO_WIREGUARD, vni, false, data)
}

impl Engine {
    /// A datagram with a Geneve header, from a peer relay server. False if
    /// it isn't one.
    pub(super) fn handle_relayed(&mut self, src: SocketAddr, data: &[u8]) -> bool {
        let Some((proto, vni, control)) = parse_geneve(data) else { return false };
        let inner = &data[GENEVE_LEN..];
        match proto {
            PROTO_DISCO if control => self.handle_relay_server(src, vni, inner),
            PROTO_DISCO => self.handle_disco(Source::Relay { addr: src, vni }, inner),
            _ => {
                let from = self.peers.values().find(|p| p.path.relay.as_ref().is_some_and(|r| r.vni == vni && r.bound == Some(src)));
                match from {
                    Some(p) => {
                        let key = p.key;
                        self.handle_wg(inner.to_vec(), None, Some(key));
                    }
                    None => log::debug!("relayed WireGuard from {src} for unknown VNI {vni}"),
                }
            }
        }
        true
    }

    /// A peer offered us an endpoint on a relay server.
    pub(super) fn handle_call_me_maybe_via(&mut self, node_id: i64, ep: RelayEndpoint) {
        let ours = self.disco_private.public_key();
        let now = self.now;
        let Some(peer) = self.peers.get_mut(&node_id) else { return };
        let Some(theirs) = peer.disco else { return };
        if !ep.client_disco.contains(&ours) || !ep.client_disco.contains(&theirs) || ep.addrs.is_empty() {
            log::debug!("relay endpoint from {} isn't for the two of us", peer.name);
            return;
        }
        // Direct paths win; and a repeat of the endpoint we have changes nothing.
        if peer.path.trusted(now).is_some()
            || peer.path.relay.as_ref().is_some_and(|r| r.server_disco == ep.server_disco && r.vni == ep.vni)
        {
            return;
        }
        let mut generation = [0u8; 4];
        if crate::rng::fill(&mut generation).is_err() {
            return;
        }
        log::info!("{} offered a peer relay path via {:?} (VNI {})", peer.name, ep.addrs, ep.vni);
        peer.path.relay = Some(Box::new(RelayPath {
            server_disco: ep.server_disco,
            vni: ep.vni,
            addrs: ep.addrs,
            generation: u32::from_ne_bytes(generation) | 1,
            offered: now,
            last_bind: now,
            bind_lifetime: ep.bind_lifetime,
            steady_lifetime: ep.steady_lifetime,
            bound: None,
            pings: Vec::new(),
            confirmed: None,
        }));
        peer.path.last_active = Some(now);
        self.send_relay_bind(node_id);
    }

    fn send_relay_bind(&mut self, node_id: i64) {
        let Some(peer) = self.peers.get(&node_id) else { return };
        let (Some(theirs), Some(r)) = (peer.disco, peer.path.relay.as_deref()) else { return };
        let bind = Message::RelayBind { step: BindStep::Bind, vni: r.vni, generation: r.generation, remote: theirs, challenge: [0; 32] };
        let Some(pkt) = self.seal_disco(&r.server_disco, &bind) else { return };
        let pkt = geneve(PROTO_DISCO, r.vni, true, &pkt);
        for &dst in &r.addrs {
            self.io.push_back(Io::SendUdp { dst, data: pkt.clone() });
        }
    }

    /// A control message from a relay server: its challenge to our bind.
    fn handle_relay_server(&mut self, src: SocketAddr, vni: u32, pkt: &[u8]) {
        let Some((from, msg)) = disco::open(&self.disco_private, pkt) else { return };
        let Message::RelayBind { step: BindStep::Challenge, vni: msg_vni, generation, remote, challenge } = msg else { return };
        let Some((&node_id, peer)) = self.peers.iter_mut().find(|(_, p)| {
            p.path.relay.as_ref().is_some_and(|r| r.server_disco == from && r.vni == vni && r.generation == generation)
        }) else {
            return;
        };
        let (Some(theirs), Some(r)) = (peer.disco, peer.path.relay.as_deref_mut()) else { return };
        if msg_vni != vni || remote != theirs || !r.addrs.contains(&src) || r.bound.is_some() {
            return;
        }
        r.bound = Some(src);
        let answer = Message::RelayBind { step: BindStep::Answer, vni, generation, remote, challenge };
        let server = r.server_disco;
        log::debug!("relay {src} challenged our bind for {}", peer.name);
        let Some(pkt) = self.seal_disco(&server, &answer) else { return };
        self.io.push_back(Io::SendUdp { dst: src, data: geneve(PROTO_DISCO, vni, true, &pkt) });
        self.relay_ping(node_id);
    }

    /// Pings the peer through its relay path.
    pub(super) fn relay_ping(&mut self, node_id: i64) {
        let now = self.now;
        let mut tx_id = [0u8; 12];
        if crate::rng::fill(&mut tx_id).is_err() {
            return;
        }
        let Some(peer) = self.peers.get(&node_id) else { return };
        let (Some(theirs), Some(r)) = (peer.disco, peer.path.relay.as_deref()) else { return };
        let (Some(dst), vni) = (r.bound, r.vni) else { return };
        let Some(pkt) = self.seal_disco(&theirs, &Message::Ping { tx_id, node_key: None }) else { return };
        self.io.push_back(Io::SendUdp { dst, data: geneve(PROTO_DISCO, vni, false, &pkt) });
        if let Some(r) = self.peers.get_mut(&node_id).and_then(|p| p.path.relay.as_deref_mut()) {
            r.pings.retain(|(_, sent)| now.saturating_duration_since(*sent) < PING_TIMEOUT);
            r.pings.push((tx_id, now));
        }
    }

    /// Disco from a peer through its relay path.
    pub(super) fn handle_relayed_disco(&mut self, node_id: i64, addr: SocketAddr, vni: u32, msg: Message) {
        let now = self.now;
        let Some(peer) = self.peers.get_mut(&node_id) else { return };
        let Some(r) = peer.path.relay.as_deref_mut().filter(|r| r.vni == vni && r.bound == Some(addr)) else { return };
        match msg {
            Message::Ping { tx_id, .. } => {
                let unconfirmed = r.confirmed.is_none();
                let Some(theirs) = peer.disco else { return };
                let Some(pong) = self.seal_disco(&theirs, &Message::Pong { tx_id, src: addr }) else { return };
                self.io.push_back(Io::SendUdp { dst: addr, data: geneve(PROTO_DISCO, vni, false, &pong) });
                // Our first ping may have arrived before the peer had bound.
                if unconfirmed {
                    self.relay_ping(node_id);
                }
            }
            Message::Pong { tx_id, .. } => {
                let Some(i) = r.pings.iter().position(|(id, _)| *id == tx_id) else { return };
                let (_, sent) = r.pings.swap_remove(i);
                let latency = now.saturating_duration_since(sent);
                if r.confirmed.is_none() {
                    log::info!("peer relay path to {}: {addr} ({latency:?})", peer.name);
                }
                r.confirmed = Some((now, latency));
            }
            _ => {}
        }
    }

    /// Keeps a relay path in use confirmed, retries binds, drops it once
    /// the server will have.
    pub(super) fn relay_tick(&mut self, node_id: i64) {
        let now = self.now;
        let Some(peer) = self.peers.get_mut(&node_id) else { return };
        let wanted = peer.path.trusted(now).is_none() && peer.path.active(now);
        let Some(r) = peer.path.relay.as_deref_mut() else { return };
        if r.expired(now) {
            log::debug!("peer relay path to {} expired", peer.name);
            peer.path.relay = None;
            return;
        }
        if r.bound.is_none() {
            if now.saturating_duration_since(r.last_bind) >= BIND_RETRY {
                r.last_bind = now;
                self.send_relay_bind(node_id);
            }
            return;
        }
        let last = r.confirmed.map_or(r.offered, |(at, _)| at);
        let pinged = r.pings.iter().any(|(_, sent)| now.saturating_duration_since(*sent) < HEARTBEAT);
        if wanted && now.saturating_duration_since(last) >= HEARTBEAT && !pinged {
            self.relay_ping(node_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geneve_headers_round_trip_and_never_match_wireguard_or_disco() {
        let pkt = geneve(PROTO_WIREGUARD, 0x12_3456, false, &[4, 0, 0, 0]);
        assert_eq!(&pkt[..8], &[0, 0, 0x7A, 0x12, 0x12, 0x34, 0x56, 0]);
        assert_eq!(parse_geneve(&pkt), Some((PROTO_WIREGUARD, 0x12_3456, false)));
        assert_eq!(parse_geneve(&geneve(PROTO_DISCO, 1, true, &[])), Some((PROTO_DISCO, 1, true)));
        let mut wg = [0u8; 32];
        wg[0] = 4;
        assert_eq!(parse_geneve(&wg), None);
        let mut d = [0u8; 62];
        d[..6].copy_from_slice(disco::MAGIC);
        assert_eq!(parse_geneve(&d), None);
    }
}
