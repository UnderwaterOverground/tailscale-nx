//! "magicsock": choosing between DERP and direct UDP for each peer.
//!
//! Following the Go client's design: WireGuard traffic starts over DERP;
//! meanwhile disco pings go to every candidate endpoint of the peer (and a
//! CallMeMaybe via DERP asks it to ping us back, punching NAT holes). A pong
//! proves a direct path, which then carries traffic while heartbeat pings keep
//! it confirmed. If confirmation lapses, traffic falls back to DERP.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;

use ts_keys::NodePublicKey;
use ts_packet::PacketMut;
use ts_tunnel::PeerId;

use super::{Engine, Event, Io};
use crate::disco::{self, Message};
use crate::time::Instant;

/// How long a pong-confirmed direct path is trusted without a new pong.
const TRUST_UDP_ADDR: Duration = Duration::from_millis(6500);
/// More distinct public mappings than this in one netcheck round means a
/// per-destination ("hard") NAT; see finish_netcheck.
const MAX_PUBLIC_ENDPOINTS: usize = 3;
/// Heartbeat pings on an in-use direct path.
const HEARTBEAT: Duration = Duration::from_secs(3);
/// Minimum spacing of discovery rounds to a peer's endpoints.
const PING_ROUND_INTERVAL: Duration = Duration::from_secs(5);
const CALL_ME_MAYBE_INTERVAL: Duration = Duration::from_secs(5);
/// A peer counts as active this long after traffic.
const SESSION_ACTIVE: Duration = Duration::from_secs(45);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
const STUN_INTERVAL: Duration = Duration::from_secs(23);
const STUN_RETRY: Duration = Duration::from_secs(3);
/// A netcheck round waits this long for STUN replies from all regions.
const NETCHECK_WINDOW: Duration = Duration::from_millis(1500);
const NETCHECK_INTERVAL: Duration = Duration::from_secs(300);
/// WireGuard: if data was sent but nothing received for KEEPALIVE_TIMEOUT +
/// REKEY_TIMEOUT, start a new handshake (ts_tunnel doesn't implement this).
const NO_RESPONSE_REKEY: Duration = Duration::from_secs(15);
/// Minimum spacing of handshakes started because of undecryptable data.
const HANDSHAKE_REPAIR_INTERVAL: Duration = Duration::from_secs(5);
/// Go's magic IP for "via DERP" in pongs: 127.3.3.40:<region>.
const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);
const MAX_CANDIDATES: usize = 16;

/// Where a disco packet came from.
#[derive(Debug, Clone, Copy)]
pub(super) enum Source {
    Udp(SocketAddr),
    Derp { region: u32, node: NodePublicKey },
}

#[derive(Debug, Clone, Copy)]
struct BestAddr {
    addr: SocketAddr,
    latency: Duration,
    confirmed: Instant,
}

#[derive(Default)]
pub(super) struct PathState {
    best: Option<BestAddr>,
    /// Outstanding pings: (tx id, destination, sent at).
    pings: Vec<(disco::TxId, SocketAddr, Instant)>,
    last_round: Option<Instant>,
    last_call_me_maybe: Option<Instant>,
    last_active: Option<Instant>,
    /// Endpoints learned from CallMeMaybe / inbound pings, beyond the netmap's.
    candidates: Vec<SocketAddr>,
    /// First data sent since we last heard anything from the peer.
    unanswered_since: Option<Instant>,
    /// Last time undecryptable data from this peer made us re-handshake.
    last_session_repair: Option<Instant>,
}

impl PathState {
    fn trusted(&self, now: Instant) -> Option<SocketAddr> {
        self.best.filter(|b| now.saturating_duration_since(b.confirmed) < TRUST_UDP_ADDR).map(|b| b.addr)
    }

    fn active(&self, now: Instant) -> bool {
        self.last_active.is_some_and(|t| now.saturating_duration_since(t) < SESSION_ACTIVE)
    }
}

pub(super) struct MagicState {
    pub local_endpoints: Vec<SocketAddr>,
    /// Public (STUN-observed) endpoints. Several when the NAT's mapping
    /// varies by destination; all are advertised, like the Go client does.
    public_endpoints: Vec<SocketAddr>,
    /// Endpoints observed during the running netcheck round.
    netcheck_seen: Vec<SocketAddr>,
    /// What the home region's STUN server saw during the netcheck round.
    netcheck_home_seen: Option<SocketAddr>,
    advertised: Option<(Option<u32>, Vec<SocketAddr>)>,
    /// Outstanding STUN requests: tx id -> (region, sent at).
    stun_probes: alloc::collections::BTreeMap<crate::stun::TxId, (u32, Instant)>,
    pub stun_next: Instant,
    /// Region round-trip times from the latest netcheck.
    region_latency: alloc::collections::BTreeMap<u32, Duration>,
    /// When the running netcheck round ends.
    netcheck_until: Option<Instant>,
    netcheck_next: Instant,
}

impl MagicState {
    pub fn new(now: Instant) -> Self {
        Self {
            local_endpoints: Vec::new(),
            public_endpoints: Vec::new(),
            netcheck_seen: Vec::new(),
            netcheck_home_seen: None,
            advertised: None,
            stun_probes: alloc::collections::BTreeMap::new(),
            stun_next: now + Duration::from_secs(3600),
            region_latency: alloc::collections::BTreeMap::new(),
            netcheck_until: None,
            netcheck_next: now + Duration::from_secs(3600),
        }
    }
}

/// A WireGuard transport message carrying data: type 4, longer than the
/// 32 bytes (header + tag) of an empty keepalive.
fn is_wg_data(wire: &[u8]) -> bool {
    wire.len() > 32 && wire[0] == 4
}

impl Engine {
    /// Sends WireGuard wire packets to a peer over the best known path.
    pub(super) fn transmit(&mut self, wg: PeerId, pkts: Vec<PacketMut>) {
        let Some(&node_id) = self.by_wg.get(&wg.0) else { return };
        let now = self.now;
        let home = self.home_derp;
        let Some(peer) = self.peers.get_mut(&node_id) else { return };
        peer.path.last_active = Some(now);
        // As in WireGuard, only data we send expects an answer: keepalives
        // and handshake messages don't (a peer never replies to keepalives).
        if peer.path.unanswered_since.is_none() && pkts.iter().any(|p| is_wg_data(p.as_ref())) {
            peer.path.unanswered_since = Some(now);
        }
        let direct = peer.path.trusted(now);
        // While a direct path is unproven (or lapsed), keep DERP as the
        // reliable carrier; a stale best address also gets a copy.
        let stale = peer.path.best.map(|b| b.addr).filter(|a| Some(*a) != direct);
        let region = peer.home_derp.or(home);
        let key = peer.key;
        log::trace!(
            "transmit {} to {}: direct={direct:?} stale={stale:?} derp={region:?}",
            pkts.len(),
            peer.name
        );
        for p in pkts {
            let data = p.as_ref().to_vec();
            match direct {
                Some(addr) => self.io.push_back(Io::SendUdp { dst: addr, data }),
                None => {
                    if let Some(addr) = stale {
                        self.io.push_back(Io::SendUdp { dst: addr, data: data.clone() });
                    }
                    if let Some(region) = region {
                        self.derp_send(region, key, data);
                    }
                }
            }
        }
        self.discover(node_id, false);
    }

    /// Records traffic from a peer (keeps discovery/heartbeats running).
    pub(super) fn note_active(&mut self, node_id: i64, _udp_src: Option<SocketAddr>) {
        if let Some(p) = self.peers.get_mut(&node_id) {
            p.path.last_active = Some(self.now);
            p.path.unanswered_since = None;
        }
    }

    /// The peer sent transport data for a session we don't have (we
    /// restarted or reset it). It will keep doing so until a new handshake,
    /// so start one now instead of waiting for its rekey timers.
    pub(super) fn repair_session(&mut self, node_id: i64) {
        let now = self.now;
        let Some(p) = self.peers.get_mut(&node_id) else { return };
        if p.path.last_session_repair.is_some_and(|t| now.saturating_duration_since(t) < HANDSHAKE_REPAIR_INTERVAL) {
            return;
        }
        p.path.last_session_repair = Some(now);
        log::info!("{} sent data for an unknown WireGuard session; re-handshaking", p.name);
        let wg = p.wg;
        // A keepalive (empty packet) makes the tunnel initiate a handshake.
        let res = self.wg.send(now, [(wg, alloc::vec![PacketMut::from(Vec::new())])]);
        for (peer, pkts) in res.to_peers {
            self.transmit(peer, pkts);
        }
    }

    /// Finds the peer behind an underlay source (DERP node key or UDP address).
    pub(super) fn peer_for_source(&self, derp_src: Option<&NodePublicKey>, udp_src: Option<SocketAddr>) -> Option<i64> {
        if let Some(k) = derp_src {
            return self.by_key.get(&super::key_bytes(k)).copied();
        }
        let addr = udp_src?;
        self.peers.iter().find_map(|(id, p)| {
            let known = p.path.best.is_some_and(|b| b.addr == addr)
                || p.endpoints.contains(&addr)
                || p.path.candidates.contains(&addr);
            known.then_some(*id)
        })
    }

    /// Drops the WireGuard session with a peer so the next packet starts a
    /// fresh handshake.
    pub(super) fn reset_wg_session(&mut self, node_id: i64, why: &str) {
        let Some(p) = self.peers.get_mut(&node_id) else { return };
        log::info!("resetting WireGuard session with {}: {why}", p.name);
        p.path.unanswered_since = None;
        let (wg, key) = (p.wg, p.key);
        self.wg.remove_peer(wg);
        self.wg.upsert_peer(ts_tunnel::PeerConfig::new(wg, key, [0; 32]));
    }

    /// Pings the peer's candidate endpoints if due, and asks it (via DERP)
    /// to ping us back. `force` skips the rate limit (CallMeMaybe received).
    fn discover(&mut self, node_id: i64, force: bool) {
        let now = self.now;
        let our_endpoints = self.advertised_endpoints();
        let Some(peer) = self.peers.get_mut(&node_id) else { return };
        let Some(their_disco) = peer.disco else { return };
        let path = &mut peer.path;
        path.pings.retain(|(_, _, sent)| now.saturating_duration_since(*sent) < PING_TIMEOUT);

        let mut targets: Vec<SocketAddr> = Vec::new();
        let round_due = force || path.last_round.is_none_or(|t| now.saturating_duration_since(t) >= PING_ROUND_INTERVAL);
        match path.trusted(now) {
            // Healthy direct path: just heartbeat it.
            Some(addr) => {
                let last = path.best.map(|b| b.confirmed).unwrap_or(now);
                let pinged_recently = path.pings.iter().any(|(_, a, _)| *a == addr);
                if now.saturating_duration_since(last) >= HEARTBEAT && !pinged_recently {
                    targets.push(addr);
                }
            }
            None if round_due => {
                path.last_round = Some(now);
                for ep in peer.endpoints.iter().chain(path.candidates.iter()) {
                    if !targets.contains(ep) && is_usable(ep) {
                        targets.push(*ep);
                    }
                }
            }
            None => {}
        }
        let send_cmm = path.trusted(now).is_none()
            && !our_endpoints.is_empty()
            && (force || path.last_call_me_maybe.is_none_or(|t| now.saturating_duration_since(t) >= CALL_ME_MAYBE_INTERVAL));
        if send_cmm {
            path.last_call_me_maybe = Some(now);
        }
        let region = peer.home_derp.or(self.home_derp);
        let peer_key = peer.key;

        for addr in targets {
            let mut tx_id = [0u8; 12];
            if crate::rng::fill(&mut tx_id).is_err() {
                return;
            }
            let msg = Message::Ping { tx_id, node_key: None };
            if let Some(pkt) = self.seal_disco(&their_disco, &msg) {
                if let Some(p) = self.peers.get_mut(&node_id) {
                    p.path.pings.push((tx_id, addr, now));
                }
                self.io.push_back(Io::SendUdp { dst: addr, data: pkt });
            }
        }
        if send_cmm {
            if let (Some(region), Some(pkt)) =
                (region, self.seal_disco(&their_disco, &Message::CallMeMaybe { endpoints: our_endpoints }))
            {
                self.derp_send(region, peer_key, pkt);
            }
        }
    }

    fn seal_disco(&self, to: &ts_keys::DiscoPublicKey, msg: &Message) -> Option<Vec<u8>> {
        disco::seal(&self.disco_private, to, &self.node_private.public_key(), msg)
    }

    pub(super) fn handle_disco(&mut self, source: Source, pkt: &[u8]) {
        let Some((from, msg)) = disco::open(&self.disco_private, pkt) else {
            log::debug!("undecryptable disco packet from {source:?}");
            return;
        };
        let Some(&node_id) = self.by_disco.get(&super::disco_bytes(&from)) else {
            log::debug!("disco from unknown key via {source:?}");
            return;
        };
        let now = self.now;

        match msg {
            Message::Ping { tx_id, .. } => {
                let observed = match source {
                    Source::Udp(addr) => addr,
                    Source::Derp { region, .. } => SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), region as u16),
                };
                let Some(pong) = self.seal_disco(&from, &Message::Pong { tx_id, src: observed }) else { return };
                match source {
                    Source::Udp(addr) => {
                        self.io.push_back(Io::SendUdp { dst: addr, data: pong });
                        // A ping from a new address is a path candidate: probe it.
                        let mut probe = false;
                        if let Some(p) = self.peers.get_mut(&node_id) {
                            if !p.path.candidates.contains(&addr) && !p.endpoints.contains(&addr) {
                                p.path.candidates.push(addr);
                                p.path.candidates.truncate(MAX_CANDIDATES);
                                probe = p.path.trusted(now).is_none();
                            }
                        }
                        if probe {
                            self.discover(node_id, true);
                        }
                    }
                    Source::Derp { region, node } => self.derp_send(region, node, pong),
                }
            }
            Message::Pong { tx_id, src: _ } => {
                let Some(peer) = self.peers.get_mut(&node_id) else { return };
                let Some(i) = peer.path.pings.iter().position(|(id, _, _)| *id == tx_id) else { return };
                let (_, addr, sent) = peer.path.pings.swap_remove(i);
                let latency = now.saturating_duration_since(sent);
                // Only a pong received directly from that address proves the path.
                if !matches!(source, Source::Udp(a) if a == addr) {
                    return;
                }
                let better = match peer.path.best {
                    None => true,
                    Some(b) if b.addr == addr => true,
                    // Switch only for a clearly better path, or if ours lapsed.
                    Some(b) => {
                        latency + Duration::from_millis(1) < b.latency * 9 / 10
                            || now.saturating_duration_since(b.confirmed) >= TRUST_UDP_ADDR
                    }
                };
                if better {
                    let changed = peer.path.best.is_none_or(|b| b.addr != addr);
                    peer.path.best = Some(BestAddr { addr, latency, confirmed: now });
                    if changed {
                        let name = peer.name.clone();
                        log::info!("direct path to {name}: {addr} ({latency:?})");
                        self.events.push_back(Event::PeerPath { peer: name, direct: Some(addr) });
                    }
                }
            }
            Message::CallMeMaybe { endpoints } => {
                if let Some(p) = self.peers.get_mut(&node_id) {
                    for ep in endpoints {
                        if !p.path.candidates.contains(&ep) && !p.endpoints.contains(&ep) {
                            p.path.candidates.push(ep);
                        }
                    }
                    p.path.candidates.truncate(MAX_CANDIDATES);
                    p.path.last_active = Some(now);
                }
                self.discover(node_id, true);
            }
        }
    }

    /// Periodic work: STUN refresh, heartbeats, noticing lapsed paths.
    pub(super) fn magic_tick(&mut self) {
        let now = self.now;
        if self.magic.netcheck_until.is_some_and(|t| now >= t) {
            self.finish_netcheck();
        } else if self.magic.netcheck_until.is_none() && now >= self.magic.netcheck_next {
            self.start_netcheck();
        }
        if now >= self.magic.stun_next {
            self.send_stun();
        }
        let ids: Vec<i64> = self.peers.keys().copied().collect();
        for id in ids {
            if self.peers.get(&id).and_then(|p| p.path.unanswered_since).is_some_and(|t| now.saturating_duration_since(t) >= NO_RESPONSE_REKEY) {
                self.reset_wg_session(id, "no response for 15s");
            }
            let Some(p) = self.peers.get_mut(&id) else { continue };
            if let Some(b) = p.path.best {
                // Drop paths that have been unconfirmed for a long time.
                if now.saturating_duration_since(b.confirmed) > TRUST_UDP_ADDR * 4 {
                    p.path.best = None;
                    let name = p.name.clone();
                    self.events.push_back(Event::PeerPath { peer: name, direct: None });
                }
            }
            if self.peers.get(&id).is_some_and(|p| p.path.active(now)) {
                self.discover(id, false);
            }
        }
    }

    pub(super) fn magic_deadline(&self) -> Instant {
        let mut t = self.magic.stun_next.min(self.magic.netcheck_next);
        if let Some(n) = self.magic.netcheck_until {
            t = t.min(n);
        }
        for p in self.peers.values() {
            if let Some(u) = p.path.unanswered_since {
                t = t.min(u + NO_RESPONSE_REKEY);
            }
        }
        for p in self.peers.values() {
            if p.path.active(self.now) {
                // Heartbeats and discovery rounds are on second granularity.
                t = t.min(self.now + Duration::from_secs(1));
                break;
            }
        }
        t
    }

    /// Sends one STUN binding request to `region`'s STUN server.
    fn stun_probe(&mut self, region: u32) -> bool {
        let Some(server) = self.derp_nodes.get(&region).and_then(|n| n.stun) else { return false };
        let mut tx = [0u8; 12];
        if crate::rng::fill(&mut tx).is_err() {
            return false;
        }
        self.magic.stun_probes.insert(tx, (region, self.now));
        self.io.push_back(Io::SendUdp { dst: server, data: crate::stun::request(&tx).to_vec() });
        true
    }

    /// Keeps our NAT mapping and public endpoint fresh via the home region.
    fn send_stun(&mut self) {
        let now = self.now;
        // Forget probes that will never be answered.
        self.magic.stun_probes.retain(|_, (_, sent)| now.saturating_duration_since(*sent) < Duration::from_secs(10));
        let ok = self.home_derp.is_some_and(|r| self.stun_probe(r));
        // Retry soon if no answer; a response pushes this out to the full interval.
        self.magic.stun_next = now + if ok { STUN_RETRY } else { STUN_INTERVAL };
    }

    /// Probes every region's STUN server to measure latency (Go: netcheck).
    pub(super) fn start_netcheck(&mut self) {
        let regions: Vec<u32> = self.derp_nodes.keys().copied().collect();
        let probed = regions.into_iter().filter(|r| self.stun_probe(*r)).count();
        self.magic.region_latency.clear();
        if probed == 0 {
            // No STUN anywhere: fall back to the lowest region id.
            if let Some(&r) = self.derp_nodes.keys().next() {
                self.set_home_derp(r);
            }
            self.magic.netcheck_next = self.now + NETCHECK_INTERVAL;
            return;
        }
        log::debug!("netcheck: probing {probed} regions");
        self.magic.netcheck_seen.clear();
        self.magic.netcheck_home_seen = None;
        self.magic.netcheck_until = Some(self.now + NETCHECK_WINDOW);
    }

    fn finish_netcheck(&mut self) {
        self.magic.netcheck_until = None;
        self.magic.netcheck_next = self.now + NETCHECK_INTERVAL;
        let lat = &self.magic.region_latency;
        let best = lat.iter().min_by_key(|(_, d)| **d).map(|(r, d)| (*r, *d));
        let current = self.home_derp.and_then(|r| lat.get(&r).copied());
        log::info!(
            "netcheck: {} of {} regions answered; best {:?}",
            lat.len(),
            self.derp_nodes.len(),
            best
        );
        // Advertise every public endpoint this round observed (a NAT with
        // destination-dependent mapping shows several).
        let mut seen = core::mem::take(&mut self.magic.netcheck_seen);
        let home_seen = self.magic.netcheck_home_seen.take();
        seen.sort();
        if seen.len() > MAX_PUBLIC_ENDPOINTS {
            // A new port per destination (carrier NAT, hotspots): peers can't
            // reach any of these directly, so don't flood the netmap with
            // them. Like Go, advertise one and let traffic use DERP.
            let keep = home_seen.filter(|a| seen.contains(a)).unwrap_or(seen[0]);
            log::info!("NAT maps each destination to a new port ({} seen); advertising {keep} only", seen.len());
            seen = alloc::vec![keep];
        }
        if !seen.is_empty() && seen != self.magic.public_endpoints {
            if seen.len() > 1 {
                log::info!("NAT mapping varies by destination: {seen:?}");
            }
            self.magic.public_endpoints = seen;
            self.update_endpoints();
        }
        let choice = match (best, current) {
            (None, None) if self.home_derp.is_none() => self.derp_nodes.keys().next().copied(),
            (None, _) => None,
            (Some((r, _)), None) => Some(r),
            // Only move for a clear improvement (Go uses a similar hysteresis).
            (Some((r, d)), Some(cur)) if d * 3 < cur * 2 => Some(r),
            _ => None,
        };
        if let Some(r) = choice {
            self.set_home_derp(r);
        }
    }

    pub(super) fn handle_stun(&mut self, pkt: &[u8]) {
        let Some((tx, addr)) = crate::stun::parse_response(pkt) else {
            log::debug!("STUN: unparseable {}-byte response", pkt.len());
            return;
        };
        let Some((region, sent)) = self.magic.stun_probes.remove(&tx) else { return };
        let rtt = self.now.saturating_duration_since(sent);
        if self.magic.netcheck_until.is_some() {
            self.magic.region_latency.insert(region, rtt);
            if self.magic.region_latency.len() == self.derp_nodes.values().filter(|n| n.stun.is_some()).count() {
                self.finish_netcheck();
            }
        }
        if Some(region) == self.home_derp {
            self.magic.stun_next = self.now + STUN_INTERVAL;
        }
        log::debug!("STUN: region {region} sees us as {addr} ({rtt:?})");
        if self.magic.netcheck_until.is_some() {
            // Collected and advertised together when the round ends.
            if Some(region) == self.home_derp {
                self.magic.netcheck_home_seen = Some(addr);
            }
            if !self.magic.netcheck_seen.contains(&addr) {
                self.magic.netcheck_seen.push(addr);
            }
        } else if !self.magic.public_endpoints.contains(&addr) && self.magic.public_endpoints.len() < MAX_PUBLIC_ENDPOINTS {
            // Between netchecks (home keepalive): the mapping changed.
            log::info!("STUN: new public endpoint {addr} (via region {region})");
            self.magic.public_endpoints.push(addr);
            self.magic.public_endpoints.sort();
            self.update_endpoints();
        }
    }

    fn advertised_endpoints(&self) -> Vec<SocketAddr> {
        let mut eps: Vec<SocketAddr> = Vec::new();
        for ep in self.magic.public_endpoints.iter().chain(self.magic.local_endpoints.iter()) {
            if !eps.contains(ep) {
                eps.push(*ep);
            }
        }
        eps
    }

    /// Pushes our home DERP and endpoints to control when they change.
    pub(super) fn update_endpoints(&mut self) {
        let eps = self.advertised_endpoints();
        let current = (self.home_derp, eps.clone());
        if self.magic.advertised.as_ref() == Some(&current) {
            return;
        }
        self.magic.advertised = Some(current);
        self.control.set_net_info(self.home_derp, eps.clone());
        self.events.push_back(Event::Endpoints(eps));
    }
}

fn is_usable(ep: &SocketAddr) -> bool {
    ep.port() != 0 && !ep.ip().is_unspecified() && !ep.ip().is_multicast()
}

#[cfg(test)]
mod tests {
    use super::is_wg_data;

    #[test]
    fn keepalives_and_handshakes_are_not_data() {
        let keepalive = [4u8, 0, 0, 0].iter().copied().chain([0u8; 28]).collect::<alloc::vec::Vec<_>>();
        assert!(!is_wg_data(&keepalive));
        assert!(!is_wg_data(&[1u8; 148])); // handshake initiation
        assert!(!is_wg_data(&[2u8; 92])); // handshake response
        let mut data = keepalive.clone();
        data.extend_from_slice(&[0u8; 16]);
        assert!(is_wg_data(&data));
    }
}
