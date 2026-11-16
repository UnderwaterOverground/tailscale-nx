//! "magicsock": choosing between DERP and direct UDP for each peer.
//!
//! Following the Go client's design: WireGuard traffic starts over DERP;
//! meanwhile disco pings go to every candidate endpoint of the peer (and a
//! CallMeMaybe via DERP asks it to ping us back, punching NAT holes). A pong
//! proves a direct path, which then carries traffic while heartbeat pings keep
//! it confirmed. If confirmation lapses, traffic falls back to DERP. While a
//! peer is relayed, each round also pings it through DERP, to time that path.
//! Between the two, a peer relay path (relay.rs) beats DERP when there is one.

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
pub(super) const TRUST_UDP_ADDR: Duration = Duration::from_millis(6500);
/// More distinct public mappings than this in one netcheck round means a
/// per-destination ("hard") NAT; see finish_netcheck.
const MAX_PUBLIC_ENDPOINTS: usize = 3;
/// Heartbeat pings on an in-use direct path.
pub(super) const HEARTBEAT: Duration = Duration::from_secs(3);
/// Minimum spacing of discovery rounds to a peer's endpoints.
const PING_ROUND_INTERVAL: Duration = Duration::from_secs(5);
const CALL_ME_MAYBE_INTERVAL: Duration = Duration::from_secs(5);
/// A peer counts as active this long after traffic.
const SESSION_ACTIVE: Duration = Duration::from_secs(45);
/// A relayed path's measured round trip is shown for this long.
const RELAY_LATENCY_FRESH: Duration = Duration::from_secs(15);
pub(super) const PING_TIMEOUT: Duration = Duration::from_secs(5);
const STUN_INTERVAL: Duration = Duration::from_secs(23);
const STUN_RETRY: Duration = Duration::from_secs(3);
/// A netcheck round waits this long for STUN replies from all regions.
const NETCHECK_WINDOW: Duration = Duration::from_millis(1500);
const NETCHECK_INTERVAL: Duration = Duration::from_secs(300);
/// With no STUN replies (UDP blocked), regions are timed by a TCP connect
/// to their DERP server instead (Go uses HTTPS), one at a time: on the
/// console each TCP socket takes 32 KB of the shared socket memory.
const TCP_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// Connect times this close together across 3+ regions mean they were
/// answered locally (see finish_tcp_probe).
const TCP_PROBE_UNIFORM: Duration = Duration::from_millis(10);
/// WireGuard: if data was sent but nothing received for KEEPALIVE_TIMEOUT +
/// REKEY_TIMEOUT, start a new handshake (ts_tunnel doesn't implement this).
const NO_RESPONSE_REKEY: Duration = Duration::from_secs(15);
/// Minimum spacing of handshakes started because of undecryptable data.
const HANDSHAKE_REPAIR_INTERVAL: Duration = Duration::from_secs(5);
/// Go's magic IP for "via DERP" in pongs: 127.3.3.40:<region>.
const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);
const MAX_CANDIDATES: usize = 16;
/// A peer in use without a direct path this long gets one log line saying
/// so: it's the usual reason a stream is slow.
const NO_DIRECT_NOTICE: Duration = Duration::from_secs(30);
/// While a peer is in use the engine ticks every second; a longer gap means
/// the console slept, and that time doesn't count towards NO_DIRECT_NOTICE.
const TICK_GAP: Duration = Duration::from_secs(5);

/// Where a disco packet came from.
#[derive(Debug, Clone, Copy)]
pub(super) enum Source {
    Udp(SocketAddr),
    Derp { region: u32, node: NodePublicKey },
    /// Through a peer relay server at `addr`, on its endpoint `vni`.
    Relay { addr: SocketAddr, vni: u32 },
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
    pub(super) last_active: Option<Instant>,
    /// Endpoints learned from CallMeMaybe / inbound pings, beyond the netmap's.
    candidates: Vec<SocketAddr>,
    /// First data sent since we last heard anything from the peer.
    unanswered_since: Option<Instant>,
    /// Last time undecryptable data from this peer made us re-handshake.
    last_session_repair: Option<Instant>,
    /// The last round trip of a ping through DERP, and when it came back.
    relay_latency: Option<(Duration, Instant)>,
    /// An endpoint on a peer relay server, offered by the peer.
    pub(super) relay: Option<alloc::boxed::Box<super::relay::RelayPath>>,
    /// Since when the peer has been in use without a direct path, and
    /// whether the log has said so.
    relayed_since: Option<Instant>,
    told_relayed: bool,
}

impl PathState {
    pub(super) fn trusted(&self, now: Instant) -> Option<SocketAddr> {
        self.best.filter(|b| now.saturating_duration_since(b.confirmed) < TRUST_UDP_ADDR).map(|b| b.addr)
    }

    pub(super) fn active(&self, now: Instant) -> bool {
        self.last_active.is_some_and(|t| now.saturating_duration_since(t) < SESSION_ACTIVE)
    }

    #[cfg(test)]
    pub(super) fn for_test(last_active: Option<Instant>, direct: Option<(SocketAddr, Instant)>) -> Self {
        let best = direct.map(|(addr, confirmed)| BestAddr { addr, latency: Duration::from_millis(4), confirmed });
        PathState { last_active, best, ..Default::default() }
    }
}

/// A peer we've sent to recently, and how that traffic travels.
#[derive(Debug, PartialEq, Eq)]
pub struct ActivePeer<'a> {
    /// The first label of its name ("gaming-pc", not the full MagicDNS name).
    pub name: &'a str,
    pub path: Path,
    /// The path's round trip: from its last pong, or for DERP, the last ping
    /// through DERP (None until measured).
    pub latency: Option<Duration>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Path {
    /// A confirmed direct path.
    Direct,
    /// Through a peer relay (relay.rs).
    PeerRelay,
    /// Relayed through this DERP region (0 if no region is known yet).
    Derp(u32),
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
    last_tick: Instant,
    /// The running TCP timing round (see TCP_PROBE_TIMEOUT).
    tcp_probe: Option<TcpProbe>,
}

pub(super) struct TcpProbe {
    /// Regions are timed in id order: the last one started.
    last: Option<u32>,
    /// The connect being timed: (connection, region, started).
    current: Option<(super::ConnId, u32, Instant)>,
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
            last_tick: now,
            tcp_probe: None,
        }
    }
}

/// A WireGuard transport message carrying data: type 4, longer than the
/// 32 bytes (header + tag) of an empty keepalive.
fn is_wg_data(wire: &[u8]) -> bool {
    wire.len() > 32 && wire[0] == 4
}

impl Engine {
    /// Peers we've sent to in the last SESSION_ACTIVE, most recent first.
    pub fn active_peers(&self) -> Vec<ActivePeer<'_>> {
        let now = self.now;
        let mut peers: Vec<(Instant, ActivePeer<'_>)> = self
            .peers
            .values()
            .filter(|p| p.path.active(now))
            .filter_map(|p| {
                let peer_relay = p.path.relay.as_ref().filter(|r| r.trusted(now).is_some());
                let (path, latency) = match (p.path.trusted(now), peer_relay) {
                    (Some(_), _) => (Path::Direct, p.path.best.map(|b| b.latency)),
                    (None, Some(r)) => (Path::PeerRelay, r.latency()),
                    (None, None) => {
                        let fresh = p.path.relay_latency.filter(|(_, at)| now.saturating_duration_since(*at) < RELAY_LATENCY_FRESH);
                        (Path::Derp(p.home_derp.or(self.home_derp).unwrap_or(0)), fresh.map(|(l, _)| l))
                    }
                };
                let name = p.name.split('.').next().unwrap_or_default();
                Some((p.path.last_active?, ActivePeer { name, path, latency }))
            })
            .collect();
        peers.sort_by(|a, b| b.0.cmp(&a.0));
        peers.into_iter().map(|(_, p)| p).collect()
    }

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
        let relayed = peer.path.relay.as_ref().and_then(|r| r.trusted(now)).filter(|_| direct.is_none());
        // While a direct path is unproven (or lapsed), keep DERP as the
        // reliable carrier; a stale best address also gets a copy.
        let stale = peer.path.best.map(|b| b.addr).filter(|a| Some(*a) != direct);
        let region = peer.home_derp.or(home);
        let key = peer.key;
        log::trace!(
            "transmit {} to {}: direct={direct:?} relay={relayed:?} stale={stale:?} derp={region:?}",
            pkts.len(),
            peer.name
        );
        for p in pkts {
            if let (None, Some((addr, vni))) = (direct, relayed) {
                self.io.push_back(Io::SendUdp { dst: addr, data: super::relay::wrap_wireguard(vni, p.as_ref()) });
                continue;
            }
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
        let mut relay_ping = false;
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
                relay_ping = true;
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
            let Some(pkt) = self.new_ping(node_id, &their_disco, addr) else { return };
            self.io.push_back(Io::SendUdp { dst: addr, data: pkt });
        }
        // Relayed: through DERP too, to time the path the traffic takes. It's
        // filed under Go's "via DERP" address, which no UDP pong can match.
        if let (true, Some(region)) = (relay_ping, region) {
            let Some(pkt) = self.new_ping(node_id, &their_disco, via_derp(region)) else { return };
            self.derp_send(region, peer_key, pkt);
        }
        if send_cmm {
            if let (Some(region), Some(pkt)) =
                (region, self.seal_disco(&their_disco, &Message::CallMeMaybe { endpoints: our_endpoints }))
            {
                self.derp_send(region, peer_key, pkt);
            }
        }
    }

    /// A disco ping for the peer, filed under `dst` (where it goes) so its
    /// pong can be matched.
    fn new_ping(&mut self, node_id: i64, to: &ts_keys::DiscoPublicKey, dst: SocketAddr) -> Option<Vec<u8>> {
        let mut tx_id = [0u8; 12];
        crate::rng::fill(&mut tx_id).ok()?;
        let pkt = self.seal_disco(to, &Message::Ping { tx_id, node_key: None })?;
        let now = self.now;
        self.peers.get_mut(&node_id)?.path.pings.push((tx_id, dst, now));
        Some(pkt)
    }

    pub(super) fn seal_disco(&self, to: &ts_keys::DiscoPublicKey, msg: &Message) -> Option<Vec<u8>> {
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
        if let Source::Relay { addr, vni } = source {
            self.handle_relayed_disco(node_id, addr, vni, msg);
            return;
        }

        match msg {
            Message::Ping { tx_id, .. } => {
                let observed = match source {
                    Source::Derp { region, .. } => via_derp(region),
                    Source::Udp(addr) | Source::Relay { addr, .. } => addr,
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
                    Source::Relay { .. } => {}
                }
            }
            Message::Pong { tx_id, src: _ } => {
                let Some(peer) = self.peers.get_mut(&node_id) else { return };
                let Some(i) = peer.path.pings.iter().position(|(id, _, _)| *id == tx_id) else { return };
                let (_, addr, sent) = peer.path.pings.swap_remove(i);
                let latency = now.saturating_duration_since(sent);
                // A ping through DERP, answered through DERP: the relayed path's round trip.
                if addr.ip() == IpAddr::V4(DERP_MAGIC_IP) {
                    if matches!(source, Source::Derp { .. }) {
                        peer.path.relay_latency = Some((latency, now));
                    }
                    return;
                }
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
            Message::CallMeMaybeVia(ep) if matches!(source, Source::Derp { .. }) => self.handle_call_me_maybe_via(node_id, ep),
            _ => {}
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
        if let Some((id, _, sent)) = self.magic.tcp_probe.as_ref().and_then(|p| p.current) {
            if now >= sent + TCP_PROBE_TIMEOUT {
                self.tcp_probe_done(id, false);
            }
        }
        if now >= self.magic.stun_next {
            self.send_stun();
        }
        let woke = now.saturating_duration_since(core::mem::replace(&mut self.magic.last_tick, now)) > TICK_GAP;
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
            self.relay_tick(id);
            self.note_no_direct_path(id, woke);
        }
    }

    /// Logs once when a peer in use has had no direct path for
    /// NO_DIRECT_NOTICE, with what discovery had to work with. `woke`: the
    /// first tick after a gap (sleep), which starts the count again.
    fn note_no_direct_path(&mut self, id: i64, woke: bool) {
        let now = self.now;
        let ours = self.advertised_endpoints().len();
        let home = self.home_derp;
        let Some(p) = self.peers.get_mut(&id) else { return };
        if woke || !p.path.active(now) || p.path.trusted(now).is_some() {
            p.path.relayed_since = None;
            p.path.told_relayed = false;
            return;
        }
        let since = *p.path.relayed_since.get_or_insert(now);
        if p.path.told_relayed || now.saturating_duration_since(since) < NO_DIRECT_NOTICE {
            return;
        }
        p.path.told_relayed = true;
        let theirs = p.endpoints.iter().chain(p.path.candidates.iter()).filter(|e| is_usable(e)).count();
        if p.path.relay.as_ref().is_some_and(|r| r.trusted(now).is_some()) {
            log::info!("no direct path to {} after 30 s: using a peer relay ({theirs} of its addresses tried, {ours} of ours offered)", p.name);
        } else {
            let region = p.home_derp.or(home).unwrap_or(0);
            log::info!("no direct path to {} after 30 s: relayed through DERP region {region} ({theirs} of its addresses tried, {ours} of ours offered)", p.name);
        }
    }

    pub(super) fn magic_deadline(&self) -> Instant {
        let mut t = self.magic.stun_next.min(self.magic.netcheck_next);
        if let Some(n) = self.magic.netcheck_until {
            t = t.min(n);
        }
        if let Some((_, _, sent)) = self.magic.tcp_probe.as_ref().and_then(|p| p.current) {
            t = t.min(sent + TCP_PROBE_TIMEOUT);
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
        self.stop_tcp_probe();
        let regions: Vec<u32> = self.derp_nodes.keys().copied().collect();
        let probed = regions.into_iter().filter(|r| self.stun_probe(*r)).count();
        self.magic.region_latency.clear();
        if probed == 0 {
            // No STUN anywhere: time the regions over TCP.
            self.magic.netcheck_next = self.now + NETCHECK_INTERVAL;
            self.start_tcp_probe();
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
        if best.is_none() {
            // No STUN replies: UDP is blocked, or every probe was lost.
            self.start_tcp_probe();
        } else {
            self.choose_home_from_latency();
        }
    }

    /// Moves home to the region with the lowest measured latency, if that's
    /// a clear improvement on the current one.
    fn choose_home_from_latency(&mut self) {
        let lat = &self.magic.region_latency;
        let best = lat.iter().min_by_key(|(_, d)| **d).map(|(r, d)| (*r, *d));
        let current = self.home_derp.and_then(|r| lat.get(&r).copied());
        let choice = match (best, current) {
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

    /// Times each region by a TCP connect to its DERP server, one after
    /// another. Until it finishes, home stays where it is, or (with none
    /// yet) is the lowest region id, so peers can reach us meanwhile.
    /// Called with no round running and region_latency empty (netcheck).
    fn start_tcp_probe(&mut self) {
        if self.home_derp.is_none() {
            if let Some(&r) = self.derp_nodes.keys().next() {
                self.set_home_derp(r);
            }
        }
        self.magic.tcp_probe = Some(TcpProbe { last: None, current: None });
        // Finishing is left to tcp_probe_done: this runs on bsd:u MITM
        // threads (a map arriving), whose stacks are small.
        if !self.tcp_probe_connect() {
            self.magic.tcp_probe = None;
        }
    }

    /// Starts timing the next region, if any are left.
    fn tcp_probe_connect(&mut self) -> bool {
        let Some(last) = self.magic.tcp_probe.as_ref().map(|p| p.last) else { return false };
        let Some((&region, node)) = self.derp_nodes.iter().find(|(r, _)| last.is_none_or(|l| **r > l)) else { return false };
        let (host, port) = (node.connect_host.clone(), node.port);
        let id = self.alloc_conn(super::Owner::Probe(region));
        self.io.push_back(Io::Connect { id, host, port });
        if let Some(p) = self.magic.tcp_probe.as_mut() {
            p.last = Some(region);
            p.current = Some((id, region, self.now));
        }
        true
    }

    fn finish_tcp_probe(&mut self) {
        self.magic.tcp_probe = None;
        let lat = &self.magic.region_latency;
        let best = lat.iter().min_by_key(|(_, d)| **d);
        let worst = lat.values().max();
        // Regions span continents. If they all answer alike, something
        // nearby (a firewall or proxy) is answering for them: no information.
        let alike = lat.len() >= 3 && matches!((best, worst), (Some((_, lo)), Some(hi)) if *hi - *lo < TCP_PROBE_UNIFORM);
        log::info!(
            "netcheck (TCP): {} of {} regions answered; best {best:?}, worst {worst:?}{}",
            lat.len(),
            self.derp_nodes.len(),
            if alike { "; all alike, ignored" } else { "" }
        );
        if !alike {
            self.choose_home_from_latency();
        }
    }

    /// Probe connection `id` connected (timed) or failed (closed or timed out).
    pub(super) fn tcp_probe_done(&mut self, id: super::ConnId, connected: bool) {
        self.owners.remove(&id);
        let Some(p) = self.magic.tcp_probe.as_mut() else { return };
        let Some((cur, region, sent)) = p.current.filter(|c| c.0 == id) else { return };
        p.current = None;
        if connected {
            self.magic.region_latency.insert(region, self.now.saturating_duration_since(sent));
        }
        // Harmless if the driver already closed it.
        self.io.push_back(Io::Close { id: cur });
        if !self.tcp_probe_connect() {
            self.finish_tcp_probe();
        }
    }

    fn stop_tcp_probe(&mut self) {
        if let Some((id, _, _)) = self.magic.tcp_probe.take().and_then(|p| p.current) {
            self.owners.remove(&id);
            self.io.push_back(Io::Close { id });
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

/// Go's address for a path through DERP region `region`.
fn via_derp(region: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), region as u16)
}

fn is_usable(ep: &SocketAddr) -> bool {
    ep.port() != 0 && !ep.ip().is_unspecified() && !ep.ip().is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ts_keys::DiscoPrivateKey;

    #[test]
    fn relayed_peers_are_timed_through_derp() {
        let start = Instant::from_nanos(1_000_000_000);
        let mut e = super::super::tests::engine(start);
        let theirs = DiscoPrivateKey::from_bytes([9; 32]);
        super::super::tests::add_peer(&mut e, 1, "gaming-pc.tail1234.ts.net.", Some(8), PathState::for_test(Some(start), None));
        let peer = e.peers.get_mut(&1).unwrap();
        peer.disco = Some(theirs.public_key());
        let their_node = peer.key;
        e.by_disco.insert(super::super::disco_bytes(&theirs.public_key()), 1);

        // No direct path: a round pings through the peer's DERP region too.
        e.discover(1, false);
        let (tx_id, _, _) = *e.peers[&1].path.pings.iter().find(|(_, addr, _)| *addr == via_derp(8)).expect("a ping through DERP");
        assert_eq!(e.active_peers()[0].latency, None);

        // Its pong comes back through DERP 40 ms later.
        e.now = start + Duration::from_millis(40);
        let pong = disco::seal(&theirs, &e.disco_private.public_key(), &their_node, &Message::Pong { tx_id, src: via_derp(8) }).unwrap();
        e.handle_disco(Source::Derp { region: 8, node: their_node }, &pong);
        let peer = &e.active_peers()[0];
        assert_eq!((&peer.path, peer.latency), (&Path::Derp(8), Some(Duration::from_millis(40))));
        // It doesn't count as a direct path.
        assert!(e.peers[&1].path.trusted(e.now).is_none());

        // Shown only while fresh.
        e.now = start + RELAY_LATENCY_FRESH + Duration::from_secs(1);
        assert_eq!(e.active_peers()[0].latency, None);
    }

    /// An engine homed in region 1 of regions 1-3, each with a STUN server.
    fn three_regions(now: Instant) -> Engine {
        let mut e = super::super::tests::engine(now);
        for r in 1..=3u32 {
            let stun = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, r as u8)), 3478));
            let node = super::super::DerpNode { hostname: alloc::format!("derp{r}.test"), connect_host: alloc::format!("192.0.2.{r}"), port: 443, stun };
            e.derp_nodes.insert(r, node);
        }
        e
    }

    /// The probe connect the engine just asked for: (connection, region).
    fn probe_connect(e: &mut Engine) -> Option<(super::super::ConnId, u32)> {
        let io: Vec<Io> = core::iter::from_fn(|| e.poll_io()).collect();
        io.iter().find_map(|io| match io {
            Io::Connect { id, .. } => match e.owners.get(id) {
                Some(super::super::Owner::Probe(r)) => Some((*id, *r)),
                _ => None,
            },
            _ => None,
        })
    }

    /// Runs a netcheck round that no STUN server answers.
    fn netcheck_without_stun(e: &mut Engine) {
        e.start_netcheck();
        e.handle_timeout(e.now + NETCHECK_WINDOW);
    }

    #[test]
    fn without_stun_regions_are_timed_over_tcp() {
        let start = Instant::from_nanos(1_000_000_000);
        let mut e = three_regions(start);
        netcheck_without_stun(&mut e);

        // One region at a time, in order. Region 1 connects in 300 ms.
        let (id, r) = probe_connect(&mut e).expect("a TCP probe");
        assert_eq!(r, 1);
        let t = e.now + Duration::from_millis(300);
        e.handle_connected(id, t);
        // Region 2 in 40 ms.
        let (id, r) = probe_connect(&mut e).expect("a second probe");
        assert_eq!(r, 2);
        e.handle_connected(id, t + Duration::from_millis(40));
        // Region 3 never answers.
        let (id3, r) = probe_connect(&mut e).expect("a third probe");
        assert_eq!(r, 3);
        assert_eq!(e.next_deadline(), t + Duration::from_millis(40) + TCP_PROBE_TIMEOUT);
        e.handle_timeout(t + Duration::from_millis(40) + TCP_PROBE_TIMEOUT);

        assert_eq!(e.home_derp, Some(2));
        assert!(e.magic.tcp_probe.is_none());
        assert!(!e.owners.values().any(|o| matches!(o, super::super::Owner::Probe(_))));
        // A late answer from region 3 changes nothing.
        e.handle_connected(id3, e.now);
        assert_eq!(e.home_derp, Some(2));
    }

    #[test]
    fn tcp_timing_keeps_home_without_a_clear_win() {
        let start = Instant::from_nanos(1_000_000_000);
        let mut e = three_regions(start);
        netcheck_without_stun(&mut e);
        // Region 1 (home) connects in 50 ms, region 2 in 40.
        for ms in [50, 40] {
            let (id, _) = probe_connect(&mut e).unwrap();
            e.handle_connected(id, e.now + Duration::from_millis(ms));
        }
        // Region 3's connect fails at once.
        let (id, _) = probe_connect(&mut e).unwrap();
        e.handle_closed(id, e.now);
        assert!(e.magic.tcp_probe.is_none());
        assert_eq!(e.home_derp, Some(1));
    }

    #[test]
    fn without_a_home_the_lowest_region_serves_until_timed() {
        let start = Instant::from_nanos(1_000_000_000);
        let mut e = three_regions(start);
        e.home_derp = None;
        netcheck_without_stun(&mut e);
        assert_eq!(e.home_derp, Some(1));
        // Region 1 in 200 ms, region 2 fails, region 3 in 30 ms.
        for (ms, ok) in [(200, true), (0, false), (30, true)] {
            let (id, _) = probe_connect(&mut e).unwrap();
            let at = e.now + Duration::from_millis(ms);
            if ok {
                e.handle_connected(id, at);
            } else {
                e.handle_closed(id, at);
            }
        }
        assert_eq!(e.home_derp, Some(3));
    }

    #[test]
    fn tcp_timing_ignores_regions_that_answer_alike() {
        let start = Instant::from_nanos(1_000_000_000);
        let mut e = three_regions(start);
        netcheck_without_stun(&mut e);
        // A firewall answering every connect itself: 4, 2 and 6 ms.
        for ms in [4, 2, 6] {
            let (id, _) = probe_connect(&mut e).unwrap();
            e.handle_connected(id, e.now + Duration::from_millis(ms));
        }
        assert!(e.magic.tcp_probe.is_none());
        assert_eq!(e.home_derp, Some(1));
    }

    #[test]
    fn a_new_netcheck_stops_tcp_timing() {
        let start = Instant::from_nanos(1_000_000_000);
        let mut e = three_regions(start);
        netcheck_without_stun(&mut e);
        let (id, _) = probe_connect(&mut e).unwrap();
        e.start_netcheck();
        let io: Vec<Io> = core::iter::from_fn(|| e.poll_io()).collect();
        assert!(io.iter().any(|io| matches!(io, Io::Close { id: c } if *c == id)));
        assert!(e.magic.tcp_probe.is_none() && !e.owners.contains_key(&id));
    }

    #[test]
    fn a_peer_without_a_direct_path_is_noted_once() {
        let start = Instant::from_nanos(1_000_000_000);
        let mut e = super::super::tests::engine(start);
        super::super::tests::add_peer(&mut e, 1, "gaming-pc.tail1234.ts.net.", Some(8), PathState::for_test(Some(start), None));
        // Ticks every second up to `secs`, as the engine does while a peer
        // is in use.
        let tick_to = |e: &mut Engine, secs: u64| {
            let end = start + Duration::from_secs(secs);
            while e.now < end {
                e.now = (e.now + Duration::from_secs(1)).min(end);
                e.peers.get_mut(&1).unwrap().path.last_active = Some(e.now);
                e.magic_tick();
            }
            e.peers[&1].path.told_relayed
        };
        assert!(!tick_to(&mut e, 29));
        assert!(tick_to(&mut e, 31));
        // A direct path resets it, so a later relayed stretch is noted again.
        let addr: SocketAddr = "192.0.2.7:41641".parse().unwrap();
        let now = start + Duration::from_secs(31);
        e.peers.get_mut(&1).unwrap().path.best = Some(BestAddr { addr, latency: Duration::from_millis(4), confirmed: now });
        e.now = now;
        e.magic_tick();
        assert_eq!(e.peers[&1].path.relayed_since, None);

        // Time asleep doesn't count: 20 s relayed, a minute's sleep, then
        // the count starts again on waking.
        e.peers.get_mut(&1).unwrap().path.best = None;
        assert!(!tick_to(&mut e, 51));
        e.now = start + Duration::from_secs(111);
        e.magic_tick();
        assert!(!tick_to(&mut e, 140));
        assert!(tick_to(&mut e, 142));
    }

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
