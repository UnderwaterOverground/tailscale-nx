//! The Tailscale node engine: control session, netmap, WireGuard, DERP and
//! the overlay netstack, wired together. Sans-IO like everything else: the
//! driver performs [`Io`], delivers results via `handle_*`, and calls
//! [`Engine::handle_timeout`] at [`Engine::next_deadline`].

mod filter;
mod magic;
mod netmap;
mod packet;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use ts_keys::{DiscoPrivateKey, DiscoPublicKey, NodeKeyPair, NodePrivateKey, NodePublicKey};
use ts_packet::PacketMut;
use ts_tunnel::{PeerConfig, PeerId};
use zerocopy::IntoBytes;

use crate::control::client::{ConnId, ControlClient, ControlConfig, Io as ControlIo, Keys, Update};
use crate::derp::{DerpClient, DerpEvent};
use crate::netstack::{Netstack, MTU};
use crate::stream::SecureStream;
use crate::time::{Backoff, Instant};
use packet::Prefix;

/// Socket work for the driver. Connection ids are unique for the engine's
/// lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Io {
    /// Resolve `host` (or parse it as an IP literal) and connect TCP.
    Connect { id: ConnId, host: String, port: u16 },
    Send { id: ConnId, data: Vec<u8> },
    Close { id: ConnId },
    /// Send a datagram from the engine's UDP socket (WireGuard, disco, STUN).
    SendUdp { dst: SocketAddr, data: Vec<u8> },
}

/// Status changes for the UI / logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    LoginUrl(String),
    Authorized,
    /// This node's tailnet addresses.
    Addresses(Vec<IpAddr>),
    /// Peer table changed; current peer count.
    Peers(usize),
    HomeDerp(u32),
    /// Our advertised direct endpoints changed.
    Endpoints(Vec<SocketAddr>),
    /// The path to a peer changed (`Some(addr)` = direct, `None` = DERP).
    PeerPath { peer: String, direct: Option<SocketAddr> },
    Error(String),
    Log(String),
    /// Our node key was replaced (the old one expired); persist
    /// [`Engine::node_private_key`] in place of the stored one.
    NodeKeyChanged,
}

pub struct EngineConfig {
    pub control: ControlConfig,
    pub machine_private: [u8; 32],
    pub node_private: [u8; 32],
    /// Persisted across restarts (unlike the Go client): a new disco key
    /// makes peers drop their WireGuard sessions with us, which races with
    /// the handshake we start after a restart.
    pub disco_private: [u8; 32],
}

struct Peer {
    name: String,
    key: NodePublicKey,
    disco: Option<DiscoPublicKey>,
    /// Addresses and allowed IPs: what this peer may source, and what we
    /// route to it.
    prefixes: Vec<Prefix>,
    home_derp: Option<u32>,
    endpoints: Vec<SocketAddr>,
    wg: PeerId,
    path: magic::PathState,
}

#[derive(Clone)]
struct DerpNode {
    hostname: String,
    connect_host: String,
    port: u16,
    /// STUN server for this region, if it has a fixed IPv4 address.
    stun: Option<SocketAddr>,
}

enum Owner {
    Control(ConnId),
    Derp(u32),
}

struct DerpConn {
    id: ConnId,
    node: DerpNode,
    client: Option<DerpClient>,
    queue: VecDeque<(NodePublicKey, Vec<u8>)>,
    last_rx: Instant,
    /// Last packet sent or received through it (not server keep-alives).
    last_used: Instant,
}

/// How long a DERP connection may be silent (server keep-alives are 60s).
const DERP_SILENCE_LIMIT: Duration = Duration::from_secs(130);
const DERP_QUEUE_MAX: usize = 64;
/// A connection to a region other than our home one (to reach a peer homed
/// there) costs a TLS session; close it once unused, like Tailscale does.
const DERP_IDLE_LIMIT: Duration = Duration::from_secs(60);

pub struct Engine {
    control: ControlClient,
    node_private: NodePrivateKey,
    disco_private: DiscoPrivateKey,
    wg: ts_tunnel::Endpoint,
    net: Netstack,
    /// Our own MagicDNS name (from the netmap).
    self_name: String,
    peers: BTreeMap<i64, Peer>,
    by_wg: BTreeMap<u32, i64>,
    by_key: BTreeMap<[u8; 32], i64>,
    by_disco: BTreeMap<[u8; 32], i64>,
    next_wg: u32,
    magic: magic::MagicState,
    derp_nodes: BTreeMap<u32, DerpNode>,
    home_derp: Option<u32>,
    derps: BTreeMap<u32, DerpConn>,
    derp_backoff: Backoff,
    derp_retry_at: Option<Instant>,
    owners: BTreeMap<ConnId, Owner>,
    control_ids: BTreeMap<ConnId, ConnId>,
    next_conn: ConnId,
    tls: Arc<rustls::ClientConfig>,
    io: VecDeque<Io>,
    events: VecDeque<Event>,
    now: Instant,
    last_trim: Instant,
    /// Wall clock reference: at monotonic `.0`, Unix time was `.1`.
    wall: (Instant, Duration),
    /// `node_private` as bytes (ts_keys doesn't export private keys).
    node_private_bytes: [u8; 32],
    /// The tailnet's access rules for traffic coming in to us.
    filter: filter::Filter,
    /// When our node key expires (Unix seconds, from the netmap).
    key_expiry: Option<u64>,
    /// The expiry we already replaced the key for: the netmap may report it
    /// again until the server catches up, and that must not rotate twice.
    expiry_handled: Option<u64>,
}

/// How often buffers that grew for a burst are shrunk back.
const TRIM_INTERVAL: Duration = Duration::from_secs(15);

impl Engine {
    pub fn new(cfg: EngineConfig, now: Instant, unix_time: Duration) -> Result<Self, String> {
        crate::tls::CLOCK.set(unix_time.as_secs());
        let node_private = NodePrivateKey::from_bytes(cfg.node_private);
        let tls = crate::tls::client_config(&cfg.control.extra_roots).map_err(|e| e.to_string())?;
        let disco_private = cfg.disco_private;
        let keys = Keys {
            machine_private: cfg.machine_private,
            node_private: cfg.node_private,
            disco_public: crate::crypto::x25519_public(&disco_private),
        };
        let mut wg = ts_tunnel::Endpoint::new(NodeKeyPair::from(node_private.clone()));
        wg.set_wall_clock(now, unix_time);
        Ok(Self {
            control: ControlClient::new(cfg.control, keys, now)?,
            node_private,
            disco_private: DiscoPrivateKey::from_bytes(disco_private),
            wg,
            net: Netstack::new(now),
            self_name: String::new(),
            peers: BTreeMap::new(),
            by_wg: BTreeMap::new(),
            by_key: BTreeMap::new(),
            by_disco: BTreeMap::new(),
            next_wg: 1,
            magic: magic::MagicState::new(now),
            derp_nodes: BTreeMap::new(),
            home_derp: None,
            derps: BTreeMap::new(),
            derp_backoff: Backoff::new(Duration::from_secs(1), Duration::from_secs(30)),
            derp_retry_at: None,
            owners: BTreeMap::new(),
            control_ids: BTreeMap::new(),
            next_conn: 1,
            tls,
            io: VecDeque::new(),
            events: VecDeque::new(),
            now,
            last_trim: now,
            wall: (now, unix_time),
            node_private_bytes: cfg.node_private,
            filter: filter::Filter::default(),
            key_expiry: None,
            expiry_handled: None,
        })
    }

    pub fn poll_io(&mut self) -> Option<Io> {
        self.io.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// IPv4 address and MagicDNS name (no trailing dot) of every peer and of
    /// this node, for name resolution outside the engine (e.g. a hosts file).
    pub fn hosts(&self) -> Vec<(core::net::Ipv4Addr, &str)> {
        let v4 = |prefixes: &[Prefix]| {
            prefixes.iter().find_map(|p| match p.addr {
                IpAddr::V4(a) if p.len == 32 => Some(a),
                _ => None,
            })
        };
        let mut out = Vec::new();
        let own: Vec<Prefix> = self.net.addresses().iter().map(|&addr| Prefix { addr, len: if addr.is_ipv4() { 32 } else { 128 } }).collect();
        if let Some(a) = v4(&own) {
            out.push((a, self.self_name.trim_end_matches('.')));
        }
        for p in self.peers.values() {
            if let Some(a) = v4(&p.prefixes) {
                out.push((a, p.name.trim_end_matches('.')));
            }
        }
        out.retain(|(_, n)| !n.is_empty());
        out
    }

    /// The overlay socket API. Call [`Engine::flush`] after using it so
    /// queued packets are sent.
    pub fn net(&mut self) -> &mut Netstack {
        &mut self.net
    }

    pub fn addresses(&self) -> &[IpAddr] {
        self.net.addresses()
    }

    pub fn next_deadline(&mut self) -> Instant {
        let mut t = self.control.next_deadline();
        if let Some(r) = self.wg.next_event() {
            t = t.min(r.end());
        }
        if let Some(at) = self.net.poll_at(self.now) {
            t = t.min(at);
        }
        if let Some(at) = self.derp_retry_at {
            t = t.min(at);
        }
        for (r, d) in &self.derps {
            t = t.min(d.last_rx + DERP_SILENCE_LIMIT);
            if self.home_derp != Some(*r) {
                t = t.min(d.last_used + DERP_IDLE_LIMIT);
            }
        }
        if let Some(at) = self.key_expiry_deadline() {
            t = t.min(at);
        }
        t.min(self.last_trim + TRIM_INTERVAL).min(self.magic_deadline())
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        self.control.handle_timeout(now);
        let stale: Vec<u32> =
            self.derps.iter().filter(|(_, d)| now >= d.last_rx + DERP_SILENCE_LIMIT).map(|(r, _)| *r).collect();
        for region in stale {
            self.drop_derp(region, "DERP connection silent");
        }
        let home = self.home_derp;
        let idle: Vec<u32> = self
            .derps
            .iter()
            .filter(|(r, d)| home != Some(**r) && now >= d.last_used + DERP_IDLE_LIMIT)
            .map(|(r, _)| *r)
            .collect();
        for region in idle {
            if let Some(conn) = self.derps.remove(&region) {
                self.owners.remove(&conn.id);
                self.io.push_back(Io::Close { id: conn.id });
                self.events.push_back(Event::Log(format!("DERP region {region} idle; closed")));
            }
        }
        if self.derp_retry_at.is_some_and(|t| now >= t) {
            self.derp_retry_at = None;
            if let Some(home) = self.home_derp {
                self.ensure_derp(home);
            }
        }
        let ev = self.wg.dispatch_events(now);
        for (peer, pkts) in ev.to_peers {
            self.transmit(peer, pkts);
        }
        self.magic_tick();
        self.pump();
        self.check_key_expiry();
        if now >= self.last_trim + TRIM_INTERVAL {
            self.last_trim = now;
            self.trim();
        }
    }

    /// Releases spare buffer capacity everywhere (see [`crate::trim_vec`]).
    fn trim(&mut self) {
        self.control.trim();
        for d in self.derps.values_mut() {
            if let Some(c) = d.client.as_mut() {
                c.trim();
            }
            d.queue.shrink_to_fit();
        }
        self.net.trim();
        self.filter.expire(self.now);
        self.io.shrink_to_fit();
        self.events.shrink_to_fit();
    }

    /// A datagram arrived on the engine's UDP socket.
    pub fn handle_udp(&mut self, src: SocketAddr, data: &[u8], now: Instant) {
        self.now = now;
        if crate::stun::is_stun(data) {
            self.handle_stun(data);
        } else if crate::disco::is_disco(data) {
            self.handle_disco(magic::Source::Udp(src), data);
        } else {
            self.handle_wg(data.to_vec(), Some(src), None);
        }
        self.pump();
    }

    /// Tells the engine its local UDP endpoints (interface address + bound
    /// port), which are advertised to peers for direct connections.
    pub fn set_local_endpoints(&mut self, endpoints: &[SocketAddr], now: Instant) {
        self.now = now;
        self.magic.local_endpoints = endpoints.to_vec();
        self.update_endpoints();
        self.pump();
    }

    pub fn handle_connected(&mut self, id: ConnId, now: Instant) {
        self.now = now;
        match self.owners.get(&id) {
            Some(Owner::Control(local)) => self.control.on_connected(*local, now),
            Some(Owner::Derp(region)) => {
                let region = *region;
                self.derp_connected(region);
            }
            None => {}
        }
        self.pump();
    }

    pub fn handle_data(&mut self, id: ConnId, data: &[u8], now: Instant) {
        self.now = now;
        match self.owners.get(&id) {
            Some(Owner::Control(local)) => self.control.on_data(*local, data, now),
            Some(Owner::Derp(region)) => {
                let region = *region;
                self.derp_data(region, data);
            }
            None => {}
        }
        self.pump();
    }

    pub fn handle_closed(&mut self, id: ConnId, now: Instant) {
        self.now = now;
        match self.owners.remove(&id) {
            Some(Owner::Control(local)) => {
                self.control_ids.remove(&local);
                self.control.on_closed(local, now);
            }
            Some(Owner::Derp(region)) => {
                if self.derps.get(&region).is_some_and(|d| d.id == id) {
                    self.derps.remove(&region);
                    self.derp_disconnected(region, "DERP connection closed");
                }
            }
            None => {}
        }
        self.pump();
    }

    /// Re-runs the stack and flushes output after socket API calls.
    pub fn flush(&mut self, now: Instant) {
        self.now = now;
        self.pump();
    }

    // ---- plumbing --------------------------------------------------------

    fn pump(&mut self) {
        // Control session.
        while let Some(io) = self.control.poll_io() {
            match io {
                ControlIo::Connect { id, host, port } => {
                    let g = self.alloc_conn(Owner::Control(id));
                    self.control_ids.insert(id, g);
                    self.io.push_back(Io::Connect { id: g, host, port });
                }
                ControlIo::Send { id, data } => {
                    if let Some(&g) = self.control_ids.get(&id) {
                        self.io.push_back(Io::Send { id: g, data });
                    }
                }
                ControlIo::Close { id } => {
                    if let Some(g) = self.control_ids.remove(&id) {
                        self.owners.remove(&g);
                        self.io.push_back(Io::Close { id: g });
                    }
                }
            }
        }
        while let Some(u) = self.control.poll_update() {
            match u {
                Update::LoginUrl(url) => self.events.push_back(Event::LoginUrl(url)),
                Update::Authorized => self.events.push_back(Event::Authorized),
                Update::NodeKeyRotated(key) => self.rotate_node_key(key),
                Update::Error(e) => self.events.push_back(Event::Error(format!("control: {e}"))),
                Update::Map(json) => {
                    if let Err(e) = self.apply_map(&json) {
                        self.events.push_back(Event::Error(format!("netmap: {e}")));
                    }
                }
            }
        }

        // Overlay stack -> tunnel.
        self.net.poll(self.now);
        let outbound: Vec<Vec<u8>> = self.net.take_outbound().collect();
        if !outbound.is_empty() {
            let mut by_peer: BTreeMap<u32, Vec<PacketMut>> = BTreeMap::new();
            for mut pkt in outbound {
                self.filter.note_outbound(&pkt, self.now);
                let Some(dst) = packet::dst(&pkt) else { continue };
                let Some(peer) = self.route(dst) else {
                    log::debug!("no route to {dst}");
                    continue;
                };
                log::debug!("outbound {} bytes to {dst} via {}", pkt.len(), peer.name);
                packet::pad(&mut pkt, MTU);
                by_peer.entry(peer.wg.0).or_default().push(PacketMut::from(pkt));
            }
            let res = self.wg.send(self.now, by_peer.into_iter().map(|(id, p)| (PeerId(id), p)));
            for (peer, pkts) in res.to_peers {
                self.transmit(peer, pkts);
            }
        }
    }

    fn alloc_conn(&mut self, owner: Owner) -> ConnId {
        let id = self.next_conn;
        self.next_conn += 1;
        self.owners.insert(id, owner);
        id
    }

    /// Finds the peer whose addresses/allowed IPs contain `dst` (longest prefix).
    fn route(&self, dst: IpAddr) -> Option<&Peer> {
        self.peers
            .values()
            .filter_map(|p| p.prefixes.iter().filter(|pre| pre.contains(dst)).map(|pre| pre.len).max().map(|l| (l, p)))
            .max_by_key(|(l, _)| *l)
            .map(|(_, p)| p)
    }

    /// Handles a WireGuard packet from the underlay. `udp_src` is set when
    /// it arrived directly rather than via DERP.
    fn handle_wg(&mut self, pkt: Vec<u8>, udp_src: Option<SocketAddr>, derp_src: Option<NodePublicKey>) {
        let (ty, len) = (pkt.first().copied().unwrap_or(0), pkt.len());
        let res = self.wg.recv(self.now, [PacketMut::from(pkt)]);
        log::trace!(
            "wg in type {ty} len {len} via {}: {} to local, {} replies",
            udp_src.map_or("derp".into(), |a| alloc::format!("{a}")),
            res.to_local.values().map(Vec::len).sum::<usize>(),
            res.to_peers.values().map(Vec::len).sum::<usize>()
        );
        // Transport data that produced nothing: a session we don't have.
        if ty == 4 && res.to_local.is_empty() && res.to_peers.is_empty() {
            if let Some(node_id) = self.peer_for_source(derp_src.as_ref(), udp_src) {
                self.repair_session(node_id);
            }
        }
        for (wg, pkts) in res.to_local {
            let Some(&node_id) = self.by_wg.get(&wg.0) else { continue };
            self.note_active(node_id, udp_src);
            let Some(peer) = self.peers.get(&node_id) else { continue };
            for p in pkts {
                let mut p = p.as_ref().to_vec();
                // Keepalives are empty.
                let Some(len) = packet::ip_len(&p) else { continue };
                if len > p.len() {
                    continue;
                }
                p.truncate(len);
                // Cryptokey routing: the peer may only source its own prefixes.
                let Some(src_ip) = packet::src(&p) else { continue };
                if !peer.prefixes.iter().any(|pre| pre.contains(src_ip)) {
                    log::debug!("dropping packet from {src_ip}: not in {}'s prefixes", peer.name);
                    continue;
                }
                if !self.filter.allows_inbound(&p, self.now) {
                    log::debug!("dropping packet from {src_ip}: not allowed by the tailnet's access rules");
                    continue;
                }
                self.net.inject(p);
            }
        }
        for (peer, pkts) in res.to_peers {
            self.transmit(peer, pkts);
        }
    }

    // ---- netmap ----------------------------------------------------------

    /// Our private node key, e.g. to persist it after [`Event::NodeKeyChanged`].
    pub fn node_private_key(&self) -> [u8; 32] {
        self.node_private_bytes
    }

    /// Switches WireGuard and DERP to a new node key (control replaced an
    /// expired one). Peers learn the new key from the netmap and handshake
    /// again; DERP reconnects under the new identity.
    fn rotate_node_key(&mut self, key: [u8; 32]) {
        self.node_private = NodePrivateKey::from_bytes(key);
        self.node_private_bytes = key;
        let mut wg = ts_tunnel::Endpoint::new(NodeKeyPair::from(self.node_private.clone()));
        wg.set_wall_clock(self.wall.0, self.wall.1);
        for p in self.peers.values() {
            wg.upsert_peer(PeerConfig::new(p.wg, p.key, [0; 32]));
        }
        self.wg = wg;
        let regions: Vec<u32> = self.derps.keys().copied().collect();
        for region in regions {
            if let Some(conn) = self.derps.remove(&region) {
                self.owners.remove(&conn.id);
                self.io.push_back(Io::Close { id: conn.id });
            }
        }
        if let Some(home) = self.home_derp {
            self.ensure_derp(home);
        }
        self.events.push_back(Event::Log("node key expired; registering a new one".into()));
        self.events.push_back(Event::NodeKeyChanged);
    }

    /// Once our key's expiry passes (like Tailscale, on our own clock: the
    /// server keeps the map poll going, but peers stop talking to us),
    /// register again, which replaces the key.
    fn check_key_expiry(&mut self) {
        let Some(t) = self.key_expiry else { return };
        if t <= self.unix_now() && self.expiry_handled != Some(t) {
            self.expiry_handled = Some(t);
            self.control.replace_expired_node_key(self.now);
        }
    }

    /// Monotonic time at which our key expires, if it does.
    fn key_expiry_deadline(&self) -> Option<Instant> {
        let t = self.key_expiry?;
        if self.expiry_handled == Some(t) {
            return None;
        }
        let wait = t.saturating_sub(self.unix_now());
        // Far-off expiries (months) are rechecked daily instead of computing
        // a huge deadline.
        Some(self.now + Duration::from_secs(wait.min(24 * 3600)))
    }

    /// Current Unix time (seconds), from the clock the driver gave us.
    fn unix_now(&self) -> u64 {
        (self.wall.1 + self.now.saturating_duration_since(self.wall.0)).as_secs()
    }

    fn apply_map(&mut self, json: &[u8]) -> Result<(), String> {
        let m = netmap::parse(json).map_err(|e| e.to_string())?;
        self.filter.update(m.packet_filter.as_deref(), m.packet_filters.as_ref());
        if let Some(node) = &m.node {
            log::debug!("self node key expiry: {:?}", node.key_expiry());
            self.key_expiry = node.key_expiry();
            self.check_key_expiry();
            if !node.name.is_empty() && self.self_name != node.name {
                self.self_name = node.name.as_ref().into();
            }
            let mine = node.addresses();
            let v4 = mine.iter().find(|p| p.addr.is_ipv4());
            let v6 = mine.iter().find(|p| p.addr.is_ipv6());
            if let (Some(v4), Some(v6)) = (v4, v6) {
                let addrs = [v4.addr, v6.addr];
                if self.net.addresses() != addrs {
                    self.net.set_addresses(&addrs);
                    self.events.push_back(Event::Addresses(addrs.to_vec()));
                }
            }
        }
        if let Some(dm) = &m.derp_map {
            self.derp_nodes.clear();
            for (id, region) in &dm.regions {
                let Some(n) = region.nodes.iter().flatten().find(|n| !n.stun_only) else { continue };
                let connect_host = match n.fixed_ipv4() {
                    Some(ip) => ip.to_string(),
                    None => n.hostname.into(),
                };
                self.derp_nodes.insert(
                    *id,
                    DerpNode { hostname: n.hostname.into(), connect_host, port: n.derp_port(), stun: n.stun() },
                );
            }
            self.choose_home_derp();
        }
        let mut changed = false;
        if let Some(peers) = &m.peers {
            let keep: Vec<i64> = peers.iter().map(|p| p.id).collect();
            let stale: Vec<i64> = self.peers.keys().copied().filter(|id| !keep.contains(id)).collect();
            for id in stale {
                self.remove_peer(id);
            }
            for p in peers {
                self.upsert_peer(p);
            }
            changed = true;
        }
        if let Some(peers) = &m.peers_changed {
            for p in peers {
                self.upsert_peer(p);
            }
            changed = true;
        }
        if let Some(removed) = &m.peers_removed {
            for id in removed {
                self.remove_peer(*id);
            }
            changed = true;
        }
        let mut reset = Vec::new();
        if let Some(patches) = &m.peers_changed_patch {
            for patch in patches {
                let Some(peer) = self.peers.get_mut(&patch.node_id) else { continue };
                if let Some(r) = patch.derp_region {
                    peer.home_derp = Some(r);
                }
                if let Some(eps) = patch.endpoints() {
                    peer.endpoints = eps;
                }
                if let Some(d) = patch.disco_key() {
                    if peer.disco != Some(d) {
                        peer.path = magic::PathState::default();
                        reset.push(patch.node_id);
                    }
                    peer.disco = Some(d);
                    self.by_disco.retain(|_, v| *v != patch.node_id);
                    self.by_disco.insert(disco_bytes(&d), patch.node_id);
                }
                if let Some(k) = patch.key() {
                    // A new node key: re-register with WireGuard.
                    let wg = peer.wg;
                    peer.key = k;
                    self.by_key.retain(|_, v| *v != patch.node_id);
                    self.by_key.insert(key_bytes(&k), patch.node_id);
                    self.wg.upsert_peer(PeerConfig::new(wg, k, [0; 32]));
                }
            }
            changed = true;
        }
        for id in reset {
            self.reset_wg_session(id, "peer disco key changed");
        }
        if changed {
            self.events.push_back(Event::Peers(self.peers.len()));
        }
        Ok(())
    }

    fn upsert_peer(&mut self, n: &netmap::Node) {
        let Some(key) = n.key() else { return };
        let disco_key = n.disco_key();
        let prefixes = n.allowed_prefixes();
        let home_derp = n.home_derp();
        let wg = match self.peers.get(&n.id) {
            Some(existing) => existing.wg,
            None => {
                let id = PeerId(self.next_wg);
                self.next_wg += 1;
                id
            }
        };
        if self.peers.get(&n.id).is_none_or(|p| p.key != key) {
            self.wg.upsert_peer(PeerConfig::new(wg, key, [0; 32]));
        }
        self.by_wg.insert(wg.0, n.id);
        self.by_key.insert(key_bytes(&key), n.id);
        if let Some(d) = disco_key {
            self.by_disco.retain(|_, v| *v != n.id);
            self.by_disco.insert(disco_bytes(&d), n.id);
        }
        // Keep path state across netmap updates unless the disco key changed
        // (the peer restarted, so its paths must be re-proven).
        let (path, disco_changed) = match self.peers.remove(&n.id) {
            Some(old) if old.disco == disco_key => (old.path, false),
            Some(_) => (magic::PathState::default(), true),
            None => (magic::PathState::default(), false),
        };
        self.peers.insert(
            n.id,
            Peer { name: n.name.as_ref().into(), key, disco: disco_key, prefixes, home_derp, endpoints: n.endpoints(), wg, path },
        );
        if disco_changed {
            // The peer restarted; like Go, drop the old WireGuard session.
            self.reset_wg_session(n.id, "peer disco key changed");
        }
    }

    fn remove_peer(&mut self, id: i64) {
        if let Some(p) = self.peers.remove(&id) {
            self.wg.remove_peer(p.wg);
            self.by_wg.remove(&p.wg.0);
            self.by_key.remove(p.key.as_bytes());
            self.by_disco.retain(|_, v| *v != id);
        }
    }

    /// The DERP map changed: re-measure region latency (netcheck), which
    /// then picks our home region. Keeps the current home meanwhile.
    fn choose_home_derp(&mut self) {
        if self.home_derp.is_some_and(|r| !self.derp_nodes.contains_key(&r)) {
            self.home_derp = None;
        }
        self.start_netcheck();
    }

    /// Makes `region` our home DERP: connect, mark preferred, advertise.
    pub(super) fn set_home_derp(&mut self, region: u32) {
        if self.home_derp == Some(region) {
            return;
        }
        let old = self.home_derp.replace(region);
        self.events.push_back(Event::HomeDerp(region));
        self.update_endpoints();
        self.ensure_derp(region);
        for (r, preferred) in [(old, false), (Some(region), true)] {
            if let Some(c) = r.and_then(|r| self.derps.get_mut(&r)).and_then(|d| d.client.as_mut()) {
                if c.is_ready() && c.note_preferred(preferred).is_ok() {
                    let out = c.take_outgoing();
                    let id = self.derps[&r.unwrap()].id;
                    self.io.push_back(Io::Send { id, data: out });
                }
            }
        }
    }

    // ---- DERP connections -----------------------------------------------

    fn ensure_derp(&mut self, region: u32) {
        if self.derps.contains_key(&region) {
            return;
        }
        let Some(node) = self.derp_nodes.get(&region).cloned() else { return };
        let id = self.alloc_conn(Owner::Derp(region));
        self.io.push_back(Io::Connect { id, host: node.connect_host.clone(), port: node.port });
        let now = self.now;
        self.derps.insert(region, DerpConn { id, node, client: None, queue: VecDeque::new(), last_rx: now, last_used: now });
    }

    fn derp_send(&mut self, region: u32, dst: NodePublicKey, pkt: Vec<u8>) {
        self.ensure_derp(region);
        let Some(conn) = self.derps.get_mut(&region) else { return };
        conn.last_used = self.now;
        log::trace!(
            "derp_send region {region}: {} bytes, ready={}, queued={}",
            pkt.len(),
            conn.client.as_ref().is_some_and(|c| c.is_ready()),
            conn.queue.len()
        );
        match conn.client.as_mut() {
            Some(c) if c.is_ready() => {
                if c.send_packet(&dst, &pkt).is_ok() {
                    let out = c.take_outgoing();
                    let id = conn.id;
                    self.io.push_back(Io::Send { id, data: out });
                }
            }
            _ => {
                if conn.queue.len() < DERP_QUEUE_MAX {
                    conn.queue.push_back((dst, pkt));
                }
            }
        }
    }

    fn derp_connected(&mut self, region: u32) {
        let tls = self.tls.clone();
        let node_private = self.node_private.clone();
        let Some(conn) = self.derps.get_mut(&region) else { return };
        let stream = match SecureStream::tls(tls, &conn.node.hostname) {
            Ok(s) => s,
            Err(e) => return self.drop_derp(region, &format!("DERP TLS: {e:?}")),
        };
        match DerpClient::new(&conn.node.hostname, stream, node_private) {
            Ok(mut c) => {
                let out = c.take_outgoing();
                conn.client = Some(c);
                conn.last_rx = self.now;
                let id = conn.id;
                self.io.push_back(Io::Send { id, data: out });
            }
            Err(e) => self.drop_derp(region, &format!("DERP: {e:?}")),
        }
    }

    fn derp_data(&mut self, region: u32, data: &[u8]) {
        let now = self.now;
        let home = self.home_derp == Some(region);
        let Some(conn) = self.derps.get_mut(&region) else { return };
        conn.last_rx = now;
        let Some(client) = conn.client.as_mut() else { return };
        if let Err(e) = client.feed(data) {
            return self.drop_derp(region, &format!("DERP: {e:?}"));
        }
        let mut received = Vec::new();
        while let Some(ev) = client.poll_event() {
            match ev {
                DerpEvent::Ready => {
                    let _ = client.note_preferred(home);
                    while let Some((dst, pkt)) = conn.queue.pop_front() {
                        let _ = client.send_packet(&dst, &pkt);
                    }
                    self.derp_backoff.reset();
                    self.events.push_back(Event::Log(format!("DERP region {region} connected")));
                }
                DerpEvent::Recv { src, packet } => {
                    conn.last_used = now;
                    received.push((src, packet))
                }
                DerpEvent::Health(h) if !h.is_empty() => {
                    self.events.push_back(Event::Log(format!("DERP {region} health: {h}")))
                }
                _ => {}
            }
        }
        let out = client.take_outgoing();
        let id = conn.id;
        if !out.is_empty() {
            self.io.push_back(Io::Send { id, data: out });
        }
        for (src, pkt) in received {
            if crate::disco::is_disco(&pkt) {
                self.handle_disco(magic::Source::Derp { region, node: src }, &pkt);
            } else {
                self.handle_wg(pkt, None, Some(src));
            }
        }
    }

    fn drop_derp(&mut self, region: u32, why: &str) {
        if let Some(conn) = self.derps.remove(&region) {
            self.owners.remove(&conn.id);
            self.io.push_back(Io::Close { id: conn.id });
        }
        self.derp_disconnected(region, why);
    }

    fn derp_disconnected(&mut self, region: u32, why: &str) {
        self.events.push_back(Event::Error(format!("DERP region {region}: {why}")));
        if self.home_derp == Some(region) {
            self.derp_retry_at = Some(self.now + self.derp_backoff.next_delay());
        }
    }
}

fn key_bytes(k: &NodePublicKey) -> [u8; 32] {
    k.as_bytes().try_into().expect("32-byte key")
}

fn disco_bytes(k: &DiscoPublicKey) -> [u8; 32] {
    k.as_bytes().try_into().expect("32-byte key")
}
