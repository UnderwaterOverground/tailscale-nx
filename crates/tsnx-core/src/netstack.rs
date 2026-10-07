//! Userspace TCP/IP stack for the tailnet side, built on smoltcp.
//!
//! IP packets decrypted from WireGuard are injected here; packets the stack
//! emits are drained and sent through the tunnel. On top sits a small
//! BSD-like socket API (ids, non-blocking calls, readiness) that the socket
//! MITM layer maps intercepted `bsd:u` calls onto.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use crate::time::Instant;

/// Tailscale's tunnel MTU.
pub const MTU: usize = 1280;

// Overlay socket memory. On the Switch every byte comes out of the
// sysmodule's fixed heap, shared with the engine and with every app's
// sockets, so buffers are smaller there and all of them draw from one
// budget: past it, new TCP sockets are refused and datagrams dropped
// instead of the heap running out.
//
// TCP buffers are sized per connection from what is left of the budget (see
// `tcp_buffer_size`): the first connections get the full size, later ones
// less, down to TCP_MIN. A crowded budget makes connections slower (a TCP
// window caps throughput at window / RTT) instead of refusing them.
#[cfg(not(any(target_os = "horizon", feature = "switch-limits")))]
mod limits {
    /// Largest receive / send buffer of one TCP connection.
    pub const TCP_RX: usize = 64 << 10;
    pub const TCP_TX: usize = 64 << 10;
    /// Datagrams queued per UDP socket (bytes, counting allocation size).
    pub const UDP_RX: usize = 512 << 10;
    pub const BUDGET: usize = usize::MAX;
}
// Measured on the console: a Moonlight stream keeps 0-6 KB queued while the
// app reads; only a suspended app (HOME menu) fills a queue, and stale video
// is useless then anyway. Heap fragmentation, not the total, is the limit.
#[cfg(any(target_os = "horizon", feature = "switch-limits"))]
mod limits {
    pub const TCP_RX: usize = 32 << 10;
    pub const TCP_TX: usize = 32 << 10;
    pub const UDP_RX: usize = 64 << 10;
    /// Default; the sysmodule's config can change it (`set_budget`).
    pub const BUDGET: usize = 320 << 10;
}
use limits::*;
/// Smallest TCP buffer (each direction): a few full-size segments.
const TCP_MIN: usize = 4 << 10;

/// Buffer size (each direction) for a new TCP connection when `free` budget
/// bytes are left: a tenth of it, rounded down to a power of two, between
/// TCP_MIN and `max`. With the Switch's 320 KB: one connection at 32 KB, four
/// at 16, four at 8 and eight at 4 (17 at once, before UDP queues).
fn tcp_buffer_size(free: usize, max: usize) -> usize {
    let tenth = free / 10;
    if tenth < TCP_MIN {
        return TCP_MIN;
    }
    (1usize << (usize::BITS - 1 - tenth.leading_zeros())).clamp(TCP_MIN, max)
}

const EPHEMERAL_PORTS: core::ops::RangeInclusive<u16> = 49152..=65535;

pub type SockId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    WouldBlock,
    NotConnected,
    InvalidSocket,
    AddrInUse,
    ConnectionRefused,
    ConnectionReset,
    Invalid,
    /// The overlay memory budget is used up.
    NoBuffers,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    /// Peer closed / reset: reads return EOF or an error.
    pub hup: bool,
}

/// Packet queues that smoltcp reads from and writes to.
#[derive(Default)]
struct Queues {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
}

struct RxToken(Vec<u8>);
struct TxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for Queues {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(RxToken, TxToken<'_>)> {
        let pkt = self.inbound.pop_front()?;
        Some((RxToken(pkt), TxToken(&mut self.outbound)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<TxToken<'_>> {
        Some(TxToken(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

enum Sock {
    Tcp(SocketHandle),
    /// A listener keeps one smoltcp socket listening at a time and moves
    /// connected ones to `ready` (smoltcp listeners accept a single peer).
    /// `listening` is None while the budget can't fund another socket.
    Listener { port: u16, listening: Option<SocketHandle>, ready: VecDeque<SocketHandle>, backlog: usize },
    /// UDP is handled here rather than by smoltcp: received datagrams are
    /// queued as they arrive, so an idle socket costs nothing.
    Udp { port: u16, rx: VecDeque<(SocketAddr, Vec<u8>)>, rx_bytes: usize },
}

pub struct Netstack {
    iface: Interface,
    sockets: SocketSet<'static>,
    dev: Queues,
    socks: BTreeMap<SockId, Sock>,
    /// Closed TCP sockets still finishing their shutdown handshake.
    closing: Vec<SocketHandle>,
    next_id: SockId,
    next_port: u16,
    addrs: Vec<IpAddr>,
    /// Overlay buffer bytes currently allocated (see `limits`).
    used: usize,
    /// Most overlay buffer bytes that may be allocated at once.
    budget: usize,
}

fn random_ephemeral_port() -> u16 {
    let mut b = [0u8; 2];
    let _ = crate::rng::fill(&mut b);
    let span = EPHEMERAL_PORTS.end() - EPHEMERAL_PORTS.start() + 1;
    EPHEMERAL_PORTS.start() + u16::from_le_bytes(b) % span
}

fn smol_now(now: Instant) -> smoltcp::time::Instant {
    smoltcp::time::Instant::from_micros((now.as_nanos() / 1000) as i64)
}

fn endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(addr.ip().into(), addr.port())
}

fn socket_addr(ep: IpEndpoint) -> SocketAddr {
    SocketAddr::new(ep.addr.into(), ep.port)
}

impl Netstack {
    pub fn new(now: Instant) -> Self {
        let mut dev = Queues::default();
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut dev, smol_now(now));
        // Everything not on-link goes "out the tunnel"; with Medium::Ip the
        // gateway is never resolved, it only has to exist.
        let _ = iface.routes_mut().add_default_ipv4_route(core::net::Ipv4Addr::new(100, 100, 100, 100));
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(core::net::Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0x6464, 0x6464));
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            dev,
            socks: BTreeMap::new(),
            closing: Vec::new(),
            next_id: 1,
            // Random start: after a restart with the same tailnet IP, reusing
            // the previous run's 4-tuples would collide with connections the
            // peer still considers established.
            next_port: random_ephemeral_port(),
            addrs: Vec::new(),
            used: 0,
            budget: BUDGET,
        }
    }

    /// Sets this node's tailnet addresses (from the netmap).
    pub fn set_addresses(&mut self, addrs: &[IpAddr]) {
        self.addrs = addrs.to_vec();
        self.iface.update_ip_addrs(|cidrs| {
            cidrs.clear();
            for a in addrs {
                let cidr = match a {
                    IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(*v4), 32),
                    IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(*v6), 128),
                };
                let _ = cidrs.push(cidr);
            }
        });
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addrs
    }

    /// Delivers an IP packet received from the tunnel.
    pub fn inject(&mut self, packet: Vec<u8>) {
        if let Some(packet) = self.deliver_udp(packet) {
            self.dev.inbound.push_back(packet);
        }
    }

    /// Overlay buffer bytes in use (TCP socket buffers, queued datagrams).
    pub fn buffer_usage(&self) -> usize {
        self.used
    }

    /// Releases spare queue capacity (see [`crate::trim_vec`]).
    pub fn trim(&mut self) {
        self.dev.inbound.shrink_to_fit();
        self.dev.outbound.shrink_to_fit();
        crate::trim_vec(&mut self.closing);
        for s in self.socks.values_mut() {
            match s {
                Sock::Udp { rx, .. } => rx.shrink_to_fit(),
                Sock::Listener { ready, .. } => ready.shrink_to_fit(),
                Sock::Tcp(_) => {}
            }
        }
    }

    /// Sets the overlay buffer budget (bytes). Applies to new allocations;
    /// existing buffers are kept.
    pub fn set_budget(&mut self, bytes: usize) {
        self.budget = bytes;
    }

    /// Runs the stack. Returns true if socket state may have changed.
    pub fn poll(&mut self, now: Instant) -> bool {
        let changed = self.iface.poll(smol_now(now), &mut self.dev, &mut self.sockets)
            != smoltcp::iface::PollResult::None;
        self.service_listeners();
        self.reap_closing();
        changed
    }

    /// Takes IP packets the stack wants to send into the tunnel.
    pub fn take_outbound(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.dev.outbound.drain(..)
    }

    /// When [`Self::poll`] should next run (absent new input).
    pub fn poll_at(&mut self, now: Instant) -> Option<Instant> {
        let at = self.iface.poll_at(smol_now(now), &self.sockets)?;
        Some(Instant::from_nanos(at.total_micros().max(0) as u64 * 1000))
    }

    // ---- socket API ------------------------------------------------------

    pub fn tcp_connect(&mut self, remote: SocketAddr) -> Result<SockId, NetError> {
        let handle = self.new_tcp()?;
        let port = self.ephemeral_port();
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        if sock.connect(self.iface.context(), endpoint(remote), port).is_err() {
            self.remove_tcp(handle);
            return Err(NetError::Invalid);
        }
        Ok(self.insert(Sock::Tcp(handle)))
    }

    pub fn tcp_listen(&mut self, port: u16, backlog: usize) -> Result<SockId, NetError> {
        let in_use = self.socks.values().any(|s| matches!(s, Sock::Listener { port: p, .. } if *p == port));
        if in_use || port == 0 {
            return Err(NetError::AddrInUse);
        }
        let listening = self.new_listening(port)?;
        Ok(self.insert(Sock::Listener { port, listening: Some(listening), ready: VecDeque::new(), backlog: backlog.max(1) }))
    }

    /// Accepts a pending connection on a listener.
    pub fn tcp_accept(&mut self, id: SockId) -> Result<(SockId, SocketAddr), NetError> {
        loop {
            let Some(Sock::Listener { ready, .. }) = self.socks.get_mut(&id) else {
                return Err(NetError::InvalidSocket);
            };
            let handle = ready.pop_front().ok_or(NetError::WouldBlock)?;
            match self.sockets.get::<tcp::Socket>(handle).remote_endpoint() {
                Some(peer) => return Ok((self.insert(Sock::Tcp(handle)), socket_addr(peer))),
                // Reset while queued: free it and try the next one, as a
                // kernel would (servers treat a failed accept after poll
                // said "ready" as fatal; sys-ftpd restarts itself).
                None => self.remove_tcp(handle),
            }
        }
    }

    pub fn send(&mut self, id: SockId, data: &[u8]) -> Result<usize, NetError> {
        let sock = self.tcp(id)?;
        if !sock.may_send() {
            return Err(if sock.state() == tcp::State::SynSent { NetError::WouldBlock } else { NetError::NotConnected });
        }
        match sock.send_slice(data) {
            Ok(0) if !data.is_empty() => Err(NetError::WouldBlock),
            Ok(n) => Ok(n),
            Err(_) => Err(NetError::NotConnected),
        }
    }

    /// Reads stream data. `Ok(0)` means the peer closed (EOF).
    pub fn recv(&mut self, id: SockId, buf: &mut [u8]) -> Result<usize, NetError> {
        let sock = self.tcp(id)?;
        match sock.recv_slice(buf) {
            Ok(0) if sock.may_recv() || sock.state() == tcp::State::SynSent => Err(NetError::WouldBlock),
            Ok(n) => Ok(n),
            Err(tcp::RecvError::Finished) => Ok(0),
            Err(tcp::RecvError::InvalidState) => {
                if sock.state() == tcp::State::Closed {
                    Err(NetError::ConnectionReset)
                } else {
                    Err(NetError::WouldBlock)
                }
            }
        }
    }

    /// Half-closes the sending side (FIN).
    pub fn shutdown_write(&mut self, id: SockId) -> Result<(), NetError> {
        self.tcp(id)?.close();
        Ok(())
    }

    pub fn udp_bind(&mut self, port: u16) -> Result<SockId, NetError> {
        let port = if port == 0 { self.ephemeral_port() } else { port };
        if self.udp_port_in_use(port) {
            return Err(NetError::AddrInUse);
        }
        Ok(self.insert(Sock::Udp { port, rx: VecDeque::new(), rx_bytes: 0 }))
    }

    pub fn udp_send_to(&mut self, id: SockId, data: &[u8], dst: SocketAddr) -> Result<(), NetError> {
        let Some(Sock::Udp { port, .. }) = self.socks.get(&id) else { return Err(NetError::InvalidSocket) };
        let src = self.addrs.iter().copied().find(|a| a.is_ipv4() == dst.is_ipv4()).ok_or(NetError::Invalid)?;
        let pkt = udp::build(SocketAddr::new(src, *port), dst, data, MTU).ok_or(NetError::Invalid)?;
        self.dev.outbound.push_back(pkt);
        Ok(())
    }

    pub fn udp_recv_from(&mut self, id: SockId, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        let Some(Sock::Udp { rx, rx_bytes, .. }) = self.socks.get_mut(&id) else { return Err(NetError::InvalidSocket) };
        let (from, data) = rx.pop_front().ok_or(NetError::WouldBlock)?;
        let cost = data.capacity();
        *rx_bytes -= cost;
        self.used -= cost;
        // Like a truncating recv: a datagram larger than `buf` loses its tail.
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, from))
    }

    pub fn readiness(&self, id: SockId) -> Readiness {
        match self.socks.get(&id) {
            Some(Sock::Tcp(h)) => {
                let s = self.sockets.get::<tcp::Socket>(*h);
                let closed = matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait);
                Readiness {
                    readable: s.can_recv() || (!s.may_recv() && s.state() != tcp::State::SynSent),
                    writable: s.can_send(),
                    hup: closed || !s.may_recv() && s.state() != tcp::State::SynSent,
                }
            }
            Some(Sock::Listener { ready, .. }) => Readiness { readable: !ready.is_empty(), ..Default::default() },
            Some(Sock::Udp { rx, .. }) => Readiness { readable: !rx.is_empty(), writable: true, hup: false },
            None => Readiness { hup: true, ..Default::default() },
        }
    }

    pub fn local_addr(&self, id: SockId) -> Option<SocketAddr> {
        match self.socks.get(&id)? {
            Sock::Tcp(h) => self.sockets.get::<tcp::Socket>(*h).local_endpoint().map(socket_addr),
            Sock::Listener { port, .. } => Some(SocketAddr::new(*self.addrs.first()?, *port)),
            Sock::Udp { port, .. } => Some(SocketAddr::new(*self.addrs.first()?, *port)),
        }
    }

    pub fn peer_addr(&self, id: SockId) -> Option<SocketAddr> {
        match self.socks.get(&id)? {
            Sock::Tcp(h) => self.sockets.get::<tcp::Socket>(*h).remote_endpoint().map(socket_addr),
            _ => None,
        }
    }

    pub fn close(&mut self, id: SockId) {
        match self.socks.remove(&id) {
            Some(Sock::Tcp(h)) => {
                self.sockets.get_mut::<tcp::Socket>(h).close();
                self.closing.push(h);
            }
            Some(Sock::Listener { listening, ready, .. }) => {
                if let Some(h) = listening {
                    self.remove_tcp(h);
                }
                for h in ready {
                    self.sockets.get_mut::<tcp::Socket>(h).abort();
                    self.closing.push(h);
                }
            }
            Some(Sock::Udp { rx_bytes, .. }) => {
                self.used -= rx_bytes;
            }
            None => {}
        }
    }

    // ---- internals -------------------------------------------------------

    fn insert(&mut self, s: Sock) -> SockId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.socks.insert(id, s);
        id
    }

    fn tcp(&mut self, id: SockId) -> Result<&mut tcp::Socket<'static>, NetError> {
        match self.socks.get(&id) {
            Some(Sock::Tcp(h)) => Ok(self.sockets.get_mut::<tcp::Socket>(*h)),
            _ => Err(NetError::InvalidSocket),
        }
    }

    /// A TCP socket with its buffers, if the budget allows. Closed sockets
    /// still finishing their shutdown give way first (oldest first): apps
    /// like Moonlight open and close many connections in a burst, and a
    /// live connection matters more than a polite goodbye on a dead one.
    fn new_tcp(&mut self) -> Result<SocketHandle, NetError> {
        while self.used.saturating_add(2 * TCP_MIN) > self.budget && !self.closing.is_empty() {
            let h = self.closing.remove(0);
            // Dropped without its RST; the peer gets one if it sends again.
            self.remove_tcp(h);
        }
        if self.used.saturating_add(2 * TCP_MIN) > self.budget {
            return Err(NetError::NoBuffers);
        }
        let free = self.budget - self.used;
        let (rx_size, tx_size) = (tcp_buffer_size(free, TCP_RX), tcp_buffer_size(free, TCP_TX));
        self.used += rx_size + tx_size;
        let rx = tcp::SocketBuffer::new(vec![0u8; rx_size]);
        let tx = tcp::SocketBuffer::new(vec![0u8; tx_size]);
        let mut sock = tcp::Socket::new(rx, tx);
        sock.set_nagle_enabled(false);
        sock.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
        Ok(self.sockets.add(sock))
    }

    fn remove_tcp(&mut self, h: SocketHandle) {
        self.used -= tcp_buffers(self.sockets.get::<tcp::Socket>(h));
        self.sockets.remove(h);
    }

    fn new_listening(&mut self, port: u16) -> Result<SocketHandle, NetError> {
        let handle = self.new_tcp()?;
        if self.sockets.get_mut::<tcp::Socket>(handle).listen(port).is_err() {
            self.remove_tcp(handle);
            return Err(NetError::Invalid);
        }
        Ok(handle)
    }

    fn udp_port_in_use(&self, port: u16) -> bool {
        self.socks.values().any(|s| matches!(s, Sock::Udp { port: p, .. } if *p == port))
    }

    /// Queues a UDP datagram for a bound socket. Returns the packet if it is
    /// not one (smoltcp then handles or drops it).
    fn deliver_udp(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
        let Some(d) = udp::parse(&packet) else { return Some(packet) };
        if !self.addrs.contains(&d.dst.ip()) {
            return Some(packet);
        }
        let port = d.dst.port();
        let Some(Sock::Udp { rx, rx_bytes, .. }) = self.socks.values_mut().find(|s| matches!(s, Sock::Udp { port: p, .. } if *p == port))
        else {
            return Some(packet);
        };
        let (src, range) = (d.src, d.payload);
        let mut data = packet;
        data.truncate(range.end);
        data.drain(..range.start);
        let cost = data.capacity();
        // Full: drop the oldest datagrams of this socket (a reader that falls
        // behind wants fresh data; a stalled one shouldn't pin stale bytes).
        while !rx.is_empty() && (*rx_bytes + cost > UDP_RX || self.used.saturating_add(cost) > self.budget) {
            let (_, old) = rx.pop_front().expect("non-empty");
            *rx_bytes -= old.capacity();
            self.used -= old.capacity();
        }
        if *rx_bytes + cost > UDP_RX || self.used.saturating_add(cost) > self.budget {
            return None;  // still no room (other sockets hold the budget): drop
        }
        *rx_bytes += cost;
        self.used += cost;
        rx.push_back((src, data));
        None
    }

    fn ephemeral_port(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = if p == *EPHEMERAL_PORTS.end() { *EPHEMERAL_PORTS.start() } else { p + 1 };
        p
    }

    /// Moves connected listener sockets to the accept queue and re-arms.
    fn service_listeners(&mut self) {
        let mut rearm = Vec::new();
        let mut dead = Vec::new();
        for (&id, s) in self.socks.iter_mut() {
            if let Sock::Listener { listening, ready, backlog, .. } = s {
                // Connections reset before being accepted: readiness must
                // only report live ones.
                ready.retain(|&h| {
                    let alive = self.sockets.get::<tcp::Socket>(h).remote_endpoint().is_some();
                    if !alive {
                        dead.push(h);
                    }
                    alive
                });
                match *listening {
                    Some(h) => {
                        let st = self.sockets.get::<tcp::Socket>(h).state();
                        if st != tcp::State::Listen && st != tcp::State::SynReceived && ready.len() < *backlog {
                            ready.push_back(h);
                            *listening = None;
                            rearm.push(id);
                        }
                    }
                    // Unfunded earlier: try again.
                    None => rearm.push(id),
                }
            }
        }
        for h in dead {
            self.remove_tcp(h);
        }
        for id in rearm {
            let Some(Sock::Listener { port, .. }) = self.socks.get(&id) else { continue };
            let port = *port;
            if let Ok(h) = self.new_listening(port) {
                if let Some(Sock::Listener { listening, .. }) = self.socks.get_mut(&id) {
                    *listening = Some(h);
                }
            }
        }
    }

    fn reap_closing(&mut self) {
        let sockets = &mut self.sockets;
        let mut freed = 0;
        self.closing.retain(|&h| {
            // TIME_WAIT only guards against stray old segments; not worth
            // holding a socket's buffers for.
            let done = matches!(sockets.get::<tcp::Socket>(h).state(), tcp::State::Closed | tcp::State::TimeWait);
            if done {
                freed += tcp_buffers(sockets.get::<tcp::Socket>(h));
                sockets.remove(h);
            }
            !done
        });
        self.used -= freed;
    }
}

/// Overlay budget bytes a TCP socket's buffers take.
fn tcp_buffers(sock: &tcp::Socket) -> usize {
    sock.recv_capacity() + sock.send_capacity()
}

/// IPv4/IPv6 + UDP framing for the overlay's own UDP sockets.
mod udp {
    use alloc::vec::Vec;
    use core::net::{IpAddr, SocketAddr};
    use core::ops::Range;

    const PROTO_UDP: u8 = 17;

    pub struct Datagram {
        pub src: SocketAddr,
        pub dst: SocketAddr,
        /// Payload bytes within the packet.
        pub payload: Range<usize>,
    }

    /// Parses an unfragmented UDP packet (no IPv6 extension headers).
    pub fn parse(p: &[u8]) -> Option<Datagram> {
        let (src, dst, off) = match p.first()? >> 4 {
            4 => {
                let ihl = usize::from(p[0] & 0x0f) * 4;
                let total = usize::from(u16::from_be_bytes([*p.get(2)?, *p.get(3)?]));
                let frag = u16::from_be_bytes([*p.get(6)?, *p.get(7)?]);
                // More-fragments set, or a non-zero offset: not ours to take.
                if ihl < 20 || total > p.len() || *p.get(9)? != PROTO_UDP || frag & 0x3fff != 0 {
                    return None;
                }
                let src: [u8; 4] = p[12..16].try_into().ok()?;
                let dst: [u8; 4] = p[16..20].try_into().ok()?;
                (IpAddr::from(src), IpAddr::from(dst), ihl)
            }
            6 => {
                if p.len() < 40 || p[6] != PROTO_UDP {
                    return None;
                }
                let src: [u8; 16] = p[8..24].try_into().ok()?;
                let dst: [u8; 16] = p[24..40].try_into().ok()?;
                (IpAddr::from(src), IpAddr::from(dst), 40)
            }
            _ => return None,
        };
        let h = p.get(off..off + 8)?;
        let len = usize::from(u16::from_be_bytes([h[4], h[5]]));
        if len < 8 || off + len > p.len() {
            return None;
        }
        Some(Datagram {
            src: SocketAddr::new(src, u16::from_be_bytes([h[0], h[1]])),
            dst: SocketAddr::new(dst, u16::from_be_bytes([h[2], h[3]])),
            payload: off + 8..off + len,
        })
    }

    /// Builds an IP packet carrying one datagram (None if it exceeds `mtu`).
    pub fn build(src: SocketAddr, dst: SocketAddr, data: &[u8], mtu: usize) -> Option<Vec<u8>> {
        let ip_len = if src.is_ipv4() { 20 } else { 40 };
        let udp_len = 8 + data.len();
        if ip_len + udp_len > mtu || src.is_ipv4() != dst.is_ipv4() {
            return None;
        }
        let mut p = Vec::with_capacity(ip_len + udp_len);
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let total = (ip_len + udp_len) as u16;
                p.extend_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0]);
                p[2..4].copy_from_slice(&total.to_be_bytes());
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                let sum = !fold(sum_bytes(0, &p[..20]));
                p[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                p.extend_from_slice(&[0x60, 0, 0, 0]);
                p.extend_from_slice(&(udp_len as u16).to_be_bytes());
                p.extend_from_slice(&[PROTO_UDP, 64]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
            }
            _ => return None,
        }
        p.extend_from_slice(&src.port().to_be_bytes());
        p.extend_from_slice(&dst.port().to_be_bytes());
        p.extend_from_slice(&(udp_len as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(data);
        // Checksum over the pseudo-header, header and payload.
        let mut acc = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => sum_bytes(sum_bytes(0, &s.octets()), &d.octets()),
            (IpAddr::V6(s), IpAddr::V6(d)) => sum_bytes(sum_bytes(0, &s.octets()), &d.octets()),
            _ => return None,
        };
        acc += u32::from(PROTO_UDP) + udp_len as u32;
        acc = sum_bytes(acc, &p[ip_len..]);
        let sum = match !fold(acc) {
            0 => 0xffff,  // 0 means "no checksum" in UDP
            s => s,
        };
        p[ip_len + 6..ip_len + 8].copy_from_slice(&sum.to_be_bytes());
        Some(p)
    }

    fn sum_bytes(mut acc: u32, b: &[u8]) -> u32 {
        let mut chunks = b.chunks_exact(2);
        for c in &mut chunks {
            acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            acc += u32::from(*last) << 8;
        }
        acc
    }

    fn fold(mut acc: u32) -> u16 {
        while acc > 0xffff {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        acc as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    /// A burst loss early in a bulk transfer (DERP drops when a client's send
    /// queue overflows) must be recovered by retransmission.
    #[test]
    fn tcp_recovers_from_burst_loss() {
        let a_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        let b_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut now = Instant::from_millis(0);
        let mut a = Netstack::new(now);
        let mut b = Netstack::new(now);
        a.set_addresses(&[a_ip]);
        b.set_addresses(&[b_ip]);
        let listener = b.tcp_listen(5201, 4).unwrap();
        let client = a.tcp_connect(SocketAddr::new(b_ip, 5201)).unwrap();
        let total = 300_000usize;
        let (mut sent, mut got, mut server) = (0usize, 0usize, None);
        let mut a_to_b = 0usize;
        for _ in 0..20_000 {
            now = now + core::time::Duration::from_millis(1);
            if a.readiness(client).writable && sent < total {
                let chunk = alloc::vec![0x5au8; (total - sent).min(65536)];
                if let Ok(n) = a.send(client, &chunk) {
                    sent += n;
                }
            }
            a.poll(now);
            let out: Vec<_> = a.take_outbound().collect();
            for p in out {
                a_to_b += 1;
                // Drop data packets 4..=22 of the connection (a burst).
                if (4..=22).contains(&a_to_b) {
                    continue;
                }
                b.inject(p);
            }
            b.poll(now);
            if server.is_none() {
                server = b.tcp_accept(listener).ok().map(|(s, _)| s);
            }
            if let Some(s) = server {
                let mut buf = [0u8; 65536];
                while let Ok(n) = b.recv(s, &mut buf) {
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
            }
            b.poll(now);
            let back: Vec<_> = b.take_outbound().collect();
            back.into_iter().for_each(|p| a.inject(p));
            if got == total {
                break;
            }
        }
        assert_eq!(got, total, "transfer stalled after burst loss (sent {sent})");
    }

    /// The stack answers pings to its own addresses (peers' `tailscale ping
    /// --icmp` and plain ping rely on it).
    #[test]
    fn answers_icmp_echo() {
        let mut net = Netstack::new(Instant::from_millis(0));
        net.set_addresses(&[IpAddr::V4(Ipv4Addr::new(100, 64, 0, 4))]);
        // 100.64.0.1 -> 100.64.0.4 ICMP echo request, id 1 seq 1, no payload.
        let mut pkt = alloc::vec![
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 100, 64, 0, 1, 100, 64, 0, 4, //
            8, 0, 0, 0, 0, 1, 0, 1,
        ];
        let csum = |b: &[u8]| {
            let mut s: u32 = b.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
            while s > 0xffff {
                s = (s & 0xffff) + (s >> 16);
            }
            !(s as u16)
        };
        let ip = csum(&pkt[..20]).to_be_bytes();
        pkt[10..12].copy_from_slice(&ip);
        let icmp = csum(&pkt[20..]).to_be_bytes();
        pkt[22..24].copy_from_slice(&icmp);
        net.inject(pkt);
        net.poll(Instant::from_millis(1));
        let out: Vec<_> = net.take_outbound().collect();
        assert_eq!(out.len(), 1, "expected an echo reply");
        assert_eq!(out[0][20], 0, "ICMP type 0 = echo reply");
        assert_eq!(&out[0][16..20], &[100, 64, 0, 1]);
    }

    /// Two stacks wired back to back exchange a TCP stream and a datagram.
    #[test]
    fn tcp_and_udp_between_two_stacks() {
        let a_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        let b_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut now = Instant::from_millis(0);
        let mut a = Netstack::new(now);
        let mut b = Netstack::new(now);
        a.set_addresses(&[a_ip]);
        b.set_addresses(&[b_ip]);

        let listener = b.tcp_listen(7, 4).unwrap();
        let client = a.tcp_connect(SocketAddr::new(b_ip, 7)).unwrap();
        let ua = a.udp_bind(5000).unwrap();
        let ub = b.udp_bind(6000).unwrap();
        a.udp_send_to(ua, b"datagram", SocketAddr::new(b_ip, 6000)).unwrap();

        let mut server = None;
        let mut sent = false;
        let mut got = Vec::new();
        let mut dgram = None;
        for _ in 0..200 {
            now = now + core::time::Duration::from_millis(10);
            a.poll(now);
            let to_b: Vec<_> = a.take_outbound().collect();
            to_b.into_iter().for_each(|p| b.inject(p));
            b.poll(now);
            let to_a: Vec<_> = b.take_outbound().collect();
            to_a.into_iter().for_each(|p| a.inject(p));
            a.poll(now);

            if server.is_none() {
                if let Ok((s, peer)) = b.tcp_accept(listener) {
                    assert_eq!(peer.ip(), a_ip);
                    server = Some(s);
                }
            }
            if !sent && a.readiness(client).writable {
                assert_eq!(a.send(client, b"hello over smoltcp").unwrap(), 18);
                sent = true;
            }
            if let Some(s) = server {
                let mut buf = [0u8; 64];
                if let Ok(n) = b.recv(s, &mut buf) {
                    got.extend_from_slice(&buf[..n]);
                }
            }
            let mut buf = [0u8; 64];
            if let Ok((n, from)) = b.udp_recv_from(ub, &mut buf) {
                dgram = Some((buf[..n].to_vec(), from));
            }
        }
        assert_eq!(got, b"hello over smoltcp");
        assert_eq!(dgram, Some((b"datagram".to_vec(), SocketAddr::new(a_ip, 5000))));
    }

    #[test]
    fn udp_checksums_are_valid() {
        use smoltcp::wire::{IpAddress, Ipv4Packet, Ipv6Packet, UdpPacket};
        let v4 = udp::build("100.64.0.1:5000".parse().unwrap(), "100.64.0.2:53".parse().unwrap(), b"hello", MTU).unwrap();
        let ip = Ipv4Packet::new_checked(&v4[..]).unwrap();
        assert!(ip.verify_checksum());
        let u = UdpPacket::new_checked(ip.payload()).unwrap();
        assert!(u.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr())));
        assert_eq!(u.payload(), b"hello");

        let v6 = udp::build("[fd7a:115c:a1e0::1]:5000".parse().unwrap(), "[fd7a:115c:a1e0::2]:7".parse().unwrap(), b"odd", MTU).unwrap();
        let ip = Ipv6Packet::new_checked(&v6[..]).unwrap();
        let u = UdpPacket::new_checked(ip.payload()).unwrap();
        assert!(u.verify_checksum(&IpAddress::Ipv6(ip.src_addr()), &IpAddress::Ipv6(ip.dst_addr())));

        let d = udp::parse(&v4).unwrap();
        assert_eq!(d.dst, "100.64.0.2:53".parse().unwrap());
        assert_eq!(&v4[d.payload], b"hello");
        assert!(udp::build("100.64.0.1:1".parse().unwrap(), "100.64.0.2:1".parse().unwrap(), &[0; MTU], MTU).is_none());
    }

    #[test]
    fn buffers_are_accounted_and_released() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let mut n = Netstack::new(Instant::from_nanos(0));
        n.set_addresses(&[ip]);
        let t = n.tcp_connect("100.64.0.2:80".parse().unwrap()).unwrap();
        assert_eq!(n.buffer_usage(), TCP_RX + TCP_TX);
        let u = n.udp_bind(9).unwrap();
        let pkt = udp::build("100.64.0.2:1234".parse().unwrap(), SocketAddr::new(ip, 9), b"ping", MTU).unwrap();
        n.inject(pkt);
        assert!(n.readiness(u).readable);
        assert!(n.buffer_usage() > TCP_RX + TCP_TX);
        let mut buf = [0u8; 16];
        assert_eq!(n.udp_recv_from(u, &mut buf).unwrap(), (4, "100.64.0.2:1234".parse().unwrap()));
        assert_eq!(n.buffer_usage(), TCP_RX + TCP_TX);
        n.close(u);
        n.close(t);
        // An unanswered SYN: abort-close frees the buffers once reaped.
        for i in 0..200 {
            n.poll(Instant::from_nanos(i * 1_000_000_000));
        }
        let l = n.tcp_listen(80, 1).unwrap();
        n.close(l);
        assert_eq!(n.buffer_usage(), 0, "everything released");
    }

    /// Runs two stacks back to back for `ms` milliseconds.
    fn exchange(a: &mut Netstack, b: &mut Netstack, now: &mut Instant, ms: u64) {
        for _ in 0..ms / 10 {
            *now = *now + core::time::Duration::from_millis(10);
            a.poll(*now);
            let to_b: Vec<_> = a.take_outbound().collect();
            to_b.into_iter().for_each(|p| b.inject(p));
            b.poll(*now);
            let to_a: Vec<_> = b.take_outbound().collect();
            to_a.into_iter().for_each(|p| a.inject(p));
        }
    }

    /// A gracefully closed connection frees its buffers once the FIN
    /// exchange is done, without sitting out TIME_WAIT.
    #[test]
    fn closed_connection_frees_buffers_promptly() {
        let (a_ip, b_ip) = (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)));
        let mut now = Instant::from_millis(0);
        let (mut a, mut b) = (Netstack::new(now), Netstack::new(now));
        a.set_addresses(&[a_ip]);
        b.set_addresses(&[b_ip]);
        let listener = b.tcp_listen(7, 4).unwrap();
        let client = a.tcp_connect(SocketAddr::new(b_ip, 7)).unwrap();
        exchange(&mut a, &mut b, &mut now, 200);
        let (server, _) = b.tcp_accept(listener).unwrap();
        a.close(client);
        exchange(&mut a, &mut b, &mut now, 200);
        b.close(server);
        exchange(&mut a, &mut b, &mut now, 500);
        assert_eq!(a.buffer_usage(), 0, "client side released before TIME_WAIT ends");
    }

    /// With the budget used up by closing sockets, a new connection still
    /// gets buffers (the Switch's limits; `--features switch-limits`).
    #[cfg(any(target_os = "horizon", feature = "switch-limits"))]
    #[test]
    fn closing_sockets_give_way_to_new_ones() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let mut n = Netstack::new(Instant::from_nanos(0));
        n.set_addresses(&[ip]);
        let peer = |port| SocketAddr::new("100.64.0.2".parse().unwrap(), port);
        // Unanswered connects hold their buffers until the budget runs out.
        let mut open = Vec::new();
        while let Ok(s) = n.tcp_connect(peer(80 + open.len() as u16)) {
            open.push(s);
        }
        assert_eq!(open.len(), 17, "connections that fit in the Switch's budget");
        for &s in &open[..2] {
            n.close(s);
        }
        n.tcp_connect(peer(2)).expect("a closing socket gave way");
        while n.tcp_connect(peer(3)).is_ok() {}
        for &s in &open[2..] {
            assert!(n.peer_addr(s).is_some(), "open ones are never evicted");
        }
        assert!(n.buffer_usage() <= BUDGET);
    }

    #[test]
    fn tcp_buffers_shrink_as_the_budget_fills() {
        let k = 1024;
        assert_eq!(tcp_buffer_size(320 * k, 32 * k), 32 * k);
        assert_eq!(tcp_buffer_size(256 * k, 32 * k), 16 * k);
        assert_eq!(tcp_buffer_size(100 * k, 32 * k), 8 * k);
        assert_eq!(tcp_buffer_size(50 * k, 32 * k), 4 * k);
        assert_eq!(tcp_buffer_size(9 * k, 32 * k), 4 * k);
        assert_eq!(tcp_buffer_size(usize::MAX, 64 * k), 64 * k);
    }

    #[test]
    fn full_udp_queue_keeps_the_newest() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let mut n = Netstack::new(Instant::from_nanos(0));
        n.set_addresses(&[ip]);
        let u = n.udp_bind(9).unwrap();
        let mut sent = 0u32;
        // Far more than fits: the queue holds only the most recent ones.
        while sent < 2000 {
            let payload = sent.to_be_bytes();
            n.inject(udp::build("100.64.0.2:1".parse().unwrap(), SocketAddr::new(ip, 9), &payload, MTU).unwrap());
            sent += 1;
        }
        assert!(n.buffer_usage() <= UDP_RX);
        let mut buf = [0u8; 4];
        let mut last = None;
        while let Ok((4, _)) = n.udp_recv_from(u, &mut buf) {
            last = Some(u32::from_be_bytes(buf));
        }
        assert_eq!(last, Some(1999), "the newest datagram survives");
        assert_eq!(n.buffer_usage(), 0);
    }
}
