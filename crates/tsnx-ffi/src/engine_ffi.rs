//! The engine over the C ABI. The C driver owns sockets and the clock; see
//! `include/tsnx.h` for the contract.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use tsnx_core::control::client::ControlConfig;
use tsnx_core::engine::{Engine, EngineConfig, Event, Io};
use tsnx_core::netstack::NetError;
use tsnx_core::time::Instant;

#[repr(C)]
pub struct TsnxConfig {
    pub control_url: *const c_char,
    /// May be NULL.
    pub auth_key: *const c_char,
    pub hostname: *const c_char,
    pub machine_key: *const u8,
    pub node_key: *const u8,
    /// Persisted disco private key (32 bytes); NULL = generate per run.
    pub disco_key: *const u8,
    /// Optional extra trusted root certificate (DER), for dev servers.
    pub extra_root_der: *const u8,
    pub extra_root_len: usize,
}

pub const TSNX_IO_CONNECT: u32 = 1;
pub const TSNX_IO_SEND: u32 = 2;
pub const TSNX_IO_CLOSE: u32 = 3;
pub const TSNX_IO_SEND_UDP: u32 = 4;

#[repr(C)]
pub struct TsnxIo {
    pub kind: u32,
    pub id: u32,
    /// NUL-terminated host name or IP literal (CONNECT).
    pub host: *const c_char,
    pub port: u16,
    /// Bytes to send (SEND, SEND_UDP). Valid until the next `tsnx_engine_poll_io`.
    pub data: *const u8,
    pub len: usize,
    /// Destination (SEND_UDP).
    pub addr: TsnxAddr,
}

pub const TSNX_EVENT_LOG: u32 = 0;
pub const TSNX_EVENT_LOGIN_URL: u32 = 1;
pub const TSNX_EVENT_AUTHORIZED: u32 = 2;
pub const TSNX_EVENT_ADDRESSES: u32 = 3;
pub const TSNX_EVENT_PEERS: u32 = 4;
pub const TSNX_EVENT_HOME_DERP: u32 = 5;
pub const TSNX_EVENT_ERROR: u32 = 6;
pub const TSNX_EVENT_ENDPOINTS: u32 = 7;
pub const TSNX_EVENT_PEER_PATH: u32 = 8;
pub const TSNX_EVENT_NODE_KEY: u32 = 9;

#[repr(C)]
pub struct TsnxEvent {
    pub kind: u32,
    /// Numeric detail (peer count, DERP region).
    pub value: u32,
    /// NUL-terminated text. Valid until the next `tsnx_engine_poll_event`.
    pub text: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TsnxAddr {
    /// 4 or 6.
    pub family: u8,
    /// IPv4 uses the first 4 bytes.
    pub ip: [u8; 16],
    pub port: u16,
}

pub struct TsnxEngine {
    engine: Engine,
    now: Instant,
    io_host: Vec<u8>,
    io_data: Vec<u8>,
    event_text: Vec<u8>,
}

unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        CStr::from_ptr(p).to_str().ok()
    }
}

/// Creates an engine. Keys are 32-byte private keys. Returns NULL on bad
/// arguments (e.g. RNG not seeded, invalid URL).
#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_new(cfg: *const TsnxConfig, now_ns: u64, unix_secs: u64) -> *mut TsnxEngine {
    let cfg = &*cfg;
    let (Some(url), Some(hostname)) = (cstr(cfg.control_url), cstr(cfg.hostname)) else {
        return core::ptr::null_mut();
    };
    if cfg.machine_key.is_null() || cfg.node_key.is_null() {
        return core::ptr::null_mut();
    }
    let extra_roots = if cfg.extra_root_der.is_null() || cfg.extra_root_len == 0 {
        Vec::new()
    } else {
        alloc::vec![core::slice::from_raw_parts(cfg.extra_root_der, cfg.extra_root_len).to_vec()]
    };
    let config = EngineConfig {
        control: ControlConfig {
            url: url.into(),
            auth_key: cstr(cfg.auth_key).filter(|k| !k.is_empty()).map(String::from),
            hostname: hostname.into(),
            extra_roots,
        },
        machine_private: *(cfg.machine_key as *const [u8; 32]),
        node_private: *(cfg.node_key as *const [u8; 32]),
        disco_private: if cfg.disco_key.is_null() {
            match tsnx_core::rng::bytes32() {
                Ok(k) => k,
                Err(_) => return core::ptr::null_mut(),
            }
        } else {
            *(cfg.disco_key as *const [u8; 32])
        },
    };
    let now = Instant::from_nanos(now_ns);
    match Engine::new(config, now, Duration::from_secs(unix_secs)) {
        Ok(engine) => Box::into_raw(Box::new(TsnxEngine {
            engine,
            now,
            io_host: Vec::new(),
            io_data: Vec::new(),
            event_text: Vec::new(),
        })),
        Err(_) => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_free(e: *mut TsnxEngine) {
    if !e.is_null() {
        drop(Box::from_raw(e));
    }
}

/// Takes the next I/O request. Returns false when there is none.
#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_poll_io(e: *mut TsnxEngine, out: *mut TsnxIo) -> bool {
    let e = &mut *e;
    let Some(io) = e.engine.poll_io() else { return false };
    let out = &mut *out;
    *out = TsnxIo {
        kind: 0,
        id: 0,
        host: c"".as_ptr(),
        port: 0,
        data: core::ptr::null(),
        len: 0,
        addr: TsnxAddr { family: 0, ip: [0; 16], port: 0 },
    };
    match io {
        Io::Connect { id, host, port } => {
            e.io_host = host.into_bytes();
            e.io_host.push(0);
            out.kind = TSNX_IO_CONNECT;
            out.id = id;
            out.host = e.io_host.as_ptr().cast();
            out.port = port;
        }
        Io::Send { id, data } => {
            e.io_data = data;
            out.kind = TSNX_IO_SEND;
            out.id = id;
            out.data = e.io_data.as_ptr();
            out.len = e.io_data.len();
        }
        Io::Close { id } => {
            out.kind = TSNX_IO_CLOSE;
            out.id = id;
        }
        Io::SendUdp { dst, data } => {
            e.io_data = data;
            out.kind = TSNX_IO_SEND_UDP;
            out.data = e.io_data.as_ptr();
            out.len = e.io_data.len();
            out.addr = from_sockaddr(dst);
        }
    }
    true
}

/// A datagram arrived on the engine's UDP socket.
#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_udp(e: *mut TsnxEngine, src: *const TsnxAddr, data: *const u8, len: usize, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    if let Some(src) = to_sockaddr(&*src) {
        e.engine.handle_udp(src, core::slice::from_raw_parts(data, len), e.now);
    }
}

/// Sets the local UDP endpoints (interface IP + bound port) to advertise.
#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_set_local_endpoints(e: *mut TsnxEngine, eps: *const TsnxAddr, n: usize, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    let list: Vec<SocketAddr> = (0..n).filter_map(|i| to_sockaddr(&*eps.add(i))).collect();
    e.engine.set_local_endpoints(&list, e.now);
}

/// Takes the next status event. Returns false when there is none.
#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_poll_event(e: *mut TsnxEngine, out: *mut TsnxEvent) -> bool {
    let e = &mut *e;
    let Some(ev) = e.engine.poll_event() else { return false };
    let (kind, value, text) = match ev {
        Event::LoginUrl(u) => (TSNX_EVENT_LOGIN_URL, 0, u),
        Event::Authorized => (TSNX_EVENT_AUTHORIZED, 0, String::new()),
        Event::Addresses(a) => {
            let text = a.iter().map(|ip| alloc::format!("{ip}")).collect::<Vec<_>>().join(" ");
            (TSNX_EVENT_ADDRESSES, a.len() as u32, text)
        }
        Event::Peers(n) => (TSNX_EVENT_PEERS, n as u32, String::new()),
        Event::HomeDerp(r) => (TSNX_EVENT_HOME_DERP, r, String::new()),
        Event::Error(s) => (TSNX_EVENT_ERROR, 0, s),
        Event::Endpoints(eps) => {
            let text = eps.iter().map(|e| alloc::format!("{e}")).collect::<Vec<_>>().join(" ");
            (TSNX_EVENT_ENDPOINTS, eps.len() as u32, text)
        }
        Event::PeerPath { peer, direct } => match direct {
            Some(addr) => (TSNX_EVENT_PEER_PATH, 1, alloc::format!("{peer} direct {addr}")),
            None => (TSNX_EVENT_PEER_PATH, 0, alloc::format!("{peer} via DERP")),
        },
        Event::Log(s) => (TSNX_EVENT_LOG, 0, s),
        Event::NodeKeyChanged => (TSNX_EVENT_NODE_KEY, 0, String::new()),
    };
    e.event_text = text.into_bytes();
    e.event_text.push(0);
    *out = TsnxEvent { kind, value, text: e.event_text.as_ptr().cast() };
    true
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_connected(e: *mut TsnxEngine, id: u32, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    e.engine.handle_connected(id, e.now);
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_data(e: *mut TsnxEngine, id: u32, data: *const u8, len: usize, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    e.engine.handle_data(id, core::slice::from_raw_parts(data, len), e.now);
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_closed(e: *mut TsnxEngine, id: u32, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    e.engine.handle_closed(id, e.now);
}

/// Runs timers. Call when `tsnx_engine_next_deadline` has passed (calling it
/// more often is harmless).
#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_timeout(e: *mut TsnxEngine, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    e.engine.handle_timeout(e.now);
}

/// Monotonic time (ns) by which `tsnx_engine_timeout` should be called.
#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_next_deadline(e: *mut TsnxEngine) -> u64 {
    (*e).engine.next_deadline().as_nanos()
}

// ---- overlay sockets ------------------------------------------------------

pub const TSNX_EAGAIN: i32 = -1;
pub const TSNX_ENOTCONN: i32 = -2;
pub const TSNX_EBADF: i32 = -3;
pub const TSNX_EADDRINUSE: i32 = -4;
pub const TSNX_ECONNREFUSED: i32 = -5;
pub const TSNX_ECONNRESET: i32 = -6;
pub const TSNX_EINVAL: i32 = -7;
/// The overlay memory budget is used up (try again later).
pub const TSNX_ENOBUFS: i32 = -8;

fn err(e: NetError) -> i32 {
    match e {
        NetError::WouldBlock => TSNX_EAGAIN,
        NetError::NotConnected => TSNX_ENOTCONN,
        NetError::InvalidSocket => TSNX_EBADF,
        NetError::AddrInUse => TSNX_EADDRINUSE,
        NetError::ConnectionRefused => TSNX_ECONNREFUSED,
        NetError::ConnectionReset => TSNX_ECONNRESET,
        NetError::Invalid => TSNX_EINVAL,
        NetError::NoBuffers => TSNX_ENOBUFS,
    }
}

fn to_sockaddr(a: &TsnxAddr) -> Option<SocketAddr> {
    let ip = match a.family {
        4 => IpAddr::V4(Ipv4Addr::new(a.ip[0], a.ip[1], a.ip[2], a.ip[3])),
        6 => IpAddr::V6(Ipv6Addr::from(a.ip)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, a.port))
}

fn from_sockaddr(s: SocketAddr) -> TsnxAddr {
    let mut ip = [0u8; 16];
    let family = match s.ip() {
        IpAddr::V4(v4) => {
            ip[..4].copy_from_slice(&v4.octets());
            4
        }
        IpAddr::V6(v6) => {
            ip = v6.octets();
            6
        }
    };
    TsnxAddr { family, ip, port: s.port() }
}

/// Runs a socket operation, then lets the engine send what it produced.
unsafe fn with_net<T>(e: *mut TsnxEngine, f: impl FnOnce(&mut tsnx_core::netstack::Netstack) -> T) -> T {
    let e = &mut *e;
    let r = f(e.engine.net());
    e.engine.flush(e.now);
    r
}

/// Starts a TCP connection to a tailnet address. Returns a socket id (> 0)
/// or a negative TSNX_E* code. Poll writability to learn when it's up.
#[no_mangle]
pub unsafe extern "C" fn tsnx_net_tcp_connect(e: *mut TsnxEngine, dst: *const TsnxAddr) -> i32 {
    let Some(dst) = to_sockaddr(&*dst) else { return TSNX_EINVAL };
    with_net(e, |n| n.tcp_connect(dst).map(|id| id as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_net_tcp_listen(e: *mut TsnxEngine, port: u16, backlog: u32) -> i32 {
    with_net(e, |n| n.tcp_listen(port, backlog as usize).map(|id| id as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_net_tcp_accept(e: *mut TsnxEngine, id: i32, peer: *mut TsnxAddr) -> i32 {
    with_net(e, |n| match n.tcp_accept(id as u32) {
        Ok((sock, addr)) => {
            if !peer.is_null() {
                *peer = from_sockaddr(addr);
            }
            sock as i32
        }
        Err(x) => err(x),
    })
}

/// Sends stream data. Returns bytes accepted or a negative TSNX_E* code.
#[no_mangle]
pub unsafe extern "C" fn tsnx_net_send(e: *mut TsnxEngine, id: i32, data: *const u8, len: usize) -> i32 {
    let data = core::slice::from_raw_parts(data, len);
    with_net(e, |n| n.send(id as u32, data).map(|x| x as i32).unwrap_or_else(err))
}

/// Receives stream data. Returns bytes read, 0 at EOF, or a negative code.
#[no_mangle]
pub unsafe extern "C" fn tsnx_net_recv(e: *mut TsnxEngine, id: i32, buf: *mut u8, len: usize) -> i32 {
    let buf = core::slice::from_raw_parts_mut(buf, len);
    with_net(e, |n| n.recv(id as u32, buf).map(|x| x as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_net_shutdown(e: *mut TsnxEngine, id: i32) -> i32 {
    with_net(e, |n| n.shutdown_write(id as u32).map(|_| 0).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_net_udp_bind(e: *mut TsnxEngine, port: u16) -> i32 {
    with_net(e, |n| n.udp_bind(port).map(|id| id as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_net_udp_sendto(
    e: *mut TsnxEngine,
    id: i32,
    data: *const u8,
    len: usize,
    dst: *const TsnxAddr,
) -> i32 {
    let Some(dst) = to_sockaddr(&*dst) else { return TSNX_EINVAL };
    let data = core::slice::from_raw_parts(data, len);
    with_net(e, |n| n.udp_send_to(id as u32, data, dst).map(|_| len as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_net_udp_recvfrom(
    e: *mut TsnxEngine,
    id: i32,
    buf: *mut u8,
    len: usize,
    src: *mut TsnxAddr,
) -> i32 {
    let buf = core::slice::from_raw_parts_mut(buf, len);
    with_net(e, |n| match n.udp_recv_from(id as u32, buf) {
        Ok((got, from)) => {
            if !src.is_null() {
                *src = from_sockaddr(from);
            }
            got as i32
        }
        Err(x) => err(x),
    })
}

pub const TSNX_READABLE: u32 = 1;
pub const TSNX_WRITABLE: u32 = 2;
pub const TSNX_HUP: u32 = 4;

#[no_mangle]
pub unsafe extern "C" fn tsnx_net_readiness(e: *mut TsnxEngine, id: i32) -> u32 {
    let r = (*e).engine.net().readiness(id as u32);
    (r.readable as u32 * TSNX_READABLE) | (r.writable as u32 * TSNX_WRITABLE) | (r.hup as u32 * TSNX_HUP)
}

/// Writes "a.b.c.d name\n" for this node and every peer (MagicDNS names,
/// no trailing dot) into `buf`, NUL-terminated and truncated to `cap`.
/// Returns the full length (like snprintf).
/// Copies our current private node key into `out` (32 bytes), to persist it
/// after TSNX_EVENT_NODE_KEY. Never put it in logs.
#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_node_key(e: *mut TsnxEngine, out: *mut u8) {
    core::ptr::copy_nonoverlapping((*e).engine.node_private_key().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_engine_hosts(e: *mut TsnxEngine, buf: *mut c_char, cap: usize) -> usize {
    use core::fmt::Write;
    let mut s = String::new();
    for (ip, name) in (*e).engine.hosts() {
        let _ = writeln!(s, "{ip} {name}");
    }
    if !buf.is_null() && cap > 0 {
        let n = s.len().min(cap - 1);
        core::ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), n);
        *buf.add(n) = 0;
    }
    s.len()
}

/// Bytes of overlay socket buffers in use (TCP buffers, queued datagrams).
#[no_mangle]
pub unsafe extern "C" fn tsnx_net_buffer_usage(e: *mut TsnxEngine) -> usize {
    (*e).engine.net().buffer_usage()
}

/// Sets the overlay socket buffer budget (bytes; see Netstack::set_budget).
#[no_mangle]
pub unsafe extern "C" fn tsnx_net_set_budget(e: *mut TsnxEngine, bytes: usize) {
    (*e).engine.net().set_budget(bytes);
}

#[no_mangle]
pub unsafe extern "C" fn tsnx_net_close(e: *mut TsnxEngine, id: i32) {
    with_net(e, |n| n.close(id as u32));
}

/// The overlay socket's local address (our tailnet IP + port). 0 or error.
#[no_mangle]
pub unsafe extern "C" fn tsnx_net_local_addr(e: *mut TsnxEngine, id: i32, out: *mut TsnxAddr) -> i32 {
    match (*e).engine.net().local_addr(id as u32) {
        Some(a) => {
            *out = from_sockaddr(a);
            0
        }
        None => TSNX_ENOTCONN,
    }
}

/// The overlay TCP socket's peer address. 0 or error.
#[no_mangle]
pub unsafe extern "C" fn tsnx_net_peer_addr(e: *mut TsnxEngine, id: i32, out: *mut TsnxAddr) -> i32 {
    match (*e).engine.net().peer_addr(id as u32) {
        Some(a) => {
            *out = from_sockaddr(a);
            0
        }
        None => TSNX_ENOTCONN,
    }
}
