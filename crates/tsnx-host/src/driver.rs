//! Host driver: runs the sans-IO engine over real sockets with a
//! simple non-blocking polling loop. Fine for development; the Switch driver
//! uses poll(2) on libnx sockets instead.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use tsnx_core::control::client::ConnId;
use tsnx_core::engine::{Engine, EngineConfig, Event, Io};
use tsnx_core::time::Instant;

pub struct Clock(StdInstant);

impl Clock {
    pub fn new() -> Self {
        Self(StdInstant::now())
    }

    pub fn now(&self) -> Instant {
        Instant::from_nanos(self.0.elapsed().as_nanos() as u64)
    }
}

pub fn unix_now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

/// TSNX_CONNECT_MAP="host:port=addr:port,..." redirects connections, e.g. to
/// reach the e2e headscale container through its published port.
fn resolve(host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    let key = format!("{host}:{port}");
    if let Ok(map) = std::env::var("TSNX_CONNECT_MAP") {
        for entry in map.split(',') {
            if let Some((from, to)) = entry.split_once('=') {
                if from == key {
                    return to.parse().map_err(|_| std::io::Error::other(format!("bad map target {to}")));
                }
            }
        }
    }
    (host, port).to_socket_addrs()?.next().ok_or_else(|| std::io::Error::other(format!("no address for {host}")))
}

pub struct Sockets {
    conns: HashMap<ConnId, TcpStream>,
    udp: UdpSocket,
}

/// Best-effort local IP: the source address the OS would use for the internet.
fn local_ip() -> Option<std::net::IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:80").ok()?;
    Some(s.local_addr().ok()?.ip())
}

impl Sockets {
    pub fn new(udp_port: u16) -> std::io::Result<Self> {
        let udp = UdpSocket::bind(("0.0.0.0", udp_port))?;
        udp.set_nonblocking(true)?;
        Ok(Self { conns: HashMap::new(), udp })
    }

    /// Our local UDP endpoint(s) to advertise.
    pub fn local_endpoints(&self) -> Vec<SocketAddr> {
        let port = self.udp.local_addr().map(|a| a.port()).unwrap_or(0);
        local_ip().map(|ip| SocketAddr::new(ip, port)).into_iter().collect()
    }

    /// Performs one I/O request from the core. Returns events to deliver.
    pub fn apply(&mut self, io: Io) -> Vec<SockEvent> {
        match io {
            Io::Connect { id, host, port } => {
                let result = resolve(&host, port)
                    .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(10)))
                    .and_then(|s| {
                        s.set_nonblocking(true)?;
                        s.set_nodelay(true)?;
                        Ok(s)
                    });
                match result {
                    Ok(s) => {
                        self.conns.insert(id, s);
                        vec![SockEvent::Connected(id)]
                    }
                    Err(e) => {
                        log::warn!("connect {host}:{port}: {e}");
                        vec![SockEvent::Closed(id)]
                    }
                }
            }
            Io::Send { id, data } => match self.conns.get_mut(&id) {
                Some(s) => {
                    // Small control writes; a blocking write keeps this simple.
                    s.set_nonblocking(false).ok();
                    let r = s.write_all(&data);
                    s.set_nonblocking(true).ok();
                    match r {
                        Ok(()) => vec![],
                        Err(_) => {
                            self.conns.remove(&id);
                            vec![SockEvent::Closed(id)]
                        }
                    }
                }
                None => vec![],
            },
            Io::Close { id } => {
                self.conns.remove(&id);
                vec![]
            }
            Io::SendUdp { dst, data } => {
                if let Err(e) = self.udp.send_to(&data, dst) {
                    log::debug!("udp send to {dst}: {e}");
                }
                vec![]
            }
        }
    }

    /// Reads whatever is available on every connection.
    pub fn poll(&mut self) -> Vec<SockEvent> {
        let mut events = Vec::new();
        let mut buf = [0u8; 65536];
        let mut dead = Vec::new();
        for (&id, s) in self.conns.iter_mut() {
            loop {
                match s.read(&mut buf) {
                    Ok(0) => {
                        dead.push(id);
                        break;
                    }
                    Ok(n) => events.push(SockEvent::Data(id, buf[..n].to_vec())),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => {
                        dead.push(id);
                        break;
                    }
                }
            }
        }
        for id in dead {
            self.conns.remove(&id);
            events.push(SockEvent::Closed(id));
        }
        loop {
            match self.udp.recv_from(&mut buf) {
                Ok((n, src)) => events.push(SockEvent::Udp(src, buf[..n].to_vec())),
                Err(_) => break,
            }
        }
        events
    }
}

pub enum SockEvent {
    Connected(ConnId),
    Data(ConnId, Vec<u8>),
    Closed(ConnId),
    Udp(SocketAddr, Vec<u8>),
}

/// Runs the engine until `step` returns false. `step` is called after every
/// loop iteration with the engine, to drive tests or print status.
pub fn run_engine(
    cfg: EngineConfig,
    udp_port: u16,
    mut on_event: impl FnMut(&Event),
    mut step: impl FnMut(&mut Engine, &Clock) -> bool,
) -> Result<(), String> {
    let clock = Clock::new();
    let mut engine = Engine::new(cfg, clock.now(), unix_now())?;
    let mut sockets = Sockets::new(udp_port).map_err(|e| format!("udp bind: {e}"))?;
    engine.set_local_endpoints(&sockets.local_endpoints(), clock.now());
    loop {
        if clock.now() >= engine.next_deadline() {
            engine.handle_timeout(clock.now());
        }
        let mut events = Vec::new();
        while let Some(io) = engine.poll_io() {
            events.extend(sockets.apply(io));
        }
        events.extend(sockets.poll());
        let idle = events.is_empty();
        for ev in events {
            let now = clock.now();
            match ev {
                SockEvent::Connected(id) => engine.handle_connected(id, now),
                SockEvent::Data(id, data) => engine.handle_data(id, &data, now),
                SockEvent::Closed(id) => engine.handle_closed(id, now),
                SockEvent::Udp(src, data) => engine.handle_udp(src, &data, now),
            }
        }
        while let Some(ev) = engine.poll_event() {
            on_event(&ev);
        }
        if !step(&mut engine, &clock) {
            return Ok(());
        }
        engine.flush(clock.now());
        if idle {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
