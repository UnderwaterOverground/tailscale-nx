//! End-to-end check through the overlay: TCP and UDP echo against a peer
//! (the e2e peer runs socat echo servers on port 7).
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tsnx_core::engine::Engine;
use tsnx_core::netstack::{NetError, SockId};
use tsnx_core::time::Instant;

use crate::driver::Clock;

const PAYLOAD: &[u8] = b"tailscale-nx echo test";
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct EchoTest {
    peer: IpAddr,
    /// Bytes to stream through the TCP echo (default: just the payload).
    bulk: usize,
    bulk_sent: usize,
    started: Option<Instant>,
    tcp: Option<SockId>,
    tcp_sent: bool,
    tcp_got: Vec<u8>,
    udp: Option<SockId>,
    udp_last_send: Option<Instant>,
    udp_ok: bool,
    outcome: Option<Result<(), String>>,
}

impl EchoTest {
    pub fn new(peer: IpAddr, bulk: usize) -> Self {
        Self {
            peer,
            bulk,
            bulk_sent: 0,
            started: None,
            tcp: None,
            tcp_sent: false,
            tcp_got: Vec::new(),
            udp: None,
            udp_last_send: None,
            udp_ok: false,
            outcome: None,
        }
    }

    /// Advances the test; returns false when finished.
    pub fn step(&mut self, engine: &mut Engine, clock: &Clock) -> bool {
        let now = clock.now();
        let started = *self.started.get_or_insert(now);
        let target = SocketAddr::new(self.peer, 7);
        let net = engine.net();

        if self.tcp.is_none() {
            log::info!("echo: connecting TCP to {target}");
            self.tcp = net.tcp_connect(target).ok();
            self.udp = net.udp_bind(0).ok();
        }
        if let Some(t) = self.tcp {
            if self.bulk > 0 {
                // Stream `bulk` bytes of a known pattern and count the echo.
                while self.bulk_sent < self.bulk && net.readiness(t).writable {
                    let chunk: Vec<u8> =
                        (self.bulk_sent..(self.bulk_sent + 16384).min(self.bulk)).map(|i| i as u8).collect();
                    match net.send(t, &chunk) {
                        Ok(n) => self.bulk_sent += n,
                        Err(_) => break,
                    }
                }
                let mut buf = [0u8; 65536];
                while let Ok(n) = net.recv(t, &mut buf) {
                    if n == 0 {
                        break;
                    }
                    self.tcp_got.extend_from_slice(&buf[..n]);
                }
            } else {
                if !self.tcp_sent && net.readiness(t).writable {
                    self.tcp_sent = net.send(t, PAYLOAD).is_ok();
                }
                let mut buf = [0u8; 256];
                match net.recv(t, &mut buf) {
                    Ok(n) if n > 0 => self.tcp_got.extend_from_slice(&buf[..n]),
                    Ok(_) | Err(NetError::WouldBlock) => {}
                    Err(e) => log::warn!("echo: tcp recv: {e:?}"),
                }
            }
        }
        if let Some(u) = self.udp {
            if !self.udp_ok && self.udp_last_send.is_none_or(|t| now.saturating_duration_since(t) > Duration::from_secs(1)) {
                let _ = net.udp_send_to(u, PAYLOAD, target);
                self.udp_last_send = Some(now);
            }
            let mut buf = [0u8; 256];
            if let Ok((n, from)) = net.udp_recv_from(u, &mut buf) {
                self.udp_ok = &buf[..n] == PAYLOAD && from == target;
            }
        }

        let tcp_ok = if self.bulk > 0 {
            self.tcp_got.len() == self.bulk && self.tcp_got.iter().enumerate().all(|(i, &b)| b == i as u8)
        } else {
            self.tcp_got == PAYLOAD
        };
        if tcp_ok && self.udp_ok {
            log::info!("echo: TCP and UDP echo OK in {:?}", now.saturating_duration_since(started));
            self.outcome = Some(Ok(()));
            return false;
        }
        if now.saturating_duration_since(started) > TIMEOUT {
            self.outcome = Some(Err(format!(
                "echo timed out (tcp_ok={tcp_ok}, sent {} got {} of {}, udp_ok={})",
                self.bulk_sent,
                self.tcp_got.len(),
                self.bulk,
                self.udp_ok
            )));
            return false;
        }
        true
    }

    pub fn result(self) -> Result<(), String> {
        self.outcome.unwrap_or(Err("echo test did not run".into()))
    }
}
