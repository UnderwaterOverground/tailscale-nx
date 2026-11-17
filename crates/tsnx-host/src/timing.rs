//! Times a first request to a peer, like Moonlight's first `serverinfo`
//! (which it gives 1 s): after each idle period, a TCP connect, an HTTP GET
//! and a read to EOF. Prints how long each step took, per round.
use std::net::SocketAddr;
use std::time::Duration;

use tsnx_core::engine::Engine;
use tsnx_core::netstack::{NetError, SockId};
use tsnx_core::time::Instant;

use crate::driver::Clock;

/// Moonlight-Switch's first-request timeout.
const MOONLIGHT_LIMIT: Duration = Duration::from_secs(1);
const ROUND_TIMEOUT: Duration = Duration::from_secs(15);

enum State {
    Idle { until: Option<Instant> },
    Request { sock: SockId, start: Instant, connected: Option<Duration>, first_byte: Option<Duration>, sent: bool },
}

pub struct ConnectTiming {
    target: SocketAddr,
    idles: Vec<Duration>,
    round: usize,
    state: State,
    lines: Vec<String>,
}

impl ConnectTiming {
    /// `idles`: seconds to wait before each round (the first counts from when
    /// the netmap arrives).
    pub fn new(target: SocketAddr, idles: Vec<Duration>) -> Self {
        Self { target, idles, round: 0, state: State::Idle { until: None }, lines: Vec::new() }
    }

    /// Advances the test; returns false when every round has run.
    pub fn step(&mut self, engine: &mut Engine, clock: &Clock) -> bool {
        let now = clock.now();
        let net = engine.net();
        match &mut self.state {
            State::Idle { until } => {
                let Some(&idle) = self.idles.get(self.round) else { return false };
                let until = *until.get_or_insert(now + idle);
                if now < until {
                    return true;
                }
                log::info!("timing: round {} (idle {}s): connecting to {}", self.round, idle.as_secs(), self.target);
                match net.tcp_connect(self.target) {
                    Ok(sock) => {
                        self.state = State::Request { sock, start: now, connected: None, first_byte: None, sent: false }
                    }
                    Err(e) => return self.finish(&format!("connect failed: {e:?}")),
                }
            }
            State::Request { sock, start, connected, first_byte, sent } => {
                let sock = *sock;
                let elapsed = now.saturating_duration_since(*start);
                if !*sent && net.readiness(sock).writable {
                    *connected = Some(elapsed);
                    let req = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", self.target.ip());
                    *sent = net.send(sock, req.as_bytes()).is_ok();
                }
                let mut buf = [0u8; 4096];
                let outcome = loop {
                    match net.recv(sock, &mut buf) {
                        Ok(0) => break Some(Ok(())),
                        Ok(_) => {
                            first_byte.get_or_insert(elapsed);
                        }
                        Err(NetError::WouldBlock) => break None,
                        Err(e) => break Some(Err(format!("{e:?}"))),
                    }
                };
                let outcome = outcome.or_else(|| (elapsed > ROUND_TIMEOUT).then(|| Err("timed out".to_string())));
                if let Some(outcome) = outcome {
                    let ms = |d: Option<Duration>| d.map_or("-".to_string(), |d| format!("{} ms", d.as_millis()));
                    let verdict = match &outcome {
                        Ok(()) if elapsed <= MOONLIGHT_LIMIT => "within 1 s".to_string(),
                        Ok(()) => "OVER 1 s".to_string(),
                        Err(e) => format!("FAILED ({e})"),
                    };
                    let line = format!(
                        "connected {}, first byte {}, done {} ms: {verdict}",
                        ms(*connected),
                        ms(*first_byte),
                        elapsed.as_millis()
                    );
                    net.close(sock);
                    return self.finish(&line);
                }
            }
        }
        true
    }

    fn finish(&mut self, what: &str) -> bool {
        let line = format!("round {} (idle {}s): {what}", self.round, self.idles[self.round].as_secs());
        log::info!("timing: {line}");
        self.lines.push(line);
        self.round += 1;
        self.state = State::Idle { until: None };
        true
    }

    pub fn summary(&self) -> &[String] {
        &self.lines
    }
}
