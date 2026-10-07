//! Blocking byte streams (plain TCP or TLS over TCP) for diagnostics commands.
use std::io::{Read, Write};
use std::net::TcpStream;

use tsnx_core::tls::{self, TlsClient};

pub struct Stream {
    sock: TcpStream,
    tls: Option<TlsClient>,
    plain: Vec<u8>,
}

/// Where to connect, and the name to verify/send as Host.
pub struct Target {
    pub host: String,
    pub connect_addr: String,
    pub tls: bool,
}

impl Target {
    /// Parses `https://host[:port]` / `http://host[:port]`. TSNX_CONNECT
    /// (host:port) overrides the address dialed, e.g. to reach a container
    /// name through a published port.
    pub fn parse(url: &str) -> Result<Self, String> {
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("unsupported URL {url}"));
        };
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (authority.to_string(), if tls { "443".into() } else { "80".into() }),
        };
        let connect_addr = std::env::var("TSNX_CONNECT").unwrap_or(format!("{host}:{port}"));
        Ok(Self { host, connect_addr, tls })
    }
}

fn extra_roots() -> Result<Vec<Vec<u8>>, String> {
    match std::env::var("TSNX_EXTRA_ROOT") {
        Ok(path) => Ok(vec![std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?]),
        Err(_) => Ok(vec![]),
    }
}

impl Stream {
    pub fn connect(target: &Target) -> Result<Self, String> {
        let sock = TcpStream::connect(&target.connect_addr).map_err(|e| format!("{}: {e}", target.connect_addr))?;
        let tls = if target.tls {
            let config = tls::client_config(&extra_roots()?).map_err(|e| e.to_string())?;
            Some(TlsClient::new(config, &target.host).map_err(|e| format!("{e:?}"))?)
        } else {
            None
        };
        let mut s = Self { sock, tls, plain: Vec::new() };
        s.flush()?;
        Ok(s)
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), String> {
        match self.tls.as_mut() {
            Some(t) => t.write(data).map_err(|e| format!("{e:?}"))?,
            None => self.sock.write_all(data).map_err(|e| e.to_string())?,
        }
        self.flush()
    }

    fn flush(&mut self) -> Result<(), String> {
        if let Some(t) = self.tls.as_mut() {
            let out = t.take_outgoing();
            if !out.is_empty() {
                self.sock.write_all(&out).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    /// Blocks for the next chunk of plaintext; empty means EOF.
    pub fn read(&mut self) -> Result<Vec<u8>, String> {
        let mut buf = [0u8; 16384];
        loop {
            if !self.plain.is_empty() {
                return Ok(std::mem::take(&mut self.plain));
            }
            let n = self.sock.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(Vec::new());
            }
            match self.tls.as_mut() {
                Some(t) => {
                    t.feed(&buf[..n]).map_err(|e| format!("{e:?}"))?;
                    self.plain.extend(t.take_plaintext());
                    let closed = t.peer_closed();
                    self.flush()?;
                    if self.plain.is_empty() && closed {
                        return Ok(Vec::new());
                    }
                }
                None => self.plain.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// Reads until EOF.
    pub fn read_to_end(&mut self) -> Result<Vec<u8>, String> {
        let mut all = Vec::new();
        loop {
            let chunk = self.read()?;
            if chunk.is_empty() {
                return Ok(all);
            }
            all.extend(chunk);
        }
    }
}
