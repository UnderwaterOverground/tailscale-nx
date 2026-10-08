//! Taildrop receive: the peer API's `PUT /v0/put/<name>`, which is how
//! `tailscale file cp` and the Tailscale apps send files.
//!
//! The server speaks just enough HTTP/1.1 for that and hands the file to the
//! driver as a stream: an [`DropEvent::Offer`] it accepts or rejects (after
//! checking the disk), body bytes it pulls with [`Server::read`] straight
//! into its own buffer (so a transfer needs no buffers of its own beyond its
//! TCP connection), and [`DropEvent::Complete`] when they have all arrived,
//! answered with [`Server::finish`].
//!
//! Everything here parses input from the network, so it never indexes
//! unchecked or does unchecked arithmetic: a panic would take the whole
//! sysmodule down.
//!
//! Not supported: resuming partial transfers (senders ask first with a GET,
//! and fall back to a full upload on 404), and receiving from other users'
//! devices through ACL capability grants.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;
use core::time::Duration;

use crate::netstack::{NetError, Netstack, SockId};
use crate::time::Instant;

/// Largest request head (request line + headers).
const HEAD_MAX: usize = 4096;
/// Connections handled at once (one transfer; the rest are quick refusals
/// or a sender's resume probe).
const MAX_CONNS: usize = 4;
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
const DECIDE_TIMEOUT: Duration = Duration::from_secs(30);
/// A transfer that makes no progress for this long is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Time for a sender to read our answer and hang up.
const LINGER: Duration = Duration::from_secs(10);

/// What the driver is told (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropEvent {
    /// A peer wants to send `name` (already validated: safe as a file name
    /// in any directory). `size` is None when the sender streams without
    /// announcing a length. Answer with accept or reject.
    Offer { id: u32, name: String, size: Option<u64>, from: String },
    /// The whole file was read; write out what's left and call finish.
    Complete { id: u32, bytes: u64 },
    /// The transfer ended early (the sender hung up, timed out, or sent
    /// something malformed); discard what was written. No finish needed.
    Aborted { id: u32, why: &'static str },
}

/// Why a request is turned away before an offer is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// The sender isn't allowed to send us files.
    Forbidden,
    /// File sharing is off for this node (tailnet setting).
    Disabled,
}

#[derive(Debug, PartialEq, Eq)]
enum Body {
    Length(u64),
    Chunked(Chunked),
}

#[derive(Debug, PartialEq, Eq)]
enum Phase {
    /// Reading the request head.
    Head(Vec<u8>),
    /// Offer made; waiting for the driver.
    Deciding { body: Body, expect_continue: bool },
    /// The driver pulls the body.
    Body(Body),
    /// Body read; waiting for the driver's finish.
    Done,
    /// Answer sent; discarding input until the sender hangs up.
    Lingering,
}

struct Conn {
    /// Transfer id (unique for the server's lifetime).
    id: u32,
    sock: SockId,
    phase: Phase,
    /// Body bytes that arrived with the request head.
    early: Vec<u8>,
    /// Body bytes handed to the driver.
    received: u64,
    since: Instant,
}

pub struct Server {
    port: u16,
    listener: SockId,
    conns: Vec<Conn>,
    next_id: u32,
    events: VecDeque<DropEvent>,
    log: VecDeque<String>,
}

impl Server {
    /// Listens on `port` of our tailnet addresses.
    pub fn new(net: &mut Netstack, port: u16) -> Result<Self, NetError> {
        let listener = net.tcp_listen(port, MAX_CONNS)?;
        Ok(Self { port, listener, conns: Vec::new(), next_id: 1, events: VecDeque::new(), log: VecDeque::new() })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn poll_event(&mut self) -> Option<DropEvent> {
        self.events.pop_front()
    }

    /// Lines for the log.
    pub fn poll_log(&mut self) -> Option<String> {
        self.log.pop_front()
    }

    /// When [`Self::service`] must next run to enforce a timeout.
    pub fn deadline(&self) -> Option<Instant> {
        self.conns.iter().map(|c| c.since + c.timeout()).min()
    }

    /// Accepts connections, reads request heads, and enforces timeouts.
    /// `who` says whether the device at an address may send us files (Ok
    /// with its name).
    pub fn service(&mut self, net: &mut Netstack, now: Instant, who: &dyn Fn(IpAddr) -> Result<String, Denied>) {
        while let Ok((sock, peer)) = net.tcp_accept(self.listener) {
            if self.conns.len() >= MAX_CONNS {
                net.abort(sock);
                continue;
            }
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            self.conns.push(Conn { id, sock, phase: Phase::Head(Vec::new()), early: Vec::new(), received: 0, since: now });
            log::debug!("taildrop: connection {id} from {peer}");
        }
        let busy = self.conns.iter().any(|c| matches!(c.phase, Phase::Deciding { .. } | Phase::Body(_) | Phase::Done));
        let mut i = 0;
        while let Some(c) = self.conns.get_mut(i) {
            let keep = match &c.phase {
                Phase::Head(_) => Self::read_head(c, net, now, busy, who, &mut self.events, &mut self.log),
                Phase::Lingering => linger(c, net, now),
                _ => {
                    if now >= c.since + c.timeout() {
                        net.abort(c.sock);
                        self.events.push_back(DropEvent::Aborted { id: c.id, why: "timed out" });
                        false
                    } else {
                        true
                    }
                }
            };
            if keep {
                i += 1;
            } else {
                self.conns.swap_remove(i);
            }
        }
    }

    /// Reads (more of) a request head; once complete, answers it or makes
    /// an offer. Returns false if the connection is finished with.
    fn read_head(
        c: &mut Conn,
        net: &mut Netstack,
        now: Instant,
        busy: bool,
        who: &dyn Fn(IpAddr) -> Result<String, Denied>,
        events: &mut VecDeque<DropEvent>,
        log: &mut VecDeque<String>,
    ) -> bool {
        let Phase::Head(head) = &mut c.phase else { return true };
        let mut chunk = [0u8; 512];
        let end = loop {
            if let Some(end) = find_head_end(head) {
                break end;
            }
            if head.len() >= HEAD_MAX {
                return respond(c, net, now, 431, "request head too large");
            }
            let want = chunk.len().min(HEAD_MAX - head.len());
            match net.recv(c.sock, &mut chunk[..want]) {
                Ok(0) | Err(NetError::ConnectionReset | NetError::NotConnected | NetError::InvalidSocket) => {
                    net.close(c.sock);
                    return false;
                }
                Ok(n) => {
                    head.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    c.since = now;
                }
                Err(_) => {
                    if now >= c.since + HEAD_TIMEOUT {
                        net.abort(c.sock);
                        return false;
                    }
                    return true;
                }
            }
        };
        let head = core::mem::take(head);
        c.early = head.get(end..).unwrap_or_default().to_vec();
        let req = match Request::parse(head.get(..end).unwrap_or_default()) {
            Ok(r) => r,
            Err((status, msg)) => return respond(c, net, now, status, msg),
        };
        let Some(raw_name) = req.target.strip_prefix("/v0/put/") else {
            return respond(c, net, now, 404, "not found");
        };
        match req.method {
            // A sender asking which partial files we have, to resume one:
            // we keep none, and 404 makes it upload in full.
            "GET" => return respond(c, net, now, 404, "resuming is not supported"),
            "PUT" => {}
            _ => return respond(c, net, now, 405, "expected method PUT"),
        }
        let Some(peer) = net.peer_addr(c.sock) else {
            net.close(c.sock);
            return false;
        };
        let from = match who(peer.ip()) {
            Ok(name) => name,
            Err(Denied::Forbidden) => return respond(c, net, now, 403, "Taildrop access denied"),
            Err(Denied::Disabled) => return respond(c, net, now, 403, "file sharing not enabled by Tailscale admin"),
        };
        let Some(name) = file_name(raw_name) else {
            return respond(c, net, now, 400, "invalid filename");
        };
        if req.range {
            return respond(c, net, now, 400, "resuming is not supported");
        }
        if busy {
            return respond(c, net, now, 503, "busy receiving another file; try again shortly");
        }
        let (body, size) = match req.length {
            Length::Chunked => (Body::Chunked(Chunked::default()), None),
            Length::Bytes(n) => (Body::Length(n), Some(n)),
        };
        log.push_back(format!("taildrop: {from} is sending \"{name}\" ({})", size.map_or("size unknown".into(), |n| format!("{n} bytes"))));
        events.push_back(DropEvent::Offer { id: c.id, name, size, from });
        c.phase = Phase::Deciding { body, expect_continue: req.expect_continue };
        c.since = now;
        true
    }

    /// The driver takes an offered file.
    pub fn accept(&mut self, net: &mut Netstack, now: Instant, id: u32) {
        let Some(c) = self.conns.iter_mut().find(|c| c.id == id) else { return };
        let Phase::Deciding { .. } = c.phase else { return };
        let Phase::Deciding { body, expect_continue } = core::mem::replace(&mut c.phase, Phase::Done) else { return };
        if expect_continue {
            let _ = net.send(c.sock, b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        c.since = now;
        c.phase = match body {
            Body::Length(0) => {
                self.events.push_back(DropEvent::Complete { id, bytes: 0 });
                Phase::Done
            }
            body => Phase::Body(body),
        };
    }

    /// Ends a transfer at any point after its offer: `status` 200 if the
    /// file was saved, else an HTTP error status and a message for the
    /// sender.
    pub fn finish(&mut self, net: &mut Netstack, now: Instant, id: u32, status: u16, msg: &str) {
        let Some(i) = self.conns.iter().position(|c| c.id == id) else { return };
        let Some(c) = self.conns.get_mut(i) else { return };
        if matches!(c.phase, Phase::Head(_) | Phase::Lingering) {
            return;
        }
        let body = if status == 200 { "{}\n" } else { msg };
        if !respond(c, net, now, status, body) {
            self.conns.swap_remove(i);
        }
    }

    /// Reads body bytes into `buf` for transfer `id`. Returns how many; 0
    /// when none are available yet (or the transfer has ended: see the
    /// events).
    pub fn read(&mut self, net: &mut Netstack, now: Instant, id: u32, buf: &mut [u8]) -> usize {
        let Some(i) = self.conns.iter().position(|c| c.id == id) else { return 0 };
        loop {
            let Some(c) = self.conns.get_mut(i) else { return 0 };
            match read_step(c, net, buf) {
                Step::Data(n, done) => {
                    c.received = c.received.saturating_add(n as u64);
                    c.since = now;
                    if done {
                        c.phase = Phase::Done;
                        self.events.push_back(DropEvent::Complete { id, bytes: c.received });
                    }
                    if n > 0 || done {
                        return n;
                    }
                }
                Step::Nothing => return 0,
                Step::Fail(why) => return self.abort(net, i, why),
            }
        }
    }

    fn abort(&mut self, net: &mut Netstack, i: usize, why: &'static str) -> usize {
        if i < self.conns.len() {
            let c = self.conns.swap_remove(i);
            net.abort(c.sock);
            self.events.push_back(DropEvent::Aborted { id: c.id, why });
        }
        0
    }

    /// Closes everything (e.g. Taildrop turned off). Transfers in progress
    /// end with Aborted.
    pub fn shutdown(&mut self, net: &mut Netstack) {
        for c in self.conns.drain(..) {
            if !matches!(c.phase, Phase::Head(_) | Phase::Lingering) {
                self.events.push_back(DropEvent::Aborted { id: c.id, why: "Taildrop stopped" });
            }
            net.abort(c.sock);
        }
        net.close(self.listener);
    }
}

enum Step {
    /// Data bytes now at the front of the buffer; whether the body ended.
    Data(usize, bool),
    Nothing,
    Fail(&'static str),
}

/// Takes the next raw bytes of a body (early ones first) into `buf` and
/// decodes them.
fn read_step(c: &mut Conn, net: &mut Netstack, buf: &mut [u8]) -> Step {
    let Phase::Body(body) = &mut c.phase else { return Step::Nothing };
    // Never past a declared length, so nothing after the body is consumed.
    let want = match body {
        Body::Length(left) => usize::try_from(*left).unwrap_or(usize::MAX).min(buf.len()),
        Body::Chunked(_) => buf.len(),
    };
    let Some(dst) = buf.get_mut(..want) else { return Step::Nothing };
    let raw = if !c.early.is_empty() {
        let n = c.early.len().min(dst.len());
        if let (Some(d), Some(s)) = (dst.get_mut(..n), c.early.get(..n)) {
            d.copy_from_slice(s);
        }
        c.early.drain(..n);
        n
    } else {
        match net.recv(c.sock, dst) {
            Ok(0) => return Step::Fail("the sender disconnected"),
            Ok(n) => n,
            Err(NetError::WouldBlock) => return Step::Nothing,
            Err(_) => return Step::Fail("the sender disconnected"),
        }
    };
    match body {
        Body::Length(left) => {
            *left = left.saturating_sub(raw as u64);
            Step::Data(raw, *left == 0)
        }
        Body::Chunked(ch) => match ch.decode(buf.get_mut(..raw).unwrap_or_default()) {
            Ok((n, done)) => Step::Data(n, done),
            Err(()) => Step::Fail("malformed chunked body"),
        },
    }
}

impl Conn {
    fn timeout(&self) -> Duration {
        match self.phase {
            Phase::Head(_) => HEAD_TIMEOUT,
            Phase::Deciding { .. } => DECIDE_TIMEOUT,
            Phase::Body(_) | Phase::Done => IDLE_TIMEOUT,
            Phase::Lingering => LINGER,
        }
    }
}

/// Sends a final answer and half-closes; the connection lingers until the
/// sender hangs up. Returns whether it is still tracked (always, unless the
/// send failed).
fn respond(c: &mut Conn, net: &mut Netstack, now: Instant, status: u16, body: &str) -> bool {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Error",
    };
    let msg = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    // Small enough for any socket's send buffer (4 KB at least).
    if net.send(c.sock, msg.as_bytes()).is_err() {
        net.abort(c.sock);
        return false;
    }
    let _ = net.shutdown_write(c.sock);
    c.phase = Phase::Lingering;
    c.early = Vec::new();
    c.since = now;
    true
}

/// Discards input after our answer until the sender hangs up or LINGER
/// passes. Returns false once the connection is gone.
fn linger(c: &mut Conn, net: &mut Netstack, now: Instant) -> bool {
    let mut sink = [0u8; 512];
    // Bounded per call: a sender still uploading must not stall the engine.
    for _ in 0..64 {
        match net.recv(c.sock, &mut sink) {
            Ok(n) if n > 0 => continue,
            Err(NetError::WouldBlock) => break,
            _ => {
                net.close(c.sock);
                return false;
            }
        }
    }
    if now >= c.since + LINGER {
        net.abort(c.sock);
        return false;
    }
    true
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

#[derive(Debug, PartialEq, Eq)]
enum Length {
    Bytes(u64),
    Chunked,
}

#[derive(Debug)]
struct Request<'a> {
    method: &'a str,
    target: &'a str,
    length: Length,
    expect_continue: bool,
    range: bool,
}

impl<'a> Request<'a> {
    fn parse(head: &'a [u8]) -> Result<Self, (u16, &'static str)> {
        let bad = (400, "malformed request");
        let text = core::str::from_utf8(head).map_err(|_| bad)?;
        let mut lines = text.split("\r\n");
        let mut first = lines.next().ok_or(bad)?.split(' ');
        let (method, target, version) = (first.next().ok_or(bad)?, first.next().ok_or(bad)?, first.next().ok_or(bad)?);
        if first.next().is_some() || !version.starts_with("HTTP/1.") || method.is_empty() || !target.starts_with('/') {
            return Err(bad);
        }
        let (mut length, mut chunked, mut expect_continue, mut range) = (None::<u64>, false, false, false);
        for line in lines.filter(|l| !l.is_empty()) {
            let (name, value) = line.split_once(':').ok_or(bad)?;
            let value = value.trim_matches(|c| c == ' ' || c == '\t');
            if name.eq_ignore_ascii_case("content-length") {
                if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(bad);
                }
                let n: u64 = value.parse().map_err(|_| bad)?;
                if length.is_some_and(|l| l != n) {
                    return Err(bad);
                }
                length = Some(n);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                // Only plain chunked: nobody sends compressed uploads here.
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err((501, "unsupported transfer encoding"));
                }
                chunked = true;
            } else if name.eq_ignore_ascii_case("expect") {
                expect_continue = value.eq_ignore_ascii_case("100-continue");
            } else if name.eq_ignore_ascii_case("range") {
                range = true;
            }
        }
        // With both, the chunked framing wins (RFC 9112 6.3).
        let length = if chunked { Length::Chunked } else { Length::Bytes(length.unwrap_or(0)) };
        Ok(Self { method, target, length, expect_continue, range })
    }
}

/// Decodes a `/v0/put/` path segment into a file name that is safe in any
/// directory on the SD card (FAT32/exFAT), or None. Tailscale's own rules
/// (feature/taildrop: validateBaseName), plus what FAT can't store.
pub fn file_name(escaped: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(escaped.len());
    let mut it = escaped.bytes();
    while let Some(b) = it.next() {
        if b == b'%' {
            let hi = hex_val(it.next()?)?;
            let lo = hex_val(it.next()?)?;
            bytes.push(hi << 4 | lo);
        } else {
            bytes.push(b);
        }
    }
    let name = String::from_utf8(bytes).ok()?;
    let ok = !name.is_empty()
        && name.len() <= 255
        && name.trim() == name
        && name != "."
        && name != ".."
        // FAT drops trailing dots ("a." would be saved as "a").
        && !name.ends_with('.')
        && !name.ends_with(".partial")
        && !name.ends_with(".deleted")
        && name.chars().all(file_name_char);
    ok.then_some(name)
}

fn file_name_char(c: char) -> bool {
    !matches!(c, '/' | '\\' | ':' | '*' | '"' | '<' | '>' | '|' | '?')
        && !c.is_control()
        // Invisible formatting characters (Go rejects them as non-graphic).
        && !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
        && (c == ' ' || !c.is_whitespace())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Incremental decoder for HTTP/1.1 chunked framing.
#[derive(Debug, Default, PartialEq, Eq)]
struct Chunked {
    state: ChunkState,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
enum ChunkState {
    /// Reading a chunk size (hex digits so far, value).
    #[default]
    Size0,
    Size { digits: u8, value: u64 },
    /// After the size: extensions until LF.
    SizeLine { value: u64 },
    Data { left: u64 },
    DataCr,
    DataLf,
    /// After the last chunk: trailer lines until an empty one.
    TrailerStart,
    TrailerLine,
    TrailerLf,
    Done,
}

impl Chunked {
    /// Decodes `buf` in place: the data bytes move to its front. Returns
    /// their count and whether the body ended (input past the end is
    /// ignored).
    fn decode(&mut self, buf: &mut [u8]) -> Result<(usize, bool), ()> {
        let (mut r, mut w) = (0usize, 0usize);
        while r < buf.len() {
            let b = *buf.get(r).ok_or(())?;
            match self.state {
                ChunkState::Size0 | ChunkState::Size { .. } => {
                    let (digits, value) = match self.state {
                        ChunkState::Size { digits, value } => (digits, value),
                        _ => (0, 0),
                    };
                    if let Some(v) = hex_val(b) {
                        if digits >= 15 {
                            return Err(());
                        }
                        self.state = ChunkState::Size { digits: digits + 1, value: value << 4 | u64::from(v) };
                    } else if digits == 0 {
                        return Err(());
                    } else if b == b'\r' || b == b';' || b == b' ' || b == b'\t' {
                        self.state = ChunkState::SizeLine { value };
                    } else if b == b'\n' {
                        self.state = Self::after_size(value);
                    } else {
                        return Err(());
                    }
                    r += 1;
                }
                ChunkState::SizeLine { value } => {
                    if b == b'\n' {
                        self.state = Self::after_size(value);
                    }
                    r += 1;
                }
                ChunkState::Data { left } => {
                    let n = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len() - r);
                    buf.copy_within(r..r + n, w);
                    r += n;
                    w += n;
                    let left = left - n as u64;
                    self.state = if left == 0 { ChunkState::DataCr } else { ChunkState::Data { left } };
                }
                ChunkState::DataCr => {
                    self.state = match b {
                        b'\r' => ChunkState::DataLf,
                        b'\n' => ChunkState::Size0,
                        _ => return Err(()),
                    };
                    r += 1;
                }
                ChunkState::DataLf => {
                    if b != b'\n' {
                        return Err(());
                    }
                    self.state = ChunkState::Size0;
                    r += 1;
                }
                ChunkState::TrailerStart => {
                    self.state = match b {
                        b'\r' => ChunkState::TrailerLf,
                        b'\n' => ChunkState::Done,
                        _ => ChunkState::TrailerLine,
                    };
                    r += 1;
                }
                ChunkState::TrailerLine => {
                    if b == b'\n' {
                        self.state = ChunkState::TrailerStart;
                    }
                    r += 1;
                }
                ChunkState::TrailerLf => {
                    if b != b'\n' {
                        return Err(());
                    }
                    self.state = ChunkState::Done;
                    r += 1;
                }
                ChunkState::Done => break,
            }
        }
        Ok((w, self.state == ChunkState::Done))
    }

    fn after_size(value: u64) -> ChunkState {
        if value == 0 { ChunkState::TrailerStart } else { ChunkState::Data { left: value } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use core::net::SocketAddr;

    #[test]
    fn file_names() {
        assert_eq!(file_name("photo.jpg").as_deref(), Some("photo.jpg"));
        assert_eq!(file_name("my%20photo%20%C3%A9.jpg").as_deref(), Some("my photo é.jpg"));
        assert_eq!(file_name("a+b").as_deref(), Some("a+b"));
        for bad in [
            "", ".", "..", "%2E%2E", "a%2Fb", "a/b", "..%2Fx", "a%5Cb", "c:x", "a?b", "x%00", "x%0A", " lead", "trail ", "end.",
            "f.partial", "f.deleted", "%ZZ", "%4", "%C3", "zero%E2%80%8Bwidth", "tab%09x",
        ] {
            assert_eq!(file_name(bad), None, "{bad:?}");
        }
        assert_eq!(file_name(&"a".repeat(255)).map(|s| s.len()), Some(255));
        assert_eq!(file_name(&"a".repeat(256)), None);
    }

    #[test]
    fn request_heads() {
        let r = Request::parse(b"PUT /v0/put/a.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\nExpect: 100-continue\r\n\r\n").unwrap();
        assert_eq!((r.method, r.target, r.length, r.expect_continue, r.range), ("PUT", "/v0/put/a.txt", Length::Bytes(12), true, false));
        let r = Request::parse(b"PUT /v0/put/a HTTP/1.1\r\ntransfer-encoding: Chunked\r\ncontent-length: 5\r\n\r\n").unwrap();
        assert_eq!(r.length, Length::Chunked);
        assert_eq!(Request::parse(b"GET /v0/put/a HTTP/1.1\r\n\r\n").unwrap().length, Length::Bytes(0));
        assert!(Request::parse(b"PUT /v0/put/a HTTP/1.1\r\nRange: bytes=5-\r\n\r\n").unwrap().range);
        for bad in [
            &b"PUT /x HTTP/1.1\r\nContent-Length: -1\r\n\r\n"[..],
            b"PUT /x HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n",
            b"PUT /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            b"PUT x HTTP/1.1\r\n\r\n",
            b"PUT /x\r\n\r\n",
            b"PUT /x HTTP/1.1\r\nNoColon\r\n\r\n",
            b"\xff\xfe /x HTTP/1.1\r\n\r\n",
        ] {
            assert!(Request::parse(bad).is_err(), "{:?}", core::str::from_utf8(bad));
        }
        assert_eq!(Request::parse(b"PUT /x HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n").unwrap_err().0, 501);
    }

    fn dechunk(input: &[u8], step: usize) -> Result<(Vec<u8>, bool), ()> {
        let mut ch = Chunked::default();
        let (mut out, mut done) = (Vec::new(), false);
        for piece in input.chunks(step) {
            let mut b = piece.to_vec();
            let (n, d) = ch.decode(&mut b)?;
            out.extend_from_slice(&b[..n]);
            done = d;
            if d {
                break;
            }
        }
        Ok((out, done))
    }

    #[test]
    fn chunked_bodies() {
        let body = b"5\r\nhello\r\n7;ext=1\r\n, world\r\n0\r\nX-Trailer: 1\r\n\r\nGARBAGE";
        for step in 1..body.len() {
            assert_eq!(dechunk(body, step).unwrap(), (b"hello, world".to_vec(), true), "step {step}");
        }
        assert_eq!(dechunk(b"A\r\n0123456789\r\n0\r\n\r\n", 3).unwrap(), (b"0123456789".to_vec(), true));
        assert_eq!(dechunk(b"3\r\nabc\r\n", 4).unwrap(), (b"abc".to_vec(), false));
        for bad in [&b"x\r\n"[..], b"\r\n", b"3\r\nabcX", b"1234567890123456\r\n", b"0\r\n\rX"] {
            assert!(dechunk(bad, 2).is_err(), "{:?}", core::str::from_utf8(bad));
        }
    }

    /// Random input must never panic (the sysmodule would go down).
    #[test]
    fn garbage_never_panics() {
        let mut seed = 0x2545F4914F6CDD1Du64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet = b"0123456789abcdefABCDEF\r\n;: %/.PUTGEHTP-\x00\xff\xc3";
        for _ in 0..20_000 {
            let len = (rnd() % 64) as usize;
            let v: Vec<u8> = (0..len).map(|_| alphabet[(rnd() % alphabet.len() as u64) as usize]).collect();
            let _ = Request::parse(&v);
            let _ = dechunk(&v, 1 + (rnd() % 8) as usize);
            if let Ok(s) = core::str::from_utf8(&v) {
                let _ = file_name(s);
            }
        }
    }

    // ---- end to end through two netstacks ----

    const A: &str = "100.64.0.1";
    const B: &str = "100.64.0.2";

    struct Rig {
        now: Instant,
        sender: Netstack,
        switch: Netstack,
        server: Server,
        sock: SockId,
    }

    fn allow(_: IpAddr) -> Result<String, Denied> {
        Ok("laptop".to_string())
    }

    impl Rig {
        fn new() -> Self {
            let now = Instant::from_millis(0);
            let (mut sender, mut switch) = (Netstack::new(now), Netstack::new(now));
            sender.set_addresses(&[A.parse().unwrap()]);
            switch.set_addresses(&[B.parse().unwrap()]);
            let server = Server::new(&mut switch, 4242).unwrap();
            let sock = sender.tcp_connect(SocketAddr::new(B.parse().unwrap(), 4242)).unwrap();
            let mut rig = Self { now, sender, switch, server, sock };
            rig.run(allow);
            rig
        }

        fn run(&mut self, who: fn(IpAddr) -> Result<String, Denied>) {
            for _ in 0..30 {
                self.now = self.now + Duration::from_millis(5);
                self.sender.poll(self.now);
                let out: Vec<_> = self.sender.take_outbound().collect();
                out.into_iter().for_each(|p| self.switch.inject(p));
                self.switch.poll(self.now);
                self.server.service(&mut self.switch, self.now, &who);
                self.switch.poll(self.now);
                let out: Vec<_> = self.switch.take_outbound().collect();
                out.into_iter().for_each(|p| self.sender.inject(p));
            }
        }

        fn send(&mut self, data: &[u8]) {
            let mut off = 0;
            while off < data.len() {
                match self.sender.send(self.sock, &data[off..]) {
                    Ok(n) => off += n,
                    Err(_) => {}
                }
                self.run(allow);
            }
            self.run(allow);
        }

        fn reply(&mut self) -> String {
            self.run(allow);
            let mut out = Vec::new();
            let mut buf = [0u8; 1024];
            while let Ok(n) = self.sender.recv(self.sock, &mut buf) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            String::from_utf8(out).unwrap()
        }

        fn drain(&mut self, id: u32) -> Vec<u8> {
            let mut got = Vec::new();
            let mut buf = [0u8; 700];
            loop {
                let n = self.server.read(&mut self.switch, self.now, id, &mut buf);
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            got
        }
    }

    #[test]
    fn receives_a_file() {
        let mut rig = Rig::new();
        let data: Vec<u8> = (0..50_000u32).map(|i| (i * 7) as u8).collect();
        let head = format!("PUT /v0/put/notes%20(1).txt HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", data.len());
        rig.send(head.as_bytes());
        let Some(DropEvent::Offer { id, name, size, from }) = rig.server.poll_event() else { panic!("an offer") };
        assert_eq!((name.as_str(), size, from.as_str()), ("notes (1).txt", Some(50_000), "laptop"));
        rig.server.accept(&mut rig.switch, rig.now, id);
        let mut got = Vec::new();
        let mut off = 0;
        while got.len() < data.len() {
            if off < data.len() {
                if let Ok(n) = rig.sender.send(rig.sock, &data[off..]) {
                    off += n;
                }
            }
            rig.run(allow);
            got.extend(rig.drain(id));
        }
        assert_eq!(got, data);
        assert_eq!(rig.server.poll_event(), Some(DropEvent::Complete { id, bytes: 50_000 }));
        rig.server.finish(&mut rig.switch, rig.now, id, 200, "");
        let reply = rig.reply();
        assert!(reply.starts_with("HTTP/1.1 200 OK\r\n") && reply.ends_with("{}\n"), "{reply}");
    }

    #[test]
    fn chunked_upload_with_expect_continue() {
        let mut rig = Rig::new();
        rig.send(b"PUT /v0/put/a.bin HTTP/1.1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n");
        let Some(DropEvent::Offer { id, size: None, .. }) = rig.server.poll_event() else { panic!("an offer") };
        rig.server.accept(&mut rig.switch, rig.now, id);
        assert!(rig.reply().starts_with("HTTP/1.1 100 Continue\r\n\r\n"));
        rig.send(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
        assert_eq!(rig.drain(id), b"abcde");
        assert_eq!(rig.server.poll_event(), Some(DropEvent::Complete { id, bytes: 5 }));
    }

    #[test]
    fn body_bytes_sent_with_the_head_are_kept() {
        let mut rig = Rig::new();
        rig.send(b"PUT /v0/put/x HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd");
        let Some(DropEvent::Offer { id, .. }) = rig.server.poll_event() else { panic!("an offer") };
        rig.server.accept(&mut rig.switch, rig.now, id);
        assert_eq!(rig.drain(id), b"abcd");
        assert!(matches!(rig.server.poll_event(), Some(DropEvent::Complete { bytes: 4, .. })));
    }

    #[test]
    fn refusals_answer_the_sender() {
        // Not allowed to send.
        let mut rig = Rig::new();
        rig.send(b"PUT /v0/put/x HTTP/1.1\r\nContent-Length: 1\r\n\r\n");
        let Some(DropEvent::Offer { id, .. }) = rig.server.poll_event() else { panic!("an offer") };
        rig.server.finish(&mut rig.switch, rig.now, id, 507, "not enough space on the SD card");
        let reply = rig.reply();
        assert!(reply.starts_with("HTTP/1.1 507 ") && reply.ends_with("not enough space on the SD card"), "{reply}");

        let mut rig = Rig::new();
        rig.sender.send(rig.sock, b"PUT /v0/put/x HTTP/1.1\r\nContent-Length: 1\r\n\r\n").unwrap();
        rig.run(|_| Err(Denied::Forbidden));
        assert!(rig.reply().starts_with("HTTP/1.1 403 "));
        assert_eq!(rig.server.poll_event(), None);

        let mut rig = Rig::new();
        rig.send(b"GET /v0/put/x HTTP/1.1\r\n\r\n");
        assert!(rig.reply().starts_with("HTTP/1.1 404 "), "resume probe: upload in full");

        let mut rig = Rig::new();
        rig.send(b"PUT /v0/put/..%2Fescape HTTP/1.1\r\nContent-Length: 1\r\n\r\n");
        assert!(rig.reply().starts_with("HTTP/1.1 400 "));
        assert_eq!(rig.server.poll_event(), None);
    }

    #[test]
    fn sender_hanging_up_aborts() {
        let mut rig = Rig::new();
        rig.send(b"PUT /v0/put/x HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc");
        let Some(DropEvent::Offer { id, .. }) = rig.server.poll_event() else { panic!("an offer") };
        rig.server.accept(&mut rig.switch, rig.now, id);
        rig.sender.close(rig.sock);
        rig.run(allow);
        assert_eq!(rig.drain(id), b"abc");
        rig.drain(id);
        assert_eq!(rig.server.poll_event(), Some(DropEvent::Aborted { id, why: "the sender disconnected" }));
        rig.run(allow);
        assert_eq!(rig.switch.buffer_usage(), 0, "connection freed");
    }

    #[test]
    fn stalled_transfer_times_out() {
        let mut rig = Rig::new();
        rig.send(b"PUT /v0/put/x HTTP/1.1\r\nContent-Length: 100\r\n\r\n");
        let Some(DropEvent::Offer { id, .. }) = rig.server.poll_event() else { panic!("an offer") };
        rig.server.accept(&mut rig.switch, rig.now, id);
        rig.now = rig.now + IDLE_TIMEOUT;
        rig.run(allow);
        assert_eq!(rig.server.poll_event(), Some(DropEvent::Aborted { id, why: "timed out" }));
        assert_eq!(rig.server.deadline(), None);
    }

    #[test]
    fn one_transfer_at_a_time() {
        let mut rig = Rig::new();
        rig.send(b"PUT /v0/put/x HTTP/1.1\r\nContent-Length: 100\r\n\r\n");
        let Some(DropEvent::Offer { id, .. }) = rig.server.poll_event() else { panic!("an offer") };
        rig.server.accept(&mut rig.switch, rig.now, id);
        let second = rig.sender.tcp_connect(SocketAddr::new(B.parse().unwrap(), 4242)).unwrap();
        rig.run(allow);
        rig.sender.send(second, b"PUT /v0/put/y HTTP/1.1\r\nContent-Length: 1\r\n\r\n").unwrap();
        rig.run(allow);
        let mut buf = [0u8; 256];
        let n = rig.sender.recv(second, &mut buf).unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 503 "));
        assert_eq!(rig.server.poll_event(), None);
    }
}
