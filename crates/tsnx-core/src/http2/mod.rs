//! Minimal sans-IO HTTP/2 client (RFC 9113), enough for the Tailscale control
//! protocol, which speaks prior-knowledge HTTP/2 inside the ts2021 Noise
//! channel: a handful of POSTs with JSON bodies, one of them a long-lived
//! streaming response. No server push, priorities, or trailers handling.

pub mod hpack;
mod hpack_tables;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

pub use hpack::Header;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;
const DEFAULT_WINDOW: i64 = 65_535;
const DEFAULT_MAX_FRAME: usize = 16_384;
/// Receive window we advertise per stream and for the connection. Map
/// responses can be large; let the server send freely and replenish as we go.
const RECV_WINDOW: u32 = 4 << 20;
const HEADER_TABLE_SIZE: usize = 4096;
/// Refuse frames larger than this (we never raise SETTINGS_MAX_FRAME_SIZE).
const MAX_FRAME_LEN: usize = DEFAULT_MAX_FRAME;

mod frame {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

mod flag {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

mod setting {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2Error {
    /// The peer violated the protocol; the connection is unusable.
    Protocol(&'static str),
    Hpack(hpack::HpackError),
    /// The connection received GOAWAY or was otherwise shut down.
    Closed,
}

impl From<hpack::HpackError> for H2Error {
    fn from(e: hpack::HpackError) -> Self {
        H2Error::Hpack(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Response headers for a stream.
    Response { stream: u32, status: u16, headers: Vec<Header> },
    /// A chunk of response body.
    Data { stream: u32, data: Vec<u8> },
    /// The server finished the response.
    End { stream: u32 },
    /// The server reset the stream with an error code.
    Reset { stream: u32, code: u32 },
    /// The server is shutting the connection down.
    GoAway { last_stream: u32, code: u32 },
}

struct Stream {
    /// Request body bytes not yet sent (flow control).
    pending_body: VecDeque<u8>,
    end_after_body: bool,
    send_window: i64,
    got_headers: bool,
}

pub struct Client {
    authority: String,
    scheme: &'static str,
    outgoing: Vec<u8>,
    incoming: Vec<u8>,
    events: VecDeque<Event>,
    decoder: hpack::Decoder,
    streams: BTreeMap<u32, Stream>,
    next_stream: u32,
    conn_send_window: i64,
    peer_initial_window: i64,
    peer_max_frame: usize,
    /// Header block being assembled from HEADERS + CONTINUATION frames.
    partial_headers: Option<(u32, bool, Vec<u8>)>,
    goaway: bool,
}

impl Client {
    /// Releases spare buffer capacity (see [`crate::trim_vec`]).
    pub fn trim(&mut self) {
        crate::trim_vec(&mut self.outgoing);
        crate::trim_vec(&mut self.incoming);
        self.events.shrink_to_fit();
    }

    /// Starts a connection. `authority` is the Host the requests address.
    pub fn new(authority: &str, scheme: &'static str) -> Self {
        let mut c = Self {
            authority: authority.into(),
            scheme,
            outgoing: Vec::new(),
            incoming: Vec::new(),
            events: VecDeque::new(),
            decoder: hpack::Decoder::new(HEADER_TABLE_SIZE),
            streams: BTreeMap::new(),
            next_stream: 1,
            conn_send_window: DEFAULT_WINDOW,
            peer_initial_window: DEFAULT_WINDOW,
            peer_max_frame: DEFAULT_MAX_FRAME,
            partial_headers: None,
            goaway: false,
        };
        c.outgoing.extend_from_slice(PREFACE);
        let mut settings = Vec::new();
        for (id, value) in [
            (setting::ENABLE_PUSH, 0u32),
            (setting::INITIAL_WINDOW_SIZE, RECV_WINDOW),
            (setting::HEADER_TABLE_SIZE, HEADER_TABLE_SIZE as u32),
        ] {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&value.to_be_bytes());
        }
        c.write_frame(frame::SETTINGS, 0, 0, &settings);
        // Raise the connection-level window from the fixed 65535 default.
        c.write_frame(frame::WINDOW_UPDATE, 0, 0, &(RECV_WINDOW - DEFAULT_WINDOW as u32).to_be_bytes());
        c
    }

    pub fn is_closed(&self) -> bool {
        self.goaway
    }

    /// Starts a request and returns its stream id. `headers` are extra
    /// (lowercase) request headers; the body is sent subject to flow control.
    pub fn request(&mut self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<u32, H2Error> {
        if self.goaway {
            return Err(H2Error::Closed);
        }
        let stream = self.next_stream;
        self.next_stream += 2;

        let mut all: Vec<(&str, &str)> = alloc::vec![
            (":method", method),
            (":scheme", self.scheme),
            (":path", path),
            (":authority", self.authority.as_str()),
        ];
        all.extend_from_slice(headers);
        let block = hpack::encode(&all);
        let end_stream = body.is_empty();

        // Header blocks we build are small, but split to be safe.
        let max = self.peer_max_frame;
        let mut chunks = block.chunks(max).peekable();
        let first = chunks.next().unwrap_or(&[]);
        let mut flags = if end_stream { flag::END_STREAM } else { 0 };
        if chunks.peek().is_none() {
            flags |= flag::END_HEADERS;
        }
        self.write_frame(frame::HEADERS, flags, stream, first);
        while let Some(chunk) = chunks.next() {
            let flags = if chunks.peek().is_none() { flag::END_HEADERS } else { 0 };
            self.write_frame(frame::CONTINUATION, flags, stream, chunk);
        }

        self.streams.insert(
            stream,
            Stream {
                pending_body: body.iter().copied().collect(),
                end_after_body: !end_stream,
                send_window: self.peer_initial_window,
                got_headers: false,
            },
        );
        self.flush_bodies();
        Ok(stream)
    }

    /// Abandons a stream (e.g. a long-poll we no longer want).
    pub fn cancel(&mut self, stream: u32) {
        if self.streams.remove(&stream).is_some() {
            const CANCEL: u32 = 0x8;
            self.write_frame(frame::RST_STREAM, 0, stream, &CANCEL.to_be_bytes());
        }
    }

    /// Sends a PING; the server's ACK is consumed silently. Useful as a
    /// liveness probe on long-idle connections.
    pub fn ping(&mut self, opaque: [u8; 8]) {
        self.write_frame(frame::PING, 0, 0, &opaque);
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Feeds bytes received from the server.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), H2Error> {
        self.incoming.extend_from_slice(data);
        let mut consumed = 0;
        loop {
            let buf = &self.incoming[consumed..];
            if buf.len() < FRAME_HEADER_LEN {
                break;
            }
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if len > MAX_FRAME_LEN {
                return Err(H2Error::Protocol("frame exceeds SETTINGS_MAX_FRAME_SIZE"));
            }
            if buf.len() < FRAME_HEADER_LEN + len {
                break;
            }
            let typ = buf[3];
            let flags = buf[4];
            let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
            let payload = buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len].to_vec();
            consumed += FRAME_HEADER_LEN + len;
            self.handle_frame(typ, flags, stream, payload)?;
        }
        self.incoming.drain(..consumed);
        Ok(())
    }

    fn handle_frame(&mut self, typ: u8, flags: u8, stream: u32, payload: Vec<u8>) -> Result<(), H2Error> {
        if self.partial_headers.is_some() && typ != frame::CONTINUATION {
            return Err(H2Error::Protocol("expected CONTINUATION"));
        }
        match typ {
            frame::DATA => {
                let len = payload.len() as u32;
                let data = strip_padding(flags, payload)?;
                // Replenish both windows immediately; the engine consumes
                // data synchronously, so there is no reason to apply backpressure.
                if len > 0 {
                    self.write_frame(frame::WINDOW_UPDATE, 0, 0, &len.to_be_bytes());
                }
                if self.streams.contains_key(&stream) {
                    if len > 0 && flags & flag::END_STREAM == 0 {
                        self.write_frame(frame::WINDOW_UPDATE, 0, stream, &len.to_be_bytes());
                    }
                    if !data.is_empty() {
                        self.events.push_back(Event::Data { stream, data });
                    }
                    if flags & flag::END_STREAM != 0 {
                        self.finish_stream(stream);
                    }
                }
            }
            frame::HEADERS => {
                let mut block = strip_padding(flags, payload)?;
                if flags & flag::PRIORITY != 0 {
                    if block.len() < 5 {
                        return Err(H2Error::Protocol("short HEADERS priority"));
                    }
                    block.drain(..5);
                }
                let end_stream = flags & flag::END_STREAM != 0;
                if flags & flag::END_HEADERS != 0 {
                    self.handle_header_block(stream, end_stream, &block)?;
                } else {
                    self.partial_headers = Some((stream, end_stream, block));
                }
            }
            frame::CONTINUATION => {
                let Some((s, end_stream, mut block)) = self.partial_headers.take() else {
                    return Err(H2Error::Protocol("unexpected CONTINUATION"));
                };
                if s != stream {
                    return Err(H2Error::Protocol("CONTINUATION on wrong stream"));
                }
                block.extend_from_slice(&payload);
                if flags & flag::END_HEADERS != 0 {
                    self.handle_header_block(stream, end_stream, &block)?;
                } else {
                    self.partial_headers = Some((s, end_stream, block));
                }
            }
            frame::RST_STREAM => {
                let code = be_u32(&payload).ok_or(H2Error::Protocol("short RST_STREAM"))?;
                if self.streams.remove(&stream).is_some() {
                    self.events.push_back(Event::Reset { stream, code });
                }
            }
            frame::SETTINGS => {
                if flags & flag::ACK == 0 {
                    self.apply_settings(&payload)?;
                    self.write_frame(frame::SETTINGS, flag::ACK, 0, &[]);
                }
            }
            frame::PING => {
                if flags & flag::ACK == 0 {
                    self.write_frame(frame::PING, flag::ACK, 0, &payload);
                }
            }
            frame::GOAWAY => {
                let last_stream = be_u32(&payload).ok_or(H2Error::Protocol("short GOAWAY"))? & 0x7fff_ffff;
                let code = be_u32(payload.get(4..).unwrap_or(&[])).unwrap_or(0);
                self.goaway = true;
                self.events.push_back(Event::GoAway { last_stream, code });
            }
            frame::WINDOW_UPDATE => {
                let inc = be_u32(&payload).ok_or(H2Error::Protocol("short WINDOW_UPDATE"))? & 0x7fff_ffff;
                if stream == 0 {
                    self.conn_send_window += inc as i64;
                } else if let Some(s) = self.streams.get_mut(&stream) {
                    s.send_window += inc as i64;
                }
                self.flush_bodies();
            }
            frame::PUSH_PROMISE => return Err(H2Error::Protocol("push disabled but PUSH_PROMISE received")),
            // PRIORITY and unknown frame types are ignored (RFC 9113 4.1).
            _ => {}
        }
        Ok(())
    }

    fn handle_header_block(&mut self, stream: u32, end_stream: bool, block: &[u8]) -> Result<(), H2Error> {
        // Always decode, even for unknown streams, to keep HPACK state in sync.
        let headers = self.decoder.decode(block)?;
        let Some(s) = self.streams.get_mut(&stream) else {
            return Ok(());
        };
        if !s.got_headers {
            let status = headers
                .iter()
                .find(|(n, _)| n == ":status")
                .and_then(|(_, v)| v.parse().ok())
                .ok_or(H2Error::Protocol("response without :status"))?;
            // 1xx informational responses are followed by the real one.
            if !(100..200).contains(&status) {
                s.got_headers = true;
                self.events.push_back(Event::Response { stream, status, headers });
            }
        }
        // A second header block is trailers; ignored.
        if end_stream {
            self.finish_stream(stream);
        }
        Ok(())
    }

    fn finish_stream(&mut self, stream: u32) {
        self.streams.remove(&stream);
        self.events.push_back(Event::End { stream });
    }

    fn apply_settings(&mut self, payload: &[u8]) -> Result<(), H2Error> {
        if payload.len() % 6 != 0 {
            return Err(H2Error::Protocol("bad SETTINGS length"));
        }
        for entry in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([entry[0], entry[1]]);
            let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
            match id {
                setting::INITIAL_WINDOW_SIZE => {
                    let delta = value as i64 - self.peer_initial_window;
                    self.peer_initial_window = value as i64;
                    for s in self.streams.values_mut() {
                        s.send_window += delta;
                    }
                }
                setting::MAX_FRAME_SIZE => self.peer_max_frame = (value as usize).clamp(DEFAULT_MAX_FRAME, 1 << 24),
                _ => {}
            }
        }
        self.flush_bodies();
        Ok(())
    }

    /// Sends as much pending request body as flow control allows.
    fn flush_bodies(&mut self) {
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            loop {
                let max_frame = self.peer_max_frame;
                let conn_window = self.conn_send_window;
                let s = self.streams.get_mut(&id).unwrap();
                if s.pending_body.is_empty() {
                    if s.end_after_body {
                        s.end_after_body = false;
                        self.write_frame(frame::DATA, flag::END_STREAM, id, &[]);
                    }
                    break;
                }
                let n = s.pending_body.len().min(max_frame).min(s.send_window.min(conn_window).max(0) as usize);
                if n == 0 {
                    break;
                }
                let chunk: Vec<u8> = s.pending_body.drain(..n).collect();
                s.send_window -= n as i64;
                let last = s.pending_body.is_empty() && s.end_after_body;
                if last {
                    s.end_after_body = false;
                }
                self.conn_send_window -= n as i64;
                self.write_frame(frame::DATA, if last { flag::END_STREAM } else { 0 }, id, &chunk);
            }
        }
    }

    fn write_frame(&mut self, typ: u8, flags: u8, stream: u32, payload: &[u8]) {
        let len = payload.len() as u32;
        self.outgoing.extend_from_slice(&len.to_be_bytes()[1..]);
        self.outgoing.push(typ);
        self.outgoing.push(flags);
        self.outgoing.extend_from_slice(&stream.to_be_bytes());
        self.outgoing.extend_from_slice(payload);
    }
}

fn be_u32(b: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(..4)?.try_into().ok()?))
}

fn strip_padding(flags: u8, mut payload: Vec<u8>) -> Result<Vec<u8>, H2Error> {
    if flags & flag::PADDED == 0 {
        return Ok(payload);
    }
    let pad = *payload.first().ok_or(H2Error::Protocol("missing pad length"))? as usize;
    if pad + 1 > payload.len() {
        return Err(H2Error::Protocol("padding exceeds frame"));
    }
    payload.truncate(payload.len() - pad);
    payload.remove(0);
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Splits a byte stream into (type, flags, stream, payload) frames.
    fn frames(mut buf: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut out = Vec::new();
        while buf.len() >= 9 {
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            out.push((buf[3], buf[4], u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]), buf[9..9 + len].to_vec()));
            buf = &buf[9 + len..];
        }
        out
    }

    fn server_frame(typ: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut c = Client::new("x", "http");
        c.outgoing.clear();
        c.write_frame(typ, flags, stream, payload);
        c.outgoing
    }

    #[test]
    fn request_response_roundtrip() {
        let mut c = Client::new("controlplane.example", "http");
        let out = c.take_outgoing();
        assert!(out.starts_with(PREFACE));
        let opening = frames(&out[PREFACE.len()..]);
        assert_eq!(opening[0].0, frame::SETTINGS);
        assert_eq!(opening[1].0, frame::WINDOW_UPDATE);

        let id = c.request("POST", "/machine/register", &[("content-type", "application/json")], b"{}").unwrap();
        assert_eq!(id, 1);
        let sent = frames(&c.take_outgoing());
        assert_eq!(sent[0].0, frame::HEADERS);
        let hdrs = hpack::Decoder::new(4096).decode(&sent[0].3).unwrap();
        assert!(hdrs.contains(&(":path".into(), "/machine/register".into())));
        assert_eq!((sent[1].0, sent[1].1, sent[1].3.as_slice()), (frame::DATA, flag::END_STREAM, &b"{}"[..]));

        // Server: SETTINGS, response headers (":status 200" is static index 8), body.
        let mut input = server_frame(frame::SETTINGS, 0, 0, &[]);
        input.extend(server_frame(frame::HEADERS, flag::END_HEADERS, 1, &[0x88]));
        input.extend(server_frame(frame::DATA, flag::END_STREAM, 1, b"{\"ok\":1}"));
        // Feed in awkward pieces to exercise reassembly.
        for chunk in input.chunks(5) {
            c.feed(chunk).unwrap();
        }
        assert_eq!(c.poll_event(), Some(Event::Response { stream: 1, status: 200, headers: vec![(":status".into(), "200".into())] }));
        assert_eq!(c.poll_event(), Some(Event::Data { stream: 1, data: b"{\"ok\":1}".to_vec() }));
        assert_eq!(c.poll_event(), Some(Event::End { stream: 1 }));
        // We must have ACKed the server's SETTINGS.
        assert!(frames(&c.take_outgoing()).iter().any(|f| f.0 == frame::SETTINGS && f.1 == flag::ACK));
    }

    #[test]
    fn body_respects_flow_control() {
        let mut c = Client::new("x", "http");
        c.take_outgoing();
        let body = vec![7u8; 100_000];
        c.request("POST", "/big", &[], &body).unwrap();
        let sent: usize = frames(&c.take_outgoing()).iter().filter(|f| f.0 == frame::DATA).map(|f| f.3.len()).sum();
        assert_eq!(sent, 65_535, "initial windows cap the first flight");
        c.feed(&server_frame(frame::WINDOW_UPDATE, 0, 0, &100_000u32.to_be_bytes())).unwrap();
        c.feed(&server_frame(frame::WINDOW_UPDATE, 0, 1, &100_000u32.to_be_bytes())).unwrap();
        let rest = frames(&c.take_outgoing());
        let more: usize = rest.iter().filter(|f| f.0 == frame::DATA).map(|f| f.3.len()).sum();
        assert_eq!(more, 100_000 - 65_535);
        assert_eq!(rest.last().unwrap().1 & flag::END_STREAM, flag::END_STREAM);
    }

    #[test]
    fn answers_ping_and_reports_goaway() {
        let mut c = Client::new("x", "http");
        c.take_outgoing();
        c.feed(&server_frame(frame::PING, 0, 0, b"12345678")).unwrap();
        let out = frames(&c.take_outgoing());
        assert_eq!((out[0].0, out[0].1, out[0].3.as_slice()), (frame::PING, flag::ACK, &b"12345678"[..]));
        let mut goaway = 3u32.to_be_bytes().to_vec();
        goaway.extend(0u32.to_be_bytes());
        c.feed(&server_frame(frame::GOAWAY, 0, 0, &goaway)).unwrap();
        assert_eq!(c.poll_event(), Some(Event::GoAway { last_stream: 3, code: 0 }));
        assert!(c.request("GET", "/", &[], &[]).is_err());
    }
}
