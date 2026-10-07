//! Control plane session state machine: fetch the server key, open a ts2021
//! channel, register the node, then hold a streaming map poll open, with
//! reconnect/backoff. Sans-IO: socket work is requested through [`Io`] and
//! results come back through the `on_*` methods.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use super::conn::ControlConn;
use super::{hex32, key_request, parse_key_response, CAPABILITY_VERSION};
use crate::http2::Event as H2Event;
use crate::stream::SecureStream;
use crate::time::{Backoff, Instant};

/// Identifies one outbound TCP connection the driver manages for us.
pub type ConnId = u32;

/// Socket work for the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Io {
    /// Resolve `host` and connect to it on `port`; report back with
    /// `on_connected` or `on_closed`.
    Connect { id: ConnId, host: String, port: u16 },
    Send { id: ConnId, data: Vec<u8> },
    Close { id: ConnId },
}

/// Things the control session learned, for the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// Interactive login is needed; show this URL to the user.
    LoginUrl(String),
    /// The node is registered and authorized.
    Authorized,
    /// One MapResponse message (JSON), excluding bare keep-alives.
    Map(Vec<u8>),
    /// A recoverable failure; the session will retry after a backoff.
    Error(String),
    /// The server said our node key expired, so we made a new one (this
    /// private key) and are registering it in place of the old. The driver
    /// must persist it, or a restart would bring the expired key back.
    NodeKeyRotated([u8; 32]),
}

#[derive(Debug, Clone)]
pub struct ControlConfig {
    /// e.g. `https://controlplane.tailscale.com` or `https://headscale:8443`.
    pub url: String,
    pub auth_key: Option<String>,
    pub hostname: String,
    /// Extra DER trust anchors for the control server's TLS (dev setups).
    pub extra_roots: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
pub struct Keys {
    pub machine_private: [u8; 32],
    pub node_private: [u8; 32],
    pub disco_public: [u8; 32],
}

struct Endpoint {
    host: String,
    port: u16,
    tls: bool,
}

fn parse_url(url: &str) -> Result<Endpoint, String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("unsupported control URL {url}"));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once(':') {
        Some((h, p)) => Ok(Endpoint { host: h.into(), port: p.parse().map_err(|_| "bad port".to_string())?, tls }),
        None => Ok(Endpoint { host: authority.into(), port: if tls { 443 } else { 80 }, tls }),
    }
}

enum Phase {
    /// Waiting to (re)start.
    Idle { until: Instant },
    /// GET /key over its own short-lived connection.
    FetchKey { id: ConnId, stream: Option<SecureStream>, response: Vec<u8> },
    /// ts2021 channel being set up / in use.
    Session { id: ConnId, stream: Option<SecureStream>, conn: ControlConn, step: Step },
}

enum Step {
    Handshaking,
    Registering { stream: u32, status: u16, body: Vec<u8>, followup: bool },
    Polling { stream: u32, status: u16, buf: Vec<u8> },
}

/// How long the map poll may be silent before we assume the connection died.
/// Servers send keep-alives roughly every minute.
const POLL_SILENCE_LIMIT: Duration = Duration::from_secs(150);
/// Interactive login waits on a long-poll; allow it plenty of time.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_MAP_MESSAGE: usize = 32 << 20;

pub struct ControlClient {
    cfg: ControlConfig,
    endpoint: Endpoint,
    keys: Keys,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    control_key: Option<[u8; 32]>,
    phase: Phase,
    next_id: ConnId,
    io: VecDeque<Io>,
    updates: VecDeque<Update>,
    backoff: Backoff,
    /// Last time we heard from the server (or started waiting on it).
    last_activity: Instant,
    now: Instant,
    authorized: bool,
    login_url: Option<String>,
    ephemeral: [u8; 32],
    preferred_derp: Option<u32>,
    endpoints: Vec<core::net::SocketAddr>,
    /// Immediate re-registrations after login-flow hiccups (bounded).
    register_retries: u32,
    /// Set while registering a new node key in place of this expired one
    /// (sent as OldNodeKey until the new key is authorized).
    old_node_key: Option<String>,
}

impl ControlClient {
    /// Releases spare buffer capacity (see [`crate::trim_vec`]): the map
    /// poll's buffer grows to the largest netmap and would keep that size.
    pub fn trim(&mut self) {
        match &mut self.phase {
            Phase::Idle { .. } => {}
            Phase::FetchKey { stream, response, .. } => {
                stream.as_mut().map(SecureStream::trim);
                crate::trim_vec(response);
            }
            Phase::Session { stream, conn, step, .. } => {
                stream.as_mut().map(SecureStream::trim);
                conn.trim();
                match step {
                    Step::Handshaking => {}
                    Step::Registering { body, .. } => crate::trim_vec(body),
                    Step::Polling { buf, .. } => crate::trim_vec(buf),
                }
            }
        }
        self.io.shrink_to_fit();
        self.updates.shrink_to_fit();
    }

    pub fn new(cfg: ControlConfig, keys: Keys, now: Instant) -> Result<Self, String> {
        let endpoint = parse_url(&cfg.url)?;
        let tls_config = if endpoint.tls {
            Some(crate::tls::client_config(&cfg.extra_roots).map_err(|e| e.to_string())?)
        } else {
            None
        };
        Ok(Self {
            cfg,
            endpoint,
            keys,
            tls_config,
            control_key: None,
            phase: Phase::Idle { until: now },
            next_id: 1,
            io: VecDeque::new(),
            updates: VecDeque::new(),
            backoff: Backoff::new(Duration::from_secs(1), Duration::from_secs(60)),
            last_activity: now,
            now,
            authorized: false,
            login_url: None,
            ephemeral: [0; 32],
            preferred_derp: None,
            endpoints: Vec::new(),
            register_retries: 0,
            old_node_key: None,
        })
    }

    pub fn poll_io(&mut self) -> Option<Io> {
        self.io.pop_front()
    }

    pub fn poll_update(&mut self) -> Option<Update> {
        self.updates.pop_front()
    }

    pub fn is_polling(&self) -> bool {
        matches!(self.phase, Phase::Session { step: Step::Polling { status: 200, .. }, .. })
    }

    /// When `handle_timeout` should next be called.
    pub fn next_deadline(&self) -> Instant {
        match &self.phase {
            Phase::Idle { until } => *until,
            Phase::Session { step: Step::Polling { .. }, .. } => self.last_activity + POLL_SILENCE_LIMIT,
            Phase::Session { step: Step::Registering { followup: true, .. }, .. } => {
                // Interactive login long-polls; only the socket closing ends it.
                self.last_activity + Duration::from_secs(24 * 3600)
            }
            _ => self.last_activity + CONNECT_TIMEOUT,
        }
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        if now < self.next_deadline() {
            return;
        }
        match self.phase {
            Phase::Idle { .. } => self.start(),
            _ => self.fail("control connection timed out"),
        }
    }

    /// Our node key's expiry passed (we track it from the netmap, as the
    /// server keeps the session going): register a new key in its place.
    pub fn replace_expired_node_key(&mut self, now: Instant) {
        match new_node_key(&mut self.keys, &mut self.old_node_key, &mut self.login_url) {
            Ok(fresh) => self.updates.push_back(Update::NodeKeyRotated(fresh)),
            Err(e) => return self.updates.push_back(Update::Error(e)),
        }
        self.restart(now);
    }

    /// Forces a reconnect now (e.g. the network changed).
    pub fn restart(&mut self, now: Instant) {
        self.now = now;
        self.close_current();
        self.backoff.reset();
        self.phase = Phase::Idle { until: now };
        self.start();
    }

    /// Updates what we tell the server about our network position (home
    /// DERP region, direct UDP endpoints) and pushes it if a session is up.
    pub fn set_net_info(&mut self, preferred_derp: Option<u32>, endpoints: Vec<core::net::SocketAddr>) {
        if self.preferred_derp == preferred_derp && self.endpoints == endpoints {
            return;
        }
        self.preferred_derp = preferred_derp;
        self.endpoints = endpoints;
        if let Err(e) = self.push_net_info() {
            self.fail(&e);
        }
    }

    /// Sends a non-streaming "lite" map request carrying fresh Hostinfo and
    /// endpoints, like the Go client does after netcheck/endpoint changes.
    fn push_net_info(&mut self) -> Result<(), String> {
        if !self.is_polling() {
            return Ok(()); // The next streaming request will carry it.
        }
        let hostinfo = self.hostinfo();
        let endpoints = self.endpoints_json();
        let node_key = format!("nodekey:{}", hex32(&crate::crypto::x25519_public(&self.keys.node_private)));
        let Phase::Session { id, stream: Some(s), conn, .. } = &mut self.phase else { return Ok(()) };
        let id = *id;
        let body = format!(
            r#"{{"Version":{CAPABILITY_VERSION},"Compress":"","KeepAlive":false,"Stream":false,"OmitPeers":true,"NodeKey":"{node_key}","DiscoKey":"discokey:{}","Hostinfo":{hostinfo},"Endpoints":{endpoints}}}"#,
            hex32(&self.keys.disco_public)
        );
        conn.request("POST", "/machine/map", &[("content-type", "application/json"), ("ts-lb", &node_key)], body.as_bytes())
            .map_err(|e| format!("{e:?}"))?;
        let out = conn.take_outgoing();
        s.write(&out).map_err(|e| format!("TLS: {e:?}"))?;
        let raw = s.take_outgoing();
        self.send(id, raw);
        Ok(())
    }

    fn endpoints_json(&self) -> String {
        let items: Vec<String> = self.endpoints.iter().map(|e| format!("\"{e}\"")).collect();
        format!("[{}]", items.join(","))
    }

    pub fn on_connected(&mut self, id: ConnId, now: Instant) {
        self.now = now;
        self.last_activity = now;
        let current = match &self.phase {
            Phase::FetchKey { id, .. } | Phase::Session { id, .. } => Some(*id),
            Phase::Idle { .. } => None,
        };
        if current != Some(id) {
            return;
        }
        let mut s = match self.make_stream() {
            Ok(s) => s,
            Err(e) => return self.fail(&e),
        };
        let first = match &mut self.phase {
            Phase::FetchKey { .. } => key_request(&self.endpoint.host),
            Phase::Session { conn, .. } => conn.take_outgoing(),
            Phase::Idle { .. } => unreachable!(),
        };
        if let Err(e) = s.write(&first) {
            return self.fail(&format!("TLS: {e:?}"));
        }
        let raw = s.take_outgoing();
        match &mut self.phase {
            Phase::FetchKey { stream, .. } | Phase::Session { stream, .. } => *stream = Some(s),
            Phase::Idle { .. } => unreachable!(),
        }
        self.send(id, raw);
    }

    pub fn on_data(&mut self, id: ConnId, data: &[u8], now: Instant) {
        self.now = now;
        if let Err(e) = self.handle_data(id, data) {
            self.fail(&e);
        }
    }

    pub fn on_closed(&mut self, id: ConnId, now: Instant) {
        self.now = now;
        match &self.phase {
            Phase::FetchKey { id: cur, response, .. } if *cur == id => {
                // /key uses Connection: close; EOF ends the response.
                match parse_key_response(response) {
                    Ok(key) => {
                        self.control_key = Some(key);
                        self.open_session();
                    }
                    Err(e) => self.fail(&format!("/key: {e:?}")),
                }
            }
            Phase::Session { id: cur, .. } if *cur == id => self.fail("control connection closed"),
            _ => {}
        }
    }

    fn start(&mut self) {
        if self.control_key.is_some() {
            self.open_session();
        } else {
            let id = self.connect();
            self.phase = Phase::FetchKey { id, stream: None, response: Vec::new() };
        }
    }

    fn open_session(&mut self) {
        let Some(control_key) = self.control_key else { return self.start() };
        self.ephemeral = match crate::rng::bytes32() {
            Ok(b) => b,
            Err(_) => return self.fail("RNG not seeded"),
        };
        let conn = match ControlConn::new(
            &self.endpoint.host,
            &self.keys.machine_private,
            &control_key,
            &self.ephemeral,
            CAPABILITY_VERSION,
        ) {
            Ok(c) => c,
            Err(e) => return self.fail(&format!("{e:?}")),
        };
        let id = self.connect();
        self.phase = Phase::Session { id, stream: None, conn, step: Step::Handshaking };
    }

    fn connect(&mut self) -> ConnId {
        let id = self.next_id;
        self.next_id += 1;
        self.last_activity = self.now;
        self.io.push_back(Io::Connect { id, host: self.endpoint.host.clone(), port: self.endpoint.port });
        id
    }

    fn make_stream(&self) -> Result<SecureStream, String> {
        match &self.tls_config {
            Some(cfg) => SecureStream::tls(cfg.clone(), &self.endpoint.host).map_err(|e| format!("{e:?}")),
            None => Ok(SecureStream::plain()),
        }
    }

    fn send(&mut self, id: ConnId, data: Vec<u8>) {
        if !data.is_empty() {
            self.io.push_back(Io::Send { id, data });
        }
    }

    fn handle_data(&mut self, id: ConnId, data: &[u8]) -> Result<(), String> {
        self.last_activity = self.now;
        match &mut self.phase {
            Phase::FetchKey { id: cur, stream: Some(s), response } if *cur == id => {
                s.feed(data).map_err(|e| format!("TLS: {e:?}"))?;
                response.extend(s.take_plaintext());
                let out = s.take_outgoing();
                self.send(id, out);
                Ok(())
            }
            Phase::Session { id: cur, stream: Some(s), conn, .. } if *cur == id => {
                s.feed(data).map_err(|e| format!("TLS: {e:?}"))?;
                let plain = s.take_plaintext();
                conn.feed(&plain).map_err(|e| format!("ts2021: {e:?}"))?;
                self.pump_session()
            }
            _ => Ok(()),
        }
    }

    /// Advances the session after new input: issue requests, consume events.
    fn pump_session(&mut self) -> Result<(), String> {
        let hostinfo = self.hostinfo();
        let endpoints = self.endpoints_json();
        let Phase::Session { id, stream: Some(s), conn, step } = &mut self.phase else {
            return Ok(());
        };
        let id = *id;
        let node_key_of = |private: &[u8; 32]| format!("nodekey:{}", hex32(&crate::crypto::x25519_public(private)));
        let mut node_key = node_key_of(&self.keys.node_private);

        if matches!(step, Step::Handshaking) && conn.is_ready() {
            *step = register_request(conn, &node_key, &hostinfo, self.cfg.auth_key.as_deref(), None, self.old_node_key.as_deref())?;
        }

        let mut new_updates = Vec::new();
        while let Some(ev) = conn.poll_event() {
            match (&mut *step, ev) {
                (Step::Registering { stream, status, .. }, H2Event::Response { stream: sid, status: st, .. })
                    if *stream == sid =>
                {
                    *status = st
                }
                (Step::Registering { stream, body, .. }, H2Event::Data { stream: sid, data }) if *stream == sid => {
                    body.extend(data)
                }
                (Step::Registering { stream, status, body, followup }, H2Event::End { stream: sid }) if *stream == sid => {
                    // After an interactive login completes, the server may end the
                    // follow-up long-poll with 410 ("auth path not found"); the
                    // node is authorized by then, so just register again.
                    if *status == 410 && *followup && self.register_retries < 3 {
                        self.register_retries += 1;
                        *step = register_request(conn, &node_key, &hostinfo, None, None, self.old_node_key.as_deref())?;
                        continue;
                    }
                    if *status != 200 {
                        return Err(format!("register: HTTP {status}: {}", String::from_utf8_lossy(body)));
                    }
                    log::debug!("register response: {}", String::from_utf8_lossy(body));
                    let resp: RegisterResponse =
                        serde_json::from_slice(body).map_err(|e| format!("register response: {e}"))?;
                    if !resp.error.is_empty() {
                        return Err(format!("register: {}", resp.error));
                    }
                    if resp.node_key_expired && !resp.machine_authorized && self.old_node_key.is_none() {
                        // The key expired while we were offline: replace it.
                        let fresh = new_node_key(&mut self.keys, &mut self.old_node_key, &mut self.login_url)?;
                        node_key = node_key_of(&fresh);
                        new_updates.push(Update::NodeKeyRotated(fresh));
                        *step = register_request(
                            conn,
                            &node_key,
                            &hostinfo,
                            self.cfg.auth_key.as_deref(),
                            None,
                            self.old_node_key.as_deref(),
                        )?;
                        continue;
                    }
                    if resp.machine_authorized {
                        self.authorized = true;
                        self.register_retries = 0;
                        self.old_node_key = None;
                        new_updates.push(Update::Authorized);
                        *step = map_request(conn, &node_key, &self.keys.disco_public, &hostinfo, &endpoints)?;
                    } else if !resp.auth_url.is_empty() {
                        if self.login_url.as_deref() != Some(resp.auth_url.as_str()) {
                            self.login_url = Some(resp.auth_url.clone());
                            new_updates.push(Update::LoginUrl(resp.auth_url.clone()));
                        }
                        // Long-poll until the user completes the login.
                        *step = register_request(conn, &node_key, &hostinfo, None, Some(&resp.auth_url), self.old_node_key.as_deref())?;
                    } else if self.register_retries < 3 {
                        // Briefly seen right after a login completes, while the
                        // server finishes authorizing the node: ask again.
                        self.register_retries += 1;
                        *step = register_request(conn, &node_key, &hostinfo, None, None, self.old_node_key.as_deref())?;
                    } else {
                        return Err("register: not authorized and no login URL".into());
                    }
                }
                (Step::Polling { stream, status, .. }, H2Event::Response { stream: sid, status: st, .. })
                    if *stream == sid =>
                {
                    *status = st
                }
                (Step::Polling { stream, status, buf }, H2Event::Data { stream: sid, data }) if *stream == sid => {
                    buf.extend(data);
                    if *status != 200 {
                        continue;
                    }
                    // Length-prefixed (u32 little-endian) JSON messages.
                    while buf.len() >= 4 {
                        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
                        if len > MAX_MAP_MESSAGE {
                            return Err(format!("map message too large: {len}"));
                        }
                        if buf.len() < 4 + len {
                            break;
                        }
                        let msg: Vec<u8> = buf.drain(..4 + len).skip(4).collect();
                        if msg != br#"{"KeepAlive":true}"# {
                            new_updates.push(Update::Map(msg));
                        }
                    }
                }
                (Step::Polling { stream, status, buf }, H2Event::End { stream: sid }) if *stream == sid => {
                    return Err(format!("map poll ended: HTTP {status}: {}", String::from_utf8_lossy(buf)));
                }
                (_, H2Event::Reset { code, .. }) => return Err(format!("control stream reset ({code})")),
                (_, H2Event::GoAway { code, .. }) => return Err(format!("control GOAWAY ({code})")),
                _ => {}
            }
        }
        if !new_updates.is_empty() {
            self.backoff.reset();
        }
        self.updates.extend(new_updates);

        let out = conn.take_outgoing();
        s.write(&out).map_err(|e| format!("TLS: {e:?}"))?;
        let raw = s.take_outgoing();
        self.send(id, raw);
        Ok(())
    }

    fn hostinfo(&self) -> String {
        let net_info = match self.preferred_derp {
            Some(r) => format!(r#","NetInfo":{{"PreferredDERP":{r}}}"#),
            None => String::new(),
        };
        format!(
            r#"{{"IPNVersion":"{}-tsnx","Hostname":{},"OS":"linux","OSVersion":"Horizon","DeviceModel":"Nintendo Switch","GoArch":"arm64"{net_info}}}"#,
            crate::VERSION,
            json_string(&self.cfg.hostname)
        )
    }

    fn close_current(&mut self) {
        let id = match &self.phase {
            Phase::FetchKey { id, .. } | Phase::Session { id, .. } => Some(*id),
            Phase::Idle { .. } => None,
        };
        if let Some(id) = id {
            self.io.push_back(Io::Close { id });
        }
    }

    fn fail(&mut self, msg: &str) {
        self.close_current();
        // A bad /key response or handshake may mean the key rotated.
        if !matches!(self.phase, Phase::Session { step: Step::Polling { .. }, .. }) {
            self.control_key = None;
        }
        let delay = self.backoff.next_delay();
        self.phase = Phase::Idle { until: self.now + delay };
        self.updates.push_back(Update::Error(msg.into()));
    }
}

/// Like Tailscale's client, an expired node key is replaced by a fresh one,
/// registered with the old one as OldNodeKey (same machine, same tailnet
/// address). A reusable auth key in the config re-authorizes it at once;
/// otherwise the server answers with a login URL. Returns the new private key.
fn new_node_key(keys: &mut Keys, old_node_key: &mut Option<String>, login_url: &mut Option<String>) -> Result<[u8; 32], String> {
    let mut fresh = [0u8; 32];
    crate::rng::fill(&mut fresh).map_err(|_| "node key: RNG not seeded".to_string())?;
    let old = crate::crypto::x25519_public(&keys.node_private);
    // A second expiry before the first replacement was authorized keeps the
    // original key as the one being replaced.
    old_node_key.get_or_insert_with(|| format!("nodekey:{}", hex32(&old)));
    keys.node_private = fresh;
    *login_url = None;
    Ok(fresh)
}

fn register_request(
    conn: &mut ControlConn,
    node_key: &str,
    hostinfo: &str,
    auth_key: Option<&str>,
    followup: Option<&str>,
    old_node_key: Option<&str>,
) -> Result<Step, String> {
    let mut body = format!(r#"{{"Version":{CAPABILITY_VERSION},"NodeKey":"{node_key}","Hostinfo":{hostinfo}"#);
    if let Some(old) = old_node_key {
        body.push_str(&format!(r#","OldNodeKey":{}"#, json_string(old)));
    }
    if let Some(k) = auth_key {
        body.push_str(&format!(r#","Auth":{{"AuthKey":{}}}"#, json_string(k)));
    }
    if let Some(url) = followup {
        body.push_str(&format!(r#","Followup":{}"#, json_string(url)));
    }
    body.push('}');
    let stream = conn
        .request("POST", "/machine/register", &[("content-type", "application/json"), ("ts-lb", node_key)], body.as_bytes())
        .map_err(|e| format!("{e:?}"))?;
    Ok(Step::Registering { stream, status: 0, body: Vec::new(), followup: followup.is_some() })
}

fn map_request(
    conn: &mut ControlConn,
    node_key: &str,
    disco_public: &[u8; 32],
    hostinfo: &str,
    endpoints: &str,
) -> Result<Step, String> {
    let body = format!(
        r#"{{"Version":{CAPABILITY_VERSION},"Compress":"","KeepAlive":true,"Stream":true,"NodeKey":"{node_key}","DiscoKey":"discokey:{}","Hostinfo":{hostinfo},"Endpoints":{endpoints}}}"#,
        hex32(disco_public)
    );
    let stream = conn
        .request("POST", "/machine/map", &[("content-type", "application/json"), ("ts-lb", node_key)], body.as_bytes())
        .map_err(|e| format!("{e:?}"))?;
    Ok(Step::Polling { stream, status: 0, buf: Vec::new() })
}

/// JSON-encodes a string (with quotes).
fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

#[derive(serde::Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct RegisterResponse {
    machine_authorized: bool,
    node_key_expired: bool,
    #[serde(rename = "AuthURL")]
    auth_url: String,
    error: String,
}
