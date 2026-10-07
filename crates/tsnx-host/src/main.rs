//! Host driver for tsnx-core. For now: diagnostics subcommands used while
//! bringing up each protocol layer against real servers.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use tsnx_core::control::{self, conn::ControlConn};
use tsnx_core::http2::Event;
use tsnx_core::tls::{self, TlsClient};

/// Counts heap usage so the Switch builds' heap budget can be sized from
/// real runs (printed at exit).
mod heap {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};
    pub static CUR: AtomicUsize = AtomicUsize::new(0);
    pub static PEAK: AtomicUsize = AtomicUsize::new(0);
    pub struct Counting;
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let p = System.alloc(l);
            if !p.is_null() {
                let n = CUR.fetch_add(l.size(), Ordering::Relaxed) + l.size();
                PEAK.fetch_max(n, Ordering::Relaxed);
            }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            CUR.fetch_sub(l.size(), Ordering::Relaxed);
            System.dealloc(p, l)
        }
    }
}
#[global_allocator]
static ALLOC: heap::Counting = heap::Counting;

mod driver;
mod echo;
mod net;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    tsnx_core::rng::seed_from_os();
    tls::CLOCK.set(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("selftest") | None => selftest(),
        Some("tls-probe") => tls_probe(
            args.get(1).map(String::as_str).unwrap_or("derp1.tailscale.com"),
            args.get(2).map(String::as_str).unwrap_or("/derp/probe"),
        ),
        Some("control-probe") => control_probe(
            args.get(1).map(String::as_str).unwrap_or("https://controlplane.tailscale.com"),
            args.get(2).map(String::as_str),
        ),
        Some("up") => up(&args[1..]),
        Some(other) => Err(format!(
            "unknown command {other:?}; try selftest | tls-probe [host[:port]] [path] | control-probe <url> [authkey] | up --control URL [--authkey K] [--hostname H] [--state FILE] [--port N] [--echo-test IP [--expect-direct]]"
        )),
    };
    log::info!(
        "heap: {} KB in use, peak {} KB",
        heap::CUR.load(std::sync::atomic::Ordering::Relaxed) / 1024,
        heap::PEAK.load(std::sync::atomic::Ordering::Relaxed) / 1024
    );
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn selftest() -> Result<(), String> {
    tsnx_core::selftest::run().map_err(|f| format!("selftest failed: {f:?}"))?;
    println!("tsnx-host {}: selftest ok", tsnx_core::VERSION);
    Ok(())
}

/// HTTPS GET over the sans-IO TLS client, pumping a blocking TcpStream.
fn tls_probe(target: &str, path: &str) -> Result<(), String> {
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|e| e.to_string())?),
        None => (target, 443),
    };
    // TSNX_EXTRA_ROOT: path to a DER certificate to trust (dev DERP servers).
    let extra: Vec<Vec<u8>> = match std::env::var("TSNX_EXTRA_ROOT") {
        Ok(path) => vec![std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?],
        Err(_) => vec![],
    };
    let config = tls::client_config(&extra).map_err(|e| e.to_string())?;
    let mut tls = TlsClient::new(config, host).map_err(|e| format!("{e:?}"))?;
    let mut sock = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
    tls.write(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| format!("{e:?}"))?;

    let mut response = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        let out = tls.take_outgoing();
        if !out.is_empty() {
            sock.write_all(&out).map_err(|e| e.to_string())?;
        }
        let n = sock.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        tls.feed(&buf[..n]).map_err(|e| format!("{e:?}"))?;
        response.extend(tls.take_plaintext());
        if tls.peer_closed() {
            break;
        }
    }
    println!("established={} received {} bytes", tls.is_established(), response.len());
    let text = String::from_utf8_lossy(&response);
    println!("{}", text.lines().take(12).collect::<Vec<_>>().join("\n"));
    if !tls.is_established() {
        return Err("handshake did not complete".into());
    }
    Ok(())
}

/// Fetches the control key, opens a ts2021 channel and sends one register
/// request with throwaway keys, printing the server's answer.
fn control_probe(url: &str, auth_key: Option<&str>) -> Result<(), String> {
    let target = net::Target::parse(url)?;
    let mut s = net::Stream::connect(&target)?;
    s.write(&control::key_request(&target.host))?;
    let resp = s.read_to_end()?;
    let control_key = control::parse_key_response(&resp).map_err(|e| format!("/key: {e:?}"))?;
    println!("control key: mkey:{}", control::hex32(&control_key));

    let machine = tsnx_core::rng::bytes32().unwrap();
    let node = tsnx_core::rng::bytes32().unwrap();
    let ephemeral = tsnx_core::rng::bytes32().unwrap();
    let mut conn = ControlConn::new(&target.host, &machine, &control_key, &ephemeral, control::CAPABILITY_VERSION)
        .map_err(|e| format!("{e:?}"))?;
    let mut s = net::Stream::connect(&target)?;
    s.write(&conn.take_outgoing())?;
    while !conn.is_ready() {
        let data = s.read()?;
        if data.is_empty() {
            return Err("EOF during ts2021 setup".into());
        }
        conn.feed(&data).map_err(|e| format!("{e:?}"))?;
        s.write(&conn.take_outgoing())?;
    }
    println!("ts2021 up; early payload: {}", conn.early_payload().map(String::from_utf8_lossy).unwrap_or_default());

    let node_pub = tsnx_core::crypto::x25519_public(&node);
    let auth = auth_key.map(|k| format!(r#","Auth":{{"AuthKey":"{k}"}}"#)).unwrap_or_default();
    let body = format!(
        r#"{{"Version":{},"NodeKey":"nodekey:{}","Hostinfo":{{"Hostname":"tsnx-probe","OS":"linux","GoArch":"arm64"}}{auth}}}"#,
        control::CAPABILITY_VERSION,
        control::hex32(&node_pub)
    );
    let stream = conn
        .request("POST", "/machine/register", &[("content-type", "application/json")], body.as_bytes())
        .map_err(|e| format!("{e:?}"))?;
    s.write(&conn.take_outgoing())?;
    let mut response = Vec::new();
    loop {
        while let Some(ev) = conn.poll_event() {
            match ev {
                Event::Response { stream: id, status, .. } if id == stream => println!("register: HTTP {status}"),
                Event::Data { stream: id, data } if id == stream => response.extend(data),
                Event::End { stream: id } if id == stream => {
                    println!("{}", String::from_utf8_lossy(&response));
                    return Ok(());
                }
                Event::Reset { code, .. } => return Err(format!("stream reset: {code}")),
                Event::GoAway { code, .. } => return Err(format!("goaway: {code}")),
                _ => {}
            }
        }
        let data = s.read()?;
        if data.is_empty() {
            return Err("EOF awaiting register response".into());
        }
        conn.feed(&data).map_err(|e| format!("{e:?}"))?;
        s.write(&conn.take_outgoing())?;
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

/// Loads machine/node private keys from `path`, creating them on first run.
fn load_or_create_keys(path: &str) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    let existing = std::fs::read_to_string(path).ok();
    let field = |name: &str| -> Option<[u8; 32]> {
        existing
            .as_deref()?
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .and_then(control::parse_hex32)
    };
    let machine = field("machine").unwrap_or_else(|| tsnx_core::rng::bytes32().unwrap());
    let node = field("node").unwrap_or_else(|| tsnx_core::rng::bytes32().unwrap());
    // Persisted (see EngineConfig::disco_private).
    let disco = field("disco").unwrap_or_else(|| tsnx_core::rng::bytes32().unwrap());
    if field("disco").is_none() {
        std::fs::write(
            path,
            format!(
                "machine={}\nnode={}\ndisco={}\n",
                control::hex32(&machine),
                control::hex32(&node),
                control::hex32(&disco)
            ),
        )
        .map_err(|e| format!("{path}: {e}"))?;
    }
    Ok((machine, node, disco))
}

/// Replaces the node key in the state file (control rotated an expired one).
fn save_node_key(path: &str, node: &[u8; 32]) -> Result<(), String> {
    let old = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let new: String = old
        .lines()
        .map(|l| if l.starts_with("node=") { format!("node={}\n", control::hex32(node)) } else { format!("{l}\n") })
        .collect();
    std::fs::write(path, new).map_err(|e| format!("{path}: {e}"))
}

fn up(args: &[String]) -> Result<(), String> {
    let url = flag(args, "--control").ok_or("--control URL is required")?;
    let state = flag(args, "--state").unwrap_or("tsnx-host.state");
    let (machine_private, node_private, disco_private) = load_or_create_keys(state)?;
    let extra_roots = match std::env::var("TSNX_EXTRA_ROOT") {
        Ok(p) => vec![std::fs::read(&p).map_err(|e| format!("{p}: {e}"))?],
        Err(_) => vec![],
    };
    let cfg = tsnx_core::engine::EngineConfig {
        control: control::client::ControlConfig {
            url: url.into(),
            auth_key: flag(args, "--authkey").map(Into::into),
            hostname: flag(args, "--hostname").unwrap_or("tsnx-host").into(),
            extra_roots,
        },
        machine_private,
        node_private,
        disco_private,
    };
    let bulk = flag(args, "--bulk").map(|n| n.parse().expect("--bulk bytes")).unwrap_or(0);
    let mut echo = flag(args, "--echo-test").map(|ip| echo::EchoTest::new(ip.parse().expect("--echo-test IP"), bulk));
    let ready = std::cell::Cell::new(false);
    let key_changed = std::cell::Cell::new(false);
    let direct = std::cell::Cell::new(false);
    let expect_direct = args.iter().any(|a| a == "--expect-direct");
    let deadline = std::cell::Cell::new(None::<std::time::Instant>);
    let udp_port = flag(args, "--port").map(|p| p.parse().expect("--port")).unwrap_or(0);
    let result = driver::run_engine(
        cfg,
        udp_port,
        |ev| {
            if matches!(ev, tsnx_core::engine::Event::NodeKeyChanged) {
                key_changed.set(true);
            }
            if matches!(ev, tsnx_core::engine::Event::Peers(n) if *n > 0) {
                ready.set(true);
            }
            if matches!(ev, tsnx_core::engine::Event::PeerPath { direct: Some(_), .. }) {
                direct.set(true);
            }
            log::info!("{ev:?}");
        },
        |engine, clock| {
            if key_changed.take() {
                if let Err(e) = save_node_key(state, &engine.node_private_key()) {
                    log::error!("{e}");
                }
            }
            match echo.as_mut() {
            Some(t) if ready.get() => {
                if t.step(engine, clock) {
                    return true;
                }
                // Echo finished; optionally wait (up to 20s) for a direct path.
                if !expect_direct || direct.get() {
                    return false;
                }
                let d = *deadline.get().get_or_insert(std::time::Instant::now() + std::time::Duration::from_secs(20));
                deadline.set(Some(d));
                std::time::Instant::now() < d
            }
            _ => true,
            }
        },
    );
    if expect_direct && !direct.get() {
        return Err("no direct path established".into());
    }
    if let Some(t) = echo {
        return t.result();
    }
    result
}
