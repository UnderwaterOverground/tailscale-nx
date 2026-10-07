//! Inbound packet filter: the tailnet's access rules (ACLs) as the control
//! server sends them (`PacketFilter` / `PacketFilters` in a MapResponse).
//! As in Tailscale, the receiving node enforces them, so without this any
//! peer could reach anything listening on the Switch.
//!
//! Semantics follow Go's `wgengine/filter`:
//! - Until the first filter arrives, nothing new may come in.
//! - TCP: only connection openers (SYN without ACK) are checked; the rest
//!   belongs to existing connections (the stack drops strays).
//! - UDP: replies to flows we started are let through; anything else must
//!   match a rule.
//! - ICMP: echo requests must match a rule; replies and errors pass.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;
use core::time::Duration;

use serde::Deserialize;

use crate::time::Instant;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;
/// IPProto when a rule doesn't list any.
const DEFAULT_PROTOS: [u8; 4] = [PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_ICMPV6];
/// How long a UDP flow we started accepts replies after its last packet.
const UDP_FLOW_TTL: Duration = Duration::from_secs(120);
/// Bound on tracked UDP flows (oldest dropped first).
const MAX_UDP_FLOWS: usize = 256;

/// A rule as the control server encodes it (Go `tailcfg.FilterRule`).
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct WireRule {
    #[serde(rename = "SrcIPs", default)]
    src_ips: Option<Vec<String>>,
    #[serde(default)]
    dst_ports: Option<Vec<WirePorts>>,
    #[serde(rename = "IPProto", default)]
    ip_proto: Option<Vec<i32>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct WirePorts {
    #[serde(rename = "IP", default)]
    ip: String,
    /// Deprecated prefix length for `IP`.
    #[serde(default)]
    bits: Option<u8>,
    #[serde(default)]
    ports: WireRange,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
struct WireRange {
    #[serde(default)]
    first: u16,
    #[serde(default)]
    last: u16,
}

impl Default for WireRange {
    fn default() -> Self {
        Self { first: 0, last: u16::MAX }
    }
}

/// An inclusive address range of one family; `*` is both families' full range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRange {
    first: IpAddr,
    last: IpAddr,
}

impl IpRange {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.first, self.last, ip) {
            (IpAddr::V4(a), IpAddr::V4(b), IpAddr::V4(x)) => (u32::from(a)..=u32::from(b)).contains(&u32::from(x)),
            (IpAddr::V6(a), IpAddr::V6(b), IpAddr::V6(x)) => (u128::from(a)..=u128::from(b)).contains(&u128::from(x)),
            _ => false,
        }
    }

    fn any() -> [IpRange; 2] {
        [
            IpRange { first: IpAddr::V4(0.into()), last: IpAddr::V4(u32::MAX.into()) },
            IpRange { first: IpAddr::V6(0.into()), last: IpAddr::V6(u128::MAX.into()) },
        ]
    }

    fn prefix(addr: IpAddr, len: u8) -> Option<IpRange> {
        Some(match addr {
            IpAddr::V4(a) => {
                let len = u32::from(len.min(32));
                let host = if len == 0 { u32::MAX } else { u32::MAX.checked_shr(len).unwrap_or(0) };
                let base = u32::from(a) & !host;
                IpRange { first: IpAddr::V4(base.into()), last: IpAddr::V4((base | host).into()) }
            }
            IpAddr::V6(a) => {
                let len = u32::from(len.min(128));
                let host = if len == 0 { u128::MAX } else { u128::MAX.checked_shr(len).unwrap_or(0) };
                let base = u128::from(a) & !host;
                IpRange { first: IpAddr::V6(base.into()), last: IpAddr::V6((base | host).into()) }
            }
        })
    }

    /// `*`, `ip`, `ip/len` or `ip-ip`. Anything else (e.g. capability
    /// names) matches nothing.
    fn parse(s: &str, bits: Option<u8>) -> Vec<IpRange> {
        if s == "*" {
            return IpRange::any().to_vec();
        }
        let one = if let Some((a, b)) = s.split_once('-') {
            match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
                (Ok(a), Ok(b)) if a.is_ipv4() == b.is_ipv4() => Some(IpRange { first: a, last: b }),
                _ => None,
            }
        } else if let Some((a, len)) = s.split_once('/') {
            match (a.parse::<IpAddr>(), len.parse::<u8>()) {
                (Ok(a), Ok(len)) => IpRange::prefix(a, len),
                _ => None,
            }
        } else {
            match s.parse::<IpAddr>() {
                Ok(a) => IpRange::prefix(a, bits.unwrap_or(if a.is_ipv4() { 32 } else { 128 })),
                Err(_) => None,
            }
        };
        one.into_iter().collect()
    }
}

#[derive(Debug, Clone)]
struct Rule {
    src: Vec<IpRange>,
    dst: Vec<(IpRange, u16, u16)>,
    protos: Vec<u8>,
}

impl Rule {
    fn from_wire(w: &WireRule) -> Rule {
        let src = w.src_ips.iter().flatten().flat_map(|s| IpRange::parse(s, None)).collect();
        let dst = w
            .dst_ports
            .iter()
            .flatten()
            .flat_map(|d| IpRange::parse(&d.ip, d.bits).into_iter().map(move |r| (r, d.ports.first, d.ports.last)))
            .collect();
        let protos = match w.ip_proto.as_deref() {
            None | Some([]) => DEFAULT_PROTOS.to_vec(),
            Some(p) => p.iter().filter_map(|&n| u8::try_from(n).ok()).collect(),
        };
        Rule { src, dst, protos }
    }

    fn allows(&self, proto: u8, src: IpAddr, dst: IpAddr, dst_port: Option<u16>) -> bool {
        self.protos.contains(&proto)
            && self.src.iter().any(|r| r.contains(src))
            && self.dst.iter().any(|&(r, first, last)| {
                // ICMP has no ports: an address match is enough.
                r.contains(dst) && dst_port.is_none_or(|p| (first..=last).contains(&p))
            })
    }
}

/// Fields of an IP packet the filter looks at.
#[derive(Debug, PartialEq, Eq)]
struct Summary {
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    /// TCP SYN without ACK.
    tcp_open: bool,
    /// ICMP / ICMPv6 echo request.
    echo_request: bool,
}

fn summarize(pkt: &[u8]) -> Option<Summary> {
    let (proto, src, dst, l4) = match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            // Fragments other than the first carry no ports: treat as opaque.
            let frag_offset = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
            let l4 = if frag_offset == 0 { pkt.get(ihl..)? } else { &[][..] };
            (pkt[9], super::packet::src(pkt)?, super::packet::dst(pkt)?, l4)
        }
        6 if pkt.len() >= 40 => (pkt[6], super::packet::src(pkt)?, super::packet::dst(pkt)?, &pkt[40..]),
        _ => return None,
    };
    let port = |i: usize| l4.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0);
    let (src_port, dst_port) = match proto {
        PROTO_TCP | PROTO_UDP => (port(0), port(2)),
        _ => (0, 0),
    };
    let tcp_open = proto == PROTO_TCP && l4.get(13).is_some_and(|f| f & 0x02 != 0 && f & 0x10 == 0);
    let echo_request = match proto {
        PROTO_ICMP => l4.first() == Some(&8),
        PROTO_ICMPV6 => l4.first() == Some(&128),
        _ => false,
    };
    Some(Summary { proto, src, dst, src_port, dst_port, tcp_open, echo_request })
}

#[derive(Default)]
pub struct Filter {
    /// Named rule sets (`PacketFilters`; a plain `PacketFilter` is "base").
    /// None until the first filter arrives: then nothing new comes in.
    sets: Option<BTreeMap<String, Vec<Rule>>>,
    /// UDP flows we started: (remote ip, remote port, local port) -> last use.
    udp_flows: BTreeMap<(IpAddr, u16, u16), Instant>,
}

impl Filter {
    /// Applies a MapResponse's filter fields. `single`: `PacketFilter`
    /// (None = unchanged; empty = deny everything). `named`: `PacketFilters`
    /// (a None value deletes that set; key `*` with None clears all first).
    pub fn update(&mut self, single: Option<&[WireRule]>, named: Option<&BTreeMap<String, Option<Vec<WireRule>>>>) {
        if single.is_none() && named.is_none() {
            return;
        }
        let sets = self.sets.get_or_insert_with(BTreeMap::new);
        if let Some(rules) = single {
            sets.insert("base".into(), rules.iter().map(Rule::from_wire).collect());
        }
        if let Some(named) = named {
            if matches!(named.get("*"), Some(None)) {
                sets.clear();
            }
            for (name, rules) in named {
                match rules {
                    Some(rules) => {
                        sets.insert(name.clone(), rules.iter().map(Rule::from_wire).collect());
                    }
                    None => {
                        sets.remove(name);
                    }
                }
            }
        }
    }

    /// Notes an outgoing packet so replies to it are let in.
    pub fn note_outbound(&mut self, pkt: &[u8], now: Instant) {
        let Some(s) = summarize(pkt) else { return };
        if s.proto != PROTO_UDP {
            return;
        }
        if self.udp_flows.len() >= MAX_UDP_FLOWS && !self.udp_flows.contains_key(&(s.dst, s.dst_port, s.src_port)) {
            let oldest = self.udp_flows.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.udp_flows.remove(&k);
            }
        }
        self.udp_flows.insert((s.dst, s.dst_port, s.src_port), now);
    }

    /// Whether an incoming packet (already checked to come from its peer's
    /// own addresses) may be delivered.
    pub fn allows_inbound(&mut self, pkt: &[u8], now: Instant) -> bool {
        let Some(s) = summarize(pkt) else { return false };
        match s.proto {
            PROTO_TCP if !s.tcp_open => return true,
            PROTO_UDP => {
                if let Some(t) = self.udp_flows.get_mut(&(s.src, s.src_port, s.dst_port)) {
                    if now.saturating_duration_since(*t) < UDP_FLOW_TTL {
                        *t = now;
                        return true;
                    }
                }
            }
            PROTO_ICMP | PROTO_ICMPV6 if !s.echo_request => return true,
            _ => {}
        }
        let Some(sets) = &self.sets else { return false };
        let dst_port = matches!(s.proto, PROTO_TCP | PROTO_UDP).then_some(s.dst_port);
        sets.values().flatten().any(|r| r.allows(s.proto, s.src, s.dst, dst_port))
    }

    /// Drops UDP flows that can no longer receive replies.
    pub fn expire(&mut self, now: Instant) {
        self.udp_flows.retain(|_, t| now.saturating_duration_since(*t) < UDP_FLOW_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn rules(json: &str) -> Vec<WireRule> {
        serde_json::from_str(json).unwrap()
    }

    /// Minimal IPv4 + TCP/UDP/ICMP packet.
    fn v4(proto: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, icmp_type: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        match proto {
            PROTO_TCP | PROTO_UDP => {
                p[20..22].copy_from_slice(&sport.to_be_bytes());
                p[22..24].copy_from_slice(&dport.to_be_bytes());
                p[33] = flags;
            }
            _ => p[20] = icmp_type,
        }
        p
    }

    const ME: [u8; 4] = [100, 64, 0, 5];
    const PEER: [u8; 4] = [100, 64, 0, 1];
    const OTHER: [u8; 4] = [100, 64, 0, 9];
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;

    #[test]
    fn nothing_new_before_the_first_filter() {
        let mut f = Filter::default();
        let t = Instant::from_millis(0);
        assert!(!f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 5000, 22, SYN, 0), t));
        assert!(f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 5000, 22, ACK, 0), t), "existing TCP traffic");
    }

    #[test]
    fn rules_select_sources_ports_and_protocols() {
        let mut f = Filter::default();
        let t = Instant::from_millis(0);
        let r = rules(
            r#"[{"SrcIPs":["100.64.0.1"],"DstPorts":[{"IP":"*","Ports":{"First":5000,"Last":5001}}]},
                {"SrcIPs":["100.64.0.0/24"],"DstPorts":[{"IP":"100.64.0.5","Ports":{"First":0,"Last":65535}}],"IPProto":[1]}]"#,
        );
        f.update(Some(&r), None);
        assert!(f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 40000, 5000, SYN, 0), t));
        assert!(!f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 40000, 22, SYN, 0), t), "port not allowed");
        assert!(!f.allows_inbound(&v4(PROTO_TCP, OTHER, ME, 40000, 5000, SYN, 0), t), "source not allowed");
        assert!(f.allows_inbound(&v4(PROTO_UDP, PEER, ME, 40000, 5001, 0, 0), t));
        assert!(f.allows_inbound(&v4(PROTO_ICMP, OTHER, ME, 0, 0, 0, 8), t), "ping allowed by the ICMP rule");
        assert!(f.allows_inbound(&v4(PROTO_ICMP, [100, 64, 9, 9], ME, 0, 0, 0, 0), t), "echo replies pass");
        assert!(!f.allows_inbound(&v4(PROTO_ICMP, [100, 64, 9, 9], ME, 0, 0, 0, 8), t), "ping from outside the rule");
    }

    #[test]
    fn udp_replies_to_our_flows() {
        let mut f = Filter::default();
        let t = Instant::from_millis(0);
        f.update(Some(&[]), None); // deny everything
        assert!(!f.allows_inbound(&v4(PROTO_UDP, PEER, ME, 47998, 6000, 0, 0), t));
        f.note_outbound(&v4(PROTO_UDP, ME, PEER, 6000, 47998, 0, 0), t);
        assert!(f.allows_inbound(&v4(PROTO_UDP, PEER, ME, 47998, 6000, 0, 0), t), "reply to our flow");
        assert!(!f.allows_inbound(&v4(PROTO_UDP, PEER, ME, 47999, 6000, 0, 0), t), "other remote port");
        let later = Instant::from_millis(200_000);
        assert!(!f.allows_inbound(&v4(PROTO_UDP, PEER, ME, 47998, 6000, 0, 0), later), "flow expired");
    }

    #[test]
    fn named_filter_sets() {
        let mut f = Filter::default();
        let t = Instant::from_millis(0);
        let allow_22 = rules(r#"[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":22,"Last":22}}]}]"#);
        let allow_80 = rules(r#"[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":80,"Last":80}}]}]"#);
        let mut named = BTreeMap::new();
        named.insert(String::from("a"), Some(allow_22));
        named.insert(String::from("b"), Some(allow_80));
        f.update(None, Some(&named));
        assert!(f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 1, 22, SYN, 0), t));
        assert!(f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 1, 80, SYN, 0), t));
        let mut delete_a = BTreeMap::new();
        delete_a.insert(String::from("a"), None);
        f.update(None, Some(&delete_a));
        assert!(!f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 1, 22, SYN, 0), t));
        assert!(f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 1, 80, SYN, 0), t));
        let mut clear = BTreeMap::new();
        clear.insert(String::from("*"), None);
        f.update(None, Some(&clear));
        assert!(!f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 1, 80, SYN, 0), t), "cleared");
        f.update(None, None);
        assert!(!f.allows_inbound(&v4(PROTO_TCP, PEER, ME, 1, 80, SYN, 0), t), "absent fields change nothing");
    }

    #[test]
    fn address_forms() {
        assert_eq!(IpRange::parse("*", None).len(), 2);
        let r = IpRange::parse("100.64.0.10-100.64.0.20", None)[0];
        assert!(r.contains("100.64.0.15".parse().unwrap()) && !r.contains("100.64.0.21".parse().unwrap()));
        let p = IpRange::parse("fd7a:115c:a1e0::/48", None)[0];
        assert!(p.contains("fd7a:115c:a1e0::5".parse().unwrap()) && !p.contains("100.64.0.1".parse().unwrap()));
        assert!(IpRange::parse("100.64.0.1", Some(24))[0].contains("100.64.0.200".parse().unwrap()), "legacy Bits");
        assert!(IpRange::parse("autogroup:self", None).is_empty());
    }
}
