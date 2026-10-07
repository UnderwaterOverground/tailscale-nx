//! The parts of a MapResponse the engine uses, decoded straight from the
//! JSON. Strings are borrowed from the message and everything else (packet
//! filter, DNS config, user profiles, capabilities, ...) is skipped without
//! being materialized, which keeps both the code and the peak heap small
//! compared with decoding the full control protocol schema.
//!
//! Go encodes nil slices as `null`, so every list is an Option.

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};

use serde::Deserialize;
use ts_keys::{DiscoPublicKey, NodePublicKey};

use super::packet::Prefix;

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapResponse<'a> {
    #[serde(borrow, default)]
    pub node: Option<Node<'a>>,
    #[serde(rename = "DERPMap", borrow, default)]
    pub derp_map: Option<DerpMap<'a>>,
    #[serde(borrow, default)]
    pub peers: Option<Vec<Node<'a>>>,
    #[serde(borrow, default)]
    pub peers_changed: Option<Vec<Node<'a>>>,
    #[serde(default)]
    pub peers_removed: Option<Vec<i64>>,
    #[serde(borrow, default)]
    pub peers_changed_patch: Option<Vec<PeerChange<'a>>>,
    /// Access rules: None = unchanged, empty = deny everything.
    #[serde(default)]
    pub packet_filter: Option<Vec<super::filter::WireRule>>,
    /// Named, incremental access rules (newer servers).
    #[serde(default)]
    pub packet_filters: Option<BTreeMap<alloc::string::String, Option<Vec<super::filter::WireRule>>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Node<'a> {
    #[serde(rename = "ID", default)]
    pub id: i64,
    #[serde(borrow, default)]
    pub name: Cow<'a, str>,
    #[serde(borrow, default)]
    key: Option<&'a str>,
    #[serde(borrow, default)]
    disco_key: Option<&'a str>,
    #[serde(borrow, default)]
    addresses: Option<Vec<&'a str>>,
    #[serde(rename = "AllowedIPs", borrow, default)]
    allowed_ips: Option<Vec<&'a str>>,
    #[serde(borrow, default)]
    endpoints: Option<Vec<&'a str>>,
    #[serde(rename = "HomeDERP", default)]
    home_derp: Option<u32>,
    /// Pre-HomeDERP servers: "127.3.3.40:<region>".
    #[serde(rename = "DERP", borrow, default)]
    legacy_derp: Option<&'a str>,
    /// RFC 3339; Go's zero time (year 1) when the key never expires.
    #[serde(borrow, default)]
    key_expiry: Option<&'a str>,
}

impl Node<'_> {
    pub fn key(&self) -> Option<NodePublicKey> {
        self.key?.parse().ok()
    }

    pub fn disco_key(&self) -> Option<DiscoPublicKey> {
        self.disco_key?.parse().ok()
    }

    /// The node's own addresses (/32 and /128 prefixes).
    pub fn addresses(&self) -> Vec<Prefix> {
        parse_prefixes(self.addresses.as_deref())
    }

    /// Addresses plus any routes the node is allowed to source.
    pub fn allowed_prefixes(&self) -> Vec<Prefix> {
        let mut out = self.addresses();
        for p in parse_prefixes(self.allowed_ips.as_deref()) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
        out
    }

    pub fn endpoints(&self) -> Vec<SocketAddr> {
        parse_endpoints(self.endpoints.as_deref())
    }

    /// When the node's key expires (Unix seconds); None if it never does.
    pub fn key_expiry(&self) -> Option<u64> {
        parse_rfc3339(self.key_expiry?).filter(|&t| t > 0)
    }

    pub fn home_derp(&self) -> Option<u32> {
        match self.home_derp {
            Some(r) if r != 0 => Some(r),
            _ => self.legacy_derp.and_then(|d| d.strip_prefix("127.3.3.40:")).and_then(|r| r.parse().ok()).filter(|&r| r != 0),
        }
    }
}

/// Unix seconds of an RFC 3339 UTC timestamp as Go writes it
/// ("2026-04-05T10:11:12Z", optional fraction). None before 1970 (including
/// Go's zero time) or if malformed.
fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: core::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, sec) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !s.ends_with('Z') || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let t = days * 86400 + h * 3600 + mi * 60 + sec;
    u64::try_from(t).ok()
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PeerChange<'a> {
    #[serde(rename = "NodeID")]
    pub node_id: i64,
    #[serde(rename = "DERPRegion", default)]
    pub derp_region: Option<u32>,
    #[serde(borrow, default)]
    endpoints: Option<Vec<&'a str>>,
    #[serde(borrow, default)]
    disco_key: Option<&'a str>,
    #[serde(borrow, default)]
    key: Option<&'a str>,
}

impl PeerChange<'_> {
    /// None: unchanged.
    pub fn endpoints(&self) -> Option<Vec<SocketAddr>> {
        self.endpoints.as_ref().map(|e| parse_endpoints(Some(e)))
    }

    pub fn disco_key(&self) -> Option<DiscoPublicKey> {
        self.disco_key?.parse().ok()
    }

    pub fn key(&self) -> Option<NodePublicKey> {
        self.key?.parse().ok()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DerpMap<'a> {
    #[serde(borrow, default)]
    pub regions: BTreeMap<u32, DerpRegion<'a>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DerpRegion<'a> {
    #[serde(borrow, default)]
    pub nodes: Option<Vec<DerpNode<'a>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DerpNode<'a> {
    #[serde(rename = "HostName", borrow, default)]
    pub hostname: &'a str,
    /// "" (resolve the hostname), "none" (no IPv4), or a fixed address.
    #[serde(rename = "IPv4", borrow, default)]
    ipv4: &'a str,
    /// 0: the default (3478); negative: no STUN.
    #[serde(rename = "STUNPort", default)]
    stun_port: i32,
    #[serde(rename = "STUNOnly", default)]
    pub stun_only: bool,
    /// 0: 443.
    #[serde(rename = "DERPPort", default)]
    derp_port: u16,
}

impl DerpNode<'_> {
    pub fn fixed_ipv4(&self) -> Option<core::net::Ipv4Addr> {
        self.ipv4.parse().ok()
    }

    pub fn derp_port(&self) -> u16 {
        if self.derp_port == 0 { 443 } else { self.derp_port }
    }

    pub fn stun(&self) -> Option<SocketAddr> {
        let port = match self.stun_port {
            0 => 3478,
            p if p > 0 && p <= u16::MAX as i32 => p as u16,
            _ => return None,
        };
        Some(SocketAddr::new(IpAddr::V4(self.fixed_ipv4()?), port))
    }
}

pub fn parse(json: &[u8]) -> Result<MapResponse<'_>, serde_json::Error> {
    serde_json::from_slice(json)
}

fn parse_prefixes(list: Option<&[&str]>) -> Vec<Prefix> {
    list.unwrap_or_default().iter().filter_map(|s| parse_prefix(s)).collect()
}

pub fn parse_prefix(s: &str) -> Option<Prefix> {
    let (ip, len) = s.split_once('/')?;
    let addr: IpAddr = ip.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (len <= max).then_some(Prefix { addr, len })
}

fn parse_endpoints(list: Option<&[&str]>) -> Vec<SocketAddr> {
    list.unwrap_or_default().iter().filter_map(|s| s.parse().ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_timestamps() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-10-07T12:00:00Z"), Some(1_791_374_400));
        assert_eq!(parse_rfc3339("2024-02-29T23:59:59.123456789Z"), Some(1_709_251_199));
        assert_eq!(parse_rfc3339("0001-01-01T00:00:00Z"), None, "Go's zero time");
        assert_eq!(parse_rfc3339("2026-10-07 12:00:00"), None);
    }

    const MAP: &str = r#"{
        "KeepAlive": false,
        "Node": {"ID": 1, "Name": "me.ts.net.", "Key": "nodekey:0101010101010101010101010101010101010101010101010101010101010101",
                 "Addresses": ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"], "Hostinfo": {"OS": "switch", "Services": [{"Proto": "tcp", "Port": 22}]}},
        "DERPMap": {"Regions": {
            "1": {"RegionID": 1, "RegionCode": "nyc", "Nodes": [
                {"Name": "1a", "RegionID": 1, "HostName": "derp1a.example", "IPv4": "192.0.2.1", "STUNPort": 0},
                {"Name": "1b", "RegionID": 1, "HostName": "derp1b.example", "IPv4": "", "STUNOnly": true}]},
            "900": {"RegionID": 900, "Nodes": [{"HostName": "derp.local", "IPv4": "none", "STUNPort": -1, "DERPPort": 8443}]}
        }, "OmitDefaultRegions": false},
        "Peers": [
            {"ID": 7, "Name": "peer é.ts.net.", "Key": "nodekey:0202020202020202020202020202020202020202020202020202020202020202",
             "DiscoKey": "discokey:0303030303030303030303030303030303030303030303030303030303030303",
             "Addresses": ["100.64.0.7/32"], "AllowedIPs": ["100.64.0.7/32", "10.0.0.0/8"],
             "Endpoints": ["198.51.100.4:41641", "[2001:db8::1]:41641"], "HomeDERP": 1, "CapMap": {"x": [1, 2]}},
            {"ID": 8, "Key": "nodekey:0404040404040404040404040404040404040404040404040404040404040404",
             "Addresses": null, "AllowedIPs": null, "Endpoints": null, "DERP": "127.3.3.40:900"}
        ],
        "PeersRemoved": [3],
        "PeersChangedPatch": [{"NodeID": 7, "DERPRegion": 900, "Endpoints": ["203.0.113.9:1"]}],
        "PacketFilter": [{"SrcIPs": ["*"], "DstPorts": [{"IP": "*", "Ports": {"First": 0, "Last": 65535}}]}],
        "DNSConfig": {"Resolvers": [{"Addr": "1.1.1.1"}]},
        "UserProfiles": [{"ID": 1, "LoginName": "a@b"}]
    }"#;

    #[test]
    fn decodes_only_what_the_engine_uses() {
        let m = parse(MAP.as_bytes()).unwrap();
        let me = m.node.as_ref().unwrap();
        assert_eq!(me.addresses().len(), 2);

        let regions = &m.derp_map.as_ref().unwrap().regions;
        let r1 = regions[&1].nodes.as_ref().unwrap();
        assert_eq!(r1[0].hostname, "derp1a.example");
        assert_eq!(r1[0].stun(), Some("192.0.2.1:3478".parse().unwrap()));
        assert!(r1[1].stun_only);
        let r900 = &regions[&900].nodes.as_ref().unwrap()[0];
        assert_eq!(r900.fixed_ipv4(), None);
        assert_eq!(r900.stun(), None);
        assert_eq!(r900.derp_port(), 8443);

        let peers = m.peers.as_ref().unwrap();
        assert_eq!(peers[0].name, "peer é.ts.net.");
        assert!(peers[0].key().is_some() && peers[0].disco_key().is_some());
        assert_eq!(peers[0].allowed_prefixes(), [parse_prefix("100.64.0.7/32").unwrap(), parse_prefix("10.0.0.0/8").unwrap()]);
        assert_eq!(peers[0].endpoints().len(), 2);
        assert_eq!(peers[0].home_derp(), Some(1));
        assert_eq!(peers[1].home_derp(), Some(900));
        assert!(peers[1].allowed_prefixes().is_empty() && peers[1].endpoints().is_empty());

        assert_eq!(m.peers_removed.as_deref(), Some(&[3][..]));
        let patch = &m.peers_changed_patch.as_ref().unwrap()[0];
        assert_eq!((patch.node_id, patch.derp_region), (7, Some(900)));
        assert_eq!(patch.endpoints(), Some(alloc::vec!["203.0.113.9:1".parse().unwrap()]));
        assert!(patch.key().is_none());
    }

    #[test]
    fn prefixes_reject_garbage() {
        assert!(parse_prefix("100.64.0.1").is_none());
        assert!(parse_prefix("100.64.0.1/33").is_none());
        assert_eq!(parse_prefix("fd7a::/48").unwrap().len, 48);
    }
}
