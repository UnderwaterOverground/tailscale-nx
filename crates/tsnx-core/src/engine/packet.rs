//! Minimal IP header inspection for routing decisions on tunnel packets.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn src(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[12..16]).ok()?))),
        6 if pkt.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?))),
        _ => None,
    }
}

pub fn dst(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[16..20]).ok()?))),
        6 if pkt.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?))),
        _ => None,
    }
}

/// Total length per the IP header (WireGuard pads plaintext to 16 bytes).
pub fn ip_len(pkt: &[u8]) -> Option<usize> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(u16::from_be_bytes([pkt[2], pkt[3]]) as usize),
        6 if pkt.len() >= 40 => Some(40 + u16::from_be_bytes([pkt[4], pkt[5]]) as usize),
        _ => None,
    }
}

/// Pads a plaintext packet to a multiple of 16 bytes, as WireGuard does.
pub fn pad(pkt: &mut alloc::vec::Vec<u8>, mtu: usize) {
    let padded = pkt.len().next_multiple_of(16).min(mtu.max(pkt.len()));
    pkt.resize(padded, 0);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.len == 0 { 0 } else { u32::MAX << (32 - self.len.min(32)) };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.len == 0 { 0 } else { u128::MAX << (128 - self.len.min(128)) };
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}
