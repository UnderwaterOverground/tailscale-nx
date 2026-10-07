//! Minimal STUN (RFC 5389) binding requests, to learn our public UDP address
//! from DERP regions' STUN servers.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const HEADER_LEN: usize = 20;
/// Tailscale's STUN servers only answer requests carrying this SOFTWARE
/// attribute and a FINGERPRINT (tailscale/net/stun).
const SOFTWARE: &[u8; 8] = b"tailnode";
const REQUEST_LEN: usize = HEADER_LEN + 4 + SOFTWARE.len() + 8;

pub type TxId = [u8; 12];

pub fn request(tx_id: &TxId) -> [u8; REQUEST_LEN] {
    let mut m = [0u8; REQUEST_LEN];
    m[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    m[2..4].copy_from_slice(&((REQUEST_LEN - HEADER_LEN) as u16).to_be_bytes());
    m[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    m[8..20].copy_from_slice(tx_id);
    m[20..22].copy_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    m[22..24].copy_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    m[24..32].copy_from_slice(SOFTWARE);
    // FINGERPRINT covers everything before it (RFC 5389 15.5).
    let fp = crc32(&m[..32]) ^ 0x5354_554e;
    m[32..34].copy_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    m[34..36].copy_from_slice(&4u16.to_be_bytes());
    m[36..40].copy_from_slice(&fp.to_be_bytes());
    m
}

/// CRC-32 (IEEE 802.3), bitwise; only used on 32-byte STUN requests.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// True if `pkt` looks like a STUN message (so it is not WireGuard/disco).
pub fn is_stun(pkt: &[u8]) -> bool {
    pkt.len() >= HEADER_LEN && pkt[0] & 0xc0 == 0 && pkt[4..8] == MAGIC_COOKIE.to_be_bytes()
}

/// Parses a binding success response: (transaction id, mapped address).
pub fn parse_response(pkt: &[u8]) -> Option<(TxId, SocketAddr)> {
    if !is_stun(pkt) || u16::from_be_bytes([pkt[0], pkt[1]]) != BINDING_SUCCESS {
        return None;
    }
    let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let tx_id: TxId = pkt[8..20].try_into().ok()?;
    let mut attrs = pkt.get(HEADER_LEN..HEADER_LEN + len)?;
    let mut mapped = None;
    while attrs.len() >= 4 {
        let ty = u16::from_be_bytes([attrs[0], attrs[1]]);
        let alen = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        let value = attrs.get(4..4 + alen)?;
        match ty {
            ATTR_XOR_MAPPED_ADDRESS => return Some((tx_id, parse_addr(value, Some(&tx_id))?)),
            ATTR_MAPPED_ADDRESS => mapped = parse_addr(value, None),
            _ => {}
        }
        // Attributes are padded to 4 bytes.
        attrs = attrs.get(4 + alen.next_multiple_of(4)..).unwrap_or(&[]);
    }
    Some((tx_id, mapped?))
}

fn parse_addr(v: &[u8], xor_tx: Option<&TxId>) -> Option<SocketAddr> {
    let family = *v.get(1)?;
    let mut port = u16::from_be_bytes([*v.get(2)?, *v.get(3)?]);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    if xor_tx.is_some() {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    let ip = match family {
        0x01 => {
            let mut b: [u8; 4] = v.get(4..8)?.try_into().ok()?;
            if xor_tx.is_some() {
                for (x, c) in b.iter_mut().zip(cookie) {
                    *x ^= c;
                }
            }
            IpAddr::V4(Ipv4Addr::from(b))
        }
        0x02 => {
            let mut b: [u8; 16] = v.get(4..20)?.try_into().ok()?;
            if let Some(tx) = xor_tx {
                let key: alloc::vec::Vec<u8> = cookie.iter().chain(tx.iter()).copied().collect();
                for (x, k) in b.iter_mut().zip(key) {
                    *x ^= k;
                }
            }
            // Servers may report IPv4 clients as IPv4-mapped IPv6.
            let v6 = Ipv6Addr::from(b);
            v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5769 2.2: sample IPv4 response.
    #[test]
    fn rfc5769_ipv4_response() {
        let pkt: [u8; 80] = [
            0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87,
            0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91,
            0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
            0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
        ];
        let (tx, addr) = parse_response(&pkt).unwrap();
        assert_eq!(tx, pkt[8..20]);
        assert_eq!(addr, "192.0.2.1:32853".parse().unwrap());
    }

    #[test]
    fn request_matches_tailscale_format() {
        let r = request(&[1; 12]);
        assert!(is_stun(&r));
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(&r[2..4], &[0, 20]);
        assert_eq!(&r[24..32], b"tailnode");
        let fp = crc32(&r[..32]) ^ 0x5354_554e;
        assert_eq!(&r[36..40], &fp.to_be_bytes());
    }
}
