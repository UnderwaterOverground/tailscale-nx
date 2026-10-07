//! Disco: Tailscale's peer discovery messages (tailscale/disco), used to find
//! and confirm direct UDP paths. Wire format:
//! `"TS💬" | sender disco key (32) | nonce (24) | NaCl box([type, version=0, body])`.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv6Addr, SocketAddr};

use ts_keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use zerocopy::IntoBytes;

pub const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const ENDPOINT_LEN: usize = 18;

const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;
const TYPE_CALL_ME_MAYBE: u8 = 0x03;

pub type TxId = [u8; 12];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping { tx_id: TxId, node_key: Option<NodePublicKey> },
    /// `src` is how the pinged node saw our address.
    Pong { tx_id: TxId, src: SocketAddr },
    CallMeMaybe { endpoints: Vec<SocketAddr> },
}

pub fn is_disco(pkt: &[u8]) -> bool {
    pkt.len() >= MAGIC.len() + KEY_LEN + NONCE_LEN && pkt.starts_with(MAGIC)
}

/// The sender's disco key, readable without decrypting.
pub fn sender(pkt: &[u8]) -> Option<DiscoPublicKey> {
    if !is_disco(pkt) {
        return None;
    }
    Some(DiscoPublicKey::from_bytes(pkt[6..38].try_into().ok()?))
}

fn put_endpoint(out: &mut Vec<u8>, ep: SocketAddr) {
    let ip16 = match ep.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend_from_slice(&ip16.octets());
    out.extend_from_slice(&ep.port().to_be_bytes());
}

fn get_endpoint(b: &[u8]) -> SocketAddr {
    let ip6 = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap());
    let ip = match ip6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(ip6),
    };
    SocketAddr::new(ip, u16::from_be_bytes([b[16], b[17]]))
}

impl Message {
    fn encode_plain(&self, our_node: &NodePublicKey) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Message::Ping { tx_id, .. } => {
                b.extend_from_slice(&[TYPE_PING, 0]);
                b.extend_from_slice(tx_id);
                b.extend_from_slice(our_node.as_bytes());
            }
            Message::Pong { tx_id, src } => {
                b.extend_from_slice(&[TYPE_PONG, 0]);
                b.extend_from_slice(tx_id);
                put_endpoint(&mut b, *src);
            }
            Message::CallMeMaybe { endpoints } => {
                b.extend_from_slice(&[TYPE_CALL_ME_MAYBE, 0]);
                for ep in endpoints {
                    put_endpoint(&mut b, *ep);
                }
            }
        }
        b
    }

    fn decode_plain(b: &[u8]) -> Option<Message> {
        let (&ty, rest) = b.split_first()?;
        let (_version, body) = rest.split_first()?;
        match ty {
            TYPE_PING if body.len() >= 12 => {
                let tx_id = body[..12].try_into().ok()?;
                let node_key = body.get(12..44).map(|k| NodePublicKey::from_bytes(k.try_into().unwrap()));
                Some(Message::Ping { tx_id, node_key })
            }
            TYPE_PONG if body.len() >= 12 + ENDPOINT_LEN => {
                Some(Message::Pong { tx_id: body[..12].try_into().ok()?, src: get_endpoint(&body[12..30]) })
            }
            TYPE_CALL_ME_MAYBE if body.len() % ENDPOINT_LEN == 0 => {
                Some(Message::CallMeMaybe { endpoints: body.chunks_exact(ENDPOINT_LEN).map(get_endpoint).collect() })
            }
            _ => None,
        }
    }
}

/// Seals a disco message from `ours` to `theirs`.
pub fn seal(
    ours: &DiscoPrivateKey,
    theirs: &DiscoPublicKey,
    our_node: &NodePublicKey,
    msg: &Message,
) -> Option<Vec<u8>> {
    use crypto_box::aead::Aead;
    let plain = msg.encode_plain(our_node);
    let mut nonce = [0u8; NONCE_LEN];
    crate::rng::fill(&mut nonce).ok()?;
    let sealed = crypto_box::SalsaBox::new(&theirs.to_crypto_box(), &ours.to_crypto_box())
        .encrypt((&nonce).into(), plain.as_slice())
        .ok()?;
    let mut out = Vec::with_capacity(MAGIC.len() + KEY_LEN + NONCE_LEN + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(ours.public_key().as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Some(out)
}

/// Opens a disco packet addressed to `ours`. Returns the sender and message.
pub fn open(ours: &DiscoPrivateKey, pkt: &[u8]) -> Option<(DiscoPublicKey, Message)> {
    use crypto_box::aead::Aead;
    let from = sender(pkt)?;
    let nonce: [u8; NONCE_LEN] = pkt[38..62].try_into().ok()?;
    let plain = crypto_box::SalsaBox::new(&from.to_crypto_box(), &ours.to_crypto_box())
        .decrypt((&nonce).into(), &pkt[62..])
        .ok()?;
    Some((from, Message::decode_plain(&plain)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_messages() {
        crate::rng::seed(&[9; 32]);
        let a = DiscoPrivateKey::from_bytes([1; 32]);
        let b = DiscoPrivateKey::from_bytes([2; 32]);
        let node = ts_keys::NodePrivateKey::from_bytes([3; 32]).public_key();
        let msgs = [
            Message::Ping { tx_id: [7; 12], node_key: Some(node) },
            Message::Pong { tx_id: [8; 12], src: "203.0.113.5:41641".parse().unwrap() },
            Message::Pong { tx_id: [8; 12], src: "[2001:db8::1]:41641".parse().unwrap() },
            Message::CallMeMaybe {
                endpoints: alloc::vec!["192.0.2.1:1".parse().unwrap(), "[2001:db8::2]:2".parse().unwrap()],
            },
        ];
        for m in msgs {
            let pkt = seal(&a, &b.public_key(), &node, &m).unwrap();
            assert!(is_disco(&pkt));
            assert_eq!(sender(&pkt), Some(a.public_key()));
            assert_eq!(open(&b, &pkt), Some((a.public_key(), m)));
            // Not addressed to `a`.
            assert_eq!(open(&a, &pkt), None);
        }
    }
}
