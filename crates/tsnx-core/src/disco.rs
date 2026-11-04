//! Disco: Tailscale's peer discovery messages (tailscale/disco), used to find
//! and confirm direct UDP paths. Wire format:
//! `"TS💬" | sender disco key (32) | nonce (24) | NaCl box([type, version=0, body])`.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use ts_keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use zerocopy::IntoBytes;

pub const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const ENDPOINT_LEN: usize = 18;

const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;
const TYPE_CALL_ME_MAYBE: u8 = 0x03;
const TYPE_RELAY_BIND: u8 = 0x04;
const TYPE_RELAY_CHALLENGE: u8 = 0x05;
const TYPE_RELAY_ANSWER: u8 = 0x06;
const TYPE_CALL_ME_MAYBE_VIA: u8 = 0x07;
/// A relay bind message's body: VNI, generation, remote disco key, challenge.
const RELAY_BIND_LEN: usize = 4 + 4 + KEY_LEN + 32;
/// A relay endpoint without its addresses: server and client disco keys,
/// Lamport id, VNI, bind and steady-state lifetimes.
const RELAY_ENDPOINT_LEN: usize = 3 * KEY_LEN + 8 + 4 + 8 + 8;

pub type TxId = [u8; 12];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping { tx_id: TxId, node_key: Option<NodePublicKey> },
    /// `src` is how the pinged node saw our address.
    Pong { tx_id: TxId, src: SocketAddr },
    CallMeMaybe { endpoints: Vec<SocketAddr> },
    /// The sender set up an endpoint on a peer relay server for the two of
    /// us, and asks us to join it (always via DERP).
    CallMeMaybeVia(RelayEndpoint),
    /// The bind handshake with a peer relay server: we send Bind, the server
    /// sends Challenge, we echo it back in Answer.
    RelayBind { step: BindStep, vni: u32, generation: u32, remote: DiscoPublicKey, challenge: [u8; 32] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindStep {
    Bind,
    Challenge,
    Answer,
}

/// An endpoint on a peer relay server (Go: udprelay/endpoint.ServerEndpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub server_disco: DiscoPublicKey,
    /// The two clients allowed to bind: the sender and us.
    pub client_disco: [DiscoPublicKey; 2],
    pub lamport: u64,
    /// Geneve virtual network id: which endpoint on the server.
    pub vni: u32,
    /// How long the server waits for both clients to bind.
    pub bind_lifetime: Duration,
    /// How long a bound endpoint lasts without traffic.
    pub steady_lifetime: Duration,
    /// The server's addresses.
    pub addrs: Vec<SocketAddr>,
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
            Message::CallMeMaybeVia(ep) => {
                b.extend_from_slice(&[TYPE_CALL_ME_MAYBE_VIA, 0]);
                b.extend_from_slice(ep.server_disco.as_bytes());
                for k in &ep.client_disco {
                    b.extend_from_slice(k.as_bytes());
                }
                b.extend_from_slice(&ep.lamport.to_be_bytes());
                b.extend_from_slice(&ep.vni.to_be_bytes());
                b.extend_from_slice(&(ep.bind_lifetime.as_nanos() as u64).to_be_bytes());
                b.extend_from_slice(&(ep.steady_lifetime.as_nanos() as u64).to_be_bytes());
                for a in &ep.addrs {
                    put_endpoint(&mut b, *a);
                }
            }
            Message::RelayBind { step, vni, generation, remote, challenge } => {
                let ty = match step {
                    BindStep::Bind => TYPE_RELAY_BIND,
                    BindStep::Challenge => TYPE_RELAY_CHALLENGE,
                    BindStep::Answer => TYPE_RELAY_ANSWER,
                };
                b.extend_from_slice(&[ty, 0]);
                b.extend_from_slice(&vni.to_be_bytes());
                b.extend_from_slice(&generation.to_be_bytes());
                b.extend_from_slice(remote.as_bytes());
                b.extend_from_slice(challenge);
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
            TYPE_RELAY_BIND | TYPE_RELAY_CHALLENGE | TYPE_RELAY_ANSWER if body.len() >= RELAY_BIND_LEN => {
                let step = match ty {
                    TYPE_RELAY_BIND => BindStep::Bind,
                    TYPE_RELAY_CHALLENGE => BindStep::Challenge,
                    _ => BindStep::Answer,
                };
                Some(Message::RelayBind {
                    step,
                    vni: be32(&body[0..]),
                    generation: be32(&body[4..]),
                    remote: key_at(&body[8..]),
                    challenge: body[40..72].try_into().ok()?,
                })
            }
            TYPE_CALL_ME_MAYBE_VIA
                if body.len() > RELAY_ENDPOINT_LEN && (body.len() - RELAY_ENDPOINT_LEN) % ENDPOINT_LEN == 0 =>
            {
                let n = 3 * KEY_LEN;
                Some(Message::CallMeMaybeVia(RelayEndpoint {
                    server_disco: key_at(body),
                    client_disco: [key_at(&body[KEY_LEN..]), key_at(&body[2 * KEY_LEN..])],
                    lamport: be64(&body[n..]),
                    vni: be32(&body[n + 8..]),
                    bind_lifetime: Duration::from_nanos(be64(&body[n + 12..])),
                    steady_lifetime: Duration::from_nanos(be64(&body[n + 20..])),
                    addrs: body[RELAY_ENDPOINT_LEN..].chunks_exact(ENDPOINT_LEN).map(get_endpoint).collect(),
                }))
            }
            _ => None,
        }
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}

fn key_at(b: &[u8]) -> DiscoPublicKey {
    DiscoPublicKey::from_bytes(b[..KEY_LEN].try_into().unwrap())
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
            Message::CallMeMaybeVia(RelayEndpoint {
                server_disco: DiscoPrivateKey::from_bytes([4; 32]).public_key(),
                client_disco: [a.public_key(), b.public_key()],
                lamport: 3,
                vni: 0x00ab_cdef,
                bind_lifetime: Duration::from_secs(30),
                steady_lifetime: Duration::from_secs(300),
                addrs: alloc::vec!["198.51.100.9:40000".parse().unwrap()],
            }),
            Message::RelayBind {
                step: BindStep::Challenge,
                vni: 7,
                generation: 9,
                remote: a.public_key(),
                challenge: [5; 32],
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
