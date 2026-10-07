//! Tailscale control plane client (ts2021).

pub mod client;
pub mod conn;
pub mod noise;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Capability version we claim (tailcfg.CurrentCapabilityVersion of the Go
/// client whose behaviour we follow). Also the ts2021 Noise protocol version.
pub const CAPABILITY_VERSION: u16 = 130;

/// HTTP/1.1 request for the control server's Noise public key.
pub fn key_request(host: &str) -> Vec<u8> {
    format!("GET /key?v={CAPABILITY_VERSION} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tailscale-nx\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    Incomplete,
    Status(String),
    Missing,
}

/// Extracts the `mkey:` Noise public key from a complete /key HTTP response.
pub fn parse_key_response(resp: &[u8]) -> Result<[u8; 32], KeyError> {
    let text = core::str::from_utf8(resp).map_err(|_| KeyError::Missing)?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or(KeyError::Incomplete)?;
    let status = head.lines().next().unwrap_or("");
    if status.split(' ').nth(1) != Some("200") {
        return Err(KeyError::Status(status.into()));
    }
    let start = body.find("\"publicKey\"").ok_or(KeyError::Missing)?;
    let rest = &body[start..];
    let hex_start = rest.find("mkey:").ok_or(KeyError::Missing)? + 5;
    parse_hex32(rest.get(hex_start..hex_start + 64).ok_or(KeyError::Incomplete)?).ok_or(KeyError::Missing)
}

pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

pub fn hex32(key: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in key {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 15) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_response() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"legacyPublicKey\":\"mkey:0000000000000000000000000000000000000000000000000000000000000000\",\"publicKey\":\"mkey:19d16b8d999dfb1fbbab1480b50a3a77da4e549536827f349774233d8f42ce22\"}";
        let key = parse_key_response(resp).unwrap();
        assert_eq!(hex32(&key), "19d16b8d999dfb1fbbab1480b50a3a77da4e549536827f349774233d8f42ce22");
        assert!(matches!(parse_key_response(b"HTTP/1.1 404 Not Found\r\n\r\n"), Err(KeyError::Status(_))));
    }
}
