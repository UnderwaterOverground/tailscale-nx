//! HPACK (RFC 7541) header compression.
//!
//! The decoder is complete (dynamic table, Huffman), since we must follow
//! whatever the server sends. The encoder only emits literals that never touch
//! the dynamic table, which is always valid and keeps us stateless.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use super::hpack_tables::{HUFFMAN_CODES, STATIC_TABLE};

pub type Header = (String, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpackError {
    Truncated,
    IntegerOverflow,
    BadIndex,
    BadHuffman,
    TableSizeTooLarge,
    NotUtf8,
}

/// Per RFC 7541 4.1, each entry costs its name + value length plus 32.
const ENTRY_OVERHEAD: usize = 32;

pub struct Decoder {
    dynamic: VecDeque<Header>,
    size: usize,
    max_size: usize,
    /// Upper bound advertised in our SETTINGS_HEADER_TABLE_SIZE.
    protocol_max: usize,
}

impl Decoder {
    pub fn new(protocol_max: usize) -> Self {
        Self { dynamic: VecDeque::new(), size: 0, max_size: protocol_max, protocol_max }
    }

    /// Decodes one complete header block.
    pub fn decode(&mut self, mut buf: &[u8]) -> Result<Vec<Header>, HpackError> {
        let mut out = Vec::new();
        while let Some(&first) = buf.first() {
            if first & 0x80 != 0 {
                // Indexed header field.
                let (idx, rest) = decode_int(buf, 7)?;
                buf = rest;
                out.push(self.lookup(idx)?);
            } else if first & 0xc0 == 0x40 {
                // Literal with incremental indexing.
                let (header, rest) = self.decode_literal(buf, 6)?;
                buf = rest;
                self.insert(header.clone());
                out.push(header);
            } else if first & 0xe0 == 0x20 {
                // Dynamic table size update.
                let (size, rest) = decode_int(buf, 5)?;
                buf = rest;
                if size > self.protocol_max {
                    return Err(HpackError::TableSizeTooLarge);
                }
                self.max_size = size;
                self.evict(0);
            } else {
                // Literal without indexing (0000) or never indexed (0001).
                let (header, rest) = self.decode_literal(buf, 4)?;
                buf = rest;
                out.push(header);
            }
        }
        Ok(out)
    }

    fn decode_literal<'a>(&self, buf: &'a [u8], prefix: u8) -> Result<(Header, &'a [u8]), HpackError> {
        let (idx, rest) = decode_int(buf, prefix)?;
        let (name, rest) = if idx == 0 { decode_string(rest)? } else { (self.lookup(idx)?.0, rest) };
        let (value, rest) = decode_string(rest)?;
        Ok(((name, value), rest))
    }

    fn lookup(&self, idx: usize) -> Result<Header, HpackError> {
        match idx {
            0 => Err(HpackError::BadIndex),
            1..=61 => {
                let (n, v) = STATIC_TABLE[idx - 1];
                Ok((n.into(), v.into()))
            }
            _ => self.dynamic.get(idx - 62).cloned().ok_or(HpackError::BadIndex),
        }
    }

    fn insert(&mut self, header: Header) {
        let cost = header.0.len() + header.1.len() + ENTRY_OVERHEAD;
        self.evict(cost);
        // An entry larger than the whole table empties it and is not stored.
        if cost <= self.max_size {
            self.size += cost;
            self.dynamic.push_front(header);
        }
    }

    /// Evicts oldest entries until `incoming` more bytes fit.
    fn evict(&mut self, incoming: usize) {
        while self.size + incoming > self.max_size {
            match self.dynamic.pop_back() {
                Some((n, v)) => self.size -= n.len() + v.len() + ENTRY_OVERHEAD,
                None => break,
            }
        }
    }
}

fn decode_int(buf: &[u8], prefix: u8) -> Result<(usize, &[u8]), HpackError> {
    let mask = (1u16 << prefix) as u8 - 1;
    let (&first, mut rest) = buf.split_first().ok_or(HpackError::Truncated)?;
    let mut value = (first & mask) as usize;
    if value < mask as usize {
        return Ok((value, rest));
    }
    let mut shift = 0u32;
    loop {
        let (&b, r) = rest.split_first().ok_or(HpackError::Truncated)?;
        rest = r;
        if shift > 28 {
            return Err(HpackError::IntegerOverflow);
        }
        value += ((b & 0x7f) as usize) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((value, rest));
        }
    }
}

fn decode_string(buf: &[u8]) -> Result<(String, &[u8]), HpackError> {
    let huffman = buf.first().ok_or(HpackError::Truncated)? & 0x80 != 0;
    let (len, rest) = decode_int(buf, 7)?;
    if rest.len() < len {
        return Err(HpackError::Truncated);
    }
    let (raw, rest) = rest.split_at(len);
    let bytes = if huffman { huffman_decode(raw)? } else { raw.to_vec() };
    let s = String::from_utf8(bytes).map_err(|_| HpackError::NotUtf8)?;
    Ok((s, rest))
}

/// Bit-serial Huffman decoder. Header strings are short, so a linear scan of
/// the 256 codes per symbol is fine and avoids a large decode table.
fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, HpackError> {
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let mut acc: u64 = 0;
    let mut bits: u8 = 0;
    for &byte in input {
        acc = (acc << 8) | byte as u64;
        bits += 8;
        // Codes are at least 5 bits long; keep matching while we can.
        'symbols: while bits >= 5 {
            for len in 5..=bits.min(30) {
                let candidate = (acc >> (bits - len)) as u32 & ((1u32 << len) - 1);
                if let Some(sym) = HUFFMAN_CODES.iter().position(|&(code, l)| l == len && code == candidate) {
                    out.push(sym as u8);
                    bits -= len;
                    acc &= (1u64 << bits) - 1;
                    continue 'symbols;
                }
            }
            if bits >= 30 {
                // No code (and EOS must not appear in the data).
                return Err(HpackError::BadHuffman);
            }
            break;
        }
    }
    // Padding: fewer than 8 bits, all ones (a prefix of EOS).
    if bits >= 8 || acc != (1u64 << bits) - 1 {
        return Err(HpackError::BadHuffman);
    }
    Ok(out)
}

/// Appends an HPACK integer with an N-bit prefix; `first` carries the flag bits.
fn encode_int(out: &mut Vec<u8>, first: u8, prefix: u8, mut value: usize) {
    let mask = ((1u16 << prefix) - 1) as usize;
    if value < mask {
        out.push(first | value as u8);
        return;
    }
    out.push(first | mask as u8);
    value -= mask;
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn encode_str(out: &mut Vec<u8>, s: &str) {
    encode_int(out, 0, 7, s.len());
    out.extend_from_slice(s.as_bytes());
}

/// Encodes headers as literals without indexing, using static-table names
/// where they exist. Names must already be lowercase.
pub fn encode(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, value) in headers {
        if let Some(i) = STATIC_TABLE.iter().position(|&(n, v)| n == name && v == value) {
            encode_int(&mut out, 0x80, 7, i + 1);
        } else if let Some(i) = STATIC_TABLE.iter().position(|&(n, _)| n == name) {
            encode_int(&mut out, 0x00, 4, i + 1);
            encode_str(&mut out, value);
        } else {
            out.push(0x00);
            encode_str(&mut out, name);
            encode_str(&mut out, value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn pairs(h: &[Header]) -> Vec<(&str, &str)> {
        h.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect()
    }

    // RFC 7541 C.4: requests with Huffman coding, sharing one dynamic table.
    #[test]
    fn rfc7541_c4_requests_with_huffman() {
        let mut d = Decoder::new(4096);
        let h = d.decode(&hex("828684418cf1e3c2e5f23a6ba0ab90f4ff")).unwrap();
        assert_eq!(
            pairs(&h),
            vec![(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")]
        );
        let h = d.decode(&hex("828684be5886a8eb10649cbf")).unwrap();
        assert_eq!(pairs(&h)[4], ("cache-control", "no-cache"));
        let h = d.decode(&hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")).unwrap();
        assert_eq!(pairs(&h)[2], (":path", "/index.html"));
        assert_eq!(pairs(&h)[4], ("custom-key", "custom-value"));
        assert_eq!(d.size, 164);
    }

    // RFC 7541 C.6: responses with Huffman coding and a 256-byte table, which
    // forces evictions.
    #[test]
    fn rfc7541_c6_responses_with_eviction() {
        let mut d = Decoder::new(256);
        let h = d
            .decode(&hex(
                "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
            ))
            .unwrap();
        assert_eq!(
            pairs(&h),
            vec![
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ]
        );
        let h = d.decode(&hex("4883640effc1c0bf")).unwrap();
        assert_eq!(pairs(&h)[0], (":status", "307"));
        let h = d
            .decode(&hex(
                "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
            ))
            .unwrap();
        assert_eq!(pairs(&h)[0], (":status", "200"));
        assert_eq!(pairs(&h)[4], ("content-encoding", "gzip"));
        assert_eq!(pairs(&h)[5], ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"));
        assert_eq!(d.size, 215);
    }

    #[test]
    fn encode_roundtrips_through_decoder() {
        let headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":path", "/machine/map"),
            (":authority", "controlplane.tailscale.com"),
            ("content-type", "application/json"),
            ("ts-lb", "nodekey:abcdef"),
        ];
        let block = encode(&headers);
        let decoded = Decoder::new(4096).decode(&block).unwrap();
        assert_eq!(pairs(&decoded), headers.to_vec());
    }

    #[test]
    fn rejects_bad_padding() {
        // 'a' is 00011 (5 bits); pad with zeros instead of ones.
        assert_eq!(huffman_decode(&[0b0001_1000]), Err(HpackError::BadHuffman));
        assert_eq!(huffman_decode(&[0b0001_1111]).unwrap(), b"a");
    }
}
