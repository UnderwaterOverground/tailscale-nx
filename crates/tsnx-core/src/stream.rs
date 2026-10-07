//! A byte stream that is either plain TCP or TLS over TCP, as seen from the
//! core: ciphertext in/out on one side, plaintext on the other.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::tls::{TlsClient, TlsError};

pub struct SecureStream {
    tls: Option<TlsClient>,
    raw_out: Vec<u8>,
    plain_in: Vec<u8>,
}

impl SecureStream {
    /// Releases spare buffer capacity (see [`crate::trim_vec`]).
    pub fn trim(&mut self) {
        if let Some(t) = self.tls.as_mut() {
            t.trim();
        }
        crate::trim_vec(&mut self.raw_out);
        crate::trim_vec(&mut self.plain_in);
    }

    pub fn plain() -> Self {
        Self { tls: None, raw_out: Vec::new(), plain_in: Vec::new() }
    }

    pub fn tls(config: Arc<rustls::ClientConfig>, server_name: &str) -> Result<Self, TlsError> {
        let mut client = TlsClient::new(config, server_name)?;
        let raw_out = client.take_outgoing();
        Ok(Self { tls: Some(client), raw_out, plain_in: Vec::new() })
    }

    /// Bytes received from the socket.
    pub fn feed(&mut self, raw: &[u8]) -> Result<(), TlsError> {
        match self.tls.as_mut() {
            Some(t) => {
                t.feed(raw)?;
                self.plain_in.extend(t.take_plaintext());
                self.raw_out.extend(t.take_outgoing());
            }
            None => self.plain_in.extend_from_slice(raw),
        }
        Ok(())
    }

    pub fn write(&mut self, plain: &[u8]) -> Result<(), TlsError> {
        if plain.is_empty() {
            return Ok(());
        }
        match self.tls.as_mut() {
            Some(t) => {
                t.write(plain)?;
                self.raw_out.extend(t.take_outgoing());
            }
            None => self.raw_out.extend_from_slice(plain),
        }
        Ok(())
    }

    /// Plaintext received so far.
    pub fn take_plaintext(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.plain_in)
    }

    /// Bytes to write to the socket.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.raw_out)
    }

    /// The TLS peer closed (plain streams learn this from the socket).
    pub fn peer_closed(&self) -> bool {
        self.tls.as_ref().is_some_and(|t| t.peer_closed())
    }
}
