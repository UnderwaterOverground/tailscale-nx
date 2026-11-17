//! A byte stream that is either plain TCP or TLS over TCP, as seen from the
//! core: ciphertext in/out on one side, plaintext on the other.
//!
//! On the Switch the driver does TLS instead, through the console's ssl
//! service: a connection that needs it names the server in `Io::Connect`,
//! the stream here stays plain, and rustls isn't built in.

use alloc::string::String;
#[cfg(not(target_os = "horizon"))]
use alloc::string::ToString;
#[cfg(not(target_os = "horizon"))]
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(not(target_os = "horizon"))]
use crate::tls::TlsClient;
#[cfg(not(target_os = "horizon"))]
pub use crate::tls::TlsError;

/// TLS is the driver's job (see the module docs).
pub const DRIVER_TLS: bool = cfg!(target_os = "horizon");

/// What [`SecureStream::tls`] needs: rustls' config, or nothing when the
/// driver does TLS.
#[cfg(not(target_os = "horizon"))]
pub type TlsConfig = Arc<rustls::ClientConfig>;
#[cfg(target_os = "horizon")]
pub type TlsConfig = ();

/// The driver's TLS fails in the driver: the connection just closes.
#[cfg(target_os = "horizon")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {}

/// The config for control and DERP connections, trusting `extra_roots`
/// (DER) as well. The driver's TLS gets those from the driver's caller.
pub fn tls_config(extra_roots: &[Vec<u8>]) -> Result<TlsConfig, String> {
    #[cfg(not(target_os = "horizon"))]
    return crate::tls::client_config(extra_roots).map_err(|e| e.to_string());
    #[cfg(target_os = "horizon")]
    {
        let _ = extra_roots;
        Ok(())
    }
}

/// The server name to give `Io::Connect` for a connection that needs TLS
/// (`tls`): `Some` when the driver does it.
pub fn driver_tls_name(tls: bool, server_name: &str) -> Option<String> {
    (DRIVER_TLS && tls).then(|| server_name.into())
}

pub struct SecureStream {
    #[cfg(not(target_os = "horizon"))]
    tls: Option<TlsClient>,
    raw_out: Vec<u8>,
    plain_in: Vec<u8>,
}

impl SecureStream {
    /// Releases spare buffer capacity (see [`crate::trim_vec`]).
    pub fn trim(&mut self) {
        #[cfg(not(target_os = "horizon"))]
        if let Some(t) = self.tls.as_mut() {
            t.trim();
        }
        crate::trim_vec(&mut self.raw_out);
        crate::trim_vec(&mut self.plain_in);
    }

    pub fn plain() -> Self {
        Self {
            #[cfg(not(target_os = "horizon"))]
            tls: None,
            raw_out: Vec::new(),
            plain_in: Vec::new(),
        }
    }

    /// A TLS stream to `server_name`; plain when the driver does TLS (it was
    /// given the name in `Io::Connect`).
    #[cfg(not(target_os = "horizon"))]
    pub fn tls(config: TlsConfig, server_name: &str) -> Result<Self, TlsError> {
        let mut client = TlsClient::new(config, server_name)?;
        let raw_out = client.take_outgoing();
        Ok(Self { tls: Some(client), raw_out, plain_in: Vec::new() })
    }

    #[cfg(target_os = "horizon")]
    pub fn tls(_config: TlsConfig, _server_name: &str) -> Result<Self, TlsError> {
        Ok(Self::plain())
    }

    /// Bytes received from the socket.
    pub fn feed(&mut self, raw: &[u8]) -> Result<(), TlsError> {
        #[cfg(not(target_os = "horizon"))]
        if let Some(t) = self.tls.as_mut() {
            t.feed(raw)?;
            self.plain_in.extend(t.take_plaintext());
            self.raw_out.extend(t.take_outgoing());
            return Ok(());
        }
        self.plain_in.extend_from_slice(raw);
        Ok(())
    }

    pub fn write(&mut self, plain: &[u8]) -> Result<(), TlsError> {
        if plain.is_empty() {
            return Ok(());
        }
        #[cfg(not(target_os = "horizon"))]
        if let Some(t) = self.tls.as_mut() {
            t.write(plain)?;
            self.raw_out.extend(t.take_outgoing());
            return Ok(());
        }
        self.raw_out.extend_from_slice(plain);
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
        #[cfg(not(target_os = "horizon"))]
        return self.tls.as_ref().is_some_and(|t| t.peer_closed());
        #[cfg(target_os = "horizon")]
        false
    }
}
