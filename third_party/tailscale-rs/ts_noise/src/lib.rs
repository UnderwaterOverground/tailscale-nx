//! Implementation of the Noise protocol framework instantiations we require.
//!
//! For details on the Noise protocol framework, see <https://noiseprotocol.org/>

// tsnx: no_std port.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod core;
pub mod ik;
pub mod ikpsk2;
mod messages;
