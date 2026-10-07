//! tsnx: no-op stand-ins for the `tracing` macros used by this crate, used when the `tracing`
//! feature is disabled (the default). See the `extern crate self as tracing` in lib.rs.

#![allow(unused_macros, unused_imports)]

macro_rules! trace { ($($t:tt)*) => {{}} }
macro_rules! debug { ($($t:tt)*) => {{}} }
macro_rules! info { ($($t:tt)*) => {{}} }
// `warn` would clash with the builtin `#[warn]` attribute, so define it under another name.
macro_rules! warn_ { ($($t:tt)*) => {{}} }
macro_rules! error { ($($t:tt)*) => {{}} }
macro_rules! trace_span { ($($t:tt)*) => { $crate::tracing_shim::Span }; }

pub(crate) use warn_ as warn;
pub(crate) use {debug, error, info, trace, trace_span};

/// No-op span.
pub(crate) struct Span;

impl Span {
    /// No-op equivalent of `tracing::Span::entered`.
    pub(crate) fn entered(self) -> Self {
        self
    }
}
