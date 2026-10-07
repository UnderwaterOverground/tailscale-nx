//! Monotonic time supplied by the driver. The core never reads a clock.

use core::time::Duration;

/// A point on the driver's monotonic clock (nanoseconds since an arbitrary
/// origin). Shared with the vendored tailscale-rs crates.
pub use ts_time::Instant;

/// Exponential backoff with a cap, for reconnect loops.
#[derive(Debug, Clone)]
pub struct Backoff {
    current: Duration,
    min: Duration,
    max: Duration,
}

impl Backoff {
    pub const fn new(min: Duration, max: Duration) -> Self {
        Self { current: min, min, max }
    }

    /// Returns the delay to wait now and doubles it for next time.
    pub fn next_delay(&mut self) -> Duration {
        let d = self.current;
        self.current = (self.current * 2).min(self.max);
        d
    }

    pub fn reset(&mut self) {
        self.current = self.min;
    }
}
