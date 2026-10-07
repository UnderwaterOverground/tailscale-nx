//! tsnx: a `no_std` replacement for `std::time::Instant`.
//!
//! There is no OS clock in the sans-IO core: the driver reads its monotonic clock (e.g.
//! `armGetSystemTick` on Horizon, `std::time::Instant` on a host) and hands the value in as
//! nanoseconds since an arbitrary, fixed epoch via [`Instant::from_nanos`]. Only differences
//! between instants are meaningful.

use core::{
    fmt,
    ops::{Add, AddAssign, Sub, SubAssign},
    time::Duration,
};

/// A point on a monotonic clock, measured in nanoseconds since an arbitrary driver-chosen epoch.
///
/// This mirrors the subset of the `std::time::Instant` API used by the vendored tailscale-rs
/// crates. Arithmetic uses [`core::time::Duration`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant(u64);

fn dur_to_nanos(d: Duration) -> Option<u64> {
    u64::try_from(d.as_nanos()).ok()
}

impl Instant {
    /// The clock's epoch (nanosecond 0).
    pub const ZERO: Instant = Instant(0);

    /// Construct an instant from a monotonic nanosecond counter supplied by the driver.
    pub const fn from_nanos(nanos: u64) -> Self {
        Instant(nanos)
    }

    /// Construct an instant from a monotonic millisecond counter supplied by the driver.
    pub const fn from_millis(millis: u64) -> Self {
        Instant(millis.saturating_mul(1_000_000))
    }

    /// Construct an instant at the given offset from the clock's epoch.
    ///
    /// Saturates at `u64::MAX` nanoseconds (~584 years).
    pub fn from_duration(since_epoch: Duration) -> Self {
        Instant(dur_to_nanos(since_epoch).unwrap_or(u64::MAX))
    }

    /// Return the number of nanoseconds since the clock's epoch.
    pub const fn as_nanos(&self) -> u64 {
        self.0
    }

    /// Return the time elapsed since the clock's epoch.
    pub const fn since_epoch(&self) -> Duration {
        Duration::from_nanos(self.0)
    }

    /// Return `Some(t)` where `t` is `self + d`, or `None` on overflow.
    pub fn checked_add(&self, d: Duration) -> Option<Instant> {
        self.0.checked_add(dur_to_nanos(d)?).map(Instant)
    }

    /// Return `Some(t)` where `t` is `self - d`, or `None` on underflow.
    pub fn checked_sub(&self, d: Duration) -> Option<Instant> {
        self.0.checked_sub(dur_to_nanos(d)?).map(Instant)
    }

    /// Return the amount of time elapsed from `earlier` to `self`, or `None` if `earlier` is
    /// later than `self`.
    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }

    /// Return the amount of time elapsed from `earlier` to `self`, or zero if `earlier` is later
    /// than `self`.
    pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    /// Return the amount of time elapsed from `earlier` to `self`, saturating at zero (like
    /// `std::time::Instant::duration_since`).
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        self.saturating_duration_since(earlier)
    }
}

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Instant({:?})", self.since_epoch())
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    /// # Panics
    ///
    /// On overflow, like `std::time::Instant`.
    fn add(self, rhs: Duration) -> Instant {
        self.checked_add(rhs)
            .expect("overflow when adding duration to instant")
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    /// # Panics
    ///
    /// On underflow, like `std::time::Instant`.
    fn sub(self, rhs: Duration) -> Instant {
        self.checked_sub(rhs)
            .expect("overflow when subtracting duration from instant")
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    /// Saturates at zero, like `std::time::Instant`.
    fn sub(self, rhs: Instant) -> Duration {
        self.duration_since(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        let t = Instant::from_nanos(1_000);
        assert_eq!((t + Duration::from_nanos(500)).as_nanos(), 1_500);
        assert_eq!((t - Duration::from_nanos(500)).as_nanos(), 500);
        assert_eq!(t.checked_sub(Duration::from_nanos(1_001)), None);
        assert_eq!(Instant::from_nanos(u64::MAX).checked_add(Duration::from_nanos(1)), None);
        assert_eq!(Instant::from_nanos(3_000) - t, Duration::from_nanos(2_000));
        assert_eq!(t - Instant::from_nanos(3_000), Duration::ZERO);
        assert!(t < t + Duration::from_nanos(1));
        assert_eq!(Instant::from_millis(2).as_nanos(), 2_000_000);
    }
}
