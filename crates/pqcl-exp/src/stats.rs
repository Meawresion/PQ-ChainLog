//! Median and interquartile range over repeated timings.
//!
//! ⛔ **No mean, and no summary without a spread.** The build plan
//! §12 requires a median and an IQR, and the reason is not stylistic: a
//! latency distribution with a GC pause or a page-fault storm in it has a mean
//! that no single run ever exhibits. A reviewer shown a bare mean discounts the
//! figure, and is right to.
//!
//! The IQR is also the honest way to report the cost of *not* controlling an
//! environment. If it is wide, that is a finding about the measurement, not
//! something to hide behind an average.

use std::time::Duration;

/// A timing distribution, summarised the only way §12 permits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Summary {
    /// Repetitions behind this summary.
    pub n: usize,
    /// Median, in nanoseconds.
    pub median_ns: u128,
    /// First quartile.
    pub p25_ns: u128,
    /// Third quartile.
    pub p75_ns: u128,
    /// `p75 - p25`. Reported explicitly so nobody has to subtract.
    pub iqr_ns: u128,
    /// Fastest and slowest observed, because an outlier is a fact about the
    /// run and hiding it inside the quartiles would be a choice.
    pub min_ns: u128,
    /// See `min_ns`.
    pub max_ns: u128,
    /// The arithmetic mean, rounded down (M13 A11).
    ///
    /// ⭐ **Reported because a median can flatter a skewed arm.** The sampled
    /// sweep's detection time is geometric — most draws are short and a few
    /// are long — while a re-hash is close to uniform over its cycle, so the
    /// medians of the two can differ when their means are at parity
    /// (`audit/07` D11: means 57.6 s against 59.7 s while the medians said
    /// 33 s against 60 s). A comparison stated on medians alone would be
    /// choosing the statistic that wins.
    pub mean_ns: u128,
    /// The 95th percentile, interpolated as the quartiles are (M13 A11).
    pub p95_ns: u128,
}

/// Linear-interpolated quantile over a sorted slice.
///
/// Interpolated rather than nearest-rank so that `p25`/`p75` are stable as `n`
/// crosses a multiple of four — otherwise the IQR steps as the iteration count
/// changes, which looks like a real effect and is not.
fn quantile(sorted: &[u128], q: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "index arithmetic over a slice length; f64 is exact well past any plausible n"
    )]
    let pos = q * (sorted.len() - 1) as f64;
    let lo = pos.floor();
    let hi = pos.ceil();
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "lo and hi are floor/ceil of a value in [0, len-1], so both index validly"
    )]
    let (lo_i, hi_i) = (lo as usize, hi as usize);
    if lo_i == hi_i {
        return sorted[lo_i];
    }
    let frac = pos - lo;
    #[expect(
        clippy::cast_precision_loss,
        reason = "nanosecond counts; f64 is exact to 2^53 ns, which is 104 days"
    )]
    let interpolated = (sorted[lo_i] as f64).mul_add(1.0 - frac, sorted[hi_i] as f64 * frac);
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "interpolated lies between two non-negative observations"
    )]
    let out = interpolated as u128;
    out
}

impl Summary {
    /// Summarise a set of observations.
    ///
    /// # Panics
    ///
    /// If `samples` is empty. A summary of nothing is not a defensible number
    /// to write into a results record, and returning a zeroed one would put it
    /// there silently.
    #[must_use]
    pub fn of(samples: &[Duration]) -> Self {
        assert!(
            !samples.is_empty(),
            "cannot summarise zero samples: a record with a zeroed timing is worse than no record"
        );

        let mut ns: Vec<u128> = samples.iter().map(Duration::as_nanos).collect();
        ns.sort_unstable();

        let p25 = quantile(&ns, 0.25);
        let p75 = quantile(&ns, 0.75);

        Self {
            n: ns.len(),
            median_ns: quantile(&ns, 0.50),
            p25_ns: p25,
            p75_ns: p75,
            iqr_ns: p75.saturating_sub(p25),
            min_ns: ns[0],
            max_ns: ns[ns.len() - 1],
            mean_ns: ns.iter().sum::<u128>() / ns.len() as u128,
            p95_ns: quantile(&ns, 0.95),
        }
    }
}

/// Nanoseconds as a millisecond string, to three decimals, without floats.
///
/// ⭐ **Integer arithmetic on purpose.** The workspace denies precision-losing
/// casts, and rightly: a `u128` nanosecond count does not fit an `f64` mantissa.
/// This is only ever progress output — records carry the raw integers — but a
/// progress line that disagrees with the record it describes is its own small
/// trap, so it is derived exactly.
#[must_use]
pub fn as_ms(ns: u128) -> String {
    format!("{}.{:03}", ns / 1_000_000, (ns % 1_000_000) / 1_000)
}

/// `a / b` as a percentage, integer-only. 250 means 2.50×.
///
/// Returns 0 when `b` is 0 rather than dividing — a zero baseline means the
/// measurement is broken, and an infinity in a progress line would obscure that.
#[must_use]
pub fn ratio_pct(a: u128, b: u128) -> u128 {
    (a * 100).checked_div(b).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(ns: u64) -> Duration {
        Duration::from_nanos(ns)
    }

    #[test]
    fn milliseconds_render_without_floats() {
        assert_eq!(as_ms(0), "0.000");
        assert_eq!(as_ms(1_500_000), "1.500");
        assert_eq!(as_ms(123_456_789), "123.456");
    }

    #[test]
    fn a_zero_baseline_does_not_divide() {
        assert_eq!(ratio_pct(100, 0), 0);
        assert_eq!(ratio_pct(250, 100), 250);
    }

    #[test]
    fn summarises_a_known_distribution() {
        // 1..=9, so the median is 5 and the quartiles are 3 and 7.
        let s = Summary::of(&(1..=9).map(d).collect::<Vec<_>>());
        assert_eq!(s.n, 9);
        assert_eq!(s.median_ns, 5);
        assert_eq!(s.p25_ns, 3);
        assert_eq!(s.p75_ns, 7);
        assert_eq!(s.iqr_ns, 4);
        assert_eq!(s.min_ns, 1);
        assert_eq!(s.max_ns, 9);
        assert_eq!(s.mean_ns, 5);
        // Linear interpolation at 0.95 over nine points: index 7.6, so 8.6,
        // floored by the integer quantile to 8.
        assert_eq!(s.p95_ns, 8);
    }

    /// ⭐ Why the mean is reported beside the median (M13 A11): on a skewed
    /// sample — the sweep's geometric detection times — the two part company,
    /// and a comparison quoted on the median alone picks the flattering one.
    #[test]
    fn a_skewed_sample_separates_the_mean_from_the_median() {
        let s = Summary::of(&[d(1), d(1), d(1), d(2), d(95)]);
        assert_eq!(s.median_ns, 1);
        assert_eq!(s.mean_ns, 20);
        assert!(s.p95_ns > s.median_ns * 10);
    }

    #[test]
    fn input_order_does_not_matter() {
        let ascending = Summary::of(&[d(1), d(2), d(3), d(4), d(5)]);
        let shuffled = Summary::of(&[d(4), d(1), d(5), d(2), d(3)]);
        assert_eq!(ascending, shuffled);
    }

    #[test]
    fn an_outlier_widens_the_range_but_not_the_median() {
        // ⭐ The property the whole module exists for: one pathological sample
        // moves min/max and leaves the median where it was. A mean would have
        // moved by 20% and reported a latency no run ever saw.
        let clean = Summary::of(&[d(10), d(10), d(11), d(10), d(10)]);
        let spiked = Summary::of(&[d(10), d(10), d(11), d(10), d(1_000)]);
        assert_eq!(clean.median_ns, spiked.median_ns);
        assert!(spiked.max_ns > clean.max_ns * 50);
    }

    #[test]
    fn a_single_sample_is_summarisable_and_has_no_spread() {
        let s = Summary::of(&[d(42)]);
        assert_eq!(s.median_ns, 42);
        assert_eq!(s.iqr_ns, 0);
    }

    #[test]
    #[should_panic(expected = "cannot summarise zero samples")]
    fn refuses_an_empty_sample_set() {
        let _ = Summary::of(&[]);
    }
}
