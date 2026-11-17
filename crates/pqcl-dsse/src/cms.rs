//! Count–Min Sketch, and the s-term selection rule it exists for.
//!
//! `Π_XT` round one anchors on `w₁ ← argmin_w vol(w)`, because the candidate
//! set `Cand = DB(w₁)` bounds everything after it — the probe count is
//! `2·|Cand|·(n−1)·E`, so a badly chosen anchor is the difference between
//! probing tens of documents and probing millions.
//!
//! # Why a sketch rather than the exact counters
//!
//! The client already keeps exact `c_w` for `Π_core` chain positions, and could
//! rank with those. It cannot afford to: that map is `O(|W|)`, roughly 2 GB at
//! enwiki's 43M keywords, and it is what draft 6 already reports as the reason
//! per-keyword client state *"cannot live on an edge device"*. The sketch is
//! sublinear — `w × d × 4` bytes regardless of keyword count.
//!
//! **The exact counters stay.** The design record is explicit that
//! the sketch was never able to replace them: `Π_core` correctness depends on
//! the exact `c_w`, since search sends `c` and the server derives addresses
//! `0 … c−1`. The sketch replaces `W` **only for frequency ranking**.
//!
//! # Why modest parameters suffice, which looks wrong at first
//!
//! CMS error is one-sided and additive: `ε·‖f‖₁` with `ε = e/w`. At `‖f‖₁ ≈ 10⁹`
//! postings and `w = 2¹⁶` the overestimate is of order `10⁴`, which dwarfs a
//! selective term's true count. That sounds fatal and is not, because of *what
//! the ranking is for*.
//!
//! The only failure that costs anything is picking a **common** term over a
//! **rare** one. That needs the overestimate on the rare term to exceed the
//! common term's true count — for a common term at ~10⁶ that would need `w` in
//! the low thousands. Mis-ranking two rare terms against each other is harmless:
//! both are selective, and round one returns the exact `DB(w₁)` either way.
//!
//! So the error is one-sided, and one-sided in the direction that does not
//! matter. A mis-ranked s-term costs performance, never correctness.

use pqcl_primitives::xof::{self, Label, PrfKey};

/// Sketch width, `w = 2¹⁶`.
pub const CMS_WIDTH: usize = 1 << 16;

/// Sketch depth, `d = 5`.
pub const CMS_DEPTH: usize = 5;

/// A Count–Min Sketch over keyword frequencies.
///
/// `w × d × 4` bytes — about 1.25 MB per plane, independent of how many
/// keywords exist.
pub struct CountMinSketch {
    rows: Vec<Vec<u32>>,
    key: PrfKey,
    total: u64,
}

impl CountMinSketch {
    /// A sketch keyed for one DSSE instance.
    ///
    /// Keyed rather than using a public hash so the row positions a keyword
    /// occupies are not predictable to anyone without the key. The sketch never
    /// leaves the client, but a client that later shares one should not thereby
    /// reveal which keywords collide.
    #[must_use]
    pub fn new(key: PrfKey) -> Self {
        Self {
            rows: vec![vec![0u32; CMS_WIDTH]; CMS_DEPTH],
            key,
            total: 0,
        }
    }

    /// Memory footprint in bytes — reported, since sublinearity is the point.
    #[must_use]
    pub const fn size_bytes() -> usize {
        CMS_WIDTH * CMS_DEPTH * core::mem::size_of::<u32>()
    }

    /// Column index of `w` in every row, from **one** PRF call.
    ///
    /// ⭐ M10 H1: this used to be one PRF call *per row* — five SHAKE256
    /// invocations per index token, ~4 µs, more than the rest of the update's
    /// cryptography combined, and paid again for every range prefix. A 32-byte
    /// PRF output already holds all five 16-bit columns: row `r` reads bytes
    /// `2r..2r+2`. `CMS_WIDTH = 2¹⁶` exactly, so each column is uniform with no
    /// modulo bias, and the rows are disjoint bits of one PRF output, which is
    /// the independence the sketch's bound assumes.
    fn columns(&self, w: &[u8]) -> [usize; CMS_DEPTH] {
        const { assert!(CMS_WIDTH == 1 << 16 && 2 * CMS_DEPTH <= 32) };
        let d = xof::prf(&self.key, Label::Index, &[w]);
        core::array::from_fn(|row| usize::from(u16::from_le_bytes([d[2 * row], d[2 * row + 1]])))
    }

    /// Record one update for `w`.
    ///
    /// Counters saturate rather than wrap. A wrapped counter would report a
    /// very common keyword as very rare, which is precisely the mis-ranking
    /// that costs something.
    pub fn add(&mut self, w: &[u8]) {
        for (row, c) in self.columns(w).into_iter().enumerate() {
            self.rows[row][c] = self.rows[row][c].saturating_add(1);
        }
        self.total = self.total.saturating_add(1);
    }

    /// Estimated update count for `w`. Never an underestimate.
    #[must_use]
    pub fn estimate(&self, w: &[u8]) -> u32 {
        self.columns(w)
            .into_iter()
            .enumerate()
            .map(|(row, c)| self.rows[row][c])
            .min()
            .unwrap_or(0)
    }

    /// Total updates recorded, `‖f‖₁`.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Choose the s-term: the conjunct with the smallest estimated volume.
    ///
    /// Returns the index into `keywords`, or `None` for an empty query.
    ///
    /// # The restriction that comes with it
    ///
    /// The s-term must be a **positive literal**, because `Cand = DB(w₁)`
    /// bounds the result. A query whose every clause carries a negated literal
    /// has no anchor and is a scan, not a search — design §6a is explicit that
    /// this is OXT's restriction too and therefore not a regression. Callers
    /// building `Π_BOOL` queries must pass only positive terms here.
    #[must_use]
    pub fn select_s_term(&self, keywords: &[&[u8]]) -> Option<usize> {
        keywords
            .iter()
            .enumerate()
            .min_by_key(|(_, w)| self.estimate(w))
            .map(|(i, _)| i)
    }
}

impl core::fmt::Debug for CountMinSketch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CountMinSketch {{ w: {CMS_WIDTH}, d: {CMS_DEPTH}, total: {}, {} KiB }}",
            self.total,
            Self::size_bytes() / 1024
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcl_primitives::LAMBDA_BYTES;

    fn sketch() -> CountMinSketch {
        CountMinSketch::new(PrfKey::new([0x3du8; LAMBDA_BYTES]))
    }

    #[test]
    fn parameters_match_the_agreed_values() {
        assert_eq!(CMS_WIDTH, 65_536);
        assert_eq!(CMS_DEPTH, 5);
        // ~1.25 MB per plane, independent of keyword count.
        assert_eq!(CountMinSketch::size_bytes(), 1_310_720);
    }

    #[test]
    fn the_estimate_is_never_an_underestimate() {
        // The one-sidedness the whole argument rests on.
        let mut c = sketch();
        for i in 0..500u32 {
            for _ in 0..=(i % 7) {
                c.add(format!("kw-{i}").as_bytes());
            }
        }
        for i in 0..500u32 {
            let truth = (i % 7) + 1;
            assert!(
                c.estimate(format!("kw-{i}").as_bytes()) >= truth,
                "underestimated kw-{i}"
            );
        }
    }

    #[test]
    fn an_unseen_keyword_estimates_low() {
        let mut c = sketch();
        for i in 0..100u32 {
            c.add(format!("seen-{i}").as_bytes());
        }
        // Not necessarily zero — collisions are the point of a sketch — but it
        // must not look common.
        assert!(c.estimate(b"never-added") < 10);
    }

    #[test]
    fn a_rare_term_is_chosen_over_a_common_one() {
        // The only ranking failure that costs anything is the reverse of this.
        let mut c = sketch();
        for i in 0..100_000u32 {
            c.add(b"common");
            if i.is_multiple_of(10_000) {
                c.add(b"rare");
            }
        }
        let kws: Vec<&[u8]> = vec![b"common", b"rare"];
        assert_eq!(c.select_s_term(&kws), Some(1));
    }

    #[test]
    fn the_rare_term_wins_even_against_heavy_background_load() {
        // ~10^6 postings spread over many keywords, which is where the additive
        // error argument has to hold up.
        let mut c = sketch();
        for i in 0..200_000u32 {
            c.add(format!("bg-{}", i % 50_000).as_bytes());
        }
        for _ in 0..40_000 {
            c.add(b"common");
        }
        for _ in 0..3 {
            c.add(b"selective");
        }
        let kws: Vec<&[u8]> = vec![b"common", b"selective"];
        assert_eq!(
            c.select_s_term(&kws),
            Some(1),
            "selective term estimated at {} vs common at {}",
            c.estimate(b"selective"),
            c.estimate(b"common")
        );
    }

    #[test]
    fn selection_is_deterministic_and_handles_edges() {
        let c = sketch();
        assert_eq!(c.select_s_term(&[]), None);
        let one: Vec<&[u8]> = vec![b"only"];
        assert_eq!(c.select_s_term(&one), Some(0));
    }

    #[test]
    fn different_keys_place_a_keyword_differently() {
        // The sketch is keyed, so which keywords collide is not public.
        let a = CountMinSketch::new(PrfKey::new([1u8; LAMBDA_BYTES]));
        let b = CountMinSketch::new(PrfKey::new([2u8; LAMBDA_BYTES]));
        assert_ne!(a.columns(b"x"), b.columns(b"x"));
    }

    #[test]
    fn the_rows_hash_a_keyword_independently() {
        // Five rows that agreed would be a depth-1 sketch at five times the
        // memory. Over many keywords, no two rows may coincide more often than
        // chance (1 in 2^16 per pair).
        let c = sketch();
        let mut agree = 0usize;
        for i in 0..20_000u32 {
            let cols = c.columns(format!("kw-{i}").as_bytes());
            for a in 0..CMS_DEPTH {
                for b in (a + 1)..CMS_DEPTH {
                    agree += usize::from(cols[a] == cols[b]);
                }
            }
        }
        // Expected 20 000 * 10 / 65 536 ~ 3; 20 is far outside chance.
        assert!(agree < 20, "rows coincided {agree} times");
    }

    #[test]
    fn counters_saturate_rather_than_wrap() {
        // A wrapped counter reports a very common keyword as very rare, which
        // is exactly the mis-ranking that costs something.
        let mut c = sketch();
        for (row, col) in c.columns(b"hot").into_iter().enumerate() {
            c.rows[row][col] = u32::MAX;
        }
        c.add(b"hot");
        assert_eq!(c.estimate(b"hot"), u32::MAX);
    }
}
