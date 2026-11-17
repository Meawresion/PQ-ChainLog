//! `Π_RANGE` — range queries, by reduction rather than by new machinery.
//!
//! A numeric attribute over `[0, 2^depth)` is laid out as a binary range tree.
//! A record with value `v` is indexed under the `depth + 1` ancestors of leaf
//! `v`, **each treated as an ordinary keyword** `attr:d:prefix`. Neither
//! `Π_core` nor `Π_XT` changes at all — they see keywords.
//!
//! A query `[lo, hi]` decomposes into a *canonical cover*: at most `2·depth`
//! disjoint nodes whose union is exactly the range. That is a disjunction, and
//! [`crate::Formula::Or`] already evaluates disjunctions client-side. So range
//! search costs no new leakage above `Π_XT` and no new cryptography.
//!
//! The project rules is explicit that no novelty is claimed here: range search
//! over encrypted data goes back a decade, and Zuo'22 and Trinity are the
//! baselines. What is ours is that the reduction is *free* given the two-round
//! structure — the same reason `Π_BOOL` is free.
//!
//! # Two costs that must be stated, not buried
//!
//! 1. **Index growth.** Each numeric attribute multiplies that attribute's
//!    postings by `depth + 1`, in both `EDB` and `XSet`, because every
//!    prefix-keyword needs its own cross-tags. Design §6b′ reports this as a
//!    whole-record growth *ratio* (~5.6× for a 20-keyword, 4-numeric event)
//!    rather than a bare `log D`, which reads as catastrophic and is not.
//! 2. **Cover shape leaks range width.** How many cover nodes, and at which
//!    levels, bounds how wide the queried interval was. This belongs in the
//!    leakage function and is not hidden by the shuffle.
//!
//! # Rounds
//!
//! A **pure range** is one round: the cover nodes are disjoint, so the answer
//! is a disjoint union of `Π_core` searches with no cross-tags at all. That is
//! the claim to make against Zuo'22 — single-round on their own query class.
//! A keyword *and* a range is two rounds, like any other `Π_XT` query.

/// A binary range tree over one numeric attribute.
///
/// `depth` fixes the domain as `[0, 2^depth)`. The concrete per-attribute
/// domains are settled in design §6b′ and carried by [`Attribute`]; use
/// [`RangeTree::profile`] rather than picking a depth by hand outside tests.
///
/// The free-depth constructor stays because a unit test on a 4-bit domain can
/// exhaustively check every range against every value, which is the only way
/// `the_cover_is_exactly_the_range` can be a proof rather than a sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeTree {
    attribute: String,
    depth: u32,
}

/// The numeric attributes, at the domains `PQ-ChainLog-DESIGN.md` §6b′ commits
/// the paper to.
///
/// These are **not** free choices. §6b′ reports the index-growth ratio as ~5.6×
/// for a 20-keyword, 4-numeric event, and that figure is what Exp. 7 must
/// reproduce. A plausible-looking alternative set of depths (32/25/40/40) gives
/// 6.5× instead — a 16% disagreement with the design that nobody could then
/// adjudicate. The design record settles it: use these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribute {
    /// Timestamp, **1 min** granularity from the Unix epoch — see
    /// [`Attribute::of_unix`] for why it is not seconds. `D = 2³⁰`.
    TimestampFine,
    /// Timestamp, **1 hour** granularity from the Unix epoch — see
    /// [`Attribute::of_unix`] for why it is not minutes. `D = 2²⁴`.
    ///
    /// The default: forensic range queries are rarely to the second, and six
    /// bits of depth is six fewer prefix-keywords on every indexed event.
    Timestamp,
    /// Incident duration, 1 s up to ~12 days. `D = 2²⁰`.
    Duration,
    /// Bytes transferred, 1 KiB units up to 4 TiB. `D = 2³²`.
    Bytes,
    /// Monetary amount in minor units. `D = 2³²`.
    Amount,
}

impl Attribute {
    /// The value to index, for a Unix timestamp in seconds.
    ///
    /// ⚠️ **The one conversion, and it had to be fixed to exist** (M13 A2). The
    /// two timestamp attributes were documented as 1 s and 1 min granularity
    /// "over ~34 years", with no stated origin — and read from the Unix epoch,
    /// `2³⁰` seconds ends in **2004** and `2²⁴` minutes in **2001**. So
    /// `index_keywords` panicked on every real timestamp, and nothing had ever
    /// indexed one: the only component that tried quietly reinterpreted `ts` as
    /// *hours* to stay inside the domain, and since keywords are
    /// `ts:level:prefix` either way, its postings were unreachable by any
    /// minute-granular query over the same prefix. A disagreement about units
    /// that no type could catch.
    ///
    /// The units are now one notch coarser, which at the **pinned depths**
    /// is the only choice that covers both a
    /// 2008 artefact mtime and a 2026 custody record from one origin:
    ///
    /// | attribute | unit | window from 1970 |
    /// |---|---|---|
    /// | `Timestamp` (`ts`) | 1 hour | to ~3882 |
    /// | `TimestampFine` (`ts_s`) | 1 minute | to ~4012 |
    ///
    /// Cover sizes depend on the depth and not on the unit, so no measured
    /// quantity moves. ⚠️ **draft8's "1-minute granularity" needs to become
    /// "1-hour"**, or the depth must grow from 24 to 26 — which would change
    /// Exp. 7's cover-size figure and §0.9c's count. The choice is the main
    /// agent's; this is what the code supports.
    ///
    /// `None` past the window's end, because indexing under a clamped value
    /// would answer the wrong query and dropping the record silently would
    /// remove it from every range search.
    ///
    /// For the non-time attributes this is the identity, bounds-checked.
    #[must_use]
    pub const fn of_unix(self, unix_seconds: u64) -> Option<u64> {
        let v = match self {
            Self::Timestamp => unix_seconds / 3_600,
            Self::TimestampFine => unix_seconds / 60,
            _ => unix_seconds,
        };
        if v < 1u64 << self.depth() {
            Some(v)
        } else {
            None
        }
    }

    /// `log D` — this attribute's tree depth.
    #[must_use]
    pub const fn depth(self) -> u32 {
        match self {
            Self::TimestampFine => 30,
            Self::Timestamp => 24,
            Self::Duration => 20,
            Self::Bytes | Self::Amount => 32,
        }
    }

    /// The keyword prefix.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TimestampFine => "ts_s",
            Self::Timestamp => "ts",
            Self::Duration => "dur",
            Self::Bytes => "bytes",
            Self::Amount => "amt",
        }
    }
}

impl RangeTree {
    /// A tree for one of the committed attributes.
    ///
    /// Prefer this to [`RangeTree::new`] everywhere outside a unit test, so the
    /// domains actually exercised are the ones the paper reports.
    #[must_use]
    pub fn profile(attribute: Attribute) -> Self {
        Self::new(attribute.name(), attribute.depth())
    }

    /// A tree over `[0, 2^depth)`.
    ///
    /// # Panics
    ///
    /// If `depth > 63`, which no attribute we index needs.
    #[must_use]
    pub fn new(attribute: &str, depth: u32) -> Self {
        assert!(depth <= 63, "depth {depth} exceeds a u64 domain");
        Self {
            attribute: attribute.to_owned(),
            depth,
        }
    }

    /// Domain size, `2^depth`.
    #[must_use]
    pub const fn domain(&self) -> u64 {
        1u64 << self.depth
    }

    /// Tree depth.
    #[must_use]
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// The keyword for the node at `level` covering `prefix`.
    ///
    /// `level` counts from the root (0 = whole domain). Encoding is
    /// `attr:level:prefix`, which is unambiguous because level and prefix are
    /// decimal and colon-separated, and `attr` is an identifier without colons.
    #[must_use]
    pub fn node_keyword(&self, level: u32, prefix: u64) -> Vec<u8> {
        format!("{}:{}:{}", self.attribute, level, prefix).into_bytes()
    }

    /// Keywords a record with value `v` must be indexed under: the leaf and
    /// every ancestor, `depth + 1` in all.
    ///
    /// # Panics
    ///
    /// If `v` is outside `[0, 2^depth)`. An out-of-domain value is a caller
    /// bug that would otherwise index under a keyword no query can reach, and
    /// silently vanish from every range result.
    #[must_use]
    pub fn index_keywords(&self, v: u64) -> Vec<Vec<u8>> {
        assert!(
            v < self.domain(),
            "value {v} outside the domain [0, {}) of attribute {}",
            self.domain(),
            self.attribute
        );
        (0..=self.depth)
            .map(|level| {
                let shift = self.depth - level;
                self.node_keyword(level, (v >> shift) << shift)
            })
            .collect()
    }

    /// The canonical cover of `[lo, hi]`: the minimal set of maximal nodes
    /// whose union is exactly the range.
    ///
    /// At most `2·depth` nodes. They are **disjoint**, which is what makes a
    /// pure range a disjoint union and therefore single-round.
    ///
    /// Returns an empty cover for an inverted range.
    #[must_use]
    pub fn cover_keywords(&self, lo: u64, hi: u64) -> Vec<Vec<u8>> {
        if lo > hi || lo >= self.domain() {
            return Vec::new();
        }
        let hi = hi.min(self.domain() - 1);
        let mut out = Vec::new();
        self.cover_from(0, 0, lo, hi, &mut out);
        out
    }

    fn cover_from(&self, level: u32, prefix: u64, lo: u64, hi: u64, out: &mut Vec<Vec<u8>>) {
        let span = 1u64 << (self.depth - level);
        let node_lo = prefix;
        let node_hi = prefix + span - 1;

        if node_hi < lo || node_lo > hi {
            return;
        }
        if lo <= node_lo && node_hi <= hi {
            out.push(self.node_keyword(level, prefix));
            return;
        }
        debug_assert!(level < self.depth, "a leaf is inside or disjoint");
        let half = span / 2;
        self.cover_from(level + 1, prefix, lo, hi, out);
        self.cover_from(level + 1, prefix + half, lo, hi, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> RangeTree {
        RangeTree::new("ts", 4) // domain [0, 16)
    }

    #[test]
    fn a_value_is_indexed_under_every_ancestor() {
        let t = tree();
        let kws = t.index_keywords(5);
        assert_eq!(kws.len(), 5, "depth 4 means 5 levels");
        assert_eq!(kws[0], t.node_keyword(0, 0), "root covers the domain");
        assert_eq!(kws[4], t.node_keyword(4, 5), "leaf is the value itself");
    }

    #[test]
    fn the_cover_is_exactly_the_range() {
        let t = tree();
        // Check by construction: a value is in the range iff one of its index
        // keywords is a cover node. That is the property the reduction needs,
        // and it is stronger than counting nodes.
        for lo in 0..16u64 {
            for hi in lo..16u64 {
                let cover: std::collections::BTreeSet<_> =
                    t.cover_keywords(lo, hi).into_iter().collect();
                for v in 0..16u64 {
                    let hit = t.index_keywords(v).iter().any(|k| cover.contains(k));
                    assert_eq!(
                        hit,
                        (lo..=hi).contains(&v),
                        "value {v} against range [{lo}, {hi}]"
                    );
                }
            }
        }
    }

    #[test]
    fn the_cover_is_at_most_two_log_d_nodes() {
        let t = RangeTree::new("ts", 16);
        for (lo, hi) in [(0, 65535), (1, 65534), (12345, 54321), (7, 8)] {
            let n = t.cover_keywords(lo, hi).len();
            assert!(
                n <= 2 * t.depth() as usize,
                "[{lo}, {hi}] needed {n} nodes, above the 2·depth bound"
            );
        }
    }

    #[test]
    fn an_aligned_range_is_a_single_node() {
        // [0, 2^k) collapses to one keyword — the reason a wide range is not
        // automatically an expensive one.
        let t = tree();
        assert_eq!(t.cover_keywords(0, 15).len(), 1);
        assert_eq!(t.cover_keywords(8, 11).len(), 1);
    }

    #[test]
    fn a_point_range_is_the_leaf() {
        let t = tree();
        assert_eq!(t.cover_keywords(9, 9), vec![t.node_keyword(4, 9)]);
    }

    #[test]
    fn cover_nodes_are_disjoint() {
        // Disjointness is what makes a pure range a disjoint union, and so
        // single-round. If it failed, results would double-count.
        let t = RangeTree::new("ts", 8);
        let cover: Vec<_> = t.cover_keywords(3, 200);
        let unique: std::collections::BTreeSet<_> = cover.iter().collect();
        assert_eq!(cover.len(), unique.len());

        for v in 0..256u64 {
            let hits = t
                .index_keywords(v)
                .iter()
                .filter(|k| cover.contains(k))
                .count();
            assert!(hits <= 1, "value {v} matched {hits} cover nodes");
        }
    }

    #[test]
    fn an_inverted_or_out_of_domain_range_covers_nothing() {
        let t = tree();
        assert!(t.cover_keywords(9, 3).is_empty());
        assert!(t.cover_keywords(99, 200).is_empty());
    }

    #[test]
    fn index_growth_is_depth_plus_one_per_attribute() {
        // The honest cost. A 32-bit timestamp multiplies that attribute's
        // postings by 33, which is why design §6b′ insists the paper reports a
        // whole-record ratio rather than this number alone.
        for depth in [4u32, 8, 16, 32] {
            let t = RangeTree::new("ts", depth);
            assert_eq!(t.index_keywords(1).len(), depth as usize + 1);
        }
    }

    #[test]
    fn the_committed_profile_matches_design_6b_prime() {
        // The depths the paper reports. If these change, §6b′'s growth ratio
        // changes with them and Exp. 7 would contradict the design.
        assert_eq!(Attribute::TimestampFine.depth(), 30);
        assert_eq!(Attribute::Timestamp.depth(), 24);
        assert_eq!(Attribute::Duration.depth(), 20);
        assert_eq!(Attribute::Bytes.depth(), 32);
        assert_eq!(Attribute::Amount.depth(), 32);

        let sum: u32 = [
            Attribute::Timestamp,
            Attribute::Duration,
            Attribute::Bytes,
            Attribute::Amount,
        ]
        .iter()
        .map(|a| a.depth())
        .sum();
        assert_eq!(
            sum, 108,
            "the four default depths must sum to 108, or the ~5.6x ratio in \
             design §6b′ no longer holds"
        );
    }

    #[test]
    fn a_profiled_tree_covers_its_stated_domain() {
        for a in [
            Attribute::TimestampFine,
            Attribute::Timestamp,
            Attribute::Duration,
            Attribute::Bytes,
            Attribute::Amount,
        ] {
            let t = RangeTree::profile(a);
            assert_eq!(t.depth(), a.depth());
            assert_eq!(t.domain(), 1u64 << a.depth());
            // Both ends of the domain index without panicking.
            assert_eq!(t.index_keywords(0).len(), a.depth() as usize + 1);
            assert_eq!(
                t.index_keywords(t.domain() - 1).len(),
                a.depth() as usize + 1
            );
        }
    }

    #[test]
    fn a_real_range_over_a_committed_domain_is_exact() {
        // A day-long window at minute granularity, on the actual domain rather
        // than a toy depth.
        let t = RangeTree::profile(Attribute::Timestamp);
        let (lo, hi) = (1_000_000u64, 1_000_000 + 1_440);
        let cover: std::collections::BTreeSet<_> = t.cover_keywords(lo, hi).into_iter().collect();
        assert!(cover.len() <= 2 * t.depth() as usize);
        for v in [lo, lo + 1, lo + 720, hi - 1, hi] {
            assert!(t.index_keywords(v).iter().any(|k| cover.contains(k)), "{v}");
        }
        for v in [lo - 1, hi + 1, lo - 1000, hi + 1000] {
            assert!(
                !t.index_keywords(v).iter().any(|k| cover.contains(k)),
                "{v}"
            );
        }
    }

    #[test]
    fn different_attributes_never_collide() {
        let a = RangeTree::new("ts", 8);
        let b = RangeTree::new("bytes", 8);
        assert_ne!(a.node_keyword(3, 64), b.node_keyword(3, 64));
    }
}
