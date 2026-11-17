//! GGM range-constrained PRF — the Diana construction.
//!
//! A binary tree of depth `ℓ` whose root is a master key. Each node's two
//! children come from one `G(s) = SHAKE256(0x04 ‖ s) → 2λ` call (draft6
//! eq. (2)): the first λ bytes are the left child, the second λ the right. The
//! PRF value at index `i` is the leaf reached by following the bits of `i` from
//! the most significant down.
//!
//! Handing out a node key delegates its whole subtree and nothing else — a
//! child cannot invert `G` to recover its parent or sibling. A contiguous range
//! is therefore covered by at most `2ℓ` node keys, and that covering set **is**
//! the constrained key.
//!
//! # Where this is used, twice
//!
//! * **Counter space, `Π_core`.** `K^A_w` is the root over `[0, 2^ℓ)`; a search
//!   for `w` releases the constrained key for `[0, c_w)`, letting the server
//!   derive exactly the addresses written so far and no future ones. That is
//!   the whole mechanism behind forward privacy: the server cannot compute
//!   `addr` for counter `c_w` before the client sends it.
//! * **Writer-identifier space, design §11.2.** `K_case` is the root over
//!   `[0, 2^d)`; writer `i` gets the single leaf `K_i`. Writer selection
//!   becomes a cryptographic property rather than an HSM assumption, which
//!   downgrades the Secure Module from load-bearing to defence in depth.
//!
//! # The property that matters
//!
//! A constrained key must evaluate **identically** to the root inside its range
//! and be **unable to produce anything** outside it. Both are tested. The
//! second is the security property; the first is what makes the first property
//! useful rather than vacuous.
//!
//! # Cost
//!
//! Evaluating one index from the root is `ℓ` PRG calls. Expanding a whole range
//! is *not* `ℓ` per leaf — [`ConstrainedKey::expand`] walks each covering
//! subtree once, so it costs about **two PRG calls per leaf** amortised. The
//! server does the second thing, and `Π_core`'s per-search cost depends on it.

use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::Digest32;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// GGM tree depth, `ℓ = 64` (`PQ-DSSE-Formal.md` §9.3).
///
/// Supports `2^64` updates per keyword, so a constrained key is at most 128
/// node keys — 4 KiB. The bound is on the *token*, not the database.
pub const TREE_DEPTH: u8 = 64;

/// Failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GgmError {
    /// The index is outside the constrained key's range.
    ///
    /// This is the security property, not an inconvenience: a constrained key
    /// **must not** be able to produce a value here.
    OutOfRange {
        /// The index asked for.
        index: u64,
        /// Inclusive lower bound of the range the key covers.
        lo: u64,
        /// Inclusive upper bound.
        hi: u64,
    },
    /// `lo > hi`.
    EmptyRange {
        /// Requested lower bound.
        lo: u64,
        /// Requested upper bound.
        hi: u64,
    },
}

impl core::fmt::Display for GgmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfRange { index, lo, hi } => {
                write!(
                    f,
                    "index {index} is outside the constrained range [{lo}, {hi}]"
                )
            }
            Self::EmptyRange { lo, hi } => write!(f, "empty range [{lo}, {hi}]"),
        }
    }
}

impl core::error::Error for GgmError {}

/// A GGM subtree key: the key itself plus which subtree it governs.
///
/// `depth` is how many leading bits of an index are fixed; `prefix` holds them
/// in the **high** bits, so a node at depth `d` covers
/// `[prefix, prefix + 2^(ℓ−d) − 1]`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NodeKey {
    key: Digest32,
    #[zeroize(skip)]
    prefix: u64,
    #[zeroize(skip)]
    depth: u8,
}

impl NodeKey {
    /// Lowest index this subtree covers.
    #[must_use]
    pub const fn lo(&self) -> u64 {
        self.prefix
    }

    /// Highest index this subtree covers, inclusive.
    #[must_use]
    pub const fn hi(&self) -> u64 {
        let span = span_of(self.depth);
        self.prefix.saturating_add(span - 1)
    }

    /// Depth in the tree; `TREE_DEPTH` means a single leaf.
    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.depth
    }
}

impl core::fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "NodeKey {{ depth: {}, covers: [{}, {}], key: <redacted> }}",
            self.depth,
            self.lo(),
            self.hi()
        )
    }
}

/// How many leaves a node at `depth` covers.
const fn span_of(depth: u8) -> u64 {
    if depth == 0 {
        u64::MAX // the whole tree; only used via saturating arithmetic
    } else {
        1u64 << (TREE_DEPTH - depth)
    }
}

/// Split a node key into its two children: `G(key)`, AES-256 since M12 R3
/// (`pqcl_primitives::prg`). Left child first.
fn children(key: &Digest32) -> (Digest32, Digest32) {
    let out = pqcl_primitives::prg::ggm_step(key);
    let mut left = [0u8; LAMBDA_BYTES];
    let mut right = [0u8; LAMBDA_BYTES];
    left.copy_from_slice(&out[..LAMBDA_BYTES]);
    right.copy_from_slice(&out[LAMBDA_BYTES..]);
    (left, right)
}

/// Evaluate the PRF at a **sequence** of indices from one root, reusing the path.
///
/// ⭐ **M10 P1.** Profiling campaign 02's ingest put **92% of an update's
/// crypto cost in [`MasterKey::eval`]**: a fresh root-to-leaf walk of
/// `TREE_DEPTH = 64` PRG calls for every token (~41 µs of ~49 µs, local). But
/// `Π_core` counters only increase, and the path to leaf `c + 1` shares every
/// node with the path to `c` above the highest bit where the two indices
/// differ. This keeps the last path and recomputes only below that bit: ~2 PRG
/// calls per step amortised instead of 64.
///
/// **Output is identical to [`MasterKey::eval`] by construction** — it is the
/// same chain of `G` calls, with the unchanged prefix of the chain reused
/// rather than recomputed. Any index order is correct; ascending order is what
/// makes it cheap. Tested against both `eval` and [`ConstrainedKey::expand`].
///
/// Memory: `TREE_DEPTH + 1` node keys, 2 080 B. The node keys are secret — each
/// one delegates its whole subtree — so they are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PathEval {
    /// `nodes[d]` is the node at depth `d` on the path to `last`; `nodes[0]`
    /// is the root and `nodes[TREE_DEPTH]` the leaf.
    nodes: [Digest32; TREE_DEPTH as usize + 1],
    #[zeroize(skip)]
    last: Option<u64>,
    #[zeroize(skip)]
    prg_calls: u64,
}

impl PathEval {
    /// Start from a root. The first evaluation walks the whole path.
    #[must_use]
    pub fn new(root: &MasterKey) -> Self {
        let mut nodes = [[0u8; LAMBDA_BYTES]; TREE_DEPTH as usize + 1];
        nodes[0] = root.0;
        Self {
            nodes,
            last: None,
            prg_calls: 0,
        }
    }

    /// The PRF value at `index`, identical to `MasterKey::eval(index)`.
    #[must_use]
    pub fn eval(&mut self, index: u64) -> Digest32 {
        // Nodes above the highest differing bit are shared with the last path.
        // `bit_at` numbers depth 0 as the most significant bit, so that bit is
        // decided at depth `leading_zeros(last ^ index)`, and the node there is
        // still valid; everything below it must be recomputed.
        let start = match self.last {
            None => 0,
            Some(prev) if prev == index => return self.nodes[TREE_DEPTH as usize],
            Some(prev) => {
                // `prev != index`, so the xor is nonzero and this is < 64.
                u8::try_from((prev ^ index).leading_zeros()).unwrap_or(0)
            }
        };
        for depth in start..TREE_DEPTH {
            let (l, r) = children(&self.nodes[usize::from(depth)]);
            self.nodes[usize::from(depth) + 1] = if bit_at(index, depth) { r } else { l };
            self.prg_calls += 1;
        }
        self.last = Some(index);
        self.nodes[TREE_DEPTH as usize]
    }

    /// PRG calls made so far — the amortised-cost evidence.
    #[must_use]
    pub const fn prg_calls(&self) -> u64 {
        self.prg_calls
    }
}

/// Whether `index`'s bit at `depth` (0-based from the top) is set.
const fn bit_at(index: u64, depth: u8) -> bool {
    (index >> (TREE_DEPTH - 1 - depth)) & 1 == 1
}

/// The master key: the tree root.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(Digest32);

impl MasterKey {
    /// Adopt raw key bytes, e.g. `K^A_w = F(K_S, "addr" ‖ w)`.
    #[must_use]
    pub const fn new(bytes: Digest32) -> Self {
        Self(bytes)
    }

    /// Evaluate the PRF at `index` by walking the tree from the root.
    ///
    /// `ℓ` PRG calls. To evaluate many indices, prefer
    /// [`constrain`](Self::constrain) then [`ConstrainedKey::expand`].
    #[must_use]
    pub fn eval(&self, index: u64) -> Digest32 {
        let mut key = self.0;
        for depth in 0..TREE_DEPTH {
            let (l, r) = children(&key);
            key = if bit_at(index, depth) { r } else { l };
        }
        key
    }

    /// An incremental evaluator over this root. See [`PathEval`].
    #[must_use]
    pub fn path_eval(&self) -> PathEval {
        PathEval::new(self)
    }

    /// Produce the constrained key covering `[lo, hi]` inclusive.
    ///
    /// Returns the canonical cover: the minimal set of maximal subtrees whose
    /// union is exactly the range, at most `2ℓ` nodes. Minimality is not
    /// cosmetic — the cover is transmitted, and it is also what bounds what the
    /// recipient can compute.
    ///
    /// # Errors
    ///
    /// [`GgmError::EmptyRange`] if `lo > hi`.
    pub fn constrain(&self, lo: u64, hi: u64) -> Result<ConstrainedKey, GgmError> {
        if lo > hi {
            return Err(GgmError::EmptyRange { lo, hi });
        }
        let mut nodes = Vec::new();
        cover(&self.0, 0, 0, lo, hi, &mut nodes);
        Ok(ConstrainedKey { nodes, lo, hi })
    }

    /// Constrain to `[0, count)` — the `Π_core` search case.
    ///
    /// # Errors
    ///
    /// [`GgmError::EmptyRange`] if `count` is zero: there is nothing to
    /// delegate, and a caller that ignored an empty result would leak a search
    /// for a keyword with no updates.
    pub fn constrain_prefix(&self, count: u64) -> Result<ConstrainedKey, GgmError> {
        if count == 0 {
            return Err(GgmError::EmptyRange { lo: 0, hi: 0 });
        }
        self.constrain(0, count - 1)
    }
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Recursive canonical cover of `[lo, hi]` by maximal subtrees.
fn cover(key: &Digest32, prefix: u64, depth: u8, lo: u64, hi: u64, out: &mut Vec<NodeKey>) {
    let span = span_of(depth);
    let node_lo = prefix;
    let node_hi = prefix.saturating_add(span - 1);

    if node_hi < lo || node_lo > hi {
        return; // disjoint
    }
    if lo <= node_lo && node_hi <= hi {
        out.push(NodeKey {
            key: *key,
            prefix,
            depth,
        });
        return; // wholly inside: this subtree is the cover
    }
    debug_assert!(depth < TREE_DEPTH, "a leaf must be inside or disjoint");
    let (l, r) = children(key);
    let half = span / 2;
    cover(&l, prefix, depth + 1, lo, hi, out);
    cover(&r, prefix + half, depth + 1, lo, hi, out);
}

/// A key that evaluates the PRF on `[lo, hi]` and nowhere else.
#[derive(Clone, Debug)]
pub struct ConstrainedKey {
    nodes: Vec<NodeKey>,
    lo: u64,
    hi: u64,
}

impl ConstrainedKey {
    /// Inclusive lower bound.
    #[must_use]
    pub const fn lo(&self) -> u64 {
        self.lo
    }

    /// Inclusive upper bound.
    #[must_use]
    pub const fn hi(&self) -> u64 {
        self.hi
    }

    /// Covering subtrees. At most `2ℓ`; this is the transmitted size.
    #[must_use]
    pub fn nodes(&self) -> &[NodeKey] {
        &self.nodes
    }

    /// Wire size in bytes, ignoring framing — a communication-volume figure,
    /// which the build plan compares across every baseline
    /// including the Python ones.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.nodes.len() * LAMBDA_BYTES
    }

    /// Evaluate at `index`.
    ///
    /// # Errors
    ///
    /// [`GgmError::OutOfRange`] if `index` is outside the constrained range.
    /// **This is the security property.** A caller must not treat it as a
    /// recoverable miss.
    pub fn eval(&self, index: u64) -> Result<Digest32, GgmError> {
        let node = self
            .nodes
            .iter()
            .find(|n| n.lo() <= index && index <= n.hi())
            .ok_or(GgmError::OutOfRange {
                index,
                lo: self.lo,
                hi: self.hi,
            })?;

        let mut key = node.key;
        for depth in node.depth..TREE_DEPTH {
            let (l, r) = children(&key);
            key = if bit_at(index, depth) { r } else { l };
        }
        Ok(key)
    }

    /// Every `(index, value)` in the range, in ascending order.
    ///
    /// Walks each covering subtree once, so this is about **two PRG calls per
    /// leaf** rather than `ℓ`. The server expands a search token this way, and
    /// `Π_core`'s per-search cost is this function.
    #[must_use]
    pub fn expand(&self) -> Vec<(u64, Digest32)> {
        let mut out = Vec::new();
        for node in &self.nodes {
            expand_subtree(&node.key, node.prefix, node.depth, &mut out);
        }
        out.sort_unstable_by_key(|(i, _)| *i);
        out
    }
}

fn expand_subtree(key: &Digest32, prefix: u64, depth: u8, out: &mut Vec<(u64, Digest32)>) {
    if depth == TREE_DEPTH {
        out.push((prefix, *key));
        return;
    }
    let (l, r) = children(key);
    let half = span_of(depth) / 2;
    expand_subtree(&l, prefix, depth + 1, out);
    expand_subtree(&r, prefix + half, depth + 1, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> MasterKey {
        MasterKey::new([0x42u8; LAMBDA_BYTES])
    }

    // ------------------------------------------------- correctness (M1 accept)

    #[test]
    fn constrained_evaluation_matches_the_root_inside_the_range() {
        let m = master();
        let ck = m.constrain(10, 20).expect("constrain");
        for i in 10..=20 {
            assert_eq!(ck.eval(i).expect("in range"), m.eval(i), "mismatch at {i}");
        }
    }

    #[test]
    fn a_constrained_key_cannot_evaluate_outside_its_range() {
        // The security property. If this ever fails, forward privacy is gone:
        // the server could derive addresses for counters not yet written.
        let ck = master().constrain(10, 20).expect("constrain");
        for i in [0u64, 9, 21, 100, u64::MAX] {
            assert!(
                matches!(ck.eval(i), Err(GgmError::OutOfRange { .. })),
                "constrained key produced a value at out-of-range index {i}"
            );
        }
    }

    #[test]
    fn keys_for_disjoint_ranges_are_independent() {
        let m = master();
        let a = m.constrain(0, 7).expect("constrain");
        let b = m.constrain(8, 15).expect("constrain");

        // Neither can reach into the other.
        for i in 8..=15 {
            assert!(a.eval(i).is_err(), "a reached {i}");
        }
        for i in 0..=7 {
            assert!(b.eval(i).is_err(), "b reached {i}");
        }
        // And no node key is shared between them.
        for x in a.nodes() {
            for y in b.nodes() {
                assert_ne!(x.key, y.key, "disjoint covers share a subtree key");
            }
        }
    }

    #[test]
    fn expand_agrees_with_eval_but_walks_the_tree_once() {
        let m = master();
        let ck = m.constrain(5, 12).expect("constrain");
        let expanded = ck.expand();
        assert_eq!(expanded.len(), 8);
        for (i, v) in expanded {
            assert_eq!(v, m.eval(i), "expand disagrees with eval at {i}");
        }
    }

    // ---------------------------------------------------- PathEval (M10 P1)

    /// ⭐ The acceptance test: byte-identical over ≥ 10⁵ consecutive
    /// counters, checked against `expand` — an independent code path (subtree
    /// expansion, not a root walk) — so agreement is not one implementation
    /// agreeing with itself.
    #[test]
    fn path_eval_matches_expand_over_a_hundred_thousand_consecutive_counters() {
        const N: u64 = 100_000;
        let m = master();
        let expanded = m.constrain_prefix(N).expect("constrain").expand();
        assert_eq!(expanded.len(), usize::try_from(N).expect("fits"));
        let mut pe = m.path_eval();
        for (i, v) in expanded {
            assert_eq!(pe.eval(i), v, "PathEval disagrees with expand at {i}");
        }
        // Amortised: one full walk, then (trailing ones + 1) calls per step,
        // which sums to < 2 per step. This is the speed-up the fix exists for.
        assert!(
            pe.prg_calls() < 2 * N + u64::from(TREE_DEPTH),
            "{} PRG calls for {N} consecutive counters",
            pe.prg_calls()
        );
    }

    /// Every carry boundary `2^j − 1 → 2^j → 2^j + 1`, for every `j` the tree
    /// has — the steps where the most path is recomputed.
    #[test]
    fn path_eval_matches_eval_at_every_power_of_two_boundary() {
        let m = master();
        let mut pe = m.path_eval();
        for j in 1..u32::from(TREE_DEPTH) {
            let p = 1u64 << j;
            for i in [p - 1, p, p + 1] {
                assert_eq!(pe.eval(i), m.eval(i), "boundary 2^{j}: index {i}");
            }
        }
        assert_eq!(pe.eval(u64::MAX), m.eval(u64::MAX));
    }

    /// Correct in any order, including backwards and repeated; only the cost
    /// depends on the order.
    #[test]
    fn path_eval_is_correct_in_any_order() {
        let m = master();
        let mut pe = m.path_eval();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            assert_eq!(pe.eval(x), m.eval(x), "index {x}");
            assert_eq!(pe.eval(x), m.eval(x), "repeat of {x}");
        }
        for i in (0..50).rev() {
            assert_eq!(pe.eval(i), m.eval(i), "descending {i}");
        }
    }

    // ------------------------------------------------------------ the cover

    #[test]
    fn the_cover_is_exact_and_minimal_enough() {
        let m = master();
        // A range that forces a ragged cover on both ends.
        let ck = m.constrain(3, 21).expect("constrain");

        // Exactly covers, no overlap, no gap.
        let mut seen: Vec<u64> = ck.expand().into_iter().map(|(i, _)| i).collect();
        seen.dedup();
        assert_eq!(seen.len(), 19);
        assert_eq!(*seen.first().expect("nonempty"), 3);
        assert_eq!(*seen.last().expect("nonempty"), 21);

        // At most 2ℓ nodes, which is the transmitted-size bound.
        assert!(
            ck.nodes().len() <= 2 * usize::from(TREE_DEPTH),
            "cover of {} nodes exceeds the 2l bound",
            ck.nodes().len()
        );
    }

    #[test]
    fn an_aligned_power_of_two_range_is_a_single_node() {
        // [0, 2^k) is one subtree; the whole point of a GGM constrained key is
        // that this costs one key rather than 2^k.
        let ck = master().constrain(0, 255).expect("constrain");
        assert_eq!(ck.nodes().len(), 1);
        assert_eq!(ck.wire_bytes(), LAMBDA_BYTES);
    }

    #[test]
    fn the_whole_domain_is_one_node() {
        let ck = master().constrain(0, u64::MAX).expect("constrain");
        assert_eq!(ck.nodes().len(), 1);
        assert_eq!(ck.nodes()[0].depth(), 0);
    }

    #[test]
    fn a_single_leaf_is_one_node_at_full_depth() {
        // The writer-selection case: writer i gets exactly K_i.
        let ck = master().constrain(1234, 1234).expect("constrain");
        assert_eq!(ck.nodes().len(), 1);
        assert_eq!(ck.nodes()[0].depth(), TREE_DEPTH);
        assert_eq!(ck.eval(1234).expect("in range"), master().eval(1234));
        assert!(ck.eval(1235).is_err());
    }

    #[test]
    fn a_ragged_range_stays_within_the_2l_bound() {
        // Worst case for the cover: both ends maximally misaligned.
        let ck = master().constrain(1, u64::MAX - 1).expect("constrain");
        assert!(
            ck.nodes().len() <= 2 * usize::from(TREE_DEPTH),
            "{} nodes",
            ck.nodes().len()
        );
    }

    // ------------------------------------------------------- Pi_core shapes

    #[test]
    fn constrain_prefix_is_the_search_token() {
        // Search for w with counter c releases [0, c).
        let m = master();
        let ck = m.constrain_prefix(5).expect("constrain");
        assert_eq!(ck.lo(), 0);
        assert_eq!(ck.hi(), 4);
        assert_eq!(ck.expand().len(), 5);
        // Counter 5 has not been written yet, and must not be derivable —
        // this is forward privacy at the primitive level.
        assert!(ck.eval(5).is_err());
    }

    #[test]
    fn an_empty_counter_has_no_token() {
        assert!(matches!(
            master().constrain_prefix(0),
            Err(GgmError::EmptyRange { .. })
        ));
    }

    #[test]
    fn inverted_ranges_are_rejected() {
        assert!(matches!(
            master().constrain(9, 3),
            Err(GgmError::EmptyRange { lo: 9, hi: 3 })
        ));
    }

    // ---------------------------------------------------------- key hygiene

    #[test]
    fn different_masters_give_different_values() {
        let a = MasterKey::new([1u8; LAMBDA_BYTES]);
        let b = MasterKey::new([2u8; LAMBDA_BYTES]);
        assert_ne!(a.eval(7), b.eval(7));
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        assert_eq!(format!("{:?}", master()), "MasterKey(<redacted>)");
        let ck = master().constrain(0, 0).expect("constrain");
        let s = format!("{:?}", ck.nodes()[0]);
        assert!(s.contains("<redacted>"), "{s}");
    }
}
