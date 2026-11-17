//! The binary tree of Zuo et al. TDSC 2022, Algorithm 1.
//!
//! `TGen(d)` builds a **perfect** binary tree over `2^ℓ` leaves, where
//! `2^{ℓ−1} < d ≤ 2^ℓ`. Leaves carry range values; a leaf for `v ≥ d` exists to
//! keep the tree perfect and is never updated.
//!
//! Nodes are named by their leftmost and rightmost leaf values — the paper's
//! `w_{ab}` — so a leaf is `w_{vv}`. That naming is the node's identity as a
//! keyword, so it is what gets hashed.
//!
//! ⭐ **The tree is never materialised.** Algorithm 1 describes pointer
//! plumbing, but every operation it supports is arithmetic on `(a, b)` ranges:
//! a node's parent, its children, and whether two nodes are siblings are all
//! determined by the value interval. Allocating `2^{ℓ+1} − 1` node objects to
//! rediscover that would only add memory to the baseline's measured cost.

/// A node, identified by the leaf-value interval it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Node {
    /// Leftmost leaf value.
    pub a: u64,
    /// Rightmost leaf value.
    pub b: u64,
}

impl Node {
    /// The keyword bytes this node hashes as.
    ///
    /// A fixed 16-byte encoding rather than a formatted string: `w_{1,23}` and
    /// `w_{12,3}` render identically once the punctuation is dropped, and a
    /// keyword collision here silently merges two subtrees.
    #[must_use]
    pub fn keyword(self) -> [u8; 16] {
        let mut k = [0u8; 16];
        k[..8].copy_from_slice(&self.a.to_be_bytes());
        k[8..].copy_from_slice(&self.b.to_be_bytes());
        k
    }

    /// A leaf covers exactly one value, so its interval is degenerate.
    #[must_use]
    pub const fn is_leaf(self) -> bool {
        self.a == self.b
    }
}

/// A perfect binary tree over `2^ℓ` leaves. `TGen(d)`.
#[derive(Debug, Clone, Copy)]
pub struct BinaryTree {
    /// `ℓ`, the number of levels below the root.
    pub levels: u32,
    /// The caller's `d` — the number of *usable* range values.
    pub d: u64,
}

impl BinaryTree {
    /// `TGen(d)`.
    ///
    /// # Panics
    ///
    /// If `d` is zero. Algorithm 1 returns `⊥` there; a tree with no values is
    /// not something a caller can do anything useful with, and returning an
    /// `Option` would push the check to every call site.
    #[must_use]
    pub fn new(d: u64) -> Self {
        assert!(d > 0, "TGen(d) is undefined for d = 0");
        // Smallest ℓ with 2^ℓ ≥ d.
        let mut levels = 0u32;
        while (1u64 << levels) < d {
            levels += 1;
        }
        Self { levels, d }
    }

    /// Number of leaves, `2^ℓ` — including the padding leaves that make the
    /// tree perfect when `d` is not a power of two.
    #[must_use]
    pub const fn leaves(self) -> u64 {
        1u64 << self.levels
    }

    /// The root.
    #[must_use]
    pub const fn root(self) -> Node {
        Node {
            a: 0,
            b: self.leaves() - 1,
        }
    }

    /// `TPath(v, BT)` — the leaf for `v` and every ancestor up to the root.
    ///
    /// # Panics
    ///
    /// If `v >= d`. The padding leaves are structural; updating one would put a
    /// value outside the declared range into the index.
    #[must_use]
    pub fn path(self, v: u64) -> Vec<Node> {
        assert!(v < self.d, "value {v} is outside the range [0, {})", self.d);

        let mut out = Vec::with_capacity(self.levels as usize + 1);
        let mut span = 1u64;
        loop {
            let a = (v / span) * span;
            out.push(Node { a, b: a + span - 1 });
            if span == self.leaves() {
                break;
            }
            span *= 2;
        }
        out
    }

    /// `TGetCover(q, BT)` — the best range cover of `[a, b]`.
    ///
    /// Algorithm 1's bottom-up merge, verbatim in effect: start from the leaves
    /// of the range, repeatedly fold sibling pairs into their parent, and emit
    /// whatever cannot be paired.
    ///
    /// # Panics
    ///
    /// If the range is empty or runs past `d`.
    #[must_use]
    pub fn cover(self, from: u64, to: u64) -> Vec<Node> {
        assert!(from <= to, "an empty range has no cover");
        assert!(to < self.d, "range end {to} is outside [0, {})", self.d);

        let mut cover = Vec::new();
        let mut level_span = 1u64;
        let mut lo = from;
        let mut hi = to;

        loop {
            // A node at this level is aligned when its start is a multiple of
            // the span. An unaligned left edge, or a right edge that does not
            // complete a node, cannot be folded upward and is emitted here.
            if lo > hi {
                break;
            }
            if level_span == self.leaves() {
                cover.push(Node {
                    a: lo * level_span,
                    b: (hi + 1) * level_span - 1,
                });
                break;
            }

            if !lo.is_multiple_of(2) {
                cover.push(Node {
                    a: lo * level_span,
                    b: (lo + 1) * level_span - 1,
                });
                lo += 1;
            }
            if lo > hi {
                break;
            }
            if hi.is_multiple_of(2) {
                cover.push(Node {
                    a: hi * level_span,
                    b: (hi + 1) * level_span - 1,
                });
                if hi == 0 {
                    break;
                }
                hi -= 1;
            }
            if lo > hi {
                break;
            }

            lo /= 2;
            hi /= 2;
            level_span *= 2;
        }

        cover.sort_unstable();
        cover
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §2.2: *"For v = 1 (or the leaf w1), the set PT = {w1, w01, w03, w07}."*
    /// That is d = 5, so ℓ = 3 and the tree has 8 leaves.
    #[test]
    fn the_papers_path_example() {
        let bt = BinaryTree::new(5);
        assert_eq!(bt.levels, 3);
        assert_eq!(bt.leaves(), 8);

        let got: Vec<(u64, u64)> = bt.path(1).iter().map(|n| (n.a, n.b)).collect();
        assert_eq!(got, vec![(1, 1), (0, 1), (0, 3), (0, 7)]);
    }

    /// §2.2: *"Consider the tree depicted in Fig. 2c, BRC = {w23, w4} for range
    /// query q = [2, 4]."*
    #[test]
    fn the_papers_cover_example() {
        let bt = BinaryTree::new(5);
        let got: Vec<(u64, u64)> = bt.cover(2, 4).iter().map(|n| (n.a, n.b)).collect();
        assert_eq!(got, vec![(2, 3), (4, 4)]);
    }

    #[test]
    fn a_full_range_collapses_to_the_root() {
        let bt = BinaryTree::new(8);
        assert_eq!(bt.cover(0, 7), vec![bt.root()]);
    }

    #[test]
    fn a_single_value_is_its_own_leaf() {
        let bt = BinaryTree::new(16);
        assert_eq!(bt.cover(5, 5), vec![Node { a: 5, b: 5 }]);
    }

    /// The cover must be exact: every leaf in the range, and no leaf outside
    /// it. A cover that over-reaches would return files the query did not ask
    /// for, which no functional test on a sparse index would necessarily catch.
    #[test]
    fn covers_are_exact_over_every_range() {
        for d in [3u64, 5, 8, 13, 16, 17] {
            let bt = BinaryTree::new(d);
            for from in 0..d {
                for to in from..d {
                    let mut covered: Vec<u64> = Vec::new();
                    for n in bt.cover(from, to) {
                        assert!(n.a <= n.b);
                        covered.extend(n.a..=n.b);
                    }
                    covered.sort_unstable();
                    let want: Vec<u64> = (from..=to).collect();
                    assert_eq!(covered, want, "cover of [{from},{to}] over d={d} is wrong");
                }
            }
        }
    }

    /// Every node in a cover must be a real node of the tree, i.e. reachable as
    /// an ancestor of one of its own leaves. A cover of arbitrary intervals
    /// would be cheaper and completely wrong.
    #[test]
    fn cover_nodes_are_real_tree_nodes() {
        for d in [5u64, 8, 13, 16] {
            let bt = BinaryTree::new(d);
            for from in 0..d {
                for to in from..d {
                    for n in bt.cover(from, to) {
                        let leaf = n.a.min(bt.d - 1);
                        assert!(
                            bt.path(leaf).contains(&n),
                            "{n:?} is not an ancestor of leaf {leaf} in d={d}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_leaf_is_a_degenerate_node() {
        assert!(Node { a: 4, b: 4 }.is_leaf());
        assert!(!Node { a: 4, b: 5 }.is_leaf());
    }

    /// The keyword encoding must not let two distinct nodes collide.
    #[test]
    fn node_keywords_are_injective() {
        let bt = BinaryTree::new(16);
        let mut seen = std::collections::HashSet::new();
        for v in 0..bt.d {
            for n in bt.path(v) {
                seen.insert(n.keyword());
            }
        }
        let mut nodes = std::collections::HashSet::new();
        for v in 0..bt.d {
            for n in bt.path(v) {
                nodes.insert(n);
            }
        }
        assert_eq!(
            seen.len(),
            nodes.len(),
            "two distinct nodes share a keyword"
        );
    }
}
