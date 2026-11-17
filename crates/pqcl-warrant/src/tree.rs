//! The per-case warrant Merkle tree.
//!
//! The Case Authority inserts `C = H(0x30 ‖ ⟪warrant, s⟫)` as a leaf; the root
//! `ρ_W` is anchored at Tier 3. A spend proves `Path(C, π) = ρ_W` in zero
//! knowledge, so the index server learns that *some* anchored warrant is being
//! exercised without learning which leaf.
//!
//! # ⚠️ Why this is not `pqcl_forest::CustodyTree`
//!
//! It was, in the first version, and that was a defect (the design record
//! row 12a). `CustodyTree`'s internal nodes are tagged `0x11`. **The warrant
//! root and the custody forest root are both anchored on the same chain**, so
//! sharing a node tag leaves a digest reinterpretable between the two trees —
//! an internal node of one presented as an internal node of the other.
//!
//! draft6 eq. (`eq:relauth`) wrote `Path(C, π) = ρ_W` and never defined the node
//! function, which is exactly how that stayed invisible: there was nothing to
//! disagree with. The warrant tree therefore has its own node tag, `0x32`.
//!
//! # ⭐ The promotion rule, and why it is restated rather than imported
//!
//! An unpaired node is **promoted unchanged, never duplicated** — the
//! CVE-2012-2459 fix from row 8. That rule now lives in two implementations,
//! this one and `pqcl-forest`, which is a cost worth naming: two copies can
//! drift. It is accepted here because the alternative was a shared
//! implementation with a shared *tag*, which is the worse of the two problems.
//!
//! It will shortly live in a third — the SP1 guest — and row 12a is explicit
//! that the rule must hold **identically in the guest and in the host
//! verifier**. A divergence there does not fail loudly; it produces proofs that
//! verify against the wrong root. [`node`] and [`verify`] are `pub` precisely so
//! the guest calls these functions rather than reimplementing them.

use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

/// `C = H(0x30 ‖ ⟪warrant, s⟫)` — a warrant-tree leaf.
///
/// Takes the warrant's canonical **encoding**, the same bytes the Case
/// Authority signs. Committing to a separate digest here would create two
/// encodings of one object, which is how they drift apart.
#[must_use]
pub fn leaf(warrant_encoding: &[u8], secret: &Digest32) -> Digest32 {
    hash_domain(Domain::WarrantCommit, &[warrant_encoding, secret])
}

/// The warrant tree's internal node — `0x32`, never `0x11`.
#[must_use]
pub fn node(left: &Digest32, right: &Digest32) -> Digest32 {
    hash_domain(Domain::WarrantNode, &[left, right])
}

/// One step of an inclusion path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathStep {
    /// The sibling digest at this level.
    pub sibling: Digest32,
    /// Whether the sibling sits to the right of the node being proved.
    pub sibling_is_right: bool,
}

/// A Merkle path from a warrant commitment to `ρ_W`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WarrantPath {
    /// Leaf index proved.
    pub index: usize,
    /// Number of leaves when the proof was produced.
    pub count: usize,
    /// Sibling digests, leaf level upward.
    pub path: Vec<PathStep>,
}

/// Recompute the root a `(leaf, path)` pair implies.
///
/// The guest and the host must agree byte-for-byte, so both call this.
#[must_use]
pub fn root_from(leaf: Digest32, path: &WarrantPath) -> Digest32 {
    let mut acc = leaf;
    for step in &path.path {
        acc = if step.sibling_is_right {
            node(&acc, &step.sibling)
        } else {
            node(&step.sibling, &acc)
        };
    }
    acc
}

/// Whether `leaf` is committed under `root` by `path`.
#[must_use]
pub fn verify(leaf: Digest32, path: &WarrantPath, root: &Digest32) -> bool {
    root_from(leaf, path) == *root
}

/// The per-case tree of warrant commitments.
#[derive(Debug, Clone, Default)]
pub struct WarrantTree {
    leaves: Vec<Digest32>,
}

impl WarrantTree {
    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a commitment, returning its leaf index.
    pub fn insert(&mut self, commitment: Digest32) -> usize {
        self.leaves.push(commitment);
        self.leaves.len() - 1
    }

    /// `ρ_W`, or `None` for an empty tree.
    ///
    /// `None` rather than a zero digest: an empty tree has no root, and a
    /// sentinel is a value someone could later present a proof against.
    #[must_use]
    pub fn root(&self) -> Option<Digest32> {
        if self.leaves.is_empty() {
            return None;
        }
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            level = pair_up(&level);
        }
        level.first().copied()
    }

    /// An inclusion path for the leaf at `index`.
    #[must_use]
    pub fn path(&self, index: usize) -> Option<WarrantPath> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut path = Vec::new();
        let mut level = self.leaves.clone();
        let mut i = index;

        while level.len() > 1 {
            let sibling_is_right = i.is_multiple_of(2);
            let sib = if sibling_is_right {
                level.get(i + 1).copied()
            } else {
                level.get(i - 1).copied()
            };
            // No sibling means this node was promoted, so there is no step to
            // record. Pushing a self-pair here is precisely CVE-2012-2459.
            if let Some(sibling) = sib {
                path.push(PathStep {
                    sibling,
                    sibling_is_right,
                });
            }
            level = pair_up(&level);
            i /= 2;
        }

        Some(WarrantPath {
            index,
            count: self.leaves.len(),
            path,
        })
    }

    /// Number of committed warrants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

/// One level up. An unpaired final node is **promoted**, never doubled.
fn pair_up(level: &[Digest32]) -> Vec<Digest32> {
    level
        .chunks(2)
        .map(|pair| match pair {
            [l, r] => node(l, r),
            [only] => *only,
            _ => unreachable!("chunks(2) yields 1 or 2 elements"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u8) -> Digest32 {
        pqcl_primitives::xof::digest256(&[n])
    }

    #[test]
    fn a_path_verifies_for_every_leaf_at_every_size() {
        // Sizes either side of powers of two, where the promotion rule bites.
        for size in 1usize..=9 {
            let mut t = WarrantTree::new();
            for i in 0..size {
                t.insert(d(u8::try_from(i).expect("small")));
            }
            let root = t.root().expect("non-empty");
            for i in 0..size {
                let p = t.path(i).expect("in range");
                assert!(
                    verify(d(u8::try_from(i).expect("small")), &p, &root),
                    "leaf {i} of {size} failed to verify"
                );
            }
        }
    }

    /// ⭐ CVE-2012-2459, pinned for *this* tree.
    ///
    /// `pqcl-forest` has the same test. Both are needed: this is a second
    /// implementation of the promotion rule, and the whole reason it exists
    /// separately is a tag difference that a shared test would not exercise.
    #[test]
    fn duplicating_the_last_leaf_does_not_collide_with_promoting_it() {
        for size in [1usize, 3, 5, 7, 9] {
            let mut a = WarrantTree::new();
            for i in 0..size {
                a.insert(d(u8::try_from(i).expect("small")));
            }
            let mut b = a.clone();
            b.insert(d(u8::try_from(size - 1).expect("small")));

            assert_ne!(
                a.root().expect("non-empty"),
                b.root().expect("non-empty"),
                "a {size}-leaf tree and the same tree with its last leaf \
                 repeated must not share a root"
            );
        }
    }

    /// ⭐ The tag separation that this whole module exists for.
    ///
    /// If the warrant tree and the custody forest shared a node function, an
    /// internal node of one could be presented as an internal node of the
    /// other — and both roots are anchored on the same chain.
    #[test]
    fn a_warrant_node_is_not_a_forest_node() {
        let (l, r) = (d(1), d(2));
        assert_ne!(
            node(&l, &r),
            pqcl_forest::tier1::node(&l, &r),
            "warrant 0x32 and forest 0x11 must not agree on any input"
        );
    }

    #[test]
    fn a_leaf_commitment_binds_both_the_warrant_and_the_secret() {
        let s1 = d(1);
        let s2 = d(2);
        assert_ne!(leaf(b"warrant-A", &s1), leaf(b"warrant-B", &s1));
        assert_ne!(leaf(b"warrant-A", &s1), leaf(b"warrant-A", &s2));
    }

    #[test]
    fn an_empty_tree_has_no_root() {
        assert_eq!(WarrantTree::new().root(), None);
    }
}
