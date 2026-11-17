//! Tier 1 — one capsule's custody tree.
//!
//! A binary Merkle tree over one capsule's custody records, in event order:
//!
//! ```text
//! L_j     = H(0x10 ‖ ⟪CR_j⟫)          leaf
//! N(u,v)  = H(0x11 ‖ ⟪u, v⟫)          internal node
//! R_cap   = MR(L_0, …, L_j)
//! ```
//!
//! # Why this tier exists at all
//!
//! It is the reason `PQ-ChainLog` can hand a court **one capsule's complete
//! custody history** without revealing the shape of the rest of the case. A
//! flat MMR over every record cannot do that: the inclusion path itself would
//! leak case size and activity shape. The project rules lists per-capsule
//! selective disclosure as a live novelty claim, and this tier is what makes it
//! true rather than aspirational.
//!
//! # Distinct leaf and internal tags
//!
//! `0x10` and `0x11` are not decoration. Without them a Merkle tree admits
//! second-preimage attacks: an attacker presents an internal node as if it were
//! a leaf, and a 64-byte "record" whose halves are two real digests verifies
//! against a root it was never in. The tag makes the two domains disjoint.

use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

/// A Merkle tree over one capsule's custody records.
///
/// ⭐ **Every level is kept** (M13 A10, `audit/06` D9). `prove` and `root`
/// used to clone the leaves and rebuild the whole tree on every call — `n − 1`
/// node hashes each — so a bundle of `n` proofs cost `O(n²)` and `account()`'s
/// membership predicate grew with the target set squared. Now an append
/// rehashes only its own path to the root (`⌈log₂ n⌉` nodes), and `prove` and
/// `root` hash nothing. The tree they describe is unchanged: an unpaired final
/// node is still promoted, never doubled.
#[derive(Debug, Clone, Default)]
pub struct CustodyTree {
    /// `levels[0]` is the leaves; `levels.last()` holds the root alone.
    levels: Vec<Vec<Digest32>>,
}

/// One step of an inclusion proof: a sibling digest and which side it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    /// The sibling's digest.
    pub sibling: Digest32,
    /// True if the sibling is the **right** child, i.e. we are the left.
    pub sibling_is_right: bool,
}

/// A Tier-1 inclusion proof: `O(log n)` siblings from leaf to root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Position of the record in event order.
    pub index: usize,
    /// Number of records in the tree when the proof was made.
    pub count: usize,
    /// Sibling path, leaf-ward first.
    pub path: Vec<ProofStep>,
}

impl InclusionProof {
    /// Proof size in bytes — what a disclosure bundle actually carries.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.path.len() * (core::mem::size_of::<Digest32>() + 1)
    }
}

/// `L_j = H(0x10 ‖ ⟪CR_j⟫)`.
#[must_use]
pub fn leaf(record: &[u8]) -> Digest32 {
    hash_domain(Domain::CustodyRecord, &[record])
}

/// `N(u,v) = H(0x11 ‖ ⟪u, v⟫)`.
#[must_use]
pub fn node(left: &Digest32, right: &Digest32) -> Digest32 {
    #[cfg(test)]
    tests::NODE_HASHES.with(|c| c.set(c.get() + 1));
    hash_domain(Domain::MerkleInternal, &[left, right])
}

impl CustodyTree {
    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a custody record's serialized bytes, returning its index.
    pub fn append(&mut self, record: &[u8]) -> usize {
        self.append_leaf(leaf(record))
    }

    /// Append a pre-computed leaf digest.
    ///
    /// The new leaf is the last node of every level on its way up, so only
    /// that path changes: at each level it is either paired with its left
    /// neighbour or, with none to its right yet, promoted.
    pub fn append_leaf(&mut self, digest: Digest32) -> usize {
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        self.levels[0].push(digest);
        let index = self.levels[0].len() - 1;
        let (mut i, mut k) = (index, 0);
        while self.levels[k].len() > 1 {
            let level = &self.levels[k];
            let up = if i % 2 == 1 {
                node(&level[i - 1], &level[i])
            } else {
                level[i]
            };
            if self.levels.len() == k + 1 {
                self.levels.push(Vec::new());
            }
            let parent = &mut self.levels[k + 1];
            i /= 2;
            if i < parent.len() {
                parent[i] = up;
            } else {
                parent.push(up);
            }
            k += 1;
        }
        index
    }

    fn leaves(&self) -> &[Digest32] {
        self.levels.first().map_or(&[], Vec::as_slice)
    }

    /// Number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves().len()
    }

    /// Whether the capsule has no custody records yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves().is_empty()
    }

    /// `R_cap`, the current root, or `None` for an empty tree.
    ///
    /// Deliberately `None` rather than a zero digest: an empty tree has no
    /// root, and a sentinel would be a value someone could later present a
    /// proof against.
    #[must_use]
    pub fn root(&self) -> Option<Digest32> {
        self.levels.last().and_then(|top| top.first()).copied()
    }

    /// An inclusion proof for the record at `index`.
    #[must_use]
    pub fn prove(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.len() {
            return None;
        }
        let mut path = Vec::new();
        let mut i = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_is_right = i.is_multiple_of(2);
            // An odd final node is promoted unchanged rather than paired with
            // itself. Duplicating it is the classic CVE-2012-2459 shape, where
            // two distinct leaf lists yield the same root.
            let sib = if sibling_is_right {
                level.get(i + 1).copied()
            } else {
                level.get(i - 1).copied()
            };
            if let Some(sibling) = sib {
                path.push(ProofStep {
                    sibling,
                    sibling_is_right,
                });
            }
            i /= 2;
        }

        Some(InclusionProof {
            index,
            count: self.len(),
            path,
        })
    }
}

/// Verify an inclusion proof against a root.
///
/// Takes the **record bytes**, not a leaf digest, so a caller cannot
/// accidentally verify an internal node as a leaf — the `0x10` tag is applied
/// here rather than trusted from the caller.
#[must_use]
pub fn verify(root: &Digest32, record: &[u8], proof: &InclusionProof) -> bool {
    verify_leaf(root, &leaf(record), proof)
}

/// Verify against a pre-computed leaf digest.
#[must_use]
pub fn verify_leaf(root: &Digest32, leaf_digest: &Digest32, proof: &InclusionProof) -> bool {
    if proof.index >= proof.count {
        return false;
    }
    let mut acc = *leaf_digest;
    for step in &proof.path {
        acc = if step.sibling_is_right {
            node(&acc, &step.sibling)
        } else {
            node(&step.sibling, &acc)
        };
    }
    acc == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// How many internal nodes this thread has hashed.
        pub(super) static NODE_HASHES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    fn hashes_during(f: impl FnOnce()) -> usize {
        let before = NODE_HASHES.with(core::cell::Cell::get);
        f();
        NODE_HASHES.with(core::cell::Cell::get) - before
    }

    /// The tree as `pair_up` defined it before A10, rebuilt from scratch: the
    /// reference the cached levels must reproduce.
    fn reference_root(leaves: &[Digest32]) -> Digest32 {
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i + 1 < level.len() {
                next.push(node(&level[i], &level[i + 1]));
                i += 2;
            }
            if i < level.len() {
                next.push(level[i]);
            }
            level = next;
        }
        level[0]
    }

    /// ⭐ **Acceptance A10: `prove` and `root` hash nothing, and an append
    /// hashes at most `⌈log₂ n⌉` nodes.** Before A10 each `prove` rebuilt the
    /// tree, `n − 1` hashes, so this fails on the old code by three orders of
    /// magnitude at `n = 4096`.
    #[test]
    fn prove_and_root_are_lookups_and_an_append_is_one_path() {
        let n = 4096usize;
        let t = tree_of(n);
        assert_eq!(
            hashes_during(|| {
                core::hint::black_box(t.root());
            }),
            0,
            "root rehashed"
        );
        for i in [0, 1, n / 2, n - 1] {
            assert_eq!(
                hashes_during(|| {
                    core::hint::black_box(t.prove(i));
                }),
                0,
                "prove({i}) rehashed"
            );
        }
        let mut t = t;
        let bound = usize::try_from((n + 1).ilog2() + 1).unwrap_or(usize::MAX);
        let used = hashes_during(|| {
            core::hint::black_box(t.append(b"one more"));
        });
        assert!(
            used <= bound,
            "an append hashed {used} nodes, bound {bound}"
        );
    }

    /// The cached tree is the same tree: its root equals a from-scratch
    /// rebuild after every append, across the promotion boundaries.
    #[test]
    fn cached_levels_match_a_rebuild_after_every_append() {
        let mut t = CustodyTree::new();
        let mut leaves = Vec::new();
        for i in 0..70 {
            let r = format!("CR-{i}");
            t.append(r.as_bytes());
            leaves.push(leaf(r.as_bytes()));
            assert_eq!(
                t.root(),
                Some(reference_root(&leaves)),
                "after {} leaves",
                i + 1
            );
        }
    }

    fn tree_of(n: usize) -> CustodyTree {
        let mut t = CustodyTree::new();
        for i in 0..n {
            t.append(format!("CR-{i}").as_bytes());
        }
        t
    }

    #[test]
    fn an_empty_tree_has_no_root() {
        assert!(CustodyTree::new().root().is_none());
    }

    #[test]
    fn every_record_proves_against_the_root() {
        // Sizes either side of powers of two, where the odd-node promotion
        // rule is exercised.
        for n in [1usize, 2, 3, 4, 5, 7, 8, 9, 16, 33] {
            let t = tree_of(n);
            let root = t.root().expect("non-empty");
            for i in 0..n {
                let proof = t.prove(i).expect("in range");
                assert!(
                    verify(&root, format!("CR-{i}").as_bytes(), &proof),
                    "record {i} of {n} failed to verify"
                );
            }
        }
    }

    #[test]
    fn a_proof_does_not_verify_against_the_wrong_record() {
        let t = tree_of(8);
        let root = t.root().expect("non-empty");
        let proof = t.prove(3).expect("in range");
        assert!(!verify(&root, b"CR-4", &proof));
        assert!(!verify(&root, b"tampered", &proof));
    }

    #[test]
    fn a_proof_does_not_verify_against_another_capsules_root() {
        let a = tree_of(8);
        let mut b = CustodyTree::new();
        for i in 0..8 {
            b.append(format!("OTHER-{i}").as_bytes());
        }
        let proof = a.prove(2).expect("in range");
        assert!(!verify(&b.root().expect("non-empty"), b"CR-2", &proof));
    }

    #[test]
    fn an_internal_node_cannot_be_presented_as_a_leaf() {
        // The reason 0x11 exists. Take a real internal node's preimage — two
        // real digests — and try to pass it off as a record.
        let t = tree_of(4);
        let root = t.root().expect("non-empty");

        let l0 = leaf(b"CR-0");
        let l1 = leaf(b"CR-1");
        let internal = node(&l0, &l1);

        // The 64-byte concatenation that produced `internal`.
        let mut forged_record = Vec::new();
        forged_record.extend_from_slice(&l0);
        forged_record.extend_from_slice(&l1);

        // If leaves and internal nodes shared a tag, `leaf(forged_record)`
        // would equal `internal` and a second-preimage would exist.
        assert_ne!(
            leaf(&forged_record),
            internal,
            "leaf and internal domains collide: the tree admits second preimages"
        );

        // And the forged record does not verify anywhere in the tree.
        for i in 0..t.len() {
            let proof = t.prove(i).expect("in range");
            assert!(!verify(&root, &forged_record, &proof));
        }
    }

    #[test]
    fn duplicating_the_last_event_does_not_collide_with_promoting_it() {
        // ⭐ The CVE-2012-2459 property, pinned so it cannot reopen.
        //
        // draft6 eq. (eq:tier1) originally specified *duplicating* an unpaired
        // node. Under that rule MR([a,b,c]) and MR([a,b,c,c]) are the same
        // root, so a three-event chain and a four-event chain whose last event
        // repeats would anchor identically. The design record
        // changed the paper to *promote* instead; this asserts the code has the
        // property the paper now claims.
        let mut three = CustodyTree::new();
        for r in ["CR-a", "CR-b", "CR-c"] {
            three.append(r.as_bytes());
        }
        let mut four = CustodyTree::new();
        for r in ["CR-a", "CR-b", "CR-c", "CR-c"] {
            four.append(r.as_bytes());
        }

        assert_ne!(
            three.root().expect("non-empty"),
            four.root().expect("non-empty"),
            "MR([a,b,c]) collides with MR([a,b,c,c]): the tree duplicates              unpaired nodes again and a repeated final custody event is              indistinguishable from its absence"
        );

        // Same at every odd size, since the promotion rule applies per level.
        for n in [1usize, 3, 5, 7, 9, 11] {
            let mut a = CustodyTree::new();
            for i in 0..n {
                a.append(format!("CR-{i}").as_bytes());
            }
            let mut b = a.clone();
            b.append(format!("CR-{}", n - 1).as_bytes());
            assert_ne!(
                a.root().expect("non-empty"),
                b.root().expect("non-empty"),
                "collision at n = {n}"
            );
        }
    }

    #[test]
    fn appending_changes_the_root() {
        // Custody is append-only, so every new event must move the root or the
        // chain would not commit to it.
        let mut t = tree_of(4);
        let before = t.root().expect("non-empty");
        t.append(b"CR-4");
        assert_ne!(before, t.root().expect("non-empty"));
    }

    #[test]
    fn a_stale_proof_fails_against_a_later_root() {
        // A proof made at count=4 must not verify against the root at count=5,
        // or a disclosure could omit later custody events.
        let mut t = tree_of(4);
        let proof = t.prove(1).expect("in range");
        t.append(b"CR-4");
        assert!(!verify(&t.root().expect("non-empty"), b"CR-1", &proof));
    }

    #[test]
    fn proof_size_is_logarithmic() {
        // What a disclosure bundle carries per event.
        let t = tree_of(1024);
        let proof = t.prove(500).expect("in range");
        assert_eq!(proof.path.len(), 10);
        assert_eq!(proof.wire_bytes(), 10 * 33);
    }

    #[test]
    fn an_out_of_range_index_has_no_proof() {
        assert!(tree_of(4).prove(4).is_none());
    }

    #[test]
    fn a_proof_claiming_an_impossible_index_is_rejected() {
        let t = tree_of(4);
        let root = t.root().expect("non-empty");
        let mut proof = t.prove(1).expect("in range");
        proof.index = 99;
        assert!(!verify(&root, b"CR-1", &proof));
    }
}
