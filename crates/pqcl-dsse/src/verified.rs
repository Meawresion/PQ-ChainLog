//! Verified mode for round two (draft8 Phase 10 Step 1, the design record
//! §1ao.1.6).
//!
//! The server answers one bit per unlabelled probe. In verified mode it also
//! proves each bit against the anchored `0x03` roots, `MR(sorted XSet_e)`:
//!
//! * a **hit** is one inclusion proof against the epoch that holds the tag;
//! * a **miss** is a non-membership proof against **every** closed epoch: the
//!   two adjacent leaves of the sorted set that bracket the probe (or a
//!   boundary leaf, or an empty epoch).
//!
//! ⚠️ Non-membership rests on adjacency and boundaries ("index 0", "the last
//! leaf"), so the verifier recomputes the shape of every path from its claimed
//! `(index, count)` under the promote-never-duplicate rule. Without that check
//! a path could claim any position; `pqcl_forest::tier1::verify_leaf` alone
//! hashes the steps it is given and does not bind them to the position.

use std::collections::BTreeMap;

use pqcl_forest::{CustodyTree, InclusionProof};
use pqcl_primitives::xof::Digest32;

use crate::xt::{Epoch, HonestXSet, XTag};

/// One closed epoch's anchored commitment: `MR(sorted XSet_e)` and its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRoot {
    /// The Merkle root over the sorted tags (zero for an empty epoch).
    pub root: Digest32,
    /// How many tags the epoch holds.
    pub count: usize,
}

/// A bracketing leaf: the tag and its inclusion proof.
pub type Neighbour = (XTag, InclusionProof);

/// Why the probe is absent from one epoch: the leaves just below and just
/// above it in sorted order (either may be absent at a boundary).
#[derive(Debug, Clone)]
pub struct Gap {
    /// The epoch.
    pub epoch: Epoch,
    /// Largest tag below the probe, if any.
    pub lo: Option<Neighbour>,
    /// Smallest tag above the probe, if any.
    pub hi: Option<Neighbour>,
}

/// The proof accompanying one answered bit.
#[derive(Debug, Clone)]
pub enum BitProof {
    /// Present: the epoch that holds it and the inclusion proof.
    Hit {
        /// The epoch.
        epoch: Epoch,
        /// Inclusion of the probe itself.
        proof: InclusionProof,
    },
    /// Absent from every closed epoch.
    Miss(Vec<Gap>),
}

/// The server side: every closed epoch's sorted set and its tree.
#[derive(Debug, Default)]
pub struct VerifiedXSet {
    epochs: BTreeMap<Epoch, (Vec<XTag>, CustodyTree)>,
}

impl VerifiedXSet {
    /// Build from the closed epochs of an honest store.
    #[must_use]
    pub fn from_store(x: &HonestXSet) -> Self {
        let mut epochs = BTreeMap::new();
        for e in x.closed_epochs() {
            let tags: Vec<XTag> = x
                .epoch(e)
                .map(|s| s.into_iter().collect())
                .unwrap_or_default();
            let mut tree = CustodyTree::new();
            for t in &tags {
                tree.append_leaf(*t);
            }
            epochs.insert(e, (tags, tree));
        }
        Self { epochs }
    }

    /// The roots an auditor reads from the anchored `0x03` leaves.
    #[must_use]
    pub fn roots(&self) -> BTreeMap<Epoch, EpochRoot> {
        self.epochs
            .iter()
            .map(|(e, (tags, tree))| {
                (
                    *e,
                    EpochRoot {
                        root: tree.root().unwrap_or([0; 32]),
                        count: tags.len(),
                    },
                )
            })
            .collect()
    }

    /// Answer one probe with its proof.
    #[must_use]
    pub fn prove(&self, probe: &XTag) -> BitProof {
        for (e, (tags, tree)) in &self.epochs {
            if let Ok(i) = tags.binary_search(probe)
                && let Some(proof) = tree.prove(i)
            {
                return BitProof::Hit { epoch: *e, proof };
            }
        }
        let gaps = self
            .epochs
            .iter()
            .map(|(e, (tags, tree))| {
                let at = tags.partition_point(|t| t < probe);
                let lo = at
                    .checked_sub(1)
                    .and_then(|i| Some((tags[i], tree.prove(i)?)));
                let hi = tags.get(at).and_then(|t| Some((*t, tree.prove(at)?)));
                Gap { epoch: *e, lo, hi }
            })
            .collect();
        BitProof::Miss(gaps)
    }
}

/// Whether a path's steps have exactly the shape `(index, count)` implies.
fn shape_ok(p: &InclusionProof) -> bool {
    if p.index >= p.count {
        return false;
    }
    let (mut i, mut n) = (p.index, p.count);
    let mut steps = p.path.iter();
    while n > 1 {
        let right = i.is_multiple_of(2);
        let has_sibling = !right || i + 1 < n;
        if has_sibling {
            match steps.next() {
                Some(s) if s.sibling_is_right == right => {}
                _ => return false,
            }
        }
        i /= 2;
        n = n.div_ceil(2);
    }
    steps.next().is_none()
}

fn included(root: &EpochRoot, tag: &XTag, p: &InclusionProof) -> bool {
    p.count == root.count && shape_ok(p) && pqcl_forest::verify_leaf(&root.root, tag, p)
}

/// Verify one answered bit against the anchored roots. `Some(bit)` if the
/// proof establishes it, `None` if it does not. A miss must cover **every**
/// closed epoch the auditor knows of.
#[must_use]
pub fn verify_bit(
    probe: &XTag,
    proof: &BitProof,
    roots: &BTreeMap<Epoch, EpochRoot>,
) -> Option<bool> {
    match proof {
        BitProof::Hit { epoch, proof } => {
            let root = roots.get(epoch)?;
            included(root, probe, proof).then_some(true)
        }
        BitProof::Miss(gaps) => {
            if gaps.len() != roots.len() {
                return None;
            }
            for g in gaps {
                let root = roots.get(&g.epoch)?;
                let ok = match (&g.lo, &g.hi) {
                    (None, None) => root.count == 0,
                    (Some((lo, pl)), None) => {
                        lo < probe && pl.index + 1 == root.count && included(root, lo, pl)
                    }
                    (None, Some((hi, ph))) => probe < hi && ph.index == 0 && included(root, hi, ph),
                    (Some((lo, pl)), Some((hi, ph))) => {
                        lo < probe
                            && probe < hi
                            && ph.index == pl.index + 1
                            && included(root, lo, pl)
                            && included(root, hi, ph)
                    }
                };
                if !ok {
                    return None;
                }
            }
            Some(false)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::core::{Client, Op};
    use crate::xt::{HonestServer, XSetStore, XtClient, doc_id};
    use pqcl_primitives::xof::{PrfKey, digest256};

    fn fixture() -> (XtClient, HonestServer) {
        let mut c = XtClient::new(
            Client::new(PrfKey::new(digest256(b"K_S verified"))),
            PrfKey::new(digest256(b"K_X verified")),
            8,
        );
        let mut s = HonestServer::new();
        for j in 0..40u64 {
            let id = doc_id(c.epoch(), j);
            c.update(&mut s, Op::Add, b"w1", id).unwrap();
            if j % 3 == 0 {
                c.update(&mut s, Op::Add, b"w2", id).unwrap();
            }
            if j == 19 {
                c.close_epoch(&mut s);
            }
        }
        c.close_epoch(&mut s);
        (c, s)
    }

    #[test]
    fn every_answered_bit_is_proved_against_the_anchored_roots() {
        let (mut c, s) = fixture();
        let v = VerifiedXSet::from_store(&s.xset);
        let roots = v.roots();
        assert_eq!(roots.len(), 2, "two closed epochs");
        let cand = c.candidates(&s, b"w1").unwrap();
        let (t, _) = c.probe(&cand, &[b"w2"]);
        let bits = XSetStore::probe(&s, &t);
        assert!(bits.iter().any(|b| *b) && bits.iter().any(|b| !*b));
        for (p, b) in t.probes.iter().zip(&bits) {
            assert_eq!(verify_bit(p, &v.prove(p), &roots), Some(*b));
        }
    }

    #[test]
    fn a_wrong_bit_cannot_be_proved() {
        let (mut c, s) = fixture();
        let v = VerifiedXSet::from_store(&s.xset);
        let roots = v.roots();
        let cand = c.candidates(&s, b"w1").unwrap();
        let (t, _) = c.probe(&cand, &[b"w2"]);
        let bits = XSetStore::probe(&s, &t);
        let hit = t
            .probes
            .iter()
            .zip(&bits)
            .find(|(_, b)| **b)
            .map(|(p, _)| *p)
            .unwrap();
        let miss = t
            .probes
            .iter()
            .zip(&bits)
            .find(|(_, b)| !**b)
            .map(|(p, _)| *p)
            .unwrap();

        // A miss proof for a present tag: its own leaf lies between the
        // claimed neighbours, so they are not adjacent around it.
        let BitProof::Hit { epoch, .. } = v.prove(&hit) else {
            panic!("present")
        };
        let BitProof::Miss(gaps) = v.prove(&miss) else {
            panic!("absent")
        };
        assert_eq!(
            verify_bit(&hit, &BitProof::Miss(gaps.clone()), &roots),
            None
        );

        // A hit proof for an absent tag, reusing a real leaf's path.
        let real = gaps
            .iter()
            .find_map(|g| g.lo.clone().or_else(|| g.hi.clone()))
            .unwrap();
        let forged = BitProof::Hit {
            epoch,
            proof: real.1,
        };
        assert_eq!(verify_bit(&miss, &forged, &roots), None);

        // A miss that omits a closed epoch proves nothing.
        assert_eq!(
            verify_bit(&miss, &BitProof::Miss(gaps[..1].to_vec()), &roots),
            None
        );
    }

    #[test]
    fn a_boundary_cannot_be_claimed_by_a_reshaped_path() {
        let (_, s) = fixture();
        let v = VerifiedXSet::from_store(&s.xset);
        let roots = v.roots();
        let (e, root) = roots.iter().next().map(|(e, r)| (*e, *r)).unwrap();
        // The epoch's real first leaf, proved honestly, then relabelled as the
        // last leaf: the path no longer has the shape its index implies.
        let BitProof::Miss(gaps) = v.prove(&[0u8; 32]) else {
            panic!("zero tag is absent")
        };
        let first = gaps
            .iter()
            .find(|g| g.epoch == e)
            .and_then(|g| g.hi.clone())
            .unwrap();
        let mut relabelled = first.1.clone();
        relabelled.index = root.count - 1;
        let fake = Gap {
            epoch: e,
            lo: Some((first.0, relabelled)),
            hi: None,
        };
        let probe = [0xffu8; 32];
        let mut all = vec![fake];
        all.extend(gaps.into_iter().filter(|g| g.epoch != e));
        assert_eq!(verify_bit(&probe, &BitProof::Miss(all), &roots), None);
    }
}
