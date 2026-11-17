//! A plaintext inverted index — the ground truth every scheme is checked against.
//!
//! The build plan: *"Correctness before speed. Every scheme is
//! validated against a plaintext ground-truth oracle on the real corpus. A fast
//! wrong answer is worthless."*
//!
//! This is deliberately the dumbest correct implementation. It exists to
//! disagree with `Π_core`, and it can only do that job if it is obviously right
//! by inspection — so it does no deduplication tricks, no ordering cleverness,
//! and replays the update history exactly as the encrypted scheme must.
//!
//! **This is a reference implementation, not a stand-in.** Ground rule #1
//! requires it rather than forbidding it: what the rule bans is substituting
//! something hollow for the *system under test*, and this oracle is precisely
//! the instrument that catches that. Nothing here is ever measured, and nothing
//! here stands in for `Π_core` — both are run, and the point is the comparison.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::{DocId, Op};

/// A plaintext inverted index over `(keyword → document set)`.
#[derive(Debug, Default, Clone)]
pub struct Oracle {
    index: BTreeMap<Vec<u8>, BTreeSet<DocId>>,
    updates: usize,
}

impl Oracle {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply the same update the encrypted scheme is given.
    pub fn update(&mut self, op: Op, w: &[u8], id: DocId) {
        let set = self.index.entry(w.to_vec()).or_default();
        match op {
            Op::Add => {
                set.insert(id);
            }
            Op::Del => {
                set.remove(&id);
            }
        }
        self.updates += 1;
    }

    /// The true `DB(w)`.
    ///
    /// A keyword that was added and then fully deleted returns an empty set,
    /// **not** absence — the distinction matters, because `Π_core` still has a
    /// non-zero counter for it and must still return an empty result rather
    /// than refusing to search.
    #[must_use]
    pub fn search(&self, w: &[u8]) -> BTreeSet<DocId> {
        self.index.get(w).cloned().unwrap_or_default()
    }

    /// Every keyword ever updated, including ones now empty.
    pub fn keywords(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.index.keys()
    }

    /// Distinct keywords.
    #[must_use]
    pub fn keyword_count(&self) -> usize {
        self.index.len()
    }

    /// Total updates applied — the `N` in the correctness bound.
    #[must_use]
    pub const fn update_count(&self) -> usize {
        self.updates
    }

    /// Live `(keyword, document)` pairs. This is the quantity compaction costs
    /// `O(·)` in, and what a redaction sweep must enumerate.
    #[must_use]
    pub fn live_pairs(&self) -> usize {
        self.index.values().map(BTreeSet::len).sum()
    }
}
