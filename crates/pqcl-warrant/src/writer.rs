//! Writer selection — `K_i = GGM(K_case, i)`, draft6 eq. (`eq:writerkey`).
//!
//! DSSE is single-writer; PQ-ChainLog has many Edge Log Agents writing one
//! index. Rather than resolve that with a shared key and a hardware assumption,
//! the GGM tree already underlying `Π_core` is applied to the **writer-
//! identifier** space instead of the counter space.
//!
//! Agent `i` receives only `K_i` at enrollment and can derive neither `K_j` for
//! `j ≠ i` nor the root. A reader authorised over a writer set `S` receives the
//! minimal covering set of subtree roots — `O(log W)` keys for a contiguous
//! range — and can derive `K_i` for `i ∈ S` and nothing outside it.
//!
//! # Why this sits next to [`crate::delegate`]
//!
//! They are the same idea pointed in opposite directions, and seeing them
//! together is the point: `delegate` constrains **read** authority to a range of
//! keyword classes, this constrains **write** authority to a range of agent
//! identifiers, and both are GGM covers rooted in `K_case`. Neither needs a
//! pairing, a key-aggregate scheme or a trusted setup.
//!
//! # What this buys, and the gap it does not close
//!
//! Three consequences, all from draft6 §V-D:
//!
//! - The Secure Module drops from *the source of* writer separation to
//!   **defence in depth**, because separation now holds cryptographically.
//! - Adversary A3 improves: compromising an agent yields that agent's key, not
//!   the case write key.
//! - Revocation becomes cryptographic — exclude the leaf from subsequently
//!   issued constrained keys and let compaction re-key.
//!
//! ⚠️ **The honest cost, which the paper records as a genuine gap:** search runs
//! `O(|S|)` per-writer searches where a key-aggregate scheme such as `BiMM` uses
//! one aggregate key. We pay `|S|` symmetric searches, which parallelise; `BiMM`
//! pays group exponentiation and pairing-based aggregation and is not
//! post-quantum. We also offer writer selection **only** — `BiMM` offers
//! *bilateral* selection, and our reader side is enforced by warrant policy
//! rather than cryptographically.

use pqcl_ggm::{ConstrainedKey, GgmError, MasterKey};
use pqcl_primitives::xof::{Digest32, PrfKey};

/// An Edge Log Agent's identifier — a leaf index in the writer tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WriterId(pub u64);

/// The case's writer-identifier tree, rooted at `K_case`.
///
/// ⚠️ **Rooted at `K_case` directly, with no intervening label**, because
/// draft6 eq. (`eq:writerkey`) writes `K_i = GGM(K_case, i)` and not
/// `GGM(F(K_case, …), i)`. Adding a label here would be a reasonable-looking
/// improvement that makes every agent key in the system disagree with the
/// paper. The separation from the rest of the hierarchy comes from the
/// construction rather than the input: the hierarchy uses the PRF `F`, this
/// uses the PRG `G`, and eq. (2) gives them different role bytes.
pub struct WriterTree {
    root: MasterKey,
}

impl WriterTree {
    /// Build the writer tree for a case.
    #[must_use]
    pub fn new(case_key: &PrfKey) -> Self {
        Self {
            root: MasterKey::new(*case_key.as_bytes()),
        }
    }

    /// `K_i` — the key issued to agent `i` at enrollment.
    ///
    /// This is all the agent ever receives. It cannot walk upward to the root
    /// or sideways to a sibling, because GGM evaluation is one-way.
    #[must_use]
    pub fn enroll(&self, agent: WriterId) -> Digest32 {
        self.root.eval(agent.0)
    }

    /// The minimal covering set for readers authorised over `[lo, hi]`.
    ///
    /// `O(log W)` subtree roots for a contiguous range, from which exactly the
    /// keys in range are derivable.
    ///
    /// # Errors
    ///
    /// [`GgmError::EmptyRange`] if `lo > hi` — an authority over no writers is
    /// a caller error, not a null grant.
    pub fn authorize_range(&self, lo: WriterId, hi: WriterId) -> Result<WriterSet, GgmError> {
        Ok(WriterSet {
            key: self.root.constrain(lo.0, hi.0)?,
        })
    }
}

impl core::fmt::Debug for WriterTree {
    /// Never prints key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WriterTree(<redacted>)")
    }
}

/// Authority over a contiguous set of writers.
#[derive(Debug)]
pub struct WriterSet {
    key: ConstrainedKey,
}

impl WriterSet {
    /// `K_i` for an authorised writer.
    ///
    /// # Errors
    ///
    /// [`GgmError::OutOfRange`] outside the authorised set — and, as in
    /// [`crate::delegate`], that error comes from the key not covering the
    /// index, not from a policy check in this function.
    pub fn writer_key(&self, agent: WriterId) -> Result<Digest32, GgmError> {
        self.key.eval(agent.0)
    }

    /// Wire size of the covering set, in bytes.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.key.wire_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case() -> PrfKey {
        PrfKey::new(pqcl_primitives::xof::digest256(b"case-A"))
    }

    /// ⭐ The property the whole construction exists for: a compromised agent
    /// yields that agent's key and nothing else.
    #[test]
    fn an_agent_key_does_not_reveal_another_agents_key() {
        let t = WriterTree::new(&case());
        let mine = t.enroll(WriterId(7));

        for other in [0u64, 6, 8, 1_000, u64::MAX] {
            assert_ne!(
                mine,
                t.enroll(WriterId(other)),
                "K_7 must not equal K_{other}"
            );
        }
    }

    /// And it must not equal the root it descends from, or a compromised agent
    /// would hold the case write key — exactly the A3 improvement claimed.
    #[test]
    fn an_agent_key_is_not_the_case_key() {
        let k_case = case();
        let t = WriterTree::new(&k_case);
        for agent in [0u64, 1, 42] {
            assert_ne!(&t.enroll(WriterId(agent)), k_case.as_bytes());
        }
    }

    #[test]
    fn a_reader_derives_exactly_the_authorised_writers() {
        let t = WriterTree::new(&case());
        let s = t
            .authorize_range(WriterId(4), WriterId(11))
            .expect("valid range");

        for inside in [4u64, 7, 11] {
            assert_eq!(
                s.writer_key(WriterId(inside)).expect("authorised"),
                t.enroll(WriterId(inside)),
                "an authorised writer's key must match the tree's own"
            );
        }
        for outside in [3u64, 12, 0, u64::MAX] {
            assert!(
                s.writer_key(WriterId(outside)).is_err(),
                "writer {outside} is outside [4,11] and must be underivable"
            );
        }
    }

    /// The covering set is `O(log W)`, not `O(|S|)` — that is what makes reader
    /// authorisation over a wide range cheap to transmit.
    #[test]
    fn a_wide_authority_still_fits_in_a_logarithmic_covering_set() {
        let t = WriterTree::new(&case());
        let wide = t
            .authorize_range(WriterId(0), WriterId(1_000_000))
            .expect("valid range");
        // ℓ = 64, so at most 2ℓ = 128 nodes of 32 bytes.
        assert!(
            wide.wire_bytes() <= 128 * 32,
            "covering set was {} bytes, above the 2ℓ bound",
            wide.wire_bytes()
        );
    }

    #[test]
    fn an_inverted_writer_range_is_rejected() {
        let t = WriterTree::new(&case());
        assert!(t.authorize_range(WriterId(9), WriterId(4)).is_err());
    }
}
