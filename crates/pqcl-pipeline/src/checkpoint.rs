//! Phase 1 Step 3 and Phase 7 Steps 3–4 (draft8, D4 + P5): case registration,
//! the epoch checkpoint chain, and the M-of-N approval set.
//!
//! ```text
//! reg   = H(0x15 ‖ ⟪cid, pk_SIG, pk_KEM, pk_SLH, {pk_Cj}, M, Δ, ρ_c⟫)   eq:reg
//! ρ_c   = H(0x16 ‖ ⟪ρ⟫),  ρ = {(id, role, pk)}                         (§1br F3)
//! d_e   = H(0x12 ‖ ⟪cid, e, R_e, n_e, d_{e−1}⟫),         d_{−1} = reg  eq:checkpoint
//! A_e   = H(0x13 ‖ ⟪S_e, σ_SLH⟫)                                       eq:anchortx
//! anchor: commitRoot(cid, R_e, d_{e−1}, d_e, A_e)
//! ```
//!
//! ⭐ **`n_e` is the epoch's own leaf count, and it is not on chain** (M13 A21,
//! amending D4). `d_e` commits to it, so an auditor still verifies it — from the
//! audit package, which D4 already made mandatory for the approvals. A public
//! cumulative count made case size public (`audit/07` D2), and since A20 gave
//! every epoch its own MMR there is no cumulative count to publish: `n_e` does
//! not grow monotonically and an epoch may legitimately hold fewer leaves than
//! its predecessor. The design record has the full argument.
//!
//! ⭐ **No signature goes on chain** (user decision D4, 2026-10-06). Each
//! custodian signs `d_e` with ML-DSA independently; `M` distinct valid
//! signatures from the registered set approve it, and the co-signer adds
//! SLH-DSA. The chain stores `d_e` and `A_e` only, so the anchor's size does not
//! depend on the signature scheme; the signatures travel in the off-chain audit
//! package, and an auditor checks them against `A_e` and the registered keys.
//!
//! The `d_{e−1}` link makes the checkpoints a chain back to `reg`: an auditor
//! verifies that the history was **extended**, not merely that it grew.

use pqcl_primitives::xof::{Digest32, Domain, hash_domain};
use pqcl_primitives::{CoSigner, SoftwareMlDsa, sig, slh};

/// ML-DSA / SLH-DSA context string for checkpoint approvals. Distinct from any
/// other signing context, so an approval cannot be replayed as another object.
pub const APPROVAL_CONTEXT: &[u8] = b"pqcl-checkpoint";

/// What the Case Authority registers once, before the first checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// `cid`.
    pub cid: Digest32,
    /// The CA's ML-DSA key.
    pub pk_sig: Vec<u8>,
    /// The CA's ML-KEM key.
    pub pk_kem: Vec<u8>,
    /// The co-signer's SLH-DSA key.
    pub pk_slh: Vec<u8>,
    /// The custodians' ML-DSA keys, in index order `j = 0..N`.
    pub custodians: Vec<Vec<u8>>,
    /// Approvals required, `M`.
    pub m: u32,
    /// The epoch period `Δ`, in seconds.
    pub delta: u64,
    /// `ρ_c`, the commitment to the enrolled actors' roster
    /// (`crate::accept::Roster::digest`, §1br F3). The roster itself is
    /// released only to a court, sealed; the committee keys above are a
    /// separate set and stay separate.
    pub roster: Digest32,
}

impl Registration {
    /// `reg`, the checkpoint chain's `d_{−1}`.
    #[must_use]
    pub fn digest(&self) -> Digest32 {
        let custodians = encode_list(&self.custodians);
        hash_domain(
            Domain::CaseRegistration,
            &[
                &self.cid,
                &self.pk_sig,
                &self.pk_kem,
                &self.pk_slh,
                &custodians,
                &self.m.to_le_bytes(),
                &self.delta.to_le_bytes(),
                &self.roster,
            ],
        )
    }
}

/// A list of byte strings as one field: each framed, so the list is injective.
fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for i in items {
        out.extend_from_slice(&(i.len() as u64).to_le_bytes());
        out.extend_from_slice(i);
    }
    out
}

/// `d_e`.
#[must_use]
pub fn checkpoint(cid: &Digest32, e: u64, root: &Digest32, n_e: u64, prev: &Digest32) -> Digest32 {
    hash_domain(
        Domain::Checkpoint,
        &[cid, &e.to_le_bytes(), root, &n_e.to_le_bytes(), prev],
    )
}

/// One custodian's ML-DSA signature over `d_e`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The custodian's index in the registration.
    pub signer: u32,
    /// `ML-DSA.Sign(sk_Cj, d_e)` under [`APPROVAL_CONTEXT`].
    pub sig: Vec<u8>,
}

/// `S_e` and the SLH-DSA co-signature: what the audit package carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalSet {
    /// The approvals, sorted by signer.
    pub approvals: Vec<Approval>,
    /// The co-signer's SLH-DSA signature over `d_e`.
    pub sig_slh: Vec<u8>,
}

/// Why an approval set is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    /// Fewer than `M` distinct registered custodians signed validly.
    BelowThreshold {
        /// Valid distinct approvals found.
        valid: usize,
        /// Required.
        m: u32,
    },
    /// The SLH-DSA co-signature does not verify under the registered key.
    CoSignature,
    /// The approval set is not the one `A_e` commits to.
    Digest,
    /// Signing failed.
    Sign(String),
    /// ⭐ `eq:validcp` (M13 A5): the proposal is for a case this custodian does
    /// not hold.
    WrongCase,
    /// `d_{e−1}` is not the checkpoint this custodian last approved — the
    /// history would be forked or rolled back, not extended.
    WrongLink,
    /// The epoch number does not exceed the last one approved.
    EpochNotIncreasing {
        /// The last epoch this custodian approved.
        last: u64,
        /// The epoch proposed.
        got: u64,
    },
    /// The proposed `R_e` is not the root of the leaves handed over.
    RootMismatch,
    /// The proposed `n_e` is not the number of leaves handed over.
    CountMismatch {
        /// Leaves handed over.
        leaves: u64,
        /// Count proposed.
        claimed: u64,
    },
    /// The proposed `d_e` is not `H(0x12 ‖ ⟪cid, e, R_e, n_e, d_{e−1}⟫)` over
    /// the values just checked.
    CheckpointMismatch,
}

impl core::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BelowThreshold { valid, m } => write!(f, "{valid} valid approvals, {m} required"),
            Self::CoSignature => f.write_str("the SLH-DSA co-signature does not verify"),
            Self::Digest => f.write_str("the approval set does not match the anchored A_e"),
            Self::Sign(e) => write!(f, "signing failed: {e}"),
            Self::WrongCase => f.write_str("the checkpoint is for another case"),
            Self::WrongLink => {
                f.write_str("d_{e-1} is not the checkpoint this custodian last approved")
            }
            Self::EpochNotIncreasing { last, got } => {
                write!(
                    f,
                    "epoch {got} does not follow the last approved epoch {last}"
                )
            }
            Self::RootMismatch => f.write_str("R_e is not the root of the epoch's leaves"),
            Self::CountMismatch { leaves, claimed } => {
                write!(f, "n_e is {claimed} but the epoch has {leaves} leaves")
            }
            Self::CheckpointMismatch => {
                f.write_str("d_e is not the checkpoint over the values checked")
            }
        }
    }
}

impl core::error::Error for ApprovalError {}

/// What the root in a proposal is over, as the custodian recomputes it.
#[derive(Debug, Clone, Copy)]
pub enum Committed<'a> {
    /// An epoch's Tier-2 leaf digests, in MMR order. The custodian bags them
    /// itself, through the same [`crate::epoch_root`] the AIS anchors.
    Epoch(&'a [Digest32]),
    /// A root the custodian computed itself from data it holds, for a tree that
    /// is not this crate's to build — the warrant tree, whose leaves and node tag
    /// (`0x32`) belong to `pqcl-warrant`.
    ///
    /// ⚠️ **Not a way to approve the AIS's claim.** The values here must come
    /// from the custodian's own computation; passing the proposer's `root` back
    /// in would make every check below a tautology. The epoch path, which is
    /// every anchor the experiments make, has no such escape.
    Own {
        /// The root, as the custodian computed it.
        root: Digest32,
        /// Its leaf count, as the custodian computed it.
        count: u64,
    },
}

/// What a custodian is asked to approve: the anchor's values, and what they are
/// over.
#[derive(Debug, Clone, Copy)]
pub struct Proposal<'a> {
    /// `cid` — the case, or the warrant namespace.
    pub cid: Digest32,
    /// `e`.
    pub e: u64,
    /// The proposed `R_e`.
    pub root: Digest32,
    /// The proposed `n_e`.
    pub n_e: u64,
    /// The proposed `d_{e−1}`.
    pub d_prev: Digest32,
    /// The proposed `d_e`.
    pub d_e: Digest32,
    /// What `R_e` and `n_e` are over.
    pub over: Committed<'a>,
}

/// One custodian's view of one checkpoint chain: the case it holds, and the
/// last checkpoint and epoch it approved.
///
/// ⭐ **Why the custodian keeps its own view** (M13 A5, draft8 Phase 7 Step 3:
/// *"each custodian checks that d_{e−1} is the last checkpoint … then signs"*).
/// A custodian that took `d_{e−1}` from the proposer would approve whatever
/// history the AIS presented, including one forked off an earlier checkpoint or
/// rolled back past it. Only its own memory of what it last signed makes the
/// approval an attestation that the history was **extended**.
#[derive(Debug, Clone)]
pub struct ChainView {
    cid: Digest32,
    last: Digest32,
    last_e: Option<u64>,
}

/// A checkpoint a custodian has validated — the only thing [`approve`] signs.
///
/// Its field is private and [`ChainView::validate`] is the only constructor, so
/// an approval over an unchecked digest does not compile. Before M13 A5,
/// `approve` took a bare `&Digest32` and every custodian signed whatever it was
/// handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validated {
    d_e: Digest32,
}

impl Validated {
    /// The checkpoint validated.
    #[must_use]
    pub const fn digest(&self) -> &Digest32 {
        &self.d_e
    }
}

impl ChainView {
    /// A custodian of `cid` whose chain starts at `reg` (`d_{−1}`).
    #[must_use]
    pub const fn new(cid: Digest32, reg: Digest32) -> Self {
        Self {
            cid,
            last: reg,
            last_e: None,
        }
    }

    /// The last checkpoint approved (`reg` before the first).
    #[must_use]
    pub const fn last(&self) -> &Digest32 {
        &self.last
    }

    /// ⭐ **`eq:validcp`, checked before anything is signed** (M13 A5).
    ///
    /// In order: the case is this custodian's; `d_{e−1}` is the checkpoint it
    /// last approved; the epoch number rises (A21 replaced the growing leaf
    /// count with this, since `n_e` is now an epoch's own count and may fall);
    /// `R_e` and `n_e` are the root and size of the leaves handed over,
    /// recomputed here; and `d_e` is the checkpoint over exactly those values.
    /// Only then does the view advance, so a refused proposal leaves the
    /// custodian where it was.
    ///
    /// # Errors
    ///
    /// The first check that fails.
    pub fn validate(&mut self, p: &Proposal<'_>) -> Result<Validated, ApprovalError> {
        if p.cid != self.cid {
            return Err(ApprovalError::WrongCase);
        }
        if p.d_prev != self.last {
            return Err(ApprovalError::WrongLink);
        }
        if let Some(last) = self.last_e
            && p.e <= last
        {
            return Err(ApprovalError::EpochNotIncreasing { last, got: p.e });
        }
        let (root, count) = match p.over {
            Committed::Epoch(leaves) => (
                crate::epoch_root(&pqcl_forest::Mmr::from_digests(leaves)),
                leaves.len() as u64,
            ),
            Committed::Own { root, count } => (root, count),
        };
        if p.root != root {
            return Err(ApprovalError::RootMismatch);
        }
        if p.n_e != count {
            return Err(ApprovalError::CountMismatch {
                leaves: count,
                claimed: p.n_e,
            });
        }
        if p.d_e != checkpoint(&p.cid, p.e, &root, count, &p.d_prev) {
            return Err(ApprovalError::CheckpointMismatch);
        }
        self.last = p.d_e;
        self.last_e = Some(p.e);
        Ok(Validated { d_e: p.d_e })
    }
}

/// Custodian `j` approves a checkpoint it has validated.
///
/// Takes a [`Validated`], not a digest: the check is in the type, so the
/// signing and the checking cannot be separated by a caller who has the first
/// and skips the second. Signing stays separate from validating so a harness
/// can validate in epoch order and sign in parallel.
///
/// # Errors
///
/// A signing failure.
pub fn approve(
    custodian: &SoftwareMlDsa,
    j: u32,
    checkpoint: &Validated,
) -> Result<Approval, ApprovalError> {
    let sig = custodian
        .sign_with_context(&checkpoint.d_e, APPROVAL_CONTEXT)
        .map_err(|e| ApprovalError::Sign(e.to_string()))?;
    Ok(Approval { signer: j, sig })
}

impl ApprovalSet {
    /// Assemble from approvals and the co-signer's signature over `d_e`.
    ///
    /// # Errors
    ///
    /// The co-signature fails.
    pub fn new(
        mut approvals: Vec<Approval>,
        cosigner: &CoSigner,
        d_e: &Digest32,
    ) -> Result<Self, ApprovalError> {
        approvals.sort_by_key(|a| a.signer);
        let sig_slh = cosigner
            .sign(d_e, APPROVAL_CONTEXT, false)
            .map_err(|e| ApprovalError::Sign(e.to_string()))?;
        Ok(Self { approvals, sig_slh })
    }

    /// The canonical encoding of `S_e`: `⟪j, σ_j⟫` per approval, in signer
    /// order, as one framed field.
    #[must_use]
    pub fn encode_set(&self) -> Vec<u8> {
        let mut items = Vec::with_capacity(2 * self.approvals.len());
        for a in &self.approvals {
            items.push(a.signer.to_le_bytes().to_vec());
            items.push(a.sig.clone());
        }
        encode_list(&items)
    }

    /// `A_e = H(0x13 ‖ ⟪S_e, σ_SLH⟫)`, the digest the anchor stores.
    #[must_use]
    pub fn digest(&self) -> Digest32 {
        hash_domain(Domain::ApprovalSet, &[&self.encode_set(), &self.sig_slh])
    }

    /// Bytes the audit package carries for this epoch (never on chain).
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.encode_set().len() + self.sig_slh.len()
    }

    /// The auditor's check (Phase 10 Step 1): this set is the one `a_e`
    /// commits to, `M` distinct registered custodians signed `d_e`, and the
    /// co-signature verifies. Returns the number of valid approvals.
    ///
    /// # Errors
    ///
    /// [`ApprovalError`] naming what failed.
    pub fn verify(
        &self,
        reg: &Registration,
        d_e: &Digest32,
        a_e: &Digest32,
    ) -> Result<usize, ApprovalError> {
        if self.digest() != *a_e {
            return Err(ApprovalError::Digest);
        }
        let mut signers = std::collections::BTreeSet::new();
        for a in &self.approvals {
            let Some(pk) = usize::try_from(a.signer)
                .ok()
                .and_then(|j| reg.custodians.get(j))
            else {
                continue;
            };
            if sig::verify(d_e, &a.sig, pk, APPROVAL_CONTEXT).is_ok() {
                signers.insert(a.signer);
            }
        }
        if signers.len() < reg.m as usize {
            return Err(ApprovalError::BelowThreshold {
                valid: signers.len(),
                m: reg.m,
            });
        }
        slh::verify(d_e, &self.sig_slh, &reg.pk_slh, APPROVAL_CONTEXT)
            .map_err(|_| ApprovalError::CoSignature)?;
        Ok(signers.len())
    }
}

/// Verify a sequence of checkpoints back to `reg` (Phase 10 Step 1,
/// `eq:auditchk`): each `d_e` recomputes from its predecessor, and the **epoch
/// number** strictly increases. `epochs` is `(e, R_e, n_e, d_e)` in order.
///
/// ⚠️ **The growth test is on `e`, not on the leaf count** (M13 A21). It used to
/// be on the count, which was cumulative; `n_e` is per epoch now, so a later
/// epoch may hold fewer leaves and a count-growth test would reject an honest
/// history. What must grow is the epoch index, and the `d_{e−1}` link is what
/// makes the sequence a chain rather than a set.
#[must_use]
pub fn verify_chain(reg: &Registration, epochs: &[(u64, Digest32, u64, Digest32)]) -> bool {
    let mut prev = reg.digest();
    let mut last_e: Option<u64> = None;
    for (e, root, n_e, d) in epochs {
        if last_e.is_some_and(|l| *e <= l) || checkpoint(&reg.cid, *e, root, *n_e, &prev) != *d {
            return false;
        }
        prev = *d;
        last_e = Some(*e);
    }
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use pqcl_primitives::Signer;
    use pqcl_primitives::xof::digest256;

    struct Committee {
        reg: Registration,
        custodians: Vec<SoftwareMlDsa>,
        cosigner: CoSigner,
    }

    /// A [`Validated`] over an arbitrary digest — **only constructible here**,
    /// in this module's tests, where what is under test is `ApprovalSet`'s
    /// verification and not the custodian's check. Outside this module the
    /// only route to one is [`ChainView::validate`].
    const fn unchecked(d: Digest32) -> Validated {
        Validated { d_e: d }
    }

    fn committee() -> Committee {
        let custodians: Vec<SoftwareMlDsa> =
            (0..3).map(|_| SoftwareMlDsa::generate().unwrap()).collect();
        let cosigner = CoSigner::generate().unwrap();
        let reg = Registration {
            cid: digest256(b"cid"),
            pk_sig: vec![1; 8],
            pk_kem: vec![2; 8],
            pk_slh: cosigner.public_key().to_vec(),
            custodians: custodians.iter().map(|c| c.public_key().to_vec()).collect(),
            m: 2,
            delta: 600,
            roster: crate::accept::Roster::default().digest(),
        };
        Committee {
            reg,
            custodians,
            cosigner,
        }
    }

    #[test]
    fn two_of_three_approve_and_the_set_verifies_against_its_digest() {
        let c = committee();
        let d = checkpoint(&c.reg.cid, 1, &digest256(b"R_1"), 5, &c.reg.digest());
        let set = ApprovalSet::new(
            vec![
                approve(&c.custodians[2], 2, &unchecked(d)).unwrap(),
                approve(&c.custodians[0], 0, &unchecked(d)).unwrap(),
            ],
            &c.cosigner,
            &d,
        )
        .unwrap();
        assert_eq!(set.verify(&c.reg, &d, &set.digest()), Ok(2));
    }

    #[test]
    fn one_approval_or_a_repeated_signer_is_below_threshold() {
        let c = committee();
        let d = checkpoint(&c.reg.cid, 1, &digest256(b"R_1"), 5, &c.reg.digest());
        let a0 = approve(&c.custodians[0], 0, &unchecked(d)).unwrap();
        let set = ApprovalSet::new(vec![a0.clone(), a0], &c.cosigner, &d).unwrap();
        assert_eq!(
            set.verify(&c.reg, &d, &set.digest()),
            Err(ApprovalError::BelowThreshold { valid: 1, m: 2 })
        );
    }

    #[test]
    fn an_approval_of_another_checkpoint_or_a_swapped_set_is_refused() {
        let c = committee();
        let d = checkpoint(&c.reg.cid, 1, &digest256(b"R_1"), 5, &c.reg.digest());
        let other = checkpoint(&c.reg.cid, 1, &digest256(b"R_x"), 5, &c.reg.digest());
        let set = ApprovalSet::new(
            vec![
                approve(&c.custodians[0], 0, &unchecked(other)).unwrap(),
                approve(&c.custodians[1], 1, &unchecked(other)).unwrap(),
            ],
            &c.cosigner,
            &d,
        )
        .unwrap();
        assert!(matches!(
            set.verify(&c.reg, &d, &set.digest()),
            Err(ApprovalError::BelowThreshold { .. })
        ));
        assert_eq!(
            set.verify(&c.reg, &d, &digest256(b"another A_e")),
            Err(ApprovalError::Digest)
        );
    }

    #[test]
    fn the_checkpoint_chain_detects_a_fork_a_wrong_count_and_a_repeated_epoch() {
        let c = committee();
        let d1 = checkpoint(&c.reg.cid, 1, &digest256(b"R_1"), 5, &c.reg.digest());
        let d2 = checkpoint(&c.reg.cid, 2, &digest256(b"R_2"), 9, &d1);
        let good = [(1, digest256(b"R_1"), 5, d1), (2, digest256(b"R_2"), 9, d2)];
        assert!(verify_chain(&c.reg, &good));

        // A second epoch built on a different predecessor: the link breaks.
        let forked = checkpoint(&c.reg.cid, 2, &digest256(b"R_2"), 9, &digest256(b"fork"));
        assert!(!verify_chain(
            &c.reg,
            &[good[0], (2, digest256(b"R_2"), 9, forked)]
        ));

        // ⭐ **Acceptance A21 (b): the count is checked, from the package.**
        // `d_2` commits `n_e = 9`; an auditor handed 7 recomputes a different
        // checkpoint and refuses, even though the link is intact.
        assert!(
            !verify_chain(&c.reg, &[good[0], (2, digest256(b"R_2"), 7, d2)]),
            "a wrong n_e was accepted"
        );

        // ⚠️ **And a count that does not grow is now legal** (M13 A21). Every
        // epoch has its own MMR, so epoch 2 holding fewer leaves than epoch 1
        // is an ordinary quiet epoch, not a rollback. The pre-A21 chain
        // rejected this, which under per-epoch counts would have refused an
        // honest history.
        let quiet = checkpoint(&c.reg.cid, 2, &digest256(b"R_2"), 2, &d1);
        assert!(
            verify_chain(&c.reg, &[good[0], (2, digest256(b"R_2"), 2, quiet)]),
            "a quiet epoch was rejected: the count-growth test is still there"
        );

        // What must grow is the epoch number. A repeated or reversed epoch is
        // refused even with a well-formed checkpoint.
        let repeat = checkpoint(&c.reg.cid, 1, &digest256(b"R_2"), 9, &d1);
        assert!(!verify_chain(
            &c.reg,
            &[good[0], (1, digest256(b"R_2"), 9, repeat)]
        ));

        // A chain that does not start at this case's registration.
        let mut other = c.reg.clone();
        other.m = 3;
        assert!(!verify_chain(&other, &good));
    }
    /// An epoch of `n` leaves and the proposal an honest AIS makes for it.
    fn epoch(
        c: &Committee,
        e: u64,
        n: usize,
        prev: Digest32,
    ) -> (Vec<Digest32>, Digest32, Digest32) {
        let leaves: Vec<Digest32> = (0..n)
            .map(|i| digest256(&[e.to_le_bytes(), (i as u64).to_le_bytes()].concat()))
            .collect();
        let root = crate::epoch_root(&pqcl_forest::Mmr::from_digests(&leaves));
        let d = checkpoint(&c.reg.cid, e, &root, n as u64, &prev);
        (leaves, root, d)
    }

    fn proposal<'a>(
        c: &Committee,
        e: u64,
        leaves: &'a [Digest32],
        root: Digest32,
        prev: Digest32,
        d: Digest32,
    ) -> Proposal<'a> {
        Proposal {
            cid: c.reg.cid,
            e,
            root,
            n_e: leaves.len() as u64,
            d_prev: prev,
            d_e: d,
            over: Committed::Epoch(leaves),
        }
    }

    /// ⭐ **Acceptance A5.** An honest chain of epochs is approved, each
    /// approval verifies, and the view advances to what was approved.
    #[test]
    fn a_custodian_approves_each_extension_it_recomputes() {
        let c = committee();
        let mut view = ChainView::new(c.reg.cid, c.reg.digest());
        let mut prev = c.reg.digest();
        for (e, n) in [(0u64, 3usize), (1, 8), (2, 13), (3, 18)] {
            let (leaves, root, d) = epoch(&c, e, n, prev);
            let v = view
                .validate(&proposal(&c, e, &leaves, root, prev, d))
                .unwrap_or_else(|err| panic!("epoch {e}: {err}"));
            let a = approve(&c.custodians[0], 0, &v).unwrap();
            sig::verify(&d, &a.sig, c.custodians[0].public_key(), APPROVAL_CONTEXT)
                .expect("the approval is over the validated checkpoint");
            assert_eq!(view.last(), &d);
            prev = d;
        }
    }

    /// ⭐ **Acceptance A5: a wrong `R_e`, link or count is refused** — and so is
    /// every other field `eq:validcp` binds, each with its own error, and none
    /// of them moves the view.
    #[test]
    fn every_wrong_field_is_refused_and_the_view_does_not_move() {
        let c = committee();
        let reg = c.reg.digest();
        let mut view = ChainView::new(c.reg.cid, reg);
        let (l0, r0, d0) = epoch(&c, 0, 6, reg);
        let v0 = view.validate(&proposal(&c, 0, &l0, r0, reg, d0)).unwrap();
        assert_eq!(v0.digest(), &d0);

        let (l1, r1, d1) = epoch(&c, 1, 9, d0);
        let good = proposal(&c, 1, &l1, r1, d0, d1);

        // Each mutant changes exactly one thing. The AIS recomputes `d_e` over
        // the wrong value where a real one would, so only the custodian's own
        // recomputation can be what catches it.
        let mut fewer = l1.clone();
        fewer.pop();
        let mutants: Vec<(&str, Proposal<'_>, ApprovalError)> = vec![
            (
                "another case",
                Proposal {
                    cid: digest256(b"other case"),
                    ..good
                },
                ApprovalError::WrongCase,
            ),
            (
                "a fork off an earlier checkpoint",
                Proposal {
                    d_prev: reg,
                    d_e: checkpoint(&c.reg.cid, 1, &r1, 9, &reg),
                    ..good
                },
                ApprovalError::WrongLink,
            ),
            (
                "a repeated epoch",
                Proposal {
                    e: 0,
                    d_e: checkpoint(&c.reg.cid, 0, &r1, 9, &d0),
                    ..good
                },
                ApprovalError::EpochNotIncreasing { last: 0, got: 0 },
            ),
            (
                "a root that is not the leaves' root",
                Proposal {
                    root: digest256(b"R_x"),
                    d_e: checkpoint(&c.reg.cid, 1, &digest256(b"R_x"), 9, &d0),
                    ..good
                },
                ApprovalError::RootMismatch,
            ),
            (
                "a count that is not the leaves' count",
                Proposal {
                    n_e: 8,
                    d_e: checkpoint(&c.reg.cid, 1, &r1, 8, &d0),
                    ..good
                },
                ApprovalError::CountMismatch {
                    leaves: 9,
                    claimed: 8,
                },
            ),
            (
                "leaves withheld from the custodian",
                Proposal {
                    over: Committed::Epoch(&fewer),
                    ..good
                },
                ApprovalError::RootMismatch,
            ),
            (
                "a d_e over nothing it was shown",
                Proposal {
                    d_e: digest256(b"d_x"),
                    ..good
                },
                ApprovalError::CheckpointMismatch,
            ),
        ];
        for (what, p, want) in mutants {
            assert_eq!(
                view.validate(&p),
                Err(want),
                "{what} was not refused as expected"
            );
            assert_eq!(view.last(), &d0, "{what} moved the view");
        }

        // And the honest extension still goes through afterwards.
        assert_eq!(view.validate(&good).map(|v| *v.digest()), Ok(d1));
    }

    /// The custodian's root and the AIS's are one function over one input, so
    /// an honest AIS is never refused — including the empty-epoch sentinel,
    /// which is where a second spelling would have diverged.
    #[test]
    fn the_custodian_recomputes_exactly_the_root_the_ais_anchors() {
        for n in [0usize, 1, 2, 3, 7, 8, 9, 100] {
            let mut m = pqcl_forest::Mmr::new();
            for i in 0..n {
                m.append(&pqcl_forest::Leaf::new(
                    pqcl_primitives::xof::Domain::CustodyRoot,
                    &[&(i as u64).to_le_bytes()],
                ));
            }
            assert_eq!(
                crate::epoch_root(&pqcl_forest::Mmr::from_digests(m.leaf_digests())),
                crate::epoch_root(&m),
                "{n} leaves"
            );
        }
    }
}
