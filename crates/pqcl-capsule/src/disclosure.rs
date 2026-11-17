//! The court-disclosure bundle.
//!
//! What a lab hands a court for **one capsule**: the capsule, its custody
//! history as one [`Segment`] per epoch, a Tier-2 inclusion proof per segment
//! against that epoch's anchored root, and the three per-capsule keys that open
//! it. It must verify from that plus public chain data alone — no access to the
//! lab, the index, or the rest of the case.
//!
//! # Why the three tiers exist
//!
//! This is the payoff. A flat MMR over every custody record cannot hand over
//! one capsule's history without leaking the shape of everything else: the
//! inclusion path itself would reveal case size and activity volume. With
//! Tier 1 the disclosure is one capsule's own tree plus a single Tier-2 proof
//! per epoch, and the proof's siblings are digests of *other capsules' roots* —
//! opaque 32-byte values that say nothing about their contents.
//!
//! # Why a capsule's history is a list of segments (M13 A20)
//!
//! ⭐ **A capsule's records are filed under a different pseudonym every epoch,
//! and nothing the AIS stores joins one epoch's segment to the next.** That is
//! `audit/07` finding D1: before A20 the whole chain carried one `eid_e` and
//! the first record's cleartext `h_prev` was `H(0x24 ‖ ⟪eid⟫)`, computable by
//! anyone holding the capsule, so per-epoch pseudonyms bought nothing.
//!
//! The cost is that **assembling this bundle is a keyed operation.** The AIS
//! cannot do it: it can hand over the segment filed under a pseudonym, but only
//! a holder of `k_eid` knows which pseudonyms to ask for. The court is in the
//! same position and that is deliberate — it receives `k_eid`, derives every
//! `eid_e` itself, and so can go looking for a segment the lab left out.
//!
//! The project rules lists per-capsule selective disclosure and per-epoch
//! unlinkability as live novelty claims. [`Bundle::verify`], [`Bundle::open`]
//! and the AIS-view test in `pqcl-pipeline` are what make them properties
//! rather than assertions — and the plan is explicit that the test must
//! **assert on the bundle's byte content, not on intent**.

use pqcl_forest::{CustodyTree, Leaf, MmrProof};
use pqcl_primitives::aead::{CustodyKey, RecordKey, SealedRecord};
use pqcl_primitives::kem;
use pqcl_primitives::xof::{Digest32, Domain, PrfKey};

use crate::codec::{CodecError, Reader, Writer};
use crate::record::{Capsule, CustodyRecord, Event, OpenedRecord};

/// Why a disclosure bundle was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosureError {
    /// The custody chain is empty. A capsule always has at least a `COLLECT`.
    EmptyChain,
    /// A record's `h_prev` does not match its predecessor.
    BrokenChain {
        /// Position in the segment.
        index: usize,
    },
    /// A record belongs to a different capsule's chain.
    ForeignRecord {
        /// Position in the segment.
        index: usize,
    },
    /// The recomputed Tier-1 root does not match the claimed one.
    RootMismatch,
    /// The Tier-2 proof does not verify against the anchored root.
    NotAnchored,
    /// ⭐ The capsule's own `0x01` seal leaf is not anchored in the epoch the
    /// bundle claims sealed it (M13 A3) — the check that stops a real history
    /// being handed over beside an altered capsule.
    CapsuleNotAnchored,
    /// No anchored root was supplied for an epoch the bundle claims a segment
    /// in — the court cannot check that segment at all, which is a refusal and
    /// not a pass.
    UnanchoredEpoch {
        /// The epoch with no root.
        epoch: u64,
    },
    /// The segments are not in strictly increasing epoch order, or two claim
    /// the same epoch.
    SegmentOrder,
    /// A segment's `eid_e` is not `F(k_eid, e)` for the epoch it claims — the
    /// pseudonym and the epoch disagree, so one of them is forged.
    WrongPseudonym {
        /// The epoch the segment claims.
        epoch: u64,
    },
    /// A segment's first record does not link to the previous segment's last
    /// record. ⭐ **The cross-segment check, and it is keyed**: the real link
    /// is inside `C_rec`, so only a key holder can make it.
    BrokenSegmentLink {
        /// Index of the segment that fails to link back.
        segment: usize,
    },
    /// A record's `rid` does not match the position it was found at.
    WrongPosition {
        /// Position in the capsule's whole chain.
        j: u64,
    },
    /// A record body did not open under the disclosed `K_rec^{eid}`.
    Sealed {
        /// Position in the capsule's whole chain.
        j: u64,
    },
    /// ⭐ A record follows the chain's terminal `DISPOSE` (M13 A15). A
    /// disposed capsule's chain is closed; anything after it was appended to
    /// a history that had ended.
    AfterTerminal {
        /// Position of the first record after the `DISPOSE`.
        j: u64,
    },
    /// The bundle did not decode.
    Malformed(CodecError),
}

impl core::fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyChain => f.write_str("custody chain is empty"),
            Self::BrokenChain { index } => {
                write!(f, "record {index} does not chain to its predecessor")
            }
            Self::ForeignRecord { index } => {
                write!(f, "record {index} belongs to a different capsule")
            }
            Self::RootMismatch => f.write_str("recomputed Tier-1 root does not match"),
            Self::NotAnchored => f.write_str("Tier-2 proof does not verify against the anchor"),
            Self::CapsuleNotAnchored => {
                f.write_str("the capsule's own seal leaf is not anchored in its sealing epoch")
            }
            Self::UnanchoredEpoch { epoch } => {
                write!(f, "no anchored root supplied for epoch {epoch}")
            }
            Self::SegmentOrder => f.write_str("segments are not in increasing epoch order"),
            Self::WrongPseudonym { epoch } => {
                write!(
                    f,
                    "the segment for epoch {epoch} is filed under a pseudonym that epoch does not derive"
                )
            }
            Self::BrokenSegmentLink { segment } => {
                write!(f, "segment {segment} does not link to the previous one")
            }
            Self::WrongPosition { j } => write!(
                f,
                "the record at position {j} carries another position's rid"
            ),
            Self::Sealed { j } => write!(f, "the record at position {j} did not open"),
            Self::AfterTerminal { j } => {
                write!(f, "the record at position {j} follows the chain's DISPOSE")
            }
            Self::Malformed(e) => write!(f, "bundle did not decode: {e}"),
        }
    }
}

impl core::error::Error for DisclosureError {}

/// One epoch's worth of a capsule's custody chain (M13 A20).
///
/// A segment is the unit the forest commits to: its Tier-1 root covers *these*
/// records and no others, and the `0x02` leaf `⟪eid_e, R_seg, n_seg⟫` carrying
/// that root is anchored in its own epoch's MMR. Verifying a segment needs no
/// key at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// `eid_e = F(k_eid, e)` — the pseudonym the segment is filed under.
    pub eid_e: Digest32,
    /// The epoch `e`.
    pub epoch: u64,
    /// The segment's records, in event order.
    pub records: Vec<CustodyRecord>,
    /// `n_seg` as committed in the Tier-2 `0x02` leaf.
    pub count: u64,
    /// Tier-2 inclusion proof for the `0x02` leaf, in epoch `e`'s MMR.
    pub anchor_proof: MmrProof,
}

impl Segment {
    /// Assemble a segment from its records and its anchoring proof.
    #[must_use]
    pub fn new(
        eid_e: Digest32,
        epoch: u64,
        records: Vec<CustodyRecord>,
        anchor_proof: MmrProof,
    ) -> Self {
        let count = records.len() as u64;
        Self {
            eid_e,
            epoch,
            records,
            count,
            anchor_proof,
        }
    }

    /// Every record's Tier-1 leaf `L_j`, each computed once.
    fn leaves(&self) -> Vec<Digest32> {
        self.records.iter().map(CustodyRecord::tier1_leaf).collect()
    }

    fn root_of(leaves: &[Digest32]) -> Option<Digest32> {
        let mut t = CustodyTree::new();
        for l in leaves {
            t.append_leaf(*l);
        }
        t.root()
    }

    fn custody_leaf_over(&self, root: &Digest32) -> Leaf {
        Leaf::new(
            Domain::CustodyRoot,
            &[&self.eid_e, root, &self.count.to_le_bytes()],
        )
    }

    /// Recompute the Tier-1 root from the disclosed records.
    #[must_use]
    pub fn tier1_root(&self) -> Option<Digest32> {
        Self::root_of(&self.leaves())
    }

    /// The Tier-2 `0x02` leaf this segment claims was anchored.
    #[must_use]
    pub fn custody_leaf(&self) -> Option<Leaf> {
        let root = self.tier1_root()?;
        Some(self.custody_leaf_over(&root))
    }

    /// Checks 1–3 of [`Segment::verify`], returning the recomputed `0x02` leaf.
    fn checked_leaf(&self) -> Result<Leaf, DisclosureError> {
        let leaves = self.checked_leaves()?;
        // 3. The root is recomputed, not accepted.
        let root = Self::root_of(&leaves).ok_or(DisclosureError::EmptyChain)?;
        Ok(self.custody_leaf_over(&root))
    }

    /// Checks 1–2 of [`Segment::verify`], returning every record's leaf.
    fn checked_leaves(&self) -> Result<Vec<Digest32>, DisclosureError> {
        let first = self.records.first().ok_or(DisclosureError::EmptyChain)?;

        // ⭐ M12: each record is absorbed once. Its leaf `L_j` is both the
        // input to the next record's `h_prev = H(0x24 ‖ ⟪L_j⟫)` and a Tier-1
        // leaf, so checks 1 and 3 share it rather than hashing the record twice.
        let leaves = self.leaves();

        // 1 + 2. Linkage inside the segment, and no foreign records.
        //
        // ⭐ **The base case is the segment's own pseudonym** (A20), not the
        // capsule id: `H(0x24 ‖ ⟪eid_e⟫)`. A keyless verifier therefore learns
        // that this record opens *this* segment and nothing about what came
        // before it — which is the unlinkability property. The real link is in
        // the body, and [`Bundle::open`] is what checks it.
        if first.h_prev != CustodyRecord::segment_genesis_link(&self.eid_e) {
            return Err(DisclosureError::BrokenChain { index: 0 });
        }
        for (i, r) in self.records.iter().enumerate() {
            if r.eid_e != self.eid_e {
                return Err(DisclosureError::ForeignRecord { index: i });
            }
            if i > 0 && r.h_prev != CustodyRecord::link_from_leaf(&leaves[i - 1]) {
                return Err(DisclosureError::BrokenChain { index: i });
            }
        }
        Ok(leaves)
    }

    /// Verify this segment against its epoch's anchored root, keylessly.
    ///
    /// Four checks, in the order a sceptic would apply them:
    ///
    /// 1. the segment is non-empty and internally linked by `h_prev`;
    /// 2. every record carries the segment's pseudonym, so no foreign record
    ///    was spliced in;
    /// 3. the Tier-1 root recomputes from the disclosed records — the court is
    ///    not asked to take the lab's word for the root;
    /// 4. that root, under the `0x02` tag, is anchored in `epoch_root`.
    ///
    /// # Errors
    ///
    /// The specific [`DisclosureError`], never a bare bool: which check failed
    /// is exactly what a court would need to know.
    pub fn verify(&self, epoch_root: &Digest32) -> Result<(), DisclosureError> {
        let leaf = self.checked_leaf()?;
        if pqcl_forest::tier2::verify(epoch_root, &leaf, &self.anchor_proof) {
            Ok(())
        } else {
            Err(DisclosureError::NotAnchored)
        }
    }

    /// [`Segment::verify`] with the Tier-2 walk through a memo shared across a
    /// whole case (`tier2::NodeMemo`). Same checks, same order, same errors.
    ///
    /// # Errors
    ///
    /// As [`Segment::verify`].
    pub fn verify_memo(
        &self,
        epoch_root: &Digest32,
        memo: &mut pqcl_forest::tier2::NodeMemo,
    ) -> Result<(), DisclosureError> {
        let leaf = self.checked_leaf()?;
        if pqcl_forest::tier2::verify_memo(epoch_root, &leaf, &self.anchor_proof, memo) {
            Ok(())
        } else {
            Err(DisclosureError::NotAnchored)
        }
    }

    fn encode_into(&self, w: &mut Writer) {
        w.field(&self.eid_e).u64(self.epoch).u64(self.count);
        w.u64(self.records.len() as u64);
        for r in &self.records {
            w.field(&r.encode());
        }
        encode_proof(w, &self.anchor_proof);
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let eid_e: Digest32 = r
            .field()?
            .try_into()
            .map_err(|_| CodecError::InvalidField("eid_e"))?;
        let epoch = r.u64()?;
        let count = r.u64()?;
        let n = usize::try_from(r.u64()?).map_err(|_| CodecError::LengthOverflow)?;
        let mut records = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            records.push(CustodyRecord::decode(r.field()?)?);
        }
        let anchor_proof = decode_proof(r)?;
        Ok(Self {
            eid_e,
            epoch,
            records,
            count,
            anchor_proof,
        })
    }
}

/// The capsule's own `0x01` seal leaf, proved against the epoch that sealed it
/// (M13 A3).
///
/// ⭐ **Without this a bundle proves a history and not the thing it is about.**
/// The segments prove that *these records* were anchored under *this
/// pseudonym*; nothing in them ties the capsule's own commitments — `d_ev`,
/// `cm_ev`, `prov`, `Δ_gap`, `σ_DEFR` — to the chain. A lab could hand a court
/// a real custody history beside an altered capsule and every check would pass.
/// The seal leaf is what refuses that, and it refuses it keylessly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealProof {
    /// The epoch whose MMR holds the `0x01` leaf — the capsule's **sealing**
    /// epoch, which is `capsule.epoch` and need not be any segment's.
    pub epoch: u64,
    /// Its Tier-2 inclusion proof.
    pub proof: MmrProof,
}

/// The three per-capsule keys a disclosure hands over, and nothing else.
///
/// ⭐ **All three are per capsule** (M13 A20). That is what makes a disclosure
/// a disclosure of one capsule: nothing here derives another capsule's
/// pseudonyms, bodies or record identifiers, and nothing here is case-wide.
/// `K_coc` and `K_link` stay with the lab.
#[derive(Clone, PartialEq, Eq)]
pub struct DisclosureKeys {
    /// `k_eid = F(K_link, eid)` — derives every `eid_e` of this capsule, so
    /// the court can look for a segment the lab left out.
    pub k_eid: Digest32,
    /// `K_rec^{eid} = F(K_coc, "rec" ‖ eid)` — opens the record bodies.
    pub k_rec: Digest32,
    /// `K_rid^{eid} = F(K_coc, "rid" ‖ eid)` — recomputes each `rid` from the
    /// position the record was found at.
    pub k_rid: Digest32,
}

impl core::fmt::Debug for DisclosureKeys {
    /// Never prints key material. A key in a log line is a key on disk.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DisclosureKeys(<redacted>)")
    }
}

/// One capsule's [`DisclosureKeys`], sealed to the court: ML-KEM-768 to the
/// court's encapsulation key, AES-256-GCM under the shared secret, bound to
/// `(cid_c, eid)` — the same construction as the redaction escrow.
///
/// ⭐ **Why the keys travel sealed** (M13 A18). Under Nitro, `K_coc` and
/// `K_link` live in the enclave, so the lab's disclosure is a request to it.
/// Answering with the keys in the clear would make the enclave's parent a
/// holder of every capsule's record keys it ever asked about, and would break
/// the wire's defining property that no response carries a key. Sealed, the
/// parent relays bytes it cannot open.
///
/// ⚠️ **What this does not stop.** The court's key arrives in the request, so
/// a parent that *lies* about it can name its own key and open the result.
/// This protects against a parent that leaks — logs, core dumps, a later
/// compromise — not one that is malicious when it asks. Pinning the court's
/// key inside the boundary at enrolment is the fix, and is recorded as such.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedDisclosure {
    /// The case.
    pub cid_c: Digest32,
    /// The capsule.
    pub eid: Digest32,
    /// ML-KEM-768 ciphertext.
    pub kem_ct: Vec<u8>,
    /// `k_eid ‖ k_rec ‖ k_rid`, sealed.
    pub sealed: SealedRecord,
}

/// Sealing or opening a [`SealedDisclosure`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealError(pub String);

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "sealed disclosure: {}", self.0)
    }
}

impl core::error::Error for SealError {}

impl SealedDisclosure {
    /// The associated data: framed, so `(cid_c, eid)` is bound unambiguously.
    fn aad(cid_c: &Digest32, eid: &Digest32) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(b"pqcl/disclosure-keys").field(cid_c).field(eid);
        w.finish()
    }

    /// Seal `keys` to `court_ek`.
    ///
    /// # Errors
    ///
    /// A malformed encapsulation key, or an AEAD failure.
    pub fn seal(
        keys: &DisclosureKeys,
        cid_c: Digest32,
        eid: Digest32,
        court_ek: &[u8],
    ) -> Result<Self, SealError> {
        let (kem_ct, ss) = kem::encapsulate(court_ek).map_err(|e| SealError(e.to_string()))?;
        let plain = [keys.k_eid, keys.k_rec, keys.k_rid].concat();
        let sealed = RecordKey::new(*ss.as_bytes())
            .seal(&Self::aad(&cid_c, &eid), &plain)
            .map_err(|e| SealError(e.to_string()))?;
        Ok(Self {
            cid_c,
            eid,
            kem_ct,
            sealed,
        })
    }

    /// The court opens it with its decapsulation key.
    ///
    /// # Errors
    ///
    /// A decapsulation or authentication failure.
    pub fn open(&self, court: &kem::KeyPair) -> Result<DisclosureKeys, SealError> {
        let ss = court
            .decapsulate(&self.kem_ct)
            .map_err(|e| SealError(e.to_string()))?;
        let plain = RecordKey::new(*ss.as_bytes())
            .open(&Self::aad(&self.cid_c, &self.eid), &self.sealed)
            .map_err(|e| SealError(e.to_string()))?;
        let key = |i: usize| -> Result<Digest32, SealError> {
            plain
                .get(32 * i..32 * (i + 1))
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| SealError("not three 32-byte keys".into()))
        };
        if plain.len() != 96 {
            return Err(SealError("not three 32-byte keys".into()));
        }
        Ok(DisclosureKeys {
            k_eid: key(0)?,
            k_rec: key(1)?,
            k_rid: key(2)?,
        })
    }

    /// Canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(&self.cid_c)
            .field(&self.eid)
            .field(&self.kem_ct)
            .field(self.sealed.as_bytes());
        w.finish()
    }

    /// Decode [`Self::encode`]'s output.
    ///
    /// # Errors
    ///
    /// [`CodecError`] on a short field, a wrong-length digest or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes)?;
        let digest = |f: &[u8]| -> Result<Digest32, CodecError> {
            f.try_into()
                .map_err(|_| CodecError::InvalidField("a digest must be 32 bytes"))
        };
        let out = Self {
            cid_c: digest(r.field()?)?,
            eid: digest(r.field()?)?,
            kem_ct: r.field()?.to_vec(),
            sealed: SealedRecord::from_bytes(r.field()?.to_vec()),
        };
        r.finish()?;
        Ok(out)
    }
}

/// Everything disclosed for one capsule, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The capsule.
    pub capsule: Capsule,
    /// Its custody history, one segment per epoch it was touched in, in
    /// increasing epoch order.
    pub segments: Vec<Segment>,
    /// The capsule's `0x01` seal leaf, anchored in its sealing epoch (M13 A3).
    pub seal: SealProof,
    /// The per-capsule keys that open it.
    pub keys: DisclosureKeys,
}

impl Bundle {
    /// Assemble a bundle.
    #[must_use]
    pub const fn new(
        capsule: Capsule,
        segments: Vec<Segment>,
        seal: SealProof,
        keys: DisclosureKeys,
    ) -> Self {
        Self {
            capsule,
            segments,
            seal,
            keys,
        }
    }

    /// Every disclosed record, in order, across every segment.
    pub fn records(&self) -> impl Iterator<Item = &CustodyRecord> {
        self.segments.iter().flat_map(|s| s.records.iter())
    }

    /// How many records the bundle discloses in total.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.segments.iter().map(|s| s.records.len()).sum()
    }

    /// `eid_e = F(k_eid, e)` from the disclosed key — what the court computes
    /// to go looking for the capsule's other segments.
    #[must_use]
    pub fn expected_pseudonym(&self, epoch: u64) -> Digest32 {
        CustodyRecord::epoch_pseudonym(&PrfKey::new(self.keys.k_eid), epoch)
    }

    /// Verify every segment against its own epoch's anchored root.
    ///
    /// Keyless, and per segment: `roots` maps epoch to anchored root, as read
    /// from the chain. An epoch with no root supplied is
    /// [`DisclosureError::UnanchoredEpoch`] — a court that cannot check a
    /// segment rejects the bundle rather than ignoring the segment.
    ///
    /// ⚠️ **This does not check that the segments belong to one capsule, or
    /// that none is missing.** It cannot: those links are inside `C_rec` by
    /// construction. [`Bundle::open`] makes them, and a court runs both.
    ///
    /// # Errors
    ///
    /// The first [`DisclosureError`] any segment produces.
    pub fn verify(&self, roots: &[(u64, Digest32)]) -> Result<(), DisclosureError> {
        let mut memo = pqcl_forest::tier2::NodeMemo::default();
        self.verify_memo(roots, &mut memo)
    }

    /// [`Bundle::verify`] with the Tier-2 walk through a memo shared across a
    /// whole case.
    ///
    /// # Errors
    ///
    /// As [`Bundle::verify`].
    pub fn verify_memo(
        &self,
        roots: &[(u64, Digest32)],
        memo: &mut pqcl_forest::tier2::NodeMemo,
    ) -> Result<(), DisclosureError> {
        if self.segments.is_empty() {
            return Err(DisclosureError::EmptyChain);
        }
        for pair in self.segments.windows(2) {
            if pair[0].epoch >= pair[1].epoch {
                return Err(DisclosureError::SegmentOrder);
            }
        }
        for s in &self.segments {
            let root = roots
                .iter()
                .find(|(e, _)| *e == s.epoch)
                .map(|(_, r)| *r)
                .ok_or(DisclosureError::UnanchoredEpoch { epoch: s.epoch })?;
            s.verify_memo(&root, memo)?;
        }

        // ⭐ **The capsule itself** (M13 A3). Its `0x01` leaf is recomputed from
        // the disclosed capsule — so a swapped `d_ev`/`cm_ev`, an edited
        // pointer or a re-signed `σ_DEFR` all change the leaf — and checked
        // against the epoch that sealed it, which is `capsule.epoch` and not
        // necessarily any segment's.
        let seal_root = roots
            .iter()
            .find(|(e, _)| *e == self.seal.epoch)
            .map(|(_, r)| *r)
            .ok_or(DisclosureError::UnanchoredEpoch {
                epoch: self.seal.epoch,
            })?;
        if !pqcl_forest::tier2::verify_memo(
            &seal_root,
            &self.capsule.seal_leaf(),
            &self.seal.proof,
            memo,
        ) {
            return Err(DisclosureError::CapsuleNotAnchored);
        }
        Ok(())
    }

    /// The keyed half: open every body, and check what only a key holder can.
    ///
    /// Three checks the keyless pass cannot make, in increasing subtlety:
    ///
    /// 1. **each segment's pseudonym derives from `k_eid` and its claimed
    ///    epoch** — so a segment cannot be relabelled into another epoch, and
    ///    a court can enumerate epochs itself to find a segment the lab
    ///    omitted;
    /// 2. **the cross-segment links**, from each segment's first record's
    ///    `RecordBody::link` back to the previous segment's last record — the
    ///    link the AIS never sees;
    /// 3. **every `rid` matches the position the record was found at**, across
    ///    the whole chain rather than within a segment. ⭐ This catches a
    ///    dropped middle segment a *second*, independent way: the positions
    ///    would jump even if the link chain had been forged to close over the
    ///    gap.
    /// 4. **nothing follows a `DISPOSE`** (M13 A15): the disposition is
    ///    terminal, and the event that says so is inside `C_rec`.
    ///
    /// Returns the opened records in chain order: each body with its
    /// `σ_actor` and `σ_witness`, which since §1br F2 exist only inside
    /// `C_rec`, so this is where a court first sees them.
    ///
    /// # Errors
    ///
    /// The specific [`DisclosureError`]. [`DisclosureError::Sealed`] covers a
    /// wrong key, a wrong nonce, a wrong `rid` and a corrupted ciphertext
    /// alike: the AEAD does not distinguish them, and neither should this.
    pub fn open(&self) -> Result<Vec<OpenedRecord>, DisclosureError> {
        let k_rec = CustodyKey::new(self.keys.k_rec);
        let k_rid = PrfKey::new(self.keys.k_rid);

        let mut bodies: Vec<OpenedRecord> = Vec::with_capacity(self.record_count());
        let mut j: u64 = 0;
        let mut previous_link: Option<Digest32> = None;

        for (si, s) in self.segments.iter().enumerate() {
            if s.eid_e != self.expected_pseudonym(s.epoch) {
                return Err(DisclosureError::WrongPseudonym { epoch: s.epoch });
            }
            for (i, r) in s.records.iter().enumerate() {
                if r.rid != CustodyRecord::derive_rid(&k_rid, j) {
                    return Err(DisclosureError::WrongPosition { j });
                }
                let opened = r.open(&k_rec).map_err(|_| DisclosureError::Sealed { j })?;
                let body = &opened.body;
                if bodies
                    .last()
                    .is_some_and(|b| b.body.event == Event::Dispose)
                {
                    return Err(DisclosureError::AfterTerminal { j });
                }

                // The capsule's own base case, then every link after it. Inside
                // a segment the body's link repeats the cleartext `h_prev`,
                // which binds that cleartext into the AEAD; at a segment start
                // it is the only copy of the real link that exists.
                let expected =
                    previous_link.unwrap_or_else(|| CustodyRecord::genesis_link(&self.capsule.eid));
                if body.link != expected {
                    return Err(if i == 0 {
                        DisclosureError::BrokenSegmentLink { segment: si }
                    } else {
                        DisclosureError::BrokenChain { index: i }
                    });
                }

                previous_link = Some(r.chain_link());
                bodies.push(opened);
                j += 1;
            }
        }
        Ok(bodies)
    }

    /// Canonical bytes, so a court receives one file and an auditor can hash it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(&self.capsule.encode());
        w.field(&self.keys.k_eid)
            .field(&self.keys.k_rec)
            .field(&self.keys.k_rid);
        w.u64(self.segments.len() as u64);
        for s in &self.segments {
            s.encode_into(&mut w);
        }
        w.u64(self.seal.epoch);
        encode_proof(&mut w, &self.seal.proof);
        w.finish()
    }

    /// Parse a bundle.
    ///
    /// # Errors
    ///
    /// [`DisclosureError::Malformed`] wrapping the underlying codec error.
    pub fn decode(bytes: &[u8]) -> Result<Self, DisclosureError> {
        Self::decode_inner(bytes).map_err(DisclosureError::Malformed)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes)?;
        let capsule = Capsule::decode(r.field()?)?;
        let keys = DisclosureKeys {
            k_eid: r
                .field()?
                .try_into()
                .map_err(|_| CodecError::InvalidField("k_eid"))?,
            k_rec: r
                .field()?
                .try_into()
                .map_err(|_| CodecError::InvalidField("k_rec"))?,
            k_rid: r
                .field()?
                .try_into()
                .map_err(|_| CodecError::InvalidField("k_rid"))?,
        };
        let n = usize::try_from(r.u64()?).map_err(|_| CodecError::LengthOverflow)?;
        let mut segments = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            segments.push(Segment::decode_from(&mut r)?);
        }
        let seal = SealProof {
            epoch: r.u64()?,
            proof: decode_proof(&mut r)?,
        };
        r.finish()?;
        Ok(Self {
            capsule,
            segments,
            seal,
            keys,
        })
    }
}

/// One MMR proof's wire form. Shared by a segment's `0x02` proof and the
/// capsule's `0x01` seal proof, so the two cannot drift apart (M13 A3).
fn encode_proof(w: &mut Writer, proof: &MmrProof) {
    w.u64(proof.index).u64(proof.count);
    w.u64(proof.path.len() as u64);
    for s in &proof.path {
        w.field(&s.sibling).byte(u8::from(s.sibling_is_right));
    }
    w.u64(proof.peaks_left.len() as u64);
    for p in &proof.peaks_left {
        w.field(p);
    }
    w.u64(proof.peaks_right.len() as u64);
    for p in &proof.peaks_right {
        w.field(p);
    }
}

fn decode_proof(r: &mut Reader<'_>) -> Result<MmrProof, CodecError> {
    let index = r.u64()?;
    let count = r.u64()?;
    let path_len = usize::try_from(r.u64()?).map_err(|_| CodecError::LengthOverflow)?;
    let mut path = Vec::with_capacity(path_len.min(64));
    for _ in 0..path_len {
        let sibling: Digest32 = r
            .field()?
            .try_into()
            .map_err(|_| CodecError::InvalidField("sibling"))?;
        let sibling_is_right = match r.byte()? {
            0 => false,
            1 => true,
            _ => return Err(CodecError::InvalidField("side")),
        };
        path.push(pqcl_forest::ProofStep {
            sibling,
            sibling_is_right,
        });
    }
    let peaks_left = read_peaks(r)?;
    let peaks_right = read_peaks(r)?;
    Ok(MmrProof {
        index,
        count,
        path,
        peaks_left,
        peaks_right,
    })
}

fn read_peaks(r: &mut Reader<'_>) -> Result<Vec<Digest32>, CodecError> {
    let n = usize::try_from(r.u64()?).map_err(|_| CodecError::LengthOverflow)?;
    let mut out = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        out.push(
            r.field()?
                .try_into()
                .map_err(|_| CodecError::InvalidField("peak"))?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod sealed_disclosure_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{DisclosureKeys, SealedDisclosure};
    use pqcl_primitives::kem;

    fn keys() -> DisclosureKeys {
        DisclosureKeys {
            k_eid: [1; 32],
            k_rec: [2; 32],
            k_rid: [3; 32],
        }
    }

    /// The court opens what was sealed to it; the bytes survive the wire.
    #[test]
    fn the_court_opens_it_and_nobody_else_does() {
        let court = kem::KeyPair::generate().unwrap();
        let s =
            SealedDisclosure::seal(&keys(), [7; 32], [8; 32], court.encapsulation_key()).unwrap();
        let back = SealedDisclosure::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.open(&court).unwrap(), keys());

        let other = kem::KeyPair::generate().unwrap();
        assert!(s.open(&other).is_err(), "another key opened it");
    }

    /// Bound to `(cid_c, eid)`: relabelled for another capsule, it fails.
    #[test]
    fn it_is_bound_to_its_case_and_capsule() {
        let court = kem::KeyPair::generate().unwrap();
        let s =
            SealedDisclosure::seal(&keys(), [7; 32], [8; 32], court.encapsulation_key()).unwrap();
        let mut moved = s.clone();
        moved.eid = [9; 32];
        assert!(moved.open(&court).is_err(), "opened under another eid");
        let mut moved = s;
        moved.cid_c = [9; 32];
        assert!(moved.open(&court).is_err(), "opened under another case");
    }
}
