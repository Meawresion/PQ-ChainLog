//! Court-ordered redaction: the order and its `0x05` leaf (draft7 Phase 11).
//!
//! ```text
//! order = ML-DSA.Sign(sk_CO, (oid, tgt, scope, mode, ts, exp))      eq:order
//! 0x05 ‖ H(⟪oid, tgt, scope, mode, σ_CO, ts⟫)                       eq:leaves
//! ```
//!
//! # The signed message is fixed-width, byte for byte
//!
//! `σ_CO` signs `abi.encodePacked(bytes32 oid, bytes32 tgt, uint8 scope,
//! uint8 mode, uint64 ts, uint64 exp)`: fixed widths, big-endian, 82 bytes.
//! ⚠️ Since D4 the contract does **not** verify it: `orderRedaction(cid, oid,
//! digest)` records the order's `0x05` digest, from the case's anchorer only
//! (M13 A16), and the AIS and auditors verify `σ_CO` under the court key. The
//! encoding is kept EVM-shaped so an on-chain verifier remains possible. Fixed-width
//! packing is injective, so no framing is needed there, and [`Order::message`]
//! is that encoding. `contracts/test/vectors/redaction-order-mldsa65.json`
//! carries a real order signed here, and the Solidity suite re-encodes the
//! fields and compares, so the two cannot drift silently.
//!
//! ⚠️ **Every field is signed**. Until
//! 2026-09-28 the contract signed `(orderId, target, scope)` only: a relay could
//! turn `ERASED` into `SEALED`, keeping `r_ev` escrowed after a court ordered it
//! destroyed, and could replay an expired order, with every signature still
//! verifying.
//!
//! # The target of a sweep is one digest
//!
//! `tgt` is a capsule's pseudonym `eid`, or for a set the Merkle root over the
//! **sorted, de-duplicated** member pseudonyms, promote-never-duplicate
//! (CVE-2012-2459). A one-member set's root is that member, so the two forms
//! agree. A retention sweep is therefore one order and one leaf whatever `k`.

use pqcl_forest::{CustodyTree, InclusionProof, Leaf, verify_leaf};

use crate::codec::Writer;
use pqcl_primitives::Signer;
use pqcl_primitives::sig::{SigError, verify};
use pqcl_primitives::xof::{Digest32, Domain};

/// Bytes of the signed `eq:order` message: 32 + 32 + 1 + 1 + 8 + 8.
pub const ORDER_MESSAGE_BYTES: usize = 82;

/// What a redaction removes (Phase 11, Step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Scope {
    /// The payload only: content unreadable, a match still learnable.
    Payload = 1,
    /// Payload and index: no trapdoor returns the capsule (tombstones landed).
    PayloadIndex = 2,
    /// Payload, index and compaction: the association is unrecoverable even to
    /// a later holder of current keys.
    Full = 3,
}

impl Scope {
    /// Discriminant as signed and encoded.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Parse a discriminant.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Payload),
            2 => Some(Self::PayloadIndex),
            3 => Some(Self::Full),
            _ => None,
        }
    }

    /// Whether this scope removes the index association.
    #[must_use]
    pub const fn touches_index(self) -> bool {
        matches!(self, Self::PayloadIndex | Self::Full)
    }
}

/// What happens to `r_ev`, the opening of `cm_ev`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Mode {
    /// `r_ev` escrowed with the court: `cm_ev` stays openable on its order.
    Sealed = 1,
    /// `r_ev` destroyed: `cm_ev` can never be opened.
    Erased = 2,
}

impl Mode {
    /// Discriminant as signed and encoded.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Parse a discriminant.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Sealed),
            2 => Some(Self::Erased),
            _ => None,
        }
    }
}

/// Why an order is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderError {
    /// `σ_CO` does not verify under the court key over the whole tuple.
    BadSignature,
    /// `now > exp`.
    Expired {
        /// The order's expiry.
        exp: u64,
        /// The time it was presented.
        now: u64,
    },
    /// `ts > exp`: an order that was never valid.
    Malformed,
    /// Not recorded on chain. Phase 11 Step 1: nothing is deleted before.
    NotRecorded,
    /// ⭐ Recorded on chain, but **as a different order**: the digest the
    /// contract holds for this `oid` is not this order's `0x05` leaf
    /// (`eq:vred`'s `ℓ^ord = order^chain_oid`, M13 A7). An order id is not the
    /// order; checking only that *something* was recorded under it accepted any
    /// order an AIS chose to present under a recorded id.
    RecordedDigestDiffers,
    /// The capsule is not a member of the order's target.
    NotTargeted,
}

impl core::fmt::Display for OrderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSignature => f.write_str("court signature does not verify"),
            Self::Expired { exp, now } => write!(f, "order expired at {exp}, presented at {now}"),
            Self::Malformed => f.write_str("order issued after its own expiry"),
            Self::NotRecorded => f.write_str("order not recorded on chain"),
            Self::RecordedDigestDiffers => {
                f.write_str("the chain recorded a different order under this id")
            }
            Self::NotTargeted => f.write_str("capsule is not in the order's target"),
        }
    }
}

impl core::error::Error for OrderError {}

/// A signed redaction order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    /// `oid`, resolving to the court's own instrument.
    pub oid: Digest32,
    /// `tgt`: a pseudonym, or the root over a sorted set of them.
    pub tgt: Digest32,
    /// What is removed.
    pub scope: Scope,
    /// What happens to `r_ev`.
    pub mode: Mode,
    /// Issue time, seconds.
    pub ts: u64,
    /// Expiry, seconds.
    pub exp: u64,
    /// `σ_CO`, ML-DSA-65 by the Court Authority over [`Order::message`].
    pub sig_co: Vec<u8>,
}

impl Order {
    /// The signed `eq:order` bytes: `abi.encodePacked` of the six fields.
    #[must_use]
    pub fn message_of(
        oid: &Digest32,
        tgt: &Digest32,
        scope: Scope,
        mode: Mode,
        ts: u64,
        exp: u64,
    ) -> [u8; ORDER_MESSAGE_BYTES] {
        let mut m = [0u8; ORDER_MESSAGE_BYTES];
        m[..32].copy_from_slice(oid);
        m[32..64].copy_from_slice(tgt);
        m[64] = scope.byte();
        m[65] = mode.byte();
        m[66..74].copy_from_slice(&ts.to_be_bytes());
        m[74..82].copy_from_slice(&exp.to_be_bytes());
        m
    }

    /// This order's signed bytes.
    #[must_use]
    pub fn message(&self) -> [u8; ORDER_MESSAGE_BYTES] {
        Self::message_of(
            &self.oid, &self.tgt, self.scope, self.mode, self.ts, self.exp,
        )
    }

    /// Issue an order under the Court Authority's key.
    ///
    /// # Errors
    ///
    /// A signing failure.
    pub fn issue(
        court: &impl Signer,
        oid: Digest32,
        tgt: Digest32,
        scope: Scope,
        mode: Mode,
        ts: u64,
        exp: u64,
    ) -> Result<Self, SigError> {
        let sig_co = court.sign(&Self::message_of(&oid, &tgt, scope, mode, ts, exp))?;
        Ok(Self {
            oid,
            tgt,
            scope,
            mode,
            ts,
            exp,
            sig_co,
        })
    }

    /// Verify `σ_CO` under the court key over **every** field, and the expiry.
    ///
    /// # Errors
    ///
    /// [`OrderError::BadSignature`], [`OrderError::Expired`] or
    /// [`OrderError::Malformed`].
    pub fn verify(&self, court_pk: &[u8], now: u64) -> Result<(), OrderError> {
        if self.ts > self.exp {
            return Err(OrderError::Malformed);
        }
        if now > self.exp {
            return Err(OrderError::Expired { exp: self.exp, now });
        }
        verify(&self.message(), &self.sig_co, court_pk, &[]).map_err(|_| OrderError::BadSignature)
    }

    /// Canonical bytes, framed in field order: what a disclosure carries and
    /// what chain replay records as its entry.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(&self.oid)
            .field(&self.tgt)
            .byte(self.scope.byte())
            .byte(self.mode.byte())
            .u64(self.ts)
            .u64(self.exp)
            .field(&self.sig_co);
        w.into_inner()
    }

    /// The Tier-2 `0x05` leaf, `0x05 ‖ H(⟪oid, tgt, scope, mode, σ_CO, ts⟫)`.
    ///
    /// Framed like the other four leaf types; `ts` little-endian as `0x01`'s
    /// epoch is. `exp` is not in the leaf (draft7 `eq:leaves`): it is signed,
    /// so the anchored `σ_CO` binds it anyway.
    #[must_use]
    pub fn leaf(&self) -> Leaf {
        Leaf::new(
            Domain::Dispose,
            &[
                &self.oid,
                &self.tgt,
                &[self.scope.byte()],
                &[self.mode.byte()],
                &self.sig_co,
                &self.ts.to_le_bytes(),
            ],
        )
    }
}

/// A capsule set as an order targets it: its sorted, de-duplicated members.
#[derive(Debug, Clone)]
pub struct Target {
    members: Vec<Digest32>,
    tree: CustodyTree,
}

impl Target {
    /// The set over `members`, in any order and with repeats.
    ///
    /// # Panics
    ///
    /// If `members` is empty: an order over nothing has no target.
    #[must_use]
    pub fn new(members: &[Digest32]) -> Self {
        let mut m = members.to_vec();
        m.sort_unstable();
        m.dedup();
        assert!(
            !m.is_empty(),
            "a redaction target needs at least one capsule"
        );
        let mut tree = CustodyTree::new();
        for d in &m {
            tree.append_leaf(*d);
        }
        Self { members: m, tree }
    }

    /// `tgt`. For one member, the member itself.
    #[must_use]
    pub fn root(&self) -> Digest32 {
        self.tree
            .root()
            .unwrap_or_else(|| unreachable!("a target is never empty"))
    }

    /// Members, sorted.
    #[must_use]
    pub fn members(&self) -> &[Digest32] {
        &self.members
    }

    /// A membership proof for `eid`, or `None` if it is not targeted.
    #[must_use]
    pub fn prove(&self, eid: &Digest32) -> Option<InclusionProof> {
        let i = self.members.binary_search(eid).ok()?;
        self.tree.prove(i)
    }
}

/// Whether `eid` is covered by `tgt`, given its membership proof.
#[must_use]
pub fn targets(tgt: &Digest32, eid: &Digest32, proof: &InclusionProof) -> bool {
    verify_leaf(tgt, eid, proof)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use pqcl_primitives::SoftwareMlDsa;

    fn d(b: u8) -> Digest32 {
        [b; 32]
    }

    fn order(court: &SoftwareMlDsa) -> Order {
        Order::issue(court, d(1), d(2), Scope::Full, Mode::Erased, 100, 200).unwrap()
    }

    #[test]
    fn a_genuine_order_verifies_until_it_expires() {
        let court = SoftwareMlDsa::generate().unwrap();
        let o = order(&court);
        assert_eq!(o.verify(court.public_key(), 150), Ok(()));
        assert_eq!(o.verify(court.public_key(), 200), Ok(()));
        assert_eq!(
            o.verify(court.public_key(), 201),
            Err(OrderError::Expired { exp: 200, now: 201 })
        );
    }

    #[test]
    fn every_signed_field_is_bound() {
        // ⭐ §1u.3's negative test, Rust side: flipping `mode` or `exp` (or any
        // other field) after signing must fail verification.
        let court = SoftwareMlDsa::generate().unwrap();
        let o = order(&court);
        let pk = court.public_key();
        let mut m = o.clone();
        m.mode = Mode::Sealed;
        assert_eq!(m.verify(pk, 150), Err(OrderError::BadSignature), "mode");
        let mut m = o.clone();
        m.exp = 10_000;
        assert_eq!(m.verify(pk, 150), Err(OrderError::BadSignature), "exp");
        let mut m = o.clone();
        m.ts = 99;
        assert_eq!(m.verify(pk, 150), Err(OrderError::BadSignature), "ts");
        let mut m = o.clone();
        m.scope = Scope::Payload;
        assert_eq!(m.verify(pk, 150), Err(OrderError::BadSignature), "scope");
        let mut m = o.clone();
        m.tgt = d(3);
        assert_eq!(m.verify(pk, 150), Err(OrderError::BadSignature), "tgt");
        let mut m = o;
        m.oid = d(4);
        assert_eq!(m.verify(pk, 150), Err(OrderError::BadSignature), "oid");
    }

    #[test]
    fn another_authoritys_key_does_not_verify_an_order() {
        let court = SoftwareMlDsa::generate().unwrap();
        let warrant_key = SoftwareMlDsa::generate().unwrap();
        let o = order(&court);
        assert_eq!(
            o.verify(warrant_key.public_key(), 150),
            Err(OrderError::BadSignature)
        );
    }

    #[test]
    fn the_message_is_abi_encode_packed() {
        let m = Order::message_of(
            &d(0xaa),
            &d(0xbb),
            Scope::PayloadIndex,
            Mode::Sealed,
            1,
            0x0102,
        );
        assert_eq!(m.len(), 82);
        assert_eq!(&m[..32], &[0xaa; 32]);
        assert_eq!(&m[32..64], &[0xbb; 32]);
        assert_eq!(m[64], 2);
        assert_eq!(m[65], 1);
        assert_eq!(&m[66..74], &[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&m[74..82], &[0, 0, 0, 0, 0, 0, 1, 2]);
    }

    #[test]
    fn the_leaf_is_tagged_and_binds_its_fields() {
        let court = SoftwareMlDsa::generate().unwrap();
        let o = order(&court);
        let l = o.leaf();
        assert_eq!(l.domain, Domain::Dispose);
        let mut m = o.clone();
        m.mode = Mode::Sealed;
        assert_ne!(m.leaf().digest, l.digest);
        let same_fields = Leaf::new(
            Domain::CustodyRoot,
            &[&o.oid, &o.tgt, &[3], &[2], &o.sig_co, &o.ts.to_le_bytes()],
        );
        assert_ne!(same_fields.digest, l.digest, "0x05 must not be confusable");
    }

    #[test]
    fn a_target_is_order_independent_and_proves_membership() {
        let a = Target::new(&[d(3), d(1), d(2), d(1)]);
        let b = Target::new(&[d(1), d(2), d(3)]);
        assert_eq!(a.root(), b.root());
        assert_eq!(a.members().len(), 3);
        for x in [d(1), d(2), d(3)] {
            let p = a.prove(&x).unwrap();
            assert!(targets(&a.root(), &x, &p));
        }
        assert!(a.prove(&d(9)).is_none());
        let p = a.prove(&d(1)).unwrap();
        assert!(!targets(&a.root(), &d(9), &p), "a non-member passed");
        // One member: the root is the pseudonym itself.
        assert_eq!(Target::new(&[d(7)]).root(), d(7));
    }
}
