//! Phase 11 on the AIS, and `0x05` accounting for the auditor and sweeper.
//!
//! draft7 Phase 11, in its four steps, and Phase 10's post-redaction check:
//!
//! 1. **Order.** [`execute`] refuses unless `σ_CO` verifies under the court
//!    key over the whole `eq:order` tuple, the order has not expired, **and**
//!    it is recorded on chain ([`OrderRegistry`]). Nothing is deleted before.
//! 2. **Erase.** The payload `C_ev` is deleted. Under `PAYLOAD+INDEX` and
//!    `FULL`, every `(w, eid)` pair, **range-prefix keywords included**
//!    ([`index_keywords`]), gets an in-band `Π_core` deletion and a tombstone.
//!    `FULL` then compacts at once, destroying the superseded `{K_X^(e)}`.
//!    Tombstones land first: [`execute`] cannot be called in the other order.
//! 3. **Custody record.** [`crate::Agent::dispose_record`] carries `oid`.
//! 4. **Anchor.** [`crate::Ais::record_order`] appends the `0x05` leaf. `mode`
//!    decides `r_ev`: `ERASED` destroys it, `SEALED` escrows it to the court.
//!
//! [`account`] is the auditor's side: a payload may be absent only if a
//! genuine, anchored `0x05` order targets its capsule **and** a `DISPOSE`
//! record references that order. Anything else is a finding, and so is a
//! redacted payload that is still present.
//!
//! ⚠️ **`r_ev` is held here as opaque opening material.** `cm_ev` blinding is
//! out of campaign 05's scope, so nothing in
//! the ingest path produces an `r_ev` yet; [`Openings`] is where the lab's
//! openings live once it does, and `mode` is enforced over it now.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::io;
use std::path::{Path, PathBuf};

use pqcl_capsule::disclosure::SealProof;
use pqcl_capsule::redaction::{Mode, Order, OrderError, Scope, targets};
use pqcl_capsule::{Capsule, CustodyRecord, Segment};
use pqcl_dsse::core::{Client as CoreClient, DocId, Edb, Op};
use pqcl_dsse::range::RangeTree;
use pqcl_dsse::xt::{XSetStore, XtClient};
use pqcl_forest::{InclusionProof, MmrProof, tier2};
use pqcl_primitives::aead::{RecordKey, SealedRecord};
use pqcl_primitives::kem;
use pqcl_primitives::xof::{Digest32, PrfKey};

/// What the chain recorded for each order (`Anchor.recordedOrder(cid, oid)`,
/// or the `RedactionOrdered` events a node returned).
///
/// ⭐ **The digest, not a yes/no** (M13 A7). `eq:vred` requires the order's
/// `0x05` leaf to *equal* what the contract recorded for its id; a registry
/// that answered only "is this id recorded" let any order be presented under
/// a recorded id. A set of ids cannot answer the question, which is why there
/// is no `HashSet` implementation any more.
pub trait OrderRegistry {
    /// The `0x05` digest recorded for `oid`, if any.
    fn recorded(&self, oid: &Digest32) -> Option<Digest32>;
}

impl<H: BuildHasher> OrderRegistry for HashMap<Digest32, Digest32, H> {
    fn recorded(&self, oid: &Digest32) -> Option<Digest32> {
        self.get(oid).copied()
    }
}

/// The order's leaf is exactly what the chain recorded under its id.
fn matches_chain(order: &Order, registry: &impl OrderRegistry) -> Result<(), OrderError> {
    match registry.recorded(&order.oid) {
        None => Err(OrderError::NotRecorded),
        Some(d) if d != order.leaf().digest => Err(OrderError::RecordedDigestDiffers),
        Some(_) => Ok(()),
    }
}

/// Encrypted payloads, one file per capsule pseudonym.
#[derive(Debug, Clone)]
pub struct PayloadStore {
    dir: PathBuf,
}

impl PayloadStore {
    /// A store rooted at `dir`, created if missing.
    ///
    /// # Errors
    ///
    /// An I/O error creating the directory.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Where `eid`'s ciphertext lives.
    #[must_use]
    pub fn path(&self, eid: &Digest32) -> PathBuf {
        self.dir.join(hex(eid))
    }

    /// Store `eid`'s ciphertext.
    ///
    /// # Errors
    ///
    /// An I/O error writing it.
    pub fn put(&self, eid: &Digest32, ciphertext: &[u8]) -> io::Result<()> {
        std::fs::write(self.path(eid), ciphertext)
    }

    /// Whether `eid`'s ciphertext is present.
    #[must_use]
    pub fn exists(&self, eid: &Digest32) -> bool {
        self.path(eid).is_file()
    }

    /// Delete `eid`'s ciphertext. Deleting an absent payload is not an error:
    /// a retried order must be idempotent.
    ///
    /// # Errors
    ///
    /// Any I/O error other than "not found".
    pub fn erase(&self, eid: &Digest32) -> io::Result<()> {
        match std::fs::remove_file(self.path(eid)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// The lab's `r_ev` openings, one per capsule.
#[derive(Debug, Default)]
pub struct Openings {
    map: HashMap<Digest32, [u8; 32]>,
}

impl Openings {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `r_ev` for `eid`.
    pub fn insert(&mut self, eid: Digest32, r_ev: [u8; 32]) {
        self.map.insert(eid, r_ev);
    }

    /// Whether the lab still holds an opening for `eid`.
    #[must_use]
    pub fn holds(&self, eid: &Digest32) -> bool {
        self.map.contains_key(eid)
    }

    fn take(&mut self, eid: &Digest32) -> Option<[u8; 32]> {
        self.map.remove(eid)
    }
}

/// `r_ev` escrowed to the court under `SEALED`: ML-KEM-768 to the court's
/// encapsulation key, AES-256-GCM under the shared secret, bound to
/// `(oid, eid)`. The lab keeps nothing it can open.
#[derive(Debug, Clone)]
pub struct Escrow {
    /// The capsule.
    pub eid: Digest32,
    /// The order it was escrowed under.
    pub oid: Digest32,
    /// ML-KEM-768 ciphertext.
    pub kem_ct: Vec<u8>,
    /// `r_ev`, sealed.
    pub sealed: SealedRecord,
}

impl Escrow {
    fn seal(
        court_ek: &[u8],
        oid: Digest32,
        eid: Digest32,
        r_ev: &[u8; 32],
    ) -> Result<Self, RedactionError> {
        let (kem_ct, ss) =
            kem::encapsulate(court_ek).map_err(|e| RedactionError::Escrow(e.to_string()))?;
        let sealed = RecordKey::new(*ss.as_bytes())
            .seal(&[oid.as_slice(), eid.as_slice()].concat(), r_ev)
            .map_err(|e| RedactionError::Escrow(e.to_string()))?;
        Ok(Self {
            eid,
            oid,
            kem_ct,
            sealed,
        })
    }

    /// The court recovers `r_ev` with its decapsulation key.
    ///
    /// # Errors
    ///
    /// A decapsulation or authentication failure.
    pub fn open(&self, court: &kem::KeyPair) -> Result<[u8; 32], RedactionError> {
        let ss = court
            .decapsulate(&self.kem_ct)
            .map_err(|e| RedactionError::Escrow(e.to_string()))?;
        let r = RecordKey::new(*ss.as_bytes())
            .open(
                &[self.oid.as_slice(), self.eid.as_slice()].concat(),
                &self.sealed,
            )
            .map_err(|e| RedactionError::Escrow(e.to_string()))?;
        r.try_into()
            .map_err(|_| RedactionError::Escrow("escrowed opening is not 32 bytes".into()))
    }
}

/// Why an execution was refused or failed.
#[derive(Debug)]
pub enum RedactionError {
    /// The order itself: signature, expiry, not recorded, not targeted.
    Order(OrderError),
    /// Deleting a payload failed.
    Io(io::Error),
    /// A `Π_core` deletion failed to seal.
    Index(String),
    /// Escrowing `r_ev` failed.
    Escrow(String),
}

impl core::fmt::Display for RedactionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Order(e) => write!(f, "order refused: {e}"),
            Self::Io(e) => write!(f, "payload erase failed: {e}"),
            Self::Index(e) => write!(f, "index deletion failed: {e}"),
            Self::Escrow(e) => write!(f, "escrow failed: {e}"),
        }
    }
}

impl core::error::Error for RedactionError {}

impl From<OrderError> for RedactionError {
    fn from(e: OrderError) -> Self {
        Self::Order(e)
    }
}

/// One capsule an order covers, as the AIS holds it.
#[derive(Debug, Clone)]
pub struct Redactee {
    /// The capsule pseudonym.
    pub eid: Digest32,
    /// Its document id in the evidence-plane index.
    pub doc: DocId,
    /// Its membership proof in the order's target.
    pub membership: InclusionProof,
    /// Every keyword it was indexed under, **range prefixes included** — see
    /// [`index_keywords`].
    pub keywords: Vec<Vec<u8>>,
}

/// A capsule's full keyword set: its plain keywords plus, for every range
/// attribute, the leaf and every ancestor prefix (`RangeTree::index_keywords`).
///
/// ⭐ §1u item (f). A redaction that tombstoned only the plain keywords would
/// leave the capsule returned by any range query covering its value: a
/// searchable ghost.
#[must_use]
pub fn index_keywords(plain: &[Vec<u8>], ranges: &[(&RangeTree, u64)]) -> Vec<Vec<u8>> {
    let mut out = plain.to_vec();
    for (tree, v) in ranges {
        out.extend(tree.index_keywords(*v));
    }
    out
}

/// What an execution did.
#[derive(Debug)]
pub struct Outcome {
    /// Payloads deleted.
    pub payloads_erased: usize,
    /// `(w, eid)` pairs deleted in-band and tombstoned.
    pub pairs_tombstoned: usize,
    /// Whether compaction ran (`FULL` only).
    pub compacted: bool,
    /// Openings escrowed to the court (`SEALED`).
    pub escrows: Vec<Escrow>,
    /// Openings destroyed (`ERASED`).
    pub openings_destroyed: usize,
}

/// Execute a recorded order on the AIS: Phase 11, Steps 1–2 and `r_ev`.
///
/// `fresh_seed` is called only under `FULL`, for the compaction's new
/// `K_X^(0)`: an **independent draw**, never a derivation from a surviving key.
///
/// # Errors
///
/// [`RedactionError::Order`] before anything is touched if the order does not
/// verify, has expired, is not recorded, or does not target a capsule;
/// otherwise the first I/O, index or escrow failure.
#[allow(clippy::too_many_arguments)]
pub fn execute<S: Edb + XSetStore>(
    order: &Order,
    court_pk: &[u8],
    now: u64,
    registry: &impl OrderRegistry,
    redactees: &[Redactee],
    payloads: &PayloadStore,
    openings: &mut Openings,
    court_ek: &[u8],
    index: &mut XtClient,
    store: &mut S,
    fresh_seed: impl FnOnce() -> PrfKey,
) -> Result<Outcome, RedactionError> {
    let mut out = gate_and_erase(order, court_pk, now, registry, redactees, payloads)?;
    if order.scope.touches_index() {
        for r in redactees {
            for w in &r.keywords {
                index
                    .update(store, Op::Del, w, r.doc)
                    .map_err(|e| RedactionError::Index(e.to_string()))?;
                index.tombstone(w, r.doc);
                out.pairs_tombstoned += 1;
            }
        }
        // The deletions' own cross-tags are in the buffer; flush so the store
        // state is what the server now holds.
        index.flush(store);
    }
    if order.scope == Scope::Full {
        index.compact(store, fresh_seed());
        out.compacted = true;
    }
    settle_openings(order, redactees, openings, court_ek, &mut out)?;
    Ok(out)
}

/// [`execute`] over the evidence plane's `Π_core` index alone, with no
/// conjunctive layer: the deployment SAC describes (the design record
/// §1cf).
///
/// ⭐ **`FULL` deletes exactly what `PAYLOAD+INDEX` deletes here.** What `FULL`
/// adds in [`execute`] is compaction of `Π_XT`'s `XSet` and destruction of the
/// superseded `{K_X^(e)}`, and `Π_core` has neither: B′'s cleanup round is
/// omitted by design, so a deletion is an in-band `Del` that later searches
/// cancel client-side, and no index entry is physically dropped. `r_ev` is
/// decided by `mode` at every scope, as in [`execute`].
///
/// # Errors
///
/// As [`execute`]: [`RedactionError::Order`] before anything is touched,
/// otherwise the first I/O, index or escrow failure.
#[allow(clippy::too_many_arguments)]
pub fn execute_core<S: Edb>(
    order: &Order,
    court_pk: &[u8],
    now: u64,
    registry: &impl OrderRegistry,
    redactees: &[Redactee],
    payloads: &PayloadStore,
    openings: &mut Openings,
    court_ek: &[u8],
    index: &mut CoreClient,
    store: &mut S,
) -> Result<Outcome, RedactionError> {
    let mut out = gate_and_erase(order, court_pk, now, registry, redactees, payloads)?;
    if order.scope.touches_index() {
        for r in redactees {
            for w in &r.keywords {
                let token = index
                    .update(Op::Del, w, r.doc)
                    .map_err(|e| RedactionError::Index(e.to_string()))?;
                store.insert(&token);
                out.pairs_tombstoned += 1;
            }
        }
    }
    settle_openings(order, redactees, openings, court_ek, &mut out)?;
    Ok(out)
}

/// Step 1, every check before any deletion, then the payloads.
fn gate_and_erase(
    order: &Order,
    court_pk: &[u8],
    now: u64,
    registry: &impl OrderRegistry,
    redactees: &[Redactee],
    payloads: &PayloadStore,
) -> Result<Outcome, RedactionError> {
    order.verify(court_pk, now)?;
    matches_chain(order, registry)?;
    for r in redactees {
        if !targets(&order.tgt, &r.eid, &r.membership) {
            return Err(OrderError::NotTargeted.into());
        }
    }
    let mut out = Outcome {
        payloads_erased: 0,
        pairs_tombstoned: 0,
        compacted: false,
        escrows: Vec::new(),
        openings_destroyed: 0,
    };
    for r in redactees {
        payloads.erase(&r.eid).map_err(RedactionError::Io)?;
        out.payloads_erased += 1;
    }
    Ok(out)
}

/// `r_ev` by mode: escrowed to the court under `SEALED`, destroyed under
/// `ERASED`.
fn settle_openings(
    order: &Order,
    redactees: &[Redactee],
    openings: &mut Openings,
    court_ek: &[u8],
    out: &mut Outcome,
) -> Result<(), RedactionError> {
    for r in redactees {
        if let Some(r_ev) = openings.take(&r.eid) {
            match order.mode {
                Mode::Sealed => out
                    .escrows
                    .push(Escrow::seal(court_ek, order.oid, r.eid, &r_ev)?),
                Mode::Erased => {
                    let mut r_ev = r_ev;
                    r_ev.fill(0);
                    out.openings_destroyed += 1;
                }
            }
        }
    }
    Ok(())
}

/// Why [`verify_redaction`] refused, one variant per conjunct of
/// `eq:validredact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionCheck {
    /// `Verify_pkCO(order)` fails: not the court's signature over these fields.
    Order,
    /// `eid ∉ tgt`: the membership proof does not reach the order's target.
    NotTargeted,
    /// The disposal's last record does not carry `oref = oid`.
    NoDisposal,
    /// `L_ev` is not in its sealing epoch's anchored root.
    SealNotAnchored,
    /// `L_red` is not in the redaction epoch's anchored root.
    OrderNotAnchored,
    /// `L_coc` is not in the redaction epoch's anchored root, or the segment is
    /// filed under another capsule's pseudonym.
    DisposalNotAnchored,
    /// The redaction epoch `e′` is before the capsule's sealing epoch `e`: an
    /// order cannot redact what was not yet sealed (`genuine_orders` refuses
    /// the same, §1ci.5 item 5).
    OrderPrecedesSeal,
}

impl core::fmt::Display for RedactionCheck {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Order => "the order does not verify under the court key",
            Self::NotTargeted => "the capsule is not in the order's target",
            Self::NoDisposal => "no DISPOSE references the order",
            Self::SealNotAnchored => "the capsule's 0x01 leaf is not anchored",
            Self::OrderNotAnchored => "the order's leaf is not anchored in the redaction epoch",
            Self::DisposalNotAnchored => "the DISPOSE's 0x02 leaf is not anchored for this capsule",
            Self::OrderPrecedesSeal => "the redaction epoch is before the capsule's sealing epoch",
        })
    }
}

impl core::error::Error for RedactionCheck {}

/// What a court is handed to accept one missing payload as lawful.
#[derive(Debug, Clone, Copy)]
pub struct RedactionClaim<'a> {
    /// The order.
    pub order: &'a Order,
    /// The capsule's membership in `tgt`.
    pub membership: &'a InclusionProof,
    /// `L_red`'s inclusion proof in the redaction epoch `e′`.
    pub order_proof: &'a MmrProof,
    /// The redacted capsule; its `0x01` leaf is recomputed, not handed over.
    pub capsule: &'a Capsule,
    /// `L_ev`'s inclusion proof in the sealing epoch `e`.
    pub seal: &'a SealProof,
    /// The capsule's segment in `e′`, ending in the `DISPOSE`, with its `0x02`
    /// proof.
    pub disposal: &'a Segment,
}

/// `eq:validredact` (SAC Phase 5 Step 4), every conjunct:
///
/// ```text
/// Verify_pkCO(order) ∧ [eid ∈ tgt] ∧ [oref = oid] ∧ [e′ ≥ e]
///   ∧ Incl(L_ev, R_e) ∧ Incl(L_red, R_e′) ∧ Incl(L_coc, R_e′)
/// ```
///
/// `[e′ ≥ e]` (§1ci.5 item 5) is the ordering `genuine_orders` already
/// enforces for the auditor; it costs one comparison.
///
/// `roots` are the anchored `(e, R_e)`. `k_eid` is the capsule's link key, which
/// a court disclosure carries: it is what ties the disposal's pseudonym `eid_e′`
/// to this capsule, so a `DISPOSE` of another capsule cannot be presented.
///
/// [`account`] is the auditor's sweep over a whole case and takes each
/// `DISPOSE` as the AIS stores it; this is the per-capsule check with the
/// `0x02` inclusion that sweep leaves to the court's `accept`.
///
/// # Errors
///
/// The first conjunct that fails, as a [`RedactionCheck`].
pub fn verify_redaction(
    claim: &RedactionClaim<'_>,
    court_pk: &[u8],
    k_eid: &PrfKey,
    roots: &[(u64, Digest32)],
) -> Result<(), RedactionCheck> {
    let root_of = |e: u64| roots.iter().find(|(x, _)| *x == e).map(|(_, r)| r);
    let o = claim.order;
    let d = claim.disposal;
    // Expiry is not re-checked: an order valid when executed stays valid
    // evidence afterwards, as in `account`.
    o.verify(court_pk, o.ts)
        .map_err(|_| RedactionCheck::Order)?;
    if !targets(&o.tgt, &claim.capsule.eid, claim.membership) {
        return Err(RedactionCheck::NotTargeted);
    }
    if d.records.last().and_then(|r| r.order_ref) != Some(o.oid) {
        return Err(RedactionCheck::NoDisposal);
    }
    if d.epoch < claim.seal.epoch {
        return Err(RedactionCheck::OrderPrecedesSeal);
    }
    let sealed = root_of(claim.seal.epoch)
        .is_some_and(|r| tier2::verify(r, &claim.capsule.seal_leaf(), &claim.seal.proof));
    if !sealed {
        return Err(RedactionCheck::SealNotAnchored);
    }
    let r_red = root_of(d.epoch).ok_or(RedactionCheck::OrderNotAnchored)?;
    if !tier2::verify(r_red, &o.leaf(), claim.order_proof) {
        return Err(RedactionCheck::OrderNotAnchored);
    }
    let ours = d.eid_e == CustodyRecord::epoch_pseudonym(k_eid, d.epoch);
    let anchored = d
        .custody_leaf()
        .is_some_and(|l| tier2::verify(r_red, &l, &d.anchor_proof));
    if !(ours && anchored) {
        return Err(RedactionCheck::DisposalNotAnchored);
    }
    Ok(())
}

/// An absence or presence the auditor cannot account for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unaccounted {
    /// The payload is gone, with no genuine anchored order and `DISPOSE` for it.
    PayloadDeleted {
        /// The capsule.
        eid: Digest32,
    },
    /// A genuine order and `DISPOSE` say it was erased, but it is still there.
    RedactedPayloadPresent {
        /// The capsule.
        eid: Digest32,
    },
}

/// An order as the auditor receives it from the AIS, with the membership proof
/// for each capsule it claims to cover. The AIS may be compromised: nothing in
/// here is trusted until [`account`] checks it.
#[derive(Debug, Clone)]
pub struct ClaimedOrder {
    /// The order.
    pub order: Order,
    /// `(eid, membership proof)` per covered capsule.
    pub covers: Vec<(Digest32, InclusionProof)>,
}

/// What `0x05` accounting reads from a stored record: the capsule it belongs
/// to, and the order it executes.
///
/// ⭐ **A narrow type, so the keyless surface is visible in the signature.**
/// Since M13 A1 a `CustodyRecord`'s `event`, `ts`, `actor_c` and `params_c`
/// live inside `C_rec`, and accounting must stay keyless for the audit to be
/// delegable to a low-privilege service. Taking a whole `CustodyRecord` here
/// would hide that: a later change could reach for an encrypted field and the
/// signature would not object. These two fields are in clear, by the decision
/// in the design record, and they are all this function may touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisposalClaim {
    /// `eid_e` of the segment the `DISPOSE` sits in.
    pub eid_e: Digest32,
    /// The `oid` the `DISPOSE` references, if any. `None` is a
    /// retention-driven disposal, which answers to no order.
    pub order_ref: Option<Digest32>,
}

impl DisposalClaim {
    /// Read a claim off a stored record, with no key.
    #[must_use]
    pub const fn of(record: &CustodyRecord) -> Self {
        Self {
            eid_e: record.eid_e,
            order_ref: record.order_ref,
        }
    }
}

/// One anchored capsule as `0x05` accounting sees it: its `eid`, where its
/// payload should be, and the epoch `e` its seal was anchored in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredPayload {
    /// The capsule.
    pub eid: Digest32,
    /// Where its sealed payload lives.
    pub path: PathBuf,
    /// The epoch whose root holds its `0x01` seal leaf.
    pub epoch: u64,
}

/// The genuine orders per capsule: `eid` → the `oid`s of orders that satisfy
/// every conjunct of `eq:vred` except the `DISPOSE` (see [`account`]). Split out
/// so a court's acceptance (`crate::accept`) can require that every
/// `order_ref` a disclosed chain carries names one of them, which [`account`]
/// alone does not: it reports a payload still present only when a genuine order
/// covers it, so a `DISPOSE` citing a bogus order over a present payload passes.
#[must_use]
pub fn genuine_orders<H: BuildHasher>(
    anchored: &[AnchoredPayload],
    claimed: &[ClaimedOrder],
    anchored_leaves: &HashMap<Digest32, u64, H>,
    registry: &impl OrderRegistry,
    court_pk: &[u8],
) -> HashMap<Digest32, HashSet<Digest32>> {
    let epoch_of: HashMap<Digest32, u64> = anchored.iter().map(|a| (a.eid, a.epoch)).collect();
    let mut genuine: HashMap<Digest32, HashSet<Digest32>> = HashMap::new();
    for c in claimed {
        let o = &c.order;
        let Some(&leaf_epoch) = anchored_leaves.get(&o.leaf().digest) else {
            continue;
        };
        if o.verify(court_pk, o.ts).is_err() || matches_chain(o, registry).is_err() {
            continue;
        }
        for (eid, proof) in &c.covers {
            let after = epoch_of.get(eid).is_some_and(|&e| leaf_epoch >= e);
            if after && targets(&o.tgt, eid, proof) {
                genuine.entry(*eid).or_default().insert(o.oid);
            }
        }
    }
    genuine
}

/// Phase 10's `0x05` accounting over every anchored capsule — `eq:vred` in full
/// (M13 A7).
///
/// A capsule's absence is accounted for only when **all** hold:
/// * an order whose `σ_CO` verifies under `court_pk` (expiry is not re-checked:
///   an order valid when executed stays valid evidence afterwards);
/// * its `0x05` leaf is anchored, at an epoch `e′` (`anchored_leaves` maps each
///   leaf digest the auditor verified against an anchored root to that root's
///   epoch);
/// * ⭐ **`e′ ≥ e`**, the capsule's own anchoring epoch: an order anchored
///   before the capsule existed cannot have been about it;
/// * ⭐ **the leaf is exactly what the chain recorded for the order's id**
///   (`registry`), not merely an anchored leaf under a recorded id;
/// * its target covers the capsule, by membership proof;
/// * a `DISPOSE` record for the capsule references that order's `oid`.
///
/// Before A7 the two starred conjuncts were not checked (`audit/06` D6).
///
/// Keyless: it reads only public data and stats files.
#[must_use]
pub fn account<H: BuildHasher>(
    anchored: &[AnchoredPayload],
    claimed: &[ClaimedOrder],
    anchored_leaves: &HashMap<Digest32, u64, H>,
    registry: &impl OrderRegistry,
    disposals: &[(Digest32, DisposalClaim)],
    court_pk: &[u8],
) -> Vec<Unaccounted> {
    let genuine = genuine_orders(anchored, claimed, anchored_leaves, registry, court_pk);
    // ⭐ **Keyless, and this is what keeps the audit delegable.** Since M13 A1
    // the record's `event` lives inside `C_rec`, so `r.event == Dispose` is no
    // longer readable without a case key. It is also no longer needed: A1 holds
    // the invariant `order_ref.is_some()` ⟺ court-ordered `Dispose`, enforced
    // where records are built, so the `order_ref` filter alone selects exactly
    // the disposals that answer to an order. A retention-driven `Dispose`
    // carries `None` and is correctly absent — it answers to no order.
    //
    // Keeping this function keyless is the reason `order_ref` stays in clear
    // the `0x05` leaf already publishes the
    // `oid` on chain, so it reveals nothing the anchor does not.
    let disposed: HashSet<(Digest32, Digest32)> = disposals
        .iter()
        .filter_map(|(eid, d)| d.order_ref.map(|oid| (*eid, oid)))
        .collect();
    let accounted = |eid: &Digest32| {
        genuine
            .get(eid)
            .is_some_and(|oids| oids.iter().any(|oid| disposed.contains(&(*eid, *oid))))
    };

    let mut out = Vec::new();
    for a in anchored {
        let present = a.path.is_file();
        match (present, accounted(&a.eid)) {
            (false, false) => out.push(Unaccounted::PayloadDeleted { eid: a.eid }),
            (true, true) => out.push(Unaccounted::RedactedPayloadPresent { eid: a.eid }),
            _ => {}
        }
    }
    out
}

fn hex(d: &[u8]) -> String {
    use core::fmt::Write as _;
    d.iter()
        .fold(String::with_capacity(d.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
