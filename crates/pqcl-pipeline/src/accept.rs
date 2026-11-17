//! The court's acceptance predicate, `eq:accept`, composed (the design record
//! §1br F3).
//!
//! ```text
//! accept = Structure ∧ Open ∧ Chain(reg, d_e …) ∧ Approvals(A_e)
//!        ∧ ρ_c = H(0x16 ‖ ⟪ρ⟫)
//!        ∧ ∀ record j:  Open(actor_c_j, (id, role, r_a)_j)
//!                     ∧ Open(params_c_j, (params, r_p)_j)   or   D_j = descriptor
//!        ∧ ∀ receipt over D: an earlier release over D;  each D one pair
//!        ∧ ∀ record j:  (id, role, pk) ∈ ρ   ∧   role ∈ Role(evt_j)
//!                     ∧ Verify(pk, σ_actor_j)   ∧   Verify(pk_receiver, σ_witness_j)?
//!        ∧ Valid_Open(cm_ev, r_ev)?   ∧   Red?
//! ```
//!
//! # Why one entry point
//!
//! Every conjunct existed before this, and each was exercised on its own:
//! `Bundle::verify`, `Bundle::open`, `checkpoint::verify_chain`,
//! `ApprovalSet::verify`, `redaction::account`. Nothing ran them together, and
//! nothing in the library checked `σ_actor` or a role against a disclosed
//! record at all: the only signature checks on custody records were in
//! `handoff`, a benchmark and the demo. A court that called the parts itself
//! could skip one and not know it had. [`accept`] runs them in one order and
//! returns an [`AcceptReport`] naming every predicate that ran and every one it
//! skipped, with the reason.
//!
//! # What the court receives that it did not before
//!
//! * **The roster** `ρ = {(id, role, pk)}`, the enrolled actors. `reg` commits
//!   to it as `ρ_c` (tag `0x16`), so the court checks the roster it is handed
//!   against the registration, and the AIS, which holds only `reg`, never
//!   learns which actors a case enrolled.
//! * **The openings** of each disclosed record's `actor_c` and `params_c`
//!   (for a `TRANSFER`, the descriptor's fields). Without them `actor_c` is a
//!   hiding commitment nobody can open, and `σ_actor` names a key the court
//!   cannot place.
//!
//! Both travel together as a [`CourtPackage`], sealed to the court's ML-KEM key
//! by [`SealedPackage`], the construction the disclosure keys use. The openings
//! are the lab's to send: an appender returns them with every record (M13 A2),
//! inside the enclave or not.
//!
//! ⚠️ **`ρ_c` is binding, not hiding.** `ρ` is public keys and identifiers; an
//! observer holding a candidate roster can test it against `ρ_c`. The AIS has
//! no such candidate, since actor keys never reach it, but this is not a
//! hiding commitment and should not be described as one.

use std::collections::HashMap;
use std::path::Path;

use pqcl_capsule::codec::{CodecError, Reader, Writer};
use pqcl_capsule::{
    ActorOpening, ActorRef, Bundle, DisclosureError, Event, OpenedRecord, Params, ParamsOpening,
    Role,
};
use pqcl_primitives::aead::{RecordKey, SealedRecord};
use pqcl_primitives::kem;
use pqcl_primitives::sig;
use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

use crate::checkpoint::{ApprovalError, ApprovalSet, Registration, verify_chain};
use crate::handoff::Handoff;
use crate::redaction::{
    AnchoredPayload, ClaimedOrder, DisposalClaim, Unaccounted, account, genuine_orders,
};
use crate::{PlaintextOpening, record_signed_bytes};

// ------------------------------------------------------------------ roster

/// One enrolled actor: its name and its verification key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    /// `(role, id)`.
    pub actor: ActorRef,
    /// Its ML-DSA-65 verification key.
    pub pk: Vec<u8>,
}

/// `ρ`, the actors a case enrolled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roster {
    /// The entries, in enrolment order.
    pub entries: Vec<RosterEntry>,
}

impl Roster {
    /// `⟪ρ⟫`: a count, then `role ‖ ⟪id⟫ ‖ ⟪pk⟫` per entry.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.entries.len() as u64);
        for e in &self.entries {
            w.byte(e.actor.role.byte()).field(&e.actor.id).field(&e.pk);
        }
        w.finish()
    }

    /// Parse [`Self::encode`]'s output.
    ///
    /// # Errors
    ///
    /// [`CodecError`] on a short field, an unknown role or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes)?;
        let out = Self::read(&mut r)?;
        r.finish()?;
        Ok(out)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let n = usize::try_from(r.u64()?).map_err(|_| CodecError::LengthOverflow)?;
        let mut entries = Vec::with_capacity(n.min(256));
        for _ in 0..n {
            let role = read_role(r)?;
            let id = r.field()?.to_vec();
            entries.push(RosterEntry {
                actor: ActorRef { role, id },
                pk: r.field()?.to_vec(),
            });
        }
        Ok(Self { entries })
    }

    /// `ρ_c = H(0x16 ‖ ⟪ρ⟫)`, what `reg` commits to.
    #[must_use]
    pub fn digest(&self) -> Digest32 {
        hash_domain(Domain::Roster, &[&self.encode()])
    }

    /// The verification key of `who`, if enrolled.
    #[must_use]
    pub fn key(&self, who: &ActorRef) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|e| e.actor == *who)
            .map(|e| e.pk.as_slice())
    }

    /// Whether some `(role, id)` appears twice, which would make
    /// [`Self::key`] answer for one entry and hide the other.
    #[must_use]
    pub fn has_duplicates(&self) -> bool {
        let mut seen = std::collections::HashSet::new();
        self.entries.iter().any(|e| !seen.insert(&e.actor))
    }
}

fn read_role(r: &mut Reader<'_>) -> Result<Role, CodecError> {
    Role::from_byte(r.byte()?).ok_or(CodecError::InvalidField("role is not one of the four"))
}

fn digest(r: &mut Reader<'_>, what: &'static str) -> Result<Digest32, CodecError> {
    r.field()?
        .try_into()
        .map_err(|_| CodecError::InvalidField(what))
}

// ---------------------------------------------------------------- openings

/// What opens a record's `params_c`: the tool run's parameters, or, for either
/// half of a `TRANSFER`, the descriptor `D`'s fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActOpening {
    /// `(params, r_p)`, opening `params_c = H(0x23 ‖ ⟪…, r_p⟫)`.
    Params(ParamsOpening),
    /// The handoff whose descriptor is the record's `params_c`.
    Descriptor(Handoff),
}

/// The openings of one disclosed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordOpening {
    /// Opens `actor_c`.
    pub actor: ActorOpening,
    /// Opens `params_c`.
    pub act: ActOpening,
}

/// What the lab sends a court beside the [`Bundle`]: the roster and, in chain
/// order, one [`RecordOpening`] per disclosed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CourtPackage {
    /// `ρ`.
    pub roster: Roster,
    /// One per record of the bundle, in chain order.
    pub openings: Vec<RecordOpening>,
}

const ACT_PARAMS: u8 = 1;
const ACT_DESCRIPTOR: u8 = 2;

impl CourtPackage {
    /// Canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(&self.roster.encode())
            .u64(self.openings.len() as u64);
        for o in &self.openings {
            w.field(&o.actor.id)
                .byte(o.actor.role.byte())
                .field(&o.actor.r_a);
            match &o.act {
                ActOpening::Params(p) => {
                    w.byte(ACT_PARAMS)
                        .field(&p.params.tool)
                        .field(&p.params.ver)
                        .field(&p.params.args)
                        .field(&p.params.just)
                        .field(&p.r_p);
                }
                ActOpening::Descriptor(h) => {
                    w.byte(ACT_DESCRIPTOR)
                        .field(&h.eid_e)
                        .field(&h.from)
                        .field(&h.to)
                        .field(&h.cond)
                        .field(&h.r_cap);
                }
            }
        }
        w.finish()
    }

    /// Parse [`Self::encode`]'s output.
    ///
    /// # Errors
    ///
    /// [`CodecError`] on any malformed field or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes)?;
        let roster = Roster::decode(r.field()?)?;
        let n = usize::try_from(r.u64()?).map_err(|_| CodecError::LengthOverflow)?;
        let mut openings = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let actor = ActorOpening {
                id: r.field()?.to_vec(),
                role: read_role(&mut r)?,
                r_a: digest(&mut r, "r_a must be 32 bytes")?,
            };
            let act = match r.byte()? {
                ACT_PARAMS => ActOpening::Params(ParamsOpening {
                    params: Params {
                        tool: r.field()?.to_vec(),
                        ver: r.field()?.to_vec(),
                        args: r.field()?.to_vec(),
                        just: r.field()?.to_vec(),
                    },
                    r_p: digest(&mut r, "r_p must be 32 bytes")?,
                }),
                ACT_DESCRIPTOR => ActOpening::Descriptor(Handoff {
                    eid_e: digest(&mut r, "eid_e must be 32 bytes")?,
                    from: digest(&mut r, "from must be 32 bytes")?,
                    to: digest(&mut r, "to must be 32 bytes")?,
                    cond: digest(&mut r, "cond must be 32 bytes")?,
                    r_cap: digest(&mut r, "r_cap must be 32 bytes")?,
                }),
                _ => return Err(CodecError::InvalidField("unknown act opening")),
            };
            openings.push(RecordOpening { actor, act });
        }
        r.finish()?;
        Ok(Self { roster, openings })
    }
}

/// A [`CourtPackage`] sealed to the court: ML-KEM-768 to its encapsulation key,
/// AES-256-GCM under the shared secret, associated data
/// `⟪"pqcl/disclosure-openings", cid_c, eid⟫` (the disclosure keys' scheme, under
/// its own label so neither can be presented as the other).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPackage {
    /// The case.
    pub cid_c: Digest32,
    /// The capsule.
    pub eid: Digest32,
    /// ML-KEM-768 ciphertext.
    pub kem_ct: Vec<u8>,
    /// The package, sealed.
    pub sealed: SealedRecord,
}

/// Sealing or opening a [`SealedPackage`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageError(pub String);

impl core::fmt::Display for PackageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "court package: {}", self.0)
    }
}

impl core::error::Error for PackageError {}

impl SealedPackage {
    fn aad(cid_c: &Digest32, eid: &Digest32) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(b"pqcl/disclosure-openings").field(cid_c).field(eid);
        w.finish()
    }

    /// Seal `package` to `court_ek`, for the capsule `eid` of case `cid_c`.
    ///
    /// # Errors
    ///
    /// A malformed encapsulation key, or an AEAD failure.
    pub fn seal(
        package: &CourtPackage,
        cid_c: Digest32,
        eid: Digest32,
        court_ek: &[u8],
    ) -> Result<Self, PackageError> {
        let (kem_ct, ss) = kem::encapsulate(court_ek).map_err(|e| PackageError(e.to_string()))?;
        let sealed = RecordKey::new(*ss.as_bytes())
            .seal(&Self::aad(&cid_c, &eid), &package.encode())
            .map_err(|e| PackageError(e.to_string()))?;
        Ok(Self {
            cid_c,
            eid,
            kem_ct,
            sealed,
        })
    }

    /// The court opens it.
    ///
    /// # Errors
    ///
    /// A decapsulation, authentication or parse failure.
    pub fn open(&self, court: &kem::KeyPair) -> Result<CourtPackage, PackageError> {
        let ss = court
            .decapsulate(&self.kem_ct)
            .map_err(|e| PackageError(e.to_string()))?;
        let plain = RecordKey::new(*ss.as_bytes())
            .open(&Self::aad(&self.cid_c, &self.eid), &self.sealed)
            .map_err(|e| PackageError(e.to_string()))?;
        CourtPackage::decode(&plain).map_err(|e| PackageError(e.to_string()))
    }
}

// ------------------------------------------------------------------ accept

/// One epoch as the court sees it: `R_e`, `d_e` and `A_e` read from the chain,
/// `n_e` and the approval set from the audit package.
#[derive(Debug, Clone)]
pub struct AnchoredEpoch {
    /// `e`.
    pub e: u64,
    /// `R_e`.
    pub root: Digest32,
    /// `n_e`, the epoch's own leaf count.
    pub n_e: u64,
    /// `d_e`.
    pub d_e: Digest32,
    /// `A_e`.
    pub a_e: Digest32,
    /// `S_e` and `σ_SLH`.
    pub approvals: ApprovalSet,
}

/// What the redaction conjunct needs when the chain ends in a court-ordered
/// `DISPOSE`: the order as claimed, the anchored `0x05` leaves with their
/// epochs, the chain's recorded order digests, the court's key, and where the
/// payload would be.
#[derive(Debug, Clone, Copy)]
pub struct RedactionEvidence<'a> {
    /// Orders claimed to cover the capsule.
    pub claimed: &'a [ClaimedOrder],
    /// Anchored leaf digest → its epoch.
    pub anchored_leaves: &'a HashMap<Digest32, u64>,
    /// `oid` → the digest the chain recorded for it.
    pub registry: &'a HashMap<Digest32, Digest32>,
    /// The court authority's order key.
    pub court_pk: &'a [u8],
    /// Where the capsule's sealed payload lives.
    pub payload: &'a Path,
}

/// Everything [`accept`] reads.
#[derive(Debug, Clone, Copy)]
pub struct AcceptInputs<'a> {
    /// The disclosed bundle.
    pub bundle: &'a Bundle,
    /// The case registration.
    pub reg: &'a Registration,
    /// Every epoch from the first, in order.
    pub epochs: &'a [AnchoredEpoch],
    /// The roster and openings, already opened by the court.
    pub package: &'a CourtPackage,
    /// `(r_ev, artefact)`, when the court is to check the plaintext.
    pub plaintext: Option<(&'a PlaintextOpening, &'a [u8])>,
    /// Required when any disclosed record carries an `order_ref`.
    pub redaction: Option<RedactionEvidence<'a>>,
}

/// One conjunct of `eq:accept`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Predicate {
    /// The checkpoint chain back to `reg`.
    CheckpointChain,
    /// `M` approvals and the co-signature, per epoch.
    Approvals,
    /// `Bundle::verify`: Tier-1, Tier-2, seal leaf, pseudonyms.
    Structure,
    /// `Bundle::open`: bodies, positions, links, terminal state.
    Open,
    /// `ρ_c` and no duplicate entry.
    Roster,
    /// Every `actor_c` and `params_c` opens.
    Openings,
    /// Every receipt follows a release over the same `D`; no `D` serves two
    /// pairs.
    TransferPairs,
    /// Every signer's role may sign its event, and is enrolled.
    Roles,
    /// Every `σ_actor` verifies under its actor's key.
    ActorSignatures,
    /// Every `σ_witness` verifies under the receiving custodian's key.
    WitnessSignatures,
    /// `cm_ev` opens to the artefact.
    PlaintextOpening,
    /// `eq:vred` for the capsule.
    Redaction,
}

/// Which predicates ran, and which did not and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptReport {
    /// Ran and held, in order.
    pub ran: Vec<Predicate>,
    /// Did not run, with the reason.
    pub skipped: Vec<(Predicate, &'static str)>,
    /// Records checked.
    pub records: usize,
    /// `σ_witness` signatures checked.
    pub witnesses: usize,
}

/// The conjunct that failed, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    /// The checkpoints do not chain back to `reg`.
    CheckpointChain,
    /// An epoch's approvals fail.
    Approvals {
        /// The epoch.
        e: u64,
        /// Why.
        why: ApprovalError,
    },
    /// The bundle's structure fails.
    Structure(DisclosureError),
    /// The bundle does not open.
    Open(DisclosureError),
    /// The roster is not the one `reg` commits to.
    RosterMismatch,
    /// The roster names one `(role, id)` twice.
    RosterDuplicate,
    /// One opening per record is required.
    OpeningCount {
        /// Records disclosed.
        records: usize,
        /// Openings received.
        openings: usize,
    },
    /// Record `j`'s `actor_c` does not open.
    ActorOpening {
        /// Position.
        j: usize,
    },
    /// Record `j`'s `params_c` does not open, or the opening is of the wrong
    /// kind for its event.
    ActOpening {
        /// Position.
        j: usize,
    },
    /// Record `j` is a receipt, and no earlier record releases over its
    /// descriptor.
    ReceiptUnpaired {
        /// Position.
        j: usize,
    },
    /// Record `j` is a second release, or a second receipt, over one
    /// descriptor.
    DescriptorReused {
        /// Position.
        j: usize,
    },
    /// Record `j`'s signer is not in the roster.
    NotEnrolled {
        /// Position.
        j: usize,
    },
    /// Record `j`'s signer's role may not sign its event.
    WrongRole {
        /// Position.
        j: usize,
    },
    /// Record `j`'s `σ_actor` does not verify.
    ActorSignature {
        /// Position.
        j: usize,
    },
    /// Record `j` is witnessed, but no disclosed receipt names the witness.
    WitnessUnpaired {
        /// Position.
        j: usize,
    },
    /// Record `j`'s `σ_witness` does not verify.
    WitnessSignature {
        /// Position.
        j: usize,
    },
    /// `cm_ev` does not open to the artefact.
    PlaintextOpening,
    /// A record carries an `order_ref` and no redaction evidence was given.
    RedactionEvidenceMissing,
    /// Record `j`'s `order_ref` names no genuine order covering this capsule.
    OrderNotGenuine {
        /// Position.
        j: usize,
    },
    /// `eq:vred` fails for the capsule.
    Redaction(Vec<Unaccounted>),
}

impl core::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not accepted: {self:?}")
    }
}

impl core::error::Error for AcceptError {}

/// `eq:accept`, in full (§1br F3). Each conjunct runs in turn, and the first
/// that fails is returned.
///
/// ⚠️ **A release whose receipt is not disclosed is refused** if it carries a
/// `σ_witness`: the witness is the receiving custodian, named only by the
/// receipt's opening, so without the receipt the court cannot tell whose key
/// to check it under. A chain disclosed mid-transfer is therefore not
/// acceptable; disclose it after the receipt.
///
/// # Errors
///
/// The [`AcceptError`] naming the first conjunct that failed.
pub fn accept(inp: &AcceptInputs<'_>) -> Result<AcceptReport, AcceptError> {
    let mut report = AcceptReport {
        ran: Vec::new(),
        skipped: Vec::new(),
        records: 0,
        witnesses: 0,
    };

    // The anchor side: the checkpoints chain to `reg`, each approved.
    let chain: Vec<_> = inp
        .epochs
        .iter()
        .map(|a| (a.e, a.root, a.n_e, a.d_e))
        .collect();
    if !verify_chain(inp.reg, &chain) {
        return Err(AcceptError::CheckpointChain);
    }
    report.ran.push(Predicate::CheckpointChain);
    for a in inp.epochs {
        a.approvals
            .verify(inp.reg, &a.d_e, &a.a_e)
            .map_err(|why| AcceptError::Approvals { e: a.e, why })?;
    }
    report.ran.push(Predicate::Approvals);

    // The bundle against those roots, then opened.
    let roots: Vec<(u64, Digest32)> = inp.epochs.iter().map(|a| (a.e, a.root)).collect();
    inp.bundle.verify(&roots).map_err(AcceptError::Structure)?;
    report.ran.push(Predicate::Structure);
    let opened = inp.bundle.open().map_err(AcceptError::Open)?;
    report.ran.push(Predicate::Open);

    // The roster the court was handed is the one the case registered.
    let roster = &inp.package.roster;
    if roster.has_duplicates() {
        return Err(AcceptError::RosterDuplicate);
    }
    if roster.digest() != inp.reg.roster {
        return Err(AcceptError::RosterMismatch);
    }
    report.ran.push(Predicate::Roster);

    let records: Vec<_> = inp.bundle.records().collect();
    if inp.package.openings.len() != records.len() {
        return Err(AcceptError::OpeningCount {
            records: records.len(),
            openings: inp.package.openings.len(),
        });
    }
    report.records = records.len();

    per_record(&records, &opened, inp.package, &mut report)?;

    plaintext(inp, &mut report)?;
    redaction(inp, &records, &mut report)?;
    Ok(report)
}

/// Openings, roles, enrolment and both signatures, record by record.
fn per_record(
    records: &[&pqcl_capsule::CustodyRecord],
    opened: &[OpenedRecord],
    package: &CourtPackage,
    report: &mut AcceptReport,
) -> Result<(), AcceptError> {
    let roster = &package.roster;
    // Each record's signer, once its opening has checked out.
    let mut signers: Vec<ActorRef> = Vec::with_capacity(records.len());
    for (j, (o, op)) in opened.iter().zip(&package.openings).enumerate() {
        let body = &o.body;
        if op.actor.commit() != body.actor_c {
            return Err(AcceptError::ActorOpening { j });
        }
        let act_ok = match &op.act {
            ActOpening::Params(p) => body.event != Event::Transfer && p.commit() == body.params_c,
            ActOpening::Descriptor(h) => {
                body.event == Event::Transfer
                    && h.descriptor() == body.params_c
                    && (h.from == body.actor_c || h.to == body.actor_c)
            }
        };
        if !act_ok {
            return Err(AcceptError::ActOpening { j });
        }
        signers.push(ActorRef::new(op.actor.role, &op.actor.id));
    }
    report.ran.push(Predicate::Openings);

    transfer_pairs(opened, &package.openings)?;
    report.ran.push(Predicate::TransferPairs);

    for (j, (o, who)) in opened.iter().zip(&signers).enumerate() {
        if !o.body.event.signers().contains(&who.role) {
            return Err(AcceptError::WrongRole { j });
        }
        if roster.key(who).is_none() {
            return Err(AcceptError::NotEnrolled { j });
        }
    }
    report.ran.push(Predicate::Roles);

    for (j, ((r, o), who)) in records.iter().zip(opened).zip(&signers).enumerate() {
        let pk = roster.key(who).ok_or(AcceptError::NotEnrolled { j })?;
        sig::verify(&record_signed_bytes(r, &o.body), &o.sigs.actor, pk, &[])
            .map_err(|_| AcceptError::ActorSignature { j })?;
    }
    report.ran.push(Predicate::ActorSignatures);

    for (j, (r, o)) in records.iter().zip(opened).enumerate() {
        let Some(sig_w) = &o.sigs.witness else {
            continue;
        };
        // The witness is the receiving custodian: the later record over the
        // same descriptor whose `actor_c` is the descriptor's `to`.
        let receiver = package
            .openings
            .iter()
            .zip(opened)
            .zip(&signers)
            .skip(j + 1)
            .find_map(|((op, later), who)| match &op.act {
                ActOpening::Descriptor(h)
                    if later.body.params_c == o.body.params_c && h.to == later.body.actor_c =>
                {
                    Some(who)
                }
                _ => None,
            })
            .ok_or(AcceptError::WitnessUnpaired { j })?;
        let pk = roster
            .key(receiver)
            .ok_or(AcceptError::WitnessSignature { j })?;
        sig::verify(&record_signed_bytes(r, &o.body), sig_w, pk, &[])
            .map_err(|_| AcceptError::WitnessSignature { j })?;
        report.witnesses += 1;
    }
    report.ran.push(Predicate::WitnessSignatures);
    Ok(())
}

/// Every receipt has an earlier release over the same descriptor `D` whose
/// `actor_c` is `D`'s `from`, and no `D` serves more than one pair
///
///
/// `handoff::receive` already refuses a receipt without its release, but a
/// court's check must not rest on the append path: a custodian holding its
/// own key can build either record by hand. A trailing release is allowed
/// here; if it is witnessed, the witness check refuses it.
fn transfer_pairs(opened: &[OpenedRecord], openings: &[RecordOpening]) -> Result<(), AcceptError> {
    // Per descriptor: (released, received).
    let mut seen: HashMap<Digest32, (bool, bool)> = HashMap::new();
    for (j, (o, op)) in opened.iter().zip(openings).enumerate() {
        let ActOpening::Descriptor(h) = &op.act else {
            continue;
        };
        let pair = seen.entry(o.body.params_c).or_default();
        // The openings check has placed `actor_c` at `from` or `to`.
        if o.body.actor_c == h.from {
            if pair.0 {
                return Err(AcceptError::DescriptorReused { j });
            }
            pair.0 = true;
        } else {
            if !pair.0 {
                return Err(AcceptError::ReceiptUnpaired { j });
            }
            if pair.1 {
                return Err(AcceptError::DescriptorReused { j });
            }
            pair.1 = true;
        }
    }
    Ok(())
}

fn plaintext(inp: &AcceptInputs<'_>, report: &mut AcceptReport) -> Result<(), AcceptError> {
    match inp.plaintext {
        Some((opening, artefact)) => {
            if !opening.opens(&inp.bundle.capsule.cm_ev, artefact) {
                return Err(AcceptError::PlaintextOpening);
            }
            report.ran.push(Predicate::PlaintextOpening);
        }
        None => report.skipped.push((
            Predicate::PlaintextOpening,
            "no (r_ev, artefact) supplied: cm_ev not opened",
        )),
    }
    Ok(())
}

fn redaction(
    inp: &AcceptInputs<'_>,
    records: &[&pqcl_capsule::CustodyRecord],
    report: &mut AcceptReport,
) -> Result<(), AcceptError> {
    let ordered = records.iter().any(|r| r.order_ref.is_some());
    let Some(ev) = inp.redaction else {
        if ordered {
            return Err(AcceptError::RedactionEvidenceMissing);
        }
        report.skipped.push((
            Predicate::Redaction,
            "no court-ordered DISPOSE in the chain and no evidence supplied",
        ));
        return Ok(());
    };
    let eid = inp.bundle.capsule.eid;
    let anchored = [AnchoredPayload {
        eid,
        path: ev.payload.to_path_buf(),
        epoch: inp.bundle.seal.epoch,
    }];
    // Every order the chain cites is genuine for this capsule. `account`
    // alone would pass a bogus citation over a payload that is still there.
    let genuine = genuine_orders(
        &anchored,
        ev.claimed,
        ev.anchored_leaves,
        ev.registry,
        ev.court_pk,
    );
    for (j, r) in records.iter().enumerate() {
        if let Some(oid) = r.order_ref
            && !genuine.get(&eid).is_some_and(|g| g.contains(&oid))
        {
            return Err(AcceptError::OrderNotGenuine { j });
        }
    }
    let disposals: Vec<_> = records
        .iter()
        .map(|r| (eid, DisposalClaim::of(r)))
        .collect();
    let bad = account(
        &anchored,
        ev.claimed,
        ev.anchored_leaves,
        ev.registry,
        &disposals,
        ev.court_pk,
    );
    if !bad.is_empty() {
        return Err(AcceptError::Redaction(bad));
    }
    report.ran.push(Predicate::Redaction);
    Ok(())
}
