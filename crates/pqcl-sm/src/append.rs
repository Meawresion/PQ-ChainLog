//! The custody append, performed **inside** the Secure Module (M13 A18).
//!
//! # Why the whole append and not just the signature
//!
//! Before this, a custody record was built on the host. The host drew `r_a` and
//! `r_p`, derived `K_coc` and `K_S^COC` from a `K_case` it held in its own
//! address space, sealed the body, and signed with a key sitting beside it. The
//! module was consulted for two things only: the capsule's pseudonym and
//! `σ_DEFR`. So the boundary covered the *evidence* plane's signature and
//! nothing at all on the **custody** plane — the plane this work's title claims.
//!
//! One request now does the lot: the role check, fresh blinds, the body sealed
//! under `K_rec^{eid}`, the keyed `rid`, `σ_actor`, and the
//! [29](pqcl_pipeline::CUSTODY_KEYWORDS_PER_RECORD) `Π_core` update tokens under
//! `K_S^COC`. `K_case`, `K_coc`, `K_S^COC` and every actor's signing key stay
//! inside; the parent receives the record, the tokens, and the openings a court
//! will need.
//!
//! # ⚠️ What the boundary does and does not check
//!
//! The module is the authority on **keys and roles**, not on chain structure.
//! It signs the `ts`, the epoch and the predecessor the parent hands it, so a
//! parent that lies about any of those gets a correctly signed record that says
//! something false. That is not a gap this request can close: the module has no
//! clock, no view of the AIS, and no way to tell a real predecessor from a
//! plausible one.
//!
//! What it does close is the part that only a key holder can do. Without the
//! module the parent cannot sign as any actor, cannot seal or open a record
//! body, cannot produce an index token, and — once the keys are destroyed —
//! cannot continue the chain at all.
//!
//! There is **one** structural check, and it is here because it is a key
//! property rather than a bookkeeping one: `j` must exceed every position this
//! module has already signed for that capsule. See
//! [`SmError::PositionReused`](crate::SmError::PositionReused) — `j` fixes
//! `rid`, whose leading 12 bytes are the AEAD nonce (§1br F1).
//!
//! # ⛔ The index counters must not be lost
//!
//! `Π_core` seals each posting under a **one-time** key `F(K^M_w, c)` with a
//! zero nonce, so the key is one-time only while `(w, c)` never repeats. The
//! per-keyword counters live in this module's state; an enclave has no
//! persistent store, so a restart that forgets them would hand out `c = 0`
//! again and encrypt a second posting under a key that has already been used.
//!
//! ⚠️ **They therefore cannot be re-derived from anything the AIS holds** — it
//! stores addresses, not keywords, and cannot count per keyword. Durability has
//! to come from the same KMS-wrapped-blob mechanism that carries `K_mst`, or
//! the enclave must not be restarted mid-case. Recorded in
//! The design record, and it corrects that entry's first answer.

#[cfg(feature = "host-software")]
use std::collections::HashMap;

use pqcl_capsule::{ActorRef, Capsule, CustodyRecord, Event, Role};
use pqcl_dsse::core::{Op, UpdateToken};
use pqcl_pipeline::handoff::{self, Handoff, OpenChain, Receipt, Receiving, Release, Terms};
use pqcl_pipeline::{
    Agent, CUSTODY_KEYWORDS_PER_RECORD, CapsuleRef, CaseKeys, RecordParams, SignError, Signed,
    custody_keywords,
};
use pqcl_primitives::xof::Digest32;

use crate::custody::SmError;

/// ⭐ **The cast every harness and the enclave enrol, by `(role, id)`**
/// (`(role, id)` enrolment).
///
/// One table, because the two must agree: a harness appending through the
/// enclave names the actor it wants by `(role, id)`, and an enclave that had
/// enrolled other ids would refuse every request. Two custodians, so a
/// bilateral transfer is between two parties: the evidence store releases, and
/// the lab's custodian witnesses the release and signs the receipt.
pub const CAST: [(Role, &[u8]); 5] = [
    (Role::Defr, b"first-responder-1"),
    (Role::Custodian, b"evidence-store-1"),
    (Role::Custodian, b"lab-custodian-1"),
    (Role::Des, b"specialist-1"),
    (Role::Investigator, b"investigator-1"),
];

/// The custodian that releases in a harness transfer, and signs every other
/// custodian event.
#[must_use]
pub fn evidence_store() -> ActorRef {
    ActorRef::new(Role::Custodian, b"evidence-store-1")
}

/// The custodian that receives in a harness transfer: it witnesses the release
/// and signs the receipt.
#[must_use]
pub fn lab_custodian() -> ActorRef {
    ActorRef::new(Role::Custodian, b"lab-custodian-1")
}

/// The actor in [`CAST`] a harness signs `role` as, outside a transfer's
/// receiving half. Exhaustive, so a new role must be given a member here.
#[must_use]
pub fn cast_member(role: Role) -> ActorRef {
    match role {
        Role::Defr => ActorRef::new(role, b"first-responder-1"),
        Role::Custodian => evidence_store(),
        Role::Des => ActorRef::new(role, b"specialist-1"),
        Role::Investigator => ActorRef::new(role, b"investigator-1"),
    }
}

/// One custody append, as the parent asks for it.
///
/// ⭐ **The capsule crosses as a [`CapsuleRef`]**, which is its `eid` and
/// nothing else. Record building reads exactly that one field, and a sealed
/// capsule would put its 3309-byte `σ_DEFR` on the wire once per record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendRequest {
    /// `cid_c` — the case. `K_case` is derived from it inside the boundary, so
    /// the module needs no per-case setup and holds no case key at rest.
    pub cid_c: Digest32,
    /// Which capsule's chain this record joins.
    pub capsule: CapsuleRef,
    /// The actor to sign as, by `(role, id)`. Named rather than inferred,
    /// because two events admit two roles each (`ACCESS` the investigator or
    /// the DES, `TRANSFER` the custodian or the DEFR) and a role may have more
    /// than one enrolled actor.
    pub actor: ActorRef,
    /// The `Π_core` document identifier the 29 tokens post under.
    pub doc: u64,
    /// Position, time, epoch, note and act.
    pub params: RecordParams,
    /// Which of the three record-building steps this is.
    pub step: AppendStep,
}

/// Which record-building step a request asks for.
///
/// One variant per public method on [`pqcl_pipeline::Agent`], so there is no
/// shape of record the boundary can build that the host path cannot, and none
/// it cannot build that the host path can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendStep {
    /// Open the chain — `Agent::collect_record`. `j` is forced to 0 there.
    Collect,
    /// Append after `previous` — `Agent::append_record`.
    Append {
        /// The event.
        event: Event,
        /// The record this one follows. Boxed: a `CustodyRecord` carries a
        /// 3309-byte ML-DSA signature, and an unboxed variant would make every
        /// other one that large.
        previous: Box<CustodyRecord>,
    },
    /// Phase 11 Step 3 — `Agent::dispose_record`.
    Dispose {
        /// The record this one follows.
        previous: Box<CustodyRecord>,
        /// The court order being executed, or `None` for a retention-driven
        /// disposal, which no order covers (M13 A14).
        order_id: Option<Digest32>,
    },
    /// ⭐ **The releasing half of a bilateral transfer**, through
    /// `handoff::release` — the whole dance inside the boundary.
    ///
    /// The module commits the receiving actor, builds the descriptor `D` over
    /// it, signs the release, **and counter-signs it as the witness** before
    /// returning, because `σ_witness` sits in the release's Tier-1 leaf and the
    /// receipt's link covers that leaf (M13 A14). It then remembers the pending
    /// handoff, so the receipt needs nothing carried back through the parent —
    /// in particular not the receiver's `r_a`.
    Release {
        /// The capsule. Needed in full: `r_cap` binds the capsule's root and
        /// the receipt re-checks `d_ev`.
        capsule: Box<Capsule>,
        /// The chain so far. The module opens it with `K_rec^{eid}`, so the
        /// parent never needs the body key to make a transfer.
        chain: Vec<CustodyRecord>,
        /// `cond` — the transfer's conditions, which blind `D`.
        cond: Digest32,
        /// The actor that receives, and therefore witnesses.
        witness: ActorRef,
    },
    /// The receiving half, through `handoff::receive`.
    ///
    /// ⭐ **The descriptor and the receiving commitment come back in**, rather
    /// than being held inside the module between the two halves. The module is
    /// therefore **stateless across a transfer**, which matters because an
    /// enclave has no persistent store: a release written before a restart can
    /// still be received after it.
    ///
    /// That is safe because `handoff::receive` **verifies the release against
    /// the handoff it is given** — `params_c` must equal the descriptor and
    /// `actor_c` must equal `from`, both over a record the parent cannot forge.
    /// A parent that substitutes a handoff gets a refusal, not a mispaired
    /// transfer. And the receiver's opening reaches the parent one request later
    /// anyway, in the receipt's own `Signed`, because a court needs it.
    Receipt {
        /// The capsule, for the `d_ev` re-check.
        capsule: Box<Capsule>,
        /// The chain so far, ending in the release.
        chain: Vec<CustodyRecord>,
        /// `d_ev` as the receiver recomputed it over the stored ciphertext.
        /// ⚠️ **Supplied by the parent on purpose**: the artefact lives in
        /// object storage, which the enclave cannot reach, so re-hashing is the
        /// parent's act and the module checks the result against the anchor.
        recomputed: Digest32,
        /// What pairs this receipt with its release.
        ///
        /// Boxed because it is the one variant that would otherwise be four
        /// times the size of every other, and an enum is as large as its
        /// largest arm.
        pairing: Box<Pairing>,
    },
}

/// What comes back: the record, its tokens, and the openings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    /// The signed record with its body and openings, exactly as the host path
    /// produces it.
    pub signed: Signed,
    /// The 29 `Π_core` update tokens, in [`custody_keywords`] order.
    ///
    /// ⚠️ **Order is not a convenience.** The tokens are pseudorandom and the
    /// parent cannot tell which keyword produced which, so if it ever needs to
    /// know — it does not today — the only answer is the position.
    pub tokens: Vec<UpdateToken>,
    /// Present only for [`AppendStep::Release`]: what the matching receipt must
    /// be paired against.
    ///
    /// The caller carries it to the matching [`AppendStep::Receipt`]. See that
    /// variant on why holding it outside the boundary costs nothing.
    pub pairing: Option<Box<Pairing>>,
}

/// What pairs a receipt with its release: the descriptor the release was signed
/// over, and the commitment the module published as `to`.
///
/// ⭐ **Carried through the caller rather than kept inside the module**, which
/// is what makes a transfer survive an enclave restart. It is safe because
/// `handoff::receive` checks the release against this — `params_c` must equal
/// the descriptor and `actor_c` must equal `from`, both over a record the
/// caller cannot forge — so a substituted pairing yields a refusal, not a
/// mispaired transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    /// The descriptor `D`'s five inputs.
    pub handoff: Handoff,
    /// The receiving commitment and its opening.
    pub receiving: Receiving,
}

/// One capsule to seal, as an appender is asked for it.
///
/// ⭐ **Why sealing belongs to the appender too** (M13 A18). A harness that
/// appends records through the enclave but seals capsules with a DEFR key of its
/// own produces a case in which `σ_DEFR` and the opening `COLLECT`'s `σ_actor`
/// come from two different keys. Every signature verifies, and the chain
/// attributes acquisition to someone the capsule does not name. That is the
/// two-key defect the module's own cast was fixed for, reintroduced one level
/// up. So the first responder that seals a capsule is, by construction, the one
/// that opens its chain.
///
/// The owned twin of `pqcl_pipeline::IngestParams`, because this one crosses a
/// socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealRequest {
    /// `cid_c` — the case, from which the boundary derives `K_case`.
    pub cid_c: Digest32,
    /// `cm_ev`, the plaintext commitment, computed by whoever streamed the
    /// artefact.
    pub cm_ev: Digest32,
    /// The nonce the pseudonymous `eid` derives from.
    pub nonce: Digest32,
    /// Epoch of sealing.
    pub epoch: u64,
    /// Artefact type.
    pub artefact_type: Vec<u8>,
    /// `d_ev`, the ciphertext digest.
    pub d_ev: Digest32,
    /// Storage locator.
    pub ptr: Vec<u8>,
}

impl SealRequest {
    /// Seal with `actors`' first responder under `keys` — through
    /// `Agent::seal`, so there is one capsule builder however it is reached.
    ///
    /// # Errors
    ///
    /// [`SmError::NoSuchActor`] if no DEFR is enrolled, or [`SmError::Backend`]
    /// on a signing failure.
    pub fn seal(&self, actors: &dyn Actors, keys: &CaseKeys) -> Result<Capsule, SmError> {
        actors
            .first_responder()?
            .seal(
                keys,
                self.cm_ev,
                &pqcl_pipeline::IngestParams {
                    artefact_type: &self.artefact_type,
                    d_ev: self.d_ev,
                    ptr: &self.ptr,
                    epoch: self.epoch,
                    nonce: &self.nonce,
                },
            )
            .map_err(|e| SmError::Backend(e.to_string()))
    }
}

/// What a custody appender can do, whichever side of a boundary it is on.
///
/// Two implementations: [`HostAgentModule`](crate::host::HostAgentModule), which
/// holds the keys itself, and `pqcl_nitro::NitroAgentModule`, which forwards
/// over vsock. A harness takes this trait and therefore cannot tell which it
/// has — which is the point of A18's clause (d): the same harness produces
/// `backend: host-software` records locally and `backend: nitro` records on the
/// campaign instance, with no second code path to keep in step.
///
/// ⚠️ **Object-safe on purpose.** A harness holds one of these for a whole run
/// and the choice is made from a flag at startup, so it must be able to be a
/// `&dyn CustodyAppender`.
pub trait CustodyAppender {
    /// Which boundary this really is, carried into results metadata so a
    /// number can never be attributed to a stronger boundary than produced it.
    fn backend(&self) -> crate::custody::Backend;

    /// Build, seal, sign and index one custody record.
    ///
    /// # Errors
    ///
    /// Whatever the module refuses — see
    /// [`HostAgentModule::custody_append`](crate::host::HostAgentModule::custody_append).
    fn append(&self, req: &AppendRequest) -> Result<Appended, SmError>;

    /// Seal one capsule, signed `σ_DEFR` by the same first responder whose
    /// `COLLECT` will open its chain. See [`SealRequest`] on why.
    ///
    /// # Errors
    ///
    /// No DEFR enrolled, or a signing failure.
    fn seal(&self, req: &SealRequest) -> Result<Capsule, SmError>;

    /// An enrolled actor's verification key, which the audit package lists.
    ///
    /// # Errors
    ///
    /// A role that is not enrolled.
    fn verification_key(&self, who: &ActorRef) -> Result<Vec<u8>, SmError>;

    /// One capsule's disclosure keys, sealed to the court's encapsulation key
    /// (M13 A18) — the lab's half of a court disclosure, made where `K_case`
    /// is. See [`pqcl_capsule::SealedDisclosure`] for why sealed and what that
    /// does not stop.
    ///
    /// # Errors
    ///
    /// A case this module does not serve, a malformed court key, or a sealing
    /// failure.
    fn seal_disclosure(
        &self,
        cid_c: &Digest32,
        eid: &Digest32,
        court_ek: &[u8],
    ) -> Result<pqcl_capsule::SealedDisclosure, SmError>;
}

/// The enrolled actors an appender signs with, by `(role, id)`.
///
/// Implemented by the Secure Module, which holds its cast inside the boundary,
/// and by a harness's in-process cast, which holds it in the harness's own
/// memory. [`sign_step`] takes either, so both build records by the same code.
pub trait Actors {
    /// The actor enrolled as `who`.
    ///
    /// # Errors
    ///
    /// [`SmError::NoSuchActor`] if no actor is enrolled as `who`.
    fn actor(&self, who: &ActorRef) -> Result<&Agent, SmError>;

    /// The first responder who seals capsules: by construction the DEFR whose
    /// `COLLECT` opens each chain, so `σ_DEFR` and that `σ_actor` are one key.
    ///
    /// # Errors
    ///
    /// [`SmError::NoSuchActor`] if no DEFR is enrolled.
    fn first_responder(&self) -> Result<&Agent, SmError>;
}

/// The position a request will occupy in its capsule's chain.
///
/// A `Collect` is position 0 whatever the caller passed, because the record
/// builder forces it there; a position check must compare that, not the
/// caller's number.
#[must_use]
pub const fn position(req: &AppendRequest) -> u64 {
    match req.step {
        AppendStep::Collect => 0,
        _ => req.params.j,
    }
}

/// ⭐ **Build and sign the record a request asks for — the one record builder
/// behind every appender** (M13 A18).
///
/// The Secure Module calls it with its own cast and the case keys it derived
/// from `K_mst`; a harness's in-process appender calls it with its cast and the
/// keys it holds. There is no second implementation of any step, including the
/// two transfer halves, so local iteration exercises exactly what the enclave
/// runs. That is the Secure Module standing rule's condition 3 — "the host
/// software module **is** the enclave module minus the boundary, same source" —
/// applied one level up, to the harness.
///
/// What a caller adds around it is the caller's own business: the module adds
/// the position check and keeps the index; an in-process appender keeps an
/// index and checks nothing, because it is not a boundary.
///
/// # Errors
///
/// [`SmError::NoSuchActor`] or [`SmError::WrongRole`] for an actor the request
/// cannot sign in; [`SmError::Backend`] for a chain that does not open, a
/// handoff the protocol refuses, or a signing failure.
pub fn sign_step(
    actors: &dyn Actors,
    keys: &CaseKeys,
    req: &AppendRequest,
) -> Result<(Signed, Option<Box<Pairing>>), SmError> {
    let agent = actors.actor(&req.actor)?;
    let signed = match &req.step {
        AppendStep::Collect => agent.collect_record(keys, req.capsule, &req.params),
        AppendStep::Append { event, previous } => {
            agent.append_record(keys, req.capsule, *event, previous, &req.params)
        }
        AppendStep::Dispose { previous, order_id } => {
            agent.dispose_record(keys, req.capsule, previous, order_id.as_ref(), &req.params)
        }
        AppendStep::Release {
            capsule,
            chain,
            cond,
            witness,
        } => return release(actors, keys, req, capsule, chain, *cond, witness),
        AppendStep::Receipt {
            capsule,
            chain,
            recomputed,
            pairing,
        } => {
            return receipt(agent, keys, req, capsule, chain, *recomputed, pairing)
                .map(|signed| (signed, None));
        }
    }
    .map_err(sign_err)?;
    Ok((signed, None))
}

/// A signing failure in the module's own terms, keeping the role refusal
/// distinct because a test asserts that specific outcome.
fn sign_err(e: SignError) -> SmError {
    match e {
        SignError::WrongRole { event, role } => SmError::WrongRole {
            event: event.byte(),
            role: role.byte(),
        },
        other => SmError::Backend(other.to_string()),
    }
}

/// The releasing half: commit the receiver, build `D` over it, sign, and
/// counter-sign as the witness before the record leaves.
fn release(
    actors: &dyn Actors,
    keys: &CaseKeys,
    req: &AppendRequest,
    capsule: &Capsule,
    chain: &[CustodyRecord],
    cond: Digest32,
    witness: &ActorRef,
) -> Result<(Signed, Option<Box<Pairing>>), SmError> {
    // ⛔ **The release's position is the chain's length, and the request must
    // say so.** `handoff::release` signs at `j = chain.len()` and never reads
    // `req.params.j`, while a module's position check reads only
    // `req.params.j`. Left unchecked, the two could differ: a parent passing a
    // chain one record longer than the `j` it claims would have the release
    // signed at the higher position while the module recorded the lower one,
    // and a later append at the higher position would then pass the check and
    // reuse that AEAD nonce under the same key. Found at M13 A18 while routing
    // the harnesses through the appender, before any run used it.
    if req.params.j != chain.len() as u64 {
        return Err(SmError::Config(format!(
            "a release over a chain of {} records is at position {}, not {}",
            chain.len(),
            chain.len(),
            req.params.j
        )));
    }
    let sender = actors.actor(&req.actor)?;
    let receiver = actors.actor(witness)?;
    // The receiving custodian's commitment is drawn **before** the release is
    // signed, because `D` binds `to` (`eq:handoff`). Inside a module that means
    // the receiver's blind never existed outside the boundary while it mattered.
    let receiving = Receiving {
        actor: receiver.commit_actor().map_err(sign_err)?,
    };
    let opened = OpenChain::open(chain, &keys.record_body_key(&capsule.eid))
        .map_err(|e| SmError::Backend(format!("the chain does not open: {e}")))?;
    let (signed, handoff) = handoff::release(
        sender,
        keys,
        capsule,
        &opened,
        &Terms {
            to: receiving.to(),
            cond,
            ts: req.params.ts,
            epoch: req.params.epoch,
        },
        // The receiver witnesses the release **before it is sealed** (§1br F2):
        // `σ_witness` is inside `C_rec`, and the receipt's link covers the
        // Tier-1 leaf that ciphertext is in (M13 A14).
        Some(receiver),
    )
    .map_err(|e| SmError::Backend(e.to_string()))?;

    // Handed back rather than remembered, so an appender is stateless across a
    // transfer; `receive` verifies the release against whatever it is given.
    Ok((signed, Some(Box::new(Pairing { handoff, receiving }))))
}

/// The receiving half, paired against the handoff the release returned.
fn receipt(
    receiver: &Agent,
    keys: &CaseKeys,
    req: &AppendRequest,
    capsule: &Capsule,
    chain: &[CustodyRecord],
    recomputed: Digest32,
    pairing: &Pairing,
) -> Result<Signed, SmError> {
    let opened = OpenChain::open(chain, &keys.record_body_key(&capsule.eid))
        .map_err(|e| SmError::Backend(format!("the chain does not open: {e}")))?;
    let record = opened
        .records
        .last()
        .ok_or_else(|| SmError::Config("a receipt over an empty chain".to_owned()))?;
    let body = opened
        .bodies
        .last()
        .ok_or_else(|| SmError::Config("a receipt over an empty chain".to_owned()))?;

    handoff::receive(
        receiver,
        keys,
        capsule,
        &Release { record, body },
        &pairing.handoff,
        &Receipt {
            recomputed,
            j: req.params.j,
            ts: req.params.ts,
            epoch: req.params.epoch,
            receiving: pairing.receiving.clone(),
        },
    )
    .map_err(|e| SmError::Backend(e.to_string()))
}

/// The per-case, per-capsule state a module keeps for the append path.
///
/// Kept in one struct so the lock discipline is visible: the index and the
/// positions are taken separately and never held at once.
///
/// Only a key-holding module has any; `append-types` alone carries none.
#[cfg(feature = "host-software")]
#[derive(Default)]
pub(crate) struct AppendState {
    /// `cid_c` → that case's custody-plane `Π_core` client. Created on first
    /// use from `K_S^COC`, which is derived from `K_case`, which is derived
    /// from `K_mst` — so nothing here is supplied by the parent.
    pub(crate) index: HashMap<Digest32, pqcl_dsse::core::Client>,
    /// `(cid_c, eid)` → the highest `j` signed. See
    /// [`SmError::PositionReused`](crate::SmError::PositionReused).
    pub(crate) positions: HashMap<(Digest32, Digest32), u64>,
}

/// Produce the 29 custody-plane tokens for a freshly signed record.
///
/// ⭐ **Public so every appender indexes the same way.** The Secure Module calls
/// it under `K_S^COC` it derived itself; an in-process appender calls it with a
/// client over the same key. One function, so the index the server receives
/// cannot depend on which appender built the record — which is what
/// `the_twentynine_tokens_are_byte_identical_to_a_host_built_index` asserts.
///
/// The one subtlety is that a counter advances per token, which is why `client`
/// is `&mut`.
///
/// # Errors
///
/// [`SmError::TimestampOutOfWindow`] if the record cannot be indexed under a
/// keyword any query reaches, or [`SmError::Backend`] if a token cannot be
/// sealed.
pub fn tokens_for(
    client: &mut pqcl_dsse::core::Client,
    signed: &Signed,
    doc: u64,
) -> Result<Vec<UpdateToken>, SmError> {
    let keywords = custody_keywords(&signed.record.eid_e, &signed.body, &signed.actor)
        .ok_or(SmError::TimestampOutOfWindow { ts: signed.body.ts })?;
    debug_assert_eq!(keywords.len(), CUSTODY_KEYWORDS_PER_RECORD);

    keywords
        .iter()
        .map(|w| {
            client
                .update(Op::Add, w, doc)
                .map_err(|e| SmError::Backend(format!("Π_core update failed: {e}")))
        })
        .collect()
}
