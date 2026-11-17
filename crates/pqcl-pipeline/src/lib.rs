//! M8 — the end-to-end pipeline.
//!
//! Agent → AIS → investigator → auditor, over real forensic artefacts and real
//! tool runs. The build plan states the acceptance:
//!
//! > ingest real disk images / memory dumps / PCAPs; run real forensic tooling;
//! > query across both planes; produce a court-disclosure bundle; auditor
//! > verifies it from public data alone.
//!
//! This crate is the wiring. It constructs nothing cryptographic of its own:
//! capsules and records come from `pqcl-capsule`, the forest from
//! `pqcl-forest`, the indices from `pqcl-dsse`, the primitives from
//! `pqcl-primitives`. What is new here is the **order of operations** and the
//! places where the two planes meet.
//!
//! # The two planes, and why the join is on the client
//!
//! * **Evidence plane** — the artefact. Sealed into a [`Capsule`]: pseudonymous
//!   `eid`, ciphertext digest `d_ev`, plaintext commitment `cm_ev`, DSSE tokens.
//! * **Custody plane** — who did what to it. [`CustodyRecord`]s, hash-chained
//!   per capsule, separately keyed and separately indexed.
//!
//! ⛔ **The join between them is client-side, always** (design §6c′). A server
//! that can join the planes is a server that can correlate "which artefacts did
//! this investigator touch" — which is the question the two-plane split exists
//! to make unanswerable. [`Investigator::cross_plane`] therefore queries each
//! plane separately and intersects locally.
//!
//! # What is real here
//!
//! The artefacts are the corpora's own files, the tool runs are real
//! invocations in a pinned container, and `params_c` commits to the version the
//! binary actually reported. Ground rule #1 bans the alternative, and §8 is
//! explicit that custody records must be *derived from* work that happened
//! rather than generated.

pub mod accept;
pub mod agent_epoch;
pub mod audit;
pub mod checkpoint;
pub mod chunked;
pub mod forensics;
pub mod handoff;
pub mod redaction;
pub mod retrieval;

use std::collections::HashMap;
use std::path::Path;

use pqcl_capsule::disclosure::{DisclosureKeys, SealProof, Segment};
use pqcl_capsule::redaction::Order;
use pqcl_capsule::{
    Act, ActorOpening, ActorRef, Bundle, Capsule, CustodyRecord, Event, Params, ParamsOpening,
    Provenance, RecordBody, RecordSignatures, Role,
};
use pqcl_dsse::range::{Attribute, RangeTree};
use pqcl_forest::{CustodyTree, Leaf, Mmr};
use pqcl_primitives::aead::CustodyKey;
use pqcl_primitives::rng;
use pqcl_primitives::xof::{self, Digest32, Domain, Label, PrfKey, hash_domain, prf};
use pqcl_primitives::{Signer, SoftwareMlDsa};

pub use chunked::{ChunkedDigest, digest_file};

/// The opening of a capsule's plaintext commitment `cm_ev` (design §14.3).
///
/// Whoever holds it can show a court that a decrypted artefact, or one chunk of
/// it, is the one committed; whoever lacks it learns nothing from `cm_ev`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextOpening {
    /// The blinding `r_ev`.
    pub r_ev: Digest32,
    /// The blinded chunk leaves and root, for opening one region.
    pub chunks: ChunkedDigest,
}

impl PlaintextOpening {
    /// Whether `artefact` opens `cm_ev` under this `r_ev`.
    #[must_use]
    pub fn opens(&self, cm_ev: &Digest32, artefact: &[u8]) -> bool {
        chunked::commit_bytes(artefact, &self.r_ev).root() == cm_ev
    }
}
pub use forensics::{Forensics, ForensicsError, ToolRun};

/// The bytes `σ_DEFR` covers: the capsule with its signature field cleared.
///
/// ⭐ **Signing must exclude the signature, and verifying must reproduce that
/// exclusion exactly.** `Capsule::encode` includes `sig_defr` as a field, so
/// signing the encoding of a *populated* capsule would sign the signature — and
/// verifying would then need the signature to already be inside the message,
/// which is impossible. Defining the covered bytes in one place, used by both
/// sides, is what stops the two drifting.
#[must_use]
pub fn capsule_signed_bytes(capsule: &Capsule) -> Vec<u8> {
    let mut c = capsule.clone();
    c.sig_defr = Vec::new();
    c.encode()
}

/// The bytes `σ_actor` and `σ_witness` cover: the record's clear fields and
/// its body's **plaintext** ([`CustodyRecord::signed_message`]).
///
/// ⭐ **Sign, then encrypt**. Both
/// signatures are sealed inside `C_rec`, so verifying one needs the body key:
/// open the record, then verify against this message. Before F2 the
/// signatures sat in clear over the ciphertext, and anyone holding the
/// actors' public keys could trial-verify a stored record to name its signer.
#[must_use]
pub fn record_signed_bytes(record: &CustodyRecord, body: &RecordBody) -> Vec<u8> {
    record.signed_message(body)
}

/// Case-scoped key material. One case, one `K_case`; everything else derives.
#[derive(Debug)]
pub struct CaseKeys {
    /// `cid_c = H(0x14 ‖ ⟪case_id, r_case⟫)` (draft8 Phase 1 Step 3; the tag is §1ap's).
    pub cid_c: Digest32,
    /// `K_case`.
    pub k_case: PrfKey,
}

impl CaseKeys {
    /// Derive a case's keys from a master key and a case identifier.
    #[must_use]
    pub fn derive(k_mst: &PrfKey, case_id: &[u8], r_case: &Digest32) -> Self {
        let cid_c = hash_domain(Domain::CaseId, &[case_id, r_case]);
        let k_case = PrfKey::new(prf(k_mst, Label::Case, &[&cid_c]));
        Self { cid_c, k_case }
    }

    /// `K_S^EV = F(K_case, "idx" ‖ 0x00)` — the **evidence** plane's DSSE
    /// index master, draft6 eq. (`eq:kidx`).
    #[must_use]
    pub fn evidence_index_key(&self) -> PrfKey {
        PrfKey::new(xof::index_master(&self.k_case, xof::PLANE_EVIDENCE))
    }

    /// `K_S^COC = F(K_case, "idx" ‖ 0x01)` — the **custody** plane's DSSE
    /// index master, draft6 eq. (`eq:kidx`).
    ///
    /// ⚠️ **Before M13 A18 nothing in this crate derived it**, so each caller
    /// invented one: the demo hashed `b"custody"` under the `idx` label, and
    /// `exp6chain` used `H("K_S custody (exp6chain)")` — a key anyone reading
    /// the source can recompute, which left that harness's custody index
    /// readable by construction. The cost was identical either way, so no
    /// measurement moved and nothing failed.
    ///
    /// It has to live here because [`CaseKeys`] is where `K_case` is, and it
    /// has to be *one* derivation because
    /// [`pqcl_primitives::xof::index_master`] is also what a warrant delegates
    /// from — two spellings of `K_S^COC` are two keys.
    #[must_use]
    pub fn custody_index_key(&self) -> PrfKey {
        PrfKey::new(xof::index_master(&self.k_case, xof::PLANE_CUSTODY))
    }

    /// `K_coc = F(K_case, "note")` — the custody-plane AEAD root. Every
    /// record body key derives from it (M13 A1).
    #[must_use]
    pub fn coc_key(&self) -> PrfKey {
        PrfKey::new(prf(&self.k_case, Label::Note, &[]))
    }

    /// `K_rec^{eid} = F(K_coc, "rec" ‖ eid)` — the body key for one capsule.
    ///
    /// A court disclosure hands this over for the disclosed capsule alone.
    #[must_use]
    pub fn record_body_key(&self, eid: &Digest32) -> CustodyKey {
        CustodyRecord::body_key(&self.coc_key(), eid)
    }

    /// `K_rid^{eid} = F(K_coc, "rid" ‖ eid)` — the record-identifier key for
    /// one capsule (M13 A20; A1 had this under the case-wide `K_coc`).
    #[must_use]
    pub fn record_id_key(&self, eid: &Digest32) -> PrfKey {
        CustodyRecord::rid_key(&self.coc_key(), eid)
    }

    /// The three per-capsule keys a court disclosure carries, and nothing
    /// else — see [`pqcl_capsule::disclosure::DisclosureKeys`].
    #[must_use]
    pub fn disclosure_keys(&self, eid: &Digest32) -> DisclosureKeys {
        DisclosureKeys {
            k_eid: *self.capsule_link_key(eid).as_bytes(),
            k_rec: CustodyRecord::body_key_bytes(&self.coc_key(), eid),
            k_rid: *self.record_id_key(eid).as_bytes(),
        }
    }

    /// `K_link = F(K_case, "link")` — derives per-epoch capsule pseudonyms so
    /// the server cannot link one capsule's records across epochs.
    #[must_use]
    pub fn link_key(&self) -> PrfKey {
        PrfKey::new(prf(&self.k_case, Label::Link, &[]))
    }

    /// `k_eid = F(K_link, eid)` — one capsule's link key (M13 A20).
    ///
    /// ⭐ **The intermediate level is the point.** A disclosure hands the court
    /// `k_eid` for the disclosed capsule, which lets it derive every `eid_e`
    /// of *that* capsule — and so find the capsule's later segments — without
    /// being able to derive any other capsule's. The one-step
    /// `eid_e = F(K_link, eid ‖ e)` of A1 could not do that: a court that
    /// needed to find later segments needed `K_link`, which unlocks the whole
    /// case's pseudonyms. Row A20 acceptance (c) is exactly this.
    #[must_use]
    pub fn capsule_link_key(&self, eid: &Digest32) -> PrfKey {
        CustodyRecord::capsule_link_key(&self.link_key(), eid)
    }

    /// `eid_e = F(k_eid, e)`.
    #[must_use]
    pub fn epoch_pseudonym(&self, eid: &Digest32, epoch: u64) -> Digest32 {
        CustodyRecord::epoch_pseudonym(&self.capsule_link_key(eid), epoch)
    }
}

/// What one ingest needs, beyond the artefact itself.
///
/// A struct rather than six positional parameters: `epoch`, `nonce` and `ptr`
/// are all opaque byte-ish values, and a call site that passes them positionally
/// is one transposition away from sealing a capsule under the wrong pseudonym —
/// which would verify cleanly and be wrong.
#[derive(Debug, Clone, Copy)]
pub struct IngestParams<'a> {
    /// Artefact type, e.g. `b"disk-image"`.
    pub artefact_type: &'a [u8],
    /// `d_ev`, the ciphertext digest, supplied by whoever holds the sealed
    /// object.
    pub d_ev: Digest32,
    /// Storage locator.
    pub ptr: &'a [u8],
    /// Epoch of sealing.
    pub epoch: u64,
    /// Nonce the pseudonymous `eid` derives from.
    pub nonce: &'a Digest32,
}

/// What one custody record needs.
///
/// ⭐ **No commitments in** (M13 A2). It used to take `actor_c` and `params_c`
/// as finished digests, which meant every caller built them — and every
/// harness built them **without a blind**, over a domain of a few actors and
/// four roles, so they were openable by enumeration and equal whenever the
/// actor was. Now the caller says *who is acting* (through the [`Agent`]'s own
/// identity) and *what the act is*, and the signer draws `r_a` and `r_p`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordParams {
    /// Free-text note, sealed inside `C_rec` with the rest of the body. Empty
    /// when there is none.
    ///
    /// Before A1 the note was a ciphertext of its own beside the record; now
    /// it travels in the body, so a record carries one ciphertext and not two.
    pub note: Vec<u8>,
    /// This record's index in its capsule's chain, `j`, counting from 0.
    ///
    /// ⭐ **It is a position commitment, not bookkeeping.** `rid =
    /// F(K_coc, "rid" ‖ ⟪eid, j⟫)`, so a court holding `K_coc` recomputes
    /// every `rid` from the position it found the record at and rejects a
    /// chain whose records were renumbered. It is also the GCM nonce source,
    /// which is why it must be right — see `sign_record`.
    pub j: u64,
    /// What this record's `params_c` commits to.
    pub act: Act,
    /// Trusted timestamp.
    pub ts: u64,
    /// ⭐ **The epoch this record is appended in** — the *current* epoch, not
    /// the capsule's sealing epoch (M13 A20).
    ///
    /// It selects the record's `eid_e`, and therefore which **segment** the
    /// record joins. Until A20 the pipeline used `capsule.epoch` for every
    /// record of a capsule, so a capsule's whole chain carried one pseudonym
    /// for its entire life and the per-epoch pseudonym bought nothing
    /// (`audit/07` D1).
    pub epoch: u64,
}

impl RecordParams {
    /// A record at position `j` and time `ts`, with no note, no act and **in
    /// epoch 0**; `with_act`, `with_note` and `in_epoch` fill the rest.
    ///
    /// Epoch 0 rather than a further positional argument: `j` and `epoch` are
    /// both small `u64`s, and a transposed pair would seal the record into the
    /// wrong segment under a `rid` for the wrong position — which verifies
    /// cleanly and is wrong. A case that spans epochs says so with
    /// [`RecordParams::in_epoch`], and a stale epoch is caught loudly by
    /// [`Ais::append`], which refuses a record filed under a closed epoch's
    /// pseudonym.
    #[must_use]
    pub fn at(j: u64, ts: u64) -> Self {
        Self {
            note: Vec::new(),
            j,
            act: Act::default(),
            ts,
            epoch: 0,
        }
    }

    /// What the act was: tool, version, arguments, justification.
    #[must_use]
    pub fn with_act(mut self, act: Act) -> Self {
        self.act = act;
        self
    }

    /// The act, from its parts.
    #[must_use]
    pub fn with_params(self, params: Params) -> Self {
        self.with_act(Act::Params(params))
    }

    /// A free-text note, sealed inside `C_rec` with the rest of the body.
    #[must_use]
    pub fn with_note(mut self, note: Vec<u8>) -> Self {
        self.note = note;
        self
    }

    /// Move these parameters into epoch `epoch` (M13 A20).
    #[must_use]
    pub fn in_epoch(mut self, epoch: u64) -> Self {
        self.epoch = epoch;
        self
    }
}

/// The two things a record may carry beyond its parameters: a redaction
/// order's id, and an actor commitment the signer published earlier.
///
/// One struct rather than two trailing `Option`s, because adjacent options of
/// different types read the same at a call site and transpose silently.
struct Extras<'w> {
    order_ref: Option<Digest32>,
    published: Option<ActorOpening>,
    /// The custodian who counter-signs, before the body is sealed (§1br F2).
    witness: Option<&'w Agent>,
}

/// Who signs a record built under a published commitment: the actor whose
/// opening it is, and the custodian who witnesses it, if any (§1br F2).
pub(crate) struct Signing<'w> {
    /// The opening the signer published before the record existed.
    pub actor: ActorOpening,
    /// The witness, who signs before the body is sealed.
    pub witness: Option<&'w Agent>,
}

/// A signed record and the openings only the client keeps.
///
/// ⭐ **The openings are returned, not stored** (M13 A2). `actor_c` and
/// `params_c` are hiding commitments; whoever must later show a court *who*
/// acted and *what* they ran needs `r_a` and `r_p`, and that is the client, not
/// the server and not this library. Dropping a [`Signed`] on the floor loses
/// the ability to open that record — which is the correct failure, because the
/// alternative is a commitment nobody can open and a record nobody can explain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// The record, as the AIS receives it.
    pub record: CustodyRecord,
    /// Its body in plaintext, as the signer built it.
    ///
    /// Carried because the client needs it immediately — [`custody_keywords`]
    /// indexes the event and the timestamp — and decrypting what we just
    /// encrypted would be theatre.
    pub body: RecordBody,
    /// The opening of its `actor_c`.
    pub actor: ActorOpening,
    /// The opening of its `params_c`, absent for a transfer, whose `params_c`
    /// is the descriptor itself (see [`Act`]).
    pub params: Option<ParamsOpening>,
}

/// What building a custody record needs from its capsule: the `eid`, and
/// nothing else.
///
/// ⭐ **A 32-byte door into record building** (M13 A18). Every record method on
/// [`Agent`] reads exactly one field of the capsule it is handed, so the Secure
/// Module boundary can be crossed with a digest rather than with a sealed
/// capsule and its 3309-byte `σ_DEFR` — per record, on the ingest path whose
/// cost the paper reports.
///
/// `impl Into<CapsuleRef>` is what keeps `&Capsule` working at every existing
/// call site, and that is the point: there is still **one** record builder,
/// reached through a narrower door. A second builder taking an `eid` would be a
/// second thing to drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleRef {
    /// The capsule's pseudonymous identifier.
    pub eid: Digest32,
}

impl From<&Capsule> for CapsuleRef {
    fn from(capsule: &Capsule) -> Self {
        Self { eid: capsule.eid }
    }
}

impl From<Digest32> for CapsuleRef {
    fn from(eid: Digest32) -> Self {
        Self { eid }
    }
}

/// Why a record could not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// ⭐ The agent's role may not sign this event (draft8 §V-D, M13 A2).
    WrongRole {
        /// The event.
        event: Event,
        /// The role that tried.
        role: Role,
    },
    /// The OS entropy source failed, so `r_a` or `r_p` could not be drawn.
    /// ⛔ **Never fall back to a derived or constant blind here**: a
    /// predictable `r_a` makes `actor_c` openable by anyone.
    Entropy(String),
    /// Sealing the body failed.
    Seal(String),
    /// Signing failed.
    Sign(String),
    /// ⭐ The predecessor is the chain's terminal `DISPOSE` (M13 A15): a
    /// disposed capsule's history is closed, and nothing is appended to it.
    AfterTerminal,
    /// The predecessor's body did not open under this capsule's key, so this
    /// agent cannot tell what it is appending to — a record of another
    /// capsule, or a tampered one.
    PreviousUnreadable,
    /// ⭐ A published opening names another actor than the one signing
    /// (`(role, id)` enrolment, §1br.4). A receipt is signed under the
    /// receiver's published `to`; without this, another custodian's key could
    /// sign it and `actor_c` would name a party whose key never touched it.
    NotThisActor,
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongRole { event, role } => write!(
                f,
                "a {role:?} may not sign {event:?}: that event's signers are {:?}",
                event.signers()
            ),
            Self::Entropy(e) => write!(f, "no entropy for a fresh blind: {e}"),
            Self::Seal(e) => write!(f, "could not seal the record body: {e}"),
            Self::Sign(e) => write!(f, "could not sign the record: {e}"),
            Self::AfterTerminal => f.write_str("the chain ends in a DISPOSE; nothing follows it"),
            Self::PreviousUnreadable => {
                f.write_str("the predecessor did not open under this capsule's key")
            }
            Self::NotThisActor => {
                f.write_str("the published actor commitment names another actor than the signer")
            }
        }
    }
}

impl core::error::Error for SignError {}

/// Check every `rid` in a chain against the position the record was found at.
///
/// ⭐ **This is what makes `j` a commitment rather than bookkeeping.** `rid =
/// F(K_rid^{eid}, ⟪j⟫)`, so a key holder recomputes each one from its index and
/// rejects a chain whose records were renumbered, duplicated or reordered —
/// even though every signature and link still verifies, because those cover the
/// record, not its position in the list.
///
/// `first_j` is the position of `chain[0]` in the capsule's **whole** history,
/// which is 0 for a complete chain and the preceding segments' total for one
/// segment of it.
///
/// Keyed, so it runs at disclosure, not in the keyless sweep. That is the right
/// place: a wrong `j` matters when a court reads the chain.
#[must_use]
pub fn rids_match_positions(chain: &[CustodyRecord], k_rid: &PrfKey, first_j: u64) -> bool {
    chain
        .iter()
        .enumerate()
        .all(|(i, r)| r.rid == CustodyRecord::derive_rid(k_rid, first_j + i as u64))
}

/// How many keywords one custody record is indexed under: **29**.
///
/// Four categorical terms plus the timestamp's 25 range-tree ancestors
/// (`Attribute::Timestamp` has depth 24, so `depth + 1 = 25`). Asserted by a
/// test and emitted as a macro, because it is the per-record ingest cost of the
/// custody plane and the paper states it.
pub const CUSTODY_KEYWORDS_PER_RECORD: usize = 29;

/// The custody plane's granularity for the timestamp attribute.
const CUSTODY_TS: Attribute = Attribute::Timestamp;

/// The index set for one custody record: `{eid_e, evt, actor:⟪id, role⟫, role}
/// ∪ anc(ts)` (draft8 Phase 6 Step 4, M13 A2).
///
/// ⭐ **The actor keyword is the opening, not the commitment.** Indexing
/// `actor_c` would be indexing a value that changes every record — useless as a
/// search term — and would also hand the server a way to group an actor's
/// records, since two postings under one keyword are two records by one actor.
/// Keying on `⟪id, role⟫` keeps the *commitments* hiding while leaving the
/// *index* searchable, which is the whole point of the split: the keyword is
/// sealed under the custody plane's own DSSE key, so the server sees a token,
/// not a name.
///
/// ⚠️ **It therefore needs the opening**, which only the client has. Indexing
/// is a client-side act; this function cannot be called by the AIS, and that is
/// not an inconvenience but the design.
///
/// `None` if `ts` is past the attribute's window (hours from 1970, so ~3882).
/// An out-of-window timestamp would index under a keyword no query can reach,
/// so the caller is told rather than handed a set that answers the wrong
/// query — and silently dropping the record would remove it from every
/// time-ranged search, which is the worse of the two failures.
#[must_use]
pub fn custody_keywords(
    eid_e: &Digest32,
    body: &RecordBody,
    actor: &ActorOpening,
) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(CUSTODY_KEYWORDS_PER_RECORD);
    out.push([b"eid:".as_slice(), eid_e].concat());
    out.push(event_keyword(body.event));
    out.push(actor_keyword(&actor.id, actor.role));
    out.push(role_keyword(actor.role));
    out.extend(RangeTree::profile(CUSTODY_TS).index_keywords(CUSTODY_TS.of_unix(body.ts)?));
    Some(out)
}

/// The `evt` keyword for an event.
#[must_use]
pub fn event_keyword(event: Event) -> Vec<u8> {
    [b"evt:".as_slice(), &[event.byte()]].concat()
}

/// The `actor` keyword for an identity in a role: `actor:⟪id, role⟫`.
///
/// ⭐ **A searcher can build this; it cannot build `actor_c`.** That asymmetry
/// is the point of indexing the opening's *contents* rather than the
/// commitment: an investigator who knows who they are looking for forms the
/// keyword from the id and role, while the commitment stays blinded per record
/// and tells the server nothing.
///
/// Framed, so `⟪id, role⟫` is injective: an id ending in a digit beside a
/// one-byte role is exactly the adjacent-variable-length-fields case that is
/// not binding when concatenated raw.
#[must_use]
pub fn actor_keyword(id: &[u8], role: Role) -> Vec<u8> {
    [
        b"actor:".as_slice(),
        &(id.len() as u64).to_le_bytes(),
        id,
        &[role.byte()],
    ]
    .concat()
}

/// The `role` keyword on its own, for "everything a DES touched".
#[must_use]
pub fn role_keyword(role: Role) -> Vec<u8> {
    [b"role:".as_slice(), &[role.byte()]].concat()
}

/// The Edge Log Agent: seals an artefact and opens its custody chain.
///
/// ⭐ **An agent is an actor with a role** (M13 A2). It signs as a named
/// identity in a named role, it commits that role into every `actor_c` it
/// produces, and it refuses any event its role may not sign. Before this, any
/// holder of a key could sign any event, and the chain established presence
/// rather than responsibility — draft8's own words for why the table exists.
#[derive(Debug)]
pub struct Agent {
    signer: SoftwareMlDsa,
    actor_id: Vec<u8>,
    role: Role,
}

impl Agent {
    /// Bind an agent to a signing key, an identity and a role.
    #[must_use]
    pub fn new(signer: SoftwareMlDsa, actor_id: &[u8], role: Role) -> Self {
        Self {
            signer,
            actor_id: actor_id.to_vec(),
            role,
        }
    }

    /// The role this agent signs in.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// This agent's enrolled name, `(role, id)`.
    #[must_use]
    pub fn actor_ref(&self) -> ActorRef {
        ActorRef::new(self.role, &self.actor_id)
    }

    /// A fresh commitment to this agent's identity, with its opening.
    ///
    /// The receiving custodian of a bilateral transfer needs this **before** the
    /// release is signed, because the descriptor binds `to` (`eq:handoff`): it
    /// publishes the commitment, the sender binds it into `D`, and the receipt
    /// then uses that exact commitment — still fresh for that record.
    ///
    /// # Errors
    ///
    /// [`SignError::Entropy`] if the OS entropy source fails.
    pub fn commit_actor(&self) -> Result<ActorOpening, SignError> {
        Ok(ActorOpening {
            id: self.actor_id.clone(),
            role: self.role,
            r_a: rng::secret().map_err(|e| SignError::Entropy(e.to_string()))?,
        })
    }

    /// The agent's verification key, which an auditor needs.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.signer.public_key()
    }

    /// `sigma_DEFR` over an already-assembled sealed tuple.
    ///
    /// [`Agent::seal`] is this plus building the capsule, and is what ordinary
    /// callers want. This exists for the Secure Module, which answers
    /// `AgentModule::sign_defr` for a capsule the caller assembled — so the
    /// module needs no signing key of its own beside its cast, and the DEFR
    /// who signs a capsule is by construction the DEFR who opens its chain.
    ///
    /// ⚠️ **The message must be `capsule_signed_bytes`**, which clears
    /// `sig_defr` first. Signing an encoded capsule that already carries one
    /// would be signing the signature.
    ///
    /// # Errors
    ///
    /// A signing failure.
    pub fn sign_defr(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        self.signer
            .sign(message)
            .map_err(|e| SignError::Sign(e.to_string()))
    }

    /// Ingest one real artefact.
    ///
    /// `d_ev` and `cm_ev` are **chunked** Merkle roots (design §14), not flat
    /// digests, so corruption is localisable and a partially damaged image
    /// stays admissible for its intact regions. They are computed by streaming
    /// the file: the memory dump is ~1.8 GB expanded and will not fit in a
    /// buffer comfortably.
    ///
    /// ⚠️ **`d_ev` comes from the caller, `cm_ev` is computed here.** Design §2
    /// wants `d_ev` over *ciphertext* and `cm_ev` over *plaintext*; sealing the
    /// payload is a storage-layer concern this crate does not own, and computing
    /// both over the plaintext would silently make `d_ev` the wrong commitment.
    ///
    /// ⭐ **`cm_ev` is hiding.** A fresh `r_ev` enters every chunk leaf
    /// ([`chunked::commit_file`]), and the [`PlaintextOpening`] returned is the
    /// only way to open it: keep it with the sealed metadata, escrow it, or
    /// destroy it for redaction's FULL mode (design §12.4).
    ///
    /// # Errors
    ///
    /// Any I/O error reading `path`, a randomness failure, or a signing failure.
    pub fn ingest(
        &self,
        keys: &CaseKeys,
        path: &Path,
        p: &IngestParams<'_>,
    ) -> Result<(Capsule, PlaintextOpening), Box<dyn core::error::Error>> {
        let r_ev = pqcl_primitives::rng::secret()?;
        let chunks = chunked::commit_file(path, &r_ev)?;
        let capsule = self.seal(keys, *chunks.root(), p)?;
        Ok((capsule, PlaintextOpening { r_ev, chunks }))
    }

    /// Seal a capsule over an already-computed plaintext commitment `cm_ev`.
    ///
    /// [`Agent::ingest`] is this plus streaming the artefact to compute
    /// `cm_ev`. Split out (M10 H2) so the custody-plane experiments can open
    /// chains at scale without re-reading an artefact per capsule — the
    /// sealing and signing are identical either way.
    ///
    /// # Errors
    ///
    /// A signing failure.
    pub fn seal(
        &self,
        keys: &CaseKeys,
        cm_ev: Digest32,
        p: &IngestParams<'_>,
    ) -> Result<Capsule, Box<dyn core::error::Error>> {
        let eid = prf(&keys.k_case, Label::Eid, &[p.nonce]);

        let mut capsule = Capsule {
            eid,
            cid_c: keys.cid_c,
            epoch: p.epoch,
            artefact_type: p.artefact_type.to_vec(),
            d_ev: p.d_ev,
            cm_ev,
            ptr: p.ptr.to_vec(),
            // Our own agent acquired it, inside the module, so the attestation
            // boundary is zero-width. `Declared` with a measured `Δ_gap` is for
            // evidence someone else collected (design §2a).
            provenance: Provenance::Attested,
            gap_seconds: 0,
            sig_defr: Vec::new(),
        };

        // Sign the sealed tuple, then attach. Signing `encode()` of a capsule
        // whose `sig_defr` is already populated would be signing the signature.
        capsule.sig_defr = self.signer.sign(&capsule_signed_bytes(&capsule))?;

        Ok(capsule)
    }

    /// Open a capsule's custody chain with a `Collect` record.
    ///
    /// # Errors
    ///
    /// A signing failure.
    pub fn collect_record(
        &self,
        keys: &CaseKeys,
        capsule: impl Into<CapsuleRef>,
        p: &RecordParams,
    ) -> Result<Signed, SignError> {
        // ⭐ **`j` is forced to 0 here, whatever the caller passed.** The
        // opening record *is* position zero by definition, so letting a caller
        // say otherwise would only create a way to make `rid` disagree with
        // the position a court finds the record at.
        let p = RecordParams { j: 0, ..p.clone() };
        self.sign_record(keys, capsule.into(), Event::Collect, None, &p, None)
    }

    /// Append a record to an existing chain.
    ///
    /// # Errors
    ///
    /// A signing failure.
    pub fn append_record(
        &self,
        keys: &CaseKeys,
        capsule: impl Into<CapsuleRef>,
        event: Event,
        previous: &CustodyRecord,
        p: &RecordParams,
    ) -> Result<Signed, SignError> {
        self.sign_record(keys, capsule.into(), event, Some(previous), p, None)
    }

    /// Phase 11 Step 3: the `DISPOSE` record. With `Some(order_id)` it executes
    /// that court order and references it under `σ_actor`; with `None` it is a
    /// **retention-driven** disposal, which no order covers.
    ///
    /// Takes the id, not the order: a sweep's id is fixed before its target set
    /// is complete and the court signs.
    ///
    /// ⚠️ **The distinction is load-bearing and keyless** (M13 A1, §1ax.2).
    /// `order_ref.is_some()` is how an auditor tells a court-ordered disposal
    /// from a retention-driven one without a key, and `redaction::account`
    /// classifies on exactly that. A harness that gave every disposal an order
    /// id would make the keyless classifier look exact when it is not — which
    /// is why `None` exists rather than a placeholder digest.
    ///
    /// # Errors
    ///
    /// A signing failure.
    pub fn dispose_record(
        &self,
        keys: &CaseKeys,
        capsule: impl Into<CapsuleRef>,
        previous: &CustodyRecord,
        order_id: Option<&Digest32>,
        p: &RecordParams,
    ) -> Result<Signed, SignError> {
        self.sign_record(
            keys,
            capsule.into(),
            Event::Dispose,
            Some(previous),
            p,
            order_id.copied(),
        )
    }

    /// Build and sign a record.
    ///
    /// `previous` is the record this one follows, or `None` for the one that
    /// opens the capsule. Both things A20 needs come from it: the **true**
    /// chain link, and whether this record continues the predecessor's segment
    /// or starts a new one.
    /// [`Agent::append_record`] under an actor commitment this agent published
    /// **before** the record existed — the two halves of a bilateral transfer,
    /// whose descriptor binds `from` and `to` (`eq:handoff`).
    ///
    /// # Errors
    ///
    /// As [`Agent::append_record`].
    pub(crate) fn append_record_as(
        &self,
        keys: &CaseKeys,
        capsule: impl Into<CapsuleRef>,
        event: Event,
        previous: &CustodyRecord,
        p: &RecordParams,
        signing: Signing<'_>,
    ) -> Result<Signed, SignError> {
        self.sign_record_as(
            keys,
            capsule.into(),
            event,
            Some(previous),
            p,
            Extras {
                order_ref: None,
                published: Some(signing.actor),
                witness: signing.witness,
            },
        )
    }

    fn sign_record(
        &self,
        keys: &CaseKeys,
        capsule: CapsuleRef,
        event: Event,
        previous: Option<&CustodyRecord>,
        p: &RecordParams,
        order_ref: Option<Digest32>,
    ) -> Result<Signed, SignError> {
        self.sign_record_as(
            keys,
            capsule,
            event,
            previous,
            p,
            Extras {
                order_ref,
                published: None,
                witness: None,
            },
        )
    }

    fn sign_record_as(
        &self,
        keys: &CaseKeys,
        capsule: CapsuleRef,
        event: Event,
        previous: Option<&CustodyRecord>,
        p: &RecordParams,
        extras: Extras<'_>,
    ) -> Result<Signed, SignError> {
        let Extras {
            order_ref,
            published,
            witness,
        } = extras;
        // ⭐ **The role check, before anything else** (M13 A2). Every event has
        // exactly one accountable signer role, and it is checked against the
        // role this agent commits into `actor_c` — so the check and the
        // commitment cannot disagree.
        if !self.role.may(event) {
            return Err(SignError::WrongRole {
                event,
                role: self.role,
            });
        }

        // Fresh blinds, per record. See `ActorOpening`. The exception is a
        // commitment this agent published before the record existed, which is
        // still fresh *for this record* — it was drawn for this transfer.
        let actor = match published {
            Some(a) if a.id != self.actor_id || a.role != self.role => {
                return Err(SignError::NotThisActor);
            }
            Some(a) => a,
            None => self.commit_actor()?,
        };
        let params = match &p.act {
            Act::Params(params) => Some(ParamsOpening {
                params: params.clone(),
                r_p: rng::secret().map_err(|e| SignError::Entropy(e.to_string()))?,
            }),
            Act::Descriptor(_) => None,
        };
        let params_c = match (&p.act, &params) {
            (Act::Descriptor(d), _) => *d,
            (Act::Params(_), Some(o)) => o.commit(),
            (Act::Params(_), None) => unreachable!("an Act::Params always has an opening"),
        };
        let actor_c = actor.commit();

        let eid_e = keys.epoch_pseudonym(&capsule.eid, p.epoch);
        let k_coc = keys.coc_key();

        // ⭐ **A closed chain stays closed** (M13 A15). The predecessor's event
        // is inside its body, so the check opens it under the capsule's key —
        // which every appender holds — and refuses to extend a `DISPOSE`. One
        // AEAD open per append; the host, the harnesses and the enclave all
        // build through here.
        if let Some(prev) = previous {
            let opened = prev
                .open_body(&CustodyRecord::body_key(&k_coc, &capsule.eid))
                .map_err(|_| SignError::PreviousUnreadable)?;
            if opened.event == Event::Dispose {
                return Err(SignError::AfterTerminal);
            }
        }

        // The real link: the predecessor's, or the capsule's own base case.
        let link = previous.map_or_else(
            || CustodyRecord::genesis_link(&capsule.eid),
            CustodyRecord::chain_link,
        );

        // ⭐ **A20, in three lines.** A record continues its predecessor's
        // segment only if it lands under the same pseudonym, which means the
        // same epoch. Otherwise it opens a new segment, and its cleartext
        // `h_prev` becomes a link to its own `eid_e` — a value the AIS can
        // already compute and can therefore learn nothing from. The real link
        // goes into the body, under `K_rec^{eid}`.
        //
        // The comparison is on `eid_e` rather than on an epoch number because
        // the pseudonym is what the AIS files by: if two records share it they
        // are in one segment *by definition*, and no separate bookkeeping can
        // disagree with that.
        let same_segment = previous.map(|r| r.eid_e) == Some(eid_e);
        let h_prev = if same_segment {
            link
        } else {
            CustodyRecord::segment_genesis_link(&eid_e)
        };

        // `rid = F(K_rid^{eid}, ⟪j⟫)` (M13 A1, per-capsule key since A20).
        // Keyed, so the AIS cannot recompute it and cannot confirm a guess at
        // this record's position or event. v1 hashed `(eid, event, h_prev, ts)`
        // in the clear, which allowed exactly that.
        let rid = CustodyRecord::derive_rid(&CustodyRecord::rid_key(&k_coc, &capsule.eid), p.j);

        // The AEAD nonce is `rid`'s leading 12 bytes (`CustodyRecord::body_nonce`,
        // §1br F1). It was `⟪j⟫` until design review: under A20 that
        // is not harmless, because `j` counts across the whole chain and in
        // clear it joins a segment starting at `n` to the one ending at
        // `n − 1`. `rid` is distinct per `j` and already public.
        let body = RecordBody {
            event,
            ts: p.ts,
            actor_c,
            params_c,
            link,
            note: p.note.clone(),
        };

        let mut record = CustodyRecord {
            rid,
            eid_e,
            h_prev,
            body: Vec::new(),
            order_ref,
        };

        // ⭐ **Sign, then encrypt** (§1br F2). Both signatures cover the clear
        // fields and the body's plaintext, and are sealed with it, so the record
        // is sealed exactly once: the witness signs here, before the seal, and
        // never re-seals a finished record under the same nonce.
        let message = record_signed_bytes(&record, &body);
        let sign = |a: &Agent| {
            a.signer
                .sign(&message)
                .map_err(|e| SignError::Sign(e.to_string()))
        };
        let sigs = RecordSignatures {
            actor: sign(self)?,
            witness: witness.map(sign).transpose()?,
        };
        record.body = CustodyRecord::seal_body(
            &CustodyRecord::body_key(&k_coc, &capsule.eid),
            &rid,
            &body,
            &sigs,
        )
        .map_err(|e| SignError::Seal(e.to_string()))?;
        Ok(Signed {
            record,
            body,
            actor,
            params,
        })
    }
}

/// The Aggregation & Index Server: honest-but-curious storage and anchoring.
///
/// # What it holds, and what it therefore knows (M13 A20)
///
/// ⭐ **Custody records are filed under `eid_e`, not under a capsule.** A
/// capsule's records in one epoch form a **segment**; the next epoch's records
/// arrive under a pseudonym this server cannot connect to the previous one,
/// because `eid_e = F(k_eid, e)` and it holds no key. So it knows:
///
/// * the set of capsules, with their cleartext `eid` — they are sealed objects
///   it stores and must be able to serve;
/// * a set of segments, each with its own pseudonym, record count and arrival
///   epoch;
/// * **not** which segments belong to one capsule, and not which capsule any
///   segment belongs to.
///
/// The consequence to keep in mind when reading the rest of this type: a
/// capsule's full history cannot be assembled here. [`Ais::disclose`] takes a
/// key for that reason, and it is the lab calling it, not the server.
#[derive(Debug, Default)]
pub struct Ais {
    capsules: Vec<Capsule>,
    /// Where each capsule's `0x01` seal leaf landed, parallel to `capsules`
    /// (M13 A3). A disclosure proves it, so the server must remember it; it
    /// used to append the leaf and forget where.
    seals: Vec<LeafRef>,
    /// Segments in arrival order, each filed under its `eid_e`.
    segments: Vec<StoredSegment>,
    /// `eid_e` → index into `segments`, so an append is O(1) rather than a
    /// scan of every segment the server has ever seen.
    by_pseudonym: HashMap<Digest32, usize>,
    /// Indices into `segments` of the open epoch's segments, in arrival order.
    /// ⭐ Kept rather than found: `segments` holds every epoch's and only
    /// grows, and an ingest loop asks [`Ais::open_segments`] once per record to
    /// size its epoch. A scan there made ingest O(records × segments): campaign
    /// 08's exp6chain ran over 3 h at 10⁶ leaves per epoch against under 30 min
    /// for both runs at 10⁵.
    open: Vec<usize>,
    /// The open epoch.
    epoch: u64,
    /// The open epoch's MMR. ⭐ **One MMR per epoch** (A20/A21), not one per
    /// case: a segment's `0x02` leaf is anchored in the epoch it belongs to,
    /// and a court checks it against that epoch's root alone.
    mmr: Mmr,
    /// Closed epochs, oldest first. Their MMRs are kept because a disclosure
    /// made later still needs their inclusion proofs.
    closed: Vec<ClosedEpoch>,
}

/// One segment as the server stores it.
#[derive(Debug, Clone)]
struct StoredSegment {
    eid_e: Digest32,
    /// The epoch that was open when this segment's first record arrived.
    epoch: u64,
    records: Vec<CustodyRecord>,
    /// Where this segment's `0x02` leaf landed in its own epoch's MMR. `None`
    /// until the epoch closes.
    leaf_index: Option<u64>,
}

/// Where a leaf sits: its epoch, and its index in that epoch's MMR.
///
/// One value rather than two `u64`s, because the two are useless apart and
/// transposing them is silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafRef {
    /// The epoch whose MMR holds the leaf.
    pub epoch: u64,
    /// Its index in that MMR.
    pub index: u64,
}

/// `R_e` for an epoch's MMR — what the AIS anchors and what a custodian
/// recomputes before approving (M13 A5).
///
/// `Mmr::root` is `None` only for an empty forest: an epoch closed with no
/// capsules and no records, which is a caller error rather than a state the
/// AIS reaches after `accept`, but a defined "empty epoch" root beats panicking
/// inside a measurement run. ⭐ **Defined once, here**, because the AIS and
/// every custodian must agree on it byte for byte, and a second spelling of a
/// sentinel is a custodian refusing an epoch the AIS legitimately closed.
#[must_use]
pub fn epoch_root(mmr: &Mmr) -> Digest32 {
    mmr.root()
        .unwrap_or_else(|| hash_domain(Domain::CustodyRoot, &[b"empty epoch"]))
}

/// An epoch the server has closed: its MMR, kept for later proofs, and the
/// root that was anchored.
#[derive(Debug)]
pub struct ClosedEpoch {
    /// The epoch number.
    pub epoch: u64,
    /// `R_e`, the anchored root.
    pub root: Digest32,
    /// `n_e` — **this epoch's own** leaf count, not a running total (A21).
    pub count: u64,
    mmr: Mmr,
}

impl ClosedEpoch {
    /// The epoch's Tier-2 leaf digests, in MMR order: what the custodians are
    /// handed to recompute `R_e` and `n_e` from before they approve (M13 A5).
    #[must_use]
    pub fn leaf_digests(&self) -> &[Digest32] {
        self.mmr.leaf_digests()
    }
}

impl Ais {
    /// An empty server.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The epoch currently open.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Accept a sealed capsule and its opening record.
    pub fn accept(&mut self, capsule: Capsule, first: CustodyRecord) {
        self.seals.push(LeafRef {
            epoch: self.epoch,
            index: self.mmr.leaf_count(),
        });
        self.mmr.append(&capsule.seal_leaf());
        self.capsules.push(capsule);
        self.append(first);
    }

    /// File a custody record under its own pseudonym.
    ///
    /// ⚠️ **No capsule index, since A20.** The server cannot tell which capsule
    /// a record belongs to, so it cannot be asked for one: it files the record
    /// under `record.eid_e`, opening a segment if that pseudonym is new. A
    /// record whose pseudonym names an *unknown* capsule is therefore
    /// indistinguishable from one whose capsule it has never seen — correctly,
    /// because those are the same thing from here.
    ///
    /// # Panics
    ///
    /// If `record.eid_e` names a segment whose epoch is already closed. That
    /// is a caller bug — almost always a record built with a stale
    /// [`RecordParams::epoch`] — and filing it would put a record outside the
    /// `0x02` leaf that claims to cover its segment, which verifies cleanly
    /// against the wrong count and is worse than a crash.
    pub fn append(&mut self, record: CustodyRecord) {
        let epoch = self.epoch;
        if let Some(&i) = self.by_pseudonym.get(&record.eid_e) {
            assert!(
                self.segments[i].epoch == epoch,
                "a record arrived for epoch {}'s segment while epoch {epoch} is open: \
                 its RecordParams::epoch is stale",
                self.segments[i].epoch
            );
            self.segments[i].records.push(record);
        } else {
            self.by_pseudonym.insert(record.eid_e, self.segments.len());
            self.open.push(self.segments.len());
            self.segments.push(StoredSegment {
                eid_e: record.eid_e,
                epoch,
                records: vec![record],
                leaf_index: None,
            });
        }
    }

    /// Close the epoch: commit every segment of it as a Tier-2 `0x02` leaf,
    /// return the root to anchor on chain, and open the next epoch.
    ///
    /// ⭐ **A `0x02` leaf covers one segment, not a chain prefix.** Before A20
    /// a capsule touched in three epochs was anchored three times over
    /// lengthening prefixes of one chain under one pseudonym, which made the
    /// per-epoch pseudonym decorative: the three leaves shared it. Now each
    /// leaf is `⟪eid_e, R_seg, n_seg⟫` over that epoch's records alone, under
    /// that epoch's pseudonym.
    pub fn close_epoch(&mut self) -> Digest32 {
        let epoch = self.epoch;
        // Arrival order, as the scan over `segments` it replaces visited them.
        for i in core::mem::take(&mut self.open) {
            debug_assert_eq!(self.segments[i].epoch, epoch);
            let seg = &self.segments[i];
            let root = tier1_root(&seg.records);
            let leaf = Leaf::new(
                Domain::CustodyRoot,
                &[&seg.eid_e, &root, &(seg.records.len() as u64).to_le_bytes()],
            );
            let at = self.mmr.leaf_count();
            self.segments[i].leaf_index = Some(at);
            self.mmr.append(&leaf);
        }

        let root = epoch_root(&self.mmr);

        let mmr = core::mem::take(&mut self.mmr);
        self.closed.push(ClosedEpoch {
            epoch,
            root,
            count: mmr.leaf_count(),
            mmr,
        });
        self.epoch += 1;
        root
    }

    /// Phase 11 Step 4: anchor a recorded order's `0x05` leaf in the open
    /// epoch, beside the `0x02` leaves [`Ais::close_epoch`] appends.
    pub fn record_order(&mut self, order: &Order) -> LeafRef {
        let at = LeafRef {
            epoch: self.epoch,
            index: self.mmr.leaf_count(),
        };
        self.mmr.append(&order.leaf());
        at
    }

    /// Design §8a.2: anchor one agent-epoch's control capsule as its `0x07`
    /// leaf in the open epoch (M13 A17).
    ///
    /// ⭐ **Why it is anchored at all.** `σ_agent` stops the AIS forging a
    /// control capsule, and the heartbeat (A6) stops it hiding one an agent
    /// closed. Neither stops it *accepting* a capsule and keeping it out of the
    /// anchor, which leaves it free to drop the capsule later with nothing on
    /// chain to contradict it. Anchored, the capsule is in `R_e`, and
    /// [`crate::audit::audit_agent_epochs_anchored`] refuses one that is not.
    /// The cost is one hash and one MMR append per agent-epoch, and nothing on
    /// chain.
    pub fn record_agent_epoch(&mut self, capsule: &agent_epoch::ControlCapsule) -> LeafRef {
        let at = LeafRef {
            epoch: self.epoch,
            index: self.mmr.leaf_count(),
        };
        self.mmr.append(&capsule.leaf());
        at
    }

    /// A Tier-2 inclusion proof for a leaf this server appended, in whichever
    /// epoch holds it.
    ///
    /// ⚠️ **The epoch travels with the index, and it has to** (M13 A20). Each
    /// epoch has its own MMR and closing one starts the next, so an index alone
    /// stops meaning anything the moment the epoch closes — which is exactly
    /// when a caller wants the proof. An index-only accessor returned `None`
    /// there, silently, and cost one harness a debugging round.
    #[must_use]
    pub fn prove(&self, leaf: &LeafRef) -> Option<pqcl_forest::MmrProof> {
        if leaf.epoch == self.epoch {
            return self.mmr.prove(leaf.index);
        }
        self.closed
            .iter()
            .find(|c| c.epoch == leaf.epoch)
            .and_then(|c| c.mmr.prove(leaf.index))
    }

    /// How many leaves the open epoch's MMR holds.
    ///
    /// ⚠️ **Per epoch, not cumulative** (A21). The anchoring contract no longer
    /// receives or enforces a running `leafCount`; a cleartext cumulative count
    /// on chain is what made case size public (`audit/07` D2).
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.mmr.leaf_count()
    }

    /// How many segments the open epoch holds — the number of `0x02` leaves
    /// [`Ais::close_epoch`] is about to append.
    ///
    /// An ingest worker sizing an epoch needs this and not [`Ais::len`]: a
    /// capsule the server holds but which saw no activity this epoch
    /// contributes no leaf (M13 A20).
    #[must_use]
    pub const fn open_segments(&self) -> usize {
        self.open.len()
    }

    /// Every epoch this server has closed, oldest first.
    #[must_use]
    pub fn closed_epochs(&self) -> &[ClosedEpoch] {
        &self.closed
    }

    /// `(epoch, root)` for every closed epoch — the public chain data a court
    /// checks a bundle against.
    #[must_use]
    pub fn epoch_roots(&self) -> Vec<(u64, Digest32)> {
        self.closed.iter().map(|c| (c.epoch, c.root)).collect()
    }

    /// Capsules held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capsules.len()
    }

    /// Whether the server holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capsules.is_empty()
    }

    /// The capsule at `index`.
    #[must_use]
    pub fn capsule(&self, index: usize) -> Option<&Capsule> {
        self.capsules.get(index)
    }

    /// The records filed under one pseudonym — the **only** custody lookup the
    /// server can perform unaided.
    #[must_use]
    pub fn segment(&self, eid_e: &Digest32) -> Option<&[CustodyRecord]> {
        self.by_pseudonym
            .get(eid_e)
            .map(|&i| self.segments[i].records.as_slice())
    }

    /// Every segment, as `(eid_e, epoch, records)` — what an AIS-view test gets
    /// to work with, and what a curious server has.
    pub fn stored_segments(&self) -> impl Iterator<Item = (&Digest32, u64, &[CustodyRecord])> {
        self.segments
            .iter()
            .map(|s| (&s.eid_e, s.epoch, s.records.as_slice()))
    }

    /// Every capsule, for the same purpose.
    #[must_use]
    pub fn stored_capsules(&self) -> &[Capsule] {
        &self.capsules
    }

    /// Build the court-disclosure bundle for one capsule.
    ///
    /// ⭐ **Tier 1 exists for exactly this.** A flat MMR could not hand a court
    /// one capsule's complete history without also revealing how many other
    /// capsules the case holds and how active each was. The bundle carries that
    /// capsule's segments and a Tier-2 proof per segment — and nothing about
    /// any other capsule.
    ///
    /// ⚠️ **Keyed since A20, and the server cannot do it alone.** `keys` is the
    /// lab's: the pseudonyms are derived from `k_eid`, and without them there
    /// is no way to find a capsule's segments among everything stored here.
    /// Only **closed** epochs are disclosed; the open epoch has no anchored
    /// root to prove inclusion against yet.
    ///
    /// Returns `None` if the capsule index is unknown or no epoch has closed.
    #[must_use]
    pub fn disclose(&self, index: usize, keys: &CaseKeys) -> Option<Bundle> {
        let capsule = self.capsules.get(index)?;
        self.disclose_with(index, keys.disclosure_keys(&capsule.eid))
    }

    /// [`Self::disclose`] from the capsule's three disclosure keys alone —
    /// what a party that does not hold `K_case` has, such as the parent of an
    /// enclave that sealed them to the court (M13 A18).
    ///
    /// `None` under the same conditions; keys for another capsule find no
    /// segment and so also give `None`.
    #[must_use]
    pub fn disclose_with(&self, index: usize, keys: DisclosureKeys) -> Option<Bundle> {
        let capsule = self.capsules.get(index)?;
        let k_eid = PrfKey::new(keys.k_eid);

        // The capsule's own `0x01` leaf, in the epoch that sealed it (M13 A3).
        // Its epoch must be closed too: an unanchored capsule cannot be
        // disclosed, for the same reason an unanchored segment cannot.
        let seal_at = *self.seals.get(index)?;
        let seal = SealProof {
            epoch: seal_at.epoch,
            proof: self.prove(&seal_at)?,
        };
        if !self.closed.iter().any(|c| c.epoch == seal_at.epoch) {
            return None;
        }

        let mut segments = Vec::new();
        for closed in &self.closed {
            let eid_e = CustodyRecord::epoch_pseudonym(&k_eid, closed.epoch);
            let Some(&i) = self.by_pseudonym.get(&eid_e) else {
                continue;
            };
            let stored = &self.segments[i];
            let proof = closed.mmr.prove(stored.leaf_index?)?;
            segments.push(Segment::new(
                eid_e,
                closed.epoch,
                stored.records.clone(),
                proof,
            ));
        }
        if segments.is_empty() {
            return None;
        }
        Some(Bundle::new(capsule.clone(), segments, seal, keys))
    }
}

fn tier1_root(segment: &[CustodyRecord]) -> Digest32 {
    let mut t = CustodyTree::new();
    for r in segment {
        t.append(&r.encode());
    }
    // A segment always holds at least one record, because it is created by the
    // arrival of one. The fallback keeps that invariant from becoming a panic
    // if a caller ever constructs a segment some other way.
    t.root()
        .unwrap_or_else(|| hash_domain(Domain::CustodyRecord, &[b"empty chain"]))
}
