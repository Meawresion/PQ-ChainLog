//! The Evidence Capsule and the Custody Record — the two-plane data model.
//!
//! `PQ-ChainLog-DESIGN.md` §2 and §3. The distinction the supervisor's review
//! demanded: **the artefact** and **the record of who did what to it** are
//! different objects, separately keyed and separately indexed, and both need
//! integrity *and* confidentiality.
//!
//! # Both digests, for different reasons
//!
//! An Evidence Capsule carries `d_ev` **and** `cm_ev`, both Merkle roots over
//! 1 MiB chunks (design §14; `pqcl_pipeline::chunked`): `d_ev` over leaves
//! `H(0x20 ‖ ⟪i, C_ev[i]⟫)`, and `cm_ev` over leaves `H(0x21 ‖ ⟪i, r_ev,
//! artefact[i]⟫)`, hiding under its opening `r_ev`. Not redundancy:
//!
//! * `d_ev` binds the **ciphertext**, so an auditor can verify that stored
//!   bytes match anchored bytes **with no key at all**. That is what makes the
//!   integrity sweeper of design §14 delegable to a low-privilege service.
//! * `cm_ev` binds the **plaintext**, so a lab can open the artefact to a court
//!   without the court having to trust our encryption.
//!
//! Ciphertext-only means a lab that loses `K_ev` cannot prove what it collected.
//! Plaintext-only means the auditor cannot check storage integrity. Hence both.

use pqcl_primitives::aead::{AeadError, CustodyKey, NONCE_BYTES};
use pqcl_primitives::xof::{Digest32, Domain, DomainStream, Label, PrfKey, hash_domain, prf};

use crate::codec::{CodecError, Counter, Encoder, Reader, Sink, Writer};

/// The seven ISO-derived custody event types.
///
/// Deliberately seven and no more: the minimum covering ISO/IEC 27037's four
/// phases, plus 27042 analysis, disclosure and disposal. `ACCESS`, `ANALYZE`
/// and `EXPORT` exist because real custody includes actions that transfer **no
/// ownership** — B-CoC models only ownership transfer, and that is the gap.
///
/// ⚠️ `prov` and `dir` are deliberately **fields, not new event types**
/// so this list and its ISO mapping survive untouched.
/// Do not "tidy" `Transfer` into two variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Event {
    /// Acquisition by a first responder.
    Collect = 1,
    /// Handoff between custodians. Bilateral: two linked records.
    Transfer = 2,
    /// Read without transfer of ownership.
    Access = 3,
    /// Tool run against the artefact.
    Analyze = 4,
    /// Extraction of a derived artefact.
    Export = 5,
    /// Sealing for storage.
    Seal = 6,
    /// Court-ordered or retention-driven disposal.
    Dispose = 7,
}

impl Event {
    /// Discriminant as encoded.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Parse a discriminant.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Collect),
            2 => Some(Self::Transfer),
            3 => Some(Self::Access),
            4 => Some(Self::Analyze),
            5 => Some(Self::Export),
            6 => Some(Self::Seal),
            7 => Some(Self::Dispose),
            _ => None,
        }
    }
}

/// Provenance mode — design §2a.
///
/// The attestation boundary, made explicit and measurable. `Attested` is our
/// Edge Log Agent signing at acquisition inside the Secure Module; `Declared`
/// is an external custodian who acquired with their own tooling and uploaded
/// later.
///
/// The guarantee genuinely differs between them, and the design's position is
/// that the difference should be **stated rather than blurred** — which is what
/// turns "trust the submitting officer" into a quantity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Provenance {
    /// Signed at acquisition inside our Secure Module.
    Attested = 1,
    /// Externally acquired, uploaded later, with `gap_seconds` unattested.
    Declared = 2,
}

impl Provenance {
    /// Discriminant as encoded.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Parse a discriminant.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Attested),
            2 => Some(Self::Declared),
            _ => None,
        }
    }
}

/// An Evidence Capsule: one artefact, sealed at acquisition, immutable after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    /// `eid = F(K_case, "eid" ‖ nonce)` — pseudonymous, unlinkable without the
    /// case key.
    pub eid: Digest32,
    /// `cid_c = H(case_id ‖ r_case)` — the case commitment.
    pub cid_c: Digest32,
    /// Epoch of sealing.
    pub epoch: u64,
    /// Artefact type, e.g. `disk-image`, `memdump`, `pcap`.
    pub artefact_type: Vec<u8>,
    /// `d_ev` — ciphertext digest. Checkable with no key.
    pub d_ev: Digest32,
    /// `cm_ev` — plaintext commitment. Openable in court.
    pub cm_ev: Digest32,
    /// Storage locator. Inside the signed tuple.
    pub ptr: Vec<u8>,
    /// Provenance mode.
    pub provenance: Provenance,
    /// `Δ_gap` — the unattested interval, in seconds. Zero when `Attested`.
    ///
    /// Measured rather than hidden. This is the number that makes the
    /// attestation boundary a stated quantity instead of an assumption.
    pub gap_seconds: u64,
    /// `σ_DEFR` — ML-DSA by the first responder over the sealed tuple.
    pub sig_defr: Vec<u8>,
}

impl Capsule {
    /// Canonical bytes, in fixed field order.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(&self.eid)
            .field(&self.cid_c)
            .u64(self.epoch)
            .field(&self.artefact_type)
            .field(&self.d_ev)
            .field(&self.cm_ev)
            .field(&self.ptr)
            .byte(self.provenance.byte())
            .u64(self.gap_seconds)
            .field(&self.sig_defr);
        w.finish()
    }

    /// Parse canonical bytes.
    ///
    /// # Errors
    ///
    /// Any [`CodecError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes)?;
        let out = Self {
            eid: fixed(r.field()?, "eid")?,
            cid_c: fixed(r.field()?, "cid_c")?,
            epoch: r.u64()?,
            artefact_type: r.field()?.to_vec(),
            d_ev: fixed(r.field()?, "d_ev")?,
            cm_ev: fixed(r.field()?, "cm_ev")?,
            ptr: r.field()?.to_vec(),
            provenance: Provenance::from_byte(r.byte()?)
                .ok_or(CodecError::InvalidField("provenance"))?,
            gap_seconds: r.u64()?,
            sig_defr: r.field()?.to_vec(),
        };
        r.finish()?;
        Ok(out)
    }

    /// The Tier-2 `0x01` capsule-seal leaf.
    ///
    /// ```text
    /// 0x01 ‖ H( ⟪eid, cid_c, e, type, d_ev, cm_ev, prov, Δ_gap, σ_DEFR⟫ )
    /// ```
    ///
    /// `prov` and `Δ_gap` are in here because `PQ-ChainLog-DESIGN.md` §4 was
    /// corrected to carry them. Without them the
    /// anchor does not pin the provenance mode, and an operator could seal a
    /// capsule `DECLARED` with a six-hour gap, anchor it, and later present it
    /// as `ATTESTED` with `Δ_gap = 0` — every inclusion proof still verifying.
    ///
    /// ⚠️ **`σ_DEFR` must cover them too, and nothing here can enforce that.**
    /// The design was corrected on 2026-09-10 so its `σ_DEFR` carries `prov` and
    /// `Δ_gap` as well — until then only the leaf did, and the substitution
    /// above did not even require re-signing. `draft6.tex` eq. (24) still omits
    /// them, but that is not a defect: draft6 has no provenance modes at all, so
    /// the equation cannot reference a field the paper never defines. It lands
    /// with **task #30**.
    ///
    /// The reason this is a comment rather than an assertion: `sig_defr` is an
    /// **input** to this type. Since M5/M8 the signer is
    /// `pqcl_pipeline::capsule_signed_bytes`, inside the Secure Module: the
    /// capsule's whole encoding with `sig_defr` cleared, so `prov` and `Δ_gap`
    /// are covered. A change to that message is silent and, because `σ_DEFR`
    /// is itself hashed into this leaf, unfixable once a real anchor exists.
    #[must_use]
    pub fn seal_leaf(&self) -> pqcl_forest::Leaf {
        pqcl_forest::Leaf::new(
            Domain::CapsuleSeal,
            &[
                &self.eid,
                &self.cid_c,
                &self.epoch.to_le_bytes(),
                &self.artefact_type,
                &self.d_ev,
                &self.cm_ev,
                &[self.provenance.byte()],
                &self.gap_seconds.to_le_bytes(),
                &self.sig_defr,
            ],
        )
    }
}

/// The plaintext body of a custody record — everything M13 A1 moves inside
/// `C_rec`.
///
/// ⭐ **This is the part the AIS must not be able to read.** Before A1 the
/// event, timestamp, actor commitment and parameter commitment were all in
/// clear, so an honest-but-curious server learned the complete shape of every
/// investigation it stored: who acted, when, how often, and with which tool.
/// The papers called the custody plane "encrypted" while only the note was
/// (`audit/07` M1). Encrypting the body is what makes that word true.
///
/// The note travels inside the body rather than beside it, so a record carries
/// one ciphertext and not two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBody {
    /// What happened.
    pub event: Event,
    /// Trusted timestamp. Bracketed by anchoring, never trusted alone.
    pub ts: u64,
    /// `actor_c = H(0x22 ‖ ⟪actor_id, role, r_a⟫)` — openable under warrant.
    pub actor_c: Digest32,
    /// `params_c = H(0x23 ‖ ⟪tool, ver, args, just, r_p⟫)`.
    pub params_c: Digest32,
    /// ⭐ **The record's true chain link** (M13 A20), `H(0x24 ‖ ⟪L_{j−1}⟫)`
    /// over its predecessor's Tier-1 leaf — or `H(0x24 ‖ ⟪eid⟫)` for the
    /// record that opens the capsule.
    ///
    /// Inside a segment the cleartext [`CustodyRecord::h_prev`] carries the
    /// same value, and carrying it twice is a *check*: the clear link is bound
    /// into the AEAD, so a key holder detects a server that rewrote it even
    /// though `σ_actor` already covers it.
    ///
    /// At a **segment start** the two differ, and that is the whole of A20.
    /// The clear `h_prev` becomes `H(0x24 ‖ ⟪eid_e⟫)` — a link to the segment's
    /// own pseudonym, which tells the AIS nothing it does not already hold —
    /// while the real link to the previous segment's last record stays here,
    /// under `K_rec^{eid}`. Without this field the clear `h_prev` of a new
    /// epoch's first record would equal a value the AIS can recompute from the
    /// previous segment, and the per-epoch pseudonyms would be pointless
    /// (`audit/07` D1).
    pub link: Digest32,
    /// Free-text note. Empty when there is none.
    pub note: Vec<u8>,
}

impl RecordBody {
    /// `⟪evt, ts, actor_c, params_c, link, note⟫` — the framed plaintext that
    /// goes under `K_rec^{eid}`.
    ///
    /// Framed, not concatenated: `note` is variable-length and adjacent to a
    /// fixed field, and raw concatenation there is not injective
    /// (and two live defects of this class already found).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.byte(self.event.byte())
            .u64(self.ts)
            .field(&self.actor_c)
            .field(&self.params_c)
            .field(&self.link)
            .field(&self.note);
        w.into_inner()
    }

    /// Parse a decrypted body.
    ///
    /// # Errors
    ///
    /// Any [`CodecError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes)?;
        let out = Self {
            event: Event::from_byte(r.byte()?).ok_or(CodecError::InvalidField("event"))?,
            ts: r.u64()?,
            actor_c: fixed(r.field()?, "actor_c")?,
            params_c: fixed(r.field()?, "params_c")?,
            link: fixed(r.field()?, "link")?,
            note: r.field()?.to_vec(),
        };
        r.finish()?;
        Ok(out)
    }
}

/// Who is accountable for an event (draft8 §V-D, M13 A2).
///
/// ISO/IEC 27037 names two of these — the **DEFR** who collects and the **DES**
/// who specialises — and the custody model adds the custodian who holds the
/// evidence and the investigator who reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Digital Evidence First Responder: acquires at the scene.
    Defr = 1,
    /// Holds the sealed evidence between acts.
    Custodian = 2,
    /// Digital Evidence Specialist: runs the tools.
    Des = 3,
    /// Reads the evidence under warrant.
    Investigator = 4,
}

impl Role {
    /// Discriminant as committed in `actor_c`.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Parse a discriminant.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Defr),
            2 => Some(Self::Custodian),
            3 => Some(Self::Des),
            4 => Some(Self::Investigator),
            _ => None,
        }
    }

    /// Whether this role may sign `event`.
    #[must_use]
    pub fn may(self, event: Event) -> bool {
        event.signers().contains(&self)
    }

    /// Every role, for the registry tests.
    pub const ALL: [Self; 4] = [Self::Defr, Self::Custodian, Self::Des, Self::Investigator];
}

impl Event {
    /// ⭐ **The roles that may sign this event** — draft8's table, verbatim:
    ///
    /// > the DEFR signs `COLLECT`, the DES `ANALYZE` (with tool and parameters
    /// > in `params_c`), the investigator or DES `ACCESS`, and the custodian
    /// > `EXPORT`, `SEAL` and, under an order, `DISPOSE`; `TRANSFER` alone has
    /// > two signers, the releasing and the receiving custodian, over one
    /// > descriptor.
    ///
    /// The paper's own reason for the table: *"a chain in which any
    /// credentialed actor may sign any event establishes presence, not
    /// responsibility."* So this is not an access-control convenience — it is
    /// what makes the chain attribute an act to a role.
    ///
    /// ⚠️ **`TRANSFER`'s second signer is not enforceable here.** Both halves
    /// are signed by custodians, which this table says; that there are *two* of
    /// them, over one descriptor, is `handoff`'s invariant and `in_transit`'s
    /// alarm, because the witness signs after the record exists.
    #[must_use]
    pub const fn signers(self) -> &'static [Role] {
        match self {
            Self::Collect => &[Role::Defr],
            Self::Analyze => &[Role::Des],
            Self::Access => &[Role::Investigator, Role::Des],
            // ⚠️ **`TRANSFER` admits the DEFR as well as the custodian**, and
            // draft8's sentence needs one word for it. It says "the releasing
            // and the receiving custodian", and the first transfer in any case
            // is the DEFR handing what they collected to the evidence store —
            // so "custodian" there means *the party holding custody*, which the
            // DEFR is until they release it. The DES and the investigator are
            // still excluded, which is the distinction that matters: they
            // examine and read, and never take custody.
            Self::Transfer => &[Role::Custodian, Role::Defr],
            Self::Export | Self::Seal | Self::Dispose => &[Role::Custodian],
        }
    }
}

/// An enrolled actor's name: its role and its identifier (the design record
/// §1bg.7, §1br.4).
///
/// ⭐ **Actors are enrolled and addressed by `(role, id)`, not by role alone.**
/// A module that held one key per role could not sign a bilateral transfer
/// between two custodians: both halves, and the witness, came from one key, so
/// the transfer's two signatures named one party. The pair is also what the
/// roster `ρ = {(id, role, pk)}` lists and what `actor_c` commits to, so the
/// three cannot name an actor differently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActorRef {
    /// The role it signs in.
    pub role: Role,
    /// Its identifier, the `id` inside `actor_c`.
    pub id: Vec<u8>,
}

impl ActorRef {
    /// Name an actor.
    #[must_use]
    pub fn new(role: Role, id: &[u8]) -> Self {
        Self {
            role,
            id: id.to_vec(),
        }
    }
}

/// The opening of `actor_c` (draft8 `eq:capsule`'s `0x22`), held by the client
/// and released under warrant.
///
/// ⭐ **`r_a` is what makes `actor_c` hiding, and it must be fresh per record**
/// (M13 A2). Without it the commitment is `H(0x22 ‖ ⟪id, role⟫)` over a tiny
/// domain — a handful of actors and four roles — which anyone can enumerate;
/// and reusing one `r_a` across a chain lets the server group an actor's records
/// by equality, which is the activity profile the per-epoch pseudonyms exist to
/// deny it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorOpening {
    /// The actor's identifier.
    pub id: Vec<u8>,
    /// Its role.
    pub role: Role,
    /// `r_a`, a fresh λ-bit secret.
    pub r_a: Digest32,
}

impl ActorOpening {
    /// `actor_c = H(0x22 ‖ ⟪actor_id, role, r_a⟫)`.
    #[must_use]
    pub fn commit(&self) -> Digest32 {
        hash_domain(
            Domain::ActorCommit,
            &[&self.id, &[self.role.byte()], &self.r_a],
        )
    }
}

/// What `params_c` commits to: the act, before it is blinded.
///
/// Separate from [`ParamsOpening`] so a caller says *what was run* and the
/// Secure Module adds `r_p` — a caller that could choose `r_p` could reuse one,
/// which is the defect [`ActorOpening`] describes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Params {
    /// Tool name, as the binary reports itself.
    pub tool: Vec<u8>,
    /// Its version, as the binary reports it.
    pub ver: Vec<u8>,
    /// The arguments it was given.
    pub args: Vec<u8>,
    /// The justification for the act.
    pub just: Vec<u8>,
}

impl Params {
    /// The common case: a tool run with no separate justification.
    #[must_use]
    pub fn of(tool: &[u8], ver: &[u8], args: &[u8]) -> Self {
        Self {
            tool: tool.to_vec(),
            ver: ver.to_vec(),
            args: args.to_vec(),
            just: Vec::new(),
        }
    }

    /// An act that is not a tool run — a seal, a transfer, a disposal — with
    /// only its justification.
    #[must_use]
    pub fn justified(just: &[u8]) -> Self {
        Self {
            just: just.to_vec(),
            ..Self::default()
        }
    }
}

/// What a record's `params_c` commits to.
///
/// ⚠️ **A `TRANSFER` is the one event whose `params_c` is not a blinded params
/// commitment.** draft8 `eq:handoff` defines both halves of a bilateral
/// transfer as being *over one descriptor* `D = H(0x26 ‖ ⟪eid_e, from, to,
/// cond, R_cap⟫)`, and that shared value is what pairs them: a release and its
/// receipt are the same transfer because they carry the same `D`. A fresh `r_p`
/// per record would make the two halves' commitments differ and destroy the
/// pairing, so for a transfer `params_c = D`, which is itself blinded by
/// `cond`. Every other event takes [`Act::Params`] and is blinded per record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Act {
    /// The ordinary case: the signer adds a fresh `r_p`.
    Params(Params),
    /// A transfer's descriptor, used verbatim.
    Descriptor(Digest32),
}

impl Default for Act {
    fn default() -> Self {
        Self::Params(Params::default())
    }
}

/// The opening of `params_c` (`0x23`): what was run, and why, with its blind.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParamsOpening {
    /// What was run.
    pub params: Params,
    /// `r_p`, a fresh λ-bit secret.
    pub r_p: Digest32,
}

impl ParamsOpening {
    /// `params_c = H(0x23 ‖ ⟪tool, ver, args, just, r_p⟫)`.
    #[must_use]
    pub fn commit(&self) -> Digest32 {
        hash_domain(
            Domain::ParamsCommit,
            &[
                &self.params.tool,
                &self.params.ver,
                &self.params.args,
                &self.params.just,
                &self.r_p,
            ],
        )
    }
}

/// A Custody Record, **v2** (M13 A1): one event, appended to one capsule's
/// chain, with its body encrypted.
///
/// # What is in clear, and why each one has to be
///
/// | Field | Why it cannot be encrypted |
/// |---|---|
/// | `rid` | the AIS's primary key. Keyed under `Label::Rid`, so it is opaque |
/// | `eid_e` | the AIS's index key for the segment |
/// | `h_prev` | the keyless sequential check, **inside one segment** |
/// | `body` | the ciphertext itself |
/// | `order_ref` | ⭐ keyless `0x05` accounting — see the field |
///
/// ⭐ **Sign, then encrypt**. `σ_actor` and
/// `σ_witness` are **inside** `C_rec`, over [`CustodyRecord::signed_message`]:
/// the clear fields and the body's plaintext. In clear, ML-DSA verification
/// needs only a public key, so anyone holding the enrolled actors' keys could
/// trial-verify each stored record and name its signer, and a present
/// `σ_witness` named the event class that A1 had sealed.
///
/// What a keyless auditor checks is therefore **hash-level**: the in-segment
/// `h_prev` links, the Tier-1 and Tier-2 inclusions, the checkpoint chain, the
/// approvals and the `order_ref` accounting. Signatures and roles are checked
/// by a key holder (`Bundle::open` and the court's acceptance). The Tier-1
/// leaf covers `C_rec`, so `h_prev` still carries the predecessor's
/// signatures, and the latest record still attests the whole history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyRecord {
    /// `rid = F(K_rid^{eid}, ⟪j⟫)` — opaque record identifier.
    ///
    /// ⚠️ **Not recomputable by the AIS.** It is keyed, so a server holding
    /// the record cannot confirm a guess at its position or its event.
    pub rid: Digest32,
    /// `eid_e = F(k_eid, e)` — per-epoch pseudonym, so the server cannot link a
    /// capsule's records across epochs. A20 makes the derivation per capsule.
    pub eid_e: Digest32,
    /// `h_prev` — the previous record's chain link **within this segment**, in
    /// clear. Cheap sequential check needing no tree; redundant with the
    /// Tier-1 root **on purpose**, at a cost of 32 bytes.
    ///
    /// ⚠️ **At a segment start this is not the real link** (M13 A20): it is
    /// `H(0x24 ‖ ⟪eid_e⟫)`, and the real one lives in [`RecordBody::link`].
    /// A keyless verifier therefore checks each segment's internal linkage and
    /// nothing across segments — which is exactly the property, not a gap.
    pub h_prev: Digest32,
    /// `C_rec = AEAD(K_rec^{eid}; ⟪body, σ_actor, σ_witness?⟫)`, as
    /// `ciphertext ‖ tag`, under the nonce [`CustodyRecord::body_nonce`] and
    /// with `rid` as associated data.
    ///
    /// ⭐ **No nonce is stored**. It used to
    /// lead `C_rec` as `⟪j⟫`, the record's position across the whole chain,
    /// which told the server each capsule's history length and joined a
    /// segment starting at `j = n` to the one ending at `n − 1`. It is now
    /// derived from `rid`, which the record already carries, so a court
    /// holding `K_rec^{eid}` still opens each record on its own.
    pub body: Vec<u8>,
    /// `oid` of the redaction order a `Dispose` executes.
    ///
    /// ⭐ **In clear, deliberately, and this is the A1 decision.** The
    /// `0x05` order leaf already publishes `oid` and `tgt` on chain, so naming
    /// the order here tells an observer nothing the anchor does not already
    /// tell them — while encrypting it would force a case key into the
    /// auditor's hands and destroy the delegable, keyless `0x05` accounting
    /// that `pqcl_pipeline::redaction::account` performs. A20 §(6) already
    /// declares this linkage.
    ///
    /// ⚠️ **It is also the keyless marker of a redaction disposal**, now that
    /// `event` is encrypted. `Some(oid)` ⟺ a court-ordered `Dispose`; the
    /// constructor enforces that, so an auditor reading `order_ref` alone draws
    /// a sound conclusion. A retention-driven `Dispose` carries `None` and is
    /// invisible to keyless accounting, which is correct: it answers to no
    /// order.
    pub order_ref: Option<Digest32>,
}

/// The signatures a record carries **inside** `C_rec` (§1br F2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSignatures {
    /// `σ_actor` — ML-DSA over [`CustodyRecord::signed_message`]. Not over the
    /// Tier-1 root: the root contains this record's leaf, which contains this
    /// signature, so that would be circular (§1at.2).
    pub actor: Vec<u8>,
    /// `σ_witness` — the counter-signature of a bilateral `TRANSFER`'s
    /// release, over the same message. It is made **before** the body is
    /// sealed, so a record is sealed exactly once and no nonce is ever reused
    /// for a second version of it.
    pub witness: Option<Vec<u8>>,
}

/// A record's body and signatures, as a key holder opens them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedRecord {
    /// The plaintext body.
    pub body: RecordBody,
    /// `σ_actor` and `σ_witness`.
    pub sigs: RecordSignatures,
}

impl CustodyRecord {
    /// The fields, in their fixed canonical order, into any sink. Written once
    /// so the buffered encoding and the streamed leaf cannot drift apart.
    fn write_fields<S: Sink>(&self, e: &mut Encoder<S>) {
        e.field(&self.rid)
            .field(&self.eid_e)
            .field(&self.h_prev)
            .field(&self.body)
            .optional(self.order_ref.as_ref().map(<[u8; 32]>::as_slice));
    }

    /// Canonical bytes, in fixed field order.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write_fields(&mut w);
        w.into_inner()
    }

    /// Parse canonical bytes.
    ///
    /// # Errors
    ///
    /// Any [`CodecError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes)?;
        let out = Self {
            rid: fixed(r.field()?, "rid")?,
            eid_e: fixed(r.field()?, "eid_e")?,
            h_prev: fixed(r.field()?, "h_prev")?,
            body: r.field()?.to_vec(),
            order_ref: r.optional()?.map(|b| fixed(b, "order_ref")).transpose()?,
        };
        r.finish()?;
        Ok(out)
    }

    /// This record's Tier-1 leaf, `L = H(0x10 ‖ ⟪CR⟫)` (draft6 `eq:tier1`).
    ///
    /// ⭐ §1r.2: **streamed**, the encoding absorbed straight into SHAKE rather
    /// than assembled, hashed and dropped. The full-case audit's scaling was
    /// bounded by that per-record ~3.6 KB allocation and copy. The digest is
    /// unchanged: one counting pass gives `len₈`, then the identical bytes are
    /// absorbed, which `the_chain_link_is_eq_hprev_over_the_tier1_leaf` pins by
    /// recomputing the leaf the assembled way from the raw primitives.
    ///
    /// ⚠️ This comment used to name `tests/leaf_stream.rs`, which does not
    /// exist in this workspace — a guard claimed in prose and absent from CI,
    /// the shape the project rules exists to catch. The invariant is
    /// real and tested; only the pointer was wrong.
    #[must_use]
    pub fn tier1_leaf(&self) -> Digest32 {
        let mut count = Encoder::into_sink(Counter::default());
        self.write_fields(&mut count);
        let len = count.into_inner().0;
        let mut stream = Encoder::into_sink(DomainStream::new(Domain::CustodyRecord, len));
        self.write_fields(&mut stream);
        stream.into_inner().finish().unwrap_or_else(|| {
            unreachable!("the counting and streaming passes wrote different lengths")
        })
    }

    /// `h_prev` for the record that follows this one: `H(0x24 ‖ ⟪L⟫)`, over
    /// this record's Tier-1 leaf (draft6 `eq:hprev`, M12).
    ///
    /// ⭐ **Changed 2026-09-27** from `H(0x24 ‖ ⟪CR⟫)`. The leaf is already a
    /// collision-resistant commitment to the record, so the link binds exactly
    /// as strongly; but an audit that holds the leaf (it needs it for the
    /// Tier-1 root anyway) now absorbs each record **once**, not twice. That
    /// double absorption was ~half of the full-case audit (the design record
    /// §1m.1).
    #[must_use]
    pub fn chain_link(&self) -> Digest32 {
        Self::link_from_leaf(&self.tier1_leaf())
    }

    /// `H(0x24 ‖ ⟪L⟫)` from a leaf the caller already computed.
    #[must_use]
    pub fn link_from_leaf(leaf: &Digest32) -> Digest32 {
        hash_domain(Domain::ChainLink, &[leaf])
    }

    /// `K_rec^{eid} = F(K_coc, "rec" ‖ eid)` — the body key for one capsule.
    ///
    /// A court disclosure hands this over for the disclosed capsule alone, so
    /// it opens that capsule's records and no other's.
    #[must_use]
    pub fn body_key(k_coc: &PrfKey, eid: &Digest32) -> CustodyKey {
        CustodyKey::new(Self::body_key_bytes(k_coc, eid))
    }

    /// The same key as raw bytes, for the one caller that must serialise it:
    /// the disclosure bundle a court receives.
    ///
    /// A free function rather than an accessor on [`CustodyKey`], because that
    /// type is `ZeroizeOnDrop` and handing out its bytes is how a key ends up
    /// in a log line. Re-deriving keeps exactly one place that knows the
    /// derivation.
    #[must_use]
    pub fn body_key_bytes(k_coc: &PrfKey, eid: &Digest32) -> Digest32 {
        prf(k_coc, Label::Record, &[eid])
    }

    /// `k_eid = F(K_link, eid)` — one capsule's link key (M13 A20).
    ///
    /// ⭐ **The two-step derivation is what makes disclosure delegable.** A
    /// court is handed `k_eid` for the disclosed capsule and derives every
    /// `eid_e` of *that* capsule, so it can go looking for the capsule's later
    /// segments itself. A one-step `eid_e = F(K_link, eid ‖ e)` would force
    /// the disclosure to hand over `K_link`, which unlocks every capsule in
    /// the case — the whole point of per-capsule disclosure, lost to save one
    /// PRF call.
    #[must_use]
    pub fn capsule_link_key(k_link: &PrfKey, eid: &Digest32) -> PrfKey {
        PrfKey::new(prf(k_link, Label::Link, &[eid]))
    }

    /// `eid_e = F(k_eid, e)` — the pseudonym a capsule's epoch-`e` segment is
    /// filed under (M13 A20).
    #[must_use]
    pub fn epoch_pseudonym(k_eid: &PrfKey, epoch: u64) -> Digest32 {
        prf(k_eid, Label::Link, &[&epoch.to_le_bytes()])
    }

    /// `K_rid^{eid} = F(K_coc, "rid" ‖ eid)` — one capsule's record-identifier
    /// key.
    ///
    /// ⚠️ **Corrected in A20.** A1 derived `rid = F(K_coc, "rid" ‖ ⟪eid, j⟫)`
    /// directly under the **case-wide** `K_coc`, which left a court two bad
    /// options: receive `K_coc` and with it every other capsule's body key, or
    /// give up checking positions altogether. The per-capsule level fixes that
    /// at the cost of one PRF call, and matches `K_rec^{eid}`, which was per
    /// capsule from the start. The AIS still cannot recompute a `rid`.
    #[must_use]
    pub fn rid_key(k_coc: &PrfKey, eid: &Digest32) -> PrfKey {
        PrfKey::new(prf(k_coc, Label::Rid, &[eid]))
    }

    /// `rid = F(K_rid^{eid}, ⟪j⟫)` — the opaque identifier for the `j`-th
    /// record of a capsule's chain.
    ///
    /// `j` counts across the **whole** chain, not within a segment: it is both
    /// the position commitment and, through `rid`, the AEAD nonce source, and
    /// both have to be unique per capsule rather than per epoch.
    #[must_use]
    pub fn derive_rid(k_rid: &PrfKey, j: u64) -> Digest32 {
        prf(k_rid, Label::Rid, &[&j.to_le_bytes()])
    }

    /// The AEAD nonce of the record with this `rid`: its leading 12 bytes
    /// (§1br F1).
    ///
    /// ⭐ **Unique by structure, and pseudorandom to the server.** The key is
    /// per capsule and `rid = F(K_rid^{eid}, ⟪j⟫)` is distinct for distinct
    /// `j`, so two records of one capsule share a nonce only through a 96-bit
    /// truncation collision among a handful of records (about 2⁻⁹⁶ per pair).
    /// One position signed twice would give the same nonce, which is what the
    /// Secure Module's position guard refuses. `rid` is in clear already, so
    /// the nonce tells the server nothing, where `⟪j⟫` told it the position.
    #[must_use]
    pub fn body_nonce(rid: &Digest32) -> [u8; NONCE_BYTES] {
        let mut n = [0u8; NONCE_BYTES];
        n.copy_from_slice(&rid[..NONCE_BYTES]);
        n
    }

    /// What `σ_actor` and `σ_witness` sign: `⟪rid, eid_e, h_prev, order_ref?,
    /// body⟫`, the clear fields and the body's **plaintext** (§1br F2).
    ///
    /// Reads only the clear fields of `self`, never `self.body`, so the
    /// signer can call it before the ciphertext exists.
    #[must_use]
    pub fn signed_message(&self, body: &RecordBody) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(&self.rid)
            .field(&self.eid_e)
            .field(&self.h_prev)
            .optional(self.order_ref.as_ref().map(<[u8; 32]>::as_slice))
            .field(&body.encode());
        w.into_inner()
    }

    /// Seal a body and its signatures into `C_rec = ciphertext ‖ tag`.
    ///
    /// `rid` is the associated data, which binds the ciphertext to its own
    /// record: a body lifted into another record fails to open there, so
    /// substitution is caught by the AEAD and not only by the signature.
    ///
    /// # Errors
    ///
    /// [`AeadError`] if the body exceeds the GCM limit.
    pub fn seal_body(
        key: &CustodyKey,
        rid: &Digest32,
        body: &RecordBody,
        sigs: &RecordSignatures,
    ) -> Result<Vec<u8>, AeadError> {
        let mut w = Writer::new();
        w.field(&body.encode())
            .field(&sigs.actor)
            .optional(sigs.witness.as_deref());
        key.seal(&Self::body_nonce(rid), rid, &w.into_inner())
    }

    /// Open this record's body and its signatures.
    ///
    /// # Errors
    ///
    /// [`AeadError::Authentication`] if the key, the `rid` or the ciphertext
    /// does not match, or the plaintext does not parse. They are deliberately
    /// indistinguishable.
    pub fn open(&self, key: &CustodyKey) -> Result<OpenedRecord, AeadError> {
        let plain = key.open(&Self::body_nonce(&self.rid), &self.rid, &self.body)?;
        Self::parse_opened(&plain).map_err(|_| AeadError::Authentication)
    }

    fn parse_opened(plain: &[u8]) -> Result<OpenedRecord, CodecError> {
        let mut r = Reader::new(plain)?;
        let body = RecordBody::decode(r.field()?)?;
        let actor = r.field()?.to_vec();
        let witness = r.optional()?.map(<[u8]>::to_vec);
        r.finish()?;
        Ok(OpenedRecord {
            body,
            sigs: RecordSignatures { actor, witness },
        })
    }

    /// Open this record's body only.
    ///
    /// # Errors
    ///
    /// As [`CustodyRecord::open`].
    pub fn open_body(&self, key: &CustodyKey) -> Result<RecordBody, AeadError> {
        self.open(key).map(|o| o.body)
    }

    /// The base case at `j = 0`: `H(0x24 ‖ ⟪eid⟫)`.
    ///
    /// A distinct base rather than a zero digest, so the first record of a
    /// chain commits to *which capsule* it opens — otherwise a chain could be
    /// transplanted onto another capsule wholesale.
    #[must_use]
    pub fn genesis_link(eid: &Digest32) -> Digest32 {
        hash_domain(Domain::ChainLink, &[eid])
    }

    /// The cleartext `h_prev` of the record that **opens a segment**:
    /// `H(0x24 ‖ ⟪eid_e⟫)` (M13 A20).
    ///
    /// Same tag and same shape as [`CustodyRecord::genesis_link`], over the
    /// per-epoch pseudonym instead of the capsule id. Two consequences, both
    /// wanted:
    ///
    /// * the AIS can confirm that a record opens the segment it is filed
    ///   under, because `eid_e` is its own index key — so the keyless
    ///   per-segment check still works;
    /// * it cannot do anything else with the value. It is a function of data
    ///   the AIS already has, so it links nothing.
    #[must_use]
    pub fn segment_genesis_link(eid_e: &Digest32) -> Digest32 {
        hash_domain(Domain::ChainLink, &[eid_e])
    }
}

fn fixed(bytes: &[u8], what: &'static str) -> Result<Digest32, CodecError> {
    bytes.try_into().map_err(|_| {
        CodecError::InvalidField(match what {
            "eid" => "eid",
            "cid_c" => "cid_c",
            "d_ev" => "d_ev",
            "cm_ev" => "cm_ev",
            "rid" => "rid",
            "eid_e" => "eid_e",
            "actor_c" => "actor_c",
            "h_prev" => "h_prev",
            "link" => "link",
            _ => "digest",
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capsule() -> Capsule {
        Capsule {
            eid: [1u8; 32],
            cid_c: [2u8; 32],
            epoch: 17,
            artefact_type: b"disk-image".to_vec(),
            d_ev: [3u8; 32],
            cm_ev: [4u8; 32],
            ptr: b"s3://bucket/obj".to_vec(),
            provenance: Provenance::Attested,
            gap_seconds: 0,
            sig_defr: vec![9u8; 3309],
        }
    }

    fn k_coc() -> PrfKey {
        PrfKey::new([0x5au8; 32])
    }

    fn test_eid() -> Digest32 {
        [0x11u8; 32]
    }

    fn body(event: Event, ts: u64) -> RecordBody {
        RecordBody {
            event,
            ts,
            actor_c: [7u8; 32],
            params_c: [9u8; 32],
            link: [8u8; 32],
            note: b"bagged and tagged".to_vec(),
        }
    }

    /// A v2 record with a genuinely sealed body. Not a hand-filled struct: the
    /// ciphertext has to be real for the leaf, the signature coverage and the
    /// round trip to mean anything.
    fn record_with(event: Event, ts: u64, j: u64) -> CustodyRecord {
        let key = CustodyRecord::body_key(&k_coc(), &test_eid());
        let rid = CustodyRecord::derive_rid(&CustodyRecord::rid_key(&k_coc(), &test_eid()), j);
        CustodyRecord {
            rid,
            eid_e: [6u8; 32],
            h_prev: [8u8; 32],
            body: CustodyRecord::seal_body(&key, &rid, &body(event, ts), &sigs(None))
                .expect("seal"),
            order_ref: None,
        }
    }

    /// Recognisable signature bytes, so a test can look for them in clear.
    fn sigs(witness: Option<u8>) -> RecordSignatures {
        RecordSignatures {
            actor: vec![0xa5u8; 3309],
            witness: witness.map(|b| vec![b; 3309]),
        }
    }

    fn record() -> CustodyRecord {
        record_with(Event::Analyze, 1_700_000_000, 0)
    }

    #[test]
    fn a_dispose_carries_its_order_and_nothing_else_changes() {
        let mut d = record_with(Event::Dispose, 1_700_000_000, 0);
        d.order_ref = Some([0x0du8; 32]);
        let back = CustodyRecord::decode(&d.encode()).expect("decode");
        assert_eq!(back, d);
        let mut other = d.clone();
        other.order_ref = Some([0x0eu8; 32]);
        assert_ne!(other.encode(), d.encode(), "order_ref is not bound");
        let mut none = d.clone();
        none.order_ref = None;
        assert_eq!(CustodyRecord::decode(&none.encode()).expect("decode"), none);

        // ⚠️ **Changed by M13 A1.** v1 encoded `order_ref` only for a
        // `Dispose`, so tagging any other record left its bytes untouched. The
        // event now lives inside `C_rec`, so the decoder cannot branch on it
        // and the slot is always present — which means tagging a non-disposal
        // *does* change its bytes. That is the intended shape: `order_ref` is
        // the keyless marker of a court-ordered disposal
        // so it must be bound everywhere.
        let plain = record();
        let mut tagged = plain.clone();
        tagged.order_ref = Some([0x0du8; 32]);
        assert_ne!(
            tagged.encode(),
            plain.encode(),
            "order_ref must be bound on every record, not only a Dispose"
        );
        // `order_ref` is an unconditional `optional()` in v2, so a record
        // without one already pays the presence byte. Carrying one adds the
        // framed digest on top: `len₈` plus 32 bytes.
        assert_eq!(
            d.encode().len(),
            plain.encode().len() + 8 + 32,
            "a carried order_ref adds exactly its framed digest"
        );
    }

    #[test]
    fn a_capsule_round_trips() {
        let c = capsule();
        assert_eq!(Capsule::decode(&c.encode()).expect("decode"), c);
    }

    #[test]
    fn a_custody_record_round_trips() {
        let r = record();
        assert_eq!(CustodyRecord::decode(&r.encode()).expect("decode"), r);
    }

    /// ⭐ §1br F2: the signatures travel **inside** `C_rec`. A key holder
    /// opens both; the stored bytes contain neither, so nobody holding only
    /// the actors' public keys can trial-verify a record to name its signer,
    /// and the witness's presence is not a cleartext field.
    #[test]
    fn the_signatures_are_inside_the_ciphertext() {
        let key = CustodyRecord::body_key(&k_coc(), &test_eid());
        let r = record_with(Event::Transfer, 1_700_000_000, 0);
        let mut w = r.clone();
        w.body = CustodyRecord::seal_body(
            &key,
            &w.rid,
            &body(Event::Transfer, 1_700_000_000),
            &sigs(Some(0x5a)),
        )
        .expect("seal");

        let opened = w.open(&key).expect("open");
        assert_eq!(opened.sigs, sigs(Some(0x5a)));
        assert_eq!(opened.body, body(Event::Transfer, 1_700_000_000));
        assert_eq!(r.open(&key).expect("open").sigs.witness, None);

        for stored in [r.encode(), w.encode()] {
            for pattern in [[0xa5u8; 64], [0x5au8; 64]] {
                assert!(
                    !stored.windows(64).any(|x| x == pattern),
                    "a signature is readable in the stored record"
                );
            }
        }
        assert_eq!(CustodyRecord::decode(&w.encode()).expect("decode"), w);
    }

    /// ⭐ §1br F1: `C_rec` carries no nonce; it is `rid`'s leading 12 bytes,
    /// so the stored ciphertext begins with pseudorandom bytes, not `⟪j⟫`.
    #[test]
    fn the_nonce_is_derived_from_rid_and_not_stored() {
        let key = CustodyRecord::body_key(&k_coc(), &test_eid());
        for j in 0..4u64 {
            let r = record_with(Event::Analyze, 1, j);
            assert_eq!(
                &CustodyRecord::body_nonce(&r.rid)[..],
                &r.rid[..NONCE_BYTES]
            );
            assert_ne!(
                &r.body[..8],
                &j.to_le_bytes()[..],
                "C_rec leads with its position"
            );
            // Opening under the position nonce, the pre-F1 layout, fails.
            let mut legacy = [0u8; NONCE_BYTES];
            legacy[..8].copy_from_slice(&j.to_le_bytes());
            assert!(key.open(&legacy, &r.rid, &r.body).is_err());
            r.open(&key).expect("opens under the derived nonce");
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        assert_eq!(capsule().encode(), capsule().encode());
        assert_eq!(record().encode(), record().encode());
    }

    #[test]
    fn every_field_affects_the_encoding() {
        // If a field did not, it would not be committed to, and an anchored
        // root would not actually pin it.
        let base = capsule().encode();
        let mut m = capsule();
        m.epoch += 1;
        assert_ne!(base, m.encode());
        let mut m = capsule();
        m.gap_seconds = 42;
        assert_ne!(base, m.encode());
        let mut m = capsule();
        m.provenance = Provenance::Declared;
        assert_ne!(base, m.encode());
        let mut m = capsule();
        m.d_ev[0] ^= 1;
        assert_ne!(base, m.encode());
    }

    #[test]
    fn provenance_and_gap_are_committed_by_the_anchored_leaf() {
        // Design §4 was corrected to carry both fields — the design record
        // §0.7. This test was previously inverted, pinning the gap so it stayed
        // visible; it now asserts the property.
        //
        // What it defends: an operator sealing `DECLARED, Δ_gap = 6h`, anchoring,
        // then presenting the same capsule as `ATTESTED, Δ_gap = 0`. Before the
        // fix, every inclusion proof still verified.
        let mut a = capsule();
        a.provenance = Provenance::Attested;
        a.gap_seconds = 0;

        let mut d = capsule();
        d.provenance = Provenance::Declared;
        d.gap_seconds = 21_600;

        assert_ne!(a.encode(), d.encode(), "the record must distinguish them");
        assert_ne!(
            a.seal_leaf().digest,
            d.seal_leaf().digest,
            "the anchored leaf must commit prov and gap_seconds"
        );

        // Each field independently, so neither can be dropped later without a
        // test noticing.
        let mut only_prov = capsule();
        only_prov.provenance = Provenance::Declared;
        assert_ne!(capsule().seal_leaf().digest, only_prov.seal_leaf().digest);

        let mut only_gap = capsule();
        only_gap.gap_seconds = 1;
        assert_ne!(capsule().seal_leaf().digest, only_gap.seal_leaf().digest);
    }

    #[test]
    fn all_seven_event_types_round_trip() {
        for e in [
            Event::Collect,
            Event::Transfer,
            Event::Access,
            Event::Analyze,
            Event::Export,
            Event::Seal,
            Event::Dispose,
        ] {
            let r = record_with(e, 1_700_000_000, 0);
            let back = CustodyRecord::decode(&r.encode()).expect("decode");
            let opened = back
                .open_body(&CustodyRecord::body_key(&k_coc(), &test_eid()))
                .expect("open");
            assert_eq!(opened.event, e);
        }
    }

    /// ⚠️ **Moved from the record to the body by M13 A1.** There is no longer
    /// a cleartext event byte in a record's encoding to corrupt: the event is
    /// inside `C_rec`, so `CustodyRecord::decode` never parses one and cannot
    /// reject one. Validation moved to `RecordBody::decode`, which is where the
    /// event now appears, and this test moved with it.
    ///
    /// Corrupting the record's ciphertext instead is already covered: the AEAD
    /// refuses to open it (`a_flipped_body_byte_fails_to_open`).
    #[test]
    fn an_unknown_event_discriminant_is_rejected_by_the_body() {
        // Locate the event byte rather than assume its offset: encode two
        // bodies that differ only in the event and take the one index where
        // they disagree. A hand-computed offset silently stops pointing at the
        // event the moment the framing changes, and then the test passes for
        // the wrong reason.
        let a = body(Event::Analyze, 1_700_000_000).encode();
        let b = body(Event::Access, 1_700_000_000).encode();
        let diff: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        assert_eq!(diff.len(), 1, "exactly one byte encodes the event");

        let mut bytes = a;
        bytes[diff[0]] = 99;
        assert_eq!(
            RecordBody::decode(&bytes),
            Err(CodecError::InvalidField("event"))
        );
    }

    /// The AEAD, not the codec, is what catches a tampered body.
    #[test]
    fn a_flipped_body_byte_fails_to_open() {
        let key = CustodyRecord::body_key(&k_coc(), &test_eid());
        let mut r = record();
        r.body[0] ^= 1;
        assert!(
            r.open_body(&key).is_err(),
            "a flipped ciphertext byte must not open"
        );
    }

    /// `rid` is the associated data, so a body is bound to its own record.
    #[test]
    fn a_body_lifted_into_another_record_does_not_open() {
        let key = CustodyRecord::body_key(&k_coc(), &test_eid());
        let a = record_with(Event::Analyze, 1, 0);
        let mut b = record_with(Event::Analyze, 2, 1);
        b.body = a.body.clone();
        assert!(
            b.open_body(&key).is_err(),
            "substitution must fail at the AEAD, not only at the signature"
        );
    }

    #[test]
    fn the_genesis_link_binds_the_capsule() {
        // A chain's first record commits to which capsule it opens, so a chain
        // cannot be transplanted onto another capsule wholesale.
        assert_ne!(
            CustodyRecord::genesis_link(&[1u8; 32]),
            CustodyRecord::genesis_link(&[2u8; 32])
        );
    }

    #[test]
    fn the_chain_link_changes_with_the_record() {
        let a = record();
        let b = record_with(Event::Analyze, 1_700_000_001, 0);
        assert_ne!(a.chain_link(), b.chain_link());
    }

    #[test]
    fn the_chain_link_is_eq_hprev_over_the_tier1_leaf() {
        // Re-pinned from draft6 `eq:hprev` itself (M12), with the raw
        // primitives rather than the helpers under test:
        // h_prev = H(0x24 ‖ ⟪L⟫), L = H(0x10 ‖ ⟪CR⟫).
        let r = record();
        let leaf = hash_domain(Domain::CustodyRecord, &[&r.encode()]);
        assert_eq!(r.tier1_leaf(), leaf);
        assert_eq!(r.chain_link(), hash_domain(Domain::ChainLink, &[&leaf]));
        // And not the pre-M12 form, which absorbed the record itself.
        assert_ne!(
            r.chain_link(),
            hash_domain(Domain::ChainLink, &[&r.encode()])
        );
    }

    #[test]
    fn a_truncated_encoding_is_rejected_not_panicked() {
        let bytes = capsule().encode();
        for cut in [1usize, 5, 40, bytes.len() - 1] {
            assert!(Capsule::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }
}
