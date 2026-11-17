//! SHAKE256, and the single point through which every domain-separated hash and
//! PRF derivation in PQ-ChainLog passes.
//!
//! # The two namespaces
//!
//! `../paper/draft6.tex` eq. (2) fixes **five hash roles**, each identified by a
//! byte absorbed at a fixed position:
//!
//! ```text
//! H(x)      = SHAKE256(0x00 ‖ x)              → 256 bits
//! F(K,x)    = SHAKE256(K ‖ 0x01 ‖ x)          → λ
//! H₁(x)     = SHAKE256(0x02 ‖ x)              → 256 bits
//! H_X(K,x)  = SHAKE256(K ‖ 0x03 ‖ x)          → 256 bits
//! G(s)      = SHAKE256(0x04 ‖ s)              → 2λ
//! ```
//!
//! Separately, [`Domain`] tags identify **leaf and field types**. The two
//! namespaces overlap numerically — `0x01` is both the PRF role and the Tier-2
//! capsule-seal leaf — and are disambiguated purely by **position**: the role
//! byte is outermost, the field tag inner. So a capsule-seal commitment is
//! `SHAKE256(0x00 ‖ 0x01 ‖ …)`, which can never collide with `F(K, ·)`.
//!
//! They are modelled as two separate Rust types precisely so one cannot be
//! passed where the other belongs. Do not merge them into one enum.
//!
//! # Framing — draft6 eq. (3)
//!
//! `⟪x₁,…,xₙ⟫ = len₈(x₁) ‖ x₁ ‖ … ‖ len₈(xₙ) ‖ xₙ`, with `len₈` an 8-byte
//! little-endian length. Tags are absorbed *before* the framing and are not
//! themselves length-prefixed.
//!
//! This exists for a security reason, not tidiness. Draft 6 originally defined
//! `actor_c = H(0x22 ‖ actor_id ‖ role ‖ r_a)` by plain concatenation over two
//! variable-length fields, which is not injective: `("ab","c")` and
//! `("a","bc")` commit identically. Since `actor_c` is opened under warrant and
//! the verifier checks the committed `role` against `evt`, a committer could
//! open to whichever role made their action look authorised. Framing closes it,
//! and as a bonus removes the fixed-width precondition that the Tier-2 leaf
//! encoding would otherwise need on `e` and `type`.
//!
//! # Why this module is centralised
//!
//! M4 must prove a `0x02` leaf cannot be presented as `0x03`. That test is only
//! meaningful if there is one implementation of tagging to test — scattering
//! `shake256(&[0x02, ..])` across five crates is how the test comes to pass
//! while the property fails.

// ⭐ M12 R1: `tiny-keccak`, not `sha3`. Same function (the ACVP SHAKE-256 vectors
// and `tests/xof_backend.rs` check both), but `sha3` costs ~2.1x per call at
// 32-64 B, which is every PRF, GGM step and Merkle node (the plan's SHAKE256
// backend table). Campaign 03's range-ingest loss was that per-call cost.
use tiny_keccak::{Hasher, Shake, Xof};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::LAMBDA_BYTES;

/// A 256-bit digest. Every address, tag, commitment and root in the system.
pub type Digest32 = [u8; LAMBDA_BYTES];

/// Hash roles — draft6 eq. (2). The **outermost** domain separator.
///
/// All five roles of draft6 eq. (2) are now present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
enum Role {
    /// `H(x) = SHAKE256(0x00 ‖ x)` — collision-resistant hash.
    Hash = 0x00,
    /// `F(K,x) = SHAKE256(K ‖ 0x01 ‖ x)` — keyed PRF.
    Prf = 0x01,
    /// `H₁(x) = SHAKE256(0x02 ‖ x)` — the `Π_core` address hash.
    Addr = 0x02,
    /// `H_X(K,x) = SHAKE256(K ‖ 0x03 ‖ x)` — the cross-tag hash.
    CrossTag = 0x03,
    /// `G(s) = SHAKE256(0x04 ‖ s)` → 2λ — the GGM tree step.
    Prg = 0x04,
}

impl Role {
    const fn byte(self) -> u8 {
        self as u8
    }
}

/// Leaf and field tags — draft6 Table II and the plan's tag registry.
///
/// These byte values are normative: they appear inside anchored on-chain roots,
/// so changing one silently invalidates every previously anchored proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Domain {
    // ---- Tier 2, the per-epoch MMR ------------------------------------
    /// `0x01` — capsule seal.
    CapsuleSeal = 0x01,
    /// `0x02` — custody-tree root.
    CustodyRoot = 0x02,
    /// `0x03` — index epoch, over the **sorted** `XSet_e`.
    IndexEpoch = 0x03,
    /// `0x04` — audit / trapdoor request.
    AuditEvent = 0x04,
    /// `0x05` — dispose. Specified in `PQ-ChainLog-DESIGN.md` §12; **not yet in
    /// `draft6.tex`**, which still has seven phases.
    Dispose = 0x05,
    /// `0x06` — sweep attestation. Design §14.4; **not yet in `draft6.tex`**.
    SweepAttestation = 0x06,
    /// `0x07` — agent-epoch root, evidence plane only. Design §8a.2; **not yet
    /// in `draft6.tex`**.
    AgentEpochRoot = 0x07,

    // ---- Tier 1, one capsule's custody tree ---------------------------
    /// `0x10` — custody-record **leaf**, `L_j = H(0x10 ‖ ⟪CR_j⟫)`.
    CustodyRecord = 0x10,
    /// `0x11` — Merkle **internal node**, `N(u,v) = H(0x11 ‖ ⟪u,v⟫)`.
    ///
    /// Distinct leaf and internal tags are what stop an internal node being
    /// presented as a leaf. A Merkle tree without them admits second-preimage
    /// attacks, so this is load-bearing rather than decorative.
    MerkleInternal = 0x11,
    /// `0x12` — epoch checkpoint, `d_e = H(0x12 ‖ ⟪cid, e, R_e, leafCount,
    /// d_{e−1}⟫)` (draft8 `eq:checkpoint`).
    Checkpoint = 0x12,
    /// `0x13` — approval-set digest, `A_e = H(0x13 ‖ ⟪S_e, σ_SLH⟫)` (draft8
    /// `eq:anchortx`).
    ApprovalSet = 0x13,
    /// `0x14` — case commitment, `cid = H(0x14 ‖ ⟪case_id, r_c⟫)`.
    ///
    /// ⚠️ draft8 writes `H(case ‖ …)` with a string label; every other hash is
    /// under a one-byte tag from disjoint blocks (`eq:hashinst`), and a string
    /// after the role byte would start with a length byte equal to `0x04`. This
    /// tag and `0x15` are the fix proposed in the design record.
    CaseId = 0x14,
    /// `0x15` — case registration, `reg = H(0x15 ‖ ⟪cid, pk_SIG, pk_KEM, pk_SLH,
    /// {pk_Cj}, M, Δ, ρ_c⟫)` (draft8 `eq:reg`, `ρ_c` since §1br F3), the checkpoint chain's `d_{−1}`.
    /// Distinct from `0x14` because framing is injective only for a fixed
    /// arity: a two-field and a seven-field input must not share a tag.
    CaseRegistration = 0x15,
    /// `0x16` — the enrolled-actor roster, `ρ_c = H(0x16 ‖ ⟪ρ⟫)` with
    /// `ρ = {(id, role, pk)}`, committed in `reg` (the design record
    /// §1br F3). Proposed in design review, like `0x14`/`0x15` before it: the
    /// court checks the roster it receives sealed against this, and the AIS,
    /// which sees only `reg`, never learns which actors a case enrolled.
    Roster = 0x16,

    // ---- Record-field commitments -------------------------------------
    /// `0x20` — `d_ev = H(0x20 ‖ ⟪C_ev⟫)`. Binds ciphertext, so it is checkable
    /// with no key — which is what lets the integrity sweeper be unprivileged.
    EvidenceDigest = 0x20,
    /// `0x21` — `cm_ev = H(0x21 ‖ ⟪artefact, r_ev⟫)`. Binds plaintext, openable
    /// to a court without the court trusting our encryption.
    PlaintextCommit = 0x21,
    /// `0x22` — `actor_c = H(0x22 ‖ ⟪actor_id, role, r_a⟫)`.
    ActorCommit = 0x22,
    /// `0x23` — `params_c = H(0x23 ‖ ⟪tool, ver, args, just, r_p⟫)`.
    ParamsCommit = 0x23,
    /// `0x24` — the chain link, in three uses that share the tag because they
    /// share a preimage space of one 32-byte digest: `h_prev` inside a
    /// segment, a segment's cleartext base case `H(0x24 ‖ ⟪eid_e⟫)` (M13 A20),
    /// and a capsule's own base case at `j = 0`, which is
    /// `H(0x24 ‖ ⟪eid⟫)`.
    ChainLink = 0x24,
    /// `0x25` — correction reason. Corrections are append-only; a superseded
    /// record stays valid and in the chain.
    CorrectionReason = 0x25,

    /// `0x26` — handoff descriptor, `D = H(0x26 ‖ ⟪eid_e, from, to, cond, R_cap⟫)`.
    ///
    /// ⚠️ Framing here is **load-bearing**, not decorative. Before
    /// The design record, eq. (`eq:handoff`) concatenated three
    /// adjacent variable-length fields, so `D` did not bind the `(from, to)`
    /// pair — the one field bilateral transfer exists to make non-repudiable.
    HandoffDescriptor = 0x26,
    /// `0x27` — device signature pre-hash for the ingestion chain.
    DeviceSigPreHash = 0x27,
    /// `0x28` — device chain link, `h_i`. Same framing defect as `0x26`, found
    /// in the same pass: eq. (`eq:chain`) had `c` and `tokens` adjacent and both
    /// variable-length.
    DeviceChainLink = 0x28,

    // ---- Authorization objects (M6) -----------------------------------
    //
    // A block of its own, deliberately. `0x26`–`0x28` above continue the
    // record-field reservation of draft6 l. 1024; an authorization object is
    // not a record field, and appending it there would falsify the paper's own
    // reservation sentence.
    /// `0x30` — warrant-tree leaf, `C = H(0x30 ‖ ⟪warrant, s⟫)`.
    WarrantCommit = 0x30,
    /// `0x31` — one-time nullifier, `N = H(0x31 ‖ ⟪s, e⟫)`.
    Nullifier = 0x31,
    /// `0x32` — warrant-tree **internal node**.
    ///
    /// ⭐ **Must not reuse [`Domain::MerkleInternal`] (`0x11`).** The warrant
    /// root and the custody forest root are both anchored on the same chain, so
    /// a shared node tag would leave a digest reinterpretable between the two
    /// trees. draft6 eq. (`eq:relauth`) wrote `Path(C, π) = ρ_W` and never
    /// defined the node function at all, which is how this stayed invisible.
    WarrantNode = 0x32,
    /// `0x33` — query-scope digest, the `H(scope(q))` of the public statement.
    QueryScope = 0x33,
    /// `0x34` — trapdoor digest, the `H(trapdoor)` of the `0x04` audit leaf.
    TrapdoorDigest = 0x34,
    /// `0x35` — result-set commitment, `R_res = H(0x35 ‖ ⟪N, H(0x34‖⟪td⟫),
    /// sorted(R), r_res⟫)` (draft8 `eq:rres`).
    ResultSet = 0x35,
}

impl Domain {
    /// Every registered tag, for the registry tests.
    pub const ALL: [Self; 29] = [
        Self::CapsuleSeal,
        Self::CustodyRoot,
        Self::IndexEpoch,
        Self::AuditEvent,
        Self::Dispose,
        Self::SweepAttestation,
        Self::AgentEpochRoot,
        Self::CustodyRecord,
        Self::MerkleInternal,
        Self::Checkpoint,
        Self::ApprovalSet,
        Self::CaseId,
        Self::CaseRegistration,
        Self::Roster,
        Self::EvidenceDigest,
        Self::PlaintextCommit,
        Self::ActorCommit,
        Self::ParamsCommit,
        Self::ChainLink,
        Self::CorrectionReason,
        Self::HandoffDescriptor,
        Self::DeviceSigPreHash,
        Self::DeviceChainLink,
        Self::WarrantCommit,
        Self::Nullifier,
        Self::WarrantNode,
        Self::QueryScope,
        Self::TrapdoorDigest,
        Self::ResultSet,
    ];

    /// The normative tag byte.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Key-derivation labels — draft6 Table I.
///
/// Every variant's byte string is transcribed from the paper and pinned by a
/// test. There is no `XTag` label: draft6 remark `rem:ratchet` explicitly
/// *rejects* `K_X^(e) = F(K_mst, "xtag" ‖ e)` because a surviving master would
/// regenerate the cross-tag keys and make court-ordered erasure cosmetic. Use
/// [`Label::Ratchet`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Label {
    /// `K_case = F(K_mst, "case" ‖ cid_c)`. Also the GGM writer-tree root.
    Case,
    /// `K_S^plane = F(K_case, "idx" ‖ plane)` — one DSSE instance per plane.
    Index,
    /// `K_link = F(K_case, "link")` — derives per-epoch capsule pseudonyms.
    Link,
    /// `K_coc = F(K_case, "note")` — AEAD key for `C_note`.
    Note,
    /// `K^A_w = F(K_S, "addr" ‖ w)` — GGM root over the counter space, released
    /// in constrained form at search time.
    Addr,
    /// `K^M_w = F(K_S, "mask" ‖ w)` — payload key seed. **Never released.**
    ///
    /// The asymmetry with [`Label::Addr`] is what makes `Π_core` verifiable
    /// against a malicious server: the client derives every address itself and
    /// binds it as AEAD associated data, while the server never sees `K^M_w`.
    /// Collapsing the two trees is the natural-looking optimisation that
    /// silently destroys the scheme.
    Mask,
    /// `eid = F(K_case, "eid" ‖ nonce)` — pseudonymous capsule identifier.
    Eid,
    /// `K_rec^{eid} = F(K_coc, "rec" ‖ eid)` — the per-capsule AEAD key for a
    /// custody record body (M13 A1).
    ///
    /// ⭐ **Per capsule, not per case.** A court disclosure hands over
    /// `K_rec^{eid}` for the disclosed capsule alone, so holding it reveals
    /// that capsule's records and no other's. A single case-wide body key
    /// would make every disclosure a disclosure of the whole case.
    Record,
    /// `rid = F(K_coc, "rid" ‖ ⟪eid, j⟫)` — the opaque record identifier
    /// (M13 A1).
    ///
    /// ⚠️ **Keyed, so the AIS cannot recompute it.** v1 derived `rid` from
    /// `(eid, event, h_prev, ts)` with a plain hash, which let anyone holding
    /// the record guess-and-check its position and event. Keying it closes
    /// that without costing the chain anything: `rid` is carried in clear and
    /// covered by the leaf either way.
    Rid,
    /// `K_X^(e+1) = F(K_X^(e), "rat")` — the one-way cross-tag ratchet of
    /// draft6 eq. (`eq:ratchet`). `K_X^(0)` is an **independent draw**, not a
    /// derivation, which is why no label produces it.
    Ratchet,
}

impl Label {
    /// The byte string absorbed for this label, transcribed from draft6.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Case => b"case",
            Self::Index => b"idx",
            Self::Link => b"link",
            Self::Note => b"note",
            Self::Addr => b"addr",
            Self::Mask => b"mask",
            Self::Eid => b"eid",
            Self::Record => b"rec",
            Self::Rid => b"rid",
            Self::Ratchet => b"rat",
        }
    }
}

/// A 256-bit PRF key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrfKey([u8; LAMBDA_BYTES]);

impl PrfKey {
    /// Wrap raw key bytes.
    #[must_use]
    pub const fn new(bytes: [u8; LAMBDA_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; LAMBDA_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for PrfKey {
    /// Never prints key material. A key in a log line is a key on disk.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrfKey(<redacted>)")
    }
}

/// Raw SHAKE256 with arbitrary output length — **no role byte**.
///
/// This is the bare primitive, exposed because the ACVP vectors exercise it
/// directly. It is *not* `H`: every use inside PQ-ChainLog goes through
/// [`digest256`], [`hash_domain`] or [`prf`], which apply the role byte that
/// draft6 eq. (2) requires.
#[must_use]
pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake::v256();
    hasher.update(data);
    let mut out = vec![0u8; out_len];
    hasher.squeeze(&mut out);
    out
}

/// `H(x) = SHAKE256(0x00 ‖ x)` — draft6 eq. (2).
#[must_use]
pub fn digest256(data: &[u8]) -> Digest32 {
    let mut hasher = Shake::v256();
    hasher.update(&[Role::Hash.byte()]);
    hasher.update(data);
    squeeze(hasher)
}

/// `H(tag ‖ ⟪x⟫)` for **one** field `x` whose bytes arrive in pieces: the same
/// digest as `hash_domain(tag, &[x])`, without first assembling `x`.
///
/// §1r.2: a full-case audit spent its scaling on `CustodyRecord::encode()`,
/// a ~3.6 KB allocation and copy per record, only to hash the buffer and drop
/// it. The frame needs `len₈(x)` before the bytes, so the caller declares the
/// length up front; [`DomainStream::finish`] returns `None` unless exactly that
/// many bytes arrived, so a framing slip cannot silently produce a digest.
pub struct DomainStream {
    hasher: Shake,
    left: usize,
    overrun: bool,
}

impl DomainStream {
    /// Begin `H(tag ‖ len₈(len) ‖ …)`.
    #[must_use]
    pub fn new(domain: Domain, len: usize) -> Self {
        let mut hasher = Shake::v256();
        hasher.update(&[Role::Hash.byte()]);
        hasher.update(&[domain.tag()]);
        hasher.update(&len8(len));
        Self {
            hasher,
            left: len,
            overrun: false,
        }
    }

    /// Absorb the next bytes of `x`.
    pub fn absorb(&mut self, bytes: &[u8]) {
        match self.left.checked_sub(bytes.len()) {
            Some(rest) => self.left = rest,
            None => self.overrun = true,
        }
        self.hasher.update(bytes);
    }

    /// The digest, or `None` if the bytes absorbed were not exactly the
    /// declared length.
    #[must_use]
    pub fn finish(self) -> Option<Digest32> {
        (self.left == 0 && !self.overrun).then(|| squeeze(self.hasher))
    }
}

/// `H(tag ‖ ⟪f₁,…,fₙ⟫)` — a domain-separated commitment over framed fields.
///
/// Absorbs `0x00 ‖ tag ‖ len₈(f₁) ‖ f₁ ‖ …`. The role byte is outermost and the
/// field tag inner; absorbing them the other way round produces a different
/// digest, so the order is pinned by a test.
#[must_use]
pub fn hash_domain(domain: Domain, fields: &[&[u8]]) -> Digest32 {
    let mut hasher = Shake::v256();
    hasher.update(&[Role::Hash.byte()]);
    hasher.update(&[domain.tag()]);
    absorb_framed(&mut hasher, fields);
    squeeze(hasher)
}

/// `F(K, ⟪label, d₁,…⟫) = SHAKE256(K ‖ 0x01 ‖ ⟪label, d₁,…⟫)` — draft6 eq. (2).
///
/// The key is absorbed first and at fixed width, then the PRF role byte, then
/// the framed label and data. SHAKE256 is a sponge, so the plain-prefix keying
/// is sound here in a way it would not be for a Merkle–Damgård hash.
///
/// # Not every `F` application has a label
///
/// Draft6 also uses unlabelled applications, e.g. `eid_e = F(K_link, eid ‖ e)`,
/// where the key is dedicated to a single purpose so no label is needed. That
/// form has no caller yet and is deliberately not provided here — whoever needs
/// it at M4 should add it against the paper's equation rather than inventing a
/// label that draft6 does not contain.
#[must_use]
pub fn prf(key: &PrfKey, label: Label, data: &[&[u8]]) -> Digest32 {
    let mut hasher = Shake::v256();
    hasher.update(key.as_bytes());
    hasher.update(&[Role::Prf.byte()]);
    let label = label.as_bytes();
    hasher.update(&len8(label.len()));
    hasher.update(label);
    absorb_framed(&mut hasher, data);
    squeeze(hasher)
}

/// The byte that encodes the **evidence** plane in a key derivation.
pub const PLANE_EVIDENCE: u8 = 0x00;

/// The byte that encodes the **custody** plane in a key derivation.
pub const PLANE_CUSTODY: u8 = 0x01;

/// `K_S^plane = F(K_case, "idx" ‖ plane)` — draft6 eq. (`eq:kidx`), the DSSE
/// index master for one plane.
///
/// ⭐ **The plane's byte encoding lives here and nowhere else** (M13 A18). The
/// paper fixes the derivation but not how `plane` is *encoded*, and the project
/// had two answers at once: `b"evidence"` / `b"custody"` where the demo built
/// its index, and a 0/1 byte where a warrant delegated authority over it. Those
/// are different keys, so a trapdoor delegated from a warrant would never have
/// opened the index the demo built — and nothing failed, because no test
/// crossed from one to the other.
///
/// One function with one encoding is stronger than two call sites kept in step
/// by a test, so there is no test asserting they agree: there is only this.
#[must_use]
pub fn index_master(k_case: &PrfKey, plane: u8) -> Digest32 {
    prf(k_case, Label::Index, &[&[plane]])
}

/// `H₁(x) = SHAKE256(0x02 ‖ x)` — the `Π_core` address hash, draft6 eq. (2).
///
/// Maps a GGM leaf to the `EDB` address it is stored at. A separate role from
/// `H` because the client publishes `addr` to the server while the leaf itself
/// stays secret: without the separation, an address would be a hash the
/// adversary could also compute from public data elsewhere in the system.
#[must_use]
pub fn addr_hash(tag: &Digest32) -> Digest32 {
    let mut hasher = Shake::v256();
    hasher.update(&[Role::Addr.byte()]);
    hasher.update(tag);
    squeeze(hasher)
}

/// `H_X(K, x) = SHAKE256(K ‖ 0x03 ‖ x)` — the cross-tag hash, draft6 eq. (2).
///
/// Produces the `xtag` values that make up `XSet_e`. Keyed by the **epoch**
/// cross-tag key `K_X^(e)`, which is a one-way ratchet rather than a
/// derivation — see `Label::Ratchet`. Destroying a prefix of `{K_X^(e)}` is
/// what makes court-ordered erasure real rather than cosmetic, and that only
/// works because these keys cannot be regenerated from a surviving master.
///
/// The payload is framed, because `op ‖ w ‖ id` concatenates a variable-length
/// keyword with fixed-width neighbours and the same injectivity argument
/// applies as in eq. (3).
#[must_use]
pub fn cross_tag(key: &PrfKey, fields: &[&[u8]]) -> Digest32 {
    let mut hasher = Shake::v256();
    hasher.update(key.as_bytes());
    hasher.update(&[Role::CrossTag.byte()]);
    absorb_framed(&mut hasher, fields);
    squeeze(hasher)
}

/// `G(s) = SHAKE256(0x04 ‖ s)` → 2λ — the GGM tree step as draft6 eq. (2) wrote
/// it **before M12 R3**.
///
/// ⚠️ **Superseded for the GGM tree** by [`crate::prg::ggm_step`] (AES-256),
/// which `pqcl-ggm` now uses. Kept because role `0x04` stays in the registry
/// until the paper's `eq:hashinst` changes; nothing on a data path calls it.
///
/// One call yields **both** children of a node: the first λ bytes are the left
/// child's key, the second λ the right child's. That is what makes a GGM walk
/// one permutation per level rather than two.
///
/// Not framed: the input is a single fixed-width key, so there is no field
/// boundary to disambiguate.
#[must_use]
pub fn prg(seed: &Digest32) -> [u8; 2 * LAMBDA_BYTES] {
    let mut hasher = Shake::v256();
    hasher.update(&[Role::Prg.byte()]);
    hasher.update(seed);
    let mut out = [0u8; 2 * LAMBDA_BYTES];
    hasher.squeeze(&mut out);
    out
}

/// `⟪x₁,…,xₙ⟫` — draft6 eq. (3).
fn absorb_framed(hasher: &mut Shake, fields: &[&[u8]]) {
    for field in fields {
        hasher.update(&len8(field.len()));
        hasher.update(field);
    }
}

/// `len₈` — 8-byte little-endian length.
const fn len8(n: usize) -> [u8; 8] {
    (n as u64).to_le_bytes()
}

fn squeeze(mut hasher: Shake) -> Digest32 {
    let mut out = [0u8; LAMBDA_BYTES];
    hasher.squeeze(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> PrfKey {
        PrfKey::new([7u8; LAMBDA_BYTES])
    }

    /// Independent reference implementation of framing, written from draft6
    /// eq. (3) rather than by calling the code under test.
    fn framed(fields: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for f in fields {
            v.extend_from_slice(&(f.len() as u64).to_le_bytes());
            v.extend_from_slice(f);
        }
        v
    }

    // ---------------------------------------------------------------- tags

    #[test]
    fn tag_registry_matches_draft6() {
        // These bytes appear inside anchored on-chain roots. Changing one
        // invalidates every previously anchored proof.
        assert_eq!(Domain::CapsuleSeal.tag(), 0x01);
        assert_eq!(Domain::CustodyRoot.tag(), 0x02);
        assert_eq!(Domain::IndexEpoch.tag(), 0x03);
        assert_eq!(Domain::AuditEvent.tag(), 0x04);
        assert_eq!(Domain::Dispose.tag(), 0x05);
        assert_eq!(Domain::SweepAttestation.tag(), 0x06);
        assert_eq!(Domain::AgentEpochRoot.tag(), 0x07);
        assert_eq!(Domain::CustodyRecord.tag(), 0x10);
        assert_eq!(Domain::MerkleInternal.tag(), 0x11);
        assert_eq!(Domain::EvidenceDigest.tag(), 0x20);
        assert_eq!(Domain::PlaintextCommit.tag(), 0x21);
        assert_eq!(Domain::ActorCommit.tag(), 0x22);
        assert_eq!(Domain::ParamsCommit.tag(), 0x23);
        assert_eq!(Domain::ChainLink.tag(), 0x24);
        assert_eq!(Domain::CorrectionReason.tag(), 0x25);
        // Record-field block, extended by the design record.
        assert_eq!(Domain::HandoffDescriptor.tag(), 0x26);
        assert_eq!(Domain::DeviceSigPreHash.tag(), 0x27);
        assert_eq!(Domain::DeviceChainLink.tag(), 0x28);
        // Authorization block. Separate from the record-field block on purpose;
        // see the enum. `0x26`/`0x27` were this agent's first proposal for
        // WarrantCommit/Nullifier and were rejected for that reason, so these
        // two rows exist to stop the old bytes creeping back.
        assert_eq!(Domain::WarrantCommit.tag(), 0x30);
        assert_eq!(Domain::Nullifier.tag(), 0x31);
        assert_eq!(Domain::WarrantNode.tag(), 0x32);
        assert_eq!(Domain::QueryScope.tag(), 0x33);
        assert_eq!(Domain::TrapdoorDigest.tag(), 0x34);
        // draft8: checkpoints, approval sets, the result-set commitment, and
        // the two case tags proposed in the design record.
        assert_eq!(Domain::Checkpoint.tag(), 0x12);
        assert_eq!(Domain::ApprovalSet.tag(), 0x13);
        assert_eq!(Domain::CaseId.tag(), 0x14);
        assert_eq!(Domain::CaseRegistration.tag(), 0x15);
        assert_eq!(Domain::Roster.tag(), 0x16);
        assert_eq!(Domain::ResultSet.tag(), 0x35);
    }

    #[test]
    fn every_tag_is_in_a_registered_block_and_none_is_reused() {
        // draft8 eq:hashinst: tags are allocated in disjoint blocks so no
        // digest can be reinterpreted as another kind. A reused tag fails here
        // (and a duplicated discriminant fails to compile).
        let mut seen = std::collections::BTreeSet::new();
        for d in Domain::ALL {
            let t = d.tag();
            assert!(
                matches!(t, 0x01..=0x07 | 0x10..=0x16 | 0x20..=0x28 | 0x30..=0x35),
                "{d:?} = {t:#04x} is outside every registered block"
            );
            seen.insert(t);
        }
        assert_eq!(seen.len(), Domain::ALL.len(), "a tag is reused");
        // The role bytes (0x00 hash, 0x01 PRF, ...) sit in front of a tag and are
        // a separate namespace; nothing here may be mistaken for one.
    }

    #[test]
    fn role_bytes_match_draft6_eq2() {
        assert_eq!(Role::Hash.byte(), 0x00);
        assert_eq!(Role::Prf.byte(), 0x01);
        assert_eq!(Role::Addr.byte(), 0x02);
        assert_eq!(Role::CrossTag.byte(), 0x03);
        assert_eq!(Role::Prg.byte(), 0x04);
    }

    #[test]
    fn addr_hash_composition_is_role_then_tag() {
        let tag = [0x44u8; LAMBDA_BYTES];
        let mut expect = vec![0x02u8];
        expect.extend_from_slice(&tag);
        assert_eq!(addr_hash(&tag).to_vec(), shake256(&expect, LAMBDA_BYTES));
        // Distinct from H over the same input: the leaf stays secret while the
        // address is published, so they must not be the same function.
        assert_ne!(addr_hash(&tag), digest256(&tag));
    }

    #[test]
    fn cross_tag_composition_is_key_then_role_then_framed() {
        let k = key();
        let data: &[&[u8]] = &[b"add", b"keyword", b"doc"];
        let mut expect = k.as_bytes().to_vec();
        expect.push(0x03);
        expect.extend_from_slice(&framed(data));
        assert_eq!(
            cross_tag(&k, data).to_vec(),
            shake256(&expect, LAMBDA_BYTES)
        );
    }

    #[test]
    fn cross_tag_is_binding_across_field_splits() {
        // op ‖ w ‖ id must not be ambiguous: an adversary who could shift the
        // boundary between a keyword and a document id could forge membership.
        let k = key();
        assert_ne!(
            cross_tag(&k, &[b"add", b"ab", b"c"]),
            cross_tag(&k, &[b"add", b"a", b"bc"]),
        );
    }

    #[test]
    fn cross_tag_differs_from_the_plain_prf() {
        // 0x01 vs 0x03: an xtag must never coincide with a derived key.
        let k = key();
        assert_ne!(cross_tag(&k, &[b"x"]), prf(&k, Label::Addr, &[b"x"]));
    }

    #[test]
    fn prg_composition_is_role_then_seed() {
        let seed = [0x11u8; LAMBDA_BYTES];
        let mut expect = vec![0x04u8];
        expect.extend_from_slice(&seed);
        assert_eq!(prg(&seed).to_vec(), shake256(&expect, 2 * LAMBDA_BYTES));
    }

    #[test]
    fn prg_children_are_independent() {
        // If the two halves were correlated, a GGM sibling would leak.
        let out = prg(&[0x22u8; LAMBDA_BYTES]);
        assert_ne!(&out[..LAMBDA_BYTES], &out[LAMBDA_BYTES..]);
        // And a different seed gives a different pair.
        assert_ne!(prg(&[0x23u8; LAMBDA_BYTES]), out);
    }

    #[test]
    fn prg_is_not_the_hash_role() {
        // 0x04 is also the Tier-2 audit leaf tag; positions differ, so these
        // must not collide.
        let seed = [0x33u8; LAMBDA_BYTES];
        assert_ne!(&prg(&seed)[..LAMBDA_BYTES], &digest256(&seed)[..]);
    }

    #[test]
    fn label_strings_match_draft6() {
        // Transcribed from Table I. A label that drifts changes every key
        // derived under it, silently and irreversibly once anything is anchored.
        assert_eq!(Label::Case.as_bytes(), b"case");
        // The plane bytes are part of the derivation, so they are pinned
        // here with the labels rather than left to a call site.
        assert_eq!(PLANE_EVIDENCE, 0x00);
        assert_eq!(PLANE_CUSTODY, 0x01);
        let k = key();
        assert_ne!(
            index_master(&k, PLANE_EVIDENCE),
            index_master(&k, PLANE_CUSTODY),
            "the two planes must be independent DSSE instances"
        );
        assert_eq!(
            index_master(&k, PLANE_CUSTODY),
            prf(&k, Label::Index, &[&[PLANE_CUSTODY]]),
            "eq:kidx, spelled out"
        );
        assert_eq!(Label::Index.as_bytes(), b"idx");
        assert_eq!(Label::Link.as_bytes(), b"link");
        assert_eq!(Label::Note.as_bytes(), b"note");
        assert_eq!(Label::Addr.as_bytes(), b"addr");
        assert_eq!(Label::Mask.as_bytes(), b"mask");
        assert_eq!(Label::Eid.as_bytes(), b"eid");
        assert_eq!(Label::Ratchet.as_bytes(), b"rat");
    }

    // ------------------------------------------------- byte-level pinning

    #[test]
    fn hash_domain_composition_is_role_then_tag_then_framed() {
        // The exact composition of draft6 eq. (2) and eq. (3):
        //     H(tag ‖ ⟪f⟫) = SHAKE256(0x00 ‖ tag ‖ len₈(f₁)‖f₁ ‖ …)
        let fields: &[&[u8]] = &[b"actor-7", b"custodian", &[9u8; 32]];

        let mut expect = vec![0x00u8, Domain::ActorCommit.tag()];
        expect.extend_from_slice(&framed(fields));

        assert_eq!(
            hash_domain(Domain::ActorCommit, fields).to_vec(),
            shake256(&expect, LAMBDA_BYTES),
        );
    }

    #[test]
    fn swapping_role_and_tag_order_changes_the_digest() {
        // A test that merely checked both bytes were present would pass under
        // the wrong order. Pin the order itself.
        let fields: &[&[u8]] = &[b"x"];
        let mut wrong = vec![Domain::ActorCommit.tag(), 0x00u8];
        wrong.extend_from_slice(&framed(fields));

        assert_ne!(
            hash_domain(Domain::ActorCommit, fields).to_vec(),
            shake256(&wrong, LAMBDA_BYTES),
        );
    }

    #[test]
    fn prf_composition_is_key_then_role_then_framed() {
        //     F(K, ⟪label, d⟫) = SHAKE256(K ‖ 0x01 ‖ len₈(label)‖label ‖ …)
        let data: &[&[u8]] = &[b"nonce-42"];

        let mut expect = key().as_bytes().to_vec();
        expect.push(0x01);
        expect.extend_from_slice(&framed(&[Label::Eid.as_bytes()]));
        expect.extend_from_slice(&framed(data));

        assert_eq!(
            prf(&key(), Label::Eid, data).to_vec(),
            shake256(&expect, LAMBDA_BYTES),
        );
    }

    #[test]
    fn digest256_applies_the_hash_role_byte() {
        let mut expect = vec![0x00u8];
        expect.extend_from_slice(b"pq-chainlog");
        assert_eq!(
            digest256(b"pq-chainlog").to_vec(),
            shake256(&expect, LAMBDA_BYTES),
        );
        // And is therefore *not* bare SHAKE256 — the drift this replaces.
        assert_ne!(
            digest256(b"pq-chainlog").to_vec(),
            shake256(b"pq-chainlog", LAMBDA_BYTES),
        );
    }

    #[test]
    fn raw_shake256_stays_unprefixed_for_the_acvp_vectors() {
        // The KAT harness checks the bare primitive. If this ever grows a role
        // byte, every ACVP vector fails and the cause is non-obvious.
        let long = shake256(b"pq-chainlog", 64);
        assert_eq!(&long[..32], &shake256(b"pq-chainlog", 32)[..]);
    }

    // ------------------------------------------------ security properties

    #[test]
    fn actor_commitment_is_binding_across_field_splits() {
        // The defect that was found in draft6 eq. (14): with plain
        // concatenation, ("ab","c") and ("a","bc") commit identically, so a
        // committer could open actor_c to whichever role made their action look
        // authorised for the event type. Stated at the commitment level,
        // because that is the level at which the paper claims the property.
        let r_a = [3u8; LAMBDA_BYTES];
        let one = hash_domain(Domain::ActorCommit, &[b"ab", b"c", &r_a]);
        let two = hash_domain(Domain::ActorCommit, &[b"a", b"bc", &r_a]);
        assert_ne!(one, two);
    }

    #[test]
    fn params_commitment_is_binding_across_field_splits() {
        // Same property for eq. (15): ("tsk","3.2") vs ("tsk3",".2").
        let r_p = [4u8; LAMBDA_BYTES];
        assert_ne!(
            hash_domain(Domain::ParamsCommit, &[b"tsk", b"3.2", &r_p]),
            hash_domain(Domain::ParamsCommit, &[b"tsk3", b".2", &r_p]),
        );
    }

    #[test]
    fn a_leaf_of_one_type_cannot_be_presented_as_another() {
        // The M4 acceptance property, tested at the layer that implements it.
        let fields: &[&[u8]] = &[b"same", b"content"];
        assert_ne!(
            hash_domain(Domain::CustodyRoot, fields),
            hash_domain(Domain::IndexEpoch, fields),
        );
    }

    #[test]
    fn a_merkle_internal_node_cannot_be_presented_as_a_leaf() {
        // Why 0x11 exists: without distinct leaf and internal tags, a Merkle
        // tree admits second-preimage attacks.
        let payload: &[&[u8]] = &[&[1u8; 32], &[2u8; 32]];
        assert_ne!(
            hash_domain(Domain::CustodyRecord, payload),
            hash_domain(Domain::MerkleInternal, payload),
        );
    }

    #[test]
    fn labels_separate_derived_keys() {
        // K^A_w is released constrained at search; K^M_w never leaves the
        // client. If the label did not separate them, releasing the address key
        // would leak the payload key.
        assert_ne!(
            prf(&key(), Label::Addr, &[b"keyword"]),
            prf(&key(), Label::Mask, &[b"keyword"]),
        );
    }

    #[test]
    fn every_label_is_distinct() {
        let all = [
            Label::Case,
            Label::Index,
            Label::Link,
            Label::Note,
            Label::Addr,
            Label::Mask,
            Label::Eid,
            Label::Ratchet,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.as_bytes(), b.as_bytes());
                assert_ne!(prf(&key(), *a, &[b"x"]), prf(&key(), *b, &[b"x"]));
            }
        }
    }

    #[test]
    fn ratchet_is_one_way_and_advances() {
        // K_X^(e+1) = F(K_X^(e), "rat"). Preimage resistance of F is what makes
        // destroying a prefix final, which is what makes erasure real rather
        // than cosmetic. This asserts the shape; the erasure property itself is
        // M3b's, and must be tested against an adversary holding K_mst.
        let k0 = key();
        let k1 = PrfKey::new(prf(&k0, Label::Ratchet, &[]));
        let k2 = PrfKey::new(prf(&k1, Label::Ratchet, &[]));
        assert_ne!(k0.as_bytes(), k1.as_bytes());
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn prf_is_deterministic_and_key_dependent() {
        let a = prf(&key(), Label::Addr, &[b"w", b"id"]);
        assert_eq!(a, prf(&key(), Label::Addr, &[b"w", b"id"]));
        assert_ne!(
            a,
            prf(
                &PrfKey::new([8u8; LAMBDA_BYTES]),
                Label::Addr,
                &[b"w", b"id"]
            )
        );
    }

    #[test]
    fn prf_key_debug_does_not_leak() {
        assert_eq!(format!("{:?}", key()), "PrfKey(<redacted>)");
    }
}
