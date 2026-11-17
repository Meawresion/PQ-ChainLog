//! The two role-scoped Secure Module traits.
//!
//! # Why two traits and not one
//!
//! The design record's Secure Module standing rule. The agent-side module
//! and the investigator-side module are **different deployments holding
//! different secrets**: the agent holds `K_mst` and signs `σ_DEFR`; the
//! investigator holds a *warrant* and must never be able to derive `K_case`.
//!
//! A single trait carrying both `sign_defr` and `derive_trapdoor` would mean
//! any holder of a `dyn SecureModule` could do both — and the type system would
//! stop helping at exactly the point where the access-control story lives. The
//! separation costs nothing to write now and is expensive to retrofit, which is
//! why it is here before either implementation exists.
//!
//! # ⛔ Never implement either of these for a PKCS#11 type
//!
//! Not even returning [`SmError::Unsupported`]. A compiler error is strictly
//! stronger than a runtime one, and it is what stops the shared [`KeyCustody`]
//! suite decaying into a suite of skips. `SmError::Unsupported` remains the
//! backstop for capability gaps *within* [`KeyCustody`] — it is not the
//! mechanism for the role split.
//!
//! The reason a token cannot host these is **not** its mechanism list. Refusing
//! a trapdoor whose scope exceeds the warrant, and releasing only a result set,
//! need **arbitrary code inside the boundary**. That is what a TEE is and what
//! a PKCS#11 token is not, whatever algorithms its firmware ships.

#[cfg(feature = "roles")]
use pqcl_chainproof::Authorisation;
#[cfg(feature = "roles")]
use pqcl_primitives::Digest32;

#[cfg(feature = "roles")]
use crate::custody::{KeyCustody, SmError};

/// Which DSSE instance a key or trapdoor belongs to.
///
/// The two planes are separately keyed and separately scoped: authority over
/// the custody log is granted independently of authority over the evidence.
/// A warrant carries this field, which is why it appears in the trapdoor
/// derivation signature rather than being implied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Plane {
    /// The evidence plane — the artefacts under investigation.
    Evidence,
    /// The custody plane — who did what to them.
    Custody,
}

impl Plane {
    /// The byte this plane contributes to `K_S^plane = F(K_case, "idx" ‖ plane)`.
    ///
    /// Defers to [`pqcl_primitives::xof`]'s constants rather than writing `0`
    /// and `1` here, because the encoding had two answers in this tree once
    /// already — see [`pqcl_primitives::xof::index_master`].
    #[must_use]
    pub const fn index_byte(self) -> u8 {
        match self {
            Self::Evidence => pqcl_primitives::xof::PLANE_EVIDENCE,
            Self::Custody => pqcl_primitives::xof::PLANE_CUSTODY,
        }
    }
}

/// The agent-side Secure Module: holds `K_mst`, seals and signs at acquisition.
///
/// This is the module co-located with the Edge Log Agent. It is the only thing
/// in the system that ever holds the case master key.
///
/// ⚠️ **No method here returns a key.** Every one returns a *derived output* —
/// a pseudonym, a signature. Adding a `fn case_key(&self) -> PrfKey` would
/// defeat the entire boundary in one line, and it is the obvious-looking
/// convenience to refuse.
#[cfg(feature = "roles")]
pub trait AgentModule: KeyCustody {
    /// `eid = F(K_case, ⟪"eid", nonce⟫)` — the pseudonymous capsule identifier.
    ///
    /// Derived inside the boundary from a `K_case` the caller never sees.
    ///
    /// # Errors
    ///
    /// [`SmError`] if the module cannot derive it.
    fn capsule_pseudonym(
        &self,
        case_commitment: &Digest32,
        nonce: &[u8],
    ) -> Result<Digest32, SmError>;

    /// Sign the sealed capsule fields as the ISO/IEC 27037 Digital Evidence
    /// First Responder, producing `σ_DEFR`.
    ///
    /// ⚠️ **The message must be the design's, not draft6's.**
    /// `PQ-ChainLog-DESIGN.md` §2 covers `prov` and `Δ_gap`; `draft6.tex`
    /// eq. (24) does not, because the paper has no provenance modes yet
    /// (task #30). Signing draft6's shorter message would leave the provenance
    /// mode unpinned, and because `σ_DEFR` is itself hashed into the `0x01`
    /// leaf, that is unfixable once a real anchor exists.
    ///
    /// # Errors
    ///
    /// [`SmError`] if signing fails.
    fn sign_defr(&self, message: &[u8]) -> Result<Vec<u8>, SmError>;

    /// The DEFR verification key, 1952 bytes for ML-DSA-65.
    ///
    /// # Errors
    ///
    /// [`SmError`] if the module cannot produce it.
    fn defr_public_key(&self) -> Result<Vec<u8>, SmError>;
}

/// The investigator-side Secure Module: holds a warrant, derives scoped
/// trapdoors, and releases only results.
///
/// ⚠️ **The defining property is negative.** There is deliberately no method
/// that yields `K_case`, and none may be added. An investigator module that can
/// derive the case key can derive every trapdoor in the case, which makes the
/// warrant decorative — the scope check would be a policy the holder could
/// simply route around.
///
/// The `Warrant` is an associated type because warrants arrive with **M6**
/// (`pqcl-warrant`, SP1 proof-of-warrant). Naming it abstractly lets the role
/// separation exist now, as the standing rule requires, without inventing M6's
/// data model in advance — and without an implementation, since guessing at
/// one would be exactly the speculative scaffolding ground rule #1 forbids.
#[cfg(feature = "roles")]
pub trait InvestigatorModule: KeyCustody {
    /// The warrant type, supplied by M6.
    type Warrant;

    /// Derive a search trapdoor for `keyword` on `plane`, **only if the warrant
    /// authorises it and the chain has recorded the request**.
    ///
    /// The scope check happens inside the boundary. That is the whole reason
    /// this cannot be a PKCS#11 operation: no mechanism expresses "refuse if
    /// this keyword falls outside the warrant".
    ///
    /// ⭐ **`auth` is the on-chain precondition of design §7b′**, and it is a
    /// parameter rather than a check because of what its type is. An
    /// [`Authorisation`] cannot be constructed except by
    /// `pqcl_chainproof::verify_search_authorised` succeeding against a real
    /// inclusion proof, so *"the SM derives a trapdoor only on a valid
    /// inclusion proof of that event"* is enforced by the signature. An
    /// implementation cannot forget the check; there is nothing to forget.
    ///
    /// The property this buys is §7b′'s: **a search cannot occur without a
    /// prior public record of the request.** An insider with module access can
    /// no longer search and hope nobody reconciles the audit leaves, because
    /// the registry entry must exist, and be provable, first.
    ///
    /// ⚠️ **The caller still owes the scope binding.** This trait sees an
    /// authorisation and a warrant; that the authorisation's `scope_commit`
    /// describes *this* warrant's scope is checked by the AIS
    /// (`warrant_host::verify_authorised`), because it is the party that holds
    /// `pi_auth`. Recorded here so the division is explicit rather than assumed
    /// by both sides.
    ///
    /// # Errors
    ///
    /// [`SmError`] if the warrant does not cover `(plane, keyword)`, or if
    /// derivation fails.
    fn derive_trapdoor(
        &self,
        warrant: &Self::Warrant,
        auth: &Authorisation,
        plane: Plane,
        keyword: &[u8],
    ) -> Result<Digest32, SmError>;
}
