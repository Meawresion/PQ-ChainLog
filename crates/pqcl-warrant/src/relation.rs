//! `R_auth` — the authorization relation, in one place.
//!
//! draft6 eq. (`eq:relauth`). This module is deliberately the **only**
//! implementation: the SP1 guest calls [`check`] and so does the host verifier,
//! because draft6 is explicit that the rule *"must hold identically in the
//! circuit and in the verifier; a divergence there is silent."*
//!
//! A guest that reimplemented this would still produce proofs. They would
//! verify — against the wrong statement.
//!
//! ```text
//! x = (ρ_W, N, e, H(scope(q)))                    public
//! ω = (warrant, s, π, σ_CA)                       private
//! ```
//!
//! # Why `σ_CA` is not checked here
//!
//! It is not in the circuit at all. draft6: *"the single signature check can be
//! discharged by the `CA` at issuance rather than inside the circuit, leaving a
//! statement over hashes alone."* Soundness survives because `C` is a leaf of
//! the **anchored** tree and only the Case Authority inserts leaves — membership
//! is what vouches for the warrant, and the signature is the CA's own record.
//!
//! That is what makes this a hash-only statement, which is what lets a
//! hash-based proof system discharge it with no algebraic assumption — the
//! "nothing Shor breaks" property, across the whole system rather than the
//! search path alone.

use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

use crate::nullifier::Nullifier;
use crate::scope::Scope;
use crate::tree::{self, WarrantPath};
use crate::warrant::Warrant;

/// The public statement `x`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Statement {
    /// `ρ_W` — the anchored warrant-tree root.
    pub warrant_root: Digest32,
    /// `N` — the nullifier being spent.
    pub nullifier: Nullifier,
    /// `e` — the current epoch.
    pub epoch: u64,
    /// `H(scope(q))` — the query scope, committed rather than revealed.
    pub scope_digest: Digest32,
}

/// The private witness `ω`, minus `σ_CA`, which the circuit does not see.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Witness {
    /// The warrant itself.
    pub warrant: Warrant,
    /// `s` — the λ-bit warrant secret.
    pub secret: Digest32,
    /// `π` — the Merkle path from `C` to `ρ_W`.
    pub path: WarrantPath,
    /// The query scope, opened. Only its digest appears in the statement.
    pub query: Scope,
}

/// Which clause of `R_auth` failed.
///
/// Distinguished because a test that accepts any failure would pass while
/// checking the wrong thing — the same reasoning as `SmError::ExtractionRefused`
/// being its own variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationError {
    /// `Path(C, π) ≠ ρ_W` — the warrant is not in the anchored tree.
    NotInTree,
    /// `N ≠ H(0x31 ‖ ⟪s, e⟫)` — the nullifier is not the one this secret and
    /// epoch produce.
    WrongNullifier,
    /// `H(scope(q))` in the statement does not open to the witness's query.
    ScopeDigestMismatch,
    /// `exp ≤ e`.
    Expired,
    /// `scope(q) ⊄ scope(warrant)`.
    OutOfScope,
}

impl core::fmt::Display for RelationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotInTree => "warrant commitment is not in the anchored tree",
            Self::WrongNullifier => "nullifier does not match the secret and epoch",
            Self::ScopeDigestMismatch => "scope digest does not open to the witness query",
            Self::Expired => "warrant has expired",
            Self::OutOfScope => "query scope exceeds the warrant scope",
        })
    }
}

impl core::error::Error for RelationError {}

/// `H(0x33 ‖ ⟪plane, lo, hi⟫)` — the committed query scope.
///
/// Tagged and framed like everything else. The statement carries this rather
/// than the scope itself, which is what keeps the queried keyword classes out
/// of the public transcript.
#[must_use]
pub fn scope_digest(scope: &Scope) -> Digest32 {
    let (lo, hi) = scope.bounds();
    let plane = u8::from(scope.plane() == pqcl_sm::Plane::Custody);
    hash_domain(
        Domain::QueryScope,
        &[&[plane], &lo.to_le_bytes(), &hi.to_le_bytes()],
    )
}

/// `R_auth(x, ω) = 1`?
///
/// # Errors
///
/// The specific [`RelationError`] clause that failed.
pub fn check(x: &Statement, w: &Witness) -> Result<(), RelationError> {
    // C = H(0x30 ‖ ⟪warrant, s⟫), then Path(C, π) = ρ_W.
    //
    // The warrant is encoded once, here, and both hashed and read for scope
    // below — so the scope that is checked is provably the scope that is
    // committed. Encoding twice is how those two come apart.
    let commitment = tree::leaf(&w.warrant.encode(), &w.secret);
    if !tree::verify(commitment, &w.path, &x.warrant_root) {
        return Err(RelationError::NotInTree);
    }

    // N = H(0x31 ‖ ⟪s, e⟫), at the statement's epoch, not the witness's choice.
    if Nullifier::new(&w.secret, x.epoch) != x.nullifier {
        return Err(RelationError::WrongNullifier);
    }

    // The statement commits H(scope(q)); the witness must open to it. Without
    // this the prover could prove containment of one scope and query another.
    if scope_digest(&w.query) != x.scope_digest {
        return Err(RelationError::ScopeDigestMismatch);
    }

    // exp > e and scope(q) ⊆ scope(warrant).
    w.warrant
        .check_scope_and_expiry(&w.query, x.epoch)
        .map_err(|e| match e {
            crate::warrant::WarrantError::Expired { .. } => RelationError::Expired,
            _ => RelationError::OutOfScope,
        })
}
