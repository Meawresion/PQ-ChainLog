//! Delegating a warrant as key material, so scope is enforced by derivation.
//!
//! This module is the reason the rest of the crate exists in the shape it does.
//! draft6 §V-D: authority is enforced by key derivation, so an out-of-scope
//! probe *"is not refused, it is **underivable**, because the trapdoor never
//! contained the key that would produce it."*
//!
//! # The two designs that look identical from outside
//!
//! ```text
//! policy-enforced        SM holds the plane root.
//!                        On each query: check scope, then derive.
//!                        Compromise the checker and you have everything.
//!
//! derivation-enforced    SM holds a ConstrainedKey covering the warrant's
//!   ← what we do         class range and nothing else.
//!                        An out-of-scope class has no key. There is no
//!                        check to bypass, because there is no check.
//! ```
//!
//! Both "refuse out-of-scope queries". Only the second still holds when the
//! process doing the refusing is the one that has been compromised — which is
//! precisely the adversary a custody system exists to constrain (`A4`,
//! malicious or coerced insider).
//!
//! # What this costs, stated rather than hidden
//!
//! The GGM cover is at most `2ℓ` nodes, so a delegation is `O(log)` in the
//! class space and independent of how many classes the warrant covers. But the
//! scope **must be a contiguous range** — see [`crate::scope`]. A warrant
//! granting two disjoint class bands needs two delegations, and the class
//! numbering has to be chosen so that classes granted together sit together.

use pqcl_ggm::{ConstrainedKey, GgmError, MasterKey};
use pqcl_primitives::xof::{Digest32, PrfKey, index_master};
use pqcl_sm::Plane;

use crate::scope::{KeywordClass, Scope};
use crate::warrant::Warrant;

/// The per-plane GGM root, from which class keys descend.
///
/// One root per `(case, plane)`. Separate roots are what make a `plane` grant
/// meaningful at the key level rather than only in the warrant's fields: an
/// evidence delegation is a cover in the evidence tree and carries no material
/// from the custody tree at all.
pub struct PlaneRoot {
    root: MasterKey,
    plane: Plane,
}

impl PlaneRoot {
    /// `K_S^plane = F(K_case, ⟪"idx", plane⟫)` — draft6 eq. (`eq:kidx`).
    ///
    /// ⚠️ **This is the existing key hierarchy, not a new derivation.** The
    /// first version of this function hashed `K_S` and a plane byte under a
    /// commitment tag, inventing a step the paper already specifies. Two
    /// derivations for one key is how the code and the paper end up computing
    /// different trapdoors while both look correct in isolation.
    ///
    /// ⭐ **And it happened anyway** (found at M13 A18). This function's 0/1
    /// plane byte and the demo's `b"custody"` were both live, which is two
    /// keys for one `K_S^COC`. Both now call
    /// [`pqcl_primitives::xof::index_master`], which owns the encoding.
    ///
    /// `K_S^EV` and `K_S^COC` are separate keys by construction, which is what
    /// makes a `plane` grant meaningful at the key level rather than only in
    /// the warrant's fields: an evidence delegation is a cover in the evidence
    /// tree and carries no material from the custody tree at all.
    #[must_use]
    pub fn derive(case_key: &PrfKey, plane: Plane) -> Self {
        Self {
            root: MasterKey::new(index_master(case_key, plane.index_byte())),
            plane,
        }
    }

    /// Which plane this root serves.
    #[must_use]
    pub const fn plane(&self) -> Plane {
        self.plane
    }

    /// Delegate exactly the authority `warrant` grants, as key material.
    ///
    /// # Errors
    ///
    /// [`DelegationError::WrongPlane`] if the warrant is for the other plane —
    /// checked here because handing back a cover from the wrong tree would
    /// produce keys that silently never match anything, which is far harder to
    /// diagnose than a refusal.
    ///
    /// [`DelegationError::Ggm`] if the range is empty.
    pub fn delegate(&self, warrant: &Warrant) -> Result<Delegation, DelegationError> {
        if warrant.scope.plane() != self.plane {
            return Err(DelegationError::WrongPlane {
                warrant: warrant.scope.plane(),
                root: self.plane,
            });
        }
        let (lo, hi) = warrant.scope.bounds();
        Ok(Delegation {
            key: self.root.constrain(lo, hi)?,
            scope: warrant.scope,
        })
    }
}

impl core::fmt::Debug for PlaneRoot {
    /// Never prints key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PlaneRoot({:?}, <redacted>)", self.plane)
    }
}

/// What can go wrong delegating.
#[derive(Debug)]
pub enum DelegationError {
    /// The warrant's plane does not match the root's.
    WrongPlane {
        /// Plane the warrant grants.
        warrant: Plane,
        /// Plane this root serves.
        root: Plane,
    },
    /// The GGM layer refused the range.
    Ggm(GgmError),
}

impl From<GgmError> for DelegationError {
    fn from(e: GgmError) -> Self {
        Self::Ggm(e)
    }
}

impl core::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongPlane { warrant, root } => write!(
                f,
                "warrant grants {warrant:?} but this root serves {root:?}"
            ),
            Self::Ggm(e) => write!(f, "GGM: {e}"),
        }
    }
}

impl core::error::Error for DelegationError {}

/// A warrant reduced to the key material it authorises, and nothing more.
#[derive(Debug)]
pub struct Delegation {
    key: ConstrainedKey,
    scope: Scope,
}

impl Delegation {
    /// The trapdoor key for one keyword class.
    ///
    /// # Errors
    ///
    /// [`GgmError::OutOfRange`] for a class outside the delegated range. ⭐ This
    /// is the M6 acceptance property, and note *where* it comes from: the error
    /// is raised by `pqcl-ggm` because the key genuinely does not cover the
    /// index. It is not a scope check in this function — there is no scope check
    /// in this function, deliberately.
    pub fn trapdoor(&self, class: KeywordClass) -> Result<Digest32, GgmError> {
        self.key.eval(class.0)
    }

    /// The scope this delegation covers.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        self.scope
    }

    /// Wire size of the delegated key, in bytes — at most `2ℓ` nodes.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.key.wire_bytes()
    }
}
