//! Query scope, as a range rather than a predicate.
//!
//! # Why a range and not a set of strings
//!
//! draft6 §V-D requires that an out-of-scope probe be *underivable*, not
//! refused. That is only achievable if the scope is expressible as a
//! **constraint on key material**, and the constrained-PRF machinery we already
//! have (`pqcl-ggm`, Diana) constrains over *contiguous integer ranges*.
//!
//! So keyword classes are numbered, and a scope is a range over that numbering
//! plus a plane. A warrant is then delegated as a `ConstrainedKey` over exactly
//! that range, and the "check" is that `eval` outside it returns `Err` — a
//! property of the key, not of a caller's diligence.
//!
//! The cost is real and should be stated rather than hidden: **scopes must be
//! expressible as ranges**, so the class numbering has to put classes that are
//! granted together next to each other. That is a deployment concern (which
//! classes a jurisdiction bundles), not a cryptographic one, and it is the same
//! constraint `Π_RANGE` already lives with.

use core::fmt;

use pqcl_sm::Plane;

/// A keyword class, as an index into the case's class numbering.
///
/// Not the keyword itself. A class is a *category* of keyword — "network
/// endpoints", "financial identifiers" — because warrants are written over
/// categories, and because per-keyword grants would make the GGM range
/// degenerate to singletons and the constraint pointless.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct KeywordClass(pub u64);

/// What can be wrong with a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    /// `lo > hi`. An empty range is a programming error, not a null grant: a
    /// warrant that authorises nothing should not have been issued.
    Inverted {
        /// Lower bound supplied.
        lo: u64,
        /// Upper bound supplied.
        hi: u64,
    },
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inverted { lo, hi } => {
                write!(f, "inverted scope range: lo={lo} > hi={hi}")
            }
        }
    }
}

impl core::error::Error for ScopeError {}

/// A half-open authority: a plane, and a contiguous range of keyword classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Scope {
    plane: Plane,
    lo: u64,
    hi: u64,
}

impl Scope {
    /// Build a scope over `[lo, hi]` inclusive.
    ///
    /// # Errors
    ///
    /// [`ScopeError::Inverted`] if `lo > hi`.
    pub const fn new(plane: Plane, lo: u64, hi: u64) -> Result<Self, ScopeError> {
        if lo > hi {
            return Err(ScopeError::Inverted { lo, hi });
        }
        Ok(Self { plane, lo, hi })
    }

    /// A scope over exactly one class — what a single-keyword query has.
    #[must_use]
    pub const fn single(plane: Plane, class: KeywordClass) -> Self {
        Self {
            plane,
            lo: class.0,
            hi: class.0,
        }
    }

    /// The plane this authority covers.
    #[must_use]
    pub const fn plane(&self) -> Plane {
        self.plane
    }

    /// Inclusive bounds of the class range.
    #[must_use]
    pub const fn bounds(&self) -> (u64, u64) {
        (self.lo, self.hi)
    }

    /// Whether `self` covers all of `other` — draft6's
    /// `scope(q) ⊆ scope(warrant)`.
    ///
    /// ⚠️ **The plane comparison is equality, never a subset over a lattice.**
    /// draft6 is explicit that `COC` is *"a separate and higher-privileged
    /// grant, default deny"*, so an `EV` warrant must not cover a `COC` query
    /// and — this is the part that is easy to get backwards — a `COC` warrant
    /// must not silently cover an `EV` query either. They are different
    /// authorities, not ranks.
    #[must_use]
    pub const fn covers(&self, other: &Self) -> bool {
        matches!(
            (self.plane, other.plane),
            (Plane::Evidence, Plane::Evidence) | (Plane::Custody, Plane::Custody)
        ) && self.lo <= other.lo
            && other.hi <= self.hi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_covers_itself_and_its_subranges() {
        let w = Scope::new(Plane::Evidence, 10, 20).expect("valid");
        assert!(w.covers(&w));
        assert!(w.covers(&Scope::new(Plane::Evidence, 12, 15).expect("valid")));
        assert!(w.covers(&Scope::single(Plane::Evidence, KeywordClass(10))));
        assert!(w.covers(&Scope::single(Plane::Evidence, KeywordClass(20))));
    }

    #[test]
    fn a_scope_does_not_cover_anything_straddling_its_bounds() {
        let w = Scope::new(Plane::Evidence, 10, 20).expect("valid");
        assert!(!w.covers(&Scope::new(Plane::Evidence, 9, 15).expect("valid")));
        assert!(!w.covers(&Scope::new(Plane::Evidence, 15, 21).expect("valid")));
        assert!(!w.covers(&Scope::new(Plane::Evidence, 0, 100).expect("valid")));
    }

    /// ⭐ M6 acceptance: a plane-`EV` warrant cannot reach the custody plane.
    #[test]
    fn an_evidence_warrant_never_covers_a_custody_query() {
        let ev = Scope::new(Plane::Evidence, 0, u64::MAX).expect("valid");
        let coc = Scope::single(Plane::Custody, KeywordClass(1));
        assert!(
            !ev.covers(&coc),
            "an evidence warrant covering every class must still not reach the \
             custody plane — draft6 makes COC a separate grant, default deny"
        );
    }

    /// The direction people forget. `COC` is higher-privileged, so the tempting
    /// reading is that it subsumes `EV`. It does not: they are different
    /// authorities, and a custody warrant is not an evidence warrant.
    #[test]
    fn a_custody_warrant_never_covers_an_evidence_query_either() {
        let coc = Scope::new(Plane::Custody, 0, u64::MAX).expect("valid");
        let ev = Scope::single(Plane::Evidence, KeywordClass(1));
        assert!(!coc.covers(&ev));
    }

    #[test]
    fn an_inverted_range_is_rejected_at_construction() {
        assert_eq!(
            Scope::new(Plane::Evidence, 20, 10),
            Err(ScopeError::Inverted { lo: 20, hi: 10 })
        );
    }
}
