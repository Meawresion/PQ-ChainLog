//! One-time nullifiers — `N = H(0x31 ‖ ⟪s, e⟫)`.
//!
//! draft6 eq. (`eq:nullifier`). `N` is unlinkable to the warrant commitment
//! `C = H(0x30 ‖ ⟪warrant, s⟫)` without the secret `s`, but **repeats
//! detectably** if the same warrant is spent twice in one epoch. That is what
//! makes anonymity compatible with accountability: the index server cannot tell
//! whose warrant is being exercised, and still cannot be made to serve the same
//! spend twice.
//!
//! # ⚠️ This ledger is local, and at M7 it stops being the enforcement point
//!
//! Design §7b′ inverts the ordering: the contract verifies the proof, rejects a
//! spent `N`, and emits `SearchAuthorised`; the Secure Module derives a trapdoor
//! **only** against an inclusion proof of that event. So double-spend becomes
//! consensus-enforced rather than local to one server.
//!
//! [`NullifierLedger`] is therefore the *local* half — correct, testable now,
//! and deliberately not the whole story. It is not a stand-in for the contract:
//! it is the data structure the contract's own check is over, and M7 replaces
//! the trust in it, not the logic.

use core::fmt;
use std::collections::BTreeSet;

use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

/// A spend token for one (warrant, epoch) pair.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Nullifier(pub Digest32);

impl Nullifier {
    /// `N = H(0x31 ‖ ⟪s, e⟫)`.
    ///
    /// `s` is the λ-bit warrant secret; `e` the query epoch. Because `e` is
    /// bound, the same warrant yields a *different* `N` next epoch — which is
    /// the point: warrants are reusable across epochs and single-use within
    /// one.
    #[must_use]
    pub fn new(secret: &Digest32, epoch: u64) -> Self {
        Self(hash_domain(
            Domain::Nullifier,
            &[secret, &epoch.to_le_bytes()],
        ))
    }
}

/// What can be wrong with a spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendError {
    /// This nullifier has already been spent.
    DoubleSpend,
}

impl fmt::Display for SpendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoubleSpend => f.write_str("nullifier already spent in this epoch"),
        }
    }
}

impl core::error::Error for SpendError {}

/// The set of nullifiers already seen.
#[derive(Debug, Default)]
pub struct NullifierLedger {
    spent: BTreeSet<Nullifier>,
}

impl NullifierLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a spend.
    ///
    /// # Errors
    ///
    /// [`SpendError::DoubleSpend`] if `n` was already spent. The ledger is
    /// **not** modified on failure, so a rejected replay cannot perturb the
    /// state a later honest spend depends on.
    pub fn spend(&mut self, n: Nullifier) -> Result<(), SpendError> {
        if self.spent.insert(n) {
            Ok(())
        } else {
            Err(SpendError::DoubleSpend)
        }
    }

    /// Whether `n` has been spent.
    #[must_use]
    pub fn is_spent(&self, n: &Nullifier) -> bool {
        self.spent.contains(n)
    }

    /// How many spends are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// Whether nothing has been spent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(fill: u8) -> Digest32 {
        [fill; 32]
    }

    /// ⭐ M6 acceptance: a replayed nullifier is rejected.
    #[test]
    fn the_same_nullifier_cannot_be_spent_twice() {
        let mut ledger = NullifierLedger::new();
        let n = Nullifier::new(&secret(1), 7);
        assert_eq!(ledger.spend(n), Ok(()));
        assert_eq!(ledger.spend(n), Err(SpendError::DoubleSpend));
        assert_eq!(
            ledger.len(),
            1,
            "a rejected replay must not grow the ledger"
        );
    }

    #[test]
    fn the_same_warrant_yields_a_different_nullifier_each_epoch() {
        let s = secret(1);
        let (a, b) = (Nullifier::new(&s, 7), Nullifier::new(&s, 8));
        assert_ne!(
            a, b,
            "binding the epoch is what makes a warrant reusable across epochs \
             while single-use within one"
        );

        let mut ledger = NullifierLedger::new();
        assert_eq!(ledger.spend(a), Ok(()));
        assert_eq!(
            ledger.spend(b),
            Ok(()),
            "spending in a later epoch must not be blocked by an earlier spend"
        );
    }

    #[test]
    fn different_warrants_yield_different_nullifiers_in_one_epoch() {
        assert_ne!(Nullifier::new(&secret(1), 7), Nullifier::new(&secret(2), 7));
    }

    /// The nullifier must not leak the secret it is derived from. This is a
    /// sanity check on domain separation rather than a security proof: if `N`
    /// ever equalled a bare hash of `s`, anyone holding a candidate `s` could
    /// confirm it without the epoch.
    #[test]
    fn a_nullifier_is_not_a_bare_hash_of_the_secret() {
        let s = secret(3);
        assert_ne!(Nullifier::new(&s, 0).0, pqcl_primitives::xof::digest256(&s));
    }
}
