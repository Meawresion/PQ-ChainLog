//! The warrant: an ML-DSA-signed capability issued by the Case Authority.
//!
//! draft6 §V-D and design §7a:
//!
//! ```text
//! warrant = ML-DSA.Sign(sk_CA,
//!             { inv_id, cid_c, role, keyword_classes,
//!               plane ∈ {EV, COC}, [t₀,t₁], expiry, nonce })
//! ```
//!
//! Policy is expressed over attributes; **enforcement is a capability check**,
//! which is what keeps zero public-key operations on the search path. The
//! signature is verified once at delegation time, not per query.

use core::fmt;

#[cfg(feature = "host")]
use pqcl_primitives::sig::{SigError, Signer};
use pqcl_primitives::xof::{Digest32, digest256};

use crate::scope::Scope;

/// Identifies a warrant without revealing it. Used in the `0x04` audit leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarrantId(pub Digest32);

/// What can be wrong with a warrant.
#[derive(Debug)]
pub enum WarrantError {
    /// The Case Authority signature did not verify.
    BadSignature,
    /// The warrant expired at or before the epoch it is being used in.
    ///
    /// draft6 eq. (`eq:relauth`) requires `exp > e` — strictly greater, so a
    /// warrant expiring *at* epoch `e` is already spent by epoch `e`. Off-by-one
    /// here silently extends every warrant in the system by one epoch.
    Expired {
        /// The warrant's expiry epoch.
        expiry: u64,
        /// The epoch it was presented in.
        epoch: u64,
    },
    /// The query's scope is not covered by the warrant's.
    OutOfScope,
    /// Signing or verification failed in the backend.
    #[cfg(feature = "host")]
    Sig(SigError),
}

impl fmt::Display for WarrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSignature => f.write_str("Case Authority signature did not verify"),
            Self::Expired { expiry, epoch } => {
                write!(f, "warrant expired at epoch {expiry}, presented at {epoch}")
            }
            Self::OutOfScope => f.write_str("query scope exceeds the warrant's scope"),
            #[cfg(feature = "host")]
            Self::Sig(e) => write!(f, "signature backend: {e}"),
        }
    }
}

impl core::error::Error for WarrantError {}

#[cfg(feature = "host")]
impl From<SigError> for WarrantError {
    fn from(e: SigError) -> Self {
        Self::Sig(e)
    }
}

/// A capability issued by the Case Authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Warrant {
    /// Investigator identity commitment. Never the identity itself — the point
    /// of §7b is that the index server learns *that* a warrant is exercised,
    /// not whose.
    pub inv_id: Digest32,
    /// The case this warrant belongs to.
    pub cid_c: Digest32,
    /// The investigator's role, as a committed byte.
    pub role: u8,
    /// Plane and keyword-class range this warrant authorises.
    pub scope: Scope,
    /// Evidence-time window, inclusive.
    pub window: (u64, u64),
    /// Epoch after which the warrant is void. `exp > e` is required.
    pub expiry: u64,
    /// Issuance nonce, so two otherwise identical warrants differ.
    pub nonce: Digest32,
}

impl Warrant {
    /// The canonical framed encoding — **the bytes the Case Authority signs**,
    /// and the same bytes the warrant-tree leaf commits to.
    ///
    /// One encoding, used for both. draft6 writes
    /// `ML-DSA.Vf(pk_CA, warrant, σ_CA)` and `C = H(warrant ‖ s)`, so both take
    /// *the warrant*; producing a separate digest for one of them would create
    /// two encodings of one object, which is how they drift apart.
    ///
    /// Framed with eq. (3)'s `len₈(x) ‖ x` per field, so the encoding is
    /// injective over the variable-width fields. Every field is included: a
    /// field outside the signature is a field an insider can change.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (lo, hi) = self.scope.bounds();
        let plane = u8::from(self.scope.plane() == pqcl_sm::Plane::Custody);
        let fields: [&[u8]; 10] = [
            &self.inv_id,
            &self.cid_c,
            &[self.role],
            &[plane],
            &lo.to_le_bytes(),
            &hi.to_le_bytes(),
            &self.window.0.to_le_bytes(),
            &self.window.1.to_le_bytes(),
            &self.expiry.to_le_bytes(),
            &self.nonce,
        ];
        let mut out = Vec::new();
        for f in fields {
            out.extend_from_slice(&(f.len() as u64).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    /// This warrant's public identifier, for the `0x04` audit leaf.
    #[must_use]
    pub fn id(&self) -> WarrantId {
        WarrantId(digest256(&self.encode()))
    }

    /// The clauses of eq. (`eq:relauth`) that the **circuit** checks: scope
    /// containment and expiry.
    ///
    /// Separated from [`Self::authorizes`] because draft6 discharges the single
    /// ML-DSA clause *"by the CA at issuance rather than inside the circuit,
    /// leaving a statement over hashes alone"*. This is that split made
    /// structural: the guest calls this, the host calls `authorizes`, and
    /// neither can drift from the other because the scope logic has one home.
    ///
    /// # Errors
    ///
    /// [`WarrantError::Expired`] or [`WarrantError::OutOfScope`].
    pub fn check_scope_and_expiry(&self, query: &Scope, epoch: u64) -> Result<(), WarrantError> {
        if self.expiry <= epoch {
            return Err(WarrantError::Expired {
                expiry: self.expiry,
                epoch,
            });
        }
        if !self.scope.covers(query) {
            return Err(WarrantError::OutOfScope);
        }
        Ok(())
    }

    /// Sign as the Case Authority.
    ///
    /// # Errors
    ///
    /// [`WarrantError::Sig`] if the backend fails.
    #[cfg(feature = "host")]
    pub fn sign<S: Signer>(&self, ca: &S) -> Result<Vec<u8>, WarrantError> {
        Ok(ca.sign(&self.encode())?)
    }

    /// Verify the Case Authority signature.
    ///
    /// # Errors
    ///
    /// [`WarrantError::BadSignature`] if it does not verify.
    #[cfg(feature = "host")]
    pub fn verify(&self, ca_public_key: &[u8], signature: &[u8]) -> Result<(), WarrantError> {
        pqcl_primitives::sig::verify(&self.encode(), signature, ca_public_key, b"")
            .map_err(|_| WarrantError::BadSignature)
    }

    /// The full authorization check of draft6 eq. (`eq:relauth`), minus the
    /// Merkle and nullifier clauses which live in [`crate::tree`] and
    /// [`crate::nullifier`].
    ///
    /// # Errors
    ///
    /// [`WarrantError::BadSignature`], [`WarrantError::Expired`] or
    /// [`WarrantError::OutOfScope`], checked in that order — a forged warrant
    /// should not be able to learn *why* it failed from a scope message.
    #[cfg(feature = "host")]
    pub fn authorizes(
        &self,
        ca_public_key: &[u8],
        signature: &[u8],
        query: &Scope,
        epoch: u64,
    ) -> Result<(), WarrantError> {
        self.verify(ca_public_key, signature)?;
        self.check_scope_and_expiry(query, epoch)
    }
}
