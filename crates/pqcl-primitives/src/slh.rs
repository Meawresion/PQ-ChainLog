//! SLH-DSA-SHAKE-192s (FIPS 205) — the epoch co-signature.
//!
//! # Why this primitive exists at all
//!
//! Algorithm diversity. ML-DSA-65 carries every signature on the hot path; this
//! is the hash-based fallback if lattice assumptions weaken. It is produced
//! **once per epoch** (Δ = 1 hour), never per event, so its cost is amortised
//! across everything anchored in that epoch.
//!
//! # Parameter set
//!
//! `SLH-DSA-SHAKE-192s`, signature **16 224 bytes** — settled in
//! The design record:
//!
//! * **Level III** matches ML-KEM-768 and ML-DSA-65. A level-I hedge would make
//!   the diversity primitive the weakest thing in the system, inverting its
//!   purpose; a level-V one guards nothing extra.
//! * **`s` not `f`** because signing happens once an hour, so slow signing is
//!   free, while small signatures and fast verification are not — the auditor
//!   verifies these and they are anchored on-chain.
//! * **SHAKE not SHA-2** because SHAKE256 is already the system XOF, so this
//!   adds no second hash family to the trust base.
//!
//! `PQ-ChainLog-DESIGN.md` §8 previously implied ~41 KB, which matched no set we
//! would sensibly pick; that has been corrected to 16 224 B.
//!
//! # Backend choice, decided by evidence
//!
//! liboqs exposes SPHINCS+, which is **not** FIPS 205 — the trap
//! The project rules calls the most likely silent spec mismatch in
//! the project. So this uses a dedicated FIPS-205 crate, chosen by running both
//! candidates against the official ACVP vectors rather than by reputation.
//! **Both passed identically** (10 keyGen, 7 deterministic sigGen, 14 sigVer);
//! see `tests/slh_dsa_bakeoff.rs` for the experiment and the tie-break.

use fips205::slh_dsa_shake_192s as p;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};

/// Public key length, FIPS 205 Table 2 (`n = 24`).
pub const PUBLIC_KEY_BYTES: usize = p::PK_LEN;
/// Private key length.
pub const SECRET_KEY_BYTES: usize = p::SK_LEN;
/// Signature length. The number `PQ-ChainLog-DESIGN.md` §8 depends on.
pub const SIGNATURE_BYTES: usize = p::SIG_LEN;
/// Seed length for derandomised key generation, `n` bytes each for
/// `sk_seed`, `sk_prf` and `pk_seed`.
pub const SEED_BYTES: usize = 24;

/// Co-signature failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlhError {
    /// The signature did not verify under this key and message.
    Verification,
    /// An input had the wrong length for SLH-DSA-SHAKE-192s.
    Malformed {
        /// What was being parsed.
        what: &'static str,
        /// Length required by FIPS 205.
        expected: usize,
        /// Length actually supplied.
        got: usize,
    },
    /// The backend refused the operation.
    Backend(&'static str),
}

impl core::fmt::Display for SlhError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Verification => f.write_str("SLH-DSA signature verification failed"),
            Self::Malformed {
                what,
                expected,
                got,
            } => write!(f, "malformed {what}: expected {expected} bytes, got {got}"),
            Self::Backend(m) => write!(f, "SLH-DSA backend error: {m}"),
        }
    }
}

impl core::error::Error for SlhError {}

fn sized<const N: usize>(what: &'static str, buf: &[u8]) -> Result<[u8; N], SlhError> {
    buf.try_into().map_err(|_| SlhError::Malformed {
        what,
        expected: N,
        got: buf.len(),
    })
}

/// An SLH-DSA-SHAKE-192s keypair held in process.
///
/// The epoch co-signing key belongs in the Secure Module at M5 exactly as the
/// ML-DSA key does; this is the local-iteration form.
pub struct CoSigner {
    public: [u8; PUBLIC_KEY_BYTES],
    secret: p::PrivateKey,
}

impl CoSigner {
    /// Generate a keypair from the OS RNG.
    ///
    /// # Errors
    ///
    /// [`SlhError::Backend`] if key generation fails.
    pub fn generate() -> Result<Self, SlhError> {
        let (pk, sk) = p::try_keygen().map_err(SlhError::Backend)?;
        Ok(Self {
            public: pk.into_bytes(),
            secret: sk,
        })
    }

    /// Generate deterministically from the three FIPS 205 seeds.
    ///
    /// Present so the ACVP `keyGen` vectors check exactly the code we ship.
    ///
    /// # Errors
    ///
    /// [`SlhError::Malformed`] if any seed is not [`SEED_BYTES`] long.
    pub fn from_seeds(sk_seed: &[u8], sk_prf: &[u8], pk_seed: &[u8]) -> Result<Self, SlhError> {
        let (pk, sk) = p::KG::keygen_with_seeds(
            &sized::<SEED_BYTES>("sk_seed", sk_seed)?,
            &sized::<SEED_BYTES>("sk_prf", sk_prf)?,
            &sized::<SEED_BYTES>("pk_seed", pk_seed)?,
        );
        Ok(Self {
            public: pk.into_bytes(),
            secret: sk,
        })
    }

    /// The verification key, 48 bytes.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public
    }

    /// Co-sign an epoch root.
    ///
    /// `hedged` selects FIPS 205 randomised signing; `false` is the
    /// deterministic path the ACVP vectors pin. Prefer hedged in deployment —
    /// determinism is a testing property, not a security goal.
    ///
    /// # Errors
    ///
    /// [`SlhError::Backend`] if signing fails.
    pub fn sign(&self, message: &[u8], context: &[u8], hedged: bool) -> Result<Vec<u8>, SlhError> {
        self.secret
            .try_sign(message, context, hedged)
            .map(|s| s.to_vec())
            .map_err(SlhError::Backend)
    }
}

impl core::fmt::Debug for CoSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CoSigner { secret: <redacted> }")
    }
}

/// Verify an epoch co-signature.
///
/// # Errors
///
/// [`SlhError::Malformed`] on a wrong-length key, [`SlhError::Verification`] if
/// the signature does not verify. A wrong-length *signature* is a verification
/// failure, not a usage error — ACVP `sigVer` includes malformed signatures and
/// expects `false`.
pub fn verify(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    context: &[u8],
) -> Result<(), SlhError> {
    let pk_bytes = sized::<PUBLIC_KEY_BYTES>("public key", public_key)?;
    let Ok(sig) = sized::<SIGNATURE_BYTES>("signature", signature) else {
        return Err(SlhError::Verification);
    };
    let pk = p::PublicKey::try_from_bytes(&pk_bytes).map_err(|_| SlhError::Malformed {
        what: "public key",
        expected: PUBLIC_KEY_BYTES,
        got: public_key.len(),
    })?;
    if pk.verify(message, &sig, context) {
        Ok(())
    } else {
        Err(SlhError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_fips205_shake_192s() {
        // 16 224 B is the figure PQ-ChainLog-DESIGN.md §8's cost model now uses.
        assert_eq!(SIGNATURE_BYTES, 16_224);
        assert_eq!(PUBLIC_KEY_BYTES, 48);
        assert_eq!(SECRET_KEY_BYTES, 96);
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let k = CoSigner::generate().expect("keygen");
        let sig = k.sign(b"epoch-17 root", &[], true).expect("sign");
        assert_eq!(sig.len(), SIGNATURE_BYTES);
        verify(b"epoch-17 root", &sig, k.public_key(), &[]).expect("verify");
    }

    #[test]
    fn a_modified_message_does_not_verify() {
        let k = CoSigner::generate().expect("keygen");
        let sig = k.sign(b"epoch-17 root", &[], false).expect("sign");
        assert_eq!(
            verify(b"epoch-18 root", &sig, k.public_key(), &[]),
            Err(SlhError::Verification)
        );
    }

    #[test]
    fn deterministic_signing_is_reproducible() {
        // What the ACVP sigGen vectors pin. Hedged signing must not be.
        let k = CoSigner::generate().expect("keygen");
        let a = k.sign(b"m", &[], false).expect("sign");
        let b = k.sign(b"m", &[], false).expect("sign");
        assert_eq!(a, b);
        assert_ne!(a, k.sign(b"m", &[], true).expect("sign"));
    }

    #[test]
    fn wrong_length_inputs_are_rejected_not_panicked() {
        let k = CoSigner::generate().expect("keygen");
        let sig = k.sign(b"m", &[], false).expect("sign");
        assert!(matches!(
            verify(b"m", &sig, &[0u8; 10], &[]),
            Err(SlhError::Malformed { .. })
        ));
        assert_eq!(
            verify(b"m", &[0u8; 10], k.public_key(), &[]),
            Err(SlhError::Verification)
        );
    }

    #[test]
    fn debug_does_not_leak_the_secret_key() {
        let k = CoSigner::generate().expect("keygen");
        assert_eq!(format!("{k:?}"), "CoSigner { secret: <redacted> }");
    }
}
