//! ML-DSA-65 (FIPS 204) — the signature on the ingest hot path.
//!
//! # Where this is used
//!
//! Per-batch device signatures during ingestion, `σ_DEFR` on an Evidence
//! Capsule, and `σ_actor` on a Custody Record. Ingest signs a batch of `B`
//! events over a hash chain rather than each event, which is what makes lattice
//! signing affordable at log volumes — see `PQ-ChainLog-DESIGN.md` §8.
//!
//! # The seam for M5
//!
//! [`Signer`] and [`Verifier`] exist so the Secure Module can be dropped in
//! later without touching callers. [`SoftwareMlDsa`] holds the secret key in
//! process memory and is for tests and local iteration; at M5 a
//! `SecureModuleSigner` implements the same trait against `SoftHSM2` or a Nitro
//! Enclave, where the key never leaves. Nothing above this module should ever
//! name a concrete signer type.
//!
//! # What the KATs can and cannot check
//!
//! liboqs exposes no derandomised signing or seeded key generation for ML-DSA,
//! so the ACVP `keyGen` and `sigGen` vectors cannot be checked directly against
//! this API — those vectors fix the randomness we cannot supply. **`sigVer`
//! is checkable, and it is the one that matters**: FIPS 204 final and the
//! earlier `ipd` draft differ in domain separation, so a draft implementation
//! rejects a final-spec signature. See `tests/kat.rs`.

use std::sync::OnceLock;

use zeroize::Zeroize;

/// ML-DSA-65 public key length, FIPS 204 Table 2.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// ML-DSA-65 secret key length.
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;
/// ML-DSA-65 signature length.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

/// Signing and verification failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigError {
    /// The signature did not verify under this key and message.
    Verification,
    /// A key or signature had the wrong length for ML-DSA-65.
    Malformed {
        /// What was being parsed.
        what: &'static str,
        /// Length required by FIPS 204.
        expected: usize,
        /// Length actually supplied.
        got: usize,
    },
    /// liboqs reported a failure.
    Backend(String),
}

impl core::fmt::Display for SigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Verification => f.write_str("ML-DSA signature verification failed"),
            Self::Malformed {
                what,
                expected,
                got,
            } => write!(f, "malformed {what}: expected {expected} bytes, got {got}"),
            Self::Backend(m) => write!(f, "liboqs error: {m}"),
        }
    }
}

impl core::error::Error for SigError {}

/// Produces ML-DSA-65 signatures.
///
/// Implemented in process by [`SoftwareMlDsa`] and, from M5, by a Secure Module
/// backend where the private key is never extractable.
pub trait Signer {
    /// The verification key, 1952 bytes.
    fn public_key(&self) -> &[u8];

    /// Sign `message` under the FIPS 204 *external* interface with empty
    /// context.
    ///
    /// # Errors
    ///
    /// [`SigError::Backend`] if the backend fails.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigError>;
}

/// liboqs is process-global and wants one initialisation before use. It
/// performs runtime CPU feature detection, which is why the `non_portable`
/// feature must stay off — see the build plan.
fn backend() -> Result<&'static oqs::sig::Sig, SigError> {
    static SIG: OnceLock<Option<oqs::sig::Sig>> = OnceLock::new();
    SIG.get_or_init(|| {
        oqs::init();
        oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).ok()
    })
    .as_ref()
    .ok_or_else(|| SigError::Backend("liboqs was built without ML-DSA-65".into()))
}

/// The liboqs algorithm version this build links, recorded in every results
/// artifact so a measurement can be traced to the library that produced it.
///
/// This is the string that distinguishes final FIPS 204 from the earlier `ipd`
/// draft, and it is checked properly by the ACVP vectors in `tests/kat.rs` —
/// see the design record.
///
/// # Errors
///
/// [`SigError::Backend`] if liboqs was built without ML-DSA-65.
pub fn backend_version() -> Result<&'static str, SigError> {
    Ok(backend()?.version())
}

/// Verify an ML-DSA-65 signature under the FIPS 204 external interface.
///
/// `context` is the FIPS 204 context string; pass `&[]` for the empty context,
/// which is what the rest of PQ-ChainLog uses.
///
/// # Errors
///
/// [`SigError::Malformed`] if the key or signature is the wrong length,
/// [`SigError::Verification`] if the signature does not verify.
pub fn verify(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    context: &[u8],
) -> Result<(), SigError> {
    let sig = backend()?;

    if public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(SigError::Malformed {
            what: "public key",
            expected: ML_DSA_65_PUBLIC_KEY_BYTES,
            got: public_key.len(),
        });
    }
    // A signature of the wrong length is a verification failure, not a usage
    // error: ACVP sigVer vectors deliberately include malformed signatures and
    // expect `false`, not a panic.
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(SigError::Verification);
    }

    let pk = sig
        .public_key_from_bytes(public_key)
        .ok_or(SigError::Malformed {
            what: "public key",
            expected: ML_DSA_65_PUBLIC_KEY_BYTES,
            got: public_key.len(),
        })?;
    let sg = sig
        .signature_from_bytes(signature)
        .ok_or(SigError::Verification)?;

    sig.verify_with_ctx_str(message, sg, context, pk)
        .map_err(|_| SigError::Verification)
}

/// An in-process ML-DSA-65 keypair.
///
/// For tests and local iteration. Paper numbers involving key custody come from
/// the Secure Module backend at M5, not from this.
pub struct SoftwareMlDsa {
    public: Vec<u8>,
    secret: Vec<u8>,
}

impl SoftwareMlDsa {
    /// Generate a fresh keypair from the backend's RNG.
    ///
    /// # Errors
    ///
    /// [`SigError::Backend`] if liboqs fails.
    pub fn generate() -> Result<Self, SigError> {
        let sig = backend()?;
        let (public, secret) = sig
            .keypair()
            .map_err(|e| SigError::Backend(format!("{e}")))?;
        Ok(Self {
            public: public.into_vec(),
            secret: secret.into_vec(),
        })
    }

    /// Adopt an existing keypair, e.g. one supplied by a test vector.
    ///
    /// # Errors
    ///
    /// [`SigError::Malformed`] if either key has the wrong length.
    pub fn from_bytes(public: &[u8], secret: &[u8]) -> Result<Self, SigError> {
        if public.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
            return Err(SigError::Malformed {
                what: "public key",
                expected: ML_DSA_65_PUBLIC_KEY_BYTES,
                got: public.len(),
            });
        }
        if secret.len() != ML_DSA_65_SECRET_KEY_BYTES {
            return Err(SigError::Malformed {
                what: "secret key",
                expected: ML_DSA_65_SECRET_KEY_BYTES,
                got: secret.len(),
            });
        }
        Ok(Self {
            public: public.to_vec(),
            secret: secret.to_vec(),
        })
    }

    /// Sign with an explicit FIPS 204 context string.
    ///
    /// # Errors
    ///
    /// [`SigError::Backend`] if liboqs fails.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>, SigError> {
        let sig = backend()?;
        let sk = sig
            .secret_key_from_bytes(&self.secret)
            .ok_or(SigError::Malformed {
                what: "secret key",
                expected: ML_DSA_65_SECRET_KEY_BYTES,
                got: self.secret.len(),
            })?;
        sig.sign_with_ctx_str(message, context, sk)
            .map(oqs::sig::Signature::into_vec)
            .map_err(|e| SigError::Backend(format!("{e}")))
    }
}

impl Signer for SoftwareMlDsa {
    fn public_key(&self) -> &[u8] {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigError> {
        self.sign_with_context(message, &[])
    }
}

impl Drop for SoftwareMlDsa {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl core::fmt::Debug for SoftwareMlDsa {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SoftwareMlDsa { secret: <redacted> }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_fips204() {
        let sig = backend().expect("liboqs has ML-DSA-65");
        assert_eq!(sig.length_public_key(), ML_DSA_65_PUBLIC_KEY_BYTES);
        assert_eq!(sig.length_secret_key(), ML_DSA_65_SECRET_KEY_BYTES);
        assert_eq!(sig.length_signature(), ML_DSA_65_SIGNATURE_BYTES);
        assert_eq!(sig.claimed_nist_level(), 3);
    }

    #[test]
    fn backend_supports_the_context_string_interface() {
        // FIPS 204's external interface prefixes the message with
        // 0x00 ‖ len(ctx) ‖ ctx. Without this, liboqs would be exposing only
        // the internal interface, which is what the ipd draft looked like.
        assert!(
            backend()
                .expect("liboqs has ML-DSA-65")
                .has_ctx_str_support()
        );
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let k = SoftwareMlDsa::generate().expect("keygen");
        let sig = k.sign(b"epoch-17 chain head").expect("sign");
        assert_eq!(sig.len(), ML_DSA_65_SIGNATURE_BYTES);
        verify(b"epoch-17 chain head", &sig, k.public_key(), &[]).expect("verify");
    }

    #[test]
    fn a_modified_message_does_not_verify() {
        let k = SoftwareMlDsa::generate().expect("keygen");
        let sig = k.sign(b"epoch-17 chain head").expect("sign");
        assert_eq!(
            verify(b"epoch-18 chain head", &sig, k.public_key(), &[]),
            Err(SigError::Verification)
        );
    }

    #[test]
    fn context_is_bound_into_the_signature() {
        // If this passed, the context string would be decorative and we would
        // not actually be on the FIPS 204 external interface.
        let k = SoftwareMlDsa::generate().expect("keygen");
        let sig = k.sign_with_context(b"m", b"case-A").expect("sign");
        verify(b"m", &sig, k.public_key(), b"case-A").expect("right context");
        assert_eq!(
            verify(b"m", &sig, k.public_key(), b"case-B"),
            Err(SigError::Verification)
        );
        assert_eq!(
            verify(b"m", &sig, k.public_key(), &[]),
            Err(SigError::Verification)
        );
    }

    #[test]
    fn wrong_length_inputs_are_rejected_not_panicked() {
        let k = SoftwareMlDsa::generate().expect("keygen");
        let sig = k.sign(b"m").expect("sign");
        assert!(matches!(
            verify(b"m", &sig, &[0u8; 10], &[]),
            Err(SigError::Malformed { .. })
        ));
        assert_eq!(
            verify(b"m", &[0u8; 10], k.public_key(), &[]),
            Err(SigError::Verification)
        );
    }

    #[test]
    fn debug_does_not_leak_the_secret_key() {
        let k = SoftwareMlDsa::generate().expect("keygen");
        assert_eq!(format!("{k:?}"), "SoftwareMlDsa { secret: <redacted> }");
    }
}
