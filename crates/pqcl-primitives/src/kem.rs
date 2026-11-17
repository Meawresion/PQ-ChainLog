//! ML-KEM-768 (FIPS 203) — key transport at enrollment.
//!
//! Used for the PQ-AKE that issues a writer their GGM-derived key `K_i`, and to
//! wrap `K_ev` to a case key. **Not on the hot path**: the ingest data path is
//! symmetric-only, which `PQ-ChainLog-DESIGN.md` §0 identifies as the decision
//! every other decision in the system follows from.
//!
//! Unlike ML-DSA, liboqs *does* expose a derandomised key generation
//! (`keypair_derand`), so the ACVP `keyGen` vectors are checkable directly.
//! Encapsulation is not — it draws `m` internally with no seeded variant — so
//! the `encapsulation` AFT vectors are covered by a round-trip instead, and the
//! `decapsulation` VAL vectors are checked exactly. See `tests/kat.rs`.

use std::sync::OnceLock;

use zeroize::Zeroize;

/// ML-KEM-768 encapsulation key length, FIPS 203 Table 3.
pub const ML_KEM_768_ENCAPS_KEY_BYTES: usize = 1184;
/// ML-KEM-768 decapsulation key length.
pub const ML_KEM_768_DECAPS_KEY_BYTES: usize = 2400;
/// ML-KEM-768 ciphertext length.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
/// ML-KEM-768 shared secret length.
pub const ML_KEM_768_SHARED_SECRET_BYTES: usize = 32;
/// Seed length for derandomised key generation: `d ‖ z`, 32 bytes each.
pub const ML_KEM_768_KEYPAIR_SEED_BYTES: usize = 64;

/// KEM failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemError {
    /// An input had the wrong length for ML-KEM-768.
    Malformed {
        /// What was being parsed.
        what: &'static str,
        /// Length required by FIPS 203.
        expected: usize,
        /// Length actually supplied.
        got: usize,
    },
    /// liboqs reported a failure.
    Backend(String),
}

impl core::fmt::Display for KemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed {
                what,
                expected,
                got,
            } => write!(f, "malformed {what}: expected {expected} bytes, got {got}"),
            Self::Backend(m) => write!(f, "liboqs error: {m}"),
        }
    }
}

impl core::error::Error for KemError {}

fn backend() -> Result<&'static oqs::kem::Kem, KemError> {
    static KEM: OnceLock<Option<oqs::kem::Kem>> = OnceLock::new();
    KEM.get_or_init(|| {
        oqs::init();
        oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).ok()
    })
    .as_ref()
    .ok_or_else(|| KemError::Backend("liboqs was built without ML-KEM-768".into()))
}

fn check(what: &'static str, buf: &[u8], expected: usize) -> Result<(), KemError> {
    if buf.len() == expected {
        Ok(())
    } else {
        Err(KemError::Malformed {
            what,
            expected,
            got: buf.len(),
        })
    }
}

/// An ML-KEM-768 keypair. The decapsulation key is zeroized on drop.
pub struct KeyPair {
    encaps: Vec<u8>,
    decaps: Vec<u8>,
}

impl KeyPair {
    /// Generate from the backend RNG.
    ///
    /// # Errors
    ///
    /// [`KemError::Backend`] if liboqs fails.
    pub fn generate() -> Result<Self, KemError> {
        let (ek, dk) = backend()?
            .keypair()
            .map_err(|e| KemError::Backend(format!("{e}")))?;
        Ok(Self {
            encaps: ek.into_vec(),
            decaps: dk.into_vec(),
        })
    }

    /// Generate deterministically from a 64-byte `d ‖ z` seed.
    ///
    /// This exists so the ACVP `keyGen` vectors can be checked against exactly
    /// the code we ship, rather than against a round-trip that would pass even
    /// if our key generation disagreed with FIPS 203.
    ///
    /// # Errors
    ///
    /// [`KemError::Malformed`] if the seed is not 64 bytes; [`KemError::Backend`]
    /// if liboqs fails.
    pub fn from_seed(seed: &[u8]) -> Result<Self, KemError> {
        check("keypair seed", seed, ML_KEM_768_KEYPAIR_SEED_BYTES)?;
        let kem = backend()?;
        let s = kem
            .keypair_seed_from_bytes(seed)
            .ok_or(KemError::Malformed {
                what: "keypair seed",
                expected: ML_KEM_768_KEYPAIR_SEED_BYTES,
                got: seed.len(),
            })?;
        let (ek, dk) = kem
            .keypair_derand(s)
            .map_err(|e| KemError::Backend(format!("{e}")))?;
        Ok(Self {
            encaps: ek.into_vec(),
            decaps: dk.into_vec(),
        })
    }

    /// The encapsulation key, 1184 bytes.
    #[must_use]
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.encaps
    }

    /// The decapsulation key, 2400 bytes. Exposed only so the KAT harness can
    /// compare against a vector; nothing in the system should move this.
    #[must_use]
    pub fn decapsulation_key(&self) -> &[u8] {
        &self.decaps
    }

    /// Recover the shared secret from a ciphertext.
    ///
    /// # Errors
    ///
    /// [`KemError::Malformed`] on a wrong-length ciphertext;
    /// [`KemError::Backend`] if liboqs fails.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret, KemError> {
        decapsulate(&self.decaps, ciphertext)
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.decaps.zeroize();
    }
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyPair { decaps: <redacted> }")
    }
}

/// A 32-byte shared secret, zeroized on drop.
#[derive(Zeroize)]
pub struct SharedSecret([u8; ML_KEM_768_SHARED_SECRET_BYTES]);

impl SharedSecret {
    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ML_KEM_768_SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// Encapsulate to an encapsulation key, yielding `(ciphertext, shared secret)`.
///
/// # Errors
///
/// [`KemError::Malformed`] on a wrong-length key; [`KemError::Backend`] if
/// liboqs fails.
pub fn encapsulate(encaps_key: &[u8]) -> Result<(Vec<u8>, SharedSecret), KemError> {
    check("encapsulation key", encaps_key, ML_KEM_768_ENCAPS_KEY_BYTES)?;
    let kem = backend()?;
    let ek = kem
        .public_key_from_bytes(encaps_key)
        .ok_or(KemError::Malformed {
            what: "encapsulation key",
            expected: ML_KEM_768_ENCAPS_KEY_BYTES,
            got: encaps_key.len(),
        })?;
    let (ct, ss) = kem
        .encapsulate(ek)
        .map_err(|e| KemError::Backend(format!("{e}")))?;
    Ok((ct.into_vec(), into_shared_secret(ss.into_vec())?))
}

/// Decapsulate a ciphertext under a decapsulation key.
///
/// # Errors
///
/// [`KemError::Malformed`] on a wrong-length input; [`KemError::Backend`] if
/// liboqs fails.
pub fn decapsulate(decaps_key: &[u8], ciphertext: &[u8]) -> Result<SharedSecret, KemError> {
    check("decapsulation key", decaps_key, ML_KEM_768_DECAPS_KEY_BYTES)?;
    check("ciphertext", ciphertext, ML_KEM_768_CIPHERTEXT_BYTES)?;
    let kem = backend()?;
    let dk = kem
        .secret_key_from_bytes(decaps_key)
        .ok_or(KemError::Malformed {
            what: "decapsulation key",
            expected: ML_KEM_768_DECAPS_KEY_BYTES,
            got: decaps_key.len(),
        })?;
    let ct = kem
        .ciphertext_from_bytes(ciphertext)
        .ok_or(KemError::Malformed {
            what: "ciphertext",
            expected: ML_KEM_768_CIPHERTEXT_BYTES,
            got: ciphertext.len(),
        })?;
    let ss = kem
        .decapsulate(dk, ct)
        .map_err(|e| KemError::Backend(format!("{e}")))?;
    into_shared_secret(ss.into_vec())
}

fn into_shared_secret(mut v: Vec<u8>) -> Result<SharedSecret, KemError> {
    check("shared secret", &v, ML_KEM_768_SHARED_SECRET_BYTES)?;
    let mut out = [0u8; ML_KEM_768_SHARED_SECRET_BYTES];
    out.copy_from_slice(&v);
    v.zeroize();
    Ok(SharedSecret(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_fips203() {
        let kem = backend().expect("liboqs has ML-KEM-768");
        assert_eq!(kem.length_public_key(), ML_KEM_768_ENCAPS_KEY_BYTES);
        assert_eq!(kem.length_secret_key(), ML_KEM_768_DECAPS_KEY_BYTES);
        assert_eq!(kem.length_ciphertext(), ML_KEM_768_CIPHERTEXT_BYTES);
        assert_eq!(kem.length_shared_secret(), ML_KEM_768_SHARED_SECRET_BYTES);
        assert_eq!(kem.length_keypair_seed(), ML_KEM_768_KEYPAIR_SEED_BYTES);
        assert_eq!(kem.claimed_nist_level(), 3);
    }

    #[test]
    fn encapsulate_then_decapsulate_agrees() {
        let k = KeyPair::generate().expect("keygen");
        let (ct, ss_a) = encapsulate(k.encapsulation_key()).expect("encaps");
        let ss_b = k.decapsulate(&ct).expect("decaps");
        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn derandomised_keygen_is_deterministic() {
        let seed = [0x5au8; ML_KEM_768_KEYPAIR_SEED_BYTES];
        let a = KeyPair::from_seed(&seed).expect("seeded keygen");
        let b = KeyPair::from_seed(&seed).expect("seeded keygen");
        assert_eq!(a.encapsulation_key(), b.encapsulation_key());
        assert_eq!(a.decapsulation_key(), b.decapsulation_key());

        let mut other = seed;
        other[0] ^= 1;
        let c = KeyPair::from_seed(&other).expect("seeded keygen");
        assert_ne!(a.encapsulation_key(), c.encapsulation_key());
    }

    #[test]
    fn implicit_rejection_yields_a_secret_rather_than_an_error() {
        // FIPS 203 decapsulation never fails: a bad ciphertext produces a
        // pseudorandom secret derived from the implicit-rejection value z.
        // Asserting this stops anyone building a validity oracle on top.
        let k = KeyPair::generate().expect("keygen");
        let (mut ct, good) = encapsulate(k.encapsulation_key()).expect("encaps");
        ct[0] ^= 0xff;
        let bad = k.decapsulate(&ct).expect("decapsulation must not error");
        assert_ne!(good.as_bytes(), bad.as_bytes());
    }

    #[test]
    fn wrong_length_inputs_are_rejected() {
        assert!(matches!(
            encapsulate(&[0u8; 10]),
            Err(KemError::Malformed { .. })
        ));
        assert!(matches!(
            decapsulate(&[0u8; 10], &[0u8; ML_KEM_768_CIPHERTEXT_BYTES]),
            Err(KemError::Malformed { .. })
        ));
        assert!(matches!(
            KeyPair::from_seed(&[0u8; 8]),
            Err(KemError::Malformed { .. })
        ));
    }

    #[test]
    fn debug_does_not_leak() {
        let k = KeyPair::generate().expect("keygen");
        assert_eq!(format!("{k:?}"), "KeyPair { decaps: <redacted> }");
        let (_, ss) = encapsulate(k.encapsulation_key()).expect("encaps");
        assert_eq!(format!("{ss:?}"), "SharedSecret(<redacted>)");
    }
}
