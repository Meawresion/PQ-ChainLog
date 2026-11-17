//! AES-256-GCM, with the design's one-key-per-record discipline enforced by the
//! type system.
//!
//! # Why [`RecordKey`] is consumed by value
//!
//! `PQ-DSSE-Formal.md` §5.1 encrypts each `Π_core` payload as
//! `AEAD.Enc(k; nonce = 0; AD = addr; msg = op ‖ id)` with `k ← F(K^M_w, c)` —
//! a **fresh key per record**, and consequently a fixed all-zero nonce. §9.3
//! records the rationale: *"AES-256-GCM, one key per record — nonce reuse
//! structurally impossible."*
//!
//! That property holds only as long as nobody encrypts twice under one key.
//! Under GCM, two messages sharing a key and nonce leak their XOR *and* the
//! authentication subkey, which is a total break of integrity for that key — not
//! a degradation. So [`RecordKey::seal`] takes `self` by value. Reuse is a
//! compile error rather than a code-review item, which is the cheapest place in
//! the whole system to make it unrepresentable.
//!
//! # Scope
//!
//! This is the record-level interface: `Π_core` payloads, custody notes,
//! encrypted metadata. Bulk artefact encryption (`C_ev` over a disk image or a
//! memory dump) needs a chunked, streaming construction — a single GCM
//! invocation is capped at 64 GiB per key and would in any case require the
//! whole image in memory. That arrives with the Evidence Capsule at M4.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::LAMBDA_BYTES;

/// GCM authentication tag length, in bytes.
pub const TAG_BYTES: usize = 16;

/// GCM nonce length, in bytes.
pub const NONCE_BYTES: usize = 12;

/// The fixed nonce. Sound only because a key is used exactly once — see the
/// module documentation.
const ZERO_NONCE: [u8; NONCE_BYTES] = [0u8; NONCE_BYTES];

/// What can go wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// Authentication failed: wrong key, wrong associated data, or a modified
    /// ciphertext.
    ///
    /// In `Π_core` this is not merely an error — it is the *detection
    /// mechanism*. `PQ-ChainLog-DESIGN.md` §11.1 shows that because the client
    /// derives every `addr_i` itself and binds it as associated data, while
    /// `K^M_w` never reaches the server, this single failure covers omission,
    /// forgery, substitution and replay by a malicious server. Callers must
    /// treat it as an abort, never as an empty result.
    Authentication,
    /// The ciphertext is shorter than the authentication tag.
    Truncated,
    /// The plaintext exceeds AES-GCM's per-invocation limit of roughly 64 GiB.
    ///
    /// Unreachable for record payloads (`op ‖ id` is tens of bytes), but bulk
    /// artefacts — disk images and memory dumps — are exactly the size where it
    /// stops being unreachable, which is why they get the chunked path at M4
    /// rather than this one.
    PlaintextTooLarge,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Authentication => f.write_str("AEAD authentication failed"),
            Self::Truncated => f.write_str("ciphertext shorter than the authentication tag"),
            Self::PlaintextTooLarge => {
                f.write_str("plaintext exceeds the AES-GCM per-invocation limit")
            }
        }
    }
}

impl core::error::Error for AeadError {}

/// A single-use AES-256 key.
///
/// Cannot be cloned or copied, and both [`seal`](Self::seal) and
/// [`open`](Self::open) consume it. To decrypt, re-derive the key from
/// `F(K^M_w, c)`; that derivation is a single SHAKE256 call and is dramatically
/// cheaper than the class of bug the restriction prevents.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecordKey([u8; LAMBDA_BYTES]);

impl RecordKey {
    /// Wrap raw key bytes, typically the output of `F(K^M_w, c)`.
    #[must_use]
    pub const fn new(bytes: [u8; LAMBDA_BYTES]) -> Self {
        Self(bytes)
    }

    /// Encrypt and authenticate `plaintext`, binding `associated_data`.
    ///
    /// In `Π_core`, `associated_data` is `addr_i`. Binding it is what makes
    /// substitution detectable: a payload moved to a different address fails to
    /// authenticate there.
    ///
    /// # Errors
    ///
    /// [`AeadError::PlaintextTooLarge`] if `plaintext` exceeds AES-GCM's
    /// per-invocation limit. This returns rather than panics deliberately: the
    /// ingest path runs for hours under a measurement harness, and a panic there
    /// destroys a run instead of failing one record.
    pub fn seal(self, associated_data: &[u8], plaintext: &[u8]) -> Result<SealedRecord, AeadError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        cipher
            .encrypt(
                Nonce::from_slice(&ZERO_NONCE),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map(SealedRecord)
            .map_err(|_| AeadError::PlaintextTooLarge)
    }

    /// Verify and decrypt.
    ///
    /// # Errors
    ///
    /// [`AeadError::Authentication`] if the record was omitted, forged,
    /// substituted or replayed; [`AeadError::Truncated`] if it is too short to
    /// contain a tag.
    pub fn open(self, associated_data: &[u8], sealed: &SealedRecord) -> Result<Vec<u8>, AeadError> {
        if sealed.0.len() < TAG_BYTES {
            return Err(AeadError::Truncated);
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        cipher
            .decrypt(
                Nonce::from_slice(&ZERO_NONCE),
                Payload {
                    msg: &sealed.0,
                    aad: associated_data,
                },
            )
            .map_err(|_| AeadError::Authentication)
    }
}

impl core::fmt::Debug for RecordKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordKey(<redacted>)")
    }
}

/// Ciphertext with its appended authentication tag. This is `val` in `EDB`.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedRecord(Vec<u8>);

impl SealedRecord {
    /// Wrap bytes received from storage.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The wire representation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Total length, ciphertext plus tag. Reported as communication volume,
    /// which is a language-independent axis and so compares across every
    /// baseline including the Python ones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the record is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Constant-time equality.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl core::fmt::Debug for SealedRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SealedRecord({} bytes)", self.0.len())
    }
}

/// A **long-lived** AES-256 key used with caller-supplied nonces.
///
/// # Why this exists as a separate type, and why [`RecordKey`] is untouched
///
/// [`RecordKey`] is consumed by value with a zero nonce, because a record key
/// is used exactly once and that makes nonce reuse *unrepresentable*. That
/// invariant is worth more than the convenience of one type, so it is not
/// relaxed.
///
/// But a Secure Module key is the opposite object. A PKCS#11 token generates a
/// key that lives in the token and encrypts many messages under distinct
/// nonces; `CKA_EXTRACTABLE=false` is the whole point, so it cannot be
/// re-derived per record. `pqcl-sm`'s `KeyCustody` abstraction has to express
/// that, and it must express it identically for the token and the software
/// backend or the shared test suite proves nothing.
///
/// So: two types, because there are two objects. Same reasoning as the role
/// tags and field tags in [`crate::xof`] — the namespaces overlap numerically
/// and are kept apart by type, not by care.
///
/// # ⚠️ The obligation this type carries and `RecordKey` does not
///
/// **A nonce must never repeat under one `CustodyKey`.** Two messages sharing a
/// key and nonce leak their XOR *and* the GCM authentication subkey, which is a
/// total break rather than a degradation. The type cannot enforce this because
/// the nonce comes from the caller — which is exactly why the caller is the
/// Secure Module backend and not general code. Do not reach for this to seal a
/// record; that is [`RecordKey`]'s job and it is safe by construction.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CustodyKey([u8; LAMBDA_BYTES]);

impl CustodyKey {
    /// Wrap raw key bytes.
    #[must_use]
    pub const fn new(bytes: [u8; LAMBDA_BYTES]) -> Self {
        Self(bytes)
    }

    /// Encrypt under an explicit nonce, returning ciphertext with the tag
    /// appended.
    ///
    /// # Errors
    ///
    /// [`AeadError::PlaintextTooLarge`] if the input exceeds the GCM limit.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_BYTES],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0))
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| AeadError::PlaintextTooLarge)
    }

    /// Decrypt and verify.
    ///
    /// # Errors
    ///
    /// [`AeadError::Authentication`] if the tag, the nonce or the associated
    /// data does not match. The three are deliberately indistinguishable.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_BYTES],
        associated_data: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0))
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext_and_tag,
                    aad: associated_data,
                },
            )
            .map_err(|_| AeadError::Authentication)
    }
}

impl core::fmt::Debug for CustodyKey {
    /// Never prints key material. A key in a log line is a key on disk.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CustodyKey(<redacted>)")
    }
}

/// AES-256-GCM with an explicit nonce — **crate-private, for known-answer tests
/// only**.
///
/// The public API fixes the nonce to zero because a record key is used exactly
/// once. NIST's CAVP vectors necessarily use varied nonces, so proving our
/// AES-256-GCM against them needs a path that accepts one. Keeping it private
/// means the invariant that matters — one key, one nonce, one message — is
/// still unrepresentable to every caller outside this file.
///
/// This is not a `cfg` branch that changes measured behaviour: `seal`/`open`
/// call the same `aes-gcm` code with the same parameters. It only widens what a
/// test can reach.
#[cfg(test)]
fn seal_with_nonce(
    key: &[u8; LAMBDA_BYTES],
    nonce: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| AeadError::PlaintextTooLarge)
}

#[cfg(test)]
fn open_with_nonce(
    key: &[u8; LAMBDA_BYTES],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad: associated_data,
            },
        )
        .map_err(|_| AeadError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; LAMBDA_BYTES] = [0x42; LAMBDA_BYTES];

    /// Seal under the fixed test key. Record-sized plaintexts cannot hit
    /// [`AeadError::PlaintextTooLarge`], so unwrapping here is honest.
    fn seal(associated_data: &[u8], plaintext: &[u8]) -> SealedRecord {
        RecordKey::new(K)
            .seal(associated_data, plaintext)
            .expect("record-sized plaintext is always sealable")
    }

    #[test]
    fn round_trip() {
        let sealed = seal(b"addr", b"add|doc-17");
        let opened = RecordKey::new(K).open(b"addr", &sealed).expect("authentic");
        assert_eq!(opened, b"add|doc-17");
    }

    #[test]
    fn tag_adds_exactly_16_bytes() {
        let plaintext = b"add|doc-17";
        let sealed = seal(b"addr", plaintext);
        assert_eq!(sealed.len(), plaintext.len() + TAG_BYTES);
    }

    // The four malicious-server deviations of `PQ-ChainLog-DESIGN.md` §11.1, at
    // the layer that actually detects them. M2 re-tests them end-to-end against
    // a real server transcript; these assert the primitive underneath is sound.

    #[test]
    fn detects_forgery() {
        let mut bytes = seal(b"addr", b"add|doc-17").as_bytes().to_vec();
        bytes[0] ^= 0x01;
        let forged = SealedRecord::from_bytes(bytes);
        assert_eq!(
            RecordKey::new(K).open(b"addr", &forged),
            Err(AeadError::Authentication)
        );
    }

    #[test]
    fn detects_substitution() {
        // A payload moved to a different address must not authenticate there.
        let sealed = seal(b"addr-i", b"add|doc-17");
        assert_eq!(
            RecordKey::new(K).open(b"addr-j", &sealed),
            Err(AeadError::Authentication)
        );
    }

    #[test]
    fn detects_wrong_key() {
        // A server that never sees K^M_w cannot produce a record that opens.
        let sealed = seal(b"addr", b"add|doc-17");
        assert_eq!(
            RecordKey::new([0x43; LAMBDA_BYTES]).open(b"addr", &sealed),
            Err(AeadError::Authentication)
        );
    }

    #[test]
    fn detects_truncation() {
        let sealed = SealedRecord::from_bytes(vec![0u8; TAG_BYTES - 1]);
        assert_eq!(
            RecordKey::new(K).open(b"addr", &sealed),
            Err(AeadError::Truncated)
        );
    }

    #[test]
    fn empty_plaintext_is_still_authenticated() {
        let sealed = seal(b"addr", b"");
        assert_eq!(sealed.len(), TAG_BYTES);
        assert_eq!(
            RecordKey::new(K).open(b"addr", &sealed).expect("authentic"),
            b""
        );
    }

    #[test]
    fn record_key_debug_does_not_leak() {
        assert_eq!(format!("{:?}", RecordKey::new(K)), "RecordKey(<redacted>)");
    }

    // ------------------------------------------------------- known-answer

    /// AES-256-GCM against NIST CAVP.
    ///
    /// Lives here rather than in `tests/kat.rs` because it needs
    /// [`seal_with_nonce`], which is crate-private so that the public API keeps
    /// its one-key-one-nonce invariant.
    ///
    /// Fails loudly when the vectors are absent — a skipped KAT and a passing
    /// KAT look identical in CI output.
    #[test]
    fn aes_256_gcm_matches_cavp() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/CAVP-AES-256-GCM.json");
        let raw = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "\n\nCAVP vector file missing: {}\n  {e}\n\n\
                 Regenerate with:\n    \
                 python3 crates/pqcl-primitives/tests/vectors/extract.py\n",
                path.display()
            )
        });
        let doc: serde_json::Value = serde_json::from_slice(&raw).expect("valid JSON");

        let hexed = |s: &str| hex::decode(s).expect("hex field");
        let mut encrypted = 0usize;
        let mut decrypted = 0usize;
        let mut rejected = 0usize;

        for (file, rows) in doc["files"].as_object().expect("files map") {
            for row in rows.as_array().expect("rows array") {
                let get = |k: &str| row[k].as_str().unwrap_or("");
                let key: [u8; LAMBDA_BYTES] = hexed(get("Key")).try_into().expect("256-bit key");
                let iv = hexed(get("IV"));
                let aad = hexed(get("AAD"));
                let tag = hexed(get("Tag"));

                if file.starts_with("gcmEncrypt") {
                    let pt = hexed(get("PT"));
                    let mut expected = hexed(get("CT"));
                    expected.extend_from_slice(&tag);
                    let got = seal_with_nonce(&key, &iv, &aad, &pt).expect("seal");
                    assert_eq!(got, expected, "CAVP encrypt mismatch");
                    encrypted += 1;
                } else {
                    let mut ct = hexed(get("CT"));
                    ct.extend_from_slice(&tag);
                    let got = open_with_nonce(&key, &iv, &aad, &ct);
                    if get("fail").is_empty() {
                        assert_eq!(
                            got.expect("authentic"),
                            hexed(get("PT")),
                            "decrypt mismatch"
                        );
                        decrypted += 1;
                    } else {
                        // CAVP marks these FAIL: they must not authenticate.
                        assert_eq!(got, Err(AeadError::Authentication));
                        rejected += 1;
                    }
                }
            }
        }

        assert!(
            encrypted > 0 && decrypted > 0 && rejected > 0,
            "CAVP run was not exhaustive: {encrypted} enc, {decrypted} dec, {rejected} rejected"
        );
        eprintln!(
            "AES-256-GCM CAVP: {encrypted} encrypt, {decrypted} decrypt, {rejected} correctly rejected"
        );
    }

    /// The zero-nonce public API must agree with the general path.
    #[test]
    fn public_api_agrees_with_the_explicit_nonce_path() {
        let sealed = seal(b"addr", b"add|doc-17");
        let direct = seal_with_nonce(&K, &ZERO_NONCE, b"addr", b"add|doc-17").expect("seal");
        assert_eq!(sealed.as_bytes(), &direct[..]);
    }

    // ------------------------------------------------ hardware acceleration

    /// AES-GCM must actually be taking its hardware path.
    ///
    /// [`CpuFeatures`] says the *CPU* can do it; this says the *build* does.
    /// They differ — `aes` compiled with `force-soft`, or a `RUSTFLAGS` that
    /// disables the target feature, gives a machine with AES-NI running
    /// bitsliced software. The output is byte-identical either way, so nothing
    /// else in the suite would notice.
    ///
    /// The floor is deliberately far below real AES-NI throughput (multiple
    /// GB/s) and far above the portable fallback (tens to low hundreds of
    /// MB/s), so it separates the two without being flaky on a loaded machine
    /// or in a container.
    ///
    /// ⚠️ This number is a **guard, not a measurement**. It must never reach the
    /// paper: The build plan requires published figures to come
    /// from an AWS run through the results pipeline.
    ///
    /// # Why this is `#[ignore]`d rather than always-on
    ///
    /// `aes-gcm` is generic — `Aes256Gcm = AesGcm<Aes256, U12>` — so its hot
    /// code is monomorphised into *this* crate and compiles at this crate's
    /// opt-level. `[profile.dev.package."*"]` optimises dependencies, but this
    /// code is no longer in a dependency by the time it matters. A debug build
    /// measures **8 MiB/s** on hardware that does 4 GB/s in release, so an
    /// always-on floor would fail for a reason that has nothing to do with
    /// AES-NI.
    ///
    /// The same effect bit `slh-dsa` in the SLH-DSA bake-off. Assume any
    /// generic crypto crate behaves this way, and never trust a debug-build
    /// timing.
    ///
    /// ```text
    /// cargo test --release -p pqcl-primitives --lib -- --ignored --nocapture
    /// ```
    ///
    /// The unconditional protection is elsewhere and does not depend on
    /// anyone remembering to run this: [`crate::platform::CpuFeatures`] is
    /// asserted in its own test, and every results record carries the detected
    /// feature set so a published number can be traced to the instruction set
    /// that produced it.
    #[test]
    #[ignore = "needs --release; generic code compiles at the caller's opt-level"]
    fn aes_gcm_takes_the_hardware_path() {
        use crate::platform::CpuFeatures;

        const CHUNK: usize = 64 * 1024;
        const ROUNDS: usize = 64; // 4 MiB total

        let features = CpuFeatures::detect();
        assert!(
            features.aes_gcm_is_accelerated(),
            "CPU lacks AES-NI/PCLMULQDQ: {}",
            features.summary()
        );

        let plaintext = vec![0u8; CHUNK];

        let start = std::time::Instant::now();
        let mut sunk = 0usize;
        for _ in 0..ROUNDS {
            let out = seal_with_nonce(&K, &ZERO_NONCE, b"", &plaintext).expect("seal");
            // Consume the result so the optimiser cannot elide the work.
            sunk = sunk.wrapping_add(out.len());
        }
        let elapsed = start.elapsed();
        assert_eq!(sunk, ROUNDS * (CHUNK + TAG_BYTES));

        #[allow(clippy::cast_precision_loss)]
        let mib_per_s = (ROUNDS * CHUNK) as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
        eprintln!("AES-256-GCM: {mib_per_s:.0} MiB/s (guard, not a measurement)");

        assert!(
            mib_per_s > 300.0,
            "AES-256-GCM ran at {mib_per_s:.0} MiB/s, which is in software-fallback \
             territory despite the CPU advertising AES-NI ({}). A throughput \
             number from this build would be wrong by roughly 10x and look \
             entirely normal. Check RUSTFLAGS and the `aes` crate's features.",
            features.summary()
        );
    }
}
