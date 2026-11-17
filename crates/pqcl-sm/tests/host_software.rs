//! The host-software backend, and the M5a claim that the **same** `KeyCustody`
//! suite passes on it and on the PKCS#11 token.
//!
//! Requires `--features host-software`. The feature is default-off by
//! The design record, so these do not run in a default build —
//! and that is the point, not an oversight.

#![cfg(feature = "host-software")]
// A test's job is to fail loudly, which is what these three lints forbid in
// library code. Same header as every other test file in the workspace.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use pqcl_capsule::Role;
use pqcl_pipeline::Agent;
use pqcl_primitives::sig::SoftwareMlDsa;
use pqcl_primitives::xof::PrfKey;
use pqcl_sm::{AgentModule, Backend, HostAgentModule, KeyCustody, SmError};

fn module() -> HostAgentModule {
    let k_mst = PrfKey::new(pqcl_primitives::rng::secret().expect("entropy"));
    let defr = SoftwareMlDsa::generate().expect("ML-DSA keygen");
    // The first responder arrives as an enrolled actor since M13 A18, so the
    // key that signs a capsule is the key that opens its custody chain.
    HostAgentModule::new(k_mst, Agent::new(defr, b"defr-1", Role::Defr))
}

// ---------------------------------------------------------------------------
// The shared KeyCustody suite. These assertions are deliberately the same ones
// `pkcs11_softhsm.rs` makes. If you change one, change both — that identity is
// M5a's stated acceptance, and a suite that has drifted apart proves nothing
// about either backend.
// ---------------------------------------------------------------------------

#[test]
fn a_non_extractable_key_cannot_be_read_back_out() {
    let sm = module();
    let key = sm
        .generate_non_extractable_aes256("noextract")
        .expect("generate");

    match sm.try_export(key) {
        Err(SmError::ExtractionRefused) => {}
        Ok(bytes) => panic!(
            "the module released {} bytes of a key it claims not to export",
            bytes.len()
        ),
        Err(other) => panic!("extraction failed for the wrong reason: {other}"),
    }
}

#[test]
fn a_key_that_cannot_be_read_can_still_be_used() {
    let sm = module();
    let key = sm
        .generate_non_extractable_aes256("roundtrip")
        .expect("generate");

    let nonce = [7u8; 12];
    let aad = b"cid_c=case-42";
    let plaintext = b"custody record note, sealed under a key we cannot read";

    let ct = sm
        .aes_gcm_encrypt(key, &nonce, aad, plaintext)
        .expect("seal");
    assert_eq!(
        ct.len(),
        plaintext.len() + 16,
        "AES-GCM output must carry a full 128-bit tag"
    );

    let pt = sm.aes_gcm_decrypt(key, &nonce, aad, &ct).expect("open");
    assert_eq!(pt, plaintext);
}

#[test]
fn aad_is_actually_bound() {
    let sm = module();
    let key = sm.generate_non_extractable_aes256("aad").expect("generate");
    let nonce = [9u8; 12];
    let ct = sm
        .aes_gcm_encrypt(key, &nonce, b"case-A", b"payload")
        .expect("seal");

    assert!(
        sm.aes_gcm_decrypt(key, &nonce, b"case-B", &ct).is_err(),
        "decryption under the wrong AAD must fail"
    );
}

#[test]
fn the_module_generates_random_bytes() {
    let sm = module();
    let (a, b) = (sm.random(32).expect("rng"), sm.random(32).expect("rng"));
    assert_eq!(a.len(), 32);
    assert_ne!(a, b, "two draws must differ");
    assert_ne!(a, vec![0u8; 32], "all-zero output is a broken RNG");
}

// ---------------------------------------------------------------------------
// What is specific to having no boundary at all.
// ---------------------------------------------------------------------------

/// ⭐ The honesty assertion.
///
/// A software module that reported itself publishable would put a number with
/// no boundary behind it into a paper table, and nothing downstream would
/// catch it — `is_publishable` is what the results pipeline consults.
#[test]
fn the_host_module_is_never_publishable() {
    let sm = module();
    assert_eq!(sm.backend(), Backend::HostSoftware);
    assert!(
        !sm.backend().is_publishable(),
        "a module with no boundary must never produce a paper number"
    );
}

/// Distinct keys must be distinct. A handle allocator that reused an id would
/// silently alias two capsules' keys, and every test above would still pass.
#[test]
fn separate_handles_hold_separate_keys() {
    let sm = module();
    let a = sm.generate_non_extractable_aes256("a").expect("generate");
    let b = sm.generate_non_extractable_aes256("b").expect("generate");
    assert_ne!(a, b, "handles collided");

    let nonce = [1u8; 12];
    let ct = sm.aes_gcm_encrypt(a, &nonce, b"", b"secret").expect("seal");
    assert!(
        sm.aes_gcm_decrypt(b, &nonce, b"", &ct).is_err(),
        "one key opened another key's ciphertext"
    );
}

// ---------------------------------------------------------------------------
// AgentModule — the role half.
// ---------------------------------------------------------------------------

#[test]
fn the_capsule_pseudonym_is_deterministic_and_case_scoped() {
    let sm = module();
    let case_a = [0xAAu8; 32];
    let case_b = [0xBBu8; 32];
    let nonce = b"artefact-0001";

    let one = sm.capsule_pseudonym(&case_a, nonce).expect("derive");
    let two = sm.capsule_pseudonym(&case_a, nonce).expect("derive");
    assert_eq!(one, two, "eid must be reproducible from the same inputs");

    // Different case, same artefact nonce. If these matched, a server could
    // link the same artefact across cases, which is the unlinkability the
    // pseudonym exists to provide.
    let other = sm.capsule_pseudonym(&case_b, nonce).expect("derive");
    assert_ne!(one, other, "eid must not be reused across cases");

    let other_nonce = sm.capsule_pseudonym(&case_a, b"artefact-0002").expect("d");
    assert_ne!(one, other_nonce, "eid must depend on the artefact nonce");
}

#[test]
fn defr_signatures_verify_under_the_reported_public_key() {
    let sm = module();
    let message = b"sealed capsule fields";
    let sig = sm.sign_defr(message).expect("sign");
    let pk = sm.defr_public_key().expect("public key");

    assert_eq!(pk.len(), 1952, "ML-DSA-65 verification key is 1952 bytes");
    assert_eq!(sig.len(), 3309, "ML-DSA-65 signature is 3309 bytes");
    assert!(
        pqcl_primitives::sig::verify(message, &sig, &pk, b"").is_ok(),
        "sigma_DEFR must verify under the key the module reports"
    );
    assert!(
        pqcl_primitives::sig::verify(b"a different message", &sig, &pk, b"").is_err(),
        "a signature must not verify over a message it did not sign"
    );
}
