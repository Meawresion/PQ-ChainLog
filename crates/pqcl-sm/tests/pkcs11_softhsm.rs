//! `KeyCustody` against a real PKCS#11 token.
//!
//! Run `eval "$(scripts/softhsm2-init.sh)"` first. These tests **fail** rather
//! than skip when no token is configured, per the build plan — a
//! skipped test and a passing test look identical in CI output, which is how
//! this class of bug reaches a submission.

#![cfg(feature = "pkcs11")]
// A test's job is to fail loudly, which is what these three lints forbid in
// library code. Same header as every other test file in the workspace.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use pqcl_sm::{Backend, KeyCustody, Pkcs11Custody, SmError};

/// Read a required variable, failing with the fix rather than a bare `None`.
fn required(var: &str) -> String {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "{var} is not set, so there is no token to test against.\n\
             Run:  eval \"$(scripts/softhsm2-init.sh)\"  then re-run the tests.\n\
             These tests do not skip: see the module docs."
        ),
    }
}

fn open() -> Pkcs11Custody {
    let module = required("PQCL_PKCS11_MODULE");
    let pin = required("PQCL_PKCS11_PIN");
    // SOFTHSM2_CONF is read by the module at C_Initialize, not by us, but if it
    // is missing the failure surfaces as an opaque CKR_GENERAL_ERROR. Checking
    // it here turns that into a sentence that says what to do.
    let _ = required("SOFTHSM2_CONF");
    match Pkcs11Custody::open(&module, 0, &pin) {
        Ok(s) => s,
        Err(e) => panic!("could not open a session against the token: {e}"),
    }
}

/// Unique per test, so tests can run concurrently against one token without
/// colliding on `CKA_LABEL`. The fixture-collision lesson from the disclosure
/// test applies here too: identical labels would make one test's key visible to
/// another and the failure would look like a token bug.
fn label(test: &str) -> String {
    format!("pqcl-{test}-{}", std::process::id())
}

#[test]
fn the_token_reports_itself_as_software_and_therefore_unpublishable() {
    let sm = open();
    let backend = sm.backend();
    assert_eq!(
        backend,
        Backend::Pkcs11 {
            software_only: true
        },
        "SoftHSM2 must identify as software. If this fails against a physical \
         HSM, that is correct and the assertion is what needs updating."
    );
    assert!(
        !backend.is_publishable(),
        "a SoftHSM2 measurement must never be publishable — plan §0.3 puts \
         every paper number on AWS"
    );
}

/// ⭐ M5 acceptance: keys demonstrably do not leave the boundary.
///
/// The assertion is on the **refusal**. A test that merely declines to ask for
/// the key would pass against a token that hands it over on request, and would
/// therefore prove nothing at all.
#[test]
fn a_non_extractable_key_cannot_be_read_back_out() {
    let sm = open();
    let key = sm
        .generate_non_extractable_aes256(&label("noextract"))
        .expect("token should generate an AES-256 key");

    match sm.try_export(key) {
        Err(SmError::ExtractionRefused) => {}
        Ok(bytes) => panic!(
            "the token released {} bytes of a key marked CKA_EXTRACTABLE=false. \
             The custody property this milestone rests on does not hold.",
            bytes.len()
        ),
        Err(other) => panic!(
            "extraction failed, but for the wrong reason: {other}. The test \
             must observe a refusal specifically, or an unrelated failure would \
             make it pass while proving nothing."
        ),
    }
}

#[test]
fn a_key_that_cannot_be_read_can_still_be_used() {
    let sm = open();
    let key = sm
        .generate_non_extractable_aes256(&label("roundtrip"))
        .expect("token should generate an AES-256 key");

    let nonce = [7u8; 12];
    let aad = b"cid_c=case-42";
    let plaintext = b"custody record note, sealed under a key we cannot read";

    let ct = sm
        .aes_gcm_encrypt(key, &nonce, aad, plaintext)
        .expect("encrypt under a token-held key");
    assert_ne!(
        &ct[..plaintext.len()],
        &plaintext[..],
        "ciphertext is plaintext"
    );
    assert_eq!(
        ct.len(),
        plaintext.len() + 16,
        "AES-GCM output must carry a full 128-bit tag"
    );

    let pt = sm
        .aes_gcm_decrypt(key, &nonce, aad, &ct)
        .expect("decrypt under a token-held key");
    assert_eq!(pt, plaintext, "round trip must return the original");
}

#[test]
fn aad_is_actually_bound() {
    let sm = open();
    let key = sm
        .generate_non_extractable_aes256(&label("aad"))
        .expect("token should generate an AES-256 key");

    let nonce = [9u8; 12];
    let ct = sm
        .aes_gcm_encrypt(key, &nonce, b"case-A", b"payload")
        .expect("encrypt");

    // Π_core's verifiability rests on AEAD associated data being binding — it
    // is what makes a substituted address detectable. A token whose GCM ignored
    // AAD would break that silently, so it is checked here rather than assumed.
    assert!(
        sm.aes_gcm_decrypt(key, &nonce, b"case-B", &ct).is_err(),
        "decryption under the wrong AAD must fail; if it succeeds the token is \
         not binding associated data"
    );
}

/// ⭐ Regression: several sessions, several threads, one process.
///
/// The first version of `pkcs11.rs` built a `Pkcs11` context per session.
/// PKCS#11 allows one `C_Initialize` per process and finalizes on drop, so this
/// **segfaulted the whole harness** — while passing perfectly under
/// `--test-threads=1`. The other tests in this file cannot catch it: they only
/// crash when they happen to overlap, which makes them flaky rather than
/// diagnostic.
///
/// This one opens sessions concurrently on purpose, so the failure is
/// deterministic and attributable. The ingest pipeline is threaded, so this is
/// the shape real callers will use.
#[test]
fn concurrent_sessions_do_not_tear_down_each_others_context() {
    let handles: Vec<_> = (0u8..4)
        .map(|i: u8| {
            std::thread::spawn(move || {
                let sm = open();
                let key = sm
                    .generate_non_extractable_aes256(&label(&format!("concurrent-{i}")))
                    .expect("generate under a shared context");
                let ct = sm
                    .aes_gcm_encrypt(key, &[i; 12], b"aad", b"payload")
                    .expect("encrypt under a shared context");
                sm.aes_gcm_decrypt(key, &[i; 12], b"aad", &ct)
                    .expect("decrypt under a shared context")
            })
        })
        .collect();

    for h in handles {
        let pt = h.join().expect("no thread may panic or crash");
        assert_eq!(pt, b"payload");
    }
}

#[test]
fn the_token_generates_random_bytes() {
    let sm = open();
    let a = sm.random(32).expect("RNG");
    let b = sm.random(32).expect("RNG");
    assert_eq!(a.len(), 32);
    assert_ne!(a, b, "two draws must differ");
    assert_ne!(a, vec![0u8; 32], "all-zero output is a broken RNG");
}
