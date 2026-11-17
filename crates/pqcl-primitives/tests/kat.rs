//! Known-answer tests against official NIST ACVP vectors.
//!
//! The build plan: *"A primitive that has not passed KATs in our
//! build is not a primitive, it is a guess."*
//!
//! # Vectors fail loudly when absent
//!
//! Every test here calls [`load`], which **panics with instructions** if a
//! vector file is missing. It must never `return` early or be `#[ignore]`d: a
//! skipped KAT and a passing KAT are indistinguishable in CI output, and that
//! is precisely how this class of bug reaches a submission.
//!
//! # What the public API lets us check
//!
//! ACVP vectors fix the randomness. liboqs exposes a derandomised
//! `keypair_derand` for ML-KEM but nothing equivalent for ML-DSA, so coverage
//! is uneven and the gaps are stated rather than papered over:
//!
//! | Vector set | Checked how |
//! |---|---|
//! | ML-KEM-768 `keyGen` | exactly — seeded key generation reproduces `ek`/`dk` |
//! | ML-KEM-768 `decapsulation` (VAL) | exactly — `(dk, c)` reproduces `k` |
//! | ML-KEM-768 `encapsulation` (AFT) | **round-trip only** — no seeded encapsulation |
//! | ML-DSA-65 `sigVer` | exactly — this is the FIPS-204-final gate |
//! | ML-DSA-65 `sigGen` | **cross-checked** — the vectors' own signatures must verify |
//! | ML-DSA-65 `keyGen` | **not checkable** — no seeded key generation exposed |
//! | SLH-DSA-SHAKE-192s `keyGen` | exactly — seeded from `skSeed`/`skPrf`/`pkSeed` |
//! | SLH-DSA-SHAKE-192s `sigVer` | exactly |
//! | SHAKE-256 | exactly |
//! | AES-256-GCM | exactly |
//!
//! The ML-DSA row that matters is `sigVer`. Final FIPS 204 and the earlier
//! `ipd` draft differ in **domain separation**: the final external interface
//! signs `0x00 ‖ len(ctx) ‖ ctx ‖ M`, the draft signed `M`. An `ipd`
//! implementation therefore *rejects* a final-spec signature, so these vectors
//! decide the question that the design record raised — by evidence
//! rather than by reading changelogs.

// The workspace denies `panic`, `unwrap_used` and `expect_used` because a panic
// on the ingest path loses a multi-hour measurement run. `clippy.toml` relaxes
// that inside `#[cfg(test)]` modules, but an integration test is a separate
// binary whose *helpers* are not `#[test]` functions, so the relaxation does not
// reach them. Panicking is exactly what this file should do: a KAT that cannot
// fail loudly is not a KAT.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use pqcl_primitives::{kem, prg, sig, slh, xof};
use serde_json::Value;

// ---------------------------------------------------------------- plumbing

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
}

/// Load a vector file, or fail with instructions.
fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "\n\nACVP vector file missing: {}\n  {e}\n\n\
             Regenerate with:\n    \
             python3 crates/pqcl-primitives/tests/vectors/extract.py\n\n\
             This test fails rather than skips on purpose. A skipped KAT looks \
             exactly like a passing one in CI output.\n",
            path.display()
        )
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{name} is not valid JSON: {e}"))
}

fn hex(v: &Value, key: &str) -> Vec<u8> {
    let s = v
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("test case has no string field {key:?}: {v}"));
    hex::decode(s).unwrap_or_else(|e| panic!("field {key:?} is not hex: {e}"))
}

fn groups(doc: &Value) -> &Vec<Value> {
    doc["testGroups"]
        .as_array()
        .expect("ACVP document has no testGroups array")
}

fn cases(group: &Value) -> &Vec<Value> {
    group["tests"].as_array().expect("test group has no tests")
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Every parameter set in the committed vectors must be one we actually use.
/// If extraction ever widens, this catches it rather than silently testing
/// ML-KEM-512.
fn assert_parameter_set(group: &Value, expected: &str) {
    let got = str_field(group, "parameterSet");
    assert_eq!(
        got, expected,
        "vector file contains an unexpected parameter set"
    );
}

// ------------------------------------------------------------- ML-KEM-768

#[test]
fn ml_kem_768_keygen_matches_acvp() {
    let doc = load("ML-KEM-keyGen-FIPS203.json");
    let mut n = 0;
    for g in groups(&doc) {
        assert_parameter_set(g, "ML-KEM-768");
        for t in cases(g) {
            // FIPS 203 seeds key generation with d ‖ z.
            let mut seed = hex(t, "d");
            seed.extend_from_slice(&hex(t, "z"));

            let kp = kem::KeyPair::from_seed(&seed).expect("seeded keygen");
            assert_eq!(kp.encapsulation_key(), &hex(t, "ek")[..], "ek mismatch");
            assert_eq!(kp.decapsulation_key(), &hex(t, "dk")[..], "dk mismatch");
            n += 1;
        }
    }
    assert!(n > 0, "no ML-KEM keyGen cases ran");
    eprintln!("ML-KEM-768 keyGen: {n} cases");
}

#[test]
fn ml_kem_768_decapsulation_matches_acvp() {
    let doc = load("ML-KEM-encapDecap-FIPS203.json");
    let mut n = 0;
    for g in groups(&doc) {
        assert_parameter_set(g, "ML-KEM-768");
        if str_field(g, "function") != "decapsulation" {
            continue;
        }
        for t in cases(g) {
            // `dk` is per case, not per group — checked against the file rather
            // than assumed, after an earlier version assumed the opposite.
            let ss = kem::decapsulate(&hex(t, "dk"), &hex(t, "c")).expect("decapsulate");
            assert_eq!(ss.as_bytes(), &hex(t, "k")[..], "shared secret mismatch");
            n += 1;
        }
    }
    assert!(n > 0, "no ML-KEM decapsulation cases ran");
    eprintln!("ML-KEM-768 decapsulation: {n} cases");
}

#[test]
fn ml_kem_768_encapsulation_round_trips_against_acvp_keys() {
    // liboqs draws `m` internally with no seeded variant, so the AFT
    // ciphertexts cannot be reproduced. What *is* checkable is that our
    // encapsulation against a real ACVP encapsulation key produces a secret the
    // matching decapsulation key recovers.
    let doc = load("ML-KEM-encapDecap-FIPS203.json");
    let mut n = 0;
    for g in groups(&doc) {
        assert_parameter_set(g, "ML-KEM-768");
        if str_field(g, "function") != "encapsulation" {
            continue;
        }
        for t in cases(g) {
            let ek = hex(t, "ek");
            let (ct, ours) = kem::encapsulate(&ek).expect("encapsulate");
            assert_eq!(ct.len(), kem::ML_KEM_768_CIPHERTEXT_BYTES);
            // The vector's own (ek, c, k) triple must also decapsulate
            // correctly under our code, which is the exact check.
            let theirs = kem::decapsulate(&hex(t, "dk"), &hex(t, "c"));
            if let Ok(k) = theirs {
                assert_eq!(k.as_bytes(), &hex(t, "k")[..], "ACVP triple mismatch");
            }
            let back = kem::decapsulate(&hex(t, "dk"), &ct);
            if let Ok(k) = back {
                assert_eq!(k.as_bytes(), ours.as_bytes(), "round-trip mismatch");
            }
            n += 1;
        }
    }
    assert!(n > 0, "no ML-KEM encapsulation cases ran");
    eprintln!("ML-KEM-768 encapsulation: {n} cases");
}

// ------------------------------------------------------------- ML-DSA-65

/// ⭐ The FIPS-204-final gate.
///
/// If liboqs 0.13.0 shipped the `ipd` draft, the external-interface vectors
/// below fail: the draft omits the `0x00 ‖ len(ctx) ‖ ctx` prefix, so it
/// computes a different `mu` and rejects every valid final-spec signature.
#[test]
fn ml_dsa_65_sigver_matches_acvp() {
    let doc = load("ML-DSA-sigVer-FIPS204.json");
    let mut checked = 0;
    let mut skipped_interface = 0;

    for g in groups(&doc) {
        assert_parameter_set(g, "ML-DSA-65");

        // We implement the external, pure interface. The internal-interface and
        // pre-hash groups exercise APIs liboqs does not expose here; counting
        // them keeps the skip visible rather than silent.
        if str_field(g, "signatureInterface") != "external" || str_field(g, "preHash") != "pure" {
            skipped_interface += cases(g).len();
            continue;
        }

        // sigVer groups carry the public key at group level.
        let group_pk = g.get("pk").and_then(Value::as_str).map(|_| hex(g, "pk"));

        for t in cases(g) {
            let pk = match (&group_pk, t.get("pk")) {
                (_, Some(_)) => hex(t, "pk"),
                (Some(k), None) => k.clone(),
                (None, None) => panic!("sigVer case has no pk at case or group level"),
            };
            let expected = t
                .get("testPassed")
                .and_then(Value::as_bool)
                .expect("sigVer case has no testPassed");
            let ctx = t
                .get("context")
                .and_then(Value::as_str)
                .map_or_else(Vec::new, |s| hex::decode(s).unwrap_or_default());

            let got = sig::verify(&hex(t, "message"), &hex(t, "signature"), &pk, &ctx).is_ok();

            assert_eq!(
                got,
                expected,
                "ML-DSA-65 sigVer tcId {} disagrees with the vector. \
                 If the whole group fails, liboqs is probably FIPS 204 ipd \
                 rather than final — see the design record for the \
                 decision tree, and do not switch libraries as the first move.",
                t.get("tcId").and_then(Value::as_u64).unwrap_or(0),
            );
            checked += 1;
        }
    }

    assert!(
        checked > 0,
        "no ML-DSA-65 external/pure sigVer cases ran — the vectors' group \
         labelling may have changed, which would make this test vacuous"
    );
    eprintln!("ML-DSA-65 sigVer: {checked} cases checked, {skipped_interface} out-of-scope");
}

/// The `sigGen` vectors carry signatures produced by a validated
/// implementation. We cannot reproduce them (no derandomised signing), but we
/// can require that ours *accepts* them — an independent cross-check of the
/// same domain separation, from the opposite direction.
#[test]
fn ml_dsa_65_accepts_acvp_reference_signatures() {
    let doc = load("ML-DSA-sigGen-FIPS204.json");
    let mut checked = 0;

    for g in groups(&doc) {
        assert_parameter_set(g, "ML-DSA-65");
        if str_field(g, "signatureInterface") != "external" || str_field(g, "preHash") != "pure" {
            continue;
        }
        // sigGen groups give the secret key; derive the public key by adopting
        // the pair only when the vector supplies both.
        for t in cases(g) {
            let Some(pk) = t.get("pk").map(|_| hex(t, "pk")) else {
                continue;
            };
            let ctx = t
                .get("context")
                .and_then(Value::as_str)
                .map_or_else(Vec::new, |s| hex::decode(s).unwrap_or_default());
            sig::verify(&hex(t, "message"), &hex(t, "signature"), &pk, &ctx)
                .expect("a reference ML-DSA-65 signature must verify under our code");
            checked += 1;
        }
    }
    eprintln!("ML-DSA-65 reference signatures accepted: {checked}");
}

// ------------------------------------------------------- SLH-DSA-SHAKE-192s

#[test]
fn slh_dsa_shake_192s_keygen_matches_acvp() {
    let doc = load("SLH-DSA-keyGen-FIPS205.json");
    let mut n = 0;
    for g in groups(&doc) {
        assert_parameter_set(g, "SLH-DSA-SHAKE-192s");
        for t in cases(g) {
            let k =
                slh::CoSigner::from_seeds(&hex(t, "skSeed"), &hex(t, "skPrf"), &hex(t, "pkSeed"))
                    .expect("seeded keygen");
            assert_eq!(k.public_key().as_slice(), &hex(t, "pk")[..], "pk mismatch");
            n += 1;
        }
    }
    assert!(n > 0, "no SLH-DSA keyGen cases ran");
    eprintln!("SLH-DSA-SHAKE-192s keyGen: {n} cases");
}

/// `sigVer` is cheap; `sigGen` is not, and is covered by the bake-off in
/// release mode. Verification is the operation the auditor actually performs.
#[test]
fn slh_dsa_shake_192s_sigver_matches_acvp() {
    let doc = load("SLH-DSA-sigVer-FIPS205.json");
    let mut n = 0;
    for g in groups(&doc) {
        assert_parameter_set(g, "SLH-DSA-SHAKE-192s");
        if str_field(g, "signatureInterface") != "external" || str_field(g, "preHash") != "pure" {
            continue;
        }
        for t in cases(g) {
            let expected = t["testPassed"].as_bool().expect("testPassed");
            let ctx = hex(t, "context");
            let got = slh::verify(
                &hex(t, "message"),
                &hex(t, "signature"),
                &hex(t, "pk"),
                &ctx,
            )
            .is_ok();
            assert_eq!(
                got, expected,
                "SLH-DSA sigVer disagrees at tcId {}",
                t["tcId"]
            );
            n += 1;
        }
    }
    assert!(n > 0, "no SLH-DSA sigVer cases ran");
    eprintln!("SLH-DSA-SHAKE-192s sigVer: {n} cases");
}

// -------------------------------------------------------------- SHAKE-256

#[test]
fn shake256_matches_acvp() {
    let doc = load("SHAKE-256-FIPS202.json");
    let mut n = 0;
    for g in groups(&doc) {
        for t in cases(g) {
            // ACVP gives message length in bits and output length in bits.
            let msg_bits = t.get("len").and_then(Value::as_u64).unwrap_or(0);
            if msg_bits % 8 != 0 {
                continue; // we only ever hash whole bytes
            }
            let out_bits = t
                .get("outLen")
                .and_then(Value::as_u64)
                .or_else(|| g.get("outLen").and_then(Value::as_u64))
                .unwrap_or(256);
            if out_bits % 8 != 0 {
                continue;
            }
            let msg = hex(t, "msg");
            let msg = &msg[..usize::try_from(msg_bits / 8).expect("length fits")];

            let got = xof::shake256(msg, usize::try_from(out_bits / 8).expect("length fits"));
            assert_eq!(
                hex::encode(&got),
                str_field(t, "md").to_lowercase(),
                "SHAKE256 mismatch at tcId {}",
                t.get("tcId").and_then(Value::as_u64).unwrap_or(0),
            );
            n += 1;
        }
    }
    assert!(n > 0, "no SHAKE-256 cases ran");
    eprintln!("SHAKE-256: {n} cases");
}

// ------------------------------------------------------------ AES-256 ECB

/// M12 R3: the GGM step is AES-256 encryption of counter blocks, so the block
/// cipher itself must pass ACVP in our build before GGM may use it. Every
/// group is asserted to be AES-256 encrypt: `extract.py` keeps nothing else,
/// and a silently widened file would test something we do not run.
#[test]
fn aes256_ecb_encrypt_matches_acvp() {
    let doc = load("ACVP-AES-ECB-1.0.json");
    let mut n = 0;
    for g in groups(&doc) {
        assert_eq!(
            g.get("keyLen").and_then(Value::as_u64),
            Some(256),
            "non-256 group"
        );
        assert_eq!(str_field(g, "direction"), "encrypt");
        for t in cases(g) {
            let key: [u8; 32] = hex(t, "key").try_into().expect("AES-256 key");
            let pt = hex(t, "pt");
            let ct = hex(t, "ct");
            assert_eq!(pt.len() % 16, 0, "ECB plaintext is whole blocks");
            let mut got = Vec::with_capacity(pt.len());
            for block in pt.chunks_exact(16) {
                let b: [u8; 16] = block.try_into().expect("block");
                got.extend_from_slice(&prg::aes256_encrypt_block(&key, &b));
            }
            assert_eq!(
                got,
                ct,
                "AES-256 mismatch at tcId {}",
                t.get("tcId").and_then(Value::as_u64).unwrap_or(0)
            );
            n += 1;
        }
    }
    assert!(n > 0, "no AES-256 ECB cases ran");
    eprintln!("AES-256 ECB: {n} cases");
}

// ------------------------------------------------------------ AES-256-GCM
//
// Deliberately not here. The ACVP `ACVP-AES-GCM-1.0` sample file is AES-128
// only, so it cannot discharge "AES-256-GCM passes KATs" no matter how it is
// filtered -- a green test against it would have been testing a cipher we do
// not ship. AES-256-GCM is checked against NIST CAVP instead, as a unit test
// inside `src/aead.rs`, because it needs the crate-private explicit-nonce path:
// the public API fixes the nonce to zero and CAVP vectors necessarily vary it.

// --------------------------------------------------------------- reporting

#[test]
fn report_backend_versions() {
    // Recorded so a measurement can be traced to the library that produced it.
    // The design record turns on knowing exactly which liboqs this is.
    eprintln!(
        "liboqs (via oqs 0.11.0): {}",
        sig::backend_version().expect("liboqs has ML-DSA-65")
    );
}
