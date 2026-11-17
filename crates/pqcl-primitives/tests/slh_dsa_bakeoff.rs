//! SLH-DSA-SHAKE-192s: two candidate crates, one set of official vectors.
//!
//! The project rules calls the FIPS-205 source *"the most likely
//! silent spec mismatch in the project"*, because liboqs exposes SPHINCS+ —
//! which is **not** FIPS 205 — under a name that looks right. Neither candidate
//! is clean on reputation:
//!
//! | Crate | For | Against |
//! |---|---|---|
//! | `fips205` 0.4.1 | stable release, `no_std`, all 12 parameter sets | makes **no ACVP claim**; self-describes as experimental |
//! | `RustCrypto` `slh-dsa` 0.2.0-rc.5 | actively maintained, MSRV 1.85 | **pre-release**; never independently audited |
//!
//! So the choice is made by evidence rather than reputation: run both against
//! the same ACVP vectors and keep whichever passes. This file is that
//! experiment, kept in the repository as the record of how the decision was
//! made — the build plan requires every baseline and library
//! choice to be stated, not assumed.
//!

//! # Why these tests are `#[ignore]`d
//!
//! This is a **one-time library-selection experiment**, not a correctness gate.
//! Its result is recorded in the build plan and in `src/slh.rs`; the
//! ongoing gate is the winner's SLH-DSA KAT in `tests/kat.rs`, which always
//! runs. Keeping the experiment reproducible matters for artifact evaluation,
//! but re-running it every CI would cost ~20 minutes in a debug build for no
//! new information.
//!
//! Run it with:
//!
//! ```text
//! cargo test --release -p pqcl-primitives --test slh_dsa_bakeoff -- --ignored --nocapture
//! ```
//!
//! **Use `--release`.** `slh-dsa` is heavily generic, so its hot code is
//! monomorphised into *this* crate and compiles at this crate's opt-level —
//! `[profile.dev.package."*"]` never reaches it. Unoptimised it takes tens of
//! minutes; in release the whole file runs in ~40 s.
//!
//! Both crates are `dev-dependencies` while this runs. The winner is promoted to
//! a real dependency behind `src/`; the loser is removed.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;

/// FIPS 205 Table 2, SLH-DSA-SHAKE-192s. `n = 24`.
const PK_BYTES: usize = 48;
const SK_BYTES: usize = 96;
const SIG_BYTES: usize = 16_224;

fn load(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "\n\nACVP vector file missing: {}\n  {e}\n\n\
             Regenerate with:\n    \
             python3 crates/pqcl-primitives/tests/vectors/extract.py\n",
            path.display()
        )
    });
    serde_json::from_slice(&bytes).expect("valid JSON")
}

fn hex(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v.get(k).and_then(Value::as_str).unwrap_or("")).expect("hex")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// The groups we implement: FIPS 205 external interface, no pre-hash.
fn is_external_pure(g: &Value) -> bool {
    s(g, "signatureInterface") == "external" && s(g, "preHash") == "pure"
}

/// The sizes are normative and are asserted first, because a crate compiled for
/// the wrong parameter set would otherwise fail later in a confusing way.
#[test]
fn parameter_set_sizes_are_fips205_shake_192s() {
    assert_eq!(fips205::slh_dsa_shake_192s::PK_LEN, PK_BYTES);
    assert_eq!(fips205::slh_dsa_shake_192s::SK_LEN, SK_BYTES);
    assert_eq!(fips205::slh_dsa_shake_192s::SIG_LEN, SIG_BYTES);
}

// ---------------------------------------------------------------- candidate A

/// `RustCrypto` `slh-dsa` against ACVP keyGen, sigGen and sigVer.
#[test]
#[ignore = "one-time library-selection experiment; see the module docs"]
fn candidate_rustcrypto_slh_dsa() {
    use slh_dsa::{Shake192s, SigningKey, VerifyingKey};

    // ---- keyGen: (skSeed, skPrf, pkSeed) -> (sk, pk)
    let doc = load("SLH-DSA-keyGen-FIPS205.json");
    let mut keygen = 0;
    for g in doc["testGroups"].as_array().expect("groups") {
        assert_eq!(s(g, "parameterSet"), "SLH-DSA-SHAKE-192s");
        for t in g["tests"].as_array().expect("tests") {
            let sk = SigningKey::<Shake192s>::slh_keygen_internal(
                &hex(t, "skSeed"),
                &hex(t, "skPrf"),
                &hex(t, "pkSeed"),
            );
            assert_eq!(sk.to_vec(), hex(t, "sk"), "sk mismatch");
            let vk: &VerifyingKey<Shake192s> = sk.as_ref();
            assert_eq!(vk.to_vec(), hex(t, "pk"), "pk mismatch");
            keygen += 1;
        }
    }

    // ---- sigGen, deterministic external/pure: signature must match exactly
    let doc = load("SLH-DSA-sigGen-FIPS205.json");
    let mut siggen = 0;
    for g in doc["testGroups"].as_array().expect("groups") {
        if !is_external_pure(g) || g.get("deterministic") != Some(&Value::Bool(true)) {
            continue;
        }
        for t in g["tests"].as_array().expect("tests") {
            let sk_bytes = hex(t, "sk");
            let sk = SigningKey::<Shake192s>::try_from(&sk_bytes[..]).expect("parse sk");
            // Deterministic signing: opt_rand = None means PRF(sk_prf, ...) per
            // FIPS 205, which is what `deterministic: true` fixes.
            let sig = sk
                .try_sign_with_context(&hex(t, "message"), &hex(t, "context"), None)
                .expect("sign");
            assert_eq!(
                sig.to_vec(),
                hex(t, "signature"),
                "deterministic signature mismatch at tcId {}",
                t["tcId"]
            );
            siggen += 1;
        }
    }

    // ---- sigVer: accept/reject must match testPassed
    let doc = load("SLH-DSA-sigVer-FIPS205.json");
    let mut sigver = 0;
    for g in doc["testGroups"].as_array().expect("groups") {
        if !is_external_pure(g) {
            continue;
        }
        for t in g["tests"].as_array().expect("tests") {
            let expected = t["testPassed"].as_bool().expect("testPassed");
            let pk_bytes = hex(t, "pk");
            let sig_bytes = hex(t, "signature");

            let got = VerifyingKey::<Shake192s>::try_from(&pk_bytes[..]).is_ok_and(|vk| {
                slh_dsa::Signature::<Shake192s>::try_from(&sig_bytes[..]).is_ok_and(|sig| {
                    vk.try_verify_with_context(&hex(t, "message"), &hex(t, "context"), &sig)
                        .is_ok()
                })
            });
            assert_eq!(got, expected, "sigVer disagrees at tcId {}", t["tcId"]);
            sigver += 1;
        }
    }

    assert!(
        keygen > 0 && siggen > 0 && sigver > 0,
        "bake-off ran nothing"
    );
    eprintln!(
        "RustCrypto slh-dsa 0.2.0-rc.5: PASS  ({keygen} keyGen, {siggen} sigGen, {sigver} sigVer)"
    );
}

// ---------------------------------------------------------------- candidate B

/// `fips205` against the same vectors.
#[test]
#[ignore = "one-time library-selection experiment; see the module docs"]
fn candidate_integritychain_fips205() {
    use fips205::slh_dsa_shake_192s::{PrivateKey, PublicKey};
    use fips205::traits::{KeyGen, SerDes, Signer, Verifier};

    // ---- keyGen
    let doc = load("SLH-DSA-keyGen-FIPS205.json");
    let mut keygen = 0;
    for g in doc["testGroups"].as_array().expect("groups") {
        for t in g["tests"].as_array().expect("tests") {
            let to24 = |k: &str| -> [u8; 24] { hex(t, k).try_into().expect("24-byte seed") };
            let (pk, sk) = fips205::slh_dsa_shake_192s::KG::keygen_with_seeds(
                &to24("skSeed"),
                &to24("skPrf"),
                &to24("pkSeed"),
            );
            assert_eq!(sk.into_bytes().to_vec(), hex(t, "sk"), "sk mismatch");
            assert_eq!(pk.into_bytes().to_vec(), hex(t, "pk"), "pk mismatch");
            keygen += 1;
        }
    }

    // ---- sigGen, deterministic external/pure
    let doc = load("SLH-DSA-sigGen-FIPS205.json");
    let mut siggen = 0;
    for g in doc["testGroups"].as_array().expect("groups") {
        if !is_external_pure(g) || g.get("deterministic") != Some(&Value::Bool(true)) {
            continue;
        }
        for t in g["tests"].as_array().expect("tests") {
            let sk_bytes: [u8; SK_BYTES] = hex(t, "sk").try_into().expect("sk length");
            let sk = PrivateKey::try_from_bytes(&sk_bytes).expect("parse sk");
            // `hedged = false` is FIPS 205 deterministic signing.
            let sig = sk
                .try_sign(&hex(t, "message"), &hex(t, "context"), false)
                .expect("sign");
            assert_eq!(
                sig.to_vec(),
                hex(t, "signature"),
                "deterministic signature mismatch at tcId {}",
                t["tcId"]
            );
            siggen += 1;
        }
    }

    // ---- sigVer
    let doc = load("SLH-DSA-sigVer-FIPS205.json");
    let mut sigver = 0;
    for g in doc["testGroups"].as_array().expect("groups") {
        if !is_external_pure(g) {
            continue;
        }
        for t in g["tests"].as_array().expect("tests") {
            let expected = t["testPassed"].as_bool().expect("testPassed");
            let pk_bytes: Result<[u8; PK_BYTES], _> = hex(t, "pk").try_into();
            let sig_bytes: Result<[u8; SIG_BYTES], _> = hex(t, "signature").try_into();

            let got = match (pk_bytes, sig_bytes) {
                (Ok(p), Ok(sg)) => PublicKey::try_from_bytes(&p)
                    .is_ok_and(|pk| pk.verify(&hex(t, "message"), &sg, &hex(t, "context"))),
                _ => false,
            };
            assert_eq!(got, expected, "sigVer disagrees at tcId {}", t["tcId"]);
            sigver += 1;
        }
    }

    assert!(
        keygen > 0 && siggen > 0 && sigver > 0,
        "bake-off ran nothing"
    );
    eprintln!("fips205 0.4.1: PASS  ({keygen} keyGen, {siggen} sigGen, {sigver} sigVer)");
}
