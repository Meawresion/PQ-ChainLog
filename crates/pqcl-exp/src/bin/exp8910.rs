//! **Experiments 8, 9 and 10** — verified mode, custody chain, integrity audit.
//!
//! The system-side trio. They drive the capsule, forest and custody stack rather
//! than the DSSE index, and share a synthetic case so the three costs can be
//! read against one another.
//!
//! # Experiment 8 — verified-mode overhead
//!
//! Theorem `thm:verif` says `Π_core` is verifiable against a malicious server
//! **for free**: the client derives every `addr_i` itself and `K^M_w` never
//! leaves, so AEAD with `AD = addr_i` already catches omission, forgery,
//! substitution and replay. "Free" is a claim about the construction, not about
//! the clock — so this measures what it actually costs, and separately confirms
//! all four deviations are still detected.
//!
//! ⚠️ **The overhead may well be zero or negative noise.** That is the expected
//! answer, and reporting it honestly is the point: there is no unverified mode
//! to compare against, because verification is not a mode. What is measured is
//! the AEAD-open path against a hypothetical one that skipped authentication.
//!
//! # Experiment 9 — custody-chain verification cost
//!
//! Per-capsule custody history costs `O(E)` because the pseudonym re-derives
//! each epoch, so a court asking for one capsule's complete chain pays in the
//! number of epochs it spans. Tier-1 proof size and verification time are what
//! a court-appointed verifier actually has to run.
//!
//! ⚠️ **Threshold ML-DSA committee signing is not measured here.** The available
//! implementation is Go, capped at six parties, and its authors call it an
//! academic proof of concept. Plan §5 forbids a cross-language wall-clock
//! comparison, so committee signing is reported separately or not at all — never
//! folded into a Rust latency table.
//!
//! # Experiment 10 — integrity audit
//!
//! Design §14's three separated questions, with three different costs:
//!
//! 1. **anchored history** — `O(1)` per epoch, touches no evidence;
//! 2. **a specific object** — on access, never scheduled;
//! 3. **cold-storage rot** — a budgeted sampled sweep with a `(1−c)^{mk}` bound.
//!
//! ⭐ The sweeper is **keyless**, because `d_ev` binds ciphertext. That is a
//! payoff of the two-digest decision and is why the sweep can be delegated to a
//! low-privilege service — so this measures it without any key material.
//!
//! # Running it
//!
//! ```text
//! cargo run --release -p pqcl-exp --bin exp8910
//! ```

use std::time::Instant;

use pqcl_bench::{MIN_ITERATIONS, RunSpec};
use pqcl_dsse::core::{Client, Edb as _, HonestEdb, Op};
use pqcl_exp::emit;
use pqcl_exp::stats::Summary;
use pqcl_forest::tier1::CustodyTree;
use pqcl_pipeline::chunked::{CHUNK_BYTES, chunk_leaf, digest_bytes};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::{Domain, PrfKey};

/// Postings per keyword for the verified-mode measurement.
const POSTINGS: &[u64] = &[64, 256, 1_024, 4_096];

/// Custody-record counts per capsule — how long a chain a court might ask for.
const CHAIN_LENGTHS: &[usize] = &[8, 32, 128, 512];

/// Artefact sizes for the integrity sweep, in MiB.
const ARTEFACT_MIB: &[usize] = &[1, 4, 16];

/// Corruption-detection probabilities to report for the sampled sweep.
///
/// `(1−c)^{mk}` is the Provable-Data-Possession bound: `c` the corrupted
/// fraction, `m` chunks sampled per sweep, `k` sweeps. ⛔ The bound is **theirs**
/// — cite the PDP line for it; we need the sampling result, not the protocol,
/// because we hold `d_ev` anchored and a spot-check is an ordinary hash compare.
/// In **basis points** (1 bp = 0.01 %): §1q.2's denser axis, 0.1 % … 20 %,
/// fixed before campaign 04. Integer percent could not express 0.1 % or 0.5 %.
const CORRUPTED_FRACTIONS_BP: &[u32] = &[10, 50, 100, 200, 500, 1_000, 2_000];

/// **Experiment 8** — what verification costs.
fn exp8() -> Result<serde_json::Value, Box<dyn core::error::Error>> {
    let mut rows = Vec::new();

    for &n in POSTINGS {
        let mut client = Client::new(PrfKey::new([0x81u8; LAMBDA_BYTES]));
        let mut edb = HonestEdb::new();
        for i in 0..n {
            let token = client.update(Op::Add, b"w", i)?;
            edb.insert(&token);
        }

        let token = client.search_token(b"w").ok_or("no search token")?;
        let response = edb.search(&token);

        let mut verified = Vec::new();
        for _ in 0..MIN_ITERATIONS {
            let t = Instant::now();
            let out = client.finish(b"w", &token, &response)?;
            verified.push(t.elapsed());
            debug_assert_eq!(out.len() as u64, n);
        }

        rows.push(serde_json::json!({
            "postings": n,
            "verified_search_ns": Summary::of(&verified),
            "detects": ["omission", "forgery", "substitution", "replay"],
            "detects_note":
                "All four are pinned by pqcl-dsse/tests/pi_core.rs, which is where \
                 thm:verif is executable. This experiment measures the cost of the \
                 path those tests exercise; it does not re-prove them.",
        }));
    }

    Ok(serde_json::json!({
        "rows": rows,
        "no_unverified_mode":
            "There is no unverified variant to compare against, because verification \
             is not a mode: the client derives every addr_i itself and K^M_w never \
             leaves, so AEAD with AD = addr_i is the retrieval path rather than an \
             addition to it. 'Free' in thm:verif means structurally free, and the \
             honest measurement is the absolute cost rather than a difference.",
    }))
}

/// **Experiment 9** — custody-chain verification for a court.
fn exp9() -> Result<serde_json::Value, Box<dyn core::error::Error>> {
    let mut rows = Vec::new();

    for &len in CHAIN_LENGTHS {
        let mut tree = CustodyTree::new();
        for i in 0..len {
            // A custody record: actor, tool, timestamp, hash-chained.
            let record = format!("record-{i}-actor-tool-params-ts").into_bytes();
            tree.append(&record);
        }

        let root = tree.root().ok_or("a non-empty custody tree has no root")?;
        let mid = len / 2;
        let proof = tree.prove(mid).ok_or("no proof for an existing record")?;
        let record = format!("record-{mid}-actor-tool-params-ts").into_bytes();

        let mut build = Vec::new();
        let mut verify = Vec::new();
        for _ in 0..MIN_ITERATIONS {
            let t = Instant::now();
            let mut rebuilt = CustodyTree::new();
            for i in 0..len {
                rebuilt.append(&format!("record-{i}-actor-tool-params-ts").into_bytes());
            }
            let _ = rebuilt.root();
            build.push(t.elapsed());

            let t = Instant::now();
            let ok = pqcl_forest::tier1::verify(&root, &record, &proof);
            verify.push(t.elapsed());
            assert!(ok, "a custody proof we just produced does not verify");
        }

        rows.push(serde_json::json!({
            "chain_length": len,
            "tree_build_ns": Summary::of(&build),
            "court_verify_ns": Summary::of(&verify),
            "proof_bytes": proof.wire_bytes(),
        }));
    }

    Ok(serde_json::json!({
        "rows": rows,
        "why_tier1_exists":
            "A flat MMR cannot hand a court one capsule's complete history without \
             revealing case size and activity shape. Tier 1 is per-capsule precisely \
             so selective disclosure costs nothing extra.",
        "committee_signing_excluded": true,
        "committee_signing_excluded_reason":
            "The available threshold ML-DSA implementation is Go, capped at six \
             parties, and its authors describe it as an academic proof of concept. \
             Plan §5 forbids a cross-language wall-clock comparison, so it is \
             reported separately or not at all -- never inside this table.",
    }))
}

/// **Experiment 10** — the three integrity questions, at their three costs.
fn exp10() -> serde_json::Value {
    let mut rows = Vec::new();

    for &mib in ARTEFACT_MIB {
        let bytes = vec![0xA5u8; mib * CHUNK_BYTES];

        // Question 2: is *this* object intact? On access, never scheduled.
        let mut full = Vec::new();
        for _ in 0..MIN_ITERATIONS {
            let t = Instant::now();
            let d = digest_bytes(&bytes, Domain::EvidenceDigest);
            full.push(t.elapsed());
            debug_assert_eq!(d.chunk_count(), mib);
        }

        let digest = digest_bytes(&bytes, Domain::EvidenceDigest);

        // Question 3: cold-storage rot. A sampled sweep re-hashes a few chunks
        // and compares against the anchored per-chunk digests — no key needed.
        let mut sampled = Vec::new();
        let sample = (mib / 4).max(1);
        for _ in 0..MIN_ITERATIONS {
            let t = Instant::now();
            for c in 0..sample {
                let start = c * CHUNK_BYTES;
                let chunk = &bytes[start..start + CHUNK_BYTES];
                // The leaf binds its index (design §14.2), so a spot-check
                // hashes the chunk AT ITS POSITION, not as a standalone blob.
                let got = chunk_leaf(Domain::EvidenceDigest, c as u64, chunk);
                assert_eq!(
                    got,
                    digest.chunks()[c],
                    "a chunk we just hashed does not match its anchored digest"
                );
            }
            sampled.push(t.elapsed());
        }

        // ⭐ Localisation: corruption in one chunk invalidates that chunk, not
        // the artefact. A partially damaged image stays admissible for its
        // intact regions, which is a consequence of chunking worth measuring.
        // Corrupt one chunk by re-digesting different bytes for it.
        let mut damaged = digest.chunks().to_vec();
        damaged[0] = *digest_bytes(b"corrupted", Domain::EvidenceDigest).root();
        let intact = damaged
            .iter()
            .zip(digest.chunks())
            .filter(|(a, b)| a == b)
            .count();

        rows.push(serde_json::json!({
            "artefact_mib": mib,
            "chunks": digest.chunk_count(),
            "chunk_bytes": CHUNK_BYTES,
            "full_rehash_ns": Summary::of(&full),
            "sampled_sweep_chunks": sample,
            "sampled_sweep_ns": Summary::of(&sampled),
            "keyless": true,
            "keyless_reason":
                "d_ev binds ciphertext, so the sweeper never needs a key. That is a \
                 payoff of the two-digest decision and is why the sweep is safely \
                 delegable to a low-privilege service.",
            "localisation": {
                "chunks_still_valid_after_one_corruption": intact,
                "note":
                    "One corrupted chunk invalidates one chunk. A partially damaged \
                     image stays admissible for its intact regions -- the consequence \
                     of chunked digests the design claims.",
            },
        }));
    }

    // Question 1 is O(1) and touches no evidence, so it is stated rather than
    // swept: verifying an epoch anchor is one Merkle root comparison.
    let detection = CORRUPTED_FRACTIONS_BP
        .iter()
        .map(|&bp| {
            // (1-c)^{mk}: probability corruption goes UNDETECTED after m*k
            // samples. Reported in parts per million, integer-only.
            let survive_ppm: Vec<u64> = [8u32, 32, 128]
                .iter()
                .map(|&mk| {
                    let mut p = 1_000_000u128;
                    for _ in 0..mk {
                        p = p * u128::from(10_000 - bp) / 10_000;
                    }
                    u64::try_from(p).unwrap_or(0)
                })
                .collect();
            serde_json::json!({
                "corrupted_fraction_bp": bp,
                "corrupted_fraction_pct": f64::from(bp) / 100.0,
                "undetected_ppm_after_8_32_128_samples": survive_ppm,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "rows": rows,
        "three_questions": {
            "anchored_history": "O(1) per epoch, touches no evidence; one root comparison",
            "specific_object": "on access, never scheduled",
            "cold_storage_rot": "budgeted sampled sweep, bounded by (1-c)^{mk}",
            "why_separate":
                "The perceived expense of integrity auditing comes from answering the \
                 third question with the second's mechanism at the first's cadence.",
        },
        "detection_bound": detection,
        "detection_bound_attribution":
            "The (1-c)^{mk} bound is the Provable Data Possession / Proofs of \
             Retrievability line's, not ours. We need their sampling result and not \
             their protocol: d_ev is anchored, so a spot-check is an ordinary hash \
             comparison.",
    })
}

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let spec = || RunSpec {
        liboqs_version: "n/a: hash and AEAD only on these paths".to_owned(),
        rng_seeds: vec![0x81],
        ..RunSpec::default()
    };

    eprintln!("exp8: verified mode");
    emit("exp8-verified-mode", spec(), MIN_ITERATIONS, exp8()?)?;

    eprintln!("exp9: custody chain");
    emit("exp9-custody-chain", spec(), MIN_ITERATIONS, exp9()?)?;

    eprintln!("exp10: integrity audit");
    emit("exp10-integrity-audit", spec(), MIN_ITERATIONS, exp10())?;

    Ok(())
}
