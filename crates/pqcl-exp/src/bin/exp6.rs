//! **Experiment 6** — anchoring cost, and the message-length sweep.
//!
//! Carries the on-chain feasibility claim: whether post-quantum anchoring is
//! affordable at a realistic cadence.
//!
//! # The sweep design, and why it is not evenly spaced
//!
//! ⭐ **Sample at `136k − 1`, `136k` and `136k + 1` for several `k`.**
//!
//! On-chain ML-DSA verification is not a fixed charge. The NIST variant derives
//! `mu` by absorbing `tr ‖ M'` through a Solidity SHAKE256, which consumes the
//! message in 136-byte rate blocks — so cost carries a term in the *number of
//! absorbed blocks*, and possibly a second term in the raw byte count (memory
//! expansion, copying).
//!
//! Evenly spaced samples **cannot separate those two terms**: both grow with the
//! message, so a fit will attribute the whole slope to whichever term it was
//! asked about. The triples separate them because only the block count changes
//! across a boundary, and only a per-byte term changes within one. `136k − 1`
//! and `136k` sit in different blocks one byte apart; `136k` and `136k + 1` sit
//! in the same block.
//!
//! ⚠️ **We already know a two-parameter block model does not fit.** Fitting
//! `c0 + c1·ceil((m + pad)/136)` to the three ACVP conformance lengths leaves a
//! residual of half a block at both security levels, and an exhaustive search
//! over `pad ∈ [0, 4096)` finds no value that fits. How many parameters the data
//! actually supports is therefore something this sweep must establish, not
//! assume. That is why it records raw `(length, gas)` pairs and fits nothing.
//!
//! # What this binary measures, and what it cannot
//!
//! ⛔ **Gas is measured by Foundry, not here.** `contracts/test/GasProfile.t.sol`
//! drives the deployed verifier and reports `gasleft()` deltas; a Rust process
//! cannot observe EVM gas. This binary measures the **client side** of anchoring
//! — building the epoch MMR, producing the anchor message, signing it with
//! ML-DSA-65, and the auditor's proof size and verification time — and emits the
//! anchor lengths the Solidity sweep must then be run over.
//!
//! ⚠️ **Private-chain figures only.** A QBFT chain has no blob market, so
//! nothing here extrapolates to a public rollup or an EIP-4844 cost.
//!
//! ⚠️ **Calldata is reported separately from compute.** The level-III signature
//! is 3309 B against level II's 2420 B, so calldata alone grows by ~889 × 16 gas
//! before any verification work happens. The breakdown is what lets a reviewer
//! check the `k·l` scaling instead of taking a total on trust.
//!
//! # Running it
//!
//! ```text
//! cargo run --release -p pqcl-exp --bin exp6
//! ```
//!
//! Needs no corpus: the workload is epoch sizes, which are ours to choose.

use std::time::Instant;

use pqcl_bench::{MIN_ITERATIONS, RunSpec};
use pqcl_exp::{emit, stats::Summary};
use pqcl_forest::tier2::{Leaf, Mmr};
use pqcl_pipeline::checkpoint;
use pqcl_primitives::sig::SoftwareMlDsa;
use pqcl_primitives::xof::{Domain, digest256};

/// SHAKE256 rate in bytes: the 1600-bit state minus 2×256 bits of capacity.
/// This is the block size the sweep straddles.
const SHAKE256_RATE: usize = 136;

/// How many block boundaries to straddle. Each contributes three lengths.
const BOUNDARY_COUNT: usize = 12;

/// Repetitions for the signing measurement specifically.
///
/// ⭐ **ML-DSA signing is rejection-sampled, so its cost is a distribution with
/// a genuinely long tail, not a constant.** A signature is retried until the
/// candidate passes the norm checks, and the number of retries varies per
/// attempt. Ten repetitions over that gave medians bouncing between 51 and
/// 125 µs across epoch sizes that do *no different signing work at all* — the
/// message is a 32-byte root either way, so the whole spread was the sampler.
///
/// A hundred is still cheap (~10 ms) and makes the median mean something. This
/// is above [`MIN_ITERATIONS`], never below it — §12's floor is a floor.
const SIGN_ITERATIONS: u32 = 100;

/// Leaves per epoch, swept to find the anchoring cadence's cost.
///
/// These are the batch sizes the amortized per-entry figure is computed over:
/// a larger epoch amortises one signature and one on-chain write across more
/// evidence, at the cost of a longer window before anything is anchored.
const EPOCH_SIZES: &[usize] = &[64, 256, 1_024, 4_096, 16_384];

/// The lengths the Solidity sweep must be run over.
///
/// ⭐ Built as triples around each block boundary rather than a linear range.
/// `136k − 1` and `136k` differ by one byte and one **block**; `136k` and
/// `136k + 1` differ by one byte and **no** block. A model with a per-block term
/// and a per-byte term predicts different gaps for those two pairs, so the pair
/// of gaps identifies both coefficients — which evenly spaced samples cannot do.
fn boundary_lengths() -> Vec<usize> {
    let mut out = Vec::new();
    for k in 1..=BOUNDARY_COUNT {
        let boundary = k * SHAKE256_RATE;
        // `-1` is skipped for k where it would collide with a previous `+1`;
        // at rate 136 that never happens, but the dedup below makes the
        // property hold rather than depend on the constant.
        out.push(boundary - 1);
        out.push(boundary);
        out.push(boundary + 1);
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The leaf at index `i`.
///
/// ⭐ **One definition, used by both the builder and the verifier.** The first
/// version built leaves with alternating domains and then reconstructed the one
/// under test as `CapsuleSeal` unconditionally — so the proof was checked
/// against a leaf that had never been in the tree, and verification failed. The
/// assertion caught it immediately, which is the argument for asserting rather
/// than merely recording that a proof verified.
///
/// Alternating domains matter: a real epoch mixes capsule seals, custody roots
/// and index commitments, and a tree filled with one kind would not exercise the
/// domain separation that keeps them from being reinterpreted as each other.
fn leaf_at(i: usize) -> Leaf {
    let domain = match i % 3 {
        0 => Domain::CapsuleSeal,
        1 => Domain::CustodyRoot,
        _ => Domain::IndexEpoch,
    };
    Leaf::new(domain, &[&i.to_le_bytes()])
}

/// Build an epoch MMR of `n` leaves and return it.
fn build_epoch(n: usize) -> Mmr {
    let mut mmr = Mmr::new();
    for i in 0..n {
        mmr.append(&leaf_at(i));
    }
    mmr
}

/// Measure one epoch size: root computation, signing, proof size, verification.
fn measure_epoch(n: usize, signer: &SoftwareMlDsa) -> Result<serde_json::Value, String> {
    let mut root_samples = Vec::new();
    let mut sign_samples = Vec::new();
    let mut verify_samples = Vec::new();

    // Built once: the tree is the workload, not the thing being timed.
    let mmr = build_epoch(n);
    let root = mmr.root().ok_or("an epoch MMR with leaves has no root")?;

    // What a custodian signs (draft8 Phase 7 Step 3): the checkpoint d_e over
    // this root, 32 bytes whatever the epoch holds. It is approved off chain;
    // no signature goes on chain (D4).
    let anchor_message = checkpoint::checkpoint(
        &digest256(b"exp6 cid"),
        1,
        &root,
        n as u64,
        &digest256(b"exp6 reg"),
    )
    .to_vec();
    let signature = signer
        .sign_with_context(&anchor_message, checkpoint::APPROVAL_CONTEXT)
        .map_err(|e| format!("signing the checkpoint: {e}"))?;

    // An inclusion proof for a leaf in the middle: proof length varies with
    // position, and the middle is representative rather than best or worst.
    let proof = mmr
        .prove((n / 2) as u64)
        .ok_or("no inclusion proof for a leaf that exists")?;
    let proof_bytes = proof.wire_bytes();
    let leaf = leaf_at(n / 2);

    for _ in 0..MIN_ITERATIONS {
        let t = Instant::now();
        let rebuilt = build_epoch(n);
        let _ = rebuilt.root();
        root_samples.push(t.elapsed());

        // The auditor's side: this must be practical for a court-appointed and
        // possibly non-specialist verifier, which is why it is measured at all.
        let t = Instant::now();
        let ok = pqcl_forest::tier2::verify(&root, &leaf, &proof);
        verify_samples.push(t.elapsed());
        assert!(ok, "an inclusion proof we just produced does not verify");
    }

    // Signing is measured in its own loop, at its own repetition count, for the
    // reason in `SIGN_ITERATIONS`. It does not depend on the epoch size — the
    // message is a 32-byte root regardless — so it is timed once per epoch
    // only to confirm that independence rather than to discover it.
    for _ in 0..SIGN_ITERATIONS {
        let t = Instant::now();
        let _ = signer
            .sign_with_context(&anchor_message, checkpoint::APPROVAL_CONTEXT)
            .map_err(|e| format!("signing the checkpoint: {e}"))?;
        sign_samples.push(t.elapsed());
    }

    Ok(serde_json::json!({
        "leaves": n,
        "mmr_build_and_root_ns": Summary::of(&root_samples),
        "anchor_sign_ns": Summary::of(&sign_samples),
        "anchor_sign_iterations": SIGN_ITERATIONS,
        "anchor_sign_note":
            "ML-DSA signing is rejection-sampled, so this is a distribution with \
             a long tail rather than a constant. Measured at a higher repetition \
             count than the rest for that reason; the spread is the sampler, not \
             the epoch size.",
        "auditor_verify_inclusion_ns": Summary::of(&verify_samples),
        "anchor_message_bytes": anchor_message.len(),
        "signature_bytes": signature.len(),
        "inclusion_proof_bytes": proof_bytes,
        // ⭐ Amortization is the decision this experiment informs — one
        // signature and one chain write per epoch, spread over however much
        // evidence the epoch held — but the *ratio* is deliberately not
        // computed here. A results record carries measurements; `mkfigs.py`
        // derives presentation values from them. Emitting a rounded float would
        // put a derived number in the record where a reader would take it for
        // an observation, and it would lose the exact integers it came from.
    }))
}

/// The anchor's gas, carried out of Foundry.
///
/// ⛔ **Without this the number has no path to the paper.** `tab:exp6` rests on
/// one measured quantity — what a single anchor transaction costs — and it is
/// measured in Solidity, where `cargo xtask contracts` checks pass/fail and
/// discards every figure to `console.log`. A campaign would have run `forge`,
/// seen it pass, and produced no gas number at all. Same shape as the carve-out
/// record the pipeline could not reach: a measurement with nowhere to go.
///
/// ⚠️ **Absent is `None`, never a default.** A plausible constant here would be
/// indistinguishable from a measurement, and `mkfigs.py` refuses and names the
/// cells it cannot fill only if the record admits the field is missing.
fn anchor_gas() -> Option<serde_json::Value> {
    let path = std::path::Path::new("contracts/out/anchor-gas.json");
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<serde_json::Value>(&text).ok()
}

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let signer = SoftwareMlDsa::generate()?;

    let mut epochs = Vec::new();
    for &n in EPOCH_SIZES {
        eprintln!("epoch of {n} leaves");
        epochs.push(measure_epoch(n, &signer)?);
    }

    // ⭐ Emitted as a *specification for the Solidity sweep*, not as a
    // measurement. Gas belongs to Foundry; this binary's job is to fix the
    // lengths so the two halves of Exp. 6 cannot disagree about what was swept.
    let lengths = boundary_lengths();

    let measurements = serde_json::json!({
        "epochs": epochs,
        "solidity_sweep_spec": {
            "rate_bytes": SHAKE256_RATE,
            "lengths": lengths,
            "design": "triples at 136k-1, 136k, 136k+1",
            "design_reason":
                "Evenly spaced samples cannot separate a per-block term from a \
                 per-byte one, because both grow with the message. Across a \
                 boundary only the block count changes; within a block only a \
                 per-byte term does. The pair of gaps identifies both.",
            "known_misfit":
                "A two-parameter model c0 + c1*ceil((m+pad)/136) fitted to the \
                 three ACVP conformance lengths leaves a half-block residual at \
                 both levels, and no pad in [0,4096) removes it. How many \
                 parameters the data supports is for this sweep to establish.",
        },
        // ⭐ Read from Foundry's output rather than re-measured here, and the
        // provenance says so: this crate cannot run the EVM, and a second
        // implementation of the anchor's cost would be a second thing to
        // diverge from the contract that actually ships.
        "anchor_gas": anchor_gas(),
        "anchor_gas_source":
            "contracts/out/anchor-gas.json, written by              contracts/test/GasProfile.t.sol::test_GasProfile_AnchorCommit. Run              `cargo xtask contracts` first; null here means it was not run, not              that the anchor is free.",
        "scope": {
            "gas_measured_here": false,
            "gas_measured_by": "contracts/test/GasProfile.t.sol",
            "chain": "private QBFT; no blob market, so nothing extrapolates to a public rollup",
            "calldata_reported_separately": true,
        },
    });

    emit(
        "exp6-anchoring-cost",
        RunSpec {
            liboqs_version: "ML-DSA-65 via liboqs; see the KAT suite for the FIPS 204 evidence"
                .to_owned(),
            rng_seeds: vec![],
            ..RunSpec::default()
        },
        MIN_ITERATIONS,
        measurements,
    )?;

    Ok(())
}
