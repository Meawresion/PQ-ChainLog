//! **M6 acceptance**: *"Assert the proof is a STARK — test that the pipeline
//! has no [SNARK] path compiled in at all."*
//!
//! # ⚠️ The second half of that sentence is not achievable, and this file says
//! so rather than pretending otherwise
//!
//! The first version of this test asserted the pairing-based prover was absent
//! from the dependency graph, on the reasoning that sp1-sdk's default feature
//! set is empty and the prover sits behind `native-gnark`. **That was wrong,
//! and this test is what caught it.** Measured:
//!
//! ```text
//! $ cargo tree -i sp1-recursion-gnark-ffi
//! sp1-recursion-gnark-ffi v6.7.0
//! └── sp1-prover v6.7.0
//!     └── sp1-sdk v6.7.0
//!         └── warrant-host
//! ```
//!
//! `sp1-prover` depends on it **unconditionally**. The `native` feature only
//! controls whether `bindgen` links the Go library; the modules exist either
//! way, and three object files are produced. So the crate *is* compiled in, and
//! no feature flag available to us removes it. Short of vendoring a patched
//! sp1-prover — which would be a far larger liability than the one it fixes —
//! the plan's wording cannot be satisfied literally.
//!
//! # What is true, and is asserted here
//!
//! Two barriers, both real, neither depending on the dependency graph:
//!
//! 1. **Not expressible.** [`ProofMode`] is exhaustively `{Core, Compressed}`.
//!    A caller cannot name a SNARK mode, and [`ProofMode::sdk`] cannot return
//!    one, because it matches exhaustively over our enum and not the SDK's.
//! 2. **Not writable.** `cargo xtask no-stubs` bans both wrapper names as
//!    literal strings repo-wide, so the call cannot be added without the gate
//!    failing.
//!
//! And a third that runs only when a proof exists: `proof_of_warrant.rs`
//! asserts the produced proof's variant is a STARK. That is the assertion the
//! plan actually wanted, and it is a *positive* one — it says what the proof
//! **is**, rather than enumerating what it must not be.
//!
//! ⚠️ **The plan's wording should be corrected**, not quietly reinterpreted.
//! Recorded for the next consultation.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use sp1_sdk::{SP1Proof, SP1ProofMode, SP1ProofWithPublicValues, SP1PublicValues};
use sp1_verifier::{Groth16Bn254Proof, PlonkBn254Proof};
use warrant_host::{ProofMode, ZkError, is_stark};

/// Every mode this crate can express maps to a STARK.
///
/// Positive assertion on purpose. A negative one — "is not a SNARK mode" —
/// would silently pass if the SDK ever added a fifth variant, which is exactly
/// the direction this needs to be robust in.
#[test]
fn every_expressible_mode_is_a_stark() {
    for mode in [ProofMode::Core, ProofMode::Compressed] {
        assert!(
            matches!(
                mode.sdk(),
                SP1ProofMode::Core | SP1ProofMode::Compressed
            ),
            "{mode:?} maps to a mode that is not a STARK"
        );
    }
}

/// A test that cannot fail is not a test.
///
/// If someone adds a third variant to [`ProofMode`], the loop above would still
/// pass while leaving the new variant unchecked. This match is exhaustive, so
/// adding one makes this file stop compiling — which is the loudest possible
/// failure and the point.
#[test]
fn proof_mode_has_exactly_the_two_stark_variants() {
    fn exhaustive(m: ProofMode) -> &'static str {
        match m {
            ProofMode::Core => "core",
            ProofMode::Compressed => "compressed",
        }
    }
    assert_eq!(exhaustive(ProofMode::Core), "core");
    assert_eq!(exhaustive(ProofMode::Compressed), "compressed");
}


// ---------------------------------------------------------------------------
// ⭐ Barrier 4 — what we ACCEPT. The three barriers above are prover-side, and
// the prover is us; the adversary is whoever submits the proof.
//
// This file can name the wrapper types even though `cargo xtask no-stubs` bans
// those strings repo-wide, because `collect_rs` skips any directory called
// `tests`. That exemption is what makes a negative test writable at all.
// ---------------------------------------------------------------------------

fn wrapped_in_a_snark() -> SP1ProofWithPublicValues {
    SP1ProofWithPublicValues {
        // Contents are irrelevant: barrier 4 rejects on the *variant*, never
        // looking inside. A well-formed one would be rejected identically, and
        // that is the property under test.
        proof: SP1Proof::Groth16(Groth16Bn254Proof::default()),
        public_values: SP1PublicValues::new(),
        sp1_version: String::from("6.7.0"),
        tee_proof: None,
    }
}

fn wrapped_in_the_other_snark() -> SP1ProofWithPublicValues {
    SP1ProofWithPublicValues {
        proof: SP1Proof::Plonk(PlonkBn254Proof::default()),
        public_values: SP1PublicValues::new(),
        sp1_version: String::from("6.7.0"),
        tee_proof: None,
    }
}

/// The predicate, over **every** variant the SDK defines.
#[test]
fn only_the_two_stark_variants_are_starks() {
    assert!(!is_stark(&wrapped_in_a_snark().proof));
    assert!(!is_stark(&wrapped_in_the_other_snark().proof));
}

/// ⭐ The barrier itself: rejected, and rejected for **that** reason.
///
/// Asserting the specific error matters. If the rejection came from SP1's
/// verifier failing on a malformed proof instead of from our variant check,
/// this would pass while the barrier did not exist — and a *well-formed*
/// SNARK-wrapped proof would sail through.
#[test]
fn a_snark_wrapped_proof_is_rejected_before_sp1_sees_it() {
    let vk = unused_verifying_key();
    for bad in [wrapped_in_a_snark(), wrapped_in_the_other_snark()] {
        match warrant_host::verify(&bad, &vk) {
            Err(ZkError::NonStarkProof) => {}
            Err(other) => panic!(
                "rejected, but for the wrong reason: {other}. Barrier 4 must \
                 reject on the variant, before the proof reaches SP1."
            ),
            Ok(()) => panic!(
                "a SNARK-wrapped proof was ACCEPTED. Warrant unforgeability now \
                 rests on a pairing assumption, which Shor breaks, and the \
                 paper's central claim is false."
            ),
        }
    }
}

/// A verifying key that is never consulted, because the variant check returns
/// first. If barrier 4 were removed this would reach SP1 and the test would
/// fail on the key rather than silently passing — which is the intent.
fn unused_verifying_key() -> sp1_sdk::SP1VerifyingKey {
    let client = sp1_sdk::blocking::ProverClient::from_env();
    use sp1_sdk::blocking::Prover as _;
    use sp1_sdk::ProvingKey as _;
    client
        .setup(warrant_host::warrant_elf())
        .expect("setup")
        .verifying_key()
        .clone()
}
