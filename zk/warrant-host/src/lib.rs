//! The SP1 host: prove and verify the warrant relation.
//!
//! ```text
//! issue  : CA inserts C = H(0x30 ‖ ⟪warrant, s⟫) into the warrant tree
//! spend  : investigator proves R_auth and registers (N, scopeCommit) on chain
//! record : contract rejects a spent N, emits SearchAuthorised(N, scopeCommit)
//! verify : the AIS checks π_auth **and binds it to that event**
//! ```
//!
//! ⭐ **Who verifies, settled by the design record.** The **AIS**,
//! not the investigator's own Secure Module. The threat is a rogue
//! investigator, and a module that verifies its own operator's proof is
//! trustworthy only *through* remote attestation — a strictly stronger
//! assumption than needed when the AIS can simply check the proof itself.
//! Design §7b already said this; §7b′ contradicted it.
//!
//! # ⛔ STARK proofs only — this is the post-quantum claim
//!
//! SP1 can wrap a STARK in either of two SNARKs to shrink on-chain
//! verification. **Both wrappers are pairing-based**, so either one silently
//! reintroduces an assumption Shor breaks — into the single component whose
//! purpose (design §7b) is to keep the system free of algebraic assumptions.
//! Nothing would fail. The proofs would verify. The claim would simply be
//! false.
//!
//! ⚠️ **The prover IS linked, and we cannot remove it.** `sp1-prover` depends
//! on the pairing-based FFI crate unconditionally — verified with
//! `cargo tree -i`, not assumed — so the plan's *"no path compiled in at all"*
//! is not achievable without vendoring a patched SP1. `tests/stark_only.rs`
//! records the measurement and the reasoning.
//!
//! The property to hold is **not** *"no pairing-based code is linked"* — that
//! was never true and cannot be made true. It is *"no pairing-based assumption
//! is load-bearing"*. Four barriers, and note which side each guards:
//!
//! | # | Barrier | Guards |
//! |---|---|---|
//! | 1 | [`ProofMode`] exhaustively `{Core, Compressed}` | what we *express* |
//! | 2 | `cargo xtask no-stubs` bans both wrapper names repo-wide | what we *write* |
//! | 3 | emitted proof's variant asserted to **be** a STARK | what we *produce* |
//! | 4 | ⭐ [`verify`] rejects any other variant **before** SP1 sees it | what we ***accept*** |
//!
//! ⭐ **Barrier 4 is the one that matters, and the first three do not imply
//! it.** They are all prover-side, and the prover is us. The adversary in
//! `R_auth` is whoever submits `π_auth` — an investigator, or someone
//! impersonating one. A verifier that simply dispatched on the proof's own
//! variant would accept a SNARK-wrapped proof quite happily, at which point
//! forging a warrant costs a **pairing break rather than a hash break**, and
//! draft6's *"introduces no algebraic assumption … keeps the 'nothing Shor
//! breaks' property across the whole system"* is false.
//!
//! ⛔ **There is no Solidity half of barrier 4** — corrected 2026-09-12,
//! The design record. An earlier version of this comment said the
//! check "is required again in the M7 anchoring contract". That assumed the
//! contract verifies the proof. It does not and cannot, so it never receives a
//! proof object and has no variant to inspect. The only way to imitate one
//! there is a **submitter-declared `mode` field**, which the submitter chooses
//! — satisfying the letter of barrier 4 while providing none. Barrier 4 lives
//! entirely here, where a real proof exists.
//!
//! # Why the relation is not implemented here either
//!
//! [`pqcl_warrant::relation::check`] is the one implementation, shared with the
//! guest. This crate only moves data across the zkVM boundary.

use pqcl_warrant::relation::{Statement, Witness};
// The **blocking** SDK. `sp1_sdk::ProverClient::from_env` is `async` in 6.x, and
// an async runtime in the test harness would buy nothing here: proving is a
// long CPU-bound call, not a concurrency problem.
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{
    Elf, ProvingKey, SP1Proof, SP1ProofMode, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
    include_elf,
};

/// The guest, compiled to `riscv32im-succinct-zkvm-elf` by `build.rs`.
///
/// A function rather than a `const` because `include_elf!` yields an owned
/// [`Elf`] and both `setup` and `execute` take one by value.
#[must_use]
pub fn warrant_elf() -> Elf {
    include_elf!("warrant-guest")
}

/// Which STARK to produce.
///
/// ⭐ **There is deliberately no SNARK variant, and none may be added.** See the
/// module docs: adding one is a two-line change that would void the paper's
/// central claim without failing a single test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMode {
    /// Core STARK. Fastest to produce, largest to carry.
    Core,
    /// Recursively compressed STARK. Constant size, still hash-based.
    Compressed,
}

impl ProofMode {
    /// Map to the SDK's mode.
    ///
    /// ⚠️ This `match` is exhaustive over [`ProofMode`], not over
    /// [`SP1ProofMode`] — which is the point. The SDK's enum *does* carry the
    /// two pairing-based wrappers; ours does not, so there is no arm here that
    /// could reach them and no way for a caller to ask for one.
    ///
    /// Public so `tests/stark_only.rs` can assert that property directly rather
    /// than inferring it.
    #[must_use]
    pub const fn sdk(self) -> SP1ProofMode {
        match self {
            Self::Core => SP1ProofMode::Core,
            Self::Compressed => SP1ProofMode::Compressed,
        }
    }
}

/// What can go wrong.
#[derive(Debug)]
pub enum ZkError {
    /// The guest panicked, which is how an unsatisfied relation surfaces: SP1
    /// emits no proof for a guest that panics, so a false statement yields
    /// nothing rather than a proof of itself.
    Execution(String),
    /// Proving failed.
    Proving(String),
    /// The proof did not verify.
    Verification(String),
    /// The proof verified, but against a different statement than expected.
    StatementMismatch,
    /// ⭐ The proof was valid, but it proves a *different* statement than the
    /// one the chain published.
    ///
    /// This is the binding failure, and it is the one that matters. Verifying
    /// `π_auth` and reading `SearchAuthorised` are two unrelated facts until
    /// something checks they are the same fact; without that an investigator
    /// registers scope X publicly and proves scope Y privately, so the public
    /// record documents a search that never happened while concealing the one
    /// that did.
    BindingMismatch {
        /// Which field of the statement disagreed.
        field: &'static str,
    },
    /// ⭐ The submitted proof is not a STARK, so it was rejected **without**
    /// being handed to SP1's verifier.
    ///
    /// Its own variant is the only thing consulted. Accepting it would mean
    /// warrant unforgeability rested on a pairing assumption instead of a hash
    /// one — silently, because the proof would verify.
    NonStarkProof,
}

impl core::fmt::Display for ZkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Execution(m) => write!(f, "guest execution failed: {m}"),
            Self::Proving(m) => write!(f, "proving failed: {m}"),
            Self::Verification(m) => write!(f, "verification failed: {m}"),
            Self::BindingMismatch { field } => write!(
                f,
                "the proof is valid but its {field} differs from the registered authorisation"
            ),
            Self::StatementMismatch => {
                f.write_str("proof verified against a different statement than expected")
            }
            Self::NonStarkProof => f.write_str(
                "submitted proof is not a STARK; rejected before verification, because \
                 accepting it would rest warrant unforgeability on a pairing assumption",
            ),
        }
    }
}

impl std::error::Error for ZkError {}

/// Serialize the guest's inputs in the order `main` reads them.
fn stdin_for(witness: &Witness, warrant_root: [u8; 32], epoch: u64) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(witness);
    stdin.write(&warrant_root);
    stdin.write(&epoch);
    stdin
}

/// Run the guest **without proving**, returning the statement it commits.
///
/// This is the cheap check, and it is a real one: it exercises the same
/// `relation::check` the circuit runs, over the same serialized witness, and
/// returns the committed statement so a caller can assert on it. What it does
/// not do is produce a proof.
///
/// # ⚠️ An unsatisfied relation does not surface as `Err` from the SDK
///
/// Found by the negative tests, not assumed. When the guest panics — which is
/// how `relation::check` failing manifests — `ExecuteRequest::run()` still
/// returns `Ok`, carrying the public values written **so far**, which is none.
/// `SP1PublicValues::read` then panics with `UnexpectedEof` rather than
/// returning an error.
///
/// So the empty buffer is checked explicitly here. Reading first and hoping
/// turns a clean "the relation did not hold" into a panic in the caller's
/// process, several frames from the cause.
///
/// # Errors
///
/// [`ZkError::Execution`] if the guest failed, including the case where it
/// committed nothing.
pub fn execute(
    witness: &Witness,
    warrant_root: [u8; 32],
    epoch: u64,
) -> Result<Statement, ZkError> {
    let client = ProverClient::from_env();
    let stdin = stdin_for(witness, warrant_root, epoch);
    let (mut public_values, _report) = client
        .execute(warrant_elf(), stdin)
        .run()
        .map_err(|e| ZkError::Execution(e.to_string()))?;

    if public_values.as_slice().is_empty() {
        return Err(ZkError::Execution(
            "the guest committed no public values, so R_auth did not hold"
                .to_owned(),
        ));
    }
    Ok(public_values.read::<Statement>())
}

/// Whether `proof` is one of the two STARK variants.
///
/// A **positive** predicate. The negative form — "is not one of the SNARK
/// variants" — would silently start accepting anything SP1 adds in a future
/// release, which is the direction this has to be robust in.
#[must_use]
pub const fn is_stark(proof: &SP1Proof) -> bool {
    matches!(proof, SP1Proof::Core(_) | SP1Proof::Compressed(_))
}

/// ⭐ **Barrier 4.** Verify a proof submitted by someone else.
///
/// The variant is checked **first**, and SP1's verifier is not called at all if
/// the check fails. Order is the whole point: SP1 will happily verify a
/// SNARK-wrapped proof, so a verifier that called it first and inspected the
/// variant afterwards — or not at all — would accept a proof whose soundness
/// rests on BN254 pairings.
///
/// This is the verifier an index server or a court auditor uses. [`prove`]
/// routes through it too, so there is exactly one accept path.
///
/// # Errors
///
/// [`ZkError::NonStarkProof`] if the proof is not a STARK, or
/// [`ZkError::Verification`] if it is one and does not verify.
pub fn verify(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
) -> Result<(), ZkError> {
    if !is_stark(&proof.proof) {
        return Err(ZkError::NonStarkProof);
    }
    ProverClient::from_env()
        .verify(proof, vk, None)
        .map_err(|e| ZkError::Verification(e.to_string()))
}

/// Prove `R_auth`, then verify the proof before returning it.
///
/// Verifying here rather than leaving it to the caller is deliberate: a
/// `prove` that returns an unverified proof invites a caller to treat the
/// absence of an error as success.
///
/// # Errors
///
/// [`ZkError::Proving`] or [`ZkError::Verification`].
pub fn prove(
    witness: &Witness,
    warrant_root: [u8; 32],
    epoch: u64,
    mode: ProofMode,
) -> Result<(SP1ProofWithPublicValues, SP1VerifyingKey), ZkError> {
    let client = ProverClient::from_env();
    let stdin = stdin_for(witness, warrant_root, epoch);
    let pk = client
        .setup(warrant_elf())
        .map_err(|e| ZkError::Proving(e.to_string()))?;

    let proof = client
        .prove(&pk, stdin)
        .mode(mode.sdk())
        .run()
        .map_err(|e| ZkError::Proving(e.to_string()))?;

    // Through the public verifier, not `client.verify`, so the barrier-4 variant
    // check covers proofs we produce as well as proofs we receive. One accept
    // path; a second one is a second place to forget the check.
    let vk = pk.verifying_key().clone();
    verify(&proof, &vk)?;

    Ok((proof, vk))
}

/// Read the statement a verified proof commits to.
///
/// ⚠️ **Verification alone is not authorisation.** An accepting proof says
/// *some* statement was proved; the verifier must then check it is the
/// statement it cares about — this root, this epoch, this nullifier. Skipping
/// that would accept a valid proof of an irrelevant claim.
pub fn committed_statement(proof: &mut SP1ProofWithPublicValues) -> Statement {
    proof.public_values.read::<Statement>()
}

/// What the chain published, plus the AIS's own view of it.
///
/// ⭐ **This is the other half of the fact.** `authoriseSearch` emits
/// `SearchAuthorised(N, scopeCommit)`; the proof commits a [`Statement`]. Each
/// is meaningless about the other until compared, which is what
/// [`verify_authorised`] does.
///
/// `nullifier` and `scope_commit` come from the event. `warrant_root` and
/// `epoch` do **not** — the event does not carry them, and they come from the
/// AIS's own view of the anchored chain. Taking them from the submitter would
/// let a stale warrant root be replayed against a current registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchAuthorisation {
    /// `N`, as published by `SearchAuthorised`.
    pub nullifier: [u8; 32],
    /// `scopeCommit = H(0x33 ‖ ⟪scope(q)⟫)`, as published by `SearchAuthorised`.
    pub scope_commit: [u8; 32],
    /// `ρ_W`, the anchored warrant-tree root the AIS currently accepts.
    pub warrant_root: [u8; 32],
    /// The epoch the AIS currently accepts.
    pub epoch: u64,
}

/// Check that a proved statement is the statement the chain published.
///
/// Split out from [`verify_authorised`] so it is testable without producing a
/// proof — proving does not fit on a developer box (the design record
/// row 14), and a binding check that could only be exercised on AWS would in
/// practice never be exercised.
///
/// # Errors
///
/// [`ZkError::BindingMismatch`] naming the field that disagreed.
pub fn check_binding(
    statement: &Statement,
    published: &SearchAuthorisation,
) -> Result<(), ZkError> {
    // Ordered most-specific first so the reported field is the informative one
    // when several disagree.
    if statement.nullifier.0 != published.nullifier {
        return Err(ZkError::BindingMismatch { field: "nullifier" });
    }
    if statement.scope_digest != published.scope_commit {
        return Err(ZkError::BindingMismatch {
            field: "scope digest",
        });
    }
    if statement.warrant_root != published.warrant_root {
        return Err(ZkError::BindingMismatch {
            field: "warrant root",
        });
    }
    if statement.epoch != published.epoch {
        return Err(ZkError::BindingMismatch { field: "epoch" });
    }
    Ok(())
}

/// ⭐ **The AIS's entry point: verify `π_auth` and bind it to the chain.**
///
/// The design record settled that the AIS does this, not the
/// investigator's Secure Module, and that **the binding is the load-bearing
/// step**. [`verify`] alone establishes only that *some* statement was proved.
///
/// Returns the bound statement, so a caller cannot act on an authorisation it
/// has not seen.
///
/// # Errors
///
/// [`ZkError::NonStarkProof`] at barrier 4, [`ZkError::Verification`] if the
/// proof does not verify, or [`ZkError::BindingMismatch`] if it proves
/// something other than what was registered.
pub fn verify_authorised(
    proof: &mut SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    published: &SearchAuthorisation,
) -> Result<Statement, ZkError> {
    verify(proof, vk)?;
    let statement = committed_statement(proof);
    check_binding(&statement, published)?;
    Ok(statement)
}
