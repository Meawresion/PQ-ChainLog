//! The SP1 guest: proof of warrant, `R_auth` of draft6 eq. (`eq:relauth`).
//!
//! Reads the witness `ω` privately, recomputes the statement `x`, checks the
//! relation, and **commits `x` publicly**. Committing the statement the guest
//! itself derived is what binds the proof to it: a guest that read `x` from
//! input and echoed it back would prove nothing about the values the verifier
//! then checks against.
//!
//! ⚠️ **The relation is not implemented here.** It is
//! `pqcl_warrant::relation::check`, the same function the host verifier calls.
//! draft6 requires the rule to hold identically in the circuit and in the
//! verifier, and a divergence there does not fail loudly — it produces proofs
//! that verify against the wrong root.

#![no_main]

sp1_zkvm::entrypoint!(main);

use pqcl_warrant::relation::{Statement, Witness, check, scope_digest};

pub fn main() {
    // Private. Never committed, and the proof reveals nothing about it beyond
    // the truth of the statement — in particular not which warrant, not whose,
    // and not the queried classes.
    let witness = sp1_zkvm::io::read::<Witness>();

    // Public inputs the verifier will supply: the anchored root and the epoch.
    // Everything else in the statement is *derived* below rather than read, so
    // the prover cannot choose it.
    let warrant_root = sp1_zkvm::io::read::<[u8; 32]>();
    let epoch = sp1_zkvm::io::read::<u64>();

    let statement = Statement {
        warrant_root,
        nullifier: pqcl_warrant::Nullifier::new(&witness.secret, epoch),
        epoch,
        scope_digest: scope_digest(&witness.query),
    };

    // The whole circuit. Panicking is the correct failure mode: SP1 produces no
    // proof for a guest that panics, so an unsatisfied relation yields nothing
    // rather than a proof of a false statement.
    check(&statement, &witness).expect("R_auth must hold");

    sp1_zkvm::io::commit(&statement);
}
