//! The binding between `π_auth` and the `SearchAuthorised` event.
//!
//! The design record, the standing rule on who verifies:
//!
//! > **The binding is the load-bearing step, and it was missing from the
//! > proposal.** Verifying the proof and reading the event are two unrelated
//! > facts unless something checks they are the same fact. […] Without it an
//! > investigator registers scope X publicly and proves scope Y privately: the
//! > public record documents a search that never happened while concealing the
//! > one that did — which inverts the property §7b′ exists for. **Test it with
//! > a proof that is individually valid but registered against a different
//! > scope.**
//!
//! That test is [`a_valid_proof_registered_against_a_different_scope_is_refused`].
//!
//! ⭐ **These run through the real zkVM executor, not a hand-built statement.**
//! The statements compared here are the bytes the guest actually committed, so
//! a divergence between what the guest commits and what the AIS reads would
//! fail here rather than pass. Proving itself is deferred to AWS (row 14), and
//! the binding check is deliberately separable from it precisely so it is
//! exercised on every local run.

use pqcl_primitives::xof::{Digest32, digest256};
use pqcl_sm::Plane;
use pqcl_warrant::relation::{Statement, Witness};
use pqcl_warrant::{Scope, Warrant, WarrantTree, tree};
use warrant_host::{SearchAuthorisation, ZkError, check_binding, execute};

fn fixture(label: &str) -> Digest32 {
    digest256(label.as_bytes())
}

struct Case {
    witness: Witness,
    root: Digest32,
    epoch: u64,
}

fn case(query: Scope, epoch: u64) -> Case {
    let warrant = Warrant {
        inv_id: fixture("inv"),
        cid_c: fixture("case"),
        role: 3,
        scope: Scope::new(Plane::Evidence, 10, 20).expect("valid"),
        window: (0, 1_000),
        expiry: 50,
        nonce: fixture("nonce"),
    };
    let secret = fixture("warrant secret");

    let mut t = WarrantTree::new();
    t.insert(fixture("other warrant 0"));
    t.insert(fixture("other warrant 1"));
    let index = t.insert(tree::leaf(&warrant.encode(), &secret));
    t.insert(fixture("other warrant 3"));

    Case {
        witness: Witness {
            warrant,
            secret,
            path: t.path(index).expect("in range"),
            query,
        },
        root: t.root().expect("non-empty"),
        epoch,
    }
}

/// The authorisation the chain would have published for exactly this statement.
fn matching(st: &Statement) -> SearchAuthorisation {
    SearchAuthorisation {
        nullifier: st.nullifier.0,
        scope_commit: st.scope_digest,
        warrant_root: st.warrant_root,
        epoch: st.epoch,
    }
}

#[test]
fn a_statement_binds_to_its_own_registration() {
    let c = case(Scope::new(Plane::Evidence, 12, 18).expect("valid"), 5);
    let st = execute(&c.witness, c.root, c.epoch).expect("relation holds");

    check_binding(&st, &matching(&st)).expect("a statement must bind to its own registration");
}

/// ⭐ **The test §16 asked for.**
///
/// Both proofs are individually valid — each is a real guest execution over a
/// scope the warrant genuinely permits. What differs is only *which* scope was
/// registered on chain. Binding must refuse the pair, or the public record and
/// the private search come apart.
#[test]
fn a_valid_proof_registered_against_a_different_scope_is_refused() {
    // Two distinct sub-ranges, both inside the warrant's 10..20.
    let narrow = case(Scope::new(Plane::Evidence, 12, 14).expect("valid"), 5);
    let wide = case(Scope::new(Plane::Evidence, 15, 19).expect("valid"), 5);

    let proved = execute(&narrow.witness, narrow.root, narrow.epoch).expect("relation holds");
    let registered = execute(&wide.witness, wide.root, wide.epoch).expect("relation holds");

    assert_ne!(
        proved.scope_digest, registered.scope_digest,
        "the fixture is broken: the two scopes must differ for this to test anything"
    );

    // Each is valid against its own registration.
    check_binding(&proved, &matching(&proved)).expect("valid on its own");
    check_binding(&registered, &matching(&registered)).expect("valid on its own");

    // The crossed pair: prove the narrow scope, register the wide one.
    let err = check_binding(&proved, &matching(&registered))
        .expect_err("a proof of one scope must not satisfy a registration of another");

    assert!(
        matches!(err, ZkError::BindingMismatch { field: "scope digest" }),
        "refused for the wrong reason: {err}"
    );
}

/// A nullifier mismatch is the replay direction of the same failure: spend `N₁`
/// on chain, prove `N₂` off it.
#[test]
fn a_proof_carrying_a_different_nullifier_is_refused() {
    let c = case(Scope::new(Plane::Evidence, 12, 18).expect("valid"), 5);
    let st = execute(&c.witness, c.root, c.epoch).expect("relation holds");

    let mut published = matching(&st);
    published.nullifier = fixture("some other nullifier");

    let err = check_binding(&st, &published).expect_err("the nullifier must be bound");
    assert!(
        matches!(err, ZkError::BindingMismatch { field: "nullifier" }),
        "refused for the wrong reason: {err}"
    );
}

/// ⭐ The warrant root and epoch come from the **AIS's** view of the chain, not
/// from the submitter. A stale root that still verifies must not be accepted
/// against a current registration — otherwise a revoked warrant keeps working
/// for as long as its old root is remembered.
#[test]
fn a_stale_warrant_root_is_refused() {
    let c = case(Scope::new(Plane::Evidence, 12, 18).expect("valid"), 5);
    let st = execute(&c.witness, c.root, c.epoch).expect("relation holds");

    let mut published = matching(&st);
    published.warrant_root = fixture("the root after re-issuance");

    let err = check_binding(&st, &published).expect_err("the warrant root must be bound");
    assert!(
        matches!(err, ZkError::BindingMismatch { field: "warrant root" }),
        "refused for the wrong reason: {err}"
    );
}

#[test]
fn a_proof_from_another_epoch_is_refused() {
    let c = case(Scope::new(Plane::Evidence, 12, 18).expect("valid"), 5);
    let st = execute(&c.witness, c.root, c.epoch).expect("relation holds");

    let mut published = matching(&st);
    published.epoch += 1;

    let err = check_binding(&st, &published).expect_err("the epoch must be bound");
    assert!(
        matches!(err, ZkError::BindingMismatch { field: "epoch" }),
        "refused for the wrong reason: {err}"
    );
}
