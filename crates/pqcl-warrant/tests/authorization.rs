//! **M6's stated acceptance criteria**, made executable.
//!
//! The build plan (M6): *"out-of-scope query is refused by the SM;
//! a plane-`EV` warrant cannot derive a custody trapdoor; nullifier
//! double-spend is rejected; SP1 proof verifies."*
//!
//! The first three live here. The SP1 clause lives in the guest's own tests,
//! because it needs the zkVM toolchain.
//!
//! ⚠️ **"Refused" is the plan's word and it undersells the property.** draft6
//! §V-D requires *underivable*, which is strictly stronger and is what these
//! tests assert: the failure comes from `pqcl-ggm` finding no key, not from a
//! policy branch in our code that a compromised caller could skip.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use pqcl_primitives::sig::{Signer, SoftwareMlDsa};
use pqcl_primitives::xof::{Digest32, PrfKey};
use pqcl_sm::Plane;
use pqcl_warrant::delegate::{DelegationError, PlaneRoot};
use pqcl_warrant::{KeywordClass, Nullifier, NullifierLedger, Scope, SpendError, Warrant};

/// Distinct, labelled fixture values.
///
/// Derived from a label rather than a fill byte, because the disclosure test
/// once failed on `[n; 32]` patterns making one field equal another — a fixture
/// whose values collide cannot distinguish a real leak from a coincidence.
fn fixture(label: &str) -> Digest32 {
    pqcl_primitives::xof::digest256(label.as_bytes())
}

/// `K_case` for a named case.
fn case_key(label: &str) -> PrfKey {
    PrfKey::new(fixture(label))
}

fn warrant(plane: Plane, lo: u64, hi: u64, expiry: u64) -> Warrant {
    Warrant {
        inv_id: fixture("inv_id"),
        cid_c: fixture("cid_c"),
        role: 3,
        scope: Scope::new(plane, lo, hi).expect("valid scope"),
        window: (1_000, 2_000),
        expiry,
        nonce: fixture("nonce"),
    }
}

// ---------------------------------------------------------------------------
// Acceptance 1 — an out-of-scope class is underivable.
// ---------------------------------------------------------------------------

#[test]
fn a_class_outside_the_warrant_has_no_key_at_all() {
    let root = PlaneRoot::derive(&case_key("case-A"), Plane::Evidence);
    let d = root
        .delegate(&warrant(Plane::Evidence, 10, 20, 99))
        .expect("delegate");

    for inside in [10, 15, 20] {
        assert!(
            d.trapdoor(KeywordClass(inside)).is_ok(),
            "class {inside} is inside [10,20] and must be derivable"
        );
    }
    for outside in [9, 21, 0, u64::MAX] {
        assert!(
            d.trapdoor(KeywordClass(outside)).is_err(),
            "class {outside} is outside [10,20]; the delegated key must not \
             produce a trapdoor for it"
        );
    }
}

/// The trapdoor a delegation produces must equal the one the unconstrained root
/// produces. Otherwise scoping would be enforced by producing *wrong* keys
/// rather than no keys — which would look identical in the tests above while
/// silently breaking every in-scope search.
#[test]
fn an_in_scope_trapdoor_matches_the_unconstrained_derivation() {
    let root = PlaneRoot::derive(&case_key("case-A"), Plane::Evidence);

    let wide = root
        .delegate(&warrant(Plane::Evidence, 0, 1_000, 99))
        .expect("delegate");
    let narrow = root
        .delegate(&warrant(Plane::Evidence, 40, 60, 99))
        .expect("delegate");

    for class in [40, 50, 60] {
        assert_eq!(
            wide.trapdoor(KeywordClass(class)).expect("in range"),
            narrow.trapdoor(KeywordClass(class)).expect("in range"),
            "two delegations covering class {class} must agree on its trapdoor"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance 2 — a plane-EV warrant cannot reach the custody plane.
// ---------------------------------------------------------------------------

/// ⭐ Two independent barriers, and both are checked because either alone would
/// be a single point of failure.
#[test]
fn an_evidence_warrant_cannot_derive_a_custody_trapdoor() {
    let ev_root = PlaneRoot::derive(&case_key("case-A"), Plane::Evidence);
    let coc_root = PlaneRoot::derive(&case_key("case-A"), Plane::Custody);

    // Barrier 1: the scope predicate refuses the cross-plane query.
    let ev = warrant(Plane::Evidence, 0, u64::MAX, 99);
    assert!(
        !ev.scope
            .covers(&Scope::single(Plane::Custody, KeywordClass(5))),
        "an evidence warrant must not cover a custody query"
    );

    // Barrier 2: even handed to the custody root, the delegation is refused —
    // so a caller who skipped barrier 1 still gets nothing.
    assert!(
        matches!(
            coc_root.delegate(&ev),
            Err(DelegationError::WrongPlane { .. })
        ),
        "the custody root must refuse to delegate an evidence warrant"
    );

    // And the key material genuinely differs: an evidence delegation's trapdoor
    // for class 5 is not the custody trapdoor for class 5. If the two roots
    // collided, both barriers above could pass while the planes were in fact
    // one keyspace.
    let ev_d = ev_root.delegate(&ev).expect("delegate");
    let coc_d = coc_root
        .delegate(&warrant(Plane::Custody, 0, u64::MAX, 99))
        .expect("delegate");
    assert_ne!(
        ev_d.trapdoor(KeywordClass(5)).expect("in range"),
        coc_d.trapdoor(KeywordClass(5)).expect("in range"),
        "the two planes must not share a keyspace"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 3 — nullifier double-spend is rejected.
// ---------------------------------------------------------------------------

#[test]
fn a_replayed_nullifier_is_rejected_but_a_new_epoch_is_not() {
    let mut ledger = NullifierLedger::new();
    let s = fixture("warrant secret");

    assert_eq!(ledger.spend(Nullifier::new(&s, 7)), Ok(()));
    assert_eq!(
        ledger.spend(Nullifier::new(&s, 7)),
        Err(SpendError::DoubleSpend)
    );
    assert_eq!(ledger.spend(Nullifier::new(&s, 8)), Ok(()));
}

// ---------------------------------------------------------------------------
// The signed-capability half of eq. (eq:relauth).
// ---------------------------------------------------------------------------

#[test]
fn the_authorization_relation_holds_end_to_end() {
    let ca = SoftwareMlDsa::generate().expect("CA keygen");
    let w = warrant(Plane::Evidence, 10, 20, 50);
    let sig = w.sign(&ca).expect("sign");
    let pk = ca.public_key();

    let inside = Scope::new(Plane::Evidence, 12, 18).expect("valid");
    assert!(w.authorizes(pk, &sig, &inside, 49).is_ok());

    // exp > e is strict: a warrant expiring at 50 is void *at* epoch 50.
    // Getting this backwards extends every warrant by an epoch.
    assert!(w.authorizes(pk, &sig, &inside, 50).is_err());
    assert!(w.authorizes(pk, &sig, &inside, 51).is_err());

    let outside = Scope::new(Plane::Evidence, 12, 25).expect("valid");
    assert!(w.authorizes(pk, &sig, &outside, 49).is_err());
}

#[test]
fn a_tampered_warrant_fails_verification() {
    let ca = SoftwareMlDsa::generate().expect("CA keygen");
    let w = warrant(Plane::Evidence, 10, 20, 50);
    let sig = w.sign(&ca).expect("sign");
    let pk = ca.public_key();
    let query = Scope::single(Plane::Evidence, KeywordClass(15));

    // Widening the scope after signing is the attack the signature exists to
    // stop, and it is the one an insider would actually try.
    let mut widened = w.clone();
    widened.scope = Scope::new(Plane::Evidence, 0, u64::MAX).expect("valid");
    assert!(widened.authorizes(pk, &sig, &query, 49).is_err());

    // So is switching plane.
    let mut replaned = w.clone();
    replaned.scope = Scope::new(Plane::Custody, 10, 20).expect("valid");
    assert!(
        replaned
            .authorizes(
                pk,
                &sig,
                &Scope::single(Plane::Custody, KeywordClass(15)),
                49
            )
            .is_err()
    );

    // And extending the expiry.
    let mut extended = w;
    extended.expiry = 9_999;
    assert!(extended.authorizes(pk, &sig, &query, 49).is_err());
}

#[test]
fn a_warrant_from_another_authority_is_rejected() {
    let real = SoftwareMlDsa::generate().expect("keygen");
    let impostor = SoftwareMlDsa::generate().expect("keygen");
    let w = warrant(Plane::Evidence, 10, 20, 50);
    let forged = w.sign(&impostor).expect("sign");

    assert!(
        w.authorizes(
            real.public_key(),
            &forged,
            &Scope::single(Plane::Evidence, KeywordClass(15)),
            49
        )
        .is_err(),
        "a warrant signed by anyone but the Case Authority must be rejected"
    );
}
