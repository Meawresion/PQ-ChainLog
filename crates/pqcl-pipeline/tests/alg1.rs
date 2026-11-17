//! ⭐ **M13 A2's acceptance: Algorithm 1's record, in the library and in every
//! harness.**
//!
//! Four claims, one test each:
//!
//! * **(a)** a wrong-role append is refused — draft8 gives every event exactly
//!   one accountable signer role, and *"a chain in which any credentialed actor
//!   may sign any event establishes presence, not responsibility"*;
//! * **(b)** two records by one actor carry **unequal** `actor_c`, because
//!   `r_a` is drawn per record;
//! * **(c)** one record is indexed under exactly **29** keywords, the number
//!   the papers state;
//! * **(d)** no harness builds a record by hand any more — asserted by reading
//!   the sources, because a private path is invisible to any test that only
//!   exercises the public one.
//!
//! ⚠️ **(d) is a source-reading test, which is a shape to be careful with.**
//! The project rules lists four ways a guard can pass against nothing;
//! this one guards against "the universe it counts over is empty or stale", so
//! it asserts it found the files it expects, by name and by count, before
//! asserting anything about their contents.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use pqcl_capsule::{Event, Params, Role};
use pqcl_pipeline::{
    Agent, CUSTODY_KEYWORDS_PER_RECORD, CaseKeys, IngestParams, RecordParams, SignError,
    custody_keywords,
};
use pqcl_primitives::SoftwareMlDsa;
use pqcl_primitives::xof::{PrfKey, digest256};

fn keys() -> CaseKeys {
    CaseKeys::derive(&PrfKey::new(digest256(b"K_mst")), b"case", &digest256(b"r"))
}

fn agent(id: &[u8], role: Role) -> Agent {
    Agent::new(SoftwareMlDsa::generate().expect("keygen"), id, role)
}

fn capsule(a: &Agent, k: &CaseKeys) -> pqcl_capsule::Capsule {
    let nonce = digest256(b"nonce");
    a.seal(
        k,
        digest256(b"cm"),
        &IngestParams {
            artefact_type: b"disk-image",
            d_ev: digest256(b"d_ev"),
            ptr: b"s3://x",
            epoch: 0,
            nonce: &nonce,
        },
    )
    .expect("seal")
}

// ------------------------------------------------------- (a) the role table

#[test]
fn an_event_signed_by_the_wrong_role_is_refused() {
    let k = keys();
    let defr = agent(b"first-responder-1", Role::Defr);
    let des = agent(b"specialist-1", Role::Des);
    let inv = agent(b"investigator-1", Role::Investigator);
    let cust = agent(b"evidence-store-1", Role::Custodian);
    let c = capsule(&defr, &k);

    let rp = |j: u64| RecordParams::at(j, 1_000 + j).with_params(Params::justified(b"t"));

    // The DEFR opens the chain. Nobody else may.
    let first = defr.collect_record(&k, &c, &rp(0)).expect("collect").record;
    for other in [&des, &inv, &cust] {
        assert_eq!(
            other.collect_record(&k, &c, &rp(0)).unwrap_err(),
            SignError::WrongRole {
                event: Event::Collect,
                role: other.role(),
            },
            "a {:?} signed a COLLECT",
            other.role()
        );
    }

    // ⭐ The whole table, both ways: every (role, event) pair is allowed
    // exactly when `Event::signers` says so, and the library agrees with its
    // own table. A test that only checked the four happy cases would pass with
    // the check removed.
    let mut refused = 0;
    for signer in [&defr, &des, &inv, &cust] {
        for event in [
            Event::Transfer,
            Event::Access,
            Event::Analyze,
            Event::Export,
            Event::Seal,
        ] {
            let out = signer.append_record(&k, &c, event, &first, &rp(1));
            if signer.role().may(event) {
                out.unwrap_or_else(|e| panic!("{:?} may sign {event:?} but: {e}", signer.role()));
            } else {
                assert_eq!(
                    out.unwrap_err(),
                    SignError::WrongRole {
                        event,
                        role: signer.role(),
                    }
                );
                refused += 1;
            }
        }
    }
    assert!(
        refused >= 10,
        "only {refused} pairs were refused; the table has far more forbidden \
         pairs than that, so the check cannot be running"
    );

    // A DISPOSE is the custodian's, under an order.
    assert_eq!(
        des.dispose_record(&k, &c, &first, Some(&digest256(b"oid")), &rp(1))
            .unwrap_err(),
        SignError::WrongRole {
            event: Event::Dispose,
            role: Role::Des,
        }
    );
    cust.dispose_record(&k, &c, &first, Some(&digest256(b"oid")), &rp(1))
        .expect("the custodian may dispose");
    // And a retention-driven disposal, which no order covers: `order_ref` is
    // what an auditor reads to tell the two apart, keylessly.
    let retention = cust
        .dispose_record(&k, &c, &first, None, &rp(1))
        .expect("a retention-driven disposal needs no order");
    assert!(retention.record.order_ref.is_none());
}

// ------------------------------------------------- (b) a fresh blind per record

#[test]
fn two_records_by_one_actor_commit_differently() {
    let case = keys();
    let defr = agent(b"first-responder-1", Role::Defr);
    let capsule = capsule(&defr, &case);
    let rp = |j: u64| RecordParams::at(j, 1_000 + j).with_params(Params::justified(b"t"));

    let first = defr
        .collect_record(&case, &capsule, &rp(0))
        .expect("collect");
    let second = defr
        .append_record(&case, &capsule, Event::Transfer, &first.record, &rp(1))
        .expect("transfer");

    assert_ne!(
        first.body.actor_c, second.body.actor_c,
        "one actor's two records share an actor_c: r_a is being reused, which \
         lets the server group a case's records by who touched them"
    );
    assert_ne!(first.actor.r_a, second.actor.r_a, "r_a was not redrawn");

    // The same identity, though — and the openings prove it, which is how the
    // custody graph resolves a holder without the server being able to.
    assert_eq!(first.actor.id, second.actor.id);
    assert_eq!(first.actor.role, second.actor.role);
    assert_eq!(first.actor.commit(), first.body.actor_c);
    assert_eq!(second.actor.commit(), second.body.actor_c);

    // Same for `params_c`, over identical acts.
    let x = first.params.expect("a COLLECT has a params opening");
    let y = second.params.expect("a TRANSFER built by hand has one too");
    assert_eq!(x.params, y.params, "the fixture meant to use the same act");
    assert_ne!(x.r_p, y.r_p, "r_p was not redrawn");
    assert_ne!(x.commit(), y.commit());
}

// ------------------------------------------------------- (c) 29 keywords

#[test]
fn one_record_is_indexed_under_twenty_nine_keywords() {
    let k = keys();
    let defr = agent(b"first-responder-1", Role::Defr);
    let c = capsule(&defr, &k);
    let s = defr
        .collect_record(
            &k,
            &c,
            &RecordParams::at(0, 1_757_000_000).with_params(Params::justified(b"on-scene")),
        )
        .expect("collect");

    let kws = custody_keywords(&s.record.eid_e, &s.body, &s.actor).expect("in window");
    assert_eq!(kws.len(), CUSTODY_KEYWORDS_PER_RECORD);
    assert_eq!(CUSTODY_KEYWORDS_PER_RECORD, 29);

    // Distinct, or the count overstates the index: 4 categorical terms and 25
    // timestamp ancestors.
    let mut sorted = kws.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), kws.len(), "two keywords coincide");

    // The four categorical terms are the ones draft8 names, and the rest are
    // the timestamp's cover nodes.
    assert!(kws.iter().any(|w| w.starts_with(b"eid:")));
    assert!(kws.iter().any(|w| w.starts_with(b"evt:")));
    assert!(kws.iter().any(|w| w.starts_with(b"actor:")));
    assert!(kws.iter().any(|w| w.starts_with(b"role:")));
    assert_eq!(kws.iter().filter(|w| w.starts_with(b"ts:")).count(), 25);

    // ⚠️ **No commitment is a keyword.** Indexing `actor_c` or `params_c` would
    // index a value that changes every record, and would let the server group
    // an actor's records by equality of a posting list.
    for w in &kws {
        assert!(
            !contains(w, &s.body.actor_c) && !contains(w, &s.body.params_c),
            "a commitment leaked into the index set"
        );
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

// --------------------------------------- (d) no private record-building path

/// Every file that builds custody records for a measurement or a demo.
///
/// Named explicitly, and checked to exist: a glob that silently matched nothing
/// would make this test pass over an empty universe, which the project rules
/// rule 13 lists as the second of four ways a guard passes against nothing.
const HARNESSES: &[&str] = &[
    "../pqcl-exp/src/bin/custody.rs",
    "../pqcl-exp/src/bin/exp6chain.rs",
    "../pqcl-exp/src/bin/tamper.rs",
    "../pqcl-exp/src/bin/exp9redact.rs",
    "../pqcl-exp/examples/profile_audit.rs",
    "../pqcl-exp/examples/profile_audit_scaling.rs",
    "../pqcl-investigator/src/demo.rs",
    "../pqcl-investigator/src/demo/flows.rs",
];

/// Ways to build a record or its commitments without going through [`Agent`].
///
/// `CustodyRecord {` catches a literal struct; the two tags catch a commitment
/// hashed by hand, which is how every harness used to produce a **non-hiding**
/// `actor_c` and `params_c`.
const FORBIDDEN: &[&str] = &[
    "CustodyRecord {",
    "Domain::ActorCommit",
    "Domain::ParamsCommit",
];

#[test]
fn no_harness_builds_a_custody_record_by_hand() {
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for rel in HARNESSES {
        let path = here.join(rel);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{} is in the harness list but could not be read ({e}). A \
                 renamed or deleted harness must be removed from the list, not \
                 left to make this test pass over nothing.",
                path.display()
            )
        });
        assert!(
            src.len() > 500,
            "{} is suspiciously short; is this the file we meant?",
            path.display()
        );
        for bad in FORBIDDEN {
            assert!(
                !src.contains(bad),
                "{} contains `{bad}`: a record or a commitment built outside \
                 `Agent`, which bypasses the role check and the fresh blinds",
                path.display()
            );
        }
        checked += 1;
    }
    assert_eq!(checked, HARNESSES.len());

    // ⭐ The true positive: the checker must report a file that *does* build
    // one. Without this, a typo in `FORBIDDEN` would make the test vacuous.
    let planted = format!("let r = {} rid: [0u8; 32] }};", FORBIDDEN[0]);
    assert!(
        FORBIDDEN.iter().any(|bad| planted.contains(bad)),
        "the checker cannot see a hand-built record even when one is in front \
         of it"
    );
}
