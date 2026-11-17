//! ⭐ **M13 A14's acceptance: every harness `TRANSFER` goes through `handoff`.**
//!
//! Two halves, because either alone passes for the wrong reason:
//!
//! * **behaviour** — a stream's transfers, built through [`CaseBuilder`],
//!   really are bilateral: two records over one descriptor, the release
//!   counter-signed, the receipt re-verifying `d_ev`, and `in_transit` empty
//!   once the pair is complete;
//! * **the sources** — no harness calls `append_record` with
//!   `Event::Transfer`, which is how all of them used to produce a "transfer":
//!   two ordinary records that happened to be adjacent, with no descriptor
//!   binding `(from, to)` and nothing re-verified. draft8 §3a's bilateral claim
//!   rested on code no measurement ran.
//!
//! The source half is a reading test, so it carries its own true positive and
//! it refuses to pass over an empty universe — the project rules.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use pqcl_capsule::{ActorOpening, Capsule, CustodyRecord, Event, Role};
use pqcl_exp::appender::InProcess;
use pqcl_exp::case::CaseBuilder;
use pqcl_exp::cast::Cast;
use pqcl_exp::custody_stream::{StreamParams, custody_stream};
use pqcl_pipeline::CaseKeys;
use pqcl_pipeline::handoff::{OpenChain, in_transit};
use pqcl_primitives::aead::CustodyKey;
use pqcl_primitives::xof::{PrfKey, digest256};

const TS_BASE: u64 = 1_757_000_000;

/// ⭐ Two parties (`(role, id)` enrolment, §1br.4): every release is the
/// evidence store's and every receipt the lab custodian's, both in the
/// custodian role. Until this change one custodian identity signed both.
fn two_custodians<K>(openings: &std::collections::HashMap<K, (bool, ActorOpening)>) {
    for (receipt, a) in openings.values() {
        let expected = if *receipt {
            pqcl_sm::lab_custodian()
        } else {
            pqcl_sm::evidence_store()
        };
        assert_eq!(
            a.role,
            Role::Custodian,
            "a transfer half outside the custodian role"
        );
        assert_eq!(
            a.id, expected.id,
            "a transfer half signed by the wrong custodian"
        );
    }
    assert!(
        openings.values().any(|(r, _)| *r) && openings.values().any(|(r, _)| !*r),
        "the fixture has no complete pair, so the check above saw one side only"
    );
}

/// Whether a record carries `σ_witness`, which since §1br F2 is inside `C_rec`.
fn witnessed(r: &CustodyRecord, key: &CustodyKey) -> bool {
    r.open(key).expect("open").sigs.witness.is_some()
}

#[test]
fn a_streams_transfers_are_bilateral_pairs() {
    let stream = custody_stream(&StreamParams {
        capsules: 12,
        ..StreamParams::default()
    });
    let cast = Cast::generate().expect("keygen");
    let keys = CaseKeys::derive(&PrfKey::new(digest256(b"K")), b"case", &digest256(b"r"));
    let appender = InProcess::new(&cast, &keys);
    let mut build = CaseBuilder::new(&appender, &keys);

    let mut capsules: Vec<Capsule> = Vec::new();
    let mut transfers = 0;
    // The openings of each transfer half, by `(capsule, position)`: what the
    // custodian check below reads, since a commitment alone cannot say who.
    let mut openings = std::collections::HashMap::new();
    for (i, e) in stream.iter().enumerate() {
        if e.event == Event::Collect {
            let nonce = digest256(&e.capsule.to_le_bytes());
            let capsule = build
                .seal(nonce, digest256(b"cm"), digest256(&nonce), b"x", b"p", 0)
                .expect("seal");
            capsules.push(capsule.clone());
            build.insert_capsule(e.capsule, capsule);
        }
        let oid = digest256(b"sweep");
        let a = build
            .feed(e, TS_BASE + i as u64, 0, Some(&oid))
            .unwrap_or_else(|err| panic!("event {i} ({:?}): {err}", e.event));
        if e.event == Event::Transfer {
            openings.insert((e.capsule, e.seq), (e.receipt, a.signed.actor));
        }
        if e.event == Event::Transfer && e.receipt {
            transfers += 1;
        }
    }
    assert!(
        transfers >= 3,
        "the fixture produced only {transfers} completed transfers; this test \
         would then be asserting about nothing"
    );

    // Every completed pair: both records present, the release witnessed, and
    // the two halves over one descriptor. `in_transit` is the alarm draft8 §3a
    // promises, so an empty answer over a chain whose transfers all completed
    // is the property, not an absence of evidence — the next assertion shows
    // the alarm firing.
    let mut checked = 0;
    for capsule in &capsules {
        let chain = build.chain_of(capsule).expect("the chain is held");
        let body_key = keys.record_body_key(&capsule.eid);
        let open = OpenChain::open(chain, &body_key).expect("open");
        assert!(
            in_transit(&open).is_empty(),
            "a completed stream left a release unmatched"
        );
        for (i, body) in open.bodies.iter().enumerate() {
            if body.event != Event::Transfer {
                continue;
            }
            // A release is at an even offset within its pair: its successor is
            // the receipt, over the same descriptor.
            if let Some(next) = open.bodies.get(i + 1)
                && next.event == Event::Transfer
                && next.params_c == body.params_c
            {
                assert!(
                    witnessed(&chain[i], &body_key),
                    "the release at {i} was not counter-signed, so the transfer \
                     has one signature and not two"
                );
                // ⚠️ **What this does and does not show.** The two halves'
                // `actor_c` differ because each record draws a fresh `r_a`
                // (M13 A2), so this checks the blinds — it cannot tell two
                // custodians from one, and before A2 the message here claimed
                // it could. The openings can, and do below: the two halves are
                // two custodians' since `(role, id)` enrolment (§1br.4).
                assert_ne!(
                    body.actor_c, next.actor_c,
                    "both halves committed the same actor_c: a blind was reused"
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 3, "only {checked} pairs were checked");

    two_custodians(&openings);

    // ⭐ The alarm fires: drop a receipt and `in_transit` reports the release.
    let capsule = capsules.first().expect("a capsule");
    let chain = build.chain_of(capsule).expect("held");
    let body_key = keys.record_body_key(&capsule.eid);
    let cut = chain
        .iter()
        .zip(OpenChain::open(chain, &body_key).expect("open").bodies)
        .position(|(_, b)| b.event == Event::Transfer);
    if let Some(at) = cut {
        let truncated = &chain[..=at];
        let open = OpenChain::open(truncated, &body_key).expect("open");
        assert_eq!(
            in_transit(&open),
            vec![at],
            "a release with its receipt removed is not reported in transit"
        );
    }
}

// ------------------------------------------- the sources: no hand-built pair

/// Every harness that builds custody records — **found, not listed**.
///
/// ⭐ Rule 14. This was a hand-kept list of five paths, which goes stale the
/// first time a harness is added and then passes over the old universe while
/// the new harness writes transfers however it likes. Now: every `.rs` file
/// under `src/bin/` and `examples/` that builds a case (`CaseBuilder`) or a
/// record (`append_record`, `collect_record`, `dispose_record`).
fn harnesses() -> Vec<std::path::PathBuf> {
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for dir in ["src/bin", "examples"] {
        let entries =
            std::fs::read_dir(here.join(dir)).unwrap_or_else(|e| panic!("cannot list {dir}: {e}"));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.extension().is_some_and(|x| x == "rs") {
                let src = std::fs::read_to_string(&path).expect("readable");
                if [
                    "CaseBuilder",
                    "append_record",
                    "collect_record",
                    "dispose_record",
                ]
                .iter()
                .any(|p| src.contains(p))
                {
                    out.push(path);
                }
            }
        }
    }
    out.sort();
    out
}

/// How many source lines after an `append_record` call to look at. A call and
/// its `Event::` argument are within a few lines of each other in every
/// formatting rustfmt produces here.
const WINDOW: usize = 8;

fn offending_lines(src: &str) -> Vec<usize> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if !l.contains("append_record") {
            continue;
        }
        let upto = (i + WINDOW).min(lines.len());
        if lines[i..upto].iter().any(|w| w.contains("Event::Transfer")) {
            out.push(i + 1);
        }
    }
    out
}

#[test]
fn no_harness_appends_a_transfer_record_directly() {
    let found = harnesses();
    // An empty universe would pass vacuously; the three binaries and two
    // profiles that build cases today are the floor, not the list.
    assert!(
        found.len() >= 5,
        "found only {} case-building harnesses: {found:?}",
        found.len()
    );
    let mut checked = 0;
    for path in &found {
        let src = std::fs::read_to_string(path).expect("readable");
        let bad = offending_lines(&src);
        assert!(
            bad.is_empty(),
            "{} appends a TRANSFER record directly at line(s) {bad:?}: a \
             transfer is two records over one descriptor, so it comes from \
             `handoff::release`/`receive` or from `case::unilateral_transfer`, \
             which is named for being the one-party baseline",
            path.display()
        );
        checked += 1;
    }
    assert_eq!(checked, found.len());

    // ⭐ The true positive: the checker must see the pattern it forbids.
    let planted = "    let r = agent.append_record(\n        &keys,\n        &c,\n        \
                   Event::Transfer,\n        &prev,\n        &rp,\n    )?;";
    assert_eq!(
        offending_lines(planted),
        vec![1],
        "the checker cannot see a hand-built transfer even when one is in \
         front of it"
    );
}
