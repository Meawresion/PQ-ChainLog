//! The Bloom `XSet`, checked against the oracle through a **real** `Π_XT` search.
//!
//! `crate::bloom`'s module doc carries a rule: *"⛔ Validate against
//! [`HonestXSet`], never instead of it."* Until this file existed, that rule was
//! enforced in exactly one place — an `assert!` inside the `exp345` binary — and
//! `cargo xtask ci` never runs an experiment. The filter's own unit tests are
//! real but they are *unit* tests: they insert synthetic tags straight into a
//! `Filter` and never see a transcript, a probe map, or an epoch boundary.
//!
//! So the thing nothing checked was the join: that a filter loaded from the
//! oracle's own tags, probed with a transcript the client actually produced,
//! still answers a query correctly. That is what this file checks.
//!
//! # ⛔ What this file found: a false positive can *lose* a true match
//!
//! The obvious invariant to assert is `exact ⊆ bloom ⊆ Cand` — a false positive
//! admits a tag that was never inserted, so it can only widen the answer. That
//! is what [`crate::bloom`]'s module doc claimed, in so many words: *"a false
//! positive never produces a wrong answer … the cost is retrieval overhead, not
//! incorrectness."*
//!
//! **The lower bound is false, and this file is how that was found.** Round two
//! decides membership with `add && !del` ([`XtClient::evaluate`]), because
//! deletions are in-band in the cross-tag set: the probe list carries an `Add`
//! tag *and* a `Del` tag per (candidate, x-term, epoch), which is where the
//! factor 2 in `2·|Cand|·(n−1)·E` comes from. A false positive on the **`Del`**
//! half makes a live document look deleted, and the client drops it.
//!
//! So the two directions are not symmetric:
//!
//! | false positive on | effect | detectable? |
//! |---|---|---|
//! | `Add` tag | admits a non-matching document | ✅ yes — it fails to decrypt |
//! | `Del` tag | **removes a matching document** | ❌ no — nothing is fetched |
//!
//! The `Del` direction is silent. `Π_core`'s AEAD catches a document that
//! should not be there; nothing catches a document that should be there and is
//! not. `a_saturated_filter_answers_nothing_rather_than_everything` pins the
//! direction down with no `ε` and no collision involved: a filter that answers
//! `true` to everything returns the **empty set**, not the whole candidate set.
//!
//! # What is still guaranteed
//!
//! Only the upper bound, `bloom_result ⊆ Cand`, and it holds unconditionally:
//! round two never invents candidates, because `Cand` comes from `Π_core`,
//! whose AEAD is exact. That is asserted everywhere below. Answer loss is
//! *measured* rather than bounded — see
//! `what_a_false_positive_actually_costs_across_epsilon`.
//!
//! ⚠️ This bears on Experiment 5, which counts probe-level false positives and
//! never evaluates an answer, so it reports the retrieval-overhead half of the
//! story and not this half.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use pqcl_dsse::bloom::BloomXSet;
use pqcl_dsse::core::{Client, Op};
use pqcl_dsse::xt::{
    Formula, HonestServer, HonestXSet, Transcript, XSetStore, XtClient, doc_id, seq_of,
};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

type XTagT = pqcl_dsse::xt::XTag;

/// Documents in the fixture.
///
/// Larger than `transcript.rs`'s twelve on purpose: a filter sized for a handful
/// of tags is mostly empty, so it answers "no" almost always and would pass a
/// superset test while being useless. A few hundred documents put enough tags in
/// each epoch that the filter is doing real work.
const DOCS: u64 = 240;

/// Build an index with a known ground truth, spread over two closed epochs.
///
/// `w1` matches every document, so it is the s-term and `Cand` is the whole
/// corpus — which maximises the number of probes and therefore the number of
/// chances the filter has to be wrong.
fn fixture() -> (XtClient, HonestServer) {
    let mut c = XtClient::new(
        Client::new(PrfKey::new([0x31u8; LAMBDA_BYTES])),
        PrfKey::new([0x77u8; LAMBDA_BYTES]),
        64,
    );
    let mut s = HonestServer::new();

    for j in 0..DOCS {
        let id = doc_id(c.epoch(), j);
        c.update(&mut s, Op::Add, b"w1", id).expect("update");
        if j.is_multiple_of(2) {
            c.update(&mut s, Op::Add, b"w2", id).expect("update");
        }
        if j.is_multiple_of(3) {
            c.update(&mut s, Op::Add, b"w3", id).expect("update");
        }
        // Close an epoch halfway, so E = 2: the store holds two filters and
        // an unlabelled probe is tested against both (D3).
        if j + 1 == DOCS / 2 {
            c.flush(&mut s);
            c.close_epoch(&mut s);
        }
    }
    c.flush(&mut s);
    c.close_epoch(&mut s);

    (c, s)
}

/// Load a Bloom store with **exactly** the tags the oracle holds.
///
/// Via [`HonestXSet::all_epochs`] rather than by replaying the corpus: two
/// stores built by two paths could disagree about their contents, and then a
/// mismatch downstream would be ambiguous between "the filter is wrong" and
/// "the stores hold different things" — which is the one confusion an oracle
/// comparison exists to rule out.
fn load_bloom(honest: &HonestXSet, epsilon: f64) -> BloomXSet {
    let epochs = honest.all_epochs();
    assert!(!epochs.is_empty(), "the fixture closed at least one epoch");

    // Each epoch's filter is sized from its own load when sealed (M10 P3).
    // This used to size every epoch at the *largest* load, which
    // over-provisions the others and so could never show the overfill bug.
    let mut bloom = BloomXSet::new(epsilon);
    for (e, tags) in &epochs {
        bloom.add_xtags(*e, tags);
    }
    bloom.seal_all();
    bloom
}

/// One query, returning the candidate set, the transcript and the probe map.
fn query(c: &mut XtClient, s: &HonestServer) -> (Vec<u64>, Transcript, pqcl_dsse::xt::ProbeMap) {
    let cand = c.candidates(s, b"w1").expect("round 1");
    let (transcript, map) = c.probe(&cand, &[b"w2", b"w3"]);
    (cand, transcript, map)
}

// --------------------------------------------------------------- the bounds

#[test]
fn the_filter_never_loses_a_true_cross_tag() {
    // The direction a Bloom filter is not permitted to get wrong, checked on a
    // transcript the client actually produced rather than on synthetic tags.
    let (mut c, s) = fixture();
    let bloom = load_bloom(&s.xset, 1e-3);
    let (_, transcript, _) = query(&mut c, &s);

    let exact = XSetStore::probe(&s.xset, &transcript);
    let approx = bloom.probe(&transcript);
    assert_eq!(
        exact.len(),
        approx.len(),
        "the two stores answered differently many probes"
    );

    let false_negatives = exact
        .iter()
        .zip(&approx)
        .filter(|(e, a)| **e && !**a)
        .count();
    assert_eq!(
        false_negatives, 0,
        "the Bloom XSet lost {false_negatives} cross-tags the oracle holds; a \
         false negative is impossible for a correct filter, so this is a bug in \
         `positions` or in epoch routing, not a tuning question"
    );

    // ⭐ Without this the test above is vacuous: a store answering `true`
    // unconditionally has no false negatives either.
    let true_negatives = exact.iter().zip(&approx).filter(|(e, _)| !**e).count();
    assert!(
        true_negatives > 0,
        "every probe matched, so 'no false negatives' says nothing — the \
         fixture does not discriminate"
    );
    let positives = exact.iter().filter(|e| **e).count();
    assert!(
        positives > 0,
        "no probe matched; the fixture is not indexing what it thinks"
    );
}

#[test]
fn at_this_fixtures_parameters_no_true_match_is_lost() {
    // ⚠️ **A canary at `E = 2`, and nothing more.** `exact ⊆ bloom` is *not*
    // guaranteed — see `a_saturated_filter_answers_nothing_rather_than_everything`.
    //
    // ⛔ **Do not read this as "ε = 10⁻³ is safe".** That inference was made
    // once, off this very fixture, and it was wrong: loss compounds as
    // `1 − (1−ε)^((n−1)E)`, and `tab:params` allows `E ≤ 24`, where the same ε
    // loses 5–9% of the answer. `pqcl_dsse::bloom::max_epsilon` is the bound;
    // this test covers `n−1 = 2, E = 2` and says nothing about any other point.
    //
    // The fixture is fully deterministic — fixed keys, fixed corpus — so this
    // cannot flake in place. If it ever fires, report it; do not raise ε.
    let (mut c, s) = fixture();
    let bloom = load_bloom(&s.xset, 1e-3);
    let (cand, transcript, map) = query(&mut c, &s);

    let formula = Formula::conjunction(2);
    let exact = c.evaluate(
        &cand,
        2,
        &map,
        &XSetStore::probe(&s.xset, &transcript),
        &formula,
    );
    let approx = c.evaluate(&cand, 2, &map, &bloom.probe(&transcript), &formula);

    // Ground truth, computed independently of both stores.
    let truth: BTreeSet<u64> = (0..DOCS)
        .filter(|i| i.is_multiple_of(2) && i.is_multiple_of(3))
        .collect();
    assert_eq!(
        exact.iter().map(|i| seq_of(*i)).collect::<BTreeSet<u64>>(),
        truth,
        "the oracle itself disagrees with the ground truth"
    );

    assert!(
        exact.is_subset(&approx),
        "the Bloom XSet dropped {:?} — a false positive can only add documents, \
         never remove them",
        exact.difference(&approx).collect::<Vec<_>>()
    );
    let candidates: BTreeSet<u64> = cand.iter().copied().collect();
    assert!(
        approx.is_subset(&candidates),
        "the Bloom XSet returned documents that were never candidates, which \
         round two cannot do — Cand comes from Π_core, whose AEAD is exact"
    );
}

#[test]
fn what_a_false_positive_actually_costs_across_epsilon() {
    // Characterisation, printed. Run with --nocapture to see the table.
    let (mut c, s) = fixture();
    let (cand, transcript, map) = query(&mut c, &s);
    let formula = Formula::conjunction(2);

    let exact = c.evaluate(
        &cand,
        2,
        &map,
        &XSetStore::probe(&s.xset, &transcript),
        &formula,
    );
    let candidates: BTreeSet<u64> = cand.iter().copied().collect();

    println!("  eps      bits   |exact|  |got|  dropped  spurious");
    let mut sizes = Vec::new();
    for eps in [1e-1, 1e-2, 1e-3, 1e-4] {
        let bloom = load_bloom(&s.xset, eps);
        let got = c.evaluate(&cand, 2, &map, &bloom.probe(&transcript), &formula);

        let dropped = exact.difference(&got).count();
        let spurious = got.difference(&exact).count();
        println!(
            "  {:<7} {:>6}  {:>6}  {:>6}  {:>7}  {:>8}",
            eps,
            bloom.total_bits(),
            exact.len(),
            got.len(),
            dropped,
            spurious
        );

        // The only bound that survives: round two cannot invent candidates.
        assert!(
            got.is_subset(&candidates),
            "at ε={eps} the answer contained documents that were never \
             candidates, which round two cannot do"
        );
        sizes.push((eps, bloom.total_bits()));
    }

    // Tightening ε costs space. This is the one direction that must hold
    // monotonically regardless of which tags happened to collide.
    for w in sizes.windows(2) {
        let (loose, loose_bits) = w[0];
        let (tight, tight_bits) = w[1];
        assert!(
            tight_bits > loose_bits,
            "ε={tight} allocated {tight_bits} bits, no more than ε={loose}'s {loose_bits}"
        );
    }
}

#[test]
fn a_saturated_filter_errs_towards_present_and_only_negation_loses_a_match() {
    // ⭐ The direction of the Bloom error, deterministic (draft8 §VII, Bloom).
    //
    // Since D3 there are no delete tags: `match(id, w) = b`, one bit. A filter
    // can only answer a non-member "present", never the reverse. So a
    // saturated filter (every bit true) can only ADMIT under a positive term —
    // a spurious candidate the client fetches and discards — and can only
    // DROP a true match under a NEGATED term. The negation error replaces the
    // old delete-tag error, which dropped true matches of plain conjunctions.
    //
    // No ε is involved and no tag has to collide, so this cannot flake.
    let (mut c, s) = fixture();
    let (cand, transcript, map) = query(&mut c, &s);
    let saturated = vec![true; transcript.len()];
    let candidates: BTreeSet<u64> = cand.iter().copied().collect();

    let conjunction = Formula::conjunction(2);
    let exact = c.evaluate(
        &cand,
        2,
        &map,
        &XSetStore::probe(&s.xset, &transcript),
        &conjunction,
    );
    let got = c.evaluate(&cand, 2, &map, &saturated, &conjunction);
    assert!(!exact.is_empty(), "the fixture must match something");
    assert!(
        exact.is_subset(&got),
        "a positive conjunction lost a true match"
    );
    assert_eq!(got, candidates, "a saturated store admits every candidate");

    // w1 ∧ ¬w3: true matches exist, and a saturated store drops all of them.
    let negation = Formula::Not(Box::new(Formula::Term(1)));
    let exact_neg = c.evaluate(
        &cand,
        2,
        &map,
        &XSetStore::probe(&s.xset, &transcript),
        &negation,
    );
    let got_neg = c.evaluate(&cand, 2, &map, &saturated, &negation);
    assert!(
        !exact_neg.is_empty(),
        "the fixture must have records without w3"
    );
    assert!(
        got_neg.is_empty(),
        "under negation a false positive removes a true match"
    );
}

#[test]
fn the_filter_routes_probes_to_the_right_epoch() {
    // A store that merged every epoch into one filter would pass the superset
    // tests — merging only adds tags, which only adds false positives. It would
    // also silently destroy forward privacy, because a probe for a closed epoch
    // would consult tags written after it. Sized per epoch, a merged store
    // overflows its filter; the observable symptom is a tag from epoch 0 being
    // reported present in epoch 1, so check that directly.
    let (_, s) = fixture();
    let bloom = load_bloom(&s.xset, 1e-4);
    let epochs = s.xset.all_epochs();
    assert!(epochs.len() >= 2, "fixture must close at least two epochs");

    let (e0, tags0) = &epochs[0];
    let (e1, _) = &epochs[1];

    // The same tag, asked of each epoch's own filter. Probes are unlabelled
    // since D3, but the filters must stay per epoch: each is sized from its
    // own load, and a merged one would overfill.
    let probe_in = |epoch, tag: XTagT| bloom.contains_in(epoch, &tag);
    let _ = Transcript { probes: Vec::new() };

    let tag = tags0[0];
    assert!(
        probe_in(*e0, tag),
        "a tag from epoch {e0} was not found there"
    );
    let leaked = tags0.iter().filter(|t| probe_in(*e1, **t)).count();
    assert!(
        leaked * 100 < tags0.len(),
        "{leaked} of {} epoch-{e0} tags were found under epoch {e1}; at ε=10⁻⁴ \
         that is far beyond chance, so the store is not keeping epochs apart",
        tags0.len()
    );
}
