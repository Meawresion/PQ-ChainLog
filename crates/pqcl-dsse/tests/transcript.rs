//! **Thm. `thm:bool`, made executable.**
//!
//! The build plan (M3): *"record the exact bytes the server sees
//! for `w1 ∧ w2 ∧ w3` and for `w1 ∧ (w2 ∨ ¬w3)` over the same term multiset and
//! assert the transcripts are identically distributed. That test *is* the
//! theorem; it is the single highest-value test in this project."*
//!
//! # What "identically distributed" means here, precisely
//!
//! The probe list is shuffled under a key the server does not have, and the
//! shuffle draws on a counter that advances every call — so two runs never
//! produce the same *sequence*, and demanding byte equality of the sequence
//! would test the RNG, not the theorem.
//!
//! What the theorem actually claims is that the server's **view** does not
//! depend on `ψ`. The server's view is the unordered probe list: it cannot
//! invert the permutation, so ordering carries it nothing. So the test compares
//! [`Transcript::multiset`] — the order-independent content — and separately
//! checks that the probe count, epoch labels and reply length agree.
//!
//! # Why this is the test that matters
//!
//! `Π_BOOL`'s entire claim is *Boolean and range at no leakage cost above
//! `Π_XT`*. If a formula could influence the transcript by even one probe, the
//! server could distinguish a conjunction from a disjunction, `XPat` would leak,
//! and the paper's central new claim would be false. The construction is built
//! so that cannot happen — [`XtClient::probe`] takes candidates and x-terms and
//! has no formula parameter at all — but a structural argument is not a proof
//! that the code implements it.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use pqcl_dsse::core::{Client, Op};
use pqcl_dsse::xt::{Formula, HonestServer, XtClient, doc_id, seq_of};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

/// Build a small database with a known ground truth.
///
/// `w1` is the s-term and matches everything, so the candidate set is the whole
/// corpus and every formula has something to discriminate over.
fn fixture() -> (XtClient, HonestServer) {
    let mut c = XtClient::new(
        Client::new(PrfKey::new([0x31u8; LAMBDA_BYTES])),
        PrfKey::new([0x77u8; LAMBDA_BYTES]),
        4, // small beta so batches actually flush
    );
    let mut s = HonestServer::new();

    // ids 0..12 in epoch 0, 12..16 in epoch 1 (`id = (e, j)`); w2 divides
    // by 2, w3 divides by 3.
    for j in 0..12u64 {
        let id = doc_id(c.epoch(), j);
        c.update(&mut s, Op::Add, b"w1", id).expect("update");
        if j.is_multiple_of(2) {
            c.update(&mut s, Op::Add, b"w2", id).expect("update");
        }
        if j.is_multiple_of(3) {
            c.update(&mut s, Op::Add, b"w3", id).expect("update");
        }
    }
    // Two closed epochs: each candidate is probed once, under its own epoch's
    // key, whichever epoch that is (D3).
    c.close_epoch(&mut s);
    for j in 12..16u64 {
        let id = doc_id(c.epoch(), j);
        c.update(&mut s, Op::Add, b"w1", id).expect("update");
        if j.is_multiple_of(2) {
            c.update(&mut s, Op::Add, b"w2", id).expect("update");
        }
    }
    c.close_epoch(&mut s);

    (c, s)
}

/// Run one query end to end and return `(result, transcript)`.
fn query(
    c: &mut XtClient,
    s: &HonestServer,
    formula: &Formula,
) -> (BTreeSet<u64>, pqcl_dsse::xt::Transcript) {
    let cand = c.candidates(s, b"w1").expect("round 1");
    let x_terms: Vec<&[u8]> = vec![b"w2", b"w3"];
    let (transcript, map) = c.probe(&cand, &x_terms);
    let bits = pqcl_dsse::XSetStore::probe(s, &transcript);
    let result = c.evaluate(&cand, x_terms.len(), &map, &bits, formula);
    (result.into_iter().map(seq_of).collect(), transcript)
}

// ------------------------------------------------------------ the theorem

#[test]
fn the_server_view_does_not_depend_on_the_formula() {
    let (mut c, s) = fixture();

    // w1 ∧ w2 ∧ w3
    let conjunction = Formula::conjunction(2);
    // w1 ∧ (w2 ∨ ¬w3) — a disjunction and a negation over the same terms
    let boolean = Formula::Or(vec![
        Formula::Term(0),
        Formula::Not(Box::new(Formula::Term(1))),
    ]);

    let (r_and, t_and) = query(&mut c, &s, &conjunction);
    let (r_or, t_or) = query(&mut c, &s, &boolean);

    // The results differ — otherwise the test would be vacuous.
    assert_ne!(
        r_and, r_or,
        "the two formulas must actually compute different answers, or this \
         test proves nothing"
    );

    // The server saw the same thing both times.
    assert_eq!(
        t_and.multiset(),
        t_or.multiset(),
        "Thm. thm:bool FAILS: the transcript depends on the formula, so a \
         server could distinguish a conjunction from a disjunction and XPat \
         leaks after all"
    );
    assert_eq!(t_and.len(), t_or.len(), "probe counts differ");
    assert_eq!(t_and.wire_bytes_up(), t_or.wire_bytes_up());
}

#[test]
fn the_view_is_identical_across_many_formula_shapes() {
    // One pair could coincide by luck. Every formula over the same two terms
    // must produce the same view.
    let (mut client, server) = fixture();

    let formulas = [
        Formula::conjunction(2),
        Formula::Or(vec![Formula::Term(0), Formula::Term(1)]),
        Formula::And(vec![
            Formula::Term(0),
            Formula::Not(Box::new(Formula::Term(1))),
        ]),
        Formula::Not(Box::new(Formula::Or(vec![
            Formula::Term(0),
            Formula::Term(1),
        ]))),
        Formula::Term(1),
        Formula::Or(vec![
            Formula::Not(Box::new(Formula::Term(0))),
            Formula::Not(Box::new(Formula::Term(1))),
        ]),
    ];

    let mut reference = None;
    let mut answers = Vec::new();
    for f in &formulas {
        let (r, t) = query(&mut client, &server, f);
        answers.push(r);
        match &reference {
            None => reference = Some(t.multiset()),
            Some(m) => assert_eq!(&t.multiset(), m, "transcript changed for formula {f:?}"),
        }
    }

    // And the formulas really are computing different things.
    let distinct: BTreeSet<_> = answers.iter().collect();
    assert!(
        distinct.len() >= 4,
        "only {} distinct answers across {} formulas — the fixture does not \
         discriminate enough for this test to mean anything",
        distinct.len(),
        formulas.len()
    );
}

#[test]
fn negation_costs_nothing() {
    // The concrete form of "negation is free": ¬w3 probes exactly what w3 does.
    let (mut c, s) = fixture();
    let (_, plain) = query(&mut c, &s, &Formula::Term(1));
    let (_, negated) = query(&mut c, &s, &Formula::Not(Box::new(Formula::Term(1))));
    assert_eq!(plain.multiset(), negated.multiset());
    assert_eq!(plain.len(), negated.len());
}

// ------------------------------------------------------------ correctness

#[test]
fn conjunctive_search_matches_the_ground_truth() {
    let (mut c, s) = fixture();
    let (got, _) = query(&mut c, &s, &Formula::conjunction(2));
    // ids 0..16 divisible by 2 and by 3, restricted to those w3 saw (0..12).
    let expected: BTreeSet<u64> = (0..12u64)
        .filter(|i| i.is_multiple_of(2) && i.is_multiple_of(3))
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn boolean_search_matches_the_ground_truth() {
    let (mut c, s) = fixture();
    // w2 ∨ ¬w3, over candidates 0..16.
    let (got, _) = query(
        &mut c,
        &s,
        &Formula::Or(vec![
            Formula::Term(0),
            Formula::Not(Box::new(Formula::Term(1))),
        ]),
    );
    let expected: BTreeSet<u64> = (0..16u64)
        .filter(|i| {
            let w2 = i.is_multiple_of(2);
            let w3 = *i < 12 && i.is_multiple_of(3);
            w2 || !w3
        })
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn xt_and_cd_agree_on_a_conjunction() {
    // Π_XT and Π_CD have incomparable *leakage*, but they must compute the
    // same answer. If they diverged, one of them would be wrong.
    let (mut c, s) = fixture();
    let (xt, _) = query(&mut c, &s, &Formula::conjunction(2));
    let cd: BTreeSet<u64> = pqcl_dsse::cd_search(&c.core, &s, &[b"w1", b"w2", b"w3"])
        .expect("cd")
        .into_iter()
        .map(seq_of)
        .collect();
    assert_eq!(xt, cd);
}

// ------------------------------------------------------------- probe count

#[test]
fn probe_count_matches_the_published_formula() {
    // draft8 eq. (probecount): |P| = |Cand*| · (n−1), with no factor E: a
    // candidate is probed once, under its own epoch's key, however many
    // epochs are closed. The fixture spans two closed epochs, so a probe
    // count that still multiplied by E would show here.
    let (mut c, s) = fixture();
    let cand = c.candidates(&s, b"w1").expect("round 1");
    let x_terms: Vec<&[u8]> = vec![b"w2", b"w3"];
    let (t, map) = c.probe(&cand, &x_terms);

    assert!(c.pending(&cand).is_empty(), "every fixture epoch is closed");
    assert_eq!(
        t.len(),
        cand.len() * x_terms.len(),
        "|Cand*|={}, n-1={}",
        cand.len(),
        x_terms.len()
    );
    assert_eq!(map.len(), t.len());
    assert!(
        c.closed_epochs() >= 2,
        "fixture must close at least two epochs to be meaningful"
    );
}

#[test]
fn the_open_epoch_is_never_probed() {
    // Forward privacy: cross-tags for the epoch still being written must not be
    // probed, or a search would reveal that a just-written update matches.
    let (mut c, mut s) = fixture();
    let before = c.closed_epochs();

    // Write into the open epoch and flush it to the server.
    let fresh = doc_id(c.epoch(), 999);
    c.update(&mut s, Op::Add, b"w2", fresh).expect("update");
    c.update(&mut s, Op::Add, b"w1", fresh).expect("update");
    c.flush(&mut s);

    let cand = c.candidates(&s, b"w1").expect("round 1");
    let (t, _) = c.probe(&cand, &[b"w2"]);

    assert_eq!(
        c.pending(&cand),
        vec![fresh],
        "the open-epoch record is pending"
    );
    assert_eq!(
        t.len(),
        cand.len() - 1,
        "a probe was built for the open-epoch record"
    );
    assert_eq!(c.closed_epochs(), before, "nothing closed meanwhile");
}

// ------------------------------------------------------- s-term selection

#[test]
fn selecting_the_s_term_shrinks_the_probe_count() {
    // Why selection exists at all. Probes are 2*|Cand|*(n-1)*E, and
    // Cand = DB(w1), so anchoring on a common term instead of a rare one
    // multiplies the whole round-two cost.
    //
    // Without a sketch the caller guesses; with one the client picks. This
    // asserts the picked anchor is the cheap one, in probes rather than in
    // estimated volume, because probes are what the query actually pays.
    let (mut c, s) = fixture();

    let keywords: Vec<&[u8]> = vec![b"w1", b"w3"];
    let pick = c.select_s_term(&keywords).expect("non-empty query");
    assert_eq!(
        pick,
        1,
        "w3 matches 4 of 16 documents and w1 all 16, so w3 is the anchor; \
         estimates were w1={}, w3={}",
        c.estimated_volume(b"w1"),
        c.estimated_volume(b"w3")
    );

    // The chosen anchor really is cheaper, measured end to end.
    let chosen = c.candidates(&s, keywords[pick]).expect("round 1");
    let other = c.candidates(&s, keywords[1 - pick]).expect("round 1");
    let (t_chosen, _) = c.probe(&chosen, &[b"w2"]);
    let (t_other, _) = c.probe(&other, &[b"w2"]);
    assert!(
        t_chosen.len() < t_other.len(),
        "the selected s-term probed {} times, the alternative {}",
        t_chosen.len(),
        t_other.len()
    );
}

#[test]
fn the_sketch_never_underestimates_a_keyword_in_the_index() {
    // One-sidedness, at the level the selection rule depends on it.
    let (c, _) = fixture();
    assert!(c.estimated_volume(b"w1") >= 16);
    assert!(c.estimated_volume(b"w2") >= 8);
}
