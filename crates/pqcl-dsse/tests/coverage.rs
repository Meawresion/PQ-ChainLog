//! draft8 Phase 9 Step 1, the coverage rule.
//!
//! A candidate whose epoch is still open has no cross-tags the server can
//! answer for: the open epoch is never probed (forward privacy). Evaluating ψ
//! over it anyway reads every one of its bits as "absent", so `w₁ ∧ ¬w₂`
//! returns a document that **does** contain `w₂`. That is a false positive,
//! not a lag. Such candidates are set aside as pending and never evaluated, so
//! a result is exactly the set provable against a committed root.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use pqcl_dsse::core::{Client, Op};
use pqcl_dsse::xt::{Formula, HonestServer, XSetStore, XtClient};
use pqcl_primitives::xof::{PrfKey, digest256};

fn client() -> XtClient {
    XtClient::new(
        Client::new(PrfKey::new(digest256(b"K_S coverage"))),
        PrfKey::new(digest256(b"K_X^(0) coverage")),
        4,
    )
}

/// `w₁ ∧ ¬w₂` over the given candidates.
fn not_w2(c: &mut XtClient, s: &HonestServer) -> BTreeSet<u64> {
    let cand = c.candidates(s, b"w1").unwrap();
    let (t, map) = c.probe(&cand, &[b"w2"]);
    let bits = XSetStore::probe(s, &t);
    c.evaluate(
        &cand,
        1,
        &map,
        &bits,
        &Formula::Not(Box::new(Formula::Term(0))),
    )
}

#[test]
fn a_document_of_the_open_epoch_is_never_a_negation_match() {
    let mut c = client();
    let mut s = HonestServer::new();
    let id = pqcl_dsse::xt::doc_id(c.epoch(), 7);
    c.update(&mut s, Op::Add, b"w1", id).unwrap();
    c.update(&mut s, Op::Add, b"w2", id).unwrap();

    // Open epoch: the document has w2, so it must not match w1 AND NOT w2.
    assert!(
        not_w2(&mut c, &s).is_empty(),
        "an open-epoch candidate was evaluated as lacking w2"
    );
    let cand = c.candidates(&s, b"w1").unwrap();
    assert_eq!(c.pending(&cand), vec![id], "it is reported pending instead");

    // Closed: now provable, and still not a match.
    c.close_epoch(&mut s);
    assert!(
        not_w2(&mut c, &s).is_empty(),
        "a closed-epoch candidate with w2 matched NOT w2"
    );
    assert!(c.pending(&cand).is_empty());
}

#[test]
fn a_document_without_w2_is_returned_once_its_epoch_closes() {
    let mut c = client();
    let mut s = HonestServer::new();
    let id = pqcl_dsse::xt::doc_id(c.epoch(), 9);
    c.update(&mut s, Op::Add, b"w1", id).unwrap();

    assert!(
        not_w2(&mut c, &s).is_empty(),
        "not evaluable while its epoch is open"
    );
    c.close_epoch(&mut s);
    assert_eq!(not_w2(&mut c, &s), BTreeSet::from([id]));
}
