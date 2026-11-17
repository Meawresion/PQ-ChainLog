//! **M3b** — court-ordered erasure, and the ordering constraint that makes it real.
//!
//! `PQ-ChainLog-DESIGN.md` §12. The deeper point worth keeping: immutability
//! and erasure are not in conflict, because they act on **different objects**.
//! The anchored root commits to the *fact* that a capsule was sealed; that stays
//! true and must. What is erased is the payload and the index association.
//!
//! # The hole that took real work to close
//!
//! Tombstoning the index is **not sufficient**. It removes the capsule from
//! round-one candidates, so an *honest* client never probes it — but cross-tags
//! from prior epochs persist in the server's sets, and an adversary who retained
//! them and later obtains the epoch keys can confirm the association anyway.
//!
//! Erasure therefore completes at **compaction**, which rebuilds `XSet` from the
//! live pairs alone and destroys the superseded `{K_X^(e)}`. Those keys cannot
//! die earlier, because round-two probes range over all closed epochs.
//!
//! # Two constraints that are easy to get wrong, so both are tested
//!
//! 1. **Tombstone before compaction.** Compacting first carries the pair into
//!    the new `XSet`, and the redaction then appears to succeed while doing
//!    nothing. [`compaction_before_tombstoning_silently_fails`] demonstrates
//!    that rather than warning about it.
//! 2. **The adversary holds `K_mst`.** The plan is explicit that M3b's
//!    acceptance *"would pass a naive test while the property fails — the test
//!    must be against an adversary holding `K_mst`, not against a client that
//!    has merely deleted its copy."* That is why `K_X^(0)` is an independent
//!    draw rather than a derivation.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use pqcl_dsse::core::{Client, Op};
use pqcl_dsse::xt::{HonestServer, XTag, XtClient};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

const VICTIM_DOC: u64 = 3;
const VICTIM_KW: &[u8] = b"secret";

fn fixture() -> (XtClient, HonestServer) {
    let mut c = XtClient::new(
        Client::new(PrfKey::new([0x21u8; LAMBDA_BYTES])),
        PrfKey::new([0x91u8; LAMBDA_BYTES]),
        8,
    );
    let mut s = HonestServer::new();

    for id in 0..8u64 {
        c.update(&mut s, Op::Add, b"common", id).expect("update");
        if id.is_multiple_of(3) {
            c.update(&mut s, Op::Add, VICTIM_KW, id).expect("update");
        }
    }
    c.close_epoch(&mut s);
    for j in 8..12u64 {
        let id = pqcl_dsse::xt::doc_id(c.epoch(), j);
        c.update(&mut s, Op::Add, b"common", id).expect("update");
        c.update(&mut s, Op::Add, VICTIM_KW, id).expect("update");
    }
    c.close_epoch(&mut s);
    (c, s)
}

/// Every cross-tag currently held by the server, across all epochs.
fn server_tags(s: &HonestServer) -> BTreeSet<XTag> {
    let mut out = BTreeSet::new();
    for e in 0..8u64 {
        if let Some(set) = s.xset.epoch(e) {
            out.extend(set.iter().copied());
        }
    }
    out
}

// ------------------------------------------------------- the honest ordering

#[test]
fn tombstone_then_compact_erases_the_association() {
    let (mut c, mut s) = fixture();

    // Before: the pair's cross-tag is in the server's sets.
    let before = server_tags(&s);
    let derivable_before = c.derivable_xtags(VICTIM_KW, VICTIM_DOC);
    assert!(
        derivable_before.iter().any(|t| before.contains(t)),
        "fixture is wrong: the victim pair was never in XSet, so erasing it \
         would prove nothing"
    );

    // The order that works.
    c.tombstone(VICTIM_KW, VICTIM_DOC);
    c.compact(&mut s, PrfKey::new([0xa7u8; LAMBDA_BYTES]));

    // §12.6: re-derive every cross-tag the client COULD produce for the
    // redacted pair, and assert none survives.
    let after = server_tags(&s);
    for tag in c.derivable_xtags(VICTIM_KW, VICTIM_DOC) {
        assert!(
            !after.contains(&tag),
            "a derivable cross-tag for the redacted pair survived compaction"
        );
    }

    // And the old tags are gone from the server entirely.
    for tag in &derivable_before {
        assert!(
            !after.contains(tag),
            "a pre-redaction cross-tag survived compaction"
        );
    }
}

#[test]
fn other_documents_survive_the_redaction() {
    // An erasure that also destroyed unrelated evidence would be worse than
    // useless. Doc 9 also carries the victim keyword and must be untouched.
    let (mut c, mut s) = fixture();
    let nine = pqcl_dsse::xt::doc_id(1, 9);
    let survivor = c.derivable_xtags(VICTIM_KW, nine);
    assert!(survivor.iter().any(|t| server_tags(&s).contains(t)));

    c.tombstone(VICTIM_KW, VICTIM_DOC);
    c.compact(&mut s, PrfKey::new([0xa7u8; LAMBDA_BYTES]));

    let after = server_tags(&s);
    let now = c.derivable_xtags(VICTIM_KW, nine);
    assert!(
        now.iter().any(|t| after.contains(t)),
        "compaction dropped a pair that was not redacted"
    );
}

#[test]
fn the_live_set_shrinks_by_exactly_one_pair() {
    let (mut c, mut s) = fixture();
    let before = c.live_pairs();
    c.tombstone(VICTIM_KW, VICTIM_DOC);
    assert_eq!(c.live_pairs(), before - 1);
    c.compact(&mut s, PrfKey::new([0xa7u8; LAMBDA_BYTES]));
    let epochs = s.xset.all_epochs();
    assert_eq!(epochs.len(), 1, "one compacted epoch");
    assert_eq!(epochs[0].1.len(), before - 1);
}

// -------------------------------------------------- the ordering bug, shown

#[test]
fn compaction_before_tombstoning_silently_fails() {
    // The failure mode design §12 warns about, made executable.
    //
    // Compacting first re-keys the victim pair FORWARD into the new XSet. The
    // subsequent tombstone then removes it from the live set, so a naive check
    // — "is it in the client's live set?" — passes. But the association is
    // still sitting in the server's current XSet under a key the client still
    // holds, which is precisely what erasure was supposed to remove.
    let (mut c, mut s) = fixture();

    c.compact(&mut s, PrfKey::new([0xa7u8; LAMBDA_BYTES])); // WRONG ORDER
    c.tombstone(VICTIM_KW, VICTIM_DOC);

    // The naive check passes...
    assert!(c.is_tombstoned(VICTIM_KW, VICTIM_DOC));

    // ...while the real property fails.
    let after = server_tags(&s);
    let surviving = c
        .derivable_xtags(VICTIM_KW, VICTIM_DOC)
        .into_iter()
        .filter(|t| after.contains(t))
        .count();
    assert!(
        surviving > 0,
        "the wrong ordering was expected to leave the association intact; if \
         this now passes, compaction has changed and this test must be \
         rewritten rather than deleted"
    );

    // Compacting a second time, now that the tombstone is in place, fixes it.
    c.compact(&mut s, PrfKey::new([0xb8u8; LAMBDA_BYTES]));
    let after = server_tags(&s);
    for tag in c.derivable_xtags(VICTIM_KW, VICTIM_DOC) {
        assert!(!after.contains(&tag));
    }
}

// ----------------------------------------- the adversary who holds K_mst

#[test]
fn an_adversary_with_the_master_key_cannot_regenerate_destroyed_epoch_keys() {
    // The test the plan insists on. A client that merely deleted its copy would
    // pass a naive check; this models the real adversary — one who kept every
    // historical XSet_e AND holds the master key.
    //
    // It fails if K_X^(0) is ever changed to a derivation of K_mst, which is
    // exactly the drift plan §0a caught in the original xof.rs.
    let master = PrfKey::new([0x21u8; LAMBDA_BYTES]);
    let mut c = XtClient::new(Client::new(master), PrfKey::new([0x91u8; LAMBDA_BYTES]), 8);
    let mut s = HonestServer::new();

    for id in 0..6u64 {
        c.update(&mut s, Op::Add, VICTIM_KW, id).expect("update");
    }
    c.close_epoch(&mut s);

    // The adversary records everything the server ever held.
    let retained: BTreeSet<XTag> = server_tags(&s);
    assert!(!retained.is_empty());

    // Erase.
    c.tombstone(VICTIM_KW, VICTIM_DOC);
    c.compact(&mut s, PrfKey::new([0xa7u8; LAMBDA_BYTES]));

    // The adversary still has the old cross-tags. What it cannot do is
    // reproduce them from anything it can derive now: K_X^(0) was an
    // independent draw, and the ratchet is one-way, so neither the master key
    // nor any retained key regenerates a destroyed epoch key.
    let derivable_now: BTreeSet<XTag> = c
        .derivable_xtags(VICTIM_KW, VICTIM_DOC)
        .into_iter()
        .collect();

    assert!(
        derivable_now.is_disjoint(&retained),
        "an adversary holding K_mst reproduced a destroyed epoch's cross-tags. \
         K_X must be an independent draw plus a one-way ratchet -- if it has \
         become derivable from the master, court-ordered erasure is cosmetic \
         and design §12 is broken."
    );

    // And the live server holds none of the retained tags either.
    assert!(
        server_tags(&s).is_disjoint(&retained),
        "compaction left pre-erasure cross-tags in place"
    );
}

#[test]
fn compaction_collapses_every_closed_epoch_into_one() {
    // Since D3 a probe no longer multiplies by E, but the server still tests
    // each probe against every closed epoch's set (and a Bloom store keeps E
    // filters, each adding its ε), so compaction must still bring E down.
    let (mut c, mut s) = fixture();
    assert!(s.xset.all_epochs().len() >= 2);
    c.compact(&mut s, PrfKey::new([0xa7u8; LAMBDA_BYTES]));
    assert_eq!(
        s.xset.all_epochs().len(),
        1,
        "after compaction the server holds exactly one closed epoch's set"
    );
}

#[test]
fn search_still_works_after_compaction() {
    // Erasure must not break the scheme for everything else.
    let (mut c, mut s) = fixture();
    c.tombstone(VICTIM_KW, VICTIM_DOC);
    c.compact(&mut s, PrfKey::new([0xa7u8; LAMBDA_BYTES]));

    let cand = c.candidates(&s, b"common").expect("round 1");
    let x_terms: Vec<&[u8]> = vec![VICTIM_KW];
    let (t, map) = c.probe(&cand, &x_terms);
    let bits = pqcl_dsse::XSetStore::probe(&s, &t);
    let got = c.evaluate(&cand, 1, &map, &bits, &pqcl_dsse::Formula::conjunction(1));

    // Docs 0, 6 (epoch 0) and 8..12 (epoch 1) carry the victim keyword; 3 was
    // redacted. Records of both pre-compaction epochs are probed under the
    // compacted epoch's key.
    assert!(
        !got.contains(&VICTIM_DOC),
        "redacted document still matches"
    );
    assert!(got.contains(&6), "an unredacted match was lost");
    assert!(
        got.contains(&pqcl_dsse::xt::doc_id(1, 10)),
        "a record of the second pre-compaction epoch was lost"
    );
}
