//! `Π_core` against the ground-truth oracle, and against a malicious server.
//!
//! Two obligations from the build plan (M2):
//!
//! 1. `Π_core.Search(w)` equals the oracle for every keyword, across an
//!    interleaved add/delete workload.
//! 2. **All four malicious-server deviations are detected** — omission,
//!    forgery, substitution, replay (draft6 Thm. `thm:verif`). *"If any is not
//!    detected, the theorem is wrong and that is a finding to report, not to
//!    hide."*
//!
//! The workload here is deterministic and generated in-process. That is a test
//! fixture, not a substitute for the corpus: M2's acceptance is stated against
//! **Enron**, and that run lives in `tests/corpus.rs`, which fails loudly until
//! the dataset is fetched. What these tests establish is that the protocol is
//! correct and the theorem holds; what the corpus adds is that it stays correct
//! at realistic keyword distributions, where the long tail of rare keywords and
//! a handful of very common ones is what actually stresses the counter space.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use pqcl_dsse::Oracle;
use pqcl_dsse::core::{Client, Edb, HonestEdb, Op, SearchError, SearchResponse, SearchToken};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::aead::SealedRecord;
use pqcl_primitives::xof::PrfKey;

fn client() -> Client {
    Client::new(PrfKey::new([0x9cu8; LAMBDA_BYTES]))
}

/// A deterministic pseudo-random workload. Fixed seed so a failure is
/// reproducible from the test name alone.
struct Workload(u64);

impl Workload {
    fn next(&mut self) -> u64 {
        // xorshift64*: adequate for choosing test inputs, and it keeps the
        // fixture free of a dependency.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Drive both the oracle and `Π_core` through the same interleaved history.
fn run_workload(keywords: usize, updates: usize) -> (Client, HonestEdb, Oracle) {
    let mut c = client();
    let mut edb = HonestEdb::new();
    let mut oracle = Oracle::new();
    let mut rng = Workload(0x1234_5678_9abc_def0);

    // Track what is live so deletions target something real often enough to
    // matter; a delete of an absent id is legal but tests less.
    let mut live: Vec<(Vec<u8>, u64)> = Vec::new();

    for _ in 0..updates {
        let delete = !live.is_empty() && rng.next().is_multiple_of(4);
        let (w, id, op) = if delete {
            let pick = usize::try_from(rng.next() % live.len() as u64).expect("fits");
            let (w, id) = live.swap_remove(pick);
            (w, id, Op::Del)
        } else {
            let w = format!("kw{}", rng.next() % keywords as u64).into_bytes();
            let id = rng.next() % 1000;
            live.push((w.clone(), id));
            (w, id, Op::Add)
        };

        oracle.update(op, &w, id);
        let token = c.update(op, &w, id).expect("update");
        edb.insert(&token);
    }

    (c, edb, oracle)
}

fn search(c: &Client, edb: &HonestEdb, w: &[u8]) -> BTreeSet<u64> {
    match c.search_token(w) {
        None => BTreeSet::new(),
        Some(token) => c
            .finish(w, &token, &edb.search(&token))
            .expect("honest server must verify"),
    }
}

// ------------------------------------------------------------- correctness

#[test]
fn search_matches_the_oracle_across_an_interleaved_workload() {
    let (c, edb, oracle) = run_workload(64, 4000);

    assert_eq!(oracle.update_count(), 4000);
    assert!(oracle.keyword_count() > 1, "workload used too few keywords");

    for w in oracle.keywords() {
        assert_eq!(
            search(&c, &edb, w),
            oracle.search(w),
            "Π_core disagrees with the oracle for keyword {:?}",
            String::from_utf8_lossy(w)
        );
    }
}

#[test]
fn a_keyword_deleted_to_empty_returns_empty_not_absent() {
    // The distinction matters: the counter is non-zero, so the scheme must
    // still search and return nothing, rather than refusing.
    let mut c = client();
    let mut edb = HonestEdb::new();

    edb.insert(&c.update(Op::Add, b"w", 7).expect("add"));
    edb.insert(&c.update(Op::Del, b"w", 7).expect("del"));

    assert_eq!(c.counter(b"w"), 2);
    assert!(search(&c, &edb, b"w").is_empty());
}

#[test]
fn an_unseen_keyword_produces_no_token_at_all() {
    // Sending a token for c = 0 would tell the server a search happened for a
    // keyword with no history. An honest client never needs to reveal that.
    assert!(client().search_token(b"never-written").is_none());
}

#[test]
fn deletion_is_in_band_and_indistinguishable_by_size() {
    // Type-II backward privacy: the server sees when updates happened, never
    // which were deletions. If an Add and a Del ever differed in ciphertext
    // length, that would leak directly.
    let mut c = client();
    let add = c.update(Op::Add, b"w", 42).expect("add");
    let del = c.update(Op::Del, b"w", 42).expect("del");
    assert_eq!(add.val.len(), del.val.len());
    assert_ne!(add.addr, del.addr, "addresses must not repeat");
}

#[test]
fn readding_after_delete_restores_the_document() {
    let mut c = client();
    let mut edb = HonestEdb::new();
    for op in [Op::Add, Op::Del, Op::Add] {
        edb.insert(&c.update(op, b"w", 1).expect("update"));
    }
    assert_eq!(search(&c, &edb, b"w"), BTreeSet::from([1]));
}

#[test]
fn distinct_keywords_do_not_interfere() {
    let (c, edb, oracle) = run_workload(8, 400);
    for w in oracle.keywords() {
        let got = search(&c, &edb, w);
        assert_eq!(got, oracle.search(w));
    }
    // Every update produced exactly one stored record: no address collisions.
    assert_eq!(edb.len(), oracle.update_count());
}

// ------------------------------------------------- forward privacy, at the API

#[test]
fn a_search_token_cannot_reach_a_future_update() {
    // The server holds a token for [0, c). After the client writes at counter
    // c, that record must be unreachable with the old token — this is forward
    // privacy, and it is enforced by the constrained key, not by the server
    // behaving.
    let mut c = client();
    let mut edb = HonestEdb::new();
    edb.insert(&c.update(Op::Add, b"w", 1).expect("add"));

    let stale = c.search_token(b"w").expect("token");
    assert_eq!(stale.count, 1);

    edb.insert(&c.update(Op::Add, b"w", 2).expect("add"));

    // Replaying the old token yields only the first record.
    let got = c.finish(b"w", &stale, &edb.search(&stale)).expect("verify");
    assert_eq!(got, BTreeSet::from([1]));
    // And the constrained key itself refuses counter 1.
    assert!(stale.constrained.eval(1).is_err());
}

// ------------------------------------------- Thm. thm:verif, all four attacks

/// Set up one keyword with a known history, plus its honest response.
fn victim() -> (Client, HonestEdb, SearchToken, SearchResponse) {
    let mut c = client();
    let mut edb = HonestEdb::new();
    for id in 1..=4u64 {
        edb.insert(&c.update(Op::Add, b"w", id).expect("add"));
    }
    let token = c.search_token(b"w").expect("token");
    let response = edb.search(&token);
    (c, edb, token, response)
}

#[test]
fn detects_omission() {
    // The server drops a record it holds. The client expects exactly `count`
    // slots at addresses it derived itself, so a hole is structural.
    let (c, _edb, token, mut response) = victim();
    response.0[2] = None;

    assert_eq!(
        c.finish(b"w", &token, &response),
        Err(SearchError::Missing { index: 2 })
    );
}

#[test]
fn detects_truncation_as_well_as_omission() {
    // A subtler omission: return fewer slots rather than an empty one.
    let (c, _edb, token, mut response) = victim();
    response.0.pop();

    assert_eq!(
        c.finish(b"w", &token, &response),
        Err(SearchError::WrongLength {
            expected: 4,
            got: 3
        })
    );
}

#[test]
fn detects_forgery() {
    // The server invents a record. It cannot: the payload is AEAD-sealed under
    // F(K^M_w, c), and K^M_w never leaves the client.
    let (c, _edb, token, mut response) = victim();
    let mut bytes = response.0[1].as_ref().expect("slot").as_bytes().to_vec();
    bytes[0] ^= 0x01;
    response.0[1] = Some(SealedRecord::from_bytes(bytes));

    assert!(matches!(
        c.finish(b"w", &token, &response),
        Err(SearchError::Unauthentic { index: 1, .. })
    ));
}

#[test]
fn detects_substitution() {
    // The server moves a genuine record to a different position. Both are real
    // ciphertexts under real keys — what fails is that AD = addr binds each
    // payload to the address the client derived for that counter.
    let (c, _edb, token, mut response) = victim();
    response.0.swap(0, 3);

    assert!(matches!(
        c.finish(b"w", &token, &response),
        Err(SearchError::Unauthentic { .. })
    ));
}

#[test]
fn detects_replay() {
    // The server returns an earlier record again in a later slot. Same
    // mechanism as substitution: the record authenticates only at its own
    // address, and EDB[addr] is write-once.
    let (c, _edb, token, mut response) = victim();
    response.0[3] = response.0[0].clone();

    assert!(matches!(
        c.finish(b"w", &token, &response),
        Err(SearchError::Unauthentic { index: 3, .. })
    ));
}

#[test]
fn detects_a_record_from_a_different_keyword() {
    // Cross-keyword substitution: a valid record, valid key, wrong keyword.
    // Both the address and the record key are keyword-derived, so it fails.
    let mut c = client();
    let mut edb = HonestEdb::new();
    edb.insert(&c.update(Op::Add, b"alpha", 1).expect("add"));
    let other = c.update(Op::Add, b"beta", 2).expect("add");
    edb.insert(&other);

    let token = c.search_token(b"alpha").expect("token");
    let response = SearchResponse(vec![Some(other.val.clone())]);

    assert!(matches!(
        c.finish(b"alpha", &token, &response),
        Err(SearchError::Unauthentic { index: 0, .. })
    ));
}

#[test]
fn an_honest_server_always_verifies() {
    // The negative controls above are only meaningful if the positive path is
    // not accidentally rejecting everything.
    let (c, edb, oracle) = run_workload(16, 500);
    for w in oracle.keywords() {
        let token = c.search_token(w).expect("token");
        c.finish(w, &token, &edb.search(&token))
            .expect("honest server must verify");
    }
}

// ------------------------------------------------------------------ shapes

#[test]
fn token_size_is_logarithmic_not_linear() {
    // The whole point of the GGM construction: a search token for c updates is
    // O(log c) keys, not O(c). If this regressed, communication volume — a
    // headline axis in the paper — would be wrong by orders of magnitude.
    let mut c = client();
    for id in 0..1024u64 {
        c.update(Op::Add, b"w", id).expect("add");
    }
    let token = c.search_token(b"w").expect("token");
    assert_eq!(token.count, 1024);
    assert_eq!(
        token.constrained.nodes().len(),
        1,
        "an aligned [0, 2^10) range is a single subtree"
    );

    c.update(Op::Add, b"w", 9999).expect("add");
    let ragged = c.search_token(b"w").expect("token");
    assert_eq!(ragged.count, 1025);
    assert!(
        ragged.constrained.nodes().len() <= 2 * 64,
        "cover of {} nodes exceeds the 2l bound",
        ragged.constrained.nodes().len()
    );
}
