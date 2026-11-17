//! ODXT against the plaintext ground-truth oracle.
//!
//! The build plan: *"Correctness before speed. Every
//! scheme is validated against a plaintext ground-truth oracle on the real
//! corpus, including deletions."*
//!
//! A baseline gets the same treatment as our own scheme. An unfaithful or
//! simply broken baseline is worse than a missing one, because it produces a
//! comparison that looks legitimate — and every comparison in Exp. 2 is against
//! this code.

use std::collections::BTreeSet;

use baseline_odxt::{ClientState, Edb, SecretKey, search, update};
use pqcl_dsse::core::{DocId, Op};
use pqcl_dsse::oracle::Oracle;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn key() -> SecretKey {
    let mut m = [0u8; 128];
    for (i, b) in m.iter_mut().enumerate() {
        *b = u8::try_from(i % 251).unwrap_or(0);
    }
    SecretKey::from_bytes(&m)
}

/// The oracle has no conjunctive query, so intersect its single-keyword
/// answers. That is the definition of a conjunction, and keeping it separate
/// from the scheme is the point — this must not share code with ODXT.
fn oracle_conjunction(o: &Oracle, q: &[Vec<u8>]) -> BTreeSet<DocId> {
    let mut it = q.iter();
    let Some(first) = it.next() else {
        return BTreeSet::new();
    };
    let mut acc = o.search(first);
    for w in it {
        let s = o.search(w);
        acc = acc.intersection(&s).copied().collect();
    }
    acc
}

#[test]
fn conjunctions_match_the_oracle_over_a_random_history() {
    let sk = key();
    let mut st = ClientState::default();
    let mut edb = Edb::new();
    let mut oracle = Oracle::new();
    let mut rng = StdRng::seed_from_u64(0x0D47_2021);

    let vocab: Vec<Vec<u8>> = (0..40u32)
        .map(|i| format!("w{i:02}").into_bytes())
        .collect();

    // ODXT assumes update operations involving the same file identifier are
    // never repeated — §III-C, footnote 3: "when an existing file is to be
    // updated, it is deleted and re-inserted under a fresh file identifier".
    // Honouring that is part of being faithful; violating it would make the
    // scheme look broken for a reason the authors explicitly excluded.
    let mut next_id: DocId = 1;
    let mut live: Vec<(DocId, Vec<Vec<u8>>)> = Vec::new();

    for _ in 0..400 {
        let deleting = !live.is_empty() && rng.gen_bool(0.3);

        if deleting {
            let k = rng.gen_range(0..live.len());
            let (id, terms) = live.swap_remove(k);
            for w in &terms {
                let t = update(&sk, &mut st, Op::Del, id, w);
                edb.apply(&t);
                oracle.update(Op::Del, w, id);
            }
        } else {
            let id = next_id;
            next_id += 1;
            let n = rng.gen_range(1..=5);
            let mut terms: Vec<Vec<u8>> = Vec::new();
            while terms.len() < n {
                let w = vocab[rng.gen_range(0..vocab.len())].clone();
                if !terms.contains(&w) {
                    terms.push(w);
                }
            }
            for w in &terms {
                let t = update(&sk, &mut st, Op::Add, id, w);
                edb.apply(&t);
                oracle.update(Op::Add, w, id);
            }
            live.push((id, terms));
        }
    }

    let mut checked = 0usize;
    for _ in 0..200 {
        let n = rng.gen_range(2..=4);
        let mut q: Vec<Vec<u8>> = Vec::new();
        while q.len() < n {
            let w = vocab[rng.gen_range(0..vocab.len())].clone();
            if !q.contains(&w) {
                q.push(w);
            }
        }

        let got = search(&sk, &st, &edb, &q, &mut rng);
        let want = oracle_conjunction(&oracle, &q);

        assert_eq!(
            got,
            want,
            "ODXT disagreed with the oracle on {:?}",
            q.iter()
                .map(|w| String::from_utf8_lossy(w))
                .collect::<Vec<_>>()
        );
        checked += 1;
    }

    assert_eq!(checked, 200);

    // A suite where every answer is empty would pass while proving nothing.
    let non_empty = (0..vocab.len())
        .filter(|&i| !oracle.search(&vocab[i]).is_empty())
        .count();
    assert!(
        non_empty > 20,
        "the generated history is too sparse to be a real test: only {non_empty} live keywords"
    );
}

#[test]
fn a_deleted_document_stops_matching() {
    let sk = key();
    let mut st = ClientState::default();
    let mut edb = Edb::new();
    let mut rng = StdRng::seed_from_u64(7);

    let a = b"alpha".to_vec();
    let b = b"beta".to_vec();
    let q = vec![a.clone(), b.clone()];

    for w in [&a, &b] {
        let t = update(&sk, &mut st, Op::Add, 42, w);
        edb.apply(&t);
    }
    assert_eq!(
        search(&sk, &st, &edb, &q, &mut rng),
        BTreeSet::from([42]),
        "the document should match before deletion"
    );

    // ⭐ Deletion in ODXT is **document-level**: every `(id, w)` pair of the
    // document is deleted together. That is the paper's own model — §III-C
    // footnote 3, "when an existing file is to be updated, it is deleted and
    // re-inserted (in modified form) under a fresh file identifier" — and
    // `deleting_only_one_pair_is_outside_odxts_model` below pins what happens
    // if you step outside it.
    for w in [&a, &b] {
        let t = update(&sk, &mut st, Op::Del, 42, w);
        edb.apply(&t);
    }

    assert_eq!(
        search(&sk, &st, &edb, &q, &mut rng),
        BTreeSet::new(),
        "the document should not match after deletion"
    );
}

/// ⚠️ **A documented limit of ODXT, not a defect in this transcription.**
///
/// Deleting a single `(id, w)` pair while leaving the document's other pairs
/// live makes ODXT return the document anyway. The mechanism is structural:
///
/// * `Del(42, alpha)` makes `UpdateCnt[alpha] = 2` and `UpdateCnt[beta] = 1`,
///   so Figure 9 picks **beta** as the s-term.
/// * Beta's update list contains only the `add` entry, so `op_j` is never
///   `del` and the removal rule in Figure 9 step 2(d) never fires.
/// * The cross-tag test asks whether `xtag(alpha, 42, add) ∈ XSet`, which is
///   true — 42 *was* added to alpha. Deleting it appended a *separate*
///   `op = del` cross-tag; it did not retract the original.
///
/// ⭐ **Why this is recorded rather than fixed.** Our own schemes support
/// per-pair deletion, so a comparison workload containing one would make ODXT
/// look wrong — a strawman in our favour, which the baseline reading rule in `baselines/UPGRADES.md`
/// exists to prevent. Exp. 2 must therefore delete at document granularity.
/// See `../UPGRADES.md`.
///
/// This test asserts the *actual* behaviour. If a future change makes ODXT
/// return the empty set here, that is a deviation from the paper and this test
/// should fail loudly rather than quietly start passing for a better reason.
#[test]
fn deleting_only_one_pair_is_outside_odxts_model() {
    let sk = key();
    let mut st = ClientState::default();
    let mut edb = Edb::new();
    let mut rng = StdRng::seed_from_u64(13);

    for w in [b"alpha".as_slice(), b"beta".as_slice()] {
        let t = update(&sk, &mut st, Op::Add, 42, w);
        edb.apply(&t);
    }
    let t = update(&sk, &mut st, Op::Del, 42, b"alpha");
    edb.apply(&t);

    // The s-term flipped to beta, which is the whole cause.
    assert_eq!(st.update_count(b"alpha"), 2);
    assert_eq!(st.update_count(b"beta"), 1);

    let q = vec![b"alpha".to_vec(), b"beta".to_vec()];
    assert_eq!(
        search(&sk, &st, &edb, &q, &mut rng),
        BTreeSet::from([42]),
        "ODXT's behaviour outside its stated deletion model has changed;          re-read NDSS 2021 §III-C before touching this"
    );
}

#[test]
fn a_document_missing_one_conjunct_does_not_match() {
    let sk = key();
    let mut st = ClientState::default();
    let mut edb = Edb::new();
    let mut rng = StdRng::seed_from_u64(9);

    let t = update(&sk, &mut st, Op::Add, 1, b"alpha");
    edb.apply(&t);
    let t = update(&sk, &mut st, Op::Add, 2, b"alpha");
    edb.apply(&t);
    let t = update(&sk, &mut st, Op::Add, 2, b"beta");
    edb.apply(&t);

    let q = vec![b"alpha".to_vec(), b"beta".to_vec()];
    assert_eq!(
        search(&sk, &st, &edb, &q, &mut rng),
        BTreeSet::from([2]),
        "only the document carrying both terms should match"
    );
}

/// The leakage instrument must not change the server's answer, and must see
/// what the server sees: one view per candidate, the handle it was asked for,
/// and every lookup it made with its real outcome.
#[test]
fn the_observed_server_answers_identically_and_sees_every_lookup() {
    use baseline_odxt::{search_server, search_server_observed, search_token};
    let sk = key();
    let mut st = ClientState::default();
    let mut edb = Edb::new();
    for (id, w) in [
        (1, "alpha"),
        (2, "alpha"),
        (2, "beta"),
        (3, "alpha"),
        (3, "gamma"),
    ] {
        edb.apply(&update(&sk, &mut st, Op::Add, id, w.as_bytes()));
    }
    let q = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    let token = search_token(&sk, &st, &q, &mut StdRng::seed_from_u64(3)).expect("token");
    let plain = search_server(&edb, &token);
    let (observed, view) = search_server_observed(&edb, &token);
    assert_eq!(plain.entries, observed.entries);
    assert_eq!(view.len(), token.stoken_list.len());
    for (v, addr) in view.iter().zip(&token.stoken_list) {
        assert_eq!(&v.stag_addr, addr);
        assert_eq!(v.lookups.len(), q.len() - 1);
    }
    // The hits the view records are the counts the server returned.
    for ((_, _, cnt), v) in observed.entries.iter().zip(&view) {
        assert_eq!(*cnt, 1 + v.lookups.iter().filter(|(_, hit)| *hit).count());
    }
    // Deterministic per (x-term, document): the same query sees the same xtags.
    let token2 = search_token(&sk, &st, &q, &mut StdRng::seed_from_u64(4)).expect("token");
    let (_, view2) = search_server_observed(&edb, &token2);
    let tags = |v: &[baseline_odxt::ProbeView]| -> BTreeSet<[u8; 32]> {
        v.iter()
            .flat_map(|p| p.lookups.iter().map(|(t, _)| *t))
            .collect()
    };
    assert_eq!(tags(&view), tags(&view2), "xtags must link across queries");
}

/// The s-term rule is the whole performance argument: the transcript size is
/// tied to the least-updated term, not to the query order.
#[test]
fn the_s_term_is_the_least_updated_regardless_of_query_order() {
    let sk = key();
    let mut st = ClientState::default();
    let mut edb = Edb::new();
    let mut rng = StdRng::seed_from_u64(11);

    // "rare" gets one update, "common" gets thirty.
    let t = update(&sk, &mut st, Op::Add, 1, b"rare");
    edb.apply(&t);
    for id in 1..=30 {
        let t = update(&sk, &mut st, Op::Add, id, b"common");
        edb.apply(&t);
    }

    let forward = vec![b"common".to_vec(), b"rare".to_vec()];
    let reversed = vec![b"rare".to_vec(), b"common".to_vec()];

    let a = baseline_odxt::search_token(&sk, &st, &forward, &mut rng).expect("token");
    let b = baseline_odxt::search_token(&sk, &st, &reversed, &mut rng).expect("token");

    assert_eq!(a.stoken_list.len(), 1, "the s-term should be the rare term");
    assert_eq!(
        b.stoken_list.len(),
        1,
        "query order must not change the s-term"
    );

    assert_eq!(
        search(&sk, &st, &edb, &forward, &mut rng),
        search(&sk, &st, &edb, &reversed, &mut rng),
        "query order must not change the answer"
    );
}

/// Figure 9 step 5(e). Correctness cannot see this — the server only counts
/// matches — so without a direct test a no-op shuffle would pass everything
/// while leaking which x-term produced each hit.
#[test]
fn cross_token_rows_are_permuted() {
    let sk = key();
    let mut st = ClientState::default();

    // One s-term update, so there is exactly one row, and enough x-terms that
    // an unpermuted row is overwhelmingly unlikely to appear by chance.
    let mut edb = Edb::new();
    let t = update(&sk, &mut st, Op::Add, 1, b"sterm");
    edb.apply(&t);
    for i in 0..8u32 {
        let w = format!("x{i}").into_bytes();
        for id in 1..=10u64 {
            let t = update(&sk, &mut st, Op::Add, id, &w);
            edb.apply(&t);
        }
    }

    let mut q = vec![b"sterm".to_vec()];
    for i in 0..8u32 {
        q.push(format!("x{i}").into_bytes());
    }

    // Two draws from different RNG states must differ somewhere, or nothing is
    // being permuted.
    let mut r1 = StdRng::seed_from_u64(1);
    let mut r2 = StdRng::seed_from_u64(2);
    let a = baseline_odxt::search_token(&sk, &st, &q, &mut r1).expect("token");
    let b = baseline_odxt::search_token(&sk, &st, &q, &mut r2).expect("token");

    assert_eq!(a.xtoken_list.len(), 1);
    assert_eq!(a.xtoken_list[0].len(), 8);
    assert_ne!(
        a.xtoken_list[0], b.xtoken_list[0],
        "cross-token rows are not being permuted; Figure 9 step 5(e) is missing"
    );

    // …and permuting must not change the answer.
    let mut r3 = StdRng::seed_from_u64(3);
    let mut r4 = StdRng::seed_from_u64(4);
    assert_eq!(
        search(&sk, &st, &edb, &q, &mut r3),
        search(&sk, &st, &edb, &q, &mut r4),
        "the permutation changed the result, so it is not a permutation"
    );
}
