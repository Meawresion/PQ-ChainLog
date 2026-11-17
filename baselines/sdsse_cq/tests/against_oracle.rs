//! Both schemes against a plaintext oracle: a fast, wrong baseline is a strawman
//! in our favour. The harnesses repeat this on the real corpus before timing.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use baseline_sdsse_cq::{Client, Observer, Server, Variant};
use pqcl_dsse::core::Op;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const VOCAB: usize = 30;

type Oracle = BTreeMap<Vec<u8>, BTreeSet<u64>>;

fn word(i: usize) -> Vec<u8> {
    format!("w{i:02}").into_bytes()
}

fn want(oracle: &Oracle, q: &[Vec<u8>]) -> BTreeSet<u64> {
    q.iter()
        .map(|w| oracle.get(w).cloned().unwrap_or_default())
        .reduce(|a, b| a.intersection(&b).copied().collect())
        .unwrap_or_default()
}

/// Random documents, then document-granular deletions, then every query twice
/// (first and repeat), then more updates and every query again.
fn run(variant: Variant) {
    let mut rng = StdRng::seed_from_u64(0x0C0);
    let mut docs: Vec<Vec<Vec<u8>>> = Vec::new();
    for _ in 0..300 {
        let mut kws: BTreeSet<usize> = BTreeSet::new();
        for _ in 0..rng.gen_range(2..8) {
            // Skewed, so conjuncts have different volumes.
            kws.insert(rng.gen_range(0..VOCAB) * rng.gen_range(0..VOCAB) / VOCAB);
        }
        docs.push(kws.into_iter().map(word).collect());
    }

    // True deletion counts, as the harness gives them (§1cu.2).
    let deleted: Vec<usize> = (0..docs.len()).step_by(10).collect();
    let mut del_count: HashMap<Vec<u8>, usize> = HashMap::new();
    for d in &deleted {
        for w in &docs[*d] {
            *del_count.entry(w.clone()).or_insert(0) += 1;
        }
    }

    let mut c = Client::setup(variant, &[0x77; 32], del_count);
    let mut s = Server::default();
    let mut oracle: Oracle = BTreeMap::new();
    for (i, kws) in docs.iter().enumerate() {
        for w in kws {
            c.update(&mut s, Op::Add, w, i as u64, &mut rng);
            oracle.entry(w.clone()).or_default().insert(i as u64);
        }
    }
    for d in &deleted {
        for w in &docs[*d] {
            c.update(&mut s, Op::Del, w, *d as u64, &mut rng);
            oracle.get_mut(w).map(|v| v.remove(&(*d as u64)));
        }
    }

    let queries: Vec<Vec<Vec<u8>>> = (0..VOCAB - 2)
        .map(|i| vec![word(i), word(i + 1)])
        .chain((0..VOCAB - 3).map(|i| vec![word(i), word(i + 1), word(i + 2)]))
        .collect();
    for round in 0..2 {
        for q in &queries {
            assert_eq!(
                c.search(&mut s, q, &mut rng),
                want(&oracle, q),
                "{variant:?} round {round} on {q:?}"
            );
        }
    }

    // After every key has been refreshed: new documents, then a new deletion of
    // a document already cached by the searches above.
    for i in 300..340usize {
        let kws = [word(i % 5), word(5 + i % 5)];
        for w in &kws {
            c.update(&mut s, Op::Add, w, i as u64, &mut rng);
            oracle.entry(w.clone()).or_default().insert(i as u64);
        }
    }
    let victim = 1usize;
    for w in &docs[victim] {
        c.update(&mut s, Op::Del, w, victim as u64, &mut rng);
        oracle.get_mut(w).map(|v| v.remove(&(victim as u64)));
    }
    for q in &queries {
        assert_eq!(
            c.search(&mut s, q, &mut rng),
            want(&oracle, q),
            "{variant:?} after the interleaved updates, on {q:?}"
        );
    }
}

#[test]
fn sdsse_cq_agrees_with_the_oracle() {
    run(Variant::Cq);
}

#[test]
fn sdsse_cq_s_agrees_with_the_oracle() {
    run(Variant::CqS);
}

#[test]
fn a_timed_first_search_can_be_rolled_back_exactly() {
    for variant in [Variant::Cq, Variant::CqS] {
        let mut rng = StdRng::seed_from_u64(9);
        let mut c = Client::setup(variant, &[0x78; 32], HashMap::new());
        let mut s = Server::default();
        for i in 0..50u64 {
            c.update(&mut s, Op::Add, b"rare", i, &mut rng);
            if i % 2 == 0 {
                c.update(&mut s, Op::Add, b"common", i, &mut rng);
            }
        }
        let before = s.entries();
        let terms: Vec<&[u8]> = vec![b"common", b"rare"];
        let want: BTreeSet<u64> = (0..50).step_by(2).collect();
        for _ in 0..3 {
            let mut rb = c.checkpoint(&terms);
            let token = c.search_token(&terms, &mut rng);
            let token = token.unwrap_or_else(|| unreachable!("both terms exist"));
            let res = s.search(&token, &mut rb, None);
            assert_eq!(Client::finalise(&token, &res), want, "{variant:?}");
            c.rollback(&mut s, rb);
            assert_eq!(
                s.entries(),
                before,
                "{variant:?}: a rollback must restore EDB"
            );
        }
    }
}

#[test]
fn a_term_never_added_makes_the_answer_empty() {
    let mut rng = StdRng::seed_from_u64(3);
    let mut c = Client::setup(Variant::Cq, &[1; 32], HashMap::new());
    let mut s = Server::default();
    c.update(&mut s, Op::Add, b"a", 1, &mut rng);
    assert!(
        c.search(&mut s, &[b"a".to_vec(), b"b".to_vec()], &mut rng)
            .is_empty()
    );
    // ⭐ And it left `a` searchable: an absent x-term must be caught before `a`'s
    // Aura key is refreshed, or `a`'s entry is stranded under the old key.
    let only_a: Vec<&[u8]> = vec![b"a"];
    let token = c.search_token(&only_a, &mut rng);
    let token = token.unwrap_or_else(|| unreachable!("a was added"));
    let res = s.search(&token, &mut baseline_sdsse_cq::Rollback::default(), None);
    assert_eq!(Client::finalise(&token, &res), BTreeSet::from([1]));
}

/// ⭐ Type-O against Type-O⁻, made executable: the authors' Fig. 2 example. One
/// query's tokens tested against the x-term set a **later** query fetched.
#[test]
fn cross_query_reuse_works_on_cq_and_not_on_cq_s() {
    for (variant, expect) in [(Variant::Cq, true), (Variant::CqS, false)] {
        let mut rng = StdRng::seed_from_u64(11);
        let mut c = Client::setup(variant, &[2; 32], HashMap::new());
        let mut s = Server::default();
        c.update(&mut s, Op::Add, b"w3", 1, &mut rng);
        c.update(&mut s, Op::Add, b"w2", 7, &mut rng);

        // q1 = (w3, w2): retain its tokens and tuples. Nothing matches yet.
        let t1 = c.search_token(&[b"w3", b"w2"], &mut rng);
        let t1 = t1.unwrap_or_else(|| unreachable!());
        let mut rb = baseline_sdsse_cq::Rollback::default();
        let mut seen1 = Observer::default();
        let _ = s.search(&t1, &mut rb, Some(&mut seen1));
        assert!(seen1.tuples.iter().all(|o| o.lookups.iter().all(|l| !l.1)));

        // Then (w2, ind 1) is added, and q2 = (w1, w2) fetches it.
        c.update(&mut s, Op::Add, b"w2", 1, &mut rng);
        c.update(&mut s, Op::Add, b"w1", 1, &mut rng);
        let t2 = c.search_token(&[b"w1", b"w2"], &mut rng);
        let t2 = t2.unwrap_or_else(|| unreachable!());
        let mut rb2 = baseline_sdsse_cq::Rollback::default();
        let mut seen2 = Observer::default();
        let hits2 = s.search(&t2, &mut rb2, Some(&mut seen2));
        assert_eq!(
            hits2.len(),
            1,
            "{variant:?}: q2 itself must match document 1"
        );

        // The reuse: q1's element for its tuple, against q2's fetched x-term set.
        let reused = seen1
            .tuples
            .iter()
            .flat_map(|o| o.lookups.iter().map(|l| l.0))
            .any(|elt| seen2.fetched.contains(&elt));
        assert_eq!(
            reused,
            expect,
            "{variant:?}: reuse across s-terms must {} work",
            if expect { "" } else { "not" }
        );
    }
}
