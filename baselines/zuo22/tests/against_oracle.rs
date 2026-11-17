//! FBDSSE-RQ against a plaintext ground truth.
//!
//! Ground rule #5: every scheme is validated against a plaintext oracle,
//! including deletions. A baseline gets the same treatment as our own code —
//! Exp. 7's every number is measured against this.
//!
//! The oracle here is a plain `BTreeMap<value, set of files>`, deliberately the
//! dumbest thing that is obviously right by inspection.

use std::collections::{BTreeMap, BTreeSet};

use baseline_zuo22::{BitString, Client, Edb, server_update};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Plaintext truth: value → the files currently carrying it.
#[derive(Default)]
struct Oracle {
    by_value: BTreeMap<u64, BTreeSet<usize>>,
}

impl Oracle {
    fn insert(&mut self, v: u64, f: usize) {
        self.by_value.entry(v).or_default().insert(f);
    }
    fn delete(&mut self, v: u64, f: usize) {
        if let Some(s) = self.by_value.get_mut(&v) {
            s.remove(&f);
        }
    }
    fn range(&self, from: u64, to: u64) -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        for (_, s) in self.by_value.range(from..=to) {
            out.extend(s.iter().copied());
        }
        out
    }
}

fn files(bs: &BitString) -> BTreeSet<usize> {
    bs.files().into_iter().collect()
}

/// Every value gets at least one update, which is both what makes the whole
/// cover reachable and exactly what the authors' own experiment does:
/// §7, *"We update one time for each value."*
fn touch_every_value(c: &mut Client, edb: &mut Edb, d: u64, y: usize, rng: &mut impl Rng) {
    for v in 0..d {
        // A zero delta is a real update — it extends the chain and costs a
        // counter — but changes no membership, so it cannot perturb the truth.
        let msgs = c.update(v, &BitString::zero(y), rng);
        server_update(edb, &msgs);
    }
}

#[test]
fn range_queries_match_the_oracle_over_a_random_history() {
    let d = 16u64;
    let y = 64usize;
    let mut rng = StdRng::seed_from_u64(0x2022_0119);

    let mut client = Client::setup([3u8; 32], d, y);
    let mut edb = Edb::new();
    let mut oracle = Oracle::default();

    touch_every_value(&mut client, &mut edb, d, y, &mut rng);

    let mut placed: Vec<(usize, u64)> = Vec::new();

    for f in 0..y {
        let v = rng.gen_range(0..d);
        let msgs = client.update(v, &BitString::insert_delta(y, f), &mut rng);
        server_update(&mut edb, &msgs);
        oracle.insert(v, f);
        placed.push((f, v));
    }

    // Delete about a third of them, exercising the homomorphic subtraction.
    for &(f, v) in placed
        .iter()
        .filter(|_| rng.gen_bool(0.33))
        .collect::<Vec<_>>()
    {
        let msgs = client.update(v, &BitString::delete_delta(y, f), &mut rng);
        server_update(&mut edb, &msgs);
        oracle.delete(v, f);
    }

    let mut non_empty = 0usize;
    for from in 0..d {
        for to in from..d {
            let got = client
                .search(from, to, &mut edb)
                .expect("every value was touched, so no cover node is absent");
            let want = oracle.range(from, to);
            assert_eq!(
                files(&got),
                want,
                "range [{from},{to}] disagreed with the oracle"
            );
            if !want.is_empty() {
                non_empty += 1;
            }
        }
    }

    assert!(
        non_empty > 50,
        "the history is too sparse to be a real test: only {non_empty} non-empty ranges"
    );
}

/// Search is destructive and compacting. Running it twice must give the same
/// answer — the compaction is an optimisation, not a state change the client
/// can observe.
#[test]
fn a_repeated_search_returns_the_same_answer() {
    let d = 8u64;
    let y = 32usize;
    let mut rng = StdRng::seed_from_u64(5);

    let mut client = Client::setup([9u8; 32], d, y);
    let mut edb = Edb::new();
    touch_every_value(&mut client, &mut edb, d, y, &mut rng);

    for (f, v) in [(0usize, 1u64), (1, 3), (2, 3), (3, 6)] {
        let msgs = client.update(v, &BitString::insert_delta(y, f), &mut rng);
        server_update(&mut edb, &msgs);
    }

    let first = client.search(1, 3, &mut edb).expect("cover present");
    let before = edb.len();
    let second = client.search(1, 3, &mut edb).expect("cover present");

    assert_eq!(files(&first), BTreeSet::from([0, 1, 2]));
    assert_eq!(
        files(&first),
        files(&second),
        "compaction changed the answer"
    );
    assert!(
        edb.len() <= before,
        "the second search should not grow the EDB"
    );
}

/// The paper's storage argument: *"for every search, the server can remove all
/// entries corresponding to w and store the final result"*.
#[test]
fn search_compacts_the_server_index() {
    let d = 4u64;
    let y = 16usize;
    let mut rng = StdRng::seed_from_u64(6);

    let mut client = Client::setup([1u8; 32], d, y);
    let mut edb = Edb::new();
    touch_every_value(&mut client, &mut edb, d, y, &mut rng);

    for f in 0..8usize {
        let msgs = client.update(2, &BitString::insert_delta(y, f), &mut rng);
        server_update(&mut edb, &msgs);
    }

    let before = edb.len();
    let got = client.search(2, 2, &mut edb).expect("cover present");
    let after = edb.len();

    assert_eq!(files(&got), (0..8).collect::<BTreeSet<_>>());
    assert!(
        after < before,
        "search did not compact: {before} entries before, {after} after"
    );
}

/// ⚠️ Algorithm 2, `Search` lines 5–7: `return ⊥` if **any** cover node has no
/// history — not a partial answer. Faithful, and a real limitation: a range
/// whose matching files all sit in one half still returns nothing when the
/// other half's cover node was never touched.
///
/// ⭐ Note what is *not* absent. Updating a value walks `TPath`, which touches
/// every ancestor up to the root, so once any leaf has been updated all of its
/// ancestors are reachable. Only a subtree containing no updated leaf is
/// missing — which is why the aborting query below has to reach across to an
/// untouched leaf rather than merely upward.
///
/// Recorded in `../UPGRADES.md`, and the reason Exp. 7's workload must touch
/// every value, as the authors' own experiment does.
#[test]
fn an_untouched_cover_node_aborts_the_whole_query() {
    let d = 8u64;
    let y = 16usize;
    let mut rng = StdRng::seed_from_u64(8);

    let mut client = Client::setup([2u8; 32], d, y);
    let mut edb = Edb::new();

    // Only value 0 is ever updated. That touches leaf w_{0,0} and its
    // ancestors w_{0,1}, w_{0,3}, w_{0,7}.
    let msgs = client.update(0, &BitString::insert_delta(y, 0), &mut rng);
    server_update(&mut edb, &msgs);

    assert!(
        client.search(0, 0, &mut edb).is_some(),
        "the touched leaf should be searchable"
    );
    assert!(
        client.search(0, 1, &mut edb).is_some(),
        "cover([0,1]) is the single ancestor w_(0,1), which the update touched"
    );

    // cover([0,2]) = {w_(0,1), w_(2,2)}, and leaf w_(2,2) was never updated.
    assert!(
        client.search(0, 2, &mut edb).is_none(),
        "cover of [0,2] includes the untouched leaf w_(2,2), so Algorithm 2 returns ⊥"
    );
    assert!(
        client.search(1, 1, &mut edb).is_none(),
        "the untouched leaf w_(1,1) has no history, so Algorithm 2 returns ⊥"
    );
}

/// Deleting a file must remove it from every range that covered it, not just
/// the leaf — the delete propagates up the same path the insert did.
#[test]
fn a_deletion_propagates_to_every_covering_range() {
    let d = 8u64;
    let y = 16usize;
    let mut rng = StdRng::seed_from_u64(12);

    let mut client = Client::setup([4u8; 32], d, y);
    let mut edb = Edb::new();
    touch_every_value(&mut client, &mut edb, d, y, &mut rng);

    let msgs = client.update(5, &BitString::insert_delta(y, 3), &mut rng);
    server_update(&mut edb, &msgs);

    for (from, to) in [(5u64, 5u64), (4, 5), (0, 7), (5, 7)] {
        let got = client.search(from, to, &mut edb).expect("cover present");
        assert!(
            got.get(3),
            "file 3 should be in range [{from},{to}] before deletion"
        );
    }

    let msgs = client.update(5, &BitString::delete_delta(y, 3), &mut rng);
    server_update(&mut edb, &msgs);

    for (from, to) in [(5u64, 5u64), (4, 5), (0, 7), (5, 7)] {
        let got = client.search(from, to, &mut edb).expect("cover present");
        assert!(
            !got.get(3),
            "file 3 should be gone from range [{from},{to}]"
        );
    }
}

/// ⚠️ Pins a limit of the scheme, found by M14 (`UPGRADES.md`, `DSSE_SKQ`): a bitmap
/// adds in `Z_{2^y}`, so one document under two values of a range is added twice
/// and carries into its neighbour's bit. The paper's files have one value each, but
/// `exp7`'s cells with more values than documents break that, and it never checked
/// the answer. The timing is unaffected, since a carry costs nothing.
#[test]
fn a_document_with_two_values_reads_as_its_neighbour() {
    use rand::SeedableRng as _;
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let mut client = baseline_zuo22::Client::setup([9; 32], 8, 16);
    let mut edb = baseline_zuo22::Edb::new();
    for v in [1u64, 2] {
        let delta = baseline_zuo22::BitString::insert_delta(16, 3);
        let msgs = client.update(v, &delta, &mut rng);
        baseline_zuo22::server_update(&mut edb, &msgs);
    }
    let got = client.search(1, 2, &mut edb).map(|b| b.files());
    assert_eq!(
        got,
        Some(vec![4]),
        "document 3 added twice is read as document 4"
    );
}
