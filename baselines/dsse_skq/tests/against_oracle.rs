//! `DSSE_SKQ` against a plaintext oracle: range, keyword, keyword ∧ range and
//! §4.2's Boolean forms, across deletions and compaction.

use std::collections::{BTreeMap, BTreeSet};

use baseline_dsse_skq::{BitString, Client, Edb, and, not, or, search};

const L: usize = 256;
const DOMAIN: u64 = 64;

struct World {
    client: Client,
    edb: Edb,
    /// doc → (value, words)
    docs: BTreeMap<usize, (u64, Vec<&'static [u8]>)>,
}

const WORDS: &[&[u8]] = &[b"alpha", b"beta", b"gamma", b"delta"];

impl World {
    /// Every value is updated once (the workload rule) and every word used.
    fn new() -> Self {
        let mut w = Self {
            client: Client::setup([5; 32], L, &[DOMAIN]),
            edb: Edb::default(),
            docs: BTreeMap::new(),
        };
        for v in 0..DOMAIN {
            let id = usize::try_from(v).unwrap_or(0);
            let words: Vec<&'static [u8]> = WORDS
                .iter()
                .enumerate()
                .filter(|(i, _)| (id >> i) & 1 == 1 || *i == id % 4)
                .map(|(_, x)| *x)
                .collect();
            w.insert(id, v, &words);
        }
        w
    }

    fn insert(&mut self, id: usize, v: u64, words: &[&'static [u8]]) {
        let msgs = self
            .client
            .update(&[(0, v)], words, &BitString::insert_delta(L, id));
        self.edb.apply(msgs);
        self.docs.insert(id, (v, words.to_vec()));
    }

    fn delete(&mut self, id: usize) {
        let Some((v, words)) = self.docs.remove(&id) else {
            return;
        };
        let msgs = self
            .client
            .update(&[(0, v)], &words, &BitString::delete_delta(L, id));
        self.edb.apply(msgs);
    }

    fn range(&self, a: u64, b: u64) -> BTreeSet<usize> {
        self.docs
            .iter()
            .filter(|(_, (v, _))| *v >= a && *v <= b)
            .map(|(i, _)| *i)
            .collect()
    }

    fn word(&self, w: &[u8]) -> BTreeSet<usize> {
        self.docs
            .iter()
            .filter(|(_, (_, ws))| ws.contains(&w))
            .map(|(i, _)| *i)
            .collect()
    }
}

fn set(b: &BitString) -> BTreeSet<usize> {
    b.files().into_iter().collect()
}

fn check_all(w: &mut World) {
    for (a, b) in [(0, 63), (4, 7), (5, 5), (3, 40), (10, 11), (0, 0), (63, 63)] {
        let (br, _) = search(&w.client, &mut w.edb, Some((0, a, b)), &[])
            .unwrap_or_else(|| unreachable!("every value was updated once"));
        assert_eq!(set(&br), w.range(a, b), "range [{a},{b}]");

        let (br, bw) = search(&w.client, &mut w.edb, Some((0, a, b)), &[b"alpha", b"beta"])
            .unwrap_or_else(|| unreachable!());
        let want: BTreeSet<usize> = w
            .range(a, b)
            .intersection(&w.word(b"alpha"))
            .copied()
            .collect::<BTreeSet<_>>()
            .intersection(&w.word(b"beta"))
            .copied()
            .collect();
        assert_eq!(
            set(&and(&and(&br, &bw[0]), &bw[1])),
            want,
            "alpha∧beta∧[{a},{b}]"
        );

        // §4.2: Boolean on the keyword bitmaps first, then AND with the range.
        let or_want: BTreeSet<usize> = w
            .word(b"alpha")
            .union(&w.word(b"beta"))
            .copied()
            .collect::<BTreeSet<_>>()
            .intersection(&w.range(a, b))
            .copied()
            .collect();
        assert_eq!(
            set(&and(&br, &or(&bw[0], &bw[1]))),
            or_want,
            "(alpha∨beta)∧[{a},{b}]"
        );
        let not_want: BTreeSet<usize> = w
            .range(a, b)
            .difference(&w.word(b"alpha"))
            .copied()
            .collect();
        assert_eq!(set(&and(&br, &not(&bw[0]))), not_want, "¬alpha∧[{a},{b}]");
    }
}

#[test]
fn agrees_with_the_oracle_before_and_after_deletions_and_compaction() {
    let mut w = World::new();
    // First search (cold), then again over the compacted chains.
    check_all(&mut w);
    check_all(&mut w);
    // Deletions and insertions after compaction.
    for id in [1usize, 5, 7, 20, 40] {
        w.delete(id);
    }
    w.insert(70, 5, &[b"alpha"]);
    w.insert(71, 6, &[b"beta", b"gamma"]);
    check_all(&mut w);
    check_all(&mut w);
}

#[test]
fn search_compacts_every_chain_it_walks() {
    let mut w = World::new();
    let before = w.edb.len();
    let _ = search(&w.client, &mut w.edb, Some((0, 0, 63)), &[]);
    assert!(
        w.edb.len() < before,
        "a whole-domain search must compact the root's chain"
    );
    let after = w.edb.len();
    let _ = search(&w.client, &mut w.edb, Some((0, 0, 63)), &[]);
    assert_eq!(
        w.edb.len(),
        after,
        "a repeat search has nothing left to compact"
    );
}

#[test]
fn an_untouched_prefix_or_keyword_ends_the_whole_query() {
    let mut client = Client::setup([6; 32], L, &[DOMAIN]);
    let mut edb = Edb::default();
    edb.apply(client.update(&[(0, 3)], &[b"only"], &BitString::insert_delta(L, 0)));
    // [0, 63]'s cover is the root, which every value touches.
    assert!(search(&client, &mut edb, Some((0, 0, 63)), &[]).is_some());
    // [4, 7]'s cover is a subtree nothing touched: line 9, `return ∅`.
    assert!(search(&client, &mut edb, Some((0, 4, 7)), &[]).is_none());
    assert!(search(&client, &mut edb, None, &[b"never"]).is_none());
}

#[test]
fn two_attributes_keep_separate_prefix_families() {
    let mut client = Client::setup([7; 32], L, &[8, 8]);
    let mut edb = Edb::default();
    edb.apply(client.update(&[(0, 1), (1, 6)], &[], &BitString::insert_delta(L, 0)));
    edb.apply(client.update(&[(0, 6), (1, 1)], &[], &BitString::insert_delta(L, 1)));
    let one = |e: &mut Edb, attr, a, b| {
        search(&client, e, Some((attr, a, b)), &[]).map(|(br, _)| br.files())
    };
    assert_eq!(one(&mut edb, 0, 1, 1), Some(vec![0]));
    assert_eq!(one(&mut edb, 1, 1, 1), Some(vec![1]));
}

/// A document with two values under one prefix must not carry into its neighbour.
#[test]
fn a_document_with_two_values_stays_one_bit() {
    let mut client = Client::setup([8; 32], L, &[8]).multi_valued();
    let mut edb = Edb::default();
    let mut seen = std::collections::HashSet::new();
    for (value, doc) in [(1u64, 3usize), (2, 3), (6, 9)] {
        edb.apply(client.update_point_once(0, value, doc, &mut seen));
    }
    let (br, _) = search(&client, &mut edb, Some((0, 0, 7)), &[]).unwrap_or_else(|| unreachable!());
    assert_eq!(
        br.files(),
        vec![3, 9],
        "doc 3 twice would have read as doc 4"
    );
    // [0, 1] and [2, 3] are separate prefixes of this cover, both holding doc 3.
    let (br, _) = search(&client, &mut edb, Some((0, 1, 2)), &[]).unwrap_or_else(|| unreachable!());
    assert_eq!(
        br.files(),
        vec![3],
        "the same document under two cover prefixes"
    );
}
