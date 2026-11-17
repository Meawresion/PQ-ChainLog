//! `DSSE_SKQ` — forward, Type-II backward and content private DSSE for spatial
//! keyword queries, used one-dimensionally.
//!
//! Xiangyu Wang, Jianfeng Ma, Ximeng Liu, Yinbin Miao, Yang Liu and Robert H.
//! Deng, IEEE Transactions on Dependable and Secure Computing 20(4), pp.
//! 3358–3370, 2023.
//!
//! # Provenance
//!
//! Transcribed from Algorithms 1 and 2 and §4.2 of
//! `ref-papers/Forward_Backward_and_Content_Private_DSSE_for_Spatial_Keyword_Queries.pdf`,
//! read directly as the baseline reading rule in `baselines/UPGRADES.md` requires. Deviations are in
//! `../UPGRADES.md`:
//!
//! * **One dimension.** The Hilbert curve of one dimension is the identity, so
//!   `PreCode(v)` is `v`'s binary prefixes and `PreCover` the best prefix cover.
//! * **A typo.** Alg. 2 lines 18, 21 and 22 touch `KDB` for prefix entries, which
//!   Alg. 1 line 18 stores in `SDB`. They are read as `SDB`.
//! * **Several numeric attributes** get one prefix family each, under their own
//!   label, so a stream with four attributes indexes at the same depths as ours.
//!
//! # The scheme
//!
//! Postings are a bitmap in `Z_{2^l}`, one per update, encrypted as `sk + B`. An
//! update token is `H₁(K'_w, T_c)`, with `T_c` a GGM leaf: the server can derive
//! tokens for `[0, c]` from a constrained key and nothing beyond, which is forward
//! privacy. It sums the ciphertexts it finds, and only the client can open the
//! sum, which is content privacy. Insertion and deletion are the same operation.
//!
//! ⭐ **Search compacts** (Alg. 2 lines 21–22), so a second search walks less. The
//! client's decryption does not shrink: it still sums `c + 1` one-time keys.
//!
//! ⭐ **`return ∅` on an untouched prefix** (Alg. 2 line 9) is a whole-query
//! answer, the same limitation as Zuo et al.'s, so the same workload rule applies:
//! every value is updated once.
//!
//! # ⛔ What this is for
//!
//! Exps. 1 and 4's keyword-and-range baseline, and nothing else. No part of
//! PQ-ChainLog may depend on it.

use std::collections::HashMap;

pub use baseline_zuo22::{BinaryTree, BitString};
use pqcl_ggm::{ConstrainedKey, MasterKey, PathEval};
use pqcl_primitives::xof;

const F: u8 = 0x61;
const H1: u8 = 0x62;
const H2: u8 = 0x63;

/// An update token, `UT`.
pub type Token = [u8; 32];

/// `T[w]`: per-keyword client state.
struct Chain {
    /// `K'_w`.
    k2: [u8; 32],
    /// `K_w`, as a GGM root.
    root: MasterKey,
    /// The same incremental evaluator our `Π_core` uses, so neither scheme pays
    /// `ℓ` PRG calls per update where the other pays a few.
    path: PathEval,
    c: u64,
}

/// One label's update: to `SDB` for a prefix, `KDB` for a keyword.
#[derive(Debug, Clone)]
pub struct UpdateMsg {
    /// `UT_{c+1}`.
    pub ut: Token,
    /// `e_{c+1}`.
    pub e: BitString,
    /// Which map.
    pub to_sdb: bool,
}

/// What the client sends per label: `{K'_w, ST_w, c}`.
pub struct SearchLabel {
    k2: [u8; 32],
    st: ConstrainedKey,
    c: u64,
}

impl SearchLabel {
    /// Bytes on the wire.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        32 + self.st.wire_bytes() + 8
    }
}

/// A whole search token.
pub struct SearchToken {
    /// One per prefix of the best prefix cover.
    pub prefixes: Vec<SearchLabel>,
    /// One per keyword.
    pub words: Vec<SearchLabel>,
    /// See [`Client::multi_valued`].
    per_prefix: bool,
}

impl SearchToken {
    /// Bytes sent up.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.prefixes
            .iter()
            .chain(&self.words)
            .map(SearchLabel::wire_bytes)
            .sum()
    }
}

/// The server's reply: `SumP` and `{Sum_e^w}`.
#[derive(Debug, Clone)]
pub struct Reply {
    /// `SumP`.
    pub sum_p: BitString,
    /// `{Sum_e^w}`, in the token's order.
    pub sum_w: Vec<BitString>,
    /// Each prefix's sum instead of `SumP`, in the token's order, when the token
    /// asked for it ([`Client::multi_valued`]).
    pub per_prefix: Vec<BitString>,
}

impl Reply {
    /// Bytes sent down.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.sum_p.as_bytes().len()
            + self
                .sum_w
                .iter()
                .chain(&self.per_prefix)
                .map(|s| s.as_bytes().len())
                .sum::<usize>()
    }
}

/// The server's `EDB = {SDB, KDB}`.
#[derive(Debug, Default, Clone)]
pub struct Edb {
    sdb: HashMap<Token, BitString>,
    kdb: HashMap<Token, BitString>,
}

impl Edb {
    /// Apply one update's messages (Alg. 1 lines 18–19).
    pub fn apply(&mut self, msgs: Vec<UpdateMsg>) {
        for m in msgs {
            if m.to_sdb {
                self.sdb.insert(m.ut, m.e);
            } else {
                self.kdb.insert(m.ut, m.e);
            }
        }
    }

    /// Live entries over both maps. Falls after a search.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sdb.len() + self.kdb.len()
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sdb.is_empty() && self.kdb.is_empty()
    }

    /// Bytes stored, label + value: `UT` and the `l`-bit ciphertext.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.sdb
            .values()
            .chain(self.kdb.values())
            .map(|e| 32 + e.as_bytes().len())
            .sum()
    }
}

/// Alg. 2 lines 13–23 for one label.
///
/// ⚠️ The server does not know where a compacted chain ends, so it steps down one
/// leaf at a time until an entry is missing (line 19). Stepping costs `ℓ` PRG
/// calls per leaf; expanding all of `[0, c]` costs about two per leaf but walks
/// the whole history. So this steps twice and then expands if the chain is still
/// going. That is the cheaper of the two for a cold search and for a warm one with
/// no update since the last, which are the two Exp. 4 measures, so the timing is
/// about the scheme. A warm search after new updates would expand where stepping
/// a few more leaves were cheaper; no cell measures that case.
fn walk(map: &mut HashMap<Token, BitString>, t: &SearchLabel, l: usize) -> BitString {
    let mut sum = BitString::zero(l);
    let mut head: Option<Token> = None;
    let mut i = t.c;
    let mut steps = 0;
    let mut done = false;
    while steps < 2 && !done {
        let Ok(leaf) = t.st.eval(i) else { break };
        let ut = h(H1, &t.k2, &leaf);
        head.get_or_insert(ut);
        match map.remove(&ut) {
            Some(e) => sum = sum.add(&e),
            None => done = true,
        }
        steps += 1;
        if i == 0 {
            done = true;
        } else {
            i -= 1;
        }
    }
    if !done {
        let mut rest = t.st.expand();
        rest.retain(|(idx, _)| *idx <= i);
        rest.sort_by_key(|(idx, _)| core::cmp::Reverse(*idx));
        for (_, leaf) in rest {
            match map.remove(&h(H1, &t.k2, &leaf)) {
                Some(e) => sum = sum.add(&e),
                None => break,
            }
        }
    }
    // Line 22: one entry replaces the walked chain.
    if let Some(ut) = head {
        map.insert(ut, sum.clone());
    }
    sum
}

/// `Search`, server side.
#[must_use]
pub fn server_search(edb: &mut Edb, token: &SearchToken, l: usize) -> Reply {
    let mut sum_p = BitString::zero(l);
    let mut per_prefix = Vec::new();
    for p in &token.prefixes {
        let s = walk(&mut edb.sdb, p, l);
        if token.per_prefix {
            per_prefix.push(s);
        } else {
            sum_p = sum_p.add(&s);
        }
    }
    let sum_w = token
        .words
        .iter()
        .map(|w| walk(&mut edb.kdb, w, l))
        .collect();
    Reply {
        sum_p,
        sum_w,
        per_prefix,
    }
}

/// The client.
pub struct Client {
    k_s: [u8; 32],
    /// `l`: the bitmap width.
    l: usize,
    /// One tree per numeric attribute.
    trees: Vec<BinaryTree>,
    t: HashMap<Vec<u8>, Chain>,
    per_prefix: bool,
}

impl Client {
    /// `Setup(1^λ)`, with one prefix family per entry of `domains`.
    ///
    /// # Panics
    ///
    /// If `l` is zero.
    #[must_use]
    pub fn setup(k_s: [u8; 32], l: usize, domains: &[u64]) -> Self {
        assert!(l > 0, "the bitmap needs at least one file slot");
        Self {
            k_s,
            l,
            trees: domains.iter().map(|d| BinaryTree::new(*d)).collect(),
            t: HashMap::new(),
            per_prefix: false,
        }
    }

    /// For a stream where one document can hold several values of one attribute.
    ///
    /// ⚠️ The paper's object has one point, so its best-cover prefixes hold disjoint
    /// documents and line 23 can **add** them into `SumP`. With several values per
    /// document, one document can sit under two prefixes of a cover, and adding `2^i`
    /// twice carries into a neighbour's bit. So the server returns each prefix's sum
    /// and the client ORs them after decrypting: the same work, minus one addition,
    /// and `|BPC|` bitmaps down instead of one. Exp. 4's `D > N` cells need this; any
    /// other use keeps the printed line. `UPGRADES.md` records it.
    #[must_use]
    pub const fn multi_valued(mut self) -> Self {
        self.per_prefix = true;
        self
    }

    /// The bitmap width.
    #[must_use]
    pub const fn width(&self) -> usize {
        self.l
    }

    fn keys(&self, label: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut input = Vec::with_capacity(33 + label.len());
        input.push(F);
        input.extend_from_slice(&self.k_s);
        input.extend_from_slice(label);
        let out = xof::shake256(&input, 64);
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        a.copy_from_slice(&out[..32]);
        b.copy_from_slice(&out[32..]);
        (a, b)
    }

    fn prefix_label(attr: usize, node: [u8; 16]) -> Vec<u8> {
        let mut v = Vec::with_capacity(18);
        v.push(b'p');
        v.push(u8::try_from(attr).unwrap_or(u8::MAX));
        v.extend_from_slice(&node);
        v
    }

    fn word_label(w: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + w.len());
        v.push(b'w');
        v.extend_from_slice(w);
        v
    }

    /// Lines 3–8 / 11–16 for one label.
    fn one(&mut self, label: &[u8], b: &BitString, to_sdb: bool) -> UpdateMsg {
        if !self.t.contains_key(label) {
            let (k, k2) = self.keys(label);
            let root = MasterKey::new(k);
            let path = root.path_eval();
            self.t.insert(
                label.to_vec(),
                Chain {
                    k2,
                    root,
                    path,
                    c: u64::MAX, // c = −1
                },
            );
        }
        let l = self.l;
        let Some(ch) = self.t.get_mut(label) else {
            unreachable!("inserted above");
        };
        ch.c = ch.c.wrapping_add(1);
        let leaf = ch.path.eval(ch.c);
        let ut = h(H1, &ch.k2, &leaf);
        let sk = one_time_key(&ch.k2, ch.c, l);
        UpdateMsg {
            ut,
            e: b.add(&sk),
            to_sdb,
        }
    }

    /// `Update(O = {points, W}, B)`: every prefix of every point, every keyword.
    ///
    /// `points` is `(attribute, value)`. `B` is `insert_delta(i)` or
    /// `delete_delta(i)`; the scheme cannot tell them apart.
    ///
    /// # Panics
    ///
    /// If `B`'s width is not `l`, or a value is outside its attribute's domain.
    pub fn update(
        &mut self,
        points: &[(usize, u64)],
        words: &[&[u8]],
        b: &BitString,
    ) -> Vec<UpdateMsg> {
        assert_eq!(b.bits(), self.l, "bitmap width does not match the setup");
        let mut msgs = Vec::new();
        for (attr, v) in points {
            for node in self.trees[*attr].path(*v) {
                let label = Self::prefix_label(*attr, node.keyword());
                msgs.push(self.one(&label, b, true));
            }
        }
        for w in words {
            msgs.push(self.one(&Self::word_label(w), b, false));
        }
        msgs
    }

    /// [`Client::update`] for a stream where one document can hold **several
    /// values of one attribute**, which the paper never has: its object has one
    /// point.
    ///
    /// ⚠️ A bitmap entry is a bit, and `Enc` adds in `Z_{2^l}`. Adding `2^i` twice
    /// under one label carries into bit `i + 1`: a wrong document, not a wrong
    /// count. So a label already holding this document is skipped, which is what a
    /// client keeping a set must do, and it is also fewer updates. `seen` holds what
    /// has been sent. `UPGRADES.md` records it.
    pub fn update_point_once(
        &mut self,
        attr: usize,
        value: u64,
        doc: usize,
        seen: &mut std::collections::HashSet<(Vec<u8>, usize)>,
    ) -> Vec<UpdateMsg> {
        let b = BitString::insert_delta(self.l, doc);
        let mut msgs = Vec::new();
        for node in self.trees[attr].path(value) {
            let label = Self::prefix_label(attr, node.keyword());
            if seen.insert((label.clone(), doc)) {
                msgs.push(self.one(&label, &b, true));
            }
        }
        msgs
    }

    fn label_token(&self, label: &[u8]) -> Option<SearchLabel> {
        let ch = self.t.get(label)?;
        let st = ch.root.constrain_prefix(ch.c + 1).ok()?;
        Some(SearchLabel {
            k2: ch.k2,
            st,
            c: ch.c,
        })
    }

    /// `Search`, client side, lines 1–11. `None` is `return ∅`: any untouched
    /// prefix or keyword ends the whole query, as printed.
    #[must_use]
    pub fn search_token(
        &self,
        range: Option<(usize, u64, u64)>,
        words: &[&[u8]],
    ) -> Option<SearchToken> {
        let mut prefixes = Vec::new();
        if let Some((attr, from, to)) = range {
            for node in self.trees[attr].cover(from, to) {
                prefixes.push(self.label_token(&Self::prefix_label(attr, node.keyword()))?);
            }
        }
        let words = words
            .iter()
            .map(|w| self.label_token(&Self::word_label(w)))
            .collect::<Option<Vec<_>>>()?;
        Some(SearchToken {
            prefixes,
            words,
            per_prefix: self.per_prefix,
        })
    }

    fn sum_keys(&self, t: &SearchLabel) -> BitString {
        let mut s = BitString::zero(self.l);
        for i in 0..=t.c {
            s = s.add(&one_time_key(&t.k2, i, self.l));
        }
        s
    }

    /// Lines 35–46, without the AND: the range bitmap and each keyword's bitmap,
    /// which §4.2's Boolean step combines.
    #[must_use]
    pub fn decrypt(&self, token: &SearchToken, reply: &Reply) -> (BitString, Vec<BitString>) {
        let br = if token.per_prefix {
            token
                .prefixes
                .iter()
                .zip(&reply.per_prefix)
                .fold(BitString::zero(self.l), |acc, (p, s)| {
                    or(&acc, &s.sub(&self.sum_keys(p)))
                })
        } else {
            let mut sk_p = BitString::zero(self.l);
            for p in &token.prefixes {
                sk_p = sk_p.add(&self.sum_keys(p));
            }
            reply.sum_p.sub(&sk_p)
        };
        let bw = token
            .words
            .iter()
            .zip(&reply.sum_w)
            .map(|(t, s)| s.sub(&self.sum_keys(t)))
            .collect();
        (br, bw)
    }

    /// Bytes the client keeps: two keys and a counter per label.
    #[must_use]
    pub fn client_bytes(&self) -> usize {
        self.t.keys().map(|l| l.len() + 72).sum()
    }
}

/// `sk_i = H₂(K', i)`, widened to `l` bits.
fn one_time_key(k2: &[u8; 32], i: u64, l: usize) -> BitString {
    let mut input = [0u8; 41];
    input[0] = H2;
    input[1..33].copy_from_slice(k2);
    input[33..].copy_from_slice(&i.to_be_bytes());
    BitString::from_bytes(l, &xof::shake256(&input, l.div_ceil(8)))
}

fn h(domain: u8, key: &[u8; 32], input: &[u8; 32]) -> Token {
    let mut buf = [0u8; 65];
    buf[0] = domain;
    buf[1..33].copy_from_slice(key);
    buf[33..].copy_from_slice(input);
    let mut t = [0u8; 32];
    t.copy_from_slice(&xof::shake256(&buf, 32));
    t
}

/// §4.2's client-side Boolean step: `a AND b`.
#[must_use]
pub fn and(a: &BitString, b: &BitString) -> BitString {
    zip(a, b, |x, y| x & y)
}

/// §4.2's client-side Boolean step: `a OR b`.
#[must_use]
pub fn or(a: &BitString, b: &BitString) -> BitString {
    zip(a, b, |x, y| x | y)
}

/// §4.2's client-side Boolean step: `NOT a`, within the bitmap's width.
#[must_use]
pub fn not(a: &BitString) -> BitString {
    let bytes: Vec<u8> = a.as_bytes().iter().map(|x| !x).collect();
    BitString::from_bytes(a.bits(), &bytes)
}

fn zip(a: &BitString, b: &BitString, f: impl Fn(u8, u8) -> u8) -> BitString {
    let bytes: Vec<u8> = a
        .as_bytes()
        .iter()
        .zip(b.as_bytes())
        .map(|(x, y)| f(*x, *y))
        .collect();
    BitString::from_bytes(a.bits(), &bytes)
}

/// The whole search in order: `(range bitmap, keyword bitmaps)`, or `None`.
pub fn search(
    client: &Client,
    edb: &mut Edb,
    range: Option<(usize, u64, u64)>,
    words: &[&[u8]],
) -> Option<(BitString, Vec<BitString>)> {
    let token = client.search_token(range, words)?;
    let reply = server_search(edb, &token, client.width());
    Some(client.decrypt(&token, &reply))
}
