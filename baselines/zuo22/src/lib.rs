//! FBDSSE-RQ — forward and Type-R backward private DSSE for range queries.
//!
//! Cong Zuo, Shi-Feng Sun, Joseph K. Liu, Jun Shao, Josef Pieprzyk and Lei Xu,
//! IEEE Transactions on Dependable and Secure Computing, vol. 19 no. 1, 2022.
//!
//! # Provenance
//!
//! Transcribed from Algorithm 1 (binary tree), Algorithm 2 (the scheme) and
//! §2.1 (`P`, the homomorphic-addition encryption) of
//! `ref-papers/Forward_and_Backward_Private_DSSE_for_Range_Queries.pdf`,
//! read directly as the baseline reading rule in `baselines/UPGRADES.md` requires — not from the plan,
//! `LIT-REVIEW.md`, or `draft6.tex`. Deviations are in `../UPGRADES.md`.
//!
//! # The scheme
//!
//! Each file has an attribute value `v ∈ [0, d)`. A value maps to a leaf of a
//! perfect binary tree, and a file is indexed under **every node on the path
//! from its leaf to the root** — which is what makes a range query a search
//! over `O(log d)` keywords rather than over the range.
//!
//! Postings are not identifier lists but a **bitmap** in `Z_{2^y}`, encrypted
//! under a one-time key. Updates are summed homomorphically by the server, so
//! insertion and deletion are the same operation with a different addend, and
//! the server never learns which it applied. That is where Type-R backward
//! privacy comes from.
//!
//! `Update(v, bs)`, per node `w` on the path (Algorithm 2):
//!
//! ```text
//! K_w ‖ K'_w ← F_K(w);   (ST_c, c) ← CT[w]   (⊥ ⇒ c = −1, ST_c random)
//! ST_{c+1}   ←$ {0,1}^λ
//! UT_{c+1}   ← H₁(K_w, ST_{c+1})
//! C_{ST_c}   ← H₂(K_w, ST_{c+1}) ⊕ ST_c
//! sk_{c+1}   ← H₃(K'_w, c+1)
//! e_{c+1}    ← Enc(sk_{c+1}, bs, n)
//! server: EDB[UT_{c+1}] ← (e_{c+1}, C_{ST_c})
//! ```
//!
//! `Search([a,b])`: the client sends `(K_w, ST_c, c)` for each node of the best
//! range cover. The server walks each node's hash chain backwards from `ST_c`,
//! summing ciphertexts, then **compacts** the chain to a single entry. The
//! client sums the matching one-time keys and subtracts.
//!
//! ⭐ **Search is destructive, by design.** The server deletes the chain it
//! walked and writes back `EDB[UT_c] = (Sum_e, ⊥)`. The paper is explicit that
//! this is *"in order to save the server storage"*. A second search over the
//! same node therefore does far less work than the first, so any timing
//! measurement has to say which it measured.
//!
//! # ⛔ What this is for
//!
//! Exp. 7's baseline, and nothing else. No part of PQ-ChainLog may depend on
//! it.

use std::collections::HashMap;

use pqcl_primitives::xof;

pub mod bitmap;
pub mod tree;

pub use bitmap::BitString;
pub use tree::{BinaryTree, Node};

/// Domain separators for the three random oracles. The paper writes `H₁`, `H₂`
/// and `H₃` as distinct oracles; realising them from one XOF without separating
/// the domains would make them the same function.
const H1: u8 = 0x01;
const H2: u8 = 0x02;
const H3: u8 = 0x03;
const F: u8 = 0x04;

/// A `λ`-bit search token.
pub type Token = [u8; 32];

/// The client's per-keyword state: `CT[w] = (ST_c, c)`.
#[derive(Debug, Clone, Copy)]
struct Chain {
    st: Token,
    c: u64,
}

/// Client state `σ = (n, d, K, CT)`. The client keeps `(d, K, CT)` secret.
#[derive(Debug)]
pub struct Client {
    /// `y` — the bitmap width, the maximum number of files. `n = 2^y`.
    y: usize,
    tree: BinaryTree,
    k: [u8; 32],
    ct: HashMap<[u8; 16], Chain>,
}

/// The server's `EDB`.
#[derive(Debug, Default)]
pub struct Edb {
    map: HashMap<Token, (BitString, Option<Token>)>,
}

impl Edb {
    /// An empty `EDB`, as `Setup` leaves it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Live entries. Falls after a search, because search compacts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the `EDB` holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Bytes the server stores, label + value (the Doris size convention H4
    /// uses): `UT` (32 B), then the value `(e, C_ST)` — the `y`-bit bitmap
    /// ciphertext and, except at a chain's head, the 32 B masked token.
    ///
    /// Instrumentation only: a count of
    /// what is stored, not a change to what is stored. `UPGRADES.md` records it.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.map
            .values()
            .map(|(e, c_st)| {
                core::mem::size_of::<Token>() + e.as_bytes().len() + c_st.map_or(0, |t| t.len())
            })
            .sum()
    }
}

/// One `Update` message.
#[derive(Debug, Clone)]
pub struct UpdateToken {
    /// `UT_{c+1}`.
    pub ut: Token,
    /// `e_{c+1}`, the encrypted bitmap delta.
    pub e: BitString,
    /// `C_{ST_c}`, the masked previous search token. `None` at the head of a
    /// chain, which is how the server knows to stop walking.
    pub c_st: Option<Token>,
}

/// What the client sends per cover node: `(K_w, ST_c, c)`.
#[derive(Debug, Clone)]
pub struct SearchToken {
    /// `K_w`, which lets the server recompute `H₁` and `H₂` for this node.
    pub k_w: [u8; 32],
    /// The current search token.
    pub st: Token,
    /// The current counter.
    pub c: u64,
}

impl Client {
    /// `Setup(1^λ)`.
    ///
    /// # Panics
    ///
    /// If `y` is zero or `d` is zero.
    #[must_use]
    pub fn setup(k: [u8; 32], d: u64, y: usize) -> Self {
        assert!(y > 0, "the bitmap needs at least one file slot");
        Self {
            y,
            tree: BinaryTree::new(d),
            k,
            ct: HashMap::new(),
        }
    }

    /// The tree this client indexes against.
    #[must_use]
    pub const fn tree(&self) -> BinaryTree {
        self.tree
    }

    /// Distinct keywords with at least one update.
    #[must_use]
    pub fn keyword_count(&self) -> usize {
        self.ct.len()
    }

    /// `F_K(w) → K_w ‖ K'_w`.
    fn node_keys(&self, w: &Node) -> ([u8; 32], [u8; 32]) {
        // Every field is fixed-width, so plain concatenation is unambiguous.
        let mut input = Vec::with_capacity(49);
        input.push(F);
        input.extend_from_slice(&self.k);
        input.extend_from_slice(&w.keyword());

        let out = xof::shake256(&input, 64);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a.copy_from_slice(&out[..32]);
        b.copy_from_slice(&out[32..]);
        (a, b)
    }

    /// `Update(v, bs, σ, EDB)`, client side — one message per node on the path.
    ///
    /// `bs` is the bitmap **delta**: `insert_delta(i)` to add file `i`,
    /// `delete_delta(i)` to remove it. The scheme itself never distinguishes
    /// them.
    ///
    /// # Panics
    ///
    /// If `v` is outside `[0, d)`, or `bs` is not `y` bits wide.
    pub fn update(&mut self, v: u64, bs: &BitString, rng: &mut impl rand::Rng) -> Vec<UpdateToken> {
        assert_eq!(bs.bits(), self.y, "bitmap width does not match the setup");

        let path = self.tree.path(v);
        let mut msgs = Vec::with_capacity(path.len());

        for w in path {
            let (k_w, k_w_prime) = self.node_keys(&w);
            let key = w.keyword();

            let prev = self.ct.get(&key).copied();
            let (st_c, c): (Option<Token>, i128) = match prev {
                // Algorithm 2 lines 5–7: an absent entry means c = −1 and a
                // fresh random ST_c that no chain entry will ever match — which
                // is what terminates the server's backward walk.
                None => (None, -1),
                Some(ch) => (Some(ch.st), i128::from(ch.c)),
            };

            let mut st_next = [0u8; 32];
            rng.fill_bytes(&mut st_next);
            let c_next = u64::try_from(c + 1).unwrap_or(0);

            let ut = h(H1, &k_w, &st_next);
            let c_st = st_c.map(|prev_st| {
                let mask = h(H2, &k_w, &st_next);
                let mut out = [0u8; 32];
                for i in 0..32 {
                    out[i] = mask[i] ^ prev_st[i];
                }
                out
            });

            let sk = self.one_time_key(&k_w_prime, c_next);
            let e = bs.add(&sk);

            self.ct.insert(
                key,
                Chain {
                    st: st_next,
                    c: c_next,
                },
            );

            msgs.push(UpdateToken { ut, e, c_st });
        }

        msgs
    }

    /// `sk_i = H₃(K'_w, i)`, widened to the full bitmap.
    fn one_time_key(&self, k_w_prime: &[u8; 32], i: u64) -> BitString {
        let mut input = Vec::with_capacity(41);
        input.push(H3);
        input.extend_from_slice(k_w_prime);
        input.extend_from_slice(&i.to_be_bytes());

        let buf = xof::shake256(&input, self.y.div_ceil(8));
        BitString::from_bytes(self.y, &buf)
    }

    /// `Search`, client side, round one.
    ///
    /// ⚠️ Returns `None` if **any** node of the cover has never been updated.
    /// That is Algorithm 2's `Search` lines 5–7 exactly — `return ⊥` for the
    /// whole query, not a partial answer. It is faithful and it is a real
    /// limitation; see `../UPGRADES.md` on how Exp. 7's workload must be built
    /// so this path is not silently exercised.
    #[must_use]
    pub fn search_token(&self, from: u64, to: u64) -> Option<Vec<SearchToken>> {
        let cover = self.tree.cover(from, to);
        let mut out = Vec::with_capacity(cover.len());
        for w in cover {
            let (k_w, _) = self.node_keys(&w);
            let ch = self.ct.get(&w.keyword())?;
            out.push(SearchToken {
                k_w,
                st: ch.st,
                c: ch.c,
            });
        }
        Some(out)
    }

    /// `Search`, client side, final decryption.
    #[must_use]
    pub fn search_finalise(&self, from: u64, to: u64, sum: &BitString) -> Option<BitString> {
        let cover = self.tree.cover(from, to);
        let mut sum_sk = BitString::zero(self.y);

        for w in cover {
            let (_, k_w_prime) = self.node_keys(&w);
            let ch = self.ct.get(&w.keyword())?;
            for i in 0..=ch.c {
                sum_sk = sum_sk.add(&self.one_time_key(&k_w_prime, i));
            }
        }

        Some(sum.sub(&sum_sk))
    }

    /// The three phases in order.
    #[must_use]
    pub fn search(&self, from: u64, to: u64, edb: &mut Edb) -> Option<BitString> {
        let tokens = self.search_token(from, to)?;
        let sum = server_search(edb, &tokens, self.y);
        self.search_finalise(from, to, &sum)
    }
}

/// `Update`, server side.
pub fn server_update(edb: &mut Edb, msgs: &[UpdateToken]) {
    for m in msgs {
        edb.map.insert(m.ut, (m.e.clone(), m.c_st));
    }
}

/// `Search`, server side — Algorithm 2, server lines 10–26.
///
/// Walks each node's chain backwards, summing ciphertexts, and compacts the
/// chain into one entry.
#[must_use]
pub fn server_search(edb: &mut Edb, tokens: &[SearchToken], y: usize) -> BitString {
    let mut sum = BitString::zero(y);

    for t in tokens {
        let mut sum_e = BitString::zero(y);
        let mut st = t.st;

        loop {
            let ut = h(H1, &t.k_w, &st);
            let Some((e, c_st_prev)) = edb.map.remove(&ut) else {
                // The head of a compacted or absent chain. Stopping is correct;
                // the sum so far is the whole history for this node.
                break;
            };
            sum_e = sum_e.add(&e);

            let Some(c_prev) = c_st_prev else {
                break;
            };
            let mask = h(H2, &t.k_w, &st);
            let mut prev = [0u8; 32];
            for i in 0..32 {
                prev[i] = mask[i] ^ c_prev[i];
            }
            st = prev;
        }

        // Compaction: one entry replaces the whole walked chain, and it has no
        // predecessor. Written at UT_c so the *current* token still finds it.
        let ut_c = h(H1, &t.k_w, &t.st);
        edb.map.insert(ut_c, (sum_e.clone(), None));

        sum = sum.add(&sum_e);
    }

    sum
}

/// One of the three random oracles, domain-separated.
fn h(domain: u8, key: &[u8; 32], input: &[u8]) -> Token {
    // `input` is the only variable-length field and it comes last, so the
    // encoding is unambiguous without framing.
    let mut buf = Vec::with_capacity(33 + input.len());
    buf.push(domain);
    buf.extend_from_slice(key);
    buf.extend_from_slice(input);

    let out = xof::shake256(&buf, 32);
    let mut t = [0u8; 32];
    t.copy_from_slice(&out);
    t
}
