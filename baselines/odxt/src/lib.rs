//! ODXT — Oblivious Dynamic Cross-Tags.
//!
//! Sikhar Patranabis and Debdeep Mukhopadhyay, *"Forward and Backward Private
//! Conjunctive Searchable Symmetric Encryption"*, NDSS 2021.
//!
//! # Provenance of this code
//!
//! Transcribed from the paper's Figures 7 (`Setup`), 8 (`Update`) and 9
//! (`Search`) in `ref-papers/ODXT_NDSS2021.pdf`, read directly as
//! the baseline reading rule in `baselines/UPGRADES.md` requires. It was **not** written from
//! The build plan, `LIT-REVIEW.md` or `draft6.tex`, any of which
//! could have compressed a detail that matters.
//!
//! Every deviation from the paper is recorded in `../UPGRADES.md`. There are
//! four, all of them forced by the language change, and none of them touching
//! the protocol.
//!
//! # The scheme, as specified
//!
//! Keys: `K_T` for a PRF `F → {0,1}^λ`; `K_X, K_Y, K_Z` for a PRF `F_p → Z_p^*`.
//!
//! `Update(op, (id, w))`:
//!
//! ```text
//! UpdateCnt[w] += 1
//! addr  = F(K_T, w ‖ UpdateCnt[w] ‖ 0)
//! val   = (id ‖ op) ⊕ F(K_T, w ‖ UpdateCnt[w] ‖ 1)
//! α     = F_p(K_Y, id ‖ op) · F_p(K_Z, w ‖ UpdateCnt[w])^{-1}
//! xtag  = g^{F_p(K_X, w) · F_p(K_Y, id ‖ op)}
//! ```
//!
//! The server stores `TSet[addr] = (val, α)` and `XSet[xtag] = 1`.
//!
//! `Search(w₁ ∧ … ∧ wₙ)`, with `w₁` the least-updated term:
//!
//! ```text
//! client: saddr_j    = F(K_T, w₁ ‖ j ‖ 0)                    for j = 1..UpdateCnt[w₁]
//!         xtoken_i,j = g^{F_p(K_X, w_i) · F_p(K_Z, w₁ ‖ j)}   for i = 2..n
//!         (xtoken_·,j permuted within each j)
//! server: xtag_i,j   = xtoken_i,j^{α_j}
//!         cnt_j      = 1 + |{ i : xtag_i,j ∈ XSet }|
//! client: (id_j ‖ op_j) = sval_j ⊕ F(K_T, w₁ ‖ j ‖ 1)
//!         op = add ∧ cnt_j = n  ⇒  include id_j
//!         op = del ∧ cnt_j > 0  ⇒  remove id_j
//! ```
//!
//! ⭐ **Why the exponent identity works.** `xtoken_i,j^{α_j}` expands to
//! `g^{F_p(K_X,w_i) · F_p(K_Z,w₁‖j) · F_p(K_Y,id‖op) · F_p(K_Z,w₁‖j)^{-1}}`,
//! which is exactly `xtag_i,j`. The `F_p(K_Z, w₁‖j)` factors cancel, so the
//! server recomputes the cross-tag without ever learning `(id, op)`. That
//! cancellation is why the group must have **prime** order — see `UPGRADES.md`
//! on Ristretto.
//!
//! # ⛔ What this is for
//!
//! A baseline for Exp. 2, and nothing else. It is not post-quantum — the whole
//! point of the comparison is that its cross-tags rest on a discrete-log group
//! — and no part of PQ-ChainLog may depend on it.

use std::collections::{BTreeSet, HashMap, HashSet};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use pqcl_dsse::core::{DocId, Op};
use rand::seq::SliceRandom;

pub mod prf;

pub use prf::{PrfKey, prf_bytes, prf_scalar};

/// The paper's `sk = (K_T, K_X, K_Y, K_Z)`.
#[derive(Debug, Clone)]
pub struct SecretKey {
    /// `K_T` — addresses and payload masks, `F → {0,1}^λ`.
    pub k_t: PrfKey,
    /// `K_X` — the keyword half of a cross-tag exponent.
    pub k_x: PrfKey,
    /// `K_Y` — the `(id, op)` half of a cross-tag exponent.
    pub k_y: PrfKey,
    /// `K_Z` — the blinding factor the server cancels against.
    pub k_z: PrfKey,
}

impl SecretKey {
    /// Derive all four keys from 128 bytes of key material.
    ///
    /// The paper says only "sample uniformly random keys"; splitting one buffer
    /// is a convenience for tests and does not change the scheme, since the
    /// four slices are independent.
    #[must_use]
    pub fn from_bytes(material: &[u8; 128]) -> Self {
        let take = |i: usize| -> PrfKey {
            let mut k = [0u8; 32];
            k.copy_from_slice(&material[i * 32..(i + 1) * 32]);
            PrfKey(k)
        };
        Self {
            k_t: take(0),
            k_x: take(1),
            k_y: take(2),
            k_z: take(3),
        }
    }
}

/// What the client keeps: `st = UpdateCnt`.
///
/// The paper is explicit that this is the client's *only* persistent state, and
/// that its size grows as `O(|W| log N)`. Storing anything more here would
/// understate ODXT's client storage and flatter our own comparison.
#[derive(Debug, Default, Clone)]
pub struct ClientState {
    update_cnt: HashMap<Vec<u8>, u64>,
}

impl ClientState {
    /// Updates involving `w` so far — the paper's `UpdateCnt[w]`.
    #[must_use]
    pub fn update_count(&self, w: &[u8]) -> u64 {
        self.update_cnt.get(w).copied().unwrap_or(0)
    }

    /// Distinct keywords seen.
    #[must_use]
    pub fn keyword_count(&self) -> usize {
        self.update_cnt.len()
    }
}

/// One `Update` message: exactly the four values Figure 8 sends.
#[derive(Debug, Clone)]
pub struct UpdateToken {
    /// `addr`, the `TSet` key.
    pub addr: [u8; 32],
    /// `val`, the masked `(id ‖ op)`.
    pub val: [u8; 16],
    /// `α`, the dynamic blinding factor.
    pub alpha: Scalar,
    /// `xtag`, the cross-tag inserted into the `XSet`.
    pub xtag: CompressedRistretto,
}

/// The encrypted database `EDB = (TSet, XSet)`.
///
/// ⚠️ **The `XSet` is an exact set here, not a Bloom filter.** The paper uses a
/// Bloom filter, and that choice is a real part of its storage cost — but a
/// Bloom filter admits false positives, which in ODXT means a document can be
/// reported as containing an x-term it does not contain. Correctness against
/// the plaintext oracle is checked with the exact set so a genuine protocol bug
/// cannot hide behind an expected false-positive rate. The Bloom variant is
/// measured separately for the storage axis; see `UPGRADES.md`.
#[derive(Debug, Default)]
pub struct Edb {
    tset: HashMap<[u8; 32], ([u8; 16], Scalar)>,
    xset: HashSet<[u8; 32]>,
}

impl Edb {
    /// An empty EDB, as `Setup` leaves it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `TSet` entries — grows as `O(N)` in the number of updates.
    #[must_use]
    pub fn tset_len(&self) -> usize {
        self.tset.len()
    }

    /// `XSet` entries.
    #[must_use]
    pub fn xset_len(&self) -> usize {
        self.xset.len()
    }

    /// Whether the `XSet` holds `xtag`. Read-only, for Exp. 9's adversary, who
    /// holds the current key state and every `XSet` the server ever kept.
    #[must_use]
    pub fn xset_contains(&self, xtag: &[u8; 32]) -> bool {
        self.xset.contains(xtag)
    }

    /// A copy of the `XSet`, as a server that retains state would keep it.
    #[must_use]
    pub fn xset_snapshot(&self) -> HashSet<[u8; 32]> {
        self.xset.clone()
    }

    /// Apply an update. Figure 8, server side.
    pub fn apply(&mut self, t: &UpdateToken) {
        self.tset.insert(t.addr, (t.val, t.alpha));
        self.xset.insert(t.xtag.to_bytes());
    }
}

/// `Update(sk, st, op, (id, w), EDB)` — Figure 8, client side.
#[must_use]
pub fn update(sk: &SecretKey, st: &mut ClientState, op: Op, id: DocId, w: &[u8]) -> UpdateToken {
    let cnt = st.update_cnt.entry(w.to_vec()).or_insert(0);
    *cnt += 1;
    let cnt = *cnt;

    let addr = prf_bytes(&sk.k_t, &tag_wc(w, cnt, 0));

    // `val = (id ‖ op) ⊕ F(K_T, w ‖ cnt ‖ 1)`. The plaintext is 9 bytes (8 for
    // the id, 1 for the op) inside a 16-byte block; the remaining bytes are
    // masked too, so `val` reveals nothing by its shape.
    let mask = prf_bytes(&sk.k_t, &tag_wc(w, cnt, 1));
    let mut val = [0u8; 16];
    val[..8].copy_from_slice(&id.to_be_bytes());
    val[8] = op_byte(op);
    for (v, m) in val.iter_mut().zip(mask.iter()) {
        *v ^= *m;
    }

    // `α = F_p(K_Y, id ‖ op) · F_p(K_Z, w ‖ cnt)^{-1}`.
    let y = prf_scalar(&sk.k_y, &tag_id_op(id, op));
    let z = prf_scalar(&sk.k_z, &tag_wcnt(w, cnt));
    let alpha = y * z.invert();

    // `xtag = g^{F_p(K_X, w) · F_p(K_Y, id ‖ op)}`.
    let x = prf_scalar(&sk.k_x, w);
    let xtag = (RISTRETTO_BASEPOINT_TABLE * &(x * y)).compress();

    UpdateToken {
        addr,
        val,
        alpha,
        xtag,
    }
}

/// `xtag = g^{F_p(K_X, w) · F_p(K_Y, id ‖ op)}` for one `(w, id, op)`: exactly
/// what [`update`] inserts, derived from `sk` alone. Exp. 9 counts the redacted
/// pairs an adversary holding `sk` can confirm against retained `XSet`s; this
/// is that adversary's derivation, not a new operation of the scheme.
#[must_use]
pub fn xtag_of(sk: &SecretKey, w: &[u8], id: DocId, op: Op) -> [u8; 32] {
    let x = prf_scalar(&sk.k_x, w);
    let y = prf_scalar(&sk.k_y, &tag_id_op(id, op));
    (RISTRETTO_BASEPOINT_TABLE * &(x * y)).compress().to_bytes()
}

/// The client's half of `Search`, before the server round trip. Figure 9.
#[derive(Debug)]
pub struct SearchToken {
    /// `stokenList` — one `TSet` address per update involving the s-term.
    pub stoken_list: Vec<[u8; 32]>,
    /// `xtokenList_j` — for each `j`, the `n-1` cross-tokens, permuted.
    pub xtoken_list: Vec<Vec<CompressedRistretto>>,
    /// `n`, needed by the client to test `cnt_j = n`. Not sent to the server;
    /// the server learns it anyway from the token list widths.
    pub conjunction_len: usize,
}

/// What the server returns: the paper's `sEOpList`.
#[derive(Debug)]
pub struct ServerResponse {
    /// `(j, sval_j, cnt_j)`.
    ///
    /// ⚠️ `j` is carried **explicitly**, exactly as Figure 9 writes it, rather
    /// than inferred from position. The client needs `j` to rebuild the mask
    /// `F(K_T, w₁ ‖ j ‖ 1)`, so if the server ever returns a short list — a
    /// `TSet` miss, a dropped entry — positional inference would unmask every
    /// later entry with the wrong key and yield plausible-looking garbage
    /// identifiers instead of an error.
    pub entries: Vec<(u64, [u8; 16], usize)>,
}

/// Pick the s-term: "the keyword involved in the least number of update
/// operations". Returns its index in `q`.
///
/// ⚠️ A term never updated has count 0 and is therefore always the minimum,
/// which makes the conjunction empty — correct, and worth not "fixing".
#[must_use]
pub fn s_term_index(st: &ClientState, q: &[Vec<u8>]) -> Option<usize> {
    (0..q.len()).min_by_key(|&i| st.update_count(&q[i]))
}

/// `Search`, client side, round one. Figure 9 steps 1–7.
///
/// `rng` drives the step-5(e) permutation. It is an explicit parameter rather
/// than a thread-local so a test can pin it and assert the permutation actually
/// happens — a shuffle that silently no-ops is invisible in every functional
/// test, since the server only counts matches.
#[must_use]
pub fn search_token(
    sk: &SecretKey,
    st: &ClientState,
    q: &[Vec<u8>],
    rng: &mut impl rand::Rng,
) -> Option<SearchToken> {
    let s = s_term_index(st, q)?;
    let w1 = &q[s];
    let upd = st.update_count(w1);

    let mut stoken_list = Vec::with_capacity(usize::try_from(upd).unwrap_or(0));
    let mut xtoken_list = Vec::with_capacity(usize::try_from(upd).unwrap_or(0));

    for j in 1..=upd {
        stoken_list.push(prf_bytes(&sk.k_t, &tag_wc(w1, j, 0)));

        let z = prf_scalar(&sk.k_z, &tag_wcnt(w1, j));
        let mut row = Vec::with_capacity(q.len().saturating_sub(1));
        for (i, w_i) in q.iter().enumerate() {
            if i == s {
                continue;
            }
            let x = prf_scalar(&sk.k_x, w_i);
            row.push((RISTRETTO_BASEPOINT_TABLE * &(x * z)).compress());
        }

        // Figure 9 step 5(e): "randomly permute the tuple-entries".
        //
        // ⭐ Not cosmetic, and not optional. Correctness is unaffected — the
        // server only counts XSet hits — so an implementation that skipped this
        // would pass every functional test while leaking strictly more than the
        // paper proves: the server would learn *which* x-term each membership
        // outcome belongs to, not merely how many matched. Since this baseline
        // exists partly to compare leakage, dropping it would flatter our own
        // scheme by comparison.
        row.shuffle(rng);
        xtoken_list.push(row);
    }

    Some(SearchToken {
        stoken_list,
        xtoken_list,
        conjunction_len: q.len(),
    })
}

/// What ODXT's server observes for one s-term candidate `j` — Exp. 5's
/// leakage instrument (M10 H6), not part of the protocol.
///
/// `stag_addr` is the candidate's `TSet` address: a handle for one update of
/// the s-term, stable across every query that anchors on it. `lookups` are the
/// xtags the server itself computed for `j` and whether each was in `XSet`.
/// An xtag is `g^{F(K_X,w)·F(K_Y,id‖op)}`, deterministic per (x-term,
/// document, op), so the same pair looks the same in every query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeView {
    /// `stokenList[j]`.
    pub stag_addr: [u8; 32],
    /// `(xtag, in XSet)` for each cross-token of row `j`, in the order received.
    pub lookups: Vec<([u8; 32], bool)>,
}

/// `Search`, server side. Figure 9, server steps 1–5.
#[must_use]
pub fn search_server(edb: &Edb, token: &SearchToken) -> ServerResponse {
    search_server_inner(edb, token, None)
}

/// [`search_server`], also returning the server's view of each candidate.
///
/// ⭐ One loop, shared with [`search_server`], so the instrumented path cannot
/// drift from the measured one; a test pins their responses as identical.
#[must_use]
pub fn search_server_observed(edb: &Edb, token: &SearchToken) -> (ServerResponse, Vec<ProbeView>) {
    let mut view = Vec::with_capacity(token.stoken_list.len());
    let resp = search_server_inner(edb, token, Some(&mut view));
    (resp, view)
}

fn search_server_inner(
    edb: &Edb,
    token: &SearchToken,
    mut view: Option<&mut Vec<ProbeView>>,
) -> ServerResponse {
    let mut entries = Vec::with_capacity(token.stoken_list.len());

    for (idx, saddr) in token.stoken_list.iter().enumerate() {
        let j = u64::try_from(idx).unwrap_or(u64::MAX) + 1;

        let Some((sval, alpha)) = edb.tset.get(saddr) else {
            // A TSet miss cannot happen for a well-formed token against an EDB
            // that received every update. Skipping is safe now only because `j`
            // travels with the entry; the client can no longer be desynchronised
            // by a short list.
            continue;
        };

        let mut cnt = 1usize;
        let mut lookups = Vec::new();
        for xtoken in &token.xtoken_list[idx] {
            let Some(point) = xtoken.decompress() else {
                continue;
            };
            let xtag = (point * alpha).compress().to_bytes();
            let hit = edb.xset.contains(&xtag);
            if hit {
                cnt += 1;
            }
            if view.is_some() {
                lookups.push((xtag, hit));
            }
        }
        if let Some(v) = view.as_deref_mut() {
            v.push(ProbeView {
                stag_addr: *saddr,
                lookups,
            });
        }

        entries.push((j, *sval, cnt));
    }

    ServerResponse { entries }
}

/// `Search`, client side, final output computation. Figure 9, client steps 1–4.
#[must_use]
pub fn search_finalise(
    sk: &SecretKey,
    st: &ClientState,
    q: &[Vec<u8>],
    resp: &ServerResponse,
) -> BTreeSet<DocId> {
    let Some(s) = s_term_index(st, q) else {
        return BTreeSet::new();
    };
    let w1 = &q[s];
    let n = q.len();

    let mut ids = BTreeSet::new();

    for (j, sval, cnt) in &resp.entries {
        let mask = prf_bytes(&sk.k_t, &tag_wc(w1, *j, 1));

        let mut plain = [0u8; 16];
        for ((p, s), m) in plain.iter_mut().zip(sval.iter()).zip(mask.iter()) {
            *p = *s ^ *m;
        }
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&plain[..8]);
        let id = DocId::from_be_bytes(id_bytes);

        // Figure 9: add when the document matched every conjunct, remove when
        // any deletion touched it. The asymmetry is deliberate in the paper —
        // a deletion for *any* term of the conjunction removes the identifier.
        if plain[8] == op_byte(Op::Add) {
            if *cnt == n {
                ids.insert(id);
            }
        } else if *cnt > 0 {
            ids.remove(&id);
        }
    }

    ids
}

/// End-to-end convenience: the three phases in order.
#[must_use]
pub fn search(
    sk: &SecretKey,
    st: &ClientState,
    edb: &Edb,
    q: &[Vec<u8>],
    rng: &mut impl rand::Rng,
) -> BTreeSet<DocId> {
    let Some(token) = search_token(sk, st, q, rng) else {
        return BTreeSet::new();
    };
    let resp = search_server(edb, &token);
    search_finalise(sk, st, q, &resp)
}

// --- domain separation for the PRF inputs ---------------------------------
//
// The paper writes `w ‖ cnt ‖ 0`. Plain concatenation of a variable-length
// keyword with a counter is ambiguous — ("ab", 1) and ("a", 0xb1) can collide —
// so the length is framed in. This is a bug fix to the write-up rather than a
// change of scheme, and it is recorded in UPGRADES.md.

fn tag_wc(w: &[u8], cnt: u64, suffix: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(w.len() + 17);
    v.extend_from_slice(&u64::try_from(w.len()).unwrap_or(u64::MAX).to_be_bytes());
    v.extend_from_slice(w);
    v.extend_from_slice(&cnt.to_be_bytes());
    v.push(suffix);
    v
}

fn tag_wcnt(w: &[u8], cnt: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(w.len() + 16);
    v.extend_from_slice(&u64::try_from(w.len()).unwrap_or(u64::MAX).to_be_bytes());
    v.extend_from_slice(w);
    v.extend_from_slice(&cnt.to_be_bytes());
    v
}

fn tag_id_op(id: DocId, op: Op) -> Vec<u8> {
    let mut v = Vec::with_capacity(9);
    v.extend_from_slice(&id.to_be_bytes());
    v.push(op_byte(op));
    v
}

const fn op_byte(op: Op) -> u8 {
    match op {
        Op::Add => 0x01,
        Op::Del => 0x02,
    }
}
