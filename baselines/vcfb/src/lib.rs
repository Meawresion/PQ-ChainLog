//! VCFB — efficient forward and backward private conjunctive searchable
//! encryption with comprehensive verification: **its search path only**.
//!
//! Sheng Ge et al., IEEE Transactions on Big Data 11(3), May/June 2025,
//! pp. 1259–1271 (`b40`).
//!
//! # Provenance
//!
//! Transcribed from Algorithm 1 (`Update`, `TokenGen`, `Search`) and equations
//! (3)–(8) of `ref-papers/VCFB_IEEE2024.pdf`, read directly as
//! the baseline reading rule in `baselines/UPGRADES.md` requires. Every reading choice is in
//! `../UPGRADES.md`, and the ones that change cost are marked there with the
//! direction they push.
//!
//! # The scheme
//!
//! ODXT's two maps with two changes. `TSet′[addr] = (val, α′)` stores the
//! blinding factor `vα = F_p(K_Y, id)·F_p(K_Z, c)⁻¹` masked by a PRF, so only a
//! token for `(w, c)` can unmask it. The cross-tag `vxtag = g^{F_p(K_X,w‖op)·
//! F_p(K_Y,id)}` carries the operation, so the search tests `add ∈ XSet` and
//! `del ∉ XSet` per x-term, and it is uploaded as `xtag′ = vxtag ⊕ st_SrchCt` into
//! a per-search bucket `XSet′_SrchCt`. A bucket opens only once a later search
//! hands over `st_SrchCt`, which is what makes `XSet` forward private; the server
//! walks the bucket chain back through `β = H(st_m) ⊕ st_{m−1}`.
//!
//! Per candidate and x-term the client computes two fixed-base exponentiations
//! (`xtoken^{add}`, `xtoken^{del}`) and the server two variable-base ones. The
//! search does **not** fetch the x-terms' tags (SDSSE-CQ does), so its cost
//! follows the s-term alone (their Fig. 7(b)).
//!
//! # ⛔ What is not built
//!
//! The bilinear accumulator (`Acc(VAL_w)`, `Acc(XSet)`; Alg. 1 Update lines
//! 15–25), the proofs in Search lines 28–33 and `Verify` (Alg. 2, Alg. 4). §1da
//! times the search path only: `TokenGen` + `Search` + the client's decryption.
//! Leaving the proofs out **favours the arm**; their own Fig. 6(a) likewise
//! times updates without the verification step.
//!
//! # ⛔ What this is for
//!
//! M15's trial arm for Exps. 2 and 5. No part of PQ-ChainLog may depend on it.

use std::collections::{BTreeSet, HashMap, HashSet};

use baseline_odxt::prf::{PrfKey, prf_bytes, prf_scalar};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use pqcl_dsse::core::Op;
use pqcl_primitives::xof;

/// A document identifier.
pub type DocId = u64;

/// `val = (id ‖ op) ⊕ F(K_T, w‖c‖1)`: 8 bytes of id, one of op.
const VAL_BYTES: usize = 9;

const fn op_byte(op: Op) -> u8 {
    match op {
        Op::Add => 0x01,
        Op::Del => 0x02,
    }
}

/// `w ‖ c ‖ tag`, framed so two `(w, c)` pairs never collide. `tag` is the
/// paper's trailing `0`, `1` or `2`.
fn w_c_t(w: &[u8], c: u64, tag: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(w.len() + 9);
    v.push(tag);
    v.extend_from_slice(&c.to_be_bytes());
    v.extend_from_slice(w);
    v
}

/// `w ‖ op`, for `F_p(K_X, ·)`.
fn w_op(w: &[u8], op: Op) -> Vec<u8> {
    let mut v = Vec::with_capacity(w.len() + 1);
    v.push(op_byte(op));
    v.extend_from_slice(w);
    v
}

/// `H : {0,1}^λ → {0,1}^λ`, SHAKE256 (the system XOF) for their SHA-256.
fn h(st: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 33];
    input[0] = 0x56; // 'V': a domain byte of this baseline's own
    input[1..].copy_from_slice(st);
    let mut out = [0u8; 32];
    out.copy_from_slice(&xof::shake256(&input, 32));
    out
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = x ^ y;
    }
    out
}

/// `g^x`, by fixed-base precomputation: the base never changes, as for our
/// `SDSSE-CQ` port and their `GmSSL` fixed-point tables.
fn g_pow(x: &Scalar) -> RistrettoPoint {
    x * RISTRETTO_BASEPOINT_TABLE
}

fn sub_key(master: &[u8; 32], label: u8) -> PrfKey {
    let mut input = [0u8; 33];
    input[0] = label;
    input[1..].copy_from_slice(master);
    let mut k = [0u8; 32];
    k.copy_from_slice(&xof::shake256(&input, 32));
    PrfKey(k)
}

/// One `XSet′` bucket: `β` and the `xtag′` uploaded while it was open.
#[derive(Debug, Clone, Default)]
struct Bucket {
    beta: [u8; 32],
    tags: Vec<[u8; 32]>,
}

/// What one update sends: `(addr, val, α′, xtag′)`, plus the new bucket's `β`
/// when the update opened one (Update lines 6–11).
#[derive(Debug, Clone)]
pub struct UpdateMsg {
    addr: [u8; 32],
    val: [u8; VAL_BYTES],
    alpha: [u8; 32],
    xtag: [u8; 32],
    /// `(SrchCt, β)` when this update opened `XSet′_SrchCt`.
    open: Option<(u64, [u8; 32])>,
    /// The bucket the `xtag′` goes into.
    bucket: u64,
}

/// The client: `MK = (K_T, K_S, K_X, K_Y, K_Z, K_e)`, `UpdCnt`, `SrchCt`, `UpTag`.
#[derive(Debug, Clone)]
pub struct Client {
    k_t: PrfKey,
    k_s: PrfKey,
    k_x: PrfKey,
    k_y: PrfKey,
    k_z: PrfKey,
    k_e: PrfKey,
    upd_cnt: HashMap<Vec<u8>, u64>,
    srch_ct: u64,
    /// `UpTag = 1` after an update, `0` after a search (Alg. 1; the prose in
    /// §V-B says the opposite once, and the algorithm is followed).
    up_tag: bool,
}

/// The server: `EDB = (TSet′, XSet′)`, and `XSet` as earlier searches decoded it.
#[derive(Debug, Clone, Default)]
pub struct Server {
    tset: HashMap<[u8; 32], ([u8; VAL_BYTES], [u8; 32])>,
    /// `XSet′_m` at index `m − 1`.
    buckets: Vec<Bucket>,
    /// Buckets `1..=decoded` are in `xset` already.
    decoded: u64,
    xset: HashSet<[u8; 32]>,
}

/// `SToken`: `st_SrchCt`, `stokenList` and the cross-tokens.
#[derive(Debug, Clone)]
pub struct SearchToken {
    st: [u8; 32],
    srch_ct: u64,
    /// `(addr_j, K_{w1,j})`, `j = 1..=UpdCnt[w₁]`.
    stokens: Vec<([u8; 32], [u8; 32])>,
    /// `(xtoken^{add}_{i,j}, xtoken^{del}_{i,j})` for `i = 2..=d`, per `j`.
    xtokens: Vec<Vec<(RistrettoPoint, RistrettoPoint)>>,
    /// `w₁`, kept client-side to decrypt `val` (not sent).
    w1: Vec<u8>,
}

impl SearchToken {
    /// Bytes sent up: `st`, each `(addr, K)`, and each cross-token at 32 bytes.
    #[must_use]
    pub fn wire_bytes_up(&self) -> usize {
        32 + self.stokens.len() * 64 + self.xtokens.iter().map(|r| r.len() * 64).sum::<usize>()
    }

    /// `UpdCnt[w₁]`: the candidates the server will walk.
    #[must_use]
    pub fn candidates(&self) -> usize {
        self.stokens.len()
    }
}

/// What the server sends back: `R_{w1}` and `R`, each entry with its `j`.
#[derive(Debug, Clone, Default)]
pub struct SearchReply {
    /// Every `val_j` of `w₁` (Search line 16).
    pub r_w1: Vec<(u64, [u8; VAL_BYTES])>,
    /// The `val_j` that passed every x-term (line 25).
    pub r: Vec<(u64, [u8; VAL_BYTES])>,
}

/// Exp. 5's instrument for one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The document handle: `addr_j`.
    pub addr: [u8; 32],
    /// Per x-term: `(vxtag^{add}, add ∈ XSet, del ∈ XSet)`.
    pub lookups: Vec<([u8; 32], bool, bool)>,
}

/// What a first search changed on the server, so a harness can put it back
/// outside a timed region.
#[derive(Debug, Clone, Default)]
pub struct Undo {
    decoded_before: u64,
    /// `(bucket index, st)` of every bucket this search decoded.
    opened: Vec<(u64, [u8; 32])>,
}

impl Client {
    /// `Setup(λ)`: keys, empty maps, `SrchCt = UpTag = 1`, and `β = H(st₁) ⊕ st₀`
    /// in `XSet′₁`. Returns the server's initial state too.
    #[must_use]
    pub fn setup(master: &[u8; 32]) -> (Self, Server) {
        let client = Self {
            k_t: sub_key(master, 0x20),
            k_s: sub_key(master, 0x21),
            k_x: sub_key(master, 0x22),
            k_y: sub_key(master, 0x23),
            k_z: sub_key(master, 0x24),
            k_e: sub_key(master, 0x25),
            upd_cnt: HashMap::new(),
            srch_ct: 1,
            up_tag: true,
        };
        let beta = xor32(&h(&client.st(1)), &client.st(0));
        let server = Server {
            buckets: vec![Bucket {
                beta,
                tags: Vec::new(),
            }],
            ..Server::default()
        };
        (client, server)
    }

    /// `st_i = F(K_S, i)`.
    fn st(&self, i: u64) -> [u8; 32] {
        prf_bytes(&self.k_s, &i.to_be_bytes())
    }

    /// `Update(w, id, op)`, client side (Alg. 1 lines 1–14, 26–27), without the
    /// accumulator lines 15–25.
    pub fn update(&mut self, w: &[u8], id: DocId, op: Op) -> UpdateMsg {
        // Line 1.
        let c = self.upd_cnt.get(w).map_or(1, |c| c + 1);
        self.upd_cnt.insert(w.to_vec(), c);
        // Lines 2–3.
        let addr = prf_bytes(&self.k_t, &w_c_t(w, c, 0));
        let mask = prf_bytes(&self.k_t, &w_c_t(w, c, 1));
        let mut val = [0u8; VAL_BYTES];
        val[..8].copy_from_slice(&id.to_be_bytes());
        val[8] = op_byte(op);
        for (v, m) in val.iter_mut().zip(mask.iter()) {
            *v ^= m;
        }
        // Lines 4–5. ⚠️ `α′ = vα ⊕ F_p(K_e, w‖c‖2)` while TokenGen line 5 sends
        // `K_{w1,j} = F(K_e, w₁‖j‖2)` to unmask it: one 32-byte PRF output read as
        // both, or the server could never recover `vα` (UPGRADES.md).
        let v_alpha = prf_scalar(&self.k_y, &id.to_be_bytes())
            * prf_scalar(&self.k_z, &c.to_be_bytes()).invert();
        let alpha = xor32(v_alpha.as_bytes(), &prf_bytes(&self.k_e, &w_c_t(w, c, 2)));

        // Lines 6–11.
        let mut open = None;
        if !self.up_tag {
            self.srch_ct += 1;
            let st = self.st(self.srch_ct);
            let beta = xor32(&h(&st), &self.st(self.srch_ct - 1));
            open = Some((self.srch_ct, beta));
        }
        // Lines 12–13.
        let x = prf_scalar(&self.k_x, &w_op(w, op)) * prf_scalar(&self.k_y, &id.to_be_bytes());
        let vxtag = g_pow(&x).compress().to_bytes();
        let xtag = xor32(&vxtag, &self.st(self.srch_ct));
        // Line 26.
        self.up_tag = true;
        UpdateMsg {
            addr,
            val,
            alpha,
            xtag,
            open,
            bucket: self.srch_ct,
        }
    }

    /// `UpdCnt[w]`, or `None`.
    #[must_use]
    pub fn counter(&self, w: &[u8]) -> Option<u64> {
        self.upd_cnt.get(w).copied()
    }

    /// `TokenGen` line 1: "use `UpdCnt` to identify the keyword with least
    /// updates", which becomes `w₁`.
    #[must_use]
    pub fn order_terms<'q>(&self, q: &'q [Vec<u8>]) -> Vec<&'q [u8]> {
        let mut terms: Vec<&[u8]> = q.iter().map(Vec::as_slice).collect();
        terms.sort_by_key(|w| self.upd_cnt.get(*w).copied().unwrap_or(u64::MAX));
        terms
    }

    /// `TokenGen(UpdCnt, q, MK)` (lines 1–14). `None` if `w₁` was never updated:
    /// there is nothing to walk.
    pub fn token(&mut self, terms: &[&[u8]]) -> Option<SearchToken> {
        let (w1, rest) = terms.split_first()?;
        let n = *self.upd_cnt.get(*w1)?;
        // `F_p(K_X, w_i‖op)` is per x-term; computed once, outside the `j` loop.
        let kx: Vec<(Scalar, Scalar)> = rest
            .iter()
            .map(|w| {
                (
                    prf_scalar(&self.k_x, &w_op(w, Op::Add)),
                    prf_scalar(&self.k_x, &w_op(w, Op::Del)),
                )
            })
            .collect();
        let mut stokens = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
        let mut xtokens = Vec::with_capacity(stokens.capacity());
        for j in 1..=n {
            // Lines 4–6.
            let addr = prf_bytes(&self.k_t, &w_c_t(w1, j, 0));
            let k = prf_bytes(&self.k_e, &w_c_t(w1, j, 2));
            stokens.push((addr, k));
            // Lines 7–11.
            let z = prf_scalar(&self.k_z, &j.to_be_bytes());
            xtokens.push(
                kx.iter()
                    .map(|(a, d)| (g_pow(&(a * z)), g_pow(&(d * z))))
                    .collect(),
            );
        }
        // Line 13.
        self.up_tag = false;
        Some(SearchToken {
            st: self.st(self.srch_ct),
            srch_ct: self.srch_ct,
            stokens,
            xtokens,
            w1: w1.to_vec(),
        })
    }

    /// Search lines 35–46: decrypt `R`, then drop every id `R_{w1}` deletes.
    #[must_use]
    pub fn finalise(&self, token: &SearchToken, reply: &SearchReply) -> BTreeSet<DocId> {
        let open = |j: u64, val: &[u8; VAL_BYTES]| {
            let mask = prf_bytes(&self.k_t, &w_c_t(&token.w1, j, 1));
            let mut plain = *val;
            for (p, m) in plain.iter_mut().zip(mask.iter()) {
                *p ^= m;
            }
            let mut id = [0u8; 8];
            id.copy_from_slice(&plain[..8]);
            (u64::from_be_bytes(id), plain[8])
        };
        // ⚠️ Line 37 indexes `R` by its own position `j`, while the mask is keyed
        // by the candidate's counter; the server returns each entry's `j`.
        let mut ids: BTreeSet<DocId> = reply.r.iter().map(|(j, v)| open(*j, v).0).collect();
        for (j, v) in &reply.r_w1 {
            let (id, op) = open(*j, v);
            if op == op_byte(Op::Del) {
                ids.remove(&id);
            }
        }
        ids
    }

    /// `UpTag`, to save and restore around a rolled-back first search.
    #[must_use]
    pub const fn up_tag(&self) -> bool {
        self.up_tag
    }

    /// Restore `UpTag`; see [`Client::up_tag`].
    pub const fn set_up_tag(&mut self, v: bool) {
        self.up_tag = v;
    }

    /// The whole search, in order.
    pub fn search(&mut self, server: &mut Server, q: &[Vec<u8>]) -> BTreeSet<DocId> {
        let terms = self.order_terms(q);
        let Some(token) = self.token(&terms) else {
            return BTreeSet::new();
        };
        let mut undo = Undo::default();
        let reply = server.search(&token, &mut undo, None);
        self.finalise(&token, &reply)
    }

    /// Bytes the client keeps: `UpdCnt` (keyword plus counter), and the keys.
    #[must_use]
    pub fn client_bytes(&self) -> usize {
        self.upd_cnt.keys().map(|w| w.len() + 8).sum::<usize>() + 6 * 32 + 9
    }
}

impl Server {
    /// Update, server side (lines 28–30), and the bucket the update opened.
    pub fn apply(&mut self, m: &UpdateMsg) {
        if let Some((srch_ct, beta)) = m.open {
            debug_assert_eq!(usize::try_from(srch_ct).ok(), Some(self.buckets.len() + 1));
            self.buckets.push(Bucket {
                beta,
                tags: Vec::new(),
            });
        }
        let idx = usize::try_from(m.bucket - 1).unwrap_or(usize::MAX);
        if let Some(b) = self.buckets.get_mut(idx) {
            b.tags.push(m.xtag);
        }
        self.tset.insert(m.addr, (m.val, m.alpha));
    }

    /// Entries in `TSet′`, and `xtag′` uploaded.
    #[must_use]
    pub fn entries(&self) -> (usize, usize) {
        (
            self.tset.len(),
            self.buckets.iter().map(|b| b.tags.len()).sum(),
        )
    }

    /// Bytes stored: `TSet′` at label + value, `XSet′` at 32 bytes per `xtag′`
    /// and per `β`. The decoded `XSet` is a cache of `XSet′`, not counted twice.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        let (t, x) = self.entries();
        t * (32 + VAL_BYTES + 32) + x * 32 + self.buckets.len() * 32
    }

    /// `Search`, server side (lines 1–27; the proofs of 28–33 are not built).
    ///
    /// `undo` records what the bucket walk decoded, so a harness can roll a
    /// timed first search back. `observe`, when given, is Exp. 5's instrument;
    /// with it every lookup is computed, without it a candidate stops at its first
    /// failing x-term (line 17 has no break, and stopping early favours the arm,
    /// as for SDSSE-CQ).
    pub fn search(
        &mut self,
        token: &SearchToken,
        undo: &mut Undo,
        mut observe: Option<&mut Vec<Observed>>,
    ) -> SearchReply {
        // Lines 3–11: walk `m = SrchCt` down, decode each bucket with `st_m`, then
        // step to `st_{m−1} = β_m ⊕ H(st_m)`.
        // ⚠️ Line 4 overwrites `st` before line 7 uses it; bucket `m` holds tags
        // under `st_m`, so `st_m` is used first and the step comes after. And the
        // walk stops at the first bucket an earlier search decoded: every bucket
        // below it was decoded then too (UPGRADES.md).
        undo.decoded_before = self.decoded;
        let mut st = token.st;
        let mut m = token.srch_ct;
        while m > self.decoded {
            let idx = usize::try_from(m - 1).unwrap_or(usize::MAX);
            let Some(bucket) = self.buckets.get(idx) else {
                break;
            };
            self.xset.reserve(bucket.tags.len());
            for t in &bucket.tags {
                self.xset.insert(xor32(t, &st));
            }
            undo.opened.push((m, st));
            st = xor32(&bucket.beta, &h(&st));
            m -= 1;
        }
        self.decoded = self.decoded.max(token.srch_ct);

        // Lines 12–27.
        let d = token.xtokens.first().map_or(0, Vec::len);
        let mut reply = SearchReply::default();
        for (jj, ((addr, k), row)) in token.stokens.iter().zip(&token.xtokens).enumerate() {
            let j = jj as u64 + 1;
            let Some((val, alpha)) = self.tset.get(addr) else {
                continue;
            };
            // Line 16. `vα` was masked as its canonical 32-byte encoding.
            let Some(v_alpha) =
                Option::<Scalar>::from(Scalar::from_canonical_bytes(xor32(alpha, k)))
            else {
                continue;
            };
            reply.r_w1.push((j, *val));
            let mut cnt = 0usize;
            let mut seen = Vec::new();
            for (x_add, x_del) in row {
                let add = (x_add * v_alpha).compress().to_bytes();
                let add_in = self.xset.contains(&add);
                if !add_in && observe.is_none() {
                    break;
                }
                let del = (x_del * v_alpha).compress().to_bytes();
                let del_in = self.xset.contains(&del);
                if observe.is_some() {
                    seen.push((add, add_in, del_in));
                }
                if add_in && !del_in {
                    cnt += 1;
                } else if observe.is_none() {
                    break;
                }
            }
            if let Some(o) = observe.as_deref_mut() {
                o.push(Observed {
                    addr: *addr,
                    lookups: seen,
                });
            }
            // Line 24: `cnt_j` starts at 1 and must reach `d`; here it counts the
            // `d − 1` x-terms.
            if cnt == d {
                reply.r.push((j, *val));
            }
        }
        reply
    }

    /// Put back what one first search decoded.
    pub fn undo(&mut self, undo: Undo) {
        for (m, st) in undo.opened {
            let idx = usize::try_from(m - 1).unwrap_or(usize::MAX);
            if let Some(bucket) = self.buckets.get(idx) {
                for t in &bucket.tags {
                    self.xset.remove(&xor32(t, &st));
                }
            }
        }
        self.decoded = undo.decoded_before;
    }

    /// `XSet` as decoded so far: what a reuse trial tests kept elements against.
    #[must_use]
    pub fn xset_contains(&self, e: &[u8; 32]) -> bool {
        self.xset.contains(e)
    }

    /// Buckets in `XSet′`: one per search that was followed by an update.
    #[must_use]
    pub fn buckets(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
#[allow(clippy::many_single_char_names)] // c, s, q, t, u: client, server, query, token, undo
mod tests {
    use super::*;

    fn build(
        docs: &[(DocId, &[&str])],
        deleted: &[DocId],
    ) -> (Client, Server, HashMap<String, BTreeSet<DocId>>) {
        let (mut c, mut s) = Client::setup(&[7; 32]);
        let mut live: HashMap<String, BTreeSet<DocId>> = HashMap::new();
        for (id, ws) in docs {
            for w in *ws {
                s.apply(&c.update(w.as_bytes(), *id, Op::Add));
                live.entry((*w).to_owned()).or_default().insert(*id);
            }
        }
        for (id, ws) in docs {
            if deleted.contains(id) {
                for w in *ws {
                    s.apply(&c.update(w.as_bytes(), *id, Op::Del));
                    live.entry((*w).to_owned()).or_default().remove(id);
                }
            }
        }
        (c, s, live)
    }

    fn oracle(live: &HashMap<String, BTreeSet<DocId>>, q: &[&str]) -> BTreeSet<DocId> {
        q.iter()
            .map(|w| live.get(*w).cloned().unwrap_or_default())
            .reduce(|a, b| a.intersection(&b).copied().collect())
            .unwrap_or_default()
    }

    const DOCS: &[(DocId, &[&str])] = &[
        (1, &["a", "b", "c"]),
        (2, &["a", "b"]),
        (3, &["a", "c", "d"]),
        (4, &["b", "c", "d"]),
        (5, &["a", "b", "c", "d"]),
        (6, &["d"]),
    ];

    #[test]
    fn conjunctions_match_the_oracle_with_deletions() {
        let (mut c, mut s, live) = build(DOCS, &[5]);
        for q in [
            &["a", "b"][..],
            &["a", "c"],
            &["b", "c", "d"],
            &["a", "b", "c", "d"],
            &["c", "d"],
            &["d", "a"],
            &["a"],
        ] {
            let qb: Vec<Vec<u8>> = q.iter().map(|w| w.as_bytes().to_vec()).collect();
            assert_eq!(c.search(&mut s, &qb), oracle(&live, q), "{q:?}");
            // A repeat search reads the decoded `XSet` and must agree too.
            assert_eq!(c.search(&mut s, &qb), oracle(&live, q), "{q:?} again");
        }
    }

    #[test]
    fn an_update_after_a_search_lands_in_a_new_bucket_that_the_next_search_opens() {
        let (mut c, mut s, mut live) = build(DOCS, &[]);
        let q: Vec<Vec<u8>> = vec![b"a".to_vec(), b"d".to_vec()];
        assert_eq!(c.search(&mut s, &q), oracle(&live, &["a", "d"]));
        assert_eq!(s.buckets(), 1);
        s.apply(&c.update(b"d", 2, Op::Add));
        live.entry("d".to_owned()).or_default().insert(2);
        assert_eq!(s.buckets(), 2, "the update after a search opens XSet'_2");
        assert_eq!(c.search(&mut s, &q), oracle(&live, &["a", "d"]));
        assert!(c.search(&mut s, &q).contains(&2));
    }

    #[test]
    fn a_bucket_stays_closed_to_a_token_from_before_it() {
        // Forward privacy of XSet': the new xtag' is under st_2, and the server
        // holds only st_1 until the next token.
        let (mut c, mut s, _) = build(DOCS, &[]);
        let q: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
        let terms = c.order_terms(&q);
        let old = c.token(&terms).expect("indexed");
        let mut u = Undo::default();
        let _ = s.search(&old, &mut u, None);
        s.apply(&c.update(b"b", 3, Op::Add));
        let mut u = Undo::default();
        let reply = s.search(&old, &mut u, None);
        assert!(
            !c.finalise(&old, &reply).contains(&3),
            "an old token must not reach a later bucket"
        );
    }

    #[test]
    fn undo_restores_a_first_search_exactly() {
        let (mut c, mut s, live) = build(DOCS, &[2]);
        let q: Vec<Vec<u8>> = vec![b"b".to_vec(), b"c".to_vec()];
        let terms = c.order_terms(&q);
        let up = c.up_tag();
        let t = c.token(&terms).expect("indexed");
        let mut u = Undo::default();
        let first = s.search(&t, &mut u, None);
        assert_eq!(c.finalise(&t, &first), oracle(&live, &["b", "c"]));
        s.undo(u);
        c.set_up_tag(up);
        assert_eq!(s.xset.len(), 0, "nothing decoded after the undo");
        assert_eq!(c.search(&mut s, &q), oracle(&live, &["b", "c"]));
    }

    #[test]
    fn the_observer_sees_every_lookup_and_does_not_change_the_answer() {
        let (mut c, mut s, live) = build(DOCS, &[]);
        let q: Vec<Vec<u8>> = vec![b"d".to_vec(), b"a".to_vec(), b"b".to_vec()];
        let terms = c.order_terms(&q);
        let t = c.token(&terms).expect("indexed");
        let mut seen = Vec::new();
        let mut u = Undo::default();
        let r = s.search(&t, &mut u, Some(&mut seen));
        assert_eq!(c.finalise(&t, &r), oracle(&live, &["a", "b", "d"]));
        assert_eq!(seen.len(), t.candidates());
        assert!(seen.iter().all(|o| o.lookups.len() == 2));
        // vxtag^add is deterministic per (x-term, document): the same element
        // comes back under a different s-term.
        let q2: Vec<Vec<u8>> = vec![b"c".to_vec(), b"a".to_vec()];
        let t2 = c.token(&c.order_terms(&q2)).expect("indexed");
        let mut seen2 = Vec::new();
        let _ = s.search(&t2, &mut Undo::default(), Some(&mut seen2));
        let a: HashSet<[u8; 32]> = seen
            .iter()
            .flat_map(|o| o.lookups.iter().map(|l| l.0))
            .collect();
        assert!(
            seen2
                .iter()
                .any(|o| o.lookups.iter().any(|l| a.contains(&l.0)))
        );
    }
}
