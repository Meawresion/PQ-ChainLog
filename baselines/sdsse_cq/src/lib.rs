//! SDSSE-CQ and SDSSE-CQ-S — conjunctive DSSE with forward privacy on both
//! `TSet` and `XSet`, and Type-O / Type-O⁻ backward privacy.
//!
//! Cong Zuo, Shangqi Lai, Shi-Feng Sun, Xingliang Yuan, Joseph K. Liu, Jun Shao
//! and Huaxiong Wang, Proceedings on Privacy Enhancing Technologies 2025(1),
//! pp. 440–455.
//!
//! # Provenance
//!
//! Transcribed from Algorithms 1 and 2 of
//! `ref-papers/SDSSE-CQ_PoPETS2025.pdf`, read directly as
//! the baseline reading rule in `baselines/UPGRADES.md` requires. Deviations are in `../UPGRADES.md`.
//!
//! # The scheme
//!
//! OXT's two structures, each inside its own Aura instance. `Update` stores
//! `(e ‖ y ‖ c)` under `w` in `TSet` and `xtag = g^{F_p(k_x,w)·xind}` under `w`
//! in `XSet`. `Search` fetches `w₁`'s tuples and **every current xtag of each
//! x-term**, then tests `xtoken[c,j]^y ∈ XSet` per tuple. So its cost grows with
//! the x-terms' volume, where ODXT's does not: the authors' Fig. 3 shows this,
//! and it is the scheme's real mechanism.
//!
//! SDSSE-CQ-S blinds each stored xtag per `(w, c)` and has the server re-blind it
//! under the s-term, so one query's fetched set is useless to another's tokens.
//! That is what lifts Type-O to Type-O⁻, and it costs one more exponentiation per
//! fetched xtag.
//!
//! # ⛔ What this is for
//!
//! Exps. 1, 2, 3 and 5's conjunctive baseline, and nothing else. No part of
//! PQ-ChainLog may depend on it.

pub mod aura;

use std::collections::{BTreeSet, HashMap, HashSet};

use baseline_odxt::prf::{PrfKey, prf_bytes, prf_scalar};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use pqcl_dsse::core::Op;
use pqcl_primitives::xof;

/// A document identifier.
pub type DocId = u64;

/// `e‖y‖c`'s length: `e` is the IV and an 8-byte id, `y` a scalar, `c` a `u64`.
const E_BYTES: usize = 24;
const TUPLE_BYTES: usize = E_BYTES + 32 + 8;

/// Which of the two schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Algorithm 1: Type-O.
    Cq,
    /// Algorithm 2: Type-O⁻.
    CqS,
}

impl Variant {
    /// The record's key for this arm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cq => "sdsse_cq",
            Self::CqS => "sdsse_cq_s",
        }
    }
}

/// `g^x`, by fixed-base precomputation: the base never changes, and the authors
/// amortise it the same way with PBC's preprocessing (their §5).
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

/// `w‖c`, framed so two pairs can never collide.
fn w_c(w: &[u8], c: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(w.len() + 8);
    v.extend_from_slice(&c.to_be_bytes());
    v.extend_from_slice(w);
    v
}

/// The client: `σ = (k, k_x, k_i, k_z, [k'_x, k'_z], CT, σ_T, σ_X)`.
#[derive(Debug, Clone)]
pub struct Client {
    variant: Variant,
    k: PrfKey,
    k_x: PrfKey,
    k_i: PrfKey,
    k_z: PrfKey,
    k_x2: PrfKey,
    k_z2: PrfKey,
    /// `CT[w]`: the counter of `w`'s most recent update.
    ct: HashMap<Vec<u8>, u64>,
    t: aura::Client,
    x: aura::Client,
}

/// The server: `EDB = (EDB_T, EDB_X)`.
#[derive(Debug, Default, Clone)]
pub struct Server {
    t: aura::Server,
    x: aura::Server,
}

impl Server {
    /// Bytes stored, label + value, over both Aura instances.
    #[must_use]
    pub fn stored_bytes(&self) -> (usize, usize) {
        (self.t.stored_bytes(), self.x.stored_bytes())
    }

    /// Entries in `EDB_T` and `EDB_X`.
    #[must_use]
    pub fn entries(&self) -> (usize, usize) {
        (self.t.add_len(), self.x.add_len())
    }
}

/// What a search sends up: tokens, plus the two Aura token sets.
#[derive(Debug, Clone)]
pub struct SearchToken {
    /// `xtoken[i][j]` (or `wxtoken`), row `i ∈ [0, c]`, one per x-term.
    xtoken: Vec<Vec<RistrettoPoint>>,
    /// `wxt[j][k]`, Algorithm 2 only.
    wxt: Vec<Vec<Scalar>>,
    aura_t: aura::SearchMsg,
    aura_x: Vec<aura::SearchMsg>,
    /// The key that opens `e`.
    k_w1: [u8; 32],
}

impl SearchToken {
    /// Bytes sent up.
    #[must_use]
    pub fn wire_bytes_up(&self) -> usize {
        let tokens: usize = self.xtoken.iter().map(|r| r.len() * 32).sum();
        let wxt: usize = self.wxt.iter().map(|r| r.len() * 32).sum();
        tokens
            + wxt
            + self.aura_t.wire_bytes()
            + self
                .aura_x
                .iter()
                .map(aura::SearchMsg::wire_bytes)
                .sum::<usize>()
    }
}

/// Exp. 5's instrument: what the server observed for one candidate tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The document handle: `e`, in the clear after `Aura.Search`.
    pub e: Vec<u8>,
    /// `(the computed group element, in the fetched set?)`, one per x-term.
    pub lookups: Vec<([u8; 32], bool)>,
}

/// Exp. 5's whole instrument for one search: each candidate's lookups, and the
/// x-term set the server fetched, kept as the server could keep it.
#[derive(Debug, Clone, Default)]
pub struct Observer {
    /// One per candidate tuple.
    pub tuples: Vec<Observed>,
    /// `XSet` (Alg. 2: `WXSet`) as this search assembled it.
    pub fetched: Vec<[u8; 32]>,
}

/// Everything a first search consumed, to restore after timing it.
#[derive(Debug, Default)]
pub struct Rollback {
    t: Vec<(Vec<u8>, aura::ClientCheckpoint)>,
    x: Vec<(Vec<u8>, aura::ClientCheckpoint)>,
    server_t: Option<aura::Undo>,
    server_x: Vec<aura::Undo>,
}

impl Client {
    /// `Setup(1^λ)`. `deletions` sizes each keyword's Bloom filters
    /// ([`aura::Client::setup`]).
    #[must_use]
    pub fn setup(variant: Variant, master: &[u8; 32], deletions: HashMap<Vec<u8>, usize>) -> Self {
        let mut mt = *master;
        mt[0] ^= 0x54;
        let mut mx = *master;
        mx[0] ^= 0x58;
        Self {
            variant,
            k: sub_key(master, 0x10),
            k_x: sub_key(master, 0x11),
            k_i: sub_key(master, 0x12),
            k_z: sub_key(master, 0x13),
            k_x2: sub_key(master, 0x14),
            k_z2: sub_key(master, 0x15),
            ct: HashMap::new(),
            t: aura::Client::setup(&mt, deletions.clone()),
            x: aura::Client::setup(&mx, deletions),
        }
    }

    /// `Update(op, w, ind)`.
    ///
    /// ⚠️ Deletion is what the authors measure, not what line 6–8 print: their
    /// Table 3 has 0.03 ms per deletion, which cannot include the group work of
    /// lines 7–8, and §5.1 derives the tag from the real `(w, ind)`. So a deletion
    /// does lines 1–5 and sets the Bloom bits. `UPGRADES.md` records it.
    #[allow(clippy::many_single_char_names)] // the paper's own e, y, z, c
    pub fn update(
        &mut self,
        server: &mut Server,
        op: Op,
        w: &[u8],
        ind: DocId,
        rng: &mut impl rand::Rng,
    ) {
        // Lines 1–5. Both operations advance `c`, as printed.
        let c = self.ct.get(w).map_or(0, |c| c + 1);
        self.ct.insert(w.to_vec(), c);
        let ind_bytes = ind.to_be_bytes();

        if op == Op::Del {
            self.t.delete(w, &ind_bytes, rng);
            self.x.delete(w, &ind_bytes, rng);
            return;
        }

        // Line 6.
        let k_w = prf_bytes(&self.k, w);
        let e = aura::se_enc(&k_w, &ind_bytes, rng);
        // Line 7.
        let xind = prf_scalar(&self.k_i, &ind_bytes);
        let z = prf_scalar(&self.k_z, &w_c(w, c));
        let y = xind * z.invert();
        // Line 9.
        let mut tuple = Vec::with_capacity(TUPLE_BYTES);
        tuple.extend_from_slice(&e);
        tuple.extend_from_slice(y.as_bytes());
        tuple.extend_from_slice(&c.to_be_bytes());
        let mt = self.t.add(w, &ind_bytes, &tuple, rng);
        server.t.apply(mt);

        // Lines 8 and 10.
        let kx = prf_scalar(&self.k_x, w);
        let mx = match self.variant {
            Variant::Cq => {
                let xtag = g_pow(&(kx * xind)).compress();
                self.x.add(w, &ind_bytes, xtag.as_bytes(), rng)
            }
            Variant::CqS => {
                let blind = prf_scalar(&self.k_x2, &w_c(w, c)).invert();
                let wxtag = g_pow(&(kx * xind * blind)).compress();
                let mut v = Vec::with_capacity(40);
                v.extend_from_slice(wxtag.as_bytes());
                v.extend_from_slice(&c.to_be_bytes());
                self.x.add(w, &ind_bytes, &v, rng)
            }
        };
        server.x.apply(mx);
    }

    /// `CT[w]`, or `None`.
    #[must_use]
    pub fn counter(&self, w: &[u8]) -> Option<u64> {
        self.ct.get(w).copied()
    }

    /// The conjunct with the fewest updates comes first: the s-term the paper
    /// assumes (`w₁` is the least frequent).
    #[must_use]
    pub fn order_terms<'q>(&self, q: &'q [Vec<u8>]) -> Vec<&'q [u8]> {
        let mut terms: Vec<&[u8]> = q.iter().map(Vec::as_slice).collect();
        terms.sort_by_key(|w| self.ct.get(*w).copied().unwrap_or(u64::MAX));
        terms
    }

    /// `Search`, client side: lines 1–8 (Alg. 2: 1–18) and the two Aura tokens.
    /// `None` is `return ∅`, which an absent term forces.
    pub fn search_token(
        &mut self,
        terms: &[&[u8]],
        rng: &mut impl rand::Rng,
    ) -> Option<SearchToken> {
        let (w1, rest) = terms.split_first()?;
        let c = *self.ct.get(*w1)?;
        // ⚠️ Every term before any Aura search: `Aura.Search` refreshes `w₁`'s key,
        // so returning after it would strand `w₁`'s entries under the old one.
        if rest.iter().any(|w| !self.ct.contains_key(*w)) {
            return None;
        }
        let k_w1 = prf_bytes(&self.k, w1);

        let z2 = prf_scalar(&self.k_z2, w1);
        let kxs: Vec<Scalar> = rest.iter().map(|w| prf_scalar(&self.k_x, w)).collect();
        let mut xtoken = Vec::with_capacity(usize::try_from(c + 1).unwrap_or(0));
        for i in 0..=c {
            let z = prf_scalar(&self.k_z, &w_c(w1, i));
            let row = kxs
                .iter()
                .map(|kx| match self.variant {
                    Variant::Cq => g_pow(&(z * kx)),
                    Variant::CqS => g_pow(&(z * kx * z2)),
                })
                .collect();
            xtoken.push(row);
        }

        let mut wxt = Vec::new();
        if self.variant == Variant::CqS {
            for w in rest {
                let cj = *self.ct.get(*w)?;
                wxt.push(
                    (0..=cj)
                        .map(|k| prf_scalar(&self.k_x2, &w_c(w, k)) * z2)
                        .collect(),
                );
            }
        }

        let aura_t = self.t.search(w1, rng)?;
        let aura_x = rest
            .iter()
            .map(|w| self.x.search(w, rng))
            .collect::<Option<Vec<_>>>()?;
        Some(SearchToken {
            xtoken,
            wxt,
            aura_t,
            aura_x,
            k_w1,
        })
    }

    /// Lines 34–36: `ind ← SE.Dec(k_{w₁}, e)`.
    #[must_use]
    pub fn finalise(token: &SearchToken, res: &[Vec<u8>]) -> BTreeSet<DocId> {
        res.iter()
            .map(|e| {
                let plain = aura::se_dec(&token.k_w1, e);
                let mut id = [0u8; 8];
                id.copy_from_slice(&plain);
                u64::from_be_bytes(id)
            })
            .collect()
    }

    /// The whole search, in order.
    pub fn search(
        &mut self,
        server: &mut Server,
        q: &[Vec<u8>],
        rng: &mut impl rand::Rng,
    ) -> BTreeSet<DocId> {
        let terms = self.order_terms(q);
        let Some(token) = self.search_token(&terms, rng) else {
            return BTreeSet::new();
        };
        let mut rb = Rollback::default();
        let res = server.search(&token, &mut rb, None);
        Self::finalise(&token, &res)
    }

    /// Save what `search_token` will change, outside a timed region.
    #[must_use]
    pub fn checkpoint(&self, terms: &[&[u8]]) -> Rollback {
        let mut rb = Rollback::default();
        if let Some((w1, rest)) = terms.split_first() {
            if let Some(cp) = self.t.checkpoint(w1) {
                rb.t.push((w1.to_vec(), cp));
            }
            for w in rest {
                if let Some(cp) = self.x.checkpoint(w) {
                    rb.x.push((w.to_vec(), cp));
                }
            }
        }
        rb
    }

    /// Undo one **first** search, outside a timed region. `first_rb` is what
    /// [`Client::checkpoint`] returned before it, with `Server::search`'s record.
    pub fn rollback(&mut self, server: &mut Server, rb: Rollback) {
        for (w, cp) in rb.t {
            self.t.restore(&w, cp);
        }
        for (w, cp) in rb.x {
            self.x.restore(&w, cp);
        }
        if let Some(u) = rb.server_t {
            server.t.undo_first(u);
        }
        for u in rb.server_x {
            server.x.undo_first(u);
        }
    }

    /// Bytes the client keeps: the Aura per-keyword states and `CT`.
    #[must_use]
    pub fn client_bytes(&self) -> usize {
        self.t.client_bytes() + self.x.client_bytes() + self.ct.len() * 40
    }
}

impl Server {
    /// `Search`, server side: lines 9–33 (Alg. 2: 19–45).
    ///
    /// `rb` records what the search consumed, so a harness can put it back.
    /// `observe`, when given, is Exp. 5's instrument. Neither changes the work.
    pub fn search(
        &mut self,
        token: &SearchToken,
        rb: &mut Rollback,
        mut observe: Option<&mut Observer>,
    ) -> Vec<Vec<u8>> {
        // Line 9 and lines 13–20.
        let mut undo_t = aura::Undo::default();
        let tuples: Vec<(Vec<u8>, Scalar, u64)> = self
            .t
            .search(&token.aura_t, &mut undo_t)
            .iter()
            .map(|c| parse_tuple(&c.payload))
            .collect();
        rb.server_t = Some(undo_t);

        let mut xset: HashSet<[u8; 32]> = HashSet::new();
        for (j, m) in token.aura_x.iter().enumerate() {
            let mut undo = aura::Undo::default();
            let fetched = self.x.search(m, &mut undo);
            xset.reserve(fetched.len());
            for c in fetched {
                match token.wxt.get(j) {
                    None => {
                        let mut tag = [0u8; 32];
                        tag.copy_from_slice(&c.payload);
                        xset.insert(tag);
                    }
                    // Alg. 2 lines 29–31: re-blind each fetched xtag.
                    Some(row) => {
                        if let Some(tag) = reblind(&c.payload, row) {
                            xset.insert(tag);
                        }
                    }
                }
            }
            rb.server_x.push(undo);
        }

        if let Some(o) = observe.as_deref_mut() {
            o.fetched.extend(xset.iter().copied());
        }

        // Lines 22–32.
        let mut res = Vec::new();
        for (e, y, c) in tuples {
            let Some(row) = token.xtoken.get(usize::try_from(c).unwrap_or(usize::MAX)) else {
                continue;
            };
            let mut flag = true;
            let mut seen = Vec::new();
            for tok in row {
                let tested = (tok * y).compress().to_bytes();
                let hit = xset.contains(&tested);
                if observe.is_some() {
                    seen.push((tested, hit));
                }
                if !hit {
                    flag = false;
                    if observe.is_none() {
                        break;
                    }
                }
            }
            if let Some(o) = observe.as_deref_mut() {
                o.tuples.push(Observed {
                    e: e.clone(),
                    lookups: seen,
                });
            }
            if flag {
                res.push(e);
            }
        }
        res
    }
}

/// `wxtag^{wxt[j][c_j]}`, Alg. 2 line 30.
fn reblind(payload: &[u8], row: &[Scalar]) -> Option<[u8; 32]> {
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&payload[..32]);
    let mut c = [0u8; 8];
    c.copy_from_slice(&payload[32..40]);
    let scalar = row.get(usize::try_from(u64::from_be_bytes(c)).ok()?)?;
    let p = CompressedRistretto(tag).decompress()?;
    Some((p * scalar).compress().to_bytes())
}

fn parse_tuple(payload: &[u8]) -> (Vec<u8>, Scalar, u64) {
    let e = payload[..E_BYTES].to_vec();
    let mut y = [0u8; 32];
    y.copy_from_slice(&payload[E_BYTES..E_BYTES + 32]);
    let mut c = [0u8; 8];
    c.copy_from_slice(&payload[E_BYTES + 32..E_BYTES + 40]);
    (e, Scalar::from_bytes_mod_order(y), u64::from_be_bytes(c))
}
