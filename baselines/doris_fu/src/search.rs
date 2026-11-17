//! The Doris follow-up's **search** (Algorithm 4) over the Algorithm 3 build:
//! M15's trial arm for Exps. 2 and 5. Static.
//!
//! # Provenance
//!
//! Transcribed from Algorithms 3–4 and §5 (`XBPE`) of
//! `ref-papers/DORIS-followup_ProvSec2025.pdf`, read directly, with
//! Doris's own released code (`../doris/upstream/Utils/SSPE_XF.py`,
//! `Doris_XF.py`) consulted where the follow-up says it builds on "the generic
//! construction of Doris". Every reading choice is in `../UPGRADES.md`.
//!
//! # The search
//!
//! The client picks the s-term by its Count-Min estimate and sends `stag`. The
//! server walks the s-term's `TSet` list. For each candidate `c` the client
//! sends `xtoken[c] = XBPE.KeyGen(msk, {F(K_I, sterm‖w_i‖c)})`: a fresh `K`,
//! `sk¹ = K ⊕ (⊕ F(sk, x))`, `sk² = SE.Enc(K, 0^λ)` and the `3(n−1)` filter
//! locations. The server XORs those slots into `sk¹`, decrypts `sk²`, and keeps
//! `e_c` iff it reads `0^λ`: one bit per candidate for the whole conjunction. One
//! round (their Table 1); the client streams tokens until the server stops it,
//! which in process is one token per candidate.
//!
//! ⛔ **Static.** No update, no deletion. A harness builds it over the live
//! documents, the state the dynamic arms hold after their deletions.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use baseline_odxt::prf::{PrfKey, prf_bytes};
use pqcl_primitives::xof;
use rand::Rng;
use rand::seq::SliceRandom;

use crate::{CountMin, Filter, Hashes, KAPPA};

/// The Count-Min shape of the counting crate: `α = 5`, `β = 2719` (`UPGRADES.md`).
const CMS_ALPHA: usize = 5;
const CMS_BETA: usize = 2719;

/// `TSet` label bytes. Doris's `cal_size` counts an 8-byte `L`; a global map
/// here, so 16 keep collisions out of reach at `10⁸` entries.
const LABEL_BYTES: usize = 16;
/// `β ‖ e`: the continue bit and `e = IV ‖ AES-CBC(id)`, 32 bytes.
const ENTRY_BYTES: usize = 1 + 32;

/// `F(k, ⟪parts⟫)`, length-framed so `w‖w′‖c` never collides across splits.
fn f(k: &PrfKey, parts: &[&[u8]]) -> [u8; 32] {
    let mut v = Vec::with_capacity(parts.iter().map(|p| p.len() + 8).sum());
    for p in parts {
        v.extend_from_slice(&(p.len() as u64).to_be_bytes());
        v.extend_from_slice(p);
    }
    prf_bytes(k, &v)
}

fn xor_into(acc: &mut [u8; 32], x: &[u8; 32]) {
    for (a, b) in acc.iter_mut().zip(x) {
        *a ^= b;
    }
}

/// `SE.Enc(K_e, id)` as Doris's `AES_enc`: AES-256-CBC, random IV, one block
/// (an 8-byte id, PKCS#7-padded).
fn se_enc_id(k: &[u8; 32], id: u64, rng: &mut impl Rng) -> [u8; 32] {
    let cipher = Aes256::new(GenericArray::from_slice(k));
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    let mut block = [8u8; 16];
    block[..8].copy_from_slice(&id.to_be_bytes());
    for (b, v) in block.iter_mut().zip(iv) {
        *b ^= v;
    }
    let mut g = GenericArray::from(block);
    cipher.encrypt_block(&mut g);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&iv);
    out[16..].copy_from_slice(&g);
    out
}

fn se_dec_id(k: &[u8; 32], e: &[u8; 32]) -> u64 {
    let cipher = Aes256::new(GenericArray::from_slice(k));
    let mut g = GenericArray::clone_from_slice(&e[16..]);
    cipher.decrypt_block(&mut g);
    let mut id = [0u8; 8];
    for (i, b) in id.iter_mut().enumerate() {
        *b = g[i] ^ e[i];
    }
    u64::from_be_bytes(id)
}

/// XBPE's `SE`, PCPA-secure (Doris §2.2): AES-256-CTR under a random IV.
fn ctr_xor(k: &[u8; 32], iv: &[u8; 16], data: &mut [u8; 32]) {
    let cipher = Aes256::new(GenericArray::from_slice(k));
    let ctr = u128::from_be_bytes(*iv);
    for (i, chunk) in data.chunks_mut(16).enumerate() {
        let mut block = GenericArray::from(ctr.wrapping_add(i as u128).to_be_bytes());
        cipher.encrypt_block(&mut block);
        for (d, s) in chunk.iter_mut().zip(block.iter()) {
            *d ^= *s;
        }
    }
}

/// `TSet` label and mask for entry `c` of `stag`'s list.
fn tset_slot(stag: &[u8; 32], c: u64) -> ([u8; LABEL_BYTES], [u8; ENTRY_BYTES]) {
    let mut input = [0u8; 41];
    input[0] = 0x54; // 'T'
    input[1..33].copy_from_slice(stag);
    input[33..].copy_from_slice(&c.to_be_bytes());
    let out = xof::shake256(&input, LABEL_BYTES + ENTRY_BYTES);
    let mut label = [0u8; LABEL_BYTES];
    label.copy_from_slice(&out[..LABEL_BYTES]);
    let mut mask = [0u8; ENTRY_BYTES];
    mask.copy_from_slice(&out[LABEL_BYTES..]);
    (label, mask)
}

/// `K = (K_S, K_I, K_T, msk)`, the frequency table, and the filter's hashes.
#[derive(Debug, Clone)]
pub struct Client {
    k_s: PrfKey,
    k_i: PrfKey,
    k_t: PrfKey,
    /// XBPE's `sk`.
    sk: PrfKey,
    hashes: Hashes,
    cms: CountMin,
}

/// `EDB = (TSet, ct)`.
#[derive(Debug, Clone)]
pub struct Edb {
    tset: HashMap<[u8; LABEL_BYTES], [u8; ENTRY_BYTES]>,
    ct: Filter,
}

impl Edb {
    /// `TSet` entries, and XSet tags inside the filter.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.tset.len()
    }

    /// Bytes stored: `TSet` at label + value, the filter at 32 bytes per slot.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.tset.len() * (LABEL_BYTES + ENTRY_BYTES) + self.ct.stored_bytes()
    }

    /// `TSetRetrieve(TSet, stag)` (Alg. 4 line 22).
    #[must_use]
    pub fn retrieve(&self, stag: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut t = Vec::new();
        for c in 0u64.. {
            let (label, mask) = tset_slot(stag, c);
            let Some(v) = self.tset.get(&label) else {
                break;
            };
            let mut plain = *v;
            for (p, m) in plain.iter_mut().zip(mask) {
                *p ^= m;
            }
            let mut e = [0u8; 32];
            e.copy_from_slice(&plain[1..]);
            t.push(e);
            if plain[0] == 0 {
                break;
            }
        }
        t
    }

    /// Alg. 4 lines 23–28: `XBPE.Dec(xtoken[c], ct)` per candidate; `e_c` is kept
    /// iff it reads `True`. `observe`, when given, records Exp. 5's view and does
    /// not change the work.
    #[must_use]
    pub fn decide(
        &self,
        t: &[[u8; 32]],
        xtokens: &[XToken],
        mut observe: Option<&mut Vec<Observed>>,
    ) -> Vec<[u8; 32]> {
        let mut res = Vec::new();
        for (e, tok) in t.iter().zip(xtokens) {
            // K′ = (⊕_{s∈S} B[s]) ⊕ sk¹, over S as a list: two x-terms sharing a
            // slot must both XOR it in, or the identity breaks.
            let mut k = tok.sk1;
            for s in tok.s.iter().flatten() {
                xor_into(&mut k, &self.ct.slots[*s]);
            }
            let mut psi = tok.sk2_body;
            ctr_xor(&k, &tok.sk2_iv, &mut psi);
            let hit = psi == [0u8; 32];
            if let Some(o) = observe.as_deref_mut() {
                o.push(Observed {
                    e: *e,
                    s: tok.s.clone(),
                    hit,
                });
            }
            if hit {
                res.push(*e);
            }
        }
        res
    }
}

/// `xtoken[c] = (sk¹, sk², S)`.
#[derive(Debug, Clone)]
pub struct XToken {
    sk1: [u8; 32],
    sk2_iv: [u8; 16],
    sk2_body: [u8; 32],
    /// `S = {S_x}`: one location set per x-term.
    s: Vec<[usize; KAPPA]>,
}

impl XToken {
    /// Bytes sent up: `sk¹`, `sk²` and `3(n−1)` locations at 8 bytes.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        32 + 48 + self.s.len() * KAPPA * 8
    }
}

/// Exp. 5's view of one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The document handle `e_c`.
    pub e: [u8; 32],
    /// One location set per x-term.
    pub s: Vec<[usize; KAPPA]>,
    /// The whole conjunction's outcome.
    pub hit: bool,
}

/// The tags `EDBSetup` puts in `XSet`, exactly, before building anything: one per
/// (keyword of a document, other keyword of that document), so `Σ k(k−1)` over the
/// documents (keywords per document are distinct). A harness sizes its memory from
/// this (M15 c15, Exp. 2's stop size).
#[must_use]
pub fn xset_tags(docs: &[(u64, Vec<String>)]) -> u64 {
    docs.iter()
        .map(|(_, ws)| {
            let k = ws.len() as u64;
            k * k.saturating_sub(1)
        })
        .sum()
}

/// Lines 13–16's tags, `y′ = F(sk, F(K_I, w‖w′‖c))`, in the sequential order (keyword,
/// then `c`, then `w′`), computed on every core. The build is never timed; this only
/// keeps c15's largest builds from taking hours on one core. The output is the same
/// vector a single loop produces (tested).
fn xset_parallel(
    inv: &BTreeMap<&str, Vec<u64>>,
    words_of: &HashMap<u64, &[String]>,
    k_i: &PrfKey,
    sk: &PrfKey,
) -> Vec<[u8; 32]> {
    let items: Vec<(&str, &Vec<u64>)> = inv.iter().map(|(w, ids)| (*w, ids)).collect();
    let lens: Vec<usize> = items
        .iter()
        .map(|(_, ids)| {
            ids.iter()
                .map(|id| words_of.get(id).map_or(0, |ws| ws.len().saturating_sub(1)))
                .sum()
        })
        .collect();
    let total: usize = lens.iter().sum();
    let mut xset = vec![[0u8; 32]; total];
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let per = total.div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let mut rest: &mut [[u8; 32]] = &mut xset;
        let mut start = 0;
        while start < items.len() {
            let (mut end, mut n) = (start, 0);
            while end < items.len() && (n < per || end == start) {
                n += lens[end];
                end += 1;
            }
            let (chunk, tail) = std::mem::take(&mut rest).split_at_mut(n);
            rest = tail;
            let group = &items[start..end];
            scope.spawn(move || {
                let mut i = 0;
                for (w, ids) in group {
                    for (c, id) in ids.iter().enumerate() {
                        let cb = (c as u64).to_be_bytes();
                        for other in words_of.get(id).copied().unwrap_or_default() {
                            if other != w {
                                // XBPE.Enc inserts y′ = F(sk, xtag).
                                let xtag = f(k_i, &[w.as_bytes(), other.as_bytes(), &cb]);
                                chunk[i] = f(sk, &[&xtag]);
                                i += 1;
                            }
                        }
                    }
                }
            });
            start = end;
        }
    });
    xset
}

/// `FreqTableSetup` + `EDBSetup` (Alg. 3) over `(id, keywords)` documents.
/// `None` only if the filter cannot be peeled in `MAX_ATTEMPTS` seeds.
#[must_use]
pub fn setup(docs: &[(u64, Vec<String>)], master: &[u8; 32], seed: u64) -> Option<(Client, Edb)> {
    use rand::SeedableRng as _;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let key = |label: u8| {
        let mut input = [0u8; 33];
        input[0] = label;
        input[1..].copy_from_slice(master);
        let mut k = [0u8; 32];
        k.copy_from_slice(&xof::shake256(&input, 32));
        PrfKey(k)
    };
    let (k_s, k_i, k_t, sk) = (key(0x40), key(0x41), key(0x42), key(0x43));

    let mut inv: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    let mut words_of: HashMap<u64, &[String]> = HashMap::new();
    for (id, ws) in docs {
        words_of.insert(*id, ws);
        for w in ws {
            inv.entry(w).or_default().push(*id);
        }
    }

    // FreqTableSetup.
    let mut cms = CountMin::setup(CMS_ALPHA, CMS_BETA);
    for (w, ids) in &inv {
        for _ in ids {
            cms.add(w.as_bytes());
        }
    }

    // EDBSetup lines 6–20. ⚠️ Lines 13–16 pair `w` with the other keywords of
    // the id the outer loop holds (UPGRADES.md, the counting crate's reading).
    // The shuffle and `e` draw from one RNG, so the `TSet` loop is sequential.
    let mut tset = HashMap::new();
    for (w, ids) in &mut inv {
        let k_e = f(&k_s, &[w.as_bytes()]);
        let stag = f(&k_t, &[w.as_bytes()]);
        ids.shuffle(&mut rng); // "for all id ∈ DB(w) in random order"
        let last = ids.len() - 1;
        for (c, id) in ids.iter().enumerate() {
            let e = se_enc_id(&k_e, *id, &mut rng);
            let (label, mask) = tset_slot(&stag, c as u64);
            let mut v = [0u8; ENTRY_BYTES];
            v[0] = u8::from(c != last);
            v[1..].copy_from_slice(&e);
            for (x, m) in v.iter_mut().zip(mask) {
                *x ^= m;
            }
            tset.insert(label, v);
        }
    }
    let xset = xset_parallel(&inv, &words_of, &k_i, &sk);
    let ct = Filter::construct(&xset, seed ^ 0x5845_4246)?;
    let hashes = ct.hashes();
    Some((
        Client {
            k_s,
            k_i,
            k_t,
            sk,
            hashes,
            cms,
        },
        Edb { tset, ct },
    ))
}

impl Client {
    /// Alg. 4 lines 3–11: the term with the least estimated frequency, and the
    /// rest in query order.
    #[must_use]
    pub fn choose<'q>(&self, terms: &[&'q [u8]]) -> Option<(&'q [u8], Vec<&'q [u8]>)> {
        let mut best: Option<(usize, u32)> = None;
        for (i, w) in terms.iter().enumerate() {
            let n = self.cms.query(w);
            if best.is_none_or(|(_, m)| n < m) {
                best = Some((i, n));
            }
        }
        let (i, _) = best?;
        let rest = terms
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, w)| *w)
            .collect();
        Some((terms[i], rest))
    }

    /// Line 12: `stag ← TSetGetTag(K_T, sterm)`.
    #[must_use]
    pub fn stag(&self, sterm: &[u8]) -> [u8; 32] {
        f(&self.k_t, &[sterm])
    }

    /// Lines 13–19: `xtoken[c]` for `c` over the `count` candidates.
    ///
    /// ⚠️ Alg. 3 counts `c` from 0, Alg. 4 from 1; both index the same `TSet`
    /// position here, which is the only reading under which a token can match.
    pub fn xtokens(
        &self,
        sterm: &[u8],
        rest: &[&[u8]],
        count: usize,
        rng: &mut impl Rng,
    ) -> Vec<XToken> {
        (0..count as u64)
            .map(|c| {
                let cb = c.to_be_bytes();
                // XBPE.KeyGen(msk, QSet_c).
                let mut k = [0u8; 32];
                rng.fill(&mut k);
                let mut sk1 = k;
                let mut s = Vec::with_capacity(rest.len());
                for w in rest {
                    let qtag = f(&self.k_i, &[sterm, w, &cb]);
                    let y = f(&self.sk, &[&qtag]);
                    xor_into(&mut sk1, &y);
                    s.push(self.hashes.positions(&y));
                }
                let mut iv = [0u8; 16];
                rng.fill(&mut iv);
                let mut body = [0u8; 32];
                ctr_xor(&k, &iv, &mut body);
                XToken {
                    sk1,
                    sk2_iv: iv,
                    sk2_body: body,
                    s,
                }
            })
            .collect()
    }

    /// Lines 31–35: decrypt the result under `K_{e1} = F(K_S, sterm)`.
    #[must_use]
    pub fn decrypt(&self, sterm: &[u8], res: &[[u8; 32]]) -> BTreeSet<u64> {
        let k = f(&self.k_s, &[sterm]);
        res.iter().map(|e| se_dec_id(&k, e)).collect()
    }

    /// The whole search, in order.
    pub fn search(&self, edb: &Edb, q: &[&[u8]], rng: &mut impl Rng) -> BTreeSet<u64> {
        let Some((sterm, rest)) = self.choose(q) else {
            return BTreeSet::new();
        };
        let t = edb.retrieve(&self.stag(sterm));
        let tokens = self.xtokens(sterm, &rest, t.len(), rng);
        let res = edb.decide(&t, &tokens, None);
        self.decrypt(sterm, &res)
    }

    /// Bytes the client keeps: the frequency table and the keys.
    #[must_use]
    pub const fn client_bytes(&self) -> usize {
        self.cms.client_bytes() + 4 * 32 + 24
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docs() -> Vec<(u64, Vec<String>)> {
        let raw: &[(u64, &[&str])] = &[
            (1, &["a", "b", "c"]),
            (2, &["a", "b"]),
            (3, &["a", "c", "d"]),
            (4, &["b", "c", "d"]),
            (5, &["a", "b", "c", "d"]),
            (6, &["d"]),
            (7, &["a", "e"]),
        ];
        raw.iter()
            .map(|(id, ws)| (*id, ws.iter().map(|w| (*w).to_owned()).collect()))
            .collect()
    }

    fn oracle(d: &[(u64, Vec<String>)], q: &[&str]) -> BTreeSet<u64> {
        d.iter()
            .filter(|(_, ws)| q.iter().all(|w| ws.iter().any(|x| x == w)))
            .map(|(id, _)| *id)
            .collect()
    }

    #[test]
    fn the_parallel_tags_are_the_sequential_ones_and_the_count_is_exact() {
        let d = docs();
        let mut inv: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
        let mut words_of: HashMap<u64, &[String]> = HashMap::new();
        for (id, ws) in &d {
            words_of.insert(*id, ws);
            for w in ws {
                inv.entry(w).or_default().push(*id);
            }
        }
        let (ki, sk) = (PrfKey([1; 32]), PrfKey([2; 32]));
        let mut seq = Vec::new();
        for (w, ids) in &inv {
            for (c, id) in ids.iter().enumerate() {
                let cb = (c as u64).to_be_bytes();
                for other in words_of[id] {
                    if other != w {
                        seq.push(f(&sk, &[&f(&ki, &[w.as_bytes(), other.as_bytes(), &cb])]));
                    }
                }
            }
        }
        assert_eq!(xset_parallel(&inv, &words_of, &ki, &sk), seq);
        assert_eq!(xset_tags(&d), seq.len() as u64);
    }

    #[test]
    fn conjunctions_match_the_oracle() {
        use rand::SeedableRng as _;
        let d = docs();
        let (c, edb) = setup(&d, &[9; 32], 3).expect("filter builds");
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        for q in [
            &["a", "b"][..],
            &["a", "c"],
            &["b", "c", "d"],
            &["a", "b", "c", "d"],
            &["d", "e"],
            &["e", "a"],
            &["a"],
            &["zz", "a"],
        ] {
            let qb: Vec<&[u8]> = q.iter().map(|w| w.as_bytes()).collect();
            assert_eq!(c.search(&edb, &qb, &mut rng), oracle(&d, q), "{q:?}");
        }
    }

    #[test]
    fn the_server_sees_one_bit_per_candidate_and_one_set_per_x_term() {
        use rand::SeedableRng as _;
        let d = docs();
        let (c, edb) = setup(&d, &[9; 32], 3).expect("filter builds");
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let q: Vec<&[u8]> = vec![b"d", b"a", b"b"];
        let (sterm, rest) = c.choose(&q).expect("terms");
        let t = edb.retrieve(&c.stag(sterm));
        let toks = c.xtokens(sterm, &rest, t.len(), &mut rng);
        let mut seen = Vec::new();
        let res = edb.decide(&t, &toks, Some(&mut seen));
        assert_eq!(c.decrypt(sterm, &res), oracle(&d, &["a", "b", "d"]));
        assert_eq!(seen.len(), t.len());
        assert!(seen.iter().all(|o| o.s.len() == 2));
        // The same s-term and x-term at the same candidate gives the same set
        // again (their XEP); a fresh K does not hide it.
        let again = c.xtokens(sterm, &rest, t.len(), &mut rng);
        assert_eq!(again[0].s, toks[0].s);
        assert_ne!(again[0].sk1, toks[0].sk1);
    }

    #[test]
    fn a_wrong_key_reads_false_not_true() {
        use rand::SeedableRng as _;
        let d = docs();
        let (c, edb) = setup(&d, &[9; 32], 3).expect("filter builds");
        let (other, _) = setup(&d, &[8; 32], 3).expect("filter builds");
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let q: Vec<&[u8]> = vec![b"a", b"b"];
        let (sterm, rest) = c.choose(&q).expect("terms");
        let t = edb.retrieve(&c.stag(sterm));
        let wrong = other.xtokens(sterm, &rest, t.len(), &mut rng);
        assert!(edb.decide(&t, &wrong, None).is_empty());
    }
}
