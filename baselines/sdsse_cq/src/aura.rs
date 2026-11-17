//! Aura — non-interactive Type-II backward-private DSSE (Sun et al., NDSS 2021).
//!
//! Transcribed from Algorithm 3 of SDSSE-CQ's appendix and Algorithm 1 and §V of
//! `ref-papers/Aura_NDSS2021.pdf`, read directly. Deviations are in
//! `../UPGRADES.md`.
//!
//! # The scheme
//!
//! An entry is encrypted `h` times, once under each of `h` GGM leaves picked by
//! Bloom-filter hashes of its tag `t = F(K_t, (w, ind))`. To delete, the client
//! sets those `h` bits in a per-keyword Bloom filter and sends nothing. To
//! search, it punctures the GGM key at every set bit and hands the server the
//! punctured key: an entry whose `h` bits are all set cannot be decrypted, and
//! any other entry has a surviving leaf.
//!
//! The key is refreshed after each search, and decrypted entries move to a
//! server-side cache, so **a second search on a keyword decrypts only what was
//! added since.** Any timing has to say which it measured.
//!
//! The inner forward-private scheme `Σ_add` is FB-DSSE's symmetric one-way
//! chain, keyed per `(w, i)`, where `i` counts the searches on `w`.

use std::collections::HashMap;

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use baseline_odxt::prf::{PrfKey, prf_bytes};
use pqcl_dsse::core::Op;
use pqcl_primitives::xof;

/// `h`: Bloom hashes per tag, SDSSE-CQ §5.1.
pub const BLOOM_HASHES: usize = 5;
/// `p`: the Bloom false-positive rate, SDSSE-CQ §5.1.
pub const BLOOM_FP: f64 = 1e-4;
/// The smallest `d` the authors evaluate (Aura §VI). A keyword's filter is never
/// sized for fewer deletions than this.
pub const MIN_DELETIONS: usize = 10;

const IV_BYTES: usize = 16;
const H1: u8 = 0x41;
const H2: u8 = 0x42;
const HB: u8 = 0x43;

/// A chain token.
pub type Token = [u8; 32];
/// `t = F(K_t, (w, ind))`, truncated.
pub type Tag = [u8; 16];

/// One SE ciphertext over AES-256 in counter mode: `iv ‖ m ⊕ keystream`.
///
/// ⭐ `SE` is IND-CPA in the paper, with no authentication, so it adds no tag.
#[must_use]
pub fn se_enc(key: &[u8; 32], msg: &[u8], rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut out = vec![0u8; IV_BYTES + msg.len()];
    let (iv, body) = out.split_at_mut(IV_BYTES);
    rng.fill_bytes(iv);
    let iv: &[u8; IV_BYTES] = (&*iv).try_into().unwrap_or(&[0; IV_BYTES]);
    let iv = *iv;
    body.copy_from_slice(msg);
    ctr_xor(key, &iv, body);
    out
}

/// Inverse of [`se_enc`].
#[must_use]
pub fn se_dec(key: &[u8; 32], ct: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; IV_BYTES];
    iv.copy_from_slice(&ct[..IV_BYTES]);
    let mut body = ct[IV_BYTES..].to_vec();
    ctr_xor(key, &iv, &mut body);
    body
}

fn ctr_xor(key: &[u8; 32], iv: &[u8; IV_BYTES], data: &mut [u8]) {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut ctr = u128::from_be_bytes(*iv);
    for chunk in data.chunks_mut(IV_BYTES) {
        let mut block = GenericArray::from(ctr.to_be_bytes());
        cipher.encrypt_block(&mut block);
        for (d, k) in chunk.iter_mut().zip(block.iter()) {
            *d ^= *k;
        }
        ctr = ctr.wrapping_add(1);
    }
}

/// The length-doubling PRG of Aura's GGM tree, from AES (its §VI): `G_bit(node)`.
fn ggm_child(node: &[u8; 32], bit: bool) -> [u8; 32] {
    let cipher = Aes256::new(GenericArray::from_slice(node));
    let base = if bit { 2u8 } else { 0u8 };
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_exact_mut(IV_BYTES).enumerate() {
        let mut block = GenericArray::from([0u8; IV_BYTES]);
        block[15] = base + u8::try_from(i).unwrap_or(0);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    out
}

/// `F_sk(i)`: the GGM leaf at `i`, in a tree `levels` deep.
#[must_use]
fn ggm_leaf(root: &[u8; 32], i: u64, levels: u32) -> [u8; 32] {
    let mut node = *root;
    for d in (0..levels).rev() {
        node = ggm_child(&node, (i >> d) & 1 == 1);
    }
    node
}

/// `b = ⌈h·d / −ln(1 − p^{1/h})⌉`: the bits a filter with `h` hashes needs for
/// `d` tags at false-positive rate `p`. At `h = 5`, `p = 10⁻⁴` this is about
/// 29 bits per tag, which reproduces Aura's Table II (0.35 KiB at `d = 100`).
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)] // a deletion count well below 2^52, and a positive result of that size
pub fn bloom_bits(deletions: usize) -> u64 {
    let d = deletions.max(MIN_DELETIONS) as f64;
    let h = BLOOM_HASHES as f64;
    let denom = -(1.0 - BLOOM_FP.powf(1.0 / h)).ln();
    (h * d / denom).ceil() as u64
}

/// `H_j(t) ∈ [b]`, for `j ∈ [h]`.
fn bloom_indices(t: &Tag, b: u64) -> [u64; BLOOM_HASHES] {
    let mut input = [0u8; 17];
    input[0] = HB;
    input[1..].copy_from_slice(t);
    let wide = xof::shake256(&input, 8 * BLOOM_HASHES);
    let mut out = [0u64; BLOOM_HASHES];
    for (o, c) in out.iter_mut().zip(wide.chunks_exact(8)) {
        let mut x = [0u8; 8];
        x.copy_from_slice(c);
        *o = u64::from_be_bytes(x) % b;
    }
    out
}

/// A Bloom filter over `[b]`: the compressed revocation list `D`.
#[derive(Debug, Clone)]
pub struct Bloom {
    b: u64,
    bits: Vec<u64>,
}

impl Bloom {
    fn new(b: u64) -> Self {
        Self {
            b,
            bits: vec![0; usize::try_from(b.div_ceil(64)).unwrap_or(0)],
        }
    }

    fn get(&self, i: u64) -> bool {
        self.bits[usize::try_from(i / 64).unwrap_or(0)] >> (i % 64) & 1 == 1
    }

    fn set(&mut self, i: u64) {
        self.bits[usize::try_from(i / 64).unwrap_or(0)] |= 1 << (i % 64);
    }

    fn is_empty(&self) -> bool {
        self.bits.iter().all(|w| *w == 0)
    }

    /// Bytes `D` occupies, at the client and on the wire.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        usize::try_from(self.b.div_ceil(8)).unwrap_or(0)
    }

    fn set_indices(&self) -> Vec<u64> {
        (0..self.b).filter(|i| self.get(*i)).collect()
    }
}

/// `MF.Punc`: every maximal GGM subtree holding no punctured leaf.
#[derive(Debug, Clone, Default)]
pub struct PuncturedKey {
    /// `(depth, prefix) → node`. Depth 0 is the root.
    nodes: HashMap<(u32, u64), [u8; 32]>,
    levels: u32,
}

impl PuncturedKey {
    fn build(root: &[u8; 32], set: &[u64], levels: u32) -> Self {
        let mut nodes = HashMap::new();
        Self::cover(root, 0, 0, set, levels, &mut nodes);
        Self { nodes, levels }
    }

    fn cover(
        node: &[u8; 32],
        depth: u32,
        prefix: u64,
        set: &[u64],
        levels: u32,
        out: &mut HashMap<(u32, u64), [u8; 32]>,
    ) {
        if set.is_empty() {
            out.insert((depth, prefix), *node);
            return;
        }
        if depth == levels {
            return;
        }
        let shift = levels - depth - 1;
        let mid = ((prefix << 1) | 1) << shift;
        let split = set.partition_point(|i| *i < mid);
        let (l, r) = set.split_at(split);
        Self::cover(
            &ggm_child(node, false),
            depth + 1,
            prefix << 1,
            l,
            levels,
            out,
        );
        Self::cover(
            &ggm_child(node, true),
            depth + 1,
            (prefix << 1) | 1,
            r,
            levels,
            out,
        );
    }

    /// `MF.Eval`. `None` exactly on a punctured leaf.
    #[must_use]
    fn eval(&self, i: u64) -> Option<[u8; 32]> {
        for depth in 0..=self.levels {
            if let Some(node) = self.nodes.get(&(depth, i >> (self.levels - depth))) {
                let mut k = *node;
                for d in (0..self.levels - depth).rev() {
                    k = ggm_child(&k, (i >> d) & 1 == 1);
                }
                return Some(k);
            }
        }
        None
    }

    /// Bytes on the wire: 32 per node, plus 12 for its position.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.nodes.len() * 44
    }
}

/// What the client holds per keyword: `MSK[w]`, `D[w]`, `C[w]` and `σ_add`.
#[derive(Debug, Clone)]
struct Keyword {
    sk: [u8; 32],
    d: Bloom,
    levels: u32,
    /// `C[w]`: searches so far.
    i: u64,
    /// `σ_add`: the current chain head under `w‖i`, if anything was added.
    chain: Option<Token>,
}

/// `Σ_add`'s server entry: `EDB_add[UT] = (ct, t, C_ST)`.
#[derive(Debug, Clone)]
pub struct Entry {
    /// `h` SE ciphertexts of one length, concatenated.
    cts: Box<[u8]>,
    t: Tag,
    c_st: Option<Token>,
}

/// What `Aura.Update(add, ...)` sends the server.
#[derive(Debug, Clone)]
pub struct AddMsg {
    /// `UT`.
    pub ut: Token,
    /// The value stored at `UT`.
    pub entry: Entry,
}

/// What `Aura.Search` sends the server.
#[derive(Debug, Clone)]
pub struct SearchMsg {
    sk_r: PuncturedKey,
    d: Bloom,
    /// `tkn = F(K_s, w)`, which names the cache line.
    pub tkn: Token,
    /// `Σ_add`'s search token: `(K_{w‖i}, ST)`.
    add: Option<(Token, Token)>,
}

impl SearchMsg {
    /// Bytes sent up: `sk_R`, `D`, `tkn` and `Σ_add`'s token.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.sk_r.wire_bytes() + self.d.wire_bytes() + 32 + self.add.map_or(0, |_| 64)
    }
}

/// Aura's client.
#[derive(Debug, Clone)]
pub struct Client {
    k_add: PrfKey,
    k_s: PrfKey,
    k_t: PrfKey,
    /// `d_w`: how many deletions each keyword's filter is sized for (§1cu.2).
    deletions: HashMap<Vec<u8>, usize>,
    kw: HashMap<Vec<u8>, Keyword>,
}

impl Client {
    /// `Setup`, deriving the three keys from one master.
    ///
    /// `deletions` gives a keyword's true deletion count, so its filter fits it.
    /// A real client cannot know this in advance; it favours this arm, and
    /// `UPGRADES.md` says so. An absent keyword gets the floor.
    #[must_use]
    pub fn setup(master: &[u8; 32], deletions: HashMap<Vec<u8>, usize>) -> Self {
        let sub = |label: u8| {
            let mut input = [0u8; 33];
            input[0] = label;
            input[1..].copy_from_slice(master);
            let mut k = [0u8; 32];
            k.copy_from_slice(&xof::shake256(&input, 32));
            PrfKey(k)
        };
        Self {
            k_add: sub(1),
            k_s: sub(2),
            k_t: sub(3),
            deletions,
            kw: HashMap::new(),
        }
    }

    fn fresh(&self, w: &[u8], i: u64, rng: &mut impl rand::Rng) -> Keyword {
        let b = bloom_bits(self.deletions.get(w).copied().unwrap_or(0));
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        Keyword {
            sk,
            d: Bloom::new(b),
            levels: 64 - (b.max(2) - 1).leading_zeros(),
            i,
            chain: None,
        }
    }

    fn tag(&self, w: &[u8], tag_src: &[u8]) -> Tag {
        let mut input = Vec::with_capacity(w.len() + tag_src.len() + 8);
        input.extend_from_slice(&(w.len() as u64).to_be_bytes());
        input.extend_from_slice(w);
        input.extend_from_slice(tag_src);
        let full = prf_bytes(&self.k_t, &input);
        let mut t = [0u8; 16];
        t.copy_from_slice(&full[..16]);
        t
    }

    /// `K_{w‖i}`: `Σ_add`'s per-epoch key.
    fn chain_key(&self, w: &[u8], i: u64) -> Token {
        let mut input = Vec::with_capacity(w.len() + 8);
        input.extend_from_slice(&i.to_be_bytes());
        input.extend_from_slice(w);
        prf_bytes(&self.k_add, &input)
    }

    /// `Update(add, (w, ind))`. `tag_src` is the real `(w, ind)`'s `ind`, whatever
    /// the payload: SDSSE-CQ §5.1, since its payload differs on every encryption
    /// and a tag over it could never name the entry a deletion means.
    pub fn add(
        &mut self,
        w: &[u8],
        tag_src: &[u8],
        payload: &[u8],
        rng: &mut impl rand::Rng,
    ) -> AddMsg {
        let t = self.tag(w, tag_src);
        if !self.kw.contains_key(w) {
            let k = self.fresh(w, 0, rng);
            self.kw.insert(w.to_vec(), k);
        }
        let k_w = {
            let i = self.kw.get(w).map_or(0, |s| s.i);
            self.chain_key(w, i)
        };
        let Some(st) = self.kw.get_mut(w) else {
            unreachable!("inserted above");
        };

        let mut cts = Vec::with_capacity(BLOOM_HASHES * (IV_BYTES + payload.len()));
        for idx in bloom_indices(&t, st.d.b) {
            let leaf = ggm_leaf(&st.sk, idx, st.levels);
            cts.extend_from_slice(&se_enc(&leaf, payload, rng));
        }

        // Σ_add: ST_{c+1} random, UT = H1(K, ST), C_ST = H2(K, ST) ⊕ ST_c.
        let mut next = [0u8; 32];
        rng.fill_bytes(&mut next);
        let ut = chain_hash(H1, &k_w, &next);
        let c_st = st.chain.map(|prev| {
            let mask = chain_hash(H2, &k_w, &next);
            let mut out = [0u8; 32];
            for (o, (m, p)) in out.iter_mut().zip(mask.iter().zip(prev.iter())) {
                *o = m ^ p;
            }
            out
        });
        st.chain = Some(next);
        AddMsg {
            ut,
            entry: Entry {
                cts: cts.into_boxed_slice(),
                t,
                c_st,
            },
        }
    }

    /// `Update(del, (w, ind))`: local to the client, with nothing sent.
    pub fn delete(&mut self, w: &[u8], tag_src: &[u8], rng: &mut impl rand::Rng) {
        let t = self.tag(w, tag_src);
        if !self.kw.contains_key(w) {
            let k = self.fresh(w, 0, rng);
            self.kw.insert(w.to_vec(), k);
        }
        let Some(st) = self.kw.get_mut(w) else {
            unreachable!("inserted above");
        };
        for idx in bloom_indices(&t, st.d.b) {
            st.d.set(idx);
        }
    }

    /// `Search`, client side. `None` if `C[w] = ⊥`.
    ///
    /// ⭐ Aura §IV assumes at least one deletion per search and removes the
    /// assumption by deleting an identifier never added, or `sk_R` would be the
    /// root. This does
    /// the same.
    pub fn search(&mut self, w: &[u8], rng: &mut impl rand::Rng) -> Option<SearchMsg> {
        if !self.kw.contains_key(w) {
            return None;
        }
        if self.kw.get(w).is_some_and(|s| s.d.is_empty()) {
            self.delete(w, b"\0dummy", rng); // xtask-allow: dummy — Aura s.IV's own step, so sk_R is not the root
        }
        let tkn = prf_bytes(&self.k_s, w);
        let i = self.kw.get(w).map_or(0, |s| s.i);
        let k_w = self.chain_key(w, i);
        let fresh = self.fresh(w, i + 1, rng);
        let st = self.kw.insert(w.to_vec(), fresh)?;
        let sk_r = PuncturedKey::build(&st.sk, &st.d.set_indices(), st.levels);
        Some(SearchMsg {
            sk_r,
            d: st.d,
            tkn,
            add: st.chain.map(|head| (k_w, head)),
        })
    }

    /// `C[w]`, or `None` if `w` was never updated.
    #[must_use]
    pub fn searches_of(&self, w: &[u8]) -> Option<u64> {
        self.kw.get(w).map(|s| s.i)
    }

    /// The client's per-keyword state for `w`, kept outside a timed region so a
    /// **first** search can be timed more than once (§1cu.2).
    #[must_use]
    pub fn checkpoint(&self, w: &[u8]) -> Option<ClientCheckpoint> {
        self.kw.get(w).cloned().map(ClientCheckpoint)
    }

    /// Undo [`Client::search`] on `w`.
    pub fn restore(&mut self, w: &[u8], cp: ClientCheckpoint) {
        self.kw.insert(w.to_vec(), cp.0);
    }

    /// Bytes the client keeps per keyword: the key and `D`.
    #[must_use]
    pub fn client_bytes(&self) -> usize {
        self.kw
            .values()
            .map(|s| 32 + 8 + 32 + s.d.wire_bytes())
            .sum()
    }
}

/// See [`Client::checkpoint`].
#[derive(Debug, Clone)]
pub struct ClientCheckpoint(Keyword);

fn chain_hash(domain: u8, key: &Token, st: &Token) -> Token {
    let mut buf = [0u8; 65];
    buf[0] = domain;
    buf[1..33].copy_from_slice(key);
    buf[33..].copy_from_slice(st);
    let mut out = [0u8; 32];
    out.copy_from_slice(&xof::shake256(&buf, 32));
    out
}

/// One cached result: the payload and its tag.
#[derive(Debug, Clone)]
pub struct Cached {
    /// The decrypted payload, which the scheme hands the server in the clear.
    pub payload: Box<[u8]>,
    t: Tag,
}

/// Aura's server: `EDB_add` and `EDB_cache`.
#[derive(Debug, Default, Clone)]
pub struct Server {
    add: HashMap<Token, Entry>,
    cache: HashMap<Token, Vec<Cached>>,
}

/// The entries a first search consumed, to put back after timing it.
#[derive(Debug, Default)]
pub struct Undo {
    removed: Vec<(Token, Entry)>,
    tkn: Option<Token>,
}

impl Server {
    /// `Update`, server side.
    pub fn apply(&mut self, m: AddMsg) {
        self.add.insert(m.ut, m.entry);
    }

    /// `Search`, server side. Returns the live payloads in the cache line.
    ///
    /// ⚠️ Printed line 11 removes from the cache only tags seen among the **new**
    /// ciphertexts, so it cannot remove an entry cached by an earlier search and
    /// deleted since, which never comes back in the new list. The prose of its
    /// §V has the server check tags against `D`, and that is what this does.
    /// `UPGRADES.md` records it.
    pub fn search(&mut self, m: &SearchMsg, undo: &mut Undo) -> &[Cached] {
        let mut old = self.cache.remove(&m.tkn).unwrap_or_default();
        old.retain(|c| !bloom_indices(&c.t, m.d.b).iter().all(|i| m.d.get(*i)));

        if let Some((k_w, head)) = m.add {
            // The leaves this search needs, at most one derivation each.
            let mut leaves: HashMap<u64, [u8; 32]> = HashMap::new();
            let mut st = head;
            while let Some(e) = {
                let ut = chain_hash(H1, &k_w, &st);
                self.add.remove(&ut).map(|e| (ut, e))
            } {
                let (ut, e) = e;
                let idx = bloom_indices(&e.t, m.d.b);
                if let Some((j, i)) = idx.iter().enumerate().find(|(_, i)| !m.d.get(**i)) {
                    let leaf = *leaves
                        .entry(*i)
                        .or_insert_with(|| m.sk_r.eval(*i).unwrap_or([0u8; 32]));
                    let one = e.cts.len() / BLOOM_HASHES;
                    let ct = &e.cts[j * one..(j + 1) * one];
                    old.push(Cached {
                        payload: se_dec(&leaf, ct).into_boxed_slice(),
                        t: e.t,
                    });
                }
                let prev = e.c_st.map(|c| {
                    let mask = chain_hash(H2, &k_w, &st);
                    let mut out = [0u8; 32];
                    for (o, (a, b)) in out.iter_mut().zip(mask.iter().zip(c.iter())) {
                        *o = a ^ b;
                    }
                    out
                });
                undo.removed.push((ut, e));
                match prev {
                    Some(p) => st = p,
                    None => break,
                }
            }
        }
        undo.tkn = Some(m.tkn);
        self.cache.entry(m.tkn).or_insert(old)
    }

    /// Undo a **first** search: put back what it consumed and empty the cache
    /// line it created. Only meaningful when the line was empty beforehand.
    pub fn undo_first(&mut self, undo: Undo) {
        if let Some(tkn) = undo.tkn {
            self.cache.remove(&tkn);
        }
        for (ut, e) in undo.removed {
            self.add.insert(ut, e);
        }
    }

    /// Entries in `EDB_add`.
    #[must_use]
    pub fn add_len(&self) -> usize {
        self.add.len()
    }

    /// Bytes stored in `EDB_add`, label + value, and in the cache.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        let add: usize = self
            .add
            .values()
            .map(|e| 32 + e.cts.len() + e.t.len() + e.c_st.map_or(0, |c| c.len()))
            .sum();
        let cache: usize = self
            .cache
            .values()
            .flatten()
            .map(|c| c.payload.len() + c.t.len())
            .sum();
        add + cache
    }
}

/// `Op`-driven update, for callers holding one operation value.
pub fn update(
    client: &mut Client,
    server: &mut Server,
    op: Op,
    w: &[u8],
    tag_src: &[u8],
    payload: &[u8],
    rng: &mut impl rand::Rng,
) {
    match op {
        Op::Add => {
            let m = client.add(w, tag_src, payload, rng);
            server.apply(m);
        }
        Op::Del => client.delete(w, tag_src, rng),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    #[test]
    fn se_round_trips_and_hides() {
        let k = [3u8; 32];
        let ct = se_enc(&k, b"forty-two bytes of message, roughly so.", &mut rng());
        assert_eq!(se_dec(&k, &ct), b"forty-two bytes of message, roughly so.");
        assert_ne!(&ct[IV_BYTES..], b"forty-two bytes of message, roughly so.");
    }

    #[test]
    #[allow(clippy::cast_precision_loss)] // small test values
    fn bloom_size_reproduces_auras_table_ii() {
        // Aura Table II, h = 5: 0.35 KiB at d = 100 and 3.54 KiB at d = 1000.
        let kib = |d| bloom_bits(d) as f64 / 8.0 / 1024.0;
        assert!((kib(100) - 0.35).abs() < 0.01, "{}", kib(100));
        assert!((kib(1000) - 3.54).abs() < 0.03, "{}", kib(1000));
    }

    #[test]
    fn punctured_key_agrees_off_the_punctures_and_refuses_on_them() {
        let root = [9u8; 32];
        let levels = 6;
        let set = [3u64, 4, 40];
        let p = PuncturedKey::build(&root, &set, levels);
        for i in 0..(1u64 << levels) {
            if set.contains(&i) {
                assert!(p.eval(i).is_none(), "leaf {i} must be punctured");
            } else {
                assert_eq!(p.eval(i), Some(ggm_leaf(&root, i, levels)), "leaf {i}");
            }
        }
    }

    fn payloads(client: &mut Client, server: &mut Server, w: &[u8]) -> Vec<Vec<u8>> {
        let mut r = rng();
        let Some(m) = client.search(w, &mut r) else {
            return Vec::new();
        };
        let mut undo = Undo::default();
        let mut v: Vec<Vec<u8>> = server
            .search(&m, &mut undo)
            .iter()
            .map(|c| c.payload.to_vec())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn add_delete_search_across_key_refreshes() {
        let mut r = rng();
        let mut c = Client::setup(&[1; 32], HashMap::new());
        let mut s = Server::default();
        update(&mut c, &mut s, Op::Add, b"w", b"a", b"a", &mut r);
        update(&mut c, &mut s, Op::Add, b"w", b"b", b"b", &mut r);
        update(&mut c, &mut s, Op::Del, b"w", b"a", b"", &mut r);
        assert_eq!(payloads(&mut c, &mut s, b"w"), vec![b"b".to_vec()]);

        // Added after the refresh, under the new key.
        update(&mut c, &mut s, Op::Add, b"w", b"c", b"c", &mut r);
        assert_eq!(
            payloads(&mut c, &mut s, b"w"),
            vec![b"b".to_vec(), b"c".to_vec()]
        );

        // ⭐ Deleted after it was cached: the case printed line 11 misses.
        update(&mut c, &mut s, Op::Del, b"w", b"b", b"", &mut r);
        assert_eq!(payloads(&mut c, &mut s, b"w"), vec![b"c".to_vec()]);
        assert_eq!(s.add_len(), 0, "a search removes what it fetched");
    }

    #[test]
    fn undo_restores_a_first_search_exactly() {
        let mut r = rng();
        let mut c = Client::setup(&[1; 32], HashMap::new());
        let mut s = Server::default();
        for i in 0..20u8 {
            update(&mut c, &mut s, Op::Add, b"w", &[i], &[i], &mut r);
        }
        let cp = c.checkpoint(b"w").unwrap_or_else(|| unreachable!());
        let m = c.search(b"w", &mut r).unwrap_or_else(|| unreachable!());
        let mut undo = Undo::default();
        assert_eq!(s.search(&m, &mut undo).len(), 20);
        assert_eq!(s.add_len(), 0);
        s.undo_first(undo);
        c.restore(b"w", cp);
        assert_eq!(s.add_len(), 20);
        assert_eq!(payloads(&mut c, &mut s, b"w").len(), 20);
    }

    #[test]
    fn an_unknown_keyword_returns_nothing() {
        let mut c = Client::setup(&[1; 32], HashMap::new());
        assert!(c.search(b"never", &mut rng()).is_none());
    }
}
