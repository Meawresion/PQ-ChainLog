//! The Doris follow-up: non-interactive encrypted conjunctive search with storage
//! suppression. Nguyen et al., ProvSec (LNCS, 2026).
//!
//! # Provenance
//!
//! Transcribed from Algorithms 1–4 and §5 of
//! `ref-papers/DORIS-followup_ProvSec2025.pdf`, read directly as
//! the baseline reading rule in `baselines/UPGRADES.md` requires. There is no released code. Deviations
//! are in `../UPGRADES.md`.
//!
//! # What this is
//!
//! **Structural counts for Exp. 3, and nothing else.** It builds the real filter,
//! so a count is observed rather than computed from a formula, and it reports
//! bytes. It never reports a wall-clock figure.
//!
//! ⛔ **The Doris carve-out does not extend to this (§1cs.5 item 6).** It is our
//! reimplementation and goes through the normal pipeline.
//!
//! # The scheme, as counted
//!
//! Static, like Doris. `TSet` holds one `e` per pair. `XSet` holds one tag per
//! (s-term, counter, other keyword of that document), so it grows with the square
//! of the keywords per document, and goes through XBPE into a filter `B` of
//! `b ≈ 1.23·|S| + 32` slots below `10⁷` tags and `1.125·|S|` from there on.

#![allow(clippy::doc_markdown)] // scheme names (XEBFF, XBPE, TSet) are prose here

use std::collections::BTreeMap;

use pqcl_primitives::xof;

/// `b`'s switch point: below this XEBFF is an XOR filter, from here a Binary Fuse
/// Filter (§4, "Parameter choices").
pub const BFF_THRESHOLD: usize = 10_000_000;
/// One filter slot: `k = λ` bits. XBPE XORs slots to recover a 32-byte `K`, and
/// Doris counts `len(ct) * 32`.
pub const SLOT_BYTES: usize = 32;
/// One occupied `TSet` entry, by Doris's `cal_size`: an 8-byte label `L`, the
/// `β` byte and the 32-byte `e`. The follow-up uses "the generic construction of
/// Doris" for its `TSet`.
pub const TSET_ENTRY_BYTES: usize = 8 + 1 + 32;
/// Filter hash functions, `κ` (§4: "the optimal number of hash functions is
/// three").
pub const KAPPA: usize = 3;
/// Reseeds before giving up. The paper reports over 80% success per attempt below
/// `10⁷` tags and 100% from there on, so this is never close.
pub const MAX_ATTEMPTS: u32 = 64;

/// Count-Min sketch (Algorithm 1).
#[derive(Debug, Clone)]
pub struct CountMin {
    alpha: usize,
    beta: usize,
    table: Vec<u32>,
}

impl CountMin {
    /// `CMS.Setup(α, β)`.
    #[must_use]
    pub fn setup(alpha: usize, beta: usize) -> Self {
        Self {
            alpha,
            beta,
            table: vec![0; alpha * beta],
        }
    }

    fn slot(&self, i: usize, x: &[u8]) -> usize {
        let mut input = Vec::with_capacity(x.len() + 1);
        input.push(u8::try_from(i).unwrap_or(u8::MAX));
        input.extend_from_slice(x);
        let mut b = [0u8; 8];
        b.copy_from_slice(&xof::shake256(&input, 8));
        i * self.beta + usize::try_from(u64::from_be_bytes(b) % self.beta as u64).unwrap_or(0)
    }

    /// `CMS.Add(x)`.
    pub fn add(&mut self, x: &[u8]) {
        for i in 0..self.alpha {
            let s = self.slot(i, x);
            self.table[s] += 1;
        }
    }

    /// `CMS.Query(x)`: never below the true count.
    #[must_use]
    pub fn query(&self, x: &[u8]) -> u32 {
        (0..self.alpha)
            .map(|i| self.table[self.slot(i, x)])
            .min()
            .unwrap_or(0)
    }

    /// Bytes the client keeps.
    #[must_use]
    pub const fn client_bytes(&self) -> usize {
        self.alpha * self.beta * 4
    }
}

/// `b` and `m` for a set of `n` tags (§4).
#[must_use]
pub fn filter_shape(n: usize) -> (usize, usize) {
    if n < BFF_THRESHOLD {
        ((n * 123).div_ceil(100) + 32, 3)
    } else {
        ((n * 1125).div_ceil(1000), 200)
    }
}

/// Whether a filter of `b` slots over `n` tags fits the peeling's 32-bit indices
/// (`count`, `acc` and the queue hold `u32` element and slot indices).
#[must_use]
pub fn shape_fits_index(n: usize, b: usize) -> bool {
    let max = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
    n <= max && b <= max
}

/// [`shape_fits_index`] at the shape [`Filter::construct`] gives `n` tags. A
/// harness sizes its tiers with this, from the same arithmetic the build uses.
#[must_use]
pub fn index_fits(n: usize) -> bool {
    let (b, _) = filter_shape(n);
    shape_fits_index(n, b)
}

fn mix(mut x: u64, seed: u64) -> u64 {
    // A strong 64-bit finaliser: the input bytes are already PRF output.
    x ^= seed;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

const fn reduce(x: u64, range: u64) -> u64 {
    ((x as u128 * range as u128) >> 64) as u64
}

/// The `κ` positions of an element.
///
/// ⚠️ §4's `H` is printed as `[t(s+1)b/m, (t+1)(s+1)b/m)`, which leaves the array
/// for any `s > 0`. At `m = 3` it is the XOR filter's three segments. At `m = 200`
/// this takes the Binary Fuse Filter it cites: a start segment `s`, then `κ`
/// consecutive ones, as the text beside it says. `UPGRADES.md` records it.
fn positions(x: &[u8; 32], seed: u64, b: usize, m: usize) -> [usize; KAPPA] {
    let seg = (b / m) as u64;
    let word = |i: usize| {
        let mut w = [0u8; 8];
        w.copy_from_slice(&x[i * 8..(i + 1) * 8]);
        u64::from_be_bytes(w)
    };
    let start = reduce(mix(word(3), seed), (m - KAPPA + 1) as u64);
    let mut out = [0usize; KAPPA];
    for (t, o) in out.iter_mut().enumerate() {
        let turn = u32::try_from(t).unwrap_or(0) + 1;
        let inner = reduce(mix(word(t), seed.rotate_left(turn)), seg);
        *o = usize::try_from((start + t as u64) * seg + inner).unwrap_or(0);
    }
    out
}

/// `XEBFF.map`: the peeling order, or `None` if this seed left a cycle.
fn map_set(s: &[[u8; 32]], seed: u64, b: usize, m: usize) -> Option<Vec<(u32, u32)>> {
    // ⛔ Past `u32::MAX` slots an index would not fit; refuse before allocating
    // rather than truncating (a slot index of 0 would corrupt the filter silently).
    if !shape_fits_index(s.len(), b) {
        return None;
    }
    let mut count = vec![0u32; b];
    // XOR of the indices of the elements still in a slot: the single survivor's
    // index when the count reaches one, without a list per slot.
    let mut acc = vec![0u32; b];
    for (i, x) in s.iter().enumerate() {
        let i = u32::try_from(i).ok()?;
        for p in positions(x, seed, b, m) {
            count[p] += 1;
            acc[p] ^= i;
        }
    }
    let mut queue: Vec<u32> = Vec::new();
    for (p, c) in count.iter().enumerate() {
        if *c == 1 {
            queue.push(u32::try_from(p).ok()?);
        }
    }
    let mut order = Vec::with_capacity(s.len());
    while let Some(p) = queue.pop() {
        let pu = p as usize;
        if count[pu] != 1 {
            continue;
        }
        let i = acc[pu];
        order.push((i, p));
        for q in positions(&s[i as usize], seed, b, m) {
            count[q] -= 1;
            acc[q] ^= i;
            if count[q] == 1 {
                queue.push(u32::try_from(q).ok()?);
            }
        }
    }
    (order.len() == s.len()).then_some(order)
}

/// A constructed filter: `B`, its hash seed, and how many seeds it took.
#[derive(Debug, Clone)]
pub struct Filter {
    /// `B`.
    pub slots: Vec<[u8; 32]>,
    /// `m`.
    pub segments: usize,
    seed: u64,
    /// `XEBFF.map`'s attempts until peeling finished.
    pub attempts: u32,
}

impl Filter {
    /// `XEBFF.construct`.
    ///
    /// Unused slots are filled from `fill_seed` rather than left zero: Alg. 2 lines
    /// 13–17 fill them at random, and a zero slot would show the server which
    /// slots are unused.
    #[must_use]
    #[allow(clippy::many_single_char_names)] // the paper's s, b, m, p, q
    pub fn construct(s: &[[u8; 32]], fill_seed: u64) -> Option<Self> {
        let (b, m) = filter_shape(s.len());
        Self::construct_shaped(s, fill_seed, b, m)
    }

    /// [Filter::construct] at a given shape, so a test can build the `10⁷`-tag
    /// shape over a set small enough for the local memory rule.
    #[allow(clippy::many_single_char_names)] // the paper's s, b, m, p, q
    fn construct_shaped(s: &[[u8; 32]], fill_seed: u64, b: usize, m: usize) -> Option<Self> {
        // A shape past the 32-bit indices is refused once, not retried 64 times.
        if !shape_fits_index(s.len(), b) {
            return None;
        }
        let mut attempts = 0;
        let (order, seed) = loop {
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                return None;
            }
            let seed = mix(u64::from(attempts), fill_seed);
            if let Some(o) = map_set(s, seed, b, m) {
                break (o, seed);
            }
        };

        // A slot is decided when its element's turn comes, last peeled first, and
        // the other two positions of that element are then already settled.
        let mut slots = vec![[0u8; 32]; b];
        let mut set = vec![false; b];
        for (i, p) in order.iter().rev() {
            let x = &s[*i as usize];
            let mut v = *x;
            for q in positions(x, seed, b, m) {
                if q == *p as usize {
                    continue;
                }
                if !set[q] {
                    slots[q] = fill(fill_seed, q);
                    set[q] = true;
                }
                for (a, c) in v.iter_mut().zip(slots[q].iter()) {
                    *a ^= *c;
                }
            }
            slots[*p as usize] = v;
            set[*p as usize] = true;
        }
        for (q, done) in set.iter().enumerate() {
            if !done {
                slots[q] = fill(fill_seed, q);
            }
        }
        Some(Self {
            slots,
            segments: m,
            seed,
            attempts,
        })
    }

    /// Membership: the XOR of `x`'s slots is `x`. What `XBPE.Dec` relies on.
    #[must_use]
    pub fn contains(&self, x: &[u8; 32]) -> bool {
        let mut v = [0u8; 32];
        for q in positions(x, self.seed, self.slots.len(), self.segments) {
            for (a, c) in v.iter_mut().zip(self.slots[q].iter()) {
                *a ^= *c;
            }
        }
        &v == x
    }

    /// Server bytes: `|B| · 32`, Doris's `len(ct) * 32`.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.slots.len() * SLOT_BYTES
    }

    /// The hash family `H` this filter was built under: part of XBPE's `msk`,
    /// which the client needs for `XBPE.KeyGen`'s location sets (M15, `search`).
    #[must_use]
    pub const fn hashes(&self) -> Hashes {
        Hashes {
            seed: self.seed,
            b: self.slots.len(),
            m: self.segments,
        }
    }
}

/// `H = {h₀, h₁, h₂}` of one filter, without its slots: what the client holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hashes {
    seed: u64,
    b: usize,
    m: usize,
}

impl Hashes {
    /// `{h₀(x), h₁(x), h₂(x)}`: the slots whose XOR is `x` when `x` is a member.
    #[must_use]
    pub fn positions(&self, x: &[u8; 32]) -> [usize; KAPPA] {
        positions(x, self.seed, self.b, self.m)
    }
}

pub mod search;

fn fill(seed: u64, q: usize) -> [u8; 32] {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_be_bytes());
    input[8..].copy_from_slice(&(q as u64).to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&xof::shake256(&input, 32));
    out
}

/// `y' = F(sk, F(K_I, w‖w'‖c))`, directly: the filter sees only the final PRF
/// output, and these counts do not depend on two PRFs rather than one.
fn tag(key: &[u8; 32], w: &str, other: &str, c: usize) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + w.len() + other.len() + 24);
    input.extend_from_slice(key);
    input.extend_from_slice(&(w.len() as u64).to_be_bytes());
    input.extend_from_slice(w.as_bytes());
    input.extend_from_slice(&(other.len() as u64).to_be_bytes());
    input.extend_from_slice(other.as_bytes());
    input.extend_from_slice(&(c as u64).to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&xof::shake256(&input, 32));
    out
}

/// `EDBSetup`'s `XSet` (Algorithm 3, lines 6–20).
///
/// ⚠️ Lines 13–16 as printed would pair `w` with every other keyword's every id.
/// The prose says "pairing each keyword with a counter in every document", and
/// Doris's own loop agrees (`Doris_XF.py`, `xtag = prf(kx, w + w_tmp + str(i))`
/// over `id`'s keywords), so `id` here is the id the outer loop holds.
#[must_use]
pub fn xset(inv: &[(String, Vec<u64>)], key: &[u8; 32]) -> Vec<[u8; 32]> {
    let mut words_of: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
    for (w, ids) in inv {
        for id in ids {
            words_of.entry(*id).or_default().push(w);
        }
    }
    let mut out = Vec::new();
    for (w, ids) in inv {
        for (c, id) in ids.iter().enumerate() {
            for other in words_of.get(id).into_iter().flatten() {
                if *other != w.as_str() {
                    out.push(tag(key, w, other, c));
                }
            }
        }
    }
    // A set, as Doris's is.
    out.sort_unstable();
    out.dedup();
    out
}

/// What Exp. 3 reports for this scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
    /// `|TSet|`, in entries: one per pair.
    pub tset_entries: usize,
    /// Doris's `cal_size(tset)`.
    pub tset_bytes: usize,
    /// `|S|`, the tags in `XSet`.
    pub xset_tags: usize,
    /// `b`.
    pub filter_slots: usize,
    /// `m`.
    pub segments: usize,
    /// Doris's `len(ct) * 32`.
    pub xset_bytes: usize,
    /// `XEBFF.map`'s attempts.
    pub attempts: u32,
}

/// Build the real filter over `inv` and count. `None` only if `MAX_ATTEMPTS` seeds
/// all fail, which the paper's success rates make unreachable.
#[must_use]
pub fn count(inv: &[(String, Vec<u64>)], key: &[u8; 32], fill_seed: u64) -> Option<Counts> {
    let tset_entries: usize = inv.iter().map(|(_, ids)| ids.len()).sum();
    let s = xset(inv, key);
    let f = Filter::construct(&s, fill_seed)?;
    // A filter that cannot find its own tags is not counted.
    if !s
        .iter()
        .step_by((s.len() / 1000).max(1))
        .all(|x| f.contains(x))
    {
        return None;
    }
    Some(Counts {
        tset_entries,
        tset_bytes: tset_entries * TSET_ENTRY_BYTES,
        xset_tags: s.len(),
        filter_slots: f.slots.len(),
        segments: f.segments,
        xset_bytes: f.stored_bytes(),
        attempts: f.attempts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elements(n: usize) -> Vec<[u8; 32]> {
        (0..n as u64)
            .map(|i| {
                let mut v = [0u8; 32];
                v.copy_from_slice(&xof::shake256(&i.to_be_bytes(), 32));
                v
            })
            .collect()
    }

    #[test]
    fn the_32_bit_index_boundary_is_exact_and_refused_past_it() {
        // `filter_shape` above 10^7 tags is ceil(1.125 n): the largest n whose b
        // still fits u32 is floor((2^32 - 1) * 1000 / 1125) = 3 817 748 706.
        let last = 3_817_748_706usize;
        assert_eq!(filter_shape(last).0, u32::MAX as usize);
        assert_eq!(filter_shape(last + 1).0, u32::MAX as usize + 1);
        assert!(index_fits(last));
        assert!(!index_fits(last + 1));
        // c15's largest planned build (~2.1e9 tags, ~2.4e9 slots) fits.
        assert!(index_fits(2_100_000_000));
        assert!(!shape_fits_index(u32::MAX as usize + 1, 4));
        // Refused before any allocation: a one-element set at an over-index shape.
        let one = elements(1);
        assert!(Filter::construct_shaped(&one, 7, u32::MAX as usize + 1, 3).is_none());
        assert!(map_set(&one, 7, u32::MAX as usize + 1, 3).is_none());
    }

    #[test]
    fn the_sketch_never_undercounts() {
        let mut c = CountMin::setup(5, 2719);
        for i in 0..200u32 {
            for _ in 0..=(i % 7) {
                c.add(&i.to_be_bytes());
            }
        }
        for i in 0..200u32 {
            assert!(c.query(&i.to_be_bytes()) > i % 7);
        }
        assert_eq!(c.client_bytes(), 5 * 2719 * 4);
    }

    #[test]
    fn the_xor_shape_holds_its_set_and_rejects_others() {
        let s = elements(20_000);
        let f = Filter::construct(&s, 1).unwrap_or_else(|| unreachable!("peels"));
        assert_eq!(f.segments, 3);
        assert_eq!(f.slots.len(), 20_000 * 123 / 100 + 32);
        assert!(s.iter().all(|x| f.contains(x)));
        let others = elements(21_000);
        assert!(others[20_000..].iter().all(|x| !f.contains(x)));
    }

    /// The shape switches at `10⁷`, and `b` is the paper's. The 1.125 filter itself
    /// is exercised on a smaller set through `positions`, since `10⁷` elements is
    /// over the local memory rule; the campaign runs the real one.
    #[test]
    fn the_shape_switches_at_the_threshold() {
        assert_eq!(filter_shape(9_999_999), (12_299_999 + 32, 3));
        assert_eq!(filter_shape(10_000_000), (11_250_000, 200));
    }

    /// ⭐ The shape campaign 14 uses above `10⁷` tags, built for real: `1.125·|S|`
    /// slots in 200 segments must peel, or `size` stops at the top tier.
    ///
    /// ⚠️ 1.125 sits at this coupling's threshold, so success depends on segment size.
    /// Probed 2026-11-03 (two seeds each): it stalls near half the set at `4·10⁵` tags,
    /// is marginal at `10⁶`, and peels in full at 2, 5, 10 and `16·10⁶`. The scheme only
    /// uses it from `10⁷`, where the paper reports 100%. `2·10⁶` and `4·10⁶` are the
    /// smallest sizes that say something and stay under the local memory rule.
    #[test]
    fn the_bff_shape_peels_and_holds_its_set() {
        for n in [2_000_000usize, 4_000_000] {
            let s = elements(n);
            let b = (n * 1125).div_ceil(1000);
            let f = Filter::construct_shaped(&s, 7, b, 200)
                .unwrap_or_else(|| unreachable!("1.125 n in 200 segments did not peel at n = {n}"));
            assert!(f.attempts <= 4, "n = {n}: {} attempts", f.attempts);
            assert!(s.iter().step_by(97).all(|x| f.contains(x)));
        }
    }

    #[test]
    fn bff_positions_stay_in_consecutive_segments_of_the_array() {
        let (b, m) = (1_125_000, 200);
        let seg = b / m;
        for x in elements(5_000) {
            let p = positions(&x, 42, b, m);
            assert!(p.iter().all(|q| *q < b));
            assert_eq!(p[1] / seg, p[0] / seg + 1);
            assert_eq!(p[2] / seg, p[0] / seg + 2);
        }
    }

    #[test]
    fn counts_follow_the_doris_shape() {
        let inv = vec![
            ("a".to_owned(), vec![1, 2, 3]),
            ("b".to_owned(), vec![1, 2]),
            ("c".to_owned(), vec![1]),
        ];
        // Doc 1 holds a,b,c (6 ordered pairs), doc 2 holds a,b (2), doc 3 only a.
        let c = count(&inv, &[3; 32], 9).unwrap_or_else(|| unreachable!());
        assert_eq!(c.tset_entries, 6);
        assert_eq!(c.tset_bytes, 6 * 41);
        assert_eq!(c.xset_tags, 8);
        assert_eq!(c.filter_slots, 10 + 32, "b = 1.23 * 8 + 32");
    }

    #[test]
    fn counts_do_not_depend_on_the_key_or_seed() {
        let inv: Vec<(String, Vec<u64>)> = (0..30)
            .map(|i| {
                (
                    format!("w{i}"),
                    (0..40u64).filter(|d| d % (i + 2) == 0).collect(),
                )
            })
            .collect();
        let a = count(&inv, &[1; 32], 1).unwrap_or_else(|| unreachable!());
        let b = count(&inv, &[2; 32], 2).unwrap_or_else(|| unreachable!());
        assert_eq!(
            (a.tset_bytes, a.xset_tags, a.xset_bytes),
            (b.tset_bytes, b.xset_tags, b.xset_bytes)
        );
    }
}
