//! MDRSSE — fast and private multi-dimensional range search over encrypted data,
//! **in one dimension**.
//!
//! Shabnam Kasra Kermanshahi, Ron Steinfeld, Xun Yi, Joseph K. Liu et al.,
//! Information Sciences 652 (2024), art. 119773.
//!
//! # Provenance
//!
//! Transcribed from Algorithms 1–3 and §§2.1, 4, 5 of
//! `ref-papers/Fastandprivatemulti-dimensionalrangesearchoverencrypted.pdf`,
//! read directly as the baseline reading rule in `baselines/UPGRADES.md` requires. Reading choices are
//! in `../UPGRADES.md`.
//!
//! # The scheme, in one dimension
//!
//! A KD-tree whose data sit only at the leaves (their §2.1): split the sorted
//! points at the median until at most `γ` remain (Alg. 1). With one axis the
//! leaves are consecutive value buckets. Each leaf `n_i` gets `K_i = F(K_s, n_i)`
//! and `Tag_i = F(K_t, n_i)`, and its records are encrypted under `K_i` and filed
//! under `Tag_i` (Alg. 2), padded to `γ` with encryptions of zeros (§5: "padding
//! is enabled in all of the experiments"). The client keeps the tree without its
//! leaves (`kdt′`), finds the leaves covering `[a, b]`, and sends their tags; the
//! server returns their ciphertexts; the client decrypts (Alg. 3). One round.
//!
//! ⚠️ Alg. 3 adds **every** record of a returned leaf to `RS`. The client here
//! drops the padding and filters each leaf to `[a, b]`, which a range answer
//! needs and the oracle checks; the server's work is unchanged by it.
//!
//! ⛔ **Static.** Their §4.3 only sketches updates, so this cannot enter an
//! ingest experiment. M15's trial arm for Exp. 4's range rows, nothing else.

use std::collections::{BTreeSet, HashMap};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use baseline_odxt::prf::{PrfKey, prf_bytes};

/// The authors' default leaf capacity (§5.1: "500 records per node"), fixed
/// before measuring.
pub const GAMMA: usize = 500;

/// `flag ‖ value ‖ id`. `flag = 0` is padding: an encryption of zeros, which
/// must not read as the record (value 0, id 0).
const PLAIN_BYTES: usize = 1 + 8 + 8;

/// One point: an attribute value and the document it belongs to.
pub type Point = (u64, u64);

/// A leaf of `kdt′` as the client keeps it: its node id and value interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Leaf {
    id: u64,
    lo: u64,
    hi: u64,
}

/// The client: `K = (K_s, K_t)` and `kdt′`.
#[derive(Debug, Clone)]
pub struct Client {
    k_s: PrfKey,
    k_t: PrfKey,
    leaves: Vec<Leaf>,
}

/// The server: `EDS`, ciphertext lists under leaf tags.
#[derive(Debug, Clone, Default)]
pub struct Server {
    eds: HashMap<[u8; 32], Vec<Vec<u8>>>,
}

/// `ST`: one tag per covering leaf, with the node id the client keeps to itself.
#[derive(Debug, Clone)]
pub struct SearchToken {
    tags: Vec<[u8; 32]>,
    nodes: Vec<u64>,
    lo: u64,
    hi: u64,
}

impl SearchToken {
    /// Leaves in the cover.
    #[must_use]
    pub fn leaves(&self) -> usize {
        self.tags.len()
    }
}

/// Alg. 1, `f_t`, in one dimension: data at the leaves, split at the median.
///
/// ⚠️ Alg. 1 puts points "before" and "after" the median and stores the median
/// in the inner node; data live only at the leaves (§2.1), so the median point
/// goes right. Ties are split by sort position, so a value may sit in two
/// adjacent leaves, and both then cover it.
fn kd_tree(points: &mut [Point], gamma: usize, out: &mut Vec<Vec<Point>>) {
    if points.len() <= gamma {
        out.push(points.to_vec());
        return;
    }
    points.sort_unstable();
    let mid = points.len() / 2;
    let (left, right) = points.split_at_mut(mid);
    kd_tree(left, gamma, out);
    kd_tree(right, gamma, out);
}

fn node_bytes(id: u64) -> [u8; 8] {
    id.to_be_bytes()
}

fn nonce(j: usize) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&(j as u64).to_be_bytes());
    n
}

fn cipher(k: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(k))
}

/// `Setup(λ, Δ)` (Alg. 2): `kdt`, `I_t`, `EDS`. `pad` fills every leaf to `γ`.
///
/// # Errors
///
/// An AES-GCM encryption failure, which a 17-byte record cannot cause.
pub fn setup(
    points: &[Point],
    master: &[u8; 32],
    gamma: usize,
    pad: bool,
) -> Result<(Client, Server), aes_gcm::Error> {
    let mut ks = *master;
    ks[0] ^= 0x53;
    let mut kt = *master;
    kt[0] ^= 0x54;
    let (k_s, k_t) = (PrfKey(ks), PrfKey(kt));
    let mut pts = points.to_vec();
    let mut buckets = Vec::new();
    kd_tree(&mut pts, gamma.max(1), &mut buckets);

    let mut leaves = Vec::with_capacity(buckets.len());
    let mut server = Server::default();
    for (i, bucket) in buckets.iter().enumerate() {
        let id = i as u64 + 1;
        let lo = bucket.iter().map(|p| p.0).min().unwrap_or(0);
        let hi = bucket.iter().map(|p| p.0).max().unwrap_or(0);
        leaves.push(Leaf { id, lo, hi });
        // Lines 5–6.
        let k_i = prf_bytes(&k_s, &node_bytes(id));
        let tag = prf_bytes(&k_t, &node_bytes(id));
        let cipher = cipher(&k_i);
        // Lines 7–11, then the padding of §5 to `γ`.
        let total = if pad {
            gamma.max(bucket.len())
        } else {
            bucket.len()
        };
        let mut list = Vec::with_capacity(total);
        for j in 0..total {
            let mut plain = [0u8; PLAIN_BYTES];
            if let Some((v, d)) = bucket.get(j) {
                plain[0] = 1;
                plain[1..9].copy_from_slice(&v.to_be_bytes());
                plain[9..].copy_from_slice(&d.to_be_bytes());
            }
            list.push(cipher.encrypt(Nonce::from_slice(&nonce(j)), plain.as_slice())?);
        }
        server.eds.insert(tag, list);
    }
    Ok((Client { k_s, k_t, leaves }, server))
}

impl Client {
    /// `ClientSearch` lines 1–8: the leaves of `kdt′` covering `[lo, hi]`, as tags.
    #[must_use]
    pub fn token(&self, lo: u64, hi: u64) -> SearchToken {
        let nodes: Vec<u64> = self
            .leaves
            .iter()
            .filter(|l| l.lo <= hi && lo <= l.hi)
            .map(|l| l.id)
            .collect();
        SearchToken {
            tags: nodes
                .iter()
                .map(|n| prf_bytes(&self.k_t, &node_bytes(*n)))
                .collect(),
            nodes,
            lo,
            hi,
        }
    }

    /// `ClientSearch` lines 10–15, with the padding dropped and each leaf
    /// filtered to the range; returns the documents.
    #[must_use]
    pub fn decrypt(&self, token: &SearchToken, er: &[&[Vec<u8>]]) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        for (node, list) in token.nodes.iter().zip(er) {
            let k_i = prf_bytes(&self.k_s, &node_bytes(*node));
            let cipher = cipher(&k_i);
            for (j, ct) in list.iter().enumerate() {
                let Ok(plain) = cipher.decrypt(Nonce::from_slice(&nonce(j)), ct.as_slice()) else {
                    continue;
                };
                if plain.len() != PLAIN_BYTES || plain[0] != 1 {
                    continue;
                }
                let mut v = [0u8; 8];
                v.copy_from_slice(&plain[1..9]);
                let v = u64::from_be_bytes(v);
                if (token.lo..=token.hi).contains(&v) {
                    let mut d = [0u8; 8];
                    d.copy_from_slice(&plain[9..]);
                    out.insert(u64::from_be_bytes(d));
                }
            }
        }
        out
    }

    /// The whole search.
    #[must_use]
    pub fn search(&self, server: &Server, lo: u64, hi: u64) -> BTreeSet<u64> {
        let token = self.token(lo, hi);
        let er = server.search(&token);
        self.decrypt(&token, &er)
    }

    /// Leaves in `kdt′`.
    #[must_use]
    pub fn leaves(&self) -> usize {
        self.leaves.len()
    }
}

impl Server {
    /// `ServerSearch` (Alg. 3): the ciphertext list under each tag.
    #[must_use]
    pub fn search<'a>(&'a self, token: &SearchToken) -> Vec<&'a [Vec<u8>]> {
        token
            .tags
            .iter()
            .map(|t| self.eds.get(t).map_or(&[][..], Vec::as_slice))
            .collect()
    }

    /// Ciphertexts stored, padding included, and their bytes.
    #[must_use]
    pub fn stored(&self) -> (usize, usize) {
        let n = self.eds.values().map(Vec::len).sum();
        let b = self
            .eds
            .values()
            .flat_map(|l| l.iter().map(Vec::len))
            .sum::<usize>()
            + self.eds.len() * 32;
        (n, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oracle(points: &[Point], lo: u64, hi: u64) -> BTreeSet<u64> {
        points
            .iter()
            .filter(|(v, _)| (lo..=hi).contains(v))
            .map(|(_, d)| *d)
            .collect()
    }

    #[test]
    fn every_range_matches_the_oracle_padded_and_not() {
        // Several values per document, and repeated values across a split.
        let points: Vec<Point> = (0..300u64).map(|i| ((i * 7) % 113, i % 37)).collect();
        for pad in [false, true] {
            let (c, s) = setup(&points, &[3; 32], 16, pad).expect("encrypts");
            assert!(c.leaves() > 10);
            for lo in (0..113).step_by(5) {
                for hi in (lo..113).step_by(9) {
                    assert_eq!(
                        c.search(&s, lo, hi),
                        oracle(&points, lo, hi),
                        "[{lo},{hi}] pad {pad}"
                    );
                }
            }
        }
    }

    #[test]
    fn padding_fills_every_leaf_to_gamma_and_reads_as_nothing() {
        let points: Vec<Point> = (0..100u64).map(|i| (i, i)).collect();
        let (c, s) = setup(&points, &[3; 32], 30, true).expect("encrypts");
        let (n, _) = s.stored();
        assert_eq!(n, c.leaves() * 30);
        assert_eq!(c.search(&s, 0, 0), BTreeSet::from([0]));
    }

    #[test]
    fn the_cover_is_the_leaves_the_range_touches() {
        let points: Vec<Point> = (0..1000u64).map(|i| (i, i)).collect();
        let (c, _) = setup(&points, &[3; 32], GAMMA, true).expect("encrypts");
        assert_eq!(c.leaves(), 2);
        assert_eq!(c.token(10, 20).leaves(), 1);
        assert_eq!(c.token(490, 510).leaves(), 2);
    }
}
