//! PQ-ABL's integrity layer: one independent Merkle tree per epoch.
//!
//! Fugkeaw et al., *"Optimized Post-Quantum Attribute-Based Logging for
//! Real-Time and Tamper-Evident Cloud Forensics"*, IEEE Transactions on Cloud
//! Computing 14(2), 2026 (SAC `b23`).
//!
//! # Provenance of this code
//!
//! Transcribed from Phase 4 (p. 7), Phase 5 (pp. 7–8) and eq. (1) (p. 14) of
//! `ref-papers/Optimized_Post-Quantum_Attribute-Based_Logging_*.pdf`,
//! read directly as the baseline reading rule in `baselines/UPGRADES.md` requires. Only the integrity
//! half is here: the lattice CP-ABE that encrypts each log is not on the path
//! Exp. 2 measures, which starts from stored ciphertexts.
//!
//! # The scheme, as specified
//!
//! ```text
//! Phase 4, Step 1   h_n = H(CT_n)                  for every ciphertext of epoch e
//! Phase 4, Step 2   R_e = MerkleRoot(h_1, …, h_N)  bottom-up, one tree per epoch
//! Phase 4, Step 4   Commit(R_e, CID_epoch, CID_proof, t_e)   on chain
//! Phase 5, Step 3   standalone membership of one record: an O(log N) path to R_e
//!                   full-epoch verification: recompute every h_n, rebuild the
//!                   tree, accept iff R*_e = R_e        (eq. (1): N·C_hash + C_recon)
//! ```
//!
//! "Each epoch uses an independently constructed Merkle tree, isolating
//! verification state across epochs" (p. 7): nothing links epoch `e` to `e+1`
//! except the chain the anchors sit on.
//!
//! # Deviations, all recorded in `../UPGRADES.md`
//!
//! * SHAKE256 for SHA3-256, as in every Exp. 2 arm.
//! * Leaf and node hashes carry one prefix byte each (`0x00`, `0x01`, the
//!   RFC 6962 convention). The paper writes `MerkleRoot` without saying; the
//!   prefix costs one byte per hash and closes the leaf/node confusion.
//! * An unpaired last node is promoted, never duplicated (CVE-2012-2459). The
//!   paper's `T(N) = N/2 + N/4 + … + 1` is silent on odd levels.

use tiny_keccak::{Hasher, Shake, Xof};

/// A 32-byte digest.
pub type Digest = [u8; 32];

const LEAF: u8 = 0x00;
const NODE: u8 = 0x01;

fn finish(mut h: Shake) -> Digest {
    let mut out = [0u8; 32];
    h.squeeze(&mut out);
    out
}

/// `h_n = H(CT_n)`: one stored ciphertext object's leaf.
#[must_use]
pub fn leaf(ct: &[u8]) -> Digest {
    let mut h = Shake::v256();
    h.update(&[LEAF]);
    h.update(ct);
    finish(h)
}

/// An internal node over two children.
#[must_use]
pub fn node(left: &Digest, right: &Digest) -> Digest {
    let mut h = Shake::v256();
    h.update(&[NODE]);
    h.update(left);
    h.update(right);
    finish(h)
}

/// One level up: pairs hashed, an unpaired last node promoted.
fn parent_level(level: &[Digest]) -> Vec<Digest> {
    level
        .chunks(2)
        .map(|p| match p {
            [l, r] => node(l, r),
            [x] => *x,
            _ => unreachable!("chunks(2) yields one or two"),
        })
        .collect()
}

/// One epoch's tree, every level kept so paths cost no hashing.
#[derive(Debug, Clone)]
pub struct EpochTree {
    /// `levels[0]` holds the leaves; the last level holds the root alone.
    levels: Vec<Vec<Digest>>,
}

impl EpochTree {
    /// Phase 4 Step 2 over leaf digests. `None` for an empty epoch: an epoch
    /// with no logs has no root to anchor.
    #[must_use]
    pub fn build(leaves: Vec<Digest>) -> Option<Self> {
        if leaves.is_empty() {
            return None;
        }
        let mut levels = vec![leaves];
        while levels.last().is_some_and(|l| l.len() > 1) {
            let up = parent_level(levels.last()?);
            levels.push(up);
        }
        Some(Self { levels })
    }

    /// `R_e`.
    #[must_use]
    pub fn root(&self) -> Digest {
        self.levels[self.levels.len() - 1][0]
    }

    /// Number of logs in the epoch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    /// Never true: [`EpochTree::build`] refuses an empty epoch.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    /// Phase 5 Step 3's standalone membership path for log `index`.
    #[must_use]
    pub fn prove(&self, index: usize) -> Option<Path> {
        if index >= self.len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut i = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sib = if i.is_multiple_of(2) {
                level.get(i + 1)
            } else {
                level.get(i - 1)
            };
            if let Some(s) = sib {
                siblings.push(*s);
            }
            i /= 2;
        }
        Some(Path {
            index: index as u64,
            count: self.len() as u64,
            siblings,
        })
    }
}

/// A membership path: the leaf's position, the epoch's size, and the siblings
/// leaf-ward first. Position and size fix which side each sibling is on and
/// where a node was promoted, so no direction bits travel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    /// The log's position in the epoch.
    pub index: u64,
    /// Logs in the epoch.
    pub count: u64,
    /// Siblings, leaf-ward first.
    pub siblings: Vec<Digest>,
}

impl Path {
    /// Bytes on the wire: two 8-byte integers and the siblings.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        16 + 32 * self.siblings.len()
    }
}

/// Phase 5 Step 3: is `leaf` at `path.index` of the epoch whose root is `root`?
#[must_use]
pub fn verify(root: &Digest, leaf: &Digest, path: &Path) -> bool {
    if path.index >= path.count {
        return false;
    }
    let (mut i, mut n) = (path.index, path.count);
    let mut acc = *leaf;
    let mut sib = path.siblings.iter();
    while n > 1 {
        let promoted = i.is_multiple_of(2) && i + 1 == n;
        if !promoted {
            let Some(s) = sib.next() else { return false };
            acc = if i.is_multiple_of(2) {
                node(&acc, s)
            } else {
                node(s, &acc)
            };
        }
        i /= 2;
        n = n.div_ceil(2);
    }
    sib.next().is_none() && acc == *root
}

/// Phase 5 Step 3, full-epoch verification on one core: recompute every
/// `h*_n`, rebuild the tree, accept iff `R*_e = R_e` (eq. (1)).
#[must_use]
pub fn verify_epoch<T: AsRef<[u8]>>(cts: &[T], root: &Digest) -> bool {
    let leaves: Vec<Digest> = cts.iter().map(|c| leaf(c.as_ref())).collect();
    EpochTree::build(leaves).is_some_and(|t| t.root() == *root)
}

/// Below this many nodes a level is hashed on one thread: spawning costs more
/// than it saves.
const PAR_MIN: usize = 4096;

/// `f` over `items` in `threads` contiguous shards, results in order.
fn sharded<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    f: impl Fn(&[T]) -> Vec<R> + Sync,
) -> Vec<R> {
    let shard = items.len().div_ceil(threads.max(1)).max(1);
    let f = &f;
    std::thread::scope(|s| {
        let hs: Vec<_> = items.chunks(shard).map(|p| s.spawn(move || f(p))).collect();
        hs.into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    })
}

/// Full-epoch verification across `threads` cores: the leaf digests shard,
/// and so does every level wide enough to pay for it. The paper's eq. (1) is
/// the same work; this is the most parallelism the structure allows, so the
/// baseline is not measured slower than it can run.
///
/// A level is split at even offsets, so no pair straddles two shards and the
/// tree is exactly the one-core tree.
#[must_use]
pub fn verify_epoch_parallel<T: AsRef<[u8]> + Sync>(
    cts: &[T],
    root: &Digest,
    threads: usize,
) -> bool {
    leaves_parallel(cts, threads)
        .and_then(|l| root_parallel(l, threads))
        .is_some_and(|r| r == *root)
}

/// Every `h_n = H(CT_n)` across `threads` cores, in order. `None` if a shard
/// panicked.
#[must_use]
pub fn leaves_parallel<T: AsRef<[u8]> + Sync>(cts: &[T], threads: usize) -> Option<Vec<Digest>> {
    let out: Vec<Digest> = sharded(cts, threads, |p| {
        p.iter().map(|c| leaf(c.as_ref())).collect()
    });
    (out.len() == cts.len()).then_some(out)
}

/// `R_e = MerkleRoot(H_e)` across `threads` cores: every level wide enough to
/// pay for it shards at even offsets, so the root is the one-core root. `None`
/// for no leaves or a panicked shard.
#[must_use]
pub fn root_parallel(leaves: Vec<Digest>, threads: usize) -> Option<Digest> {
    if leaves.is_empty() {
        return None;
    }
    let mut level = leaves;
    while level.len() > 1 {
        let next = if level.len() >= PAR_MIN && threads > 1 {
            let pairs: Vec<&[Digest]> = level.chunks(2).collect();
            sharded(&pairs, threads, |p| {
                p.iter().map(|c| parent_level(c)[0]).collect()
            })
        } else {
            parent_level(&level)
        };
        if next.len() != level.len().div_ceil(2) {
            return None;
        }
        level = next;
    }
    Some(level[0])
}

// ------------------------------------------------- Phase 4 Step 3: packaging

/// Phase 4 Step 3's proof set `P_e`, serialized: every leaf digest in order,
/// 32 bytes each. `CID_Proof` addresses these bytes.
///
/// The paper writes `P_e = {(h_{2i−1}, h_{2i}) | i = 1…⌊N/2⌋}`, which for an
/// odd `N` drops the last leaf, and then has the auditor rebuild the tree from
/// `P_e`, which needs it. We keep the unpaired leaf (`../UPGRADES.md`).
#[must_use]
pub fn proof_set(leaves: &[Digest]) -> Vec<u8> {
    leaves.concat()
}

/// The leaf digests a serialized [`proof_set`] carries; `None` if its length
/// is not a whole number of digests.
#[must_use]
pub fn proof_set_leaves(bytes: &[u8]) -> Option<Vec<Digest>> {
    if !bytes.len().is_multiple_of(32) {
        return None;
    }
    bytes
        .chunks(32)
        .map(|c| c.try_into().ok())
        .collect::<Option<Vec<Digest>>>()
}

/// The smallest gzip member: pigz's default block size, 128 KiB.
const GZ_MEMBER_MIN: usize = 128 << 10;

/// The largest gzip member.
const GZ_MEMBER_MAX: usize = 8 << 20;

/// One ustar header for an object of `size` bytes named `name`.
fn ustar_header(name: &str, size: usize) -> [u8; 512] {
    let mut h = [0u8; 512];
    let field = |h: &mut [u8; 512], at: usize, bytes: &[u8]| {
        h[at..at + bytes.len()].copy_from_slice(bytes);
    };
    field(&mut h, 0, name.as_bytes());
    field(&mut h, 100, b"0000644\0");
    field(&mut h, 108, b"0000000\0");
    field(&mut h, 116, b"0000000\0");
    field(&mut h, 124, format!("{size:011o}\0").as_bytes());
    field(&mut h, 136, b"00000000000\0");
    field(&mut h, 156, b"0");
    field(&mut h, 257, b"ustar\0");
    field(&mut h, 263, b"00");
    // The checksum is taken with its own field as eight spaces.
    field(&mut h, 148, b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    field(&mut h, 148, format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Phase 4 Step 3: `Archive_e = tar.gz(CT_1, …, CT_N)`.
///
/// A ustar stream, one entry per ciphertext in order, then gzip at the
/// default level. The gzip runs in members on `threads` cores, concatenated:
/// a valid gzip file (RFC 1952 §2.2) that any `gunzip` reads whole. A member
/// is the stream split evenly across the cores, between pigz's 128 KiB block
/// and 8 MiB, so one epoch's archive uses every core: the most parallelism the
/// format allows. The paper names neither a level nor a threading model.
/// `None` if a compression thread failed.
#[must_use]
pub fn archive<T: AsRef<[u8]>>(cts: &[T], threads: usize) -> Option<Vec<u8>> {
    use std::io::Write as _;
    let bytes = cts.iter().map(|c| 1024 + c.as_ref().len()).sum::<usize>();
    let mut tar = Vec::with_capacity(bytes + 1024);
    for (i, c) in cts.iter().enumerate() {
        let c = c.as_ref();
        tar.extend_from_slice(&ustar_header(&format!("ct/{i:09}"), c.len()));
        tar.extend_from_slice(c);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let member = tar
        .len()
        .div_ceil(threads.max(1))
        .clamp(GZ_MEMBER_MIN, GZ_MEMBER_MAX);
    let members: Vec<&[u8]> = tar.chunks(member).collect();
    let gz = |part: &[&[u8]]| -> Vec<Option<Vec<u8>>> {
        part.iter()
            .map(|m| {
                let mut e =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(m).ok()?;
                e.finish().ok()
            })
            .collect()
    };
    let out = sharded(&members, threads, gz);
    if out.len() != members.len() {
        return None;
    }
    Some(out.into_iter().collect::<Option<Vec<_>>>()?.concat())
}

/// Phase 5 Step 2: `extract(Archive_e)`, the ciphertexts in order. `None` if
/// the gzip or the tar stream is malformed.
#[must_use]
pub fn extract(archive: &[u8]) -> Option<Vec<Vec<u8>>> {
    use std::io::Read as _;
    let mut tar = Vec::new();
    flate2::read::MultiGzDecoder::new(archive)
        .read_to_end(&mut tar)
        .ok()?;
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let h = tar.get(at..at + 512)?;
        if h.iter().all(|b| *b == 0) {
            return Some(out);
        }
        if &h[257..263] != b"ustar\0" {
            return None;
        }
        let octal = |f: &[u8]| -> Option<usize> {
            let s = std::str::from_utf8(f).ok()?;
            usize::from_str_radix(s.trim_matches(|c: char| c == '\0' || c == ' '), 8).ok()
        };
        let mut blank = [0u8; 512];
        blank.copy_from_slice(h);
        blank[148..156].copy_from_slice(b"        ");
        let sum: usize = blank.iter().map(|b| usize::from(*b)).sum();
        if octal(&h[148..156])? != sum {
            return None;
        }
        let size = octal(&h[124..136])?;
        at += 512;
        out.push(tar.get(at..at + size)?.to_vec());
        at += size.next_multiple_of(512);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_extracts_to_its_ciphertexts_in_order() {
        let objs: Vec<Vec<u8>> = (0..300u32)
            .map(|i| {
                (0..(i * 37 % 5000))
                    .map(|j| (i ^ j).to_le_bytes()[0])
                    .collect()
            })
            .collect();
        for threads in [1, 4] {
            assert_eq!(extract(&archive(&objs, threads).unwrap()).unwrap(), objs);
        }
    }

    #[test]
    fn a_multi_member_archive_is_one_stream() {
        // Over three gzip members: the decoder must read past the first.
        let objs: Vec<Vec<u8>> = (0..3).map(|i| vec![i; GZ_MEMBER_MAX]).collect();
        let a = archive(&objs, 3).unwrap();
        assert_eq!(extract(&a).unwrap(), objs);
        // A small epoch on many cores splits at the 128 KiB floor, and still
        // extracts whole.
        let small: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i; 20_000]).collect();
        let a = archive(&small, 32).unwrap();
        assert_eq!(extract(&a).unwrap(), small);
    }

    #[test]
    fn the_parallel_root_is_the_one_core_root() {
        for n in [1usize, 2, 3, 4_095, 4_096, 9_001] {
            let objs = cts(n);
            let one = EpochTree::build(objs.iter().map(|c| leaf(c)).collect()).unwrap();
            for threads in [1, 3, 8] {
                let l = leaves_parallel(&objs, threads).unwrap();
                assert_eq!(
                    root_parallel(l, threads),
                    Some(one.root()),
                    "n = {n}, threads = {threads}"
                );
            }
        }
        assert_eq!(root_parallel(Vec::new(), 4), None);
    }

    #[test]
    fn a_damaged_archive_does_not_extract_as_itself() {
        let objs: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i; 700]).collect();
        let mut a = archive(&objs, 1).unwrap();
        let mid = a.len() / 2;
        a[mid] ^= 0x40;
        assert_ne!(extract(&a), Some(objs));
    }

    #[test]
    fn a_proof_set_round_trips_including_an_unpaired_leaf() {
        let leaves: Vec<Digest> = (0..7u8).map(|i| leaf(&[i])).collect();
        let p = proof_set(&leaves);
        assert_eq!(proof_set_leaves(&p).unwrap(), leaves);
        assert!(proof_set_leaves(&p[1..]).is_none());
    }

    fn cts(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| format!("ciphertext object {i}").into_bytes())
            .collect()
    }

    fn tree(c: &[Vec<u8>]) -> EpochTree {
        EpochTree::build(c.iter().map(|x| leaf(x)).collect()).expect("non-empty")
    }

    #[test]
    fn every_path_verifies_at_every_size() {
        for n in 1..=33 {
            let c = cts(n);
            let t = tree(&c);
            for (i, x) in c.iter().enumerate() {
                let p = t.prove(i).expect("in range");
                assert!(verify(&t.root(), &leaf(x), &p), "n={n} i={i}");
                // Another log at the same position fails.
                assert!(!verify(&t.root(), &leaf(b"forged"), &p), "n={n} i={i}");
                // The same leaf claimed at a neighbouring position fails.
                if n > 1 {
                    let mut q = p.clone();
                    q.index = (q.index + 1) % q.count;
                    assert!(!verify(&t.root(), &leaf(x), &q), "n={n} i={i}");
                }
            }
        }
    }

    #[test]
    fn promote_never_duplicate() {
        // With duplication, [a,b,c] and [a,b,c,c] share a root (CVE-2012-2459).
        let a = cts(3);
        let mut b = a.clone();
        b.push(a[2].clone());
        assert_ne!(tree(&a).root(), tree(&b).root());
        // Three leaves: the root is N(N(a,b), c), c promoted.
        let l: Vec<Digest> = a.iter().map(|x| leaf(x)).collect();
        assert_eq!(tree(&a).root(), node(&node(&l[0], &l[1]), &l[2]));
    }

    #[test]
    fn epoch_validation_detects_any_change() {
        for n in [1, 2, 7, 64, 5000] {
            let c = cts(n);
            let root = tree(&c).root();
            assert!(verify_epoch(&c, &root));
            for threads in [1, 3, 8] {
                assert!(
                    verify_epoch_parallel(&c, &root, threads),
                    "n={n} t={threads}"
                );
            }
            let mut bad = c.clone();
            bad[n / 2].push(0);
            assert!(!verify_epoch(&bad, &root));
            assert!(!verify_epoch_parallel(&bad, &root, 4));
            let mut short = c.clone();
            short.pop();
            assert!(!verify_epoch(&short, &root) || n == 1 && short.is_empty());
        }
    }

    #[test]
    fn leaf_and_node_are_separated() {
        let l = [leaf(b"x"), leaf(b"y")];
        let mut joined = Vec::new();
        joined.extend_from_slice(&l[0]);
        joined.extend_from_slice(&l[1]);
        assert_ne!(node(&l[0], &l[1]), leaf(&joined));
    }
}
