//! Chunked digests over an artefact, at 1 MiB.
//!
//! `PQ-ChainLog-DESIGN.md` §14 fixes the chunk size and explains why chunking
//! rather than one digest over the whole file:
//!
//! * **Corruption is localised.** A partially damaged image stays admissible
//!   for its intact regions instead of failing wholesale — which matters
//!   because a disk image that fails one hash is otherwise worthless in court
//!   even when 99% of it is fine.
//! * **The sweeper is keyless.** `d_ev` binds *ciphertext*, so checking a chunk
//!   is an ordinary hash comparison. That is what lets the cold-storage sweep
//!   be delegated to a low-privilege service.
//!
//! It is also what makes ingest possible at all here: the memory dump in
//! `datasets/artefacts` is ~1.8 GB expanded, and hashing it as one buffer would
//! mean holding it in RAM.
//!
//! ⚠️ **The root is a Merkle root over chunk digests, not a hash of the
//! concatenation.** A flat hash would give the same localisation benefit for
//! *detection* but none for *proof*: an auditor could not be shown that chunk
//! 412 is intact without being handed every other chunk.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

/// Design §14's chunk size.
pub const CHUNK_BYTES: usize = 1024 * 1024;

/// The chunked digest of one artefact.
///
/// ⭐ **Its fields are private, so its root is always the root of its own
/// leaves** (M13 A12, `audit/06d` L2-a). Every constructor here computes the
/// root from the leaf list. With public fields, a caller could pair the
/// anchored root with a leaf list rewritten alongside a damaged chunk, and
/// `check_chunk` — which compares one chunk against one stored leaf — would
/// pass the damage. The other half of the binding, that this root is the
/// *anchored* one, is checked where an object is opened for audit
/// ([`crate::audit::StoredObject::open`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkedDigest {
    root: Digest32,
    chunks: Vec<Digest32>,
    len: u64,
}

impl ChunkedDigest {
    /// A digest from its chunk leaves and byte length; the root is computed.
    #[must_use]
    pub fn from_leaves(chunks: Vec<Digest32>, len: u64) -> Self {
        Self {
            root: merkle_root(&chunks),
            chunks,
            len,
        }
    }

    /// The Merkle root over the chunk leaves — `d_ev` or `cm_ev`.
    #[must_use]
    pub const fn root(&self) -> &Digest32 {
        &self.root
    }

    /// The per-chunk leaves, in order: what a single chunk is re-checked
    /// against, and what an inclusion proof for one region is built from.
    #[must_use]
    pub fn chunks(&self) -> &[Digest32] {
        &self.chunks
    }

    /// Total bytes digested.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.len
    }

    /// Number of chunks.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

/// One chunk's leaf: `H(domain ‖ i ‖ chunk)`, design §14.2.
///
/// ⚠️ **The index is bound in, as §14.2 writes it.** The first version hashed
/// the bytes alone. The root still bound positions, through the tree, but a
/// spot-check compares one chunk against one stored leaf — and without `i`, a
/// chunk's content moved to another index with the same bytes (zero pages are
/// everywhere in a memory image) would pass that check. The sweeper (M10 H8) is
/// built on exactly that comparison.
#[must_use]
pub fn chunk_leaf(domain: Domain, index: u64, bytes: &[u8]) -> Digest32 {
    hash_domain(domain, &[&index.to_le_bytes(), bytes])
}

/// Digest a file in 1 MiB chunks, streaming.
///
/// # Errors
///
/// Any I/O error from opening or reading `path`.
pub fn digest_file(path: &Path, domain: Domain) -> io::Result<ChunkedDigest> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; CHUNK_BYTES];
    let mut chunks = Vec::new();
    let mut len = 0u64;

    loop {
        // `read` may return short without being at EOF, so fill the buffer
        // before hashing. Hashing short reads would make the chunk boundaries
        // depend on how the OS happened to schedule I/O, and the same file
        // would digest differently on two runs.
        let mut filled = 0usize;
        while filled < CHUNK_BYTES {
            match file.read(&mut buf[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        if filled == 0 {
            break;
        }
        chunks.push(chunk_leaf(domain, chunks.len() as u64, &buf[..filled]));
        len += filled as u64;
        if filled < CHUNK_BYTES {
            break;
        }
    }

    Ok(ChunkedDigest::from_leaves(chunks, len))
}

/// Digest an in-memory buffer with the same chunking, for tests and small
/// inputs.
#[must_use]
pub fn digest_bytes(data: &[u8], domain: Domain) -> ChunkedDigest {
    let chunks: Vec<Digest32> = if data.is_empty() {
        Vec::new()
    } else {
        data.chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(i, c)| chunk_leaf(domain, i as u64, c))
            .collect()
    };
    ChunkedDigest::from_leaves(chunks, data.len() as u64)
}

/// One chunk's leaf of the **plaintext commitment** `cm_ev`, design §14.3:
/// `H(0x21 ‖ ⟪i, r_ev, chunk⟫)`.
///
/// ⭐ **`r_ev` enters every leaf, not only the root.** Without it `cm_ev` is not
/// hiding: anyone holding the capsule and a guessed copy of the artefact can
/// confirm the guess, equal chunks in two capsules link them, and redaction's
/// FULL mode, which destroys `r_ev` so that `cm_ev` becomes unopenable
/// (design §12.4), would erase nothing.
#[must_use]
pub fn blinded_leaf(index: u64, r_ev: &Digest32, bytes: &[u8]) -> Digest32 {
    hash_domain(
        Domain::PlaintextCommit,
        &[&index.to_le_bytes(), r_ev, bytes],
    )
}

/// `cm_ev` over an in-memory artefact, under opening `r_ev`.
#[must_use]
pub fn commit_bytes(data: &[u8], r_ev: &Digest32) -> ChunkedDigest {
    let chunks: Vec<Digest32> = data
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(i, c)| blinded_leaf(i as u64, r_ev, c))
        .collect();
    blinded(chunks, data.len() as u64, r_ev)
}

/// `cm_ev` over a file, streaming, under opening `r_ev`.
///
/// # Errors
///
/// Any I/O error from opening or reading `path`.
pub fn commit_file(path: &Path, r_ev: &Digest32) -> io::Result<ChunkedDigest> {
    let mut chunks = Vec::new();
    let len = for_each_chunk(path, |i, c| chunks.push(blinded_leaf(i, r_ev, c)))?;
    Ok(blinded(chunks, len, r_ev))
}

/// The root of a blinded leaf list. An empty artefact still commits under
/// `r_ev`, so it is not one public constant.
fn blinded(chunks: Vec<Digest32>, len: u64, r_ev: &Digest32) -> ChunkedDigest {
    let root = if chunks.is_empty() {
        hash_domain(Domain::PlaintextCommit, &[b"empty", r_ev])
    } else {
        merkle_root(&chunks)
    };
    ChunkedDigest { root, chunks, len }
}

/// Stream `path` in full 1 MiB chunks (the last may be short), calling `f`
/// with each chunk's index and bytes; returns the total length.
///
/// Same read loop as [`digest_file`], which is left untouched until after the
/// SAC submission: campaign 07's Exp. 8 executes it, and an edit there would
/// stale that record by the guard's rule.
fn for_each_chunk(path: &Path, mut f: impl FnMut(u64, &[u8])) -> io::Result<u64> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; CHUNK_BYTES];
    let (mut index, mut len) = (0u64, 0u64);
    loop {
        let mut filled = 0usize;
        while filled < CHUNK_BYTES {
            match file.read(&mut buf[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        if filled == 0 {
            break;
        }
        f(index, &buf[..filled]);
        index += 1;
        len += filled as u64;
        if filled < CHUNK_BYTES {
            break;
        }
    }
    Ok(len)
}

/// Merkle root over chunk digests.
///
/// ⭐ **An unpaired node is promoted, never duplicated.** Duplicating the last
/// node is CVE-2012-2459: two distinct chunk lists produce the same root, so an
/// adversary can swap one for the other under a signature that still verifies.
/// `pqcl-forest` made the same choice and `draft6.tex` was corrected to match
/// this is the third place the rule has to
/// hold, and it must hold identically.
#[must_use]
pub fn merkle_root(chunks: &[Digest32]) -> Digest32 {
    if chunks.is_empty() {
        // A distinct constant for "nothing", so an empty artefact cannot
        // collide with a single zero-filled chunk.
        return hash_domain(Domain::EvidenceDigest, &[b"empty"]);
    }

    let mut level: Vec<Digest32> = chunks.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(hash_domain(
                    Domain::MerkleInternal,
                    &[&level[i], &level[i + 1]],
                ));
            } else {
                // Promote, do not duplicate.
                next.push(level[i]);
            }
            i += 2;
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_chunk_is_its_own_root() {
        let d = digest_bytes(b"short", Domain::EvidenceDigest);
        assert_eq!(d.chunk_count(), 1);
        assert_eq!(d.root, d.chunks[0]);
        assert_eq!(d.len, 5);
    }

    #[test]
    fn chunking_happens_at_one_mebibyte() {
        let data = vec![0xABu8; CHUNK_BYTES + 1];
        let d = digest_bytes(&data, Domain::EvidenceDigest);
        assert_eq!(
            d.chunk_count(),
            2,
            "a byte past the boundary must start a new chunk"
        );
        assert_eq!(d.len, CHUNK_BYTES as u64 + 1);
    }

    #[test]
    fn changing_one_byte_changes_exactly_one_chunk() {
        let mut a = vec![7u8; 3 * CHUNK_BYTES];
        let da = digest_bytes(&a, Domain::EvidenceDigest);

        // Corrupt a byte in the middle chunk.
        a[CHUNK_BYTES + 12] ^= 0xFF;
        let db = digest_bytes(&a, Domain::EvidenceDigest);

        assert_ne!(da.root, db.root, "the root must move");
        assert_eq!(da.chunks[0], db.chunks[0], "chunk 0 is untouched");
        assert_ne!(da.chunks[1], db.chunks[1], "chunk 1 carries the damage");
        assert_eq!(da.chunks[2], db.chunks[2], "chunk 2 is untouched");
    }

    /// The whole point of §14: a damaged image is still evidence for its intact
    /// regions. If corruption smeared across chunks this would be false.
    #[test]
    fn intact_regions_survive_a_corrupt_chunk() {
        let mut data = vec![3u8; 4 * CHUNK_BYTES];
        let before = digest_bytes(&data, Domain::EvidenceDigest);
        data[2 * CHUNK_BYTES] ^= 0x01;
        let after = digest_bytes(&data, Domain::EvidenceDigest);

        let intact: Vec<usize> = (0..before.chunk_count())
            .filter(|&i| before.chunks[i] == after.chunks[i])
            .collect();
        assert_eq!(
            intact,
            vec![0, 1, 3],
            "only the damaged chunk should differ"
        );
    }

    /// CVE-2012-2459. With duplication instead of promotion, a three-chunk list
    /// and a four-chunk list whose last is repeated share a root.
    #[test]
    fn an_unpaired_chunk_is_promoted_not_duplicated() {
        let c: Vec<Digest32> = (0u8..3)
            .map(|i| hash_domain(Domain::EvidenceDigest, &[&[i]]))
            .collect();

        let mut duplicated = c.clone();
        duplicated.push(c[2]);

        assert_ne!(
            merkle_root(&c),
            merkle_root(&duplicated),
            "duplicating the unpaired node collides two distinct chunk lists"
        );
    }

    /// Two chunks with identical bytes must still have distinct leaves, or a
    /// spot-check could be satisfied by the right bytes at the wrong index.
    #[test]
    fn identical_chunks_at_different_indices_have_different_leaves() {
        let data = vec![0u8; 2 * CHUNK_BYTES];
        let d = digest_bytes(&data, Domain::EvidenceDigest);
        assert_ne!(d.chunks[0], d.chunks[1]);
        assert_eq!(
            d.chunks[1],
            chunk_leaf(Domain::EvidenceDigest, 1, &data[CHUNK_BYTES..])
        );
    }

    #[test]
    fn an_empty_artefact_is_distinct_from_a_zero_chunk() {
        let empty = digest_bytes(b"", Domain::EvidenceDigest);
        let zeros = digest_bytes(&[0u8; 16], Domain::EvidenceDigest);
        assert_eq!(empty.chunk_count(), 0);
        assert_ne!(empty.root, zeros.root);
    }

    /// `d_ev` and `cm_ev` are different commitments over different bytes, so
    /// they must not be derivable from one another.
    #[test]
    fn the_two_domains_give_different_roots_for_the_same_bytes() {
        let data = vec![9u8; 4096];
        assert_ne!(
            digest_bytes(&data, Domain::EvidenceDigest).root,
            digest_bytes(&data, Domain::PlaintextCommit).root
        );
    }
}
