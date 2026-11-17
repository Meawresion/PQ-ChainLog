//! Tier 2 — the per-epoch MMR over the whole case.
//!
//! A Merkle Mountain Range *is* a forest of perfect binary trees, which is why
//! the design calls the whole structure a Merkle forest: the two names describe
//! the same object. Appending is `O(log n)`, amortised `O(1)`, and no existing
//! node is ever rewritten — which is what an append-only custody log needs.
//!
//! # Leaf types, domain-separated
//!
//! ```text
//! 0x01 ‖ ⟪eid, cid_c, e, type, d_ev, cm_ev,
//!         prov, Δ_gap, σ_DEFR⟫                        capsule seal
//! 0x02 ‖ ⟪eid_e, R_cap, count⟫                         custody-tree root
//! 0x03 ‖ ⟪e, MerkleRoot(sorted XSet_e), digest⟫        index epoch
//! 0x04 ‖ ⟪warrant_id, H(trapdoor), ts⟫                 audit event
//! 0x05 ‖ ⟪oid, tgt, scope, mode, σ_CO, ts⟫              redaction order (draft7 Phase 11)
//! 0x06 ‖ …                                             sweep attestation (§14.4)
//! 0x07 ‖ …                                             agent-epoch root (§8a.2)
//! ```
//!
//! The tags matter because a `0x02` custody-root leaf and a `0x03` index-epoch
//! leaf are **both 32-byte digests**. Without separation a malicious
//! Aggregation & Index Server could present one as the other, and an auditor
//! checking "is this custody root anchored?" would accept an index digest.
//! [`tests::a_leaf_of_one_type_cannot_be_presented_as_another`] is that
//! property, and it is M4's stated acceptance criterion.

use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

use crate::tier1::node;

/// A Tier-2 leaf: a type tag plus its committed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    /// Which kind of thing this commits to.
    pub domain: Domain,
    /// The digest, already tagged.
    pub digest: Digest32,
}

impl Leaf {
    /// Build a leaf of the given type over an ordered field list.
    #[must_use]
    pub fn new(domain: Domain, fields: &[&[u8]]) -> Self {
        Self {
            domain,
            digest: hash_domain(domain, fields),
        }
    }
}

/// A Tier-2 inclusion proof: a path within one perfect subtree, plus the other
/// peaks so a verifier can re-bag the root.
///
/// This is what a court-disclosure bundle carries to show that a capsule's
/// custody root was anchored in a particular epoch. It must verify **from
/// public data alone** — the anchored `R_e` and these bytes — with no access to
/// the rest of the case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmrProof {
    /// Leaf position in append order.
    pub index: u64,
    /// Leaves in the MMR when the proof was made.
    pub count: u64,
    /// Sibling path from the leaf up to its subtree peak.
    pub path: Vec<crate::tier1::ProofStep>,
    /// Peaks strictly to the **left** of ours, in order.
    pub peaks_left: Vec<Digest32>,
    /// Peaks strictly to the **right** of ours, in order.
    pub peaks_right: Vec<Digest32>,
}

/// One batched Tier-2 proof for several leaves of one MMR (M13 A8).
///
/// ⭐ **Why the flat baseline gets this** (`audit/06` D7). Proving `k` leaves
/// with `k` separate [`MmrProof`]s repeats every sibling the leaves share near
/// their peaks, and every peak, `k` times. A flat-log system disclosing one
/// capsule's records would batch them, so the comparison against our Tier-1
/// bundle uses the batched form: the baseline gets smaller and faster, which is
/// against us and is the fair way round.
///
/// `nodes` is one stream, consumed in a fixed order by [`verify_many`]: for each
/// perfect subtree in append order, either its sibling nodes level by level
/// (when it holds a proved leaf) or its peak (when it holds none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmrMultiProof {
    /// Leaves in the MMR when the proof was made.
    pub count: u64,
    /// The proved positions, strictly increasing.
    pub indices: Vec<u64>,
    /// Sibling nodes and untouched peaks, in verification order.
    pub nodes: Vec<Digest32>,
}

impl MmrMultiProof {
    /// Bytes carried in a disclosure: the nodes, and the positions that place
    /// the leaves (a single proof's direction bits do the same job).
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        self.nodes.len() * core::mem::size_of::<Digest32>()
            + self.indices.len() * core::mem::size_of::<u64>()
    }
}

/// Perfect-subtree boundaries of an MMR of `count` leaves, as `(start, len)`
/// in append order, largest first.
fn subtrees_of(count: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut start = 0u64;
    for bit in (0..64u32).rev() {
        if count & (1u64 << bit) != 0 {
            out.push((start, 1u64 << bit));
            start += 1u64 << bit;
        }
    }
    out
}

impl MmrProof {
    /// Bytes carried in a disclosure bundle.
    #[must_use]
    pub fn wire_bytes(&self) -> usize {
        let d = core::mem::size_of::<Digest32>();
        self.path.len() * (d + 1) + (self.peaks_left.len() + self.peaks_right.len()) * d
    }
}

/// The per-epoch MMR.
///
/// Retains every complete node so a proof is a lookup, not a rebuild.
///
/// ⚠️ **Proving used to rebuild the leaf's whole perfect subtree** — O(n) per
/// proof, O(n²) to disclose every capsule of an epoch. Campaign 03's 10⁶-record
/// custody case spent hours in that setup. Because MMR subtrees are aligned
/// (largest first, sizes the set bits of `n`), the node at height `h` over
/// leaves `[j·2ʰ, (j+1)·2ʰ)` exists exactly when that block is complete, and
/// `levels[h][j]` is it. Retaining them costs < 2× the leaves and changes no
/// digest; `prove_matches_the_rebuild_at_every_leaf` pins that.
#[derive(Debug, Clone, Default)]
pub struct Mmr {
    /// Peaks, highest first. Each is the root of a perfect subtree.
    peaks: Vec<(u32, Digest32)>,
    /// `levels[0]` are the leaves; `levels[h][j]` covers leaves `[j·2ʰ, (j+1)·2ʰ)`.
    levels: Vec<Vec<Digest32>>,
    count: u64,
}

impl Mmr {
    /// An empty MMR.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves appended — this epoch's `n_e`, committed inside the
    /// checkpoint `d_e` and, since M13 A21, nowhere on chain.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.count
    }

    /// Whether nothing has been appended.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Current peaks, for inspection and for the bagging order.
    #[must_use]
    pub fn peaks(&self) -> &[(u32, Digest32)] {
        &self.peaks
    }

    /// Append a leaf, merging equal-height peaks.
    pub fn append(&mut self, leaf: &Leaf) {
        self.append_digest(leaf.digest);
    }

    /// An MMR over leaf digests alone, in append order.
    ///
    /// ⭐ **What a custodian rebuilds `R_e` from** (M13 A5). A leaf's type is
    /// already inside its digest — every Tier-2 leaf is `H(tag ‖ …)` — so the
    /// digests are the whole input to the bagging, and a custodian handed them
    /// recomputes exactly the root the AIS proposes, or catches that it does
    /// not.
    #[must_use]
    pub fn from_digests(digests: &[Digest32]) -> Self {
        let mut m = Self::new();
        for d in digests {
            m.append_digest(*d);
        }
        m
    }

    /// The leaf digests, in append order.
    #[must_use]
    pub fn leaf_digests(&self) -> &[Digest32] {
        self.levels.first().map_or(&[], Vec::as_slice)
    }

    fn append_digest(&mut self, digest: Digest32) {
        self.push_node(0, digest);
        self.peaks.push((0, digest));
        // Merge while the last two peaks have equal height. Peaks are strictly
        // decreasing in height afterwards, which is the MMR invariant.
        while self.peaks.len() >= 2 {
            let (h1, d1) = self.peaks[self.peaks.len() - 1];
            let (h0, d0) = self.peaks[self.peaks.len() - 2];
            if h0 != h1 {
                break;
            }
            self.peaks.truncate(self.peaks.len() - 2);
            let merged = node(&d0, &d1);
            self.push_node(h0 + 1, merged);
            self.peaks.push((h0 + 1, merged));
        }
        self.count += 1;
    }

    /// `R_e` — the bagged root, or `None` when empty.
    ///
    /// Peaks are folded **right to left**, the standard MMR bagging order.
    /// Fixing the direction matters: the auditor and the anchoring contract
    /// must agree byte-for-byte, and "fold the peaks" is ambiguous without it.
    #[must_use]
    pub fn root(&self) -> Option<Digest32> {
        let mut it = self.peaks.iter().rev();
        let (_, mut acc) = *it.next()?;
        for (_, d) in it {
            acc = node(d, &acc);
        }
        Some(acc)
    }
}

impl Mmr {
    /// Perfect-subtree boundaries, as `(start, len)` in append order.
    ///
    /// An MMR with `n` leaves decomposes into subtrees whose sizes are the set
    /// bits of `n`, largest first — which is why the peak count equals
    /// `n.count_ones()`.
    fn subtrees(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut start = 0usize;
        let mut n = self.count;
        let mut bit = 63u32;
        loop {
            if n & (1u64 << bit) != 0 {
                let len = 1usize << bit;
                out.push((start, len));
                start += len;
                n &= !(1u64 << bit);
            }
            if bit == 0 {
                break;
            }
            bit -= 1;
        }
        out
    }

    fn push_node(&mut self, height: u32, digest: Digest32) {
        let h = height as usize;
        if self.levels.len() <= h {
            self.levels.resize_with(h + 1, Vec::new);
        }
        self.levels[h].push(digest);
    }

    /// An inclusion proof for the leaf at `index`. O(log n): every sibling is
    /// a retained node.
    #[must_use]
    pub fn prove(&self, index: u64) -> Option<MmrProof> {
        let i = usize::try_from(index).ok()?;
        if i >= self.levels.first().map_or(0, Vec::len) {
            return None;
        }
        let subtrees = self.subtrees();
        let which = subtrees.iter().position(|(s, l)| i >= *s && i < s + l)?;
        let (_, len) = subtrees[which];

        let mut path = Vec::new();
        let mut pos = i;
        for h in 0..len.trailing_zeros() as usize {
            let sibling_is_right = pos.is_multiple_of(2);
            let sib = *self.levels[h].get(pos ^ 1)?;
            path.push(crate::tier1::ProofStep {
                sibling: sib,
                sibling_is_right,
            });
            pos /= 2;
        }

        // Peaks are stored highest-first, which is the same as append order
        // because subtree sizes strictly decrease.
        let peaks_left = self.peaks[..which].iter().map(|(_, d)| *d).collect();
        let peaks_right = self.peaks[which + 1..].iter().map(|(_, d)| *d).collect();

        Some(MmrProof {
            index,
            count: self.count,
            path,
            peaks_left,
            peaks_right,
        })
    }

    /// One batched proof for every leaf in `indices` (M13 A8). `None` if any
    /// index is out of range or `indices` is empty; duplicates are proved once.
    #[must_use]
    pub fn prove_many(&self, indices: &[u64]) -> Option<MmrMultiProof> {
        let mut indices = indices.to_vec();
        indices.sort_unstable();
        indices.dedup();
        if indices.is_empty() || *indices.last()? >= self.count {
            return None;
        }
        let mut nodes = Vec::new();
        let mut at = 0usize;
        for (which, (start, len)) in subtrees_of(self.count).into_iter().enumerate() {
            let from = at;
            while at < indices.len() && indices[at] < start + len {
                at += 1;
            }
            if from == at {
                nodes.push(self.peaks.get(which)?.1);
                continue;
            }
            let mut known: Vec<usize> = indices[from..at]
                .iter()
                .map(|i| usize::try_from(*i).ok())
                .collect::<Option<_>>()?;
            for h in 0..len.trailing_zeros() as usize {
                let mut next = Vec::with_capacity(known.len());
                let mut k = 0;
                while k < known.len() {
                    let p = known[k];
                    if p.is_multiple_of(2) && known.get(k + 1) == Some(&(p + 1)) {
                        k += 2;
                    } else {
                        nodes.push(*self.levels.get(h)?.get(p ^ 1)?);
                        k += 1;
                    }
                    next.push(p / 2);
                }
                known = next;
            }
        }
        Some(MmrMultiProof {
            count: self.count,
            indices,
            nodes,
        })
    }

    /// The pre-2026-09-27 `prove`, which rebuilt the subtree. Kept only as the
    /// reference the lookup version must match byte for byte.
    #[cfg(test)]
    fn prove_by_rebuild(&self, index: u64) -> Option<MmrProof> {
        let i = usize::try_from(index).ok()?;
        let leaves = self.levels.first()?;
        if i >= leaves.len() {
            return None;
        }
        let subtrees = self.subtrees();
        let which = subtrees.iter().position(|(s, l)| i >= *s && i < s + l)?;
        let (start, len) = subtrees[which];
        let mut level: Vec<Digest32> = leaves[start..start + len].to_vec();
        let mut pos = i - start;
        let mut path = Vec::new();
        while level.len() > 1 {
            let sibling_is_right = pos.is_multiple_of(2);
            let sib = if sibling_is_right {
                level[pos + 1]
            } else {
                level[pos - 1]
            };
            path.push(crate::tier1::ProofStep {
                sibling: sib,
                sibling_is_right,
            });
            let mut next = Vec::with_capacity(level.len() / 2);
            let mut k = 0;
            while k + 1 < level.len() {
                next.push(node(&level[k], &level[k + 1]));
                k += 2;
            }
            level = next;
            pos /= 2;
        }
        let peaks_left = self.peaks[..which].iter().map(|(_, d)| *d).collect();
        let peaks_right = self.peaks[which + 1..].iter().map(|(_, d)| *d).collect();
        Some(MmrProof {
            index,
            count: self.count,
            path,
            peaks_left,
            peaks_right,
        })
    }
}

/// Verify a Tier-2 inclusion proof against an anchored root.
///
/// Takes the [`Leaf`] rather than a bare digest, so the type tag is applied
/// here and a caller cannot present a `0x03` index digest as a `0x02` custody
/// root by handing over pre-hashed bytes.
#[must_use]
pub fn verify(root: &Digest32, leaf: &Leaf, proof: &MmrProof) -> bool {
    verify_with(root, leaf, proof, &mut |l, r| node(l, r))
}

/// Verify a batched proof: `leaves[i]` sits at `proof.indices[i]`.
///
/// Refuses a proof whose positions are not strictly increasing and in range,
/// whose leaf count does not match its positions, or whose node stream is
/// short **or long**: every node must be consumed, so nothing can ride along.
#[must_use]
pub fn verify_many(root: &Digest32, leaves: &[Leaf], proof: &MmrMultiProof) -> bool {
    verify_many_inner(root, leaves, proof).unwrap_or(false)
}

fn verify_many_inner(root: &Digest32, leaves: &[Leaf], proof: &MmrMultiProof) -> Option<bool> {
    let ix = &proof.indices;
    if ix.is_empty()
        || ix.len() != leaves.len()
        || ix.windows(2).any(|w| w[0] >= w[1])
        || *ix.last()? >= proof.count
    {
        return Some(false);
    }
    let mut stream = proof.nodes.iter();
    let mut peaks = Vec::new();
    let mut at = 0usize;
    for (start, len) in subtrees_of(proof.count) {
        let from = at;
        while at < ix.len() && ix[at] < start + len {
            at += 1;
        }
        if from == at {
            peaks.push(*stream.next()?);
            continue;
        }
        let mut known: Vec<(u64, Digest32)> = ix[from..at]
            .iter()
            .zip(&leaves[from..at])
            .map(|(i, l)| (*i, l.digest))
            .collect();
        for _ in 0..len.trailing_zeros() {
            let mut next = Vec::with_capacity(known.len());
            let mut k = 0;
            while k < known.len() {
                let (pos, digest) = known[k];
                let parent = match known.get(k + 1) {
                    Some(&(right_pos, right)) if pos.is_multiple_of(2) && right_pos == pos + 1 => {
                        k += 2;
                        node(&digest, &right)
                    }
                    _ => {
                        k += 1;
                        let sibling = stream.next()?;
                        if pos.is_multiple_of(2) {
                            node(&digest, sibling)
                        } else {
                            node(sibling, &digest)
                        }
                    }
                };
                next.push((pos / 2, parent));
            }
            known = next;
        }
        if known.len() != 1 {
            return Some(false);
        }
        peaks.push(known[0].1);
    }
    if stream.next().is_some() {
        return Some(false);
    }
    let mut it = peaks.iter().rev();
    let mut bag = *it.next()?;
    for d in it {
        bag = node(d, &bag);
    }
    Some(bag == *root)
}

/// A memo of Tier-2 node hashes, shared across many verifications of one
/// epoch — a full-case audit.
///
/// ⭐ **Identical by construction.** It caches the node *function*: a hit
/// returns exactly what `node(l, r)` would, so [`verify_memo`] accepts and
/// rejects exactly what [`verify`] does, whatever the proof. It only saves the
/// hashes that proofs of neighbouring leaves share near their peaks.
#[derive(Debug, Default)]
pub struct NodeMemo {
    map: std::collections::HashMap<(Digest32, Digest32), Digest32>,
    /// Node hashes answered from the memo.
    pub hits: u64,
    /// Node hashes computed.
    pub misses: u64,
}

/// [`verify`] through a shared [`NodeMemo`].
#[must_use]
pub fn verify_memo(root: &Digest32, leaf: &Leaf, proof: &MmrProof, memo: &mut NodeMemo) -> bool {
    verify_with(root, leaf, proof, &mut |l, r| {
        if let Some(d) = memo.map.get(&(*l, *r)) {
            memo.hits += 1;
            return *d;
        }
        memo.misses += 1;
        let d = node(l, r);
        memo.map.insert((*l, *r), d);
        d
    })
}

fn verify_with(
    root: &Digest32,
    leaf: &Leaf,
    proof: &MmrProof,
    node: &mut dyn FnMut(&Digest32, &Digest32) -> Digest32,
) -> bool {
    if proof.index >= proof.count {
        return false;
    }

    // Climb from the leaf to its own subtree's peak.
    let mut peak = leaf.digest;
    for step in &proof.path {
        peak = if step.sibling_is_right {
            node(&peak, &step.sibling)
        } else {
            node(&step.sibling, &peak)
        };
    }

    // Re-bag every peak in append order, folding right to left — the same
    // direction `Mmr::root` uses. Getting this backwards would produce a root
    // that no auditor and no contract would agree with.
    let mut all = Vec::with_capacity(proof.peaks_left.len() + proof.peaks_right.len() + 1);
    all.extend_from_slice(&proof.peaks_left);
    all.push(peak);
    all.extend_from_slice(&proof.peaks_right);

    let mut it = all.iter().rev();
    let Some(&last) = it.next() else {
        return false;
    };
    let mut bag = last;
    for d in it {
        bag = node(d, &bag);
    }
    bag == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_of(domain: Domain, s: &str) -> Leaf {
        Leaf::new(domain, &[s.as_bytes()])
    }

    #[test]
    fn appending_advances_the_count_and_the_root() {
        let mut m = Mmr::new();
        assert!(m.root().is_none());
        assert!(m.is_empty());

        let mut seen = Vec::new();
        for i in 0..16 {
            m.append(&leaf_of(Domain::CapsuleSeal, &format!("cap-{i}")));
            assert_eq!(m.leaf_count(), i + 1);
            let r = m.root().expect("non-empty");
            assert!(!seen.contains(&r), "root repeated at leaf {i}");
            seen.push(r);
        }
    }

    #[test]
    fn a_leaf_of_one_type_cannot_be_presented_as_another() {
        // ⭐ M4's stated acceptance criterion.
        //
        // A custody-tree root (0x02) and an index-epoch digest (0x03) are both
        // 32-byte values. If the tags did not separate them, an AIS could
        // answer "is this custody root anchored?" with an index digest.
        let fields: &[&[u8]] = &[&[0xabu8; 32]];
        let custody = Leaf::new(Domain::CustodyRoot, fields);
        let index = Leaf::new(Domain::IndexEpoch, fields);
        assert_ne!(custody.digest, index.digest);

        // And an MMR built from one is not the MMR built from the other.
        let mut a = Mmr::new();
        let mut b = Mmr::new();
        a.append(&custody);
        b.append(&index);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn every_leaf_type_is_distinct_over_identical_fields() {
        // All seven Tier-2 types, pairwise. 0x05 (`pqcl_capsule::redaction`)
        // and 0x07 (`pqcl_pipeline::agent_epoch`) are built; 0x06 is design-only
        // so far, but is anchored the same way and must separate the same way.
        let fields: &[&[u8]] = &[b"identical", b"content"];
        let domains = [
            Domain::CapsuleSeal,
            Domain::CustodyRoot,
            Domain::IndexEpoch,
            Domain::AuditEvent,
            Domain::Dispose,
            Domain::SweepAttestation,
            Domain::AgentEpochRoot,
        ];
        let digests: Vec<_> = domains
            .iter()
            .map(|d| Leaf::new(*d, fields).digest)
            .collect();
        for (i, a) in digests.iter().enumerate() {
            for b in &digests[i + 1..] {
                assert_ne!(a, b, "two Tier-2 leaf types collide");
            }
        }
    }

    #[test]
    fn peaks_are_strictly_decreasing_in_height() {
        // The MMR invariant. If it broke, bagging order would be ambiguous and
        // two implementations could compute different roots from the same log.
        let mut m = Mmr::new();
        for i in 0..37 {
            m.append(&leaf_of(Domain::AuditEvent, &format!("a-{i}")));
            let heights: Vec<u32> = m.peaks().iter().map(|(h, _)| *h).collect();
            for w in heights.windows(2) {
                assert!(w[0] > w[1], "peaks not decreasing at {i}: {heights:?}");
            }
        }
    }

    #[test]
    fn a_power_of_two_count_has_exactly_one_peak() {
        let mut m = Mmr::new();
        for i in 0..8 {
            m.append(&leaf_of(Domain::CapsuleSeal, &format!("c-{i}")));
        }
        assert_eq!(m.peaks().len(), 1);
        assert_eq!(m.peaks()[0].0, 3, "8 leaves is one height-3 subtree");
    }

    #[test]
    fn peak_count_is_the_population_count_of_the_leaf_count() {
        // A structural identity worth pinning: an MMR with n leaves has as many
        // peaks as n has set bits.
        let mut m = Mmr::new();
        for i in 0..64u64 {
            m.append(&leaf_of(Domain::CapsuleSeal, &format!("c-{i}")));
            assert_eq!(
                u32::try_from(m.peaks().len()).expect("peak count fits"),
                m.leaf_count().count_ones(),
                "at {} leaves",
                m.leaf_count()
            );
        }
    }

    #[test]
    fn the_root_depends_on_order() {
        // Custody is a sequence, not a set. Two epochs with the same events in
        // a different order must anchor differently.
        let mut a = Mmr::new();
        let mut b = Mmr::new();
        let x = leaf_of(Domain::CapsuleSeal, "x");
        let y = leaf_of(Domain::CapsuleSeal, "y");
        a.append(&x);
        a.append(&y);
        b.append(&y);
        b.append(&x);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn every_leaf_proves_against_the_anchored_root() {
        // Sizes chosen so the peak structure varies: powers of two (one peak),
        // one less (all peaks), and ragged counts in between.
        for n in [1u64, 2, 3, 4, 5, 7, 8, 15, 16, 23, 32] {
            let mut m = Mmr::new();
            let leaves: Vec<Leaf> = (0..n)
                .map(|i| leaf_of(Domain::CustodyRoot, &format!("cap-{i}")))
                .collect();
            for l in &leaves {
                m.append(l);
            }
            let root = m.root().expect("non-empty");
            for (i, l) in leaves.iter().enumerate() {
                let proof = m.prove(i as u64).expect("in range");
                assert!(verify(&root, l, &proof), "leaf {i} of {n} failed to verify");
            }
        }
    }

    #[test]
    fn prove_matches_the_rebuild_at_every_leaf() {
        // Lookup proofs must be byte-identical to the rebuild they replaced,
        // at every leaf, across ragged and power-of-two sizes -- and past the
        // end both must refuse.
        let mut m = Mmr::new();
        for n in 1u64..=300 {
            m.append(&leaf_of(Domain::CustodyRoot, &format!("cap-{n}")));
            for i in 0..n {
                assert_eq!(m.prove(i), m.prove_by_rebuild(i), "leaf {i} of {n}");
                assert!(m.prove(i).is_some());
            }
            assert_eq!(m.prove(n), None);
            assert_eq!(m.prove_by_rebuild(n), None);
        }
    }

    #[test]
    fn a_proof_does_not_verify_for_the_wrong_leaf() {
        let mut m = Mmr::new();
        for i in 0..11 {
            m.append(&leaf_of(Domain::CustodyRoot, &format!("cap-{i}")));
        }
        let root = m.root().expect("non-empty");
        let proof = m.prove(4).expect("in range");
        assert!(!verify(
            &root,
            &leaf_of(Domain::CustodyRoot, "cap-5"),
            &proof
        ));
        assert!(!verify(
            &root,
            &leaf_of(Domain::CustodyRoot, "forged"),
            &proof
        ));
    }

    #[test]
    fn a_proof_for_one_leaf_type_does_not_verify_as_another() {
        // The Tier-2 separation, now at proof level: an index-epoch digest
        // cannot be presented as an anchored custody root even with a valid
        // path, because verify() applies the tag itself.
        let mut m = Mmr::new();
        for i in 0..8 {
            m.append(&leaf_of(Domain::CustodyRoot, &format!("cap-{i}")));
        }
        let root = m.root().expect("non-empty");
        let proof = m.prove(3).expect("in range");
        assert!(verify(
            &root,
            &leaf_of(Domain::CustodyRoot, "cap-3"),
            &proof
        ));
        assert!(
            !verify(&root, &leaf_of(Domain::IndexEpoch, "cap-3"), &proof),
            "an index-epoch leaf verified against a custody-root position"
        );
    }

    #[test]
    fn a_stale_proof_fails_against_a_later_epoch_root() {
        let mut m = Mmr::new();
        for i in 0..8 {
            m.append(&leaf_of(Domain::CustodyRoot, &format!("cap-{i}")));
        }
        let proof = m.prove(2).expect("in range");
        m.append(&leaf_of(Domain::CustodyRoot, "cap-8"));
        assert!(!verify(
            &m.root().expect("non-empty"),
            &leaf_of(Domain::CustodyRoot, "cap-2"),
            &proof
        ));
    }

    #[test]
    fn proof_size_is_logarithmic_in_the_epoch() {
        let mut m = Mmr::new();
        for i in 0..1024 {
            m.append(&leaf_of(Domain::CustodyRoot, &format!("cap-{i}")));
        }
        let p = m.prove(500).expect("in range");
        assert_eq!(p.path.len(), 10);
        assert!(p.peaks_left.is_empty() && p.peaks_right.is_empty());
        assert_eq!(p.wire_bytes(), 10 * 33);
    }

    #[test]
    fn a_single_leaf_roots_to_itself() {
        let mut m = Mmr::new();
        let l = leaf_of(Domain::CapsuleSeal, "only");
        m.append(&l);
        assert_eq!(m.root(), Some(l.digest));
    }

    // ------------------------------------------------ batched proofs (M13 A8)

    fn mmr_of(n: u64) -> (Mmr, Vec<Leaf>) {
        let mut m = Mmr::new();
        let ls: Vec<Leaf> = (0..n)
            .map(|i| leaf_of(Domain::CustodyRecord, &format!("CR-{i}")))
            .collect();
        for l in &ls {
            m.append(l);
        }
        (m, ls)
    }

    /// ⭐ **Acceptance A8 (a): the batched proof verifies**, for subsets of
    /// every shape — one leaf, neighbours, a whole subtree, leaves spread
    /// across peaks, every leaf — at sizes either side of powers of two.
    #[test]
    fn a_batched_proof_verifies_for_every_subset_shape() {
        for n in [1u64, 2, 3, 5, 7, 8, 9, 13, 16, 31, 33] {
            let (m, ls) = mmr_of(n);
            let root = m.root().expect("non-empty");
            let shapes: Vec<Vec<u64>> = vec![
                vec![0],
                vec![n - 1],
                (0..n).collect(),
                (0..n).step_by(3).collect(),
                (0..n).filter(|i| i % 4 < 2).collect(),
                vec![0, n / 2, n - 1],
            ];
            for mut want in shapes {
                want.dedup();
                let p = m.prove_many(&want).expect("in range");
                let leaves: Vec<Leaf> = p
                    .indices
                    .iter()
                    .map(|i| ls[usize::try_from(*i).expect("index")].clone())
                    .collect();
                assert!(verify_many(&root, &leaves, &p), "n = {n}, {want:?}");
                let singles: usize = want
                    .iter()
                    .map(|i| m.prove(*i).expect("in range").wire_bytes())
                    .sum();
                assert!(
                    p.wire_bytes() <= singles + 8 * want.len(),
                    "n = {n}, {want:?}: batched {} > separate {singles}",
                    p.wire_bytes()
                );
            }
        }
    }

    /// ⭐ **Acceptance A8 (b): a single substituted record fails**, and so does
    /// every other way of bending the proof: leaves swapped, a position moved,
    /// a node dropped, a node added, another MMR's root.
    #[test]
    fn a_batched_proof_refuses_any_substitution() {
        let (m, ls) = mmr_of(21);
        let root = m.root().expect("non-empty");
        let want = [2u64, 3, 9, 17, 20];
        let p = m.prove_many(&want).expect("in range");
        let leaves: Vec<Leaf> = want
            .iter()
            .map(|i| ls[usize::try_from(*i).expect("index")].clone())
            .collect();
        assert!(verify_many(&root, &leaves, &p));

        let mut sub = leaves.clone();
        sub[2] = leaf_of(Domain::CustodyRecord, "substituted");
        assert!(
            !verify_many(&root, &sub, &p),
            "a substituted record verified"
        );

        let mut swapped = leaves.clone();
        swapped.swap(0, 1);
        assert!(!verify_many(&root, &swapped, &p), "swapped leaves verified");

        let mut moved = p.clone();
        moved.indices[3] = 16;
        assert!(
            !verify_many(&root, &leaves, &moved),
            "a moved position verified"
        );

        let mut short = p.clone();
        short.nodes.pop();
        assert!(
            !verify_many(&root, &leaves, &short),
            "a short stream verified"
        );

        let mut long = p.clone();
        long.nodes.push([0u8; 32]);
        assert!(
            !verify_many(&root, &leaves, &long),
            "a long stream verified"
        );

        let (other, _) = mmr_of(22);
        assert!(
            !verify_many(&other.root().expect("x"), &leaves, &p),
            "another root verified"
        );

        assert!(
            !verify_many(&root, &leaves[..4], &p),
            "fewer leaves than positions verified"
        );
    }

    #[test]
    fn an_out_of_range_or_empty_batch_has_no_proof() {
        let (m, _) = mmr_of(5);
        assert!(m.prove_many(&[]).is_none());
        assert!(m.prove_many(&[1, 5]).is_none());
    }
}
