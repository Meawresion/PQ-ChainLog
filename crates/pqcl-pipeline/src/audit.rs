//! Integrity audit (M4b; design §14 and §8a.4) — three questions, three paths.
//!
//! * **Q1/§8a.4** — [`audit_agent_epochs`]: the four record-level checks and
//!   `σ_agent`, touching records and control capsules, never evidence bytes.
//! * **Q2** — [`read_verified`]: every read verifies exactly the chunks it
//!   touches against the anchored `d_ev`, at the moment of reliance.
//! * **Q3** — [`Sweeper`]: a keyless, byte-budgeted sample of `(object, chunk)`
//!   spot-checks over cold storage, never a "check everything" mode.
//!
//! ⭐ **Keyless.** `d_ev` binds ciphertext, so nothing here takes, holds or
//! derives a case key: the types below have no field that could carry one.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use pqcl_primitives::xof::{Digest32, Domain};

use crate::agent_epoch::{ControlCapsule, EvidenceRecord, Heartbeat, leaf_hash, r_agent};
use crate::chunked::{CHUNK_BYTES, ChunkedDigest, chunk_leaf};

/// Something an auditor raises. Each names what failed and where, because
/// that is what the Custody Record written for it has to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// §8a.4 (i): a `leaf_index` gap — a record was deleted.
    RecordDeleted {
        /// Agent.
        la_id: u32,
        /// Its epoch.
        epoch: u64,
        /// The missing index.
        leaf_index: u64,
    },
    /// The store holds a different number of records than `σ_agent` signed —
    /// truncation, which leaves `leaf_index` contiguous.
    CountMismatch {
        /// Agent.
        la_id: u32,
        /// Its epoch.
        epoch: u64,
        /// Signed count.
        signed: u64,
        /// Records held.
        held: u64,
    },
    /// §8a.4 (ii): `H(encrypted_payload) ≠ leaf_hash`.
    PayloadAltered {
        /// Agent.
        la_id: u32,
        /// Its epoch.
        epoch: u64,
        /// The record.
        leaf_index: u64,
    },
    /// §8a.4 (iii): the rebuilt agent-epoch tree does not match `R_agent`.
    TreeMismatch {
        /// Agent.
        la_id: u32,
        /// Its epoch.
        epoch: u64,
    },
    /// §8a.3: `epoch_la_id` is not contiguous for this agent — a whole
    /// agent-epoch was dropped.
    EpochOmitted {
        /// Agent.
        la_id: u32,
        /// The missing epoch.
        epoch: u64,
    },
    /// `σ_agent` does not verify under the agent's key.
    BadSignature {
        /// Agent.
        la_id: u32,
        /// Its epoch.
        epoch: u64,
    },
    /// ⭐ An agent's signed heartbeat counts more closed epochs than the
    /// store holds (M13 A6): the tail was dropped, which contiguity alone
    /// cannot see.
    TailOmitted {
        /// Agent.
        la_id: u32,
        /// A closed epoch the store does not hold.
        epoch: u64,
    },
    /// No verified heartbeat for longer than `T`: the agent went silent, or
    /// its beats are being suppressed.
    HeartbeatGap {
        /// Agent.
        la_id: u32,
        /// The last beat before the gap, or `None` if there was none at all.
        from: Option<u64>,
        /// The next beat, or the audit's `now`.
        to: u64,
    },
    /// ⭐ A held control capsule whose `0x07` leaf is in no anchored epoch
    /// (M13 A17): the AIS accepted the agent-epoch and kept it out of `R_e`.
    AgentEpochNotAnchored {
        /// Agent.
        la_id: u32,
        /// Its epoch.
        epoch: u64,
    },
    /// A heartbeat whose signature does not verify under the agent's key.
    BadHeartbeat {
        /// Agent.
        la_id: u32,
        /// When it claims to be from.
        ts: u64,
    },
    /// A chunk does not match the anchored `d_ev` — Q2 or Q3.
    ChunkMismatch {
        /// Which object.
        object: String,
        /// Which chunk.
        chunk: u64,
    },
}

/// §8a.4's four checks plus `σ_agent`, over every control capsule and record
/// the stores hold. Keys are the agents' ML-DSA public keys — the auditor
/// trusts those and the anchor, never the aggregator (§8a.3).
#[must_use]
pub fn audit_agent_epochs(
    capsules: &[ControlCapsule],
    records: &[EvidenceRecord],
    agent_keys: &BTreeMap<u32, Vec<u8>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut by_epoch: BTreeMap<(u32, u64), Vec<&EvidenceRecord>> = BTreeMap::new();
    for r in records {
        by_epoch
            .entry((r.la_id, r.epoch_la_id))
            .or_default()
            .push(r);
    }
    let mut epochs: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for c in capsules {
        epochs.entry(c.la_id).or_default().push(c.epoch_la_id);
        let key = agent_keys.get(&c.la_id);
        let signed = key.is_some_and(|k| {
            pqcl_primitives::sig::verify(&c.signed_bytes(), &c.sig_agent, k, b"").is_ok()
        });
        if !signed {
            out.push(Finding::BadSignature {
                la_id: c.la_id,
                epoch: c.epoch_la_id,
            });
        }
        let mut held: Vec<&EvidenceRecord> = by_epoch
            .get(&(c.la_id, c.epoch_la_id))
            .cloned()
            .unwrap_or_default();
        held.sort_by_key(|r| r.leaf_index);
        // (i) contiguity within the epoch.
        let mut expect = 0u64;
        for r in &held {
            while expect < r.leaf_index {
                out.push(Finding::RecordDeleted {
                    la_id: c.la_id,
                    epoch: c.epoch_la_id,
                    leaf_index: expect,
                });
                expect += 1;
            }
            expect = r.leaf_index + 1;
        }
        if held.len() as u64 != c.log_count {
            out.push(Finding::CountMismatch {
                la_id: c.la_id,
                epoch: c.epoch_la_id,
                signed: c.log_count,
                held: held.len() as u64,
            });
        }
        // (ii) each payload against its leaf hash.
        for r in &held {
            if leaf_hash(r.leaf_index, &r.encrypted_payload) != r.leaf_hash {
                out.push(Finding::PayloadAltered {
                    la_id: c.la_id,
                    epoch: c.epoch_la_id,
                    leaf_index: r.leaf_index,
                });
            }
        }
        // (iii) the tree over what is held against what was signed.
        let hashes: Vec<Digest32> = held.iter().map(|r| r.leaf_hash).collect();
        if r_agent(&hashes) != c.r_agent {
            out.push(Finding::TreeMismatch {
                la_id: c.la_id,
                epoch: c.epoch_la_id,
            });
        }
    }
    // §8a.3: epoch continuity per agent, from 0.
    for (la_id, mut es) in epochs {
        es.sort_unstable();
        let mut expect = 0u64;
        for e in es {
            while expect < e {
                out.push(Finding::EpochOmitted {
                    la_id,
                    epoch: expect,
                });
                expect += 1;
            }
            expect = e + 1;
        }
    }
    out
}

/// Every held control capsule's `0x07` leaf must be among the leaf digests of
/// the anchored epochs (M13 A17). `anchored` is what a custodian already
/// rebuilds `R_e` from (A5), so this costs one hash per capsule and a lookup.
///
/// The `0x07` tag is inside each digest, so another leaf type with the same
/// fields cannot stand in for one.
#[must_use]
pub fn audit_agent_epochs_anchored<H: core::hash::BuildHasher>(
    capsules: &[ControlCapsule],
    anchored: &std::collections::HashSet<Digest32, H>,
) -> Vec<Finding> {
    capsules
        .iter()
        .filter(|c| !anchored.contains(&c.leaf().digest))
        .map(|c| Finding::AgentEpochNotAnchored {
            la_id: c.la_id,
            epoch: c.epoch_la_id,
        })
        .collect()
}

/// The heartbeat checks of M13 A6, beside [`audit_agent_epochs`]: for every
/// enrolled agent, each beat's signature, a gap longer than `t` between
/// beats or before `now`, and the tail — a verified beat counting more closed
/// epochs than the store's capsules for that agent reach.
///
/// Interior gaps stay [`audit_agent_epochs`]' job. This compares a count with
/// the highest epoch held, so it reports only what lies past it.
#[must_use]
pub fn audit_heartbeats(
    capsules: &[ControlCapsule],
    beats: &[Heartbeat],
    agent_keys: &BTreeMap<u32, Vec<u8>>,
    now: u64,
    t: u64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (&la_id, key) in agent_keys {
        let mut mine: Vec<&Heartbeat> = Vec::new();
        for b in beats.iter().filter(|b| b.la_id == la_id) {
            if pqcl_primitives::sig::verify(&b.signed_bytes(), &b.sig_agent, key, b"").is_ok() {
                mine.push(b);
            } else {
                out.push(Finding::BadHeartbeat { la_id, ts: b.ts });
            }
        }
        mine.sort_by_key(|b| b.ts);
        let mut last: Option<u64> = None;
        for b in &mine {
            if let Some(prev) = last
                && b.ts.saturating_sub(prev) > t
            {
                out.push(Finding::HeartbeatGap {
                    la_id,
                    from: Some(prev),
                    to: b.ts,
                });
            }
            last = Some(b.ts);
        }
        if last.is_none_or(|l| now.saturating_sub(l) > t) {
            out.push(Finding::HeartbeatGap {
                la_id,
                from: last,
                to: now,
            });
        }
        let held = capsules
            .iter()
            .filter(|c| c.la_id == la_id)
            .map(|c| c.epoch_la_id + 1)
            .max()
            .unwrap_or(0);
        let claimed = mine.iter().map(|b| b.counter).max().unwrap_or(0);
        for epoch in held..claimed {
            out.push(Finding::TailOmitted { la_id, epoch });
        }
    }
    out
}

/// One stored object as the sweeper sees it: where the ciphertext is, and its
/// anchored chunked digest. No key, because none is needed (§14.6).
///
/// ⭐ **Only [`StoredObject::open`] makes one, and it checks the binding**
/// (M13 A12, `audit/06d` L2-a). The leaf list a spot-check compares against
/// is stored beside the ciphertext, so whoever can rewrite a chunk can rewrite
/// its leaf too; before A12 nothing tied that list to the anchored `d_ev`, and
/// such a pair passed both the sweeper and `read_verified`. Now the list's root
/// must equal the anchored root before the object is audited at all — one
/// O(n) hash pass per object, once.
#[derive(Debug, Clone)]
pub struct StoredObject {
    /// A name for findings.
    pub id: String,
    /// Where the sealed bytes live.
    pub path: PathBuf,
    d_ev: ChunkedDigest,
}

/// The leaf list handed over for an object is not the anchored `d_ev`'s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unbound {
    /// The object.
    pub object: String,
}

impl core::fmt::Display for Unbound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}: the chunk leaves do not hash to the anchored d_ev, so no spot-check against them would mean anything",
            self.object
        )
    }
}

impl core::error::Error for Unbound {}

impl StoredObject {
    /// An object for audit, **if** its chunk leaves hash to the anchored
    /// `d_ev` — `anchored` must come from the capsule or the chain, never from
    /// the leaf list itself.
    ///
    /// # Errors
    ///
    /// [`Unbound`] if the digest's root is not `anchored`.
    pub fn open(
        id: impl Into<String>,
        path: PathBuf,
        anchored: &Digest32,
        d_ev: ChunkedDigest,
    ) -> Result<Self, Unbound> {
        let id = id.into();
        if d_ev.root() != anchored {
            return Err(Unbound { object: id });
        }
        Ok(Self { id, path, d_ev })
    }

    /// The anchored chunked digest.
    #[must_use]
    pub const fn d_ev(&self) -> &ChunkedDigest {
        &self.d_ev
    }
}

/// Re-hash one chunk and compare it with the anchored leaf. Returns the bytes
/// read and whether they matched.
///
/// # Errors
///
/// An I/O error reading the object.
pub fn check_chunk(obj: &StoredObject, chunk: u64) -> io::Result<(usize, bool)> {
    let mut f = File::open(&obj.path)?;
    f.seek(SeekFrom::Start(chunk * CHUNK_BYTES as u64))?;
    let mut buf = Vec::with_capacity(CHUNK_BYTES);
    f.take(CHUNK_BYTES as u64).read_to_end(&mut buf)?;
    let want = usize::try_from(chunk)
        .ok()
        .and_then(|i| obj.d_ev.chunks().get(i));
    let ok = want.is_some_and(|w| chunk_leaf(Domain::EvidenceDigest, chunk, &buf) == *w);
    Ok((buf.len(), ok))
}

/// Q2: read `[offset, offset + len)` and verify exactly the chunks it touches.
///
/// # Errors
///
/// `Err(Ok(finding))` on a mismatch — the read is refused, not returned —
/// and `Err(Err(io))` on an I/O failure.
pub fn read_verified(
    obj: &StoredObject,
    offset: u64,
    len: u64,
) -> Result<u64, Result<Finding, io::Error>> {
    let first = offset / CHUNK_BYTES as u64;
    let last = (offset + len.max(1) - 1) / CHUNK_BYTES as u64;
    let mut read = 0u64;
    for c in first..=last {
        let (n, ok) = check_chunk(obj, c).map_err(Err)?;
        read += n as u64;
        if !ok {
            return Err(Ok(Finding::ChunkMismatch {
                object: obj.id.clone(),
                chunk: c,
            }));
        }
    }
    Ok(read)
}

/// The time `bytes` may take at `budget` bytes per second, in integers.
#[must_use]
pub fn budget_time(bytes: u64, budget: u64) -> Duration {
    let ns = u128::from(bytes) * 1_000_000_000 / u128::from(budget.max(1));
    Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
}

/// Chunks per pass for a fraction `c` of `n`: `⌈c·n⌉`, clamped to `1..=n`
/// (and 0 only when there is nothing to check).
#[must_use]
pub fn per_pass(n: usize, fraction: f64) -> usize {
    if n == 0 {
        return 0;
    }
    let c = if fraction.is_finite() {
        fraction.clamp(0.0, 1.0)
    } else {
        1.0
    };
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let k = (c * n as f64).ceil() as usize;
    k.clamp(1, n)
}

/// `SplitMix64`: the sweeper's sampling order. Seeded and recorded, so a run's
/// sample is reproducible; not a security primitive, and not used as one.
#[derive(Debug, Clone)]
pub struct SplitMix(u64);

impl SplitMix {
    /// Seeded generator.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Next value.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Q3: the budgeted sweep (§14.3), **in passes without replacement** (M13
/// A13).
///
/// Each pass checks `⌈c·n⌉` **distinct** chunks, a uniformly random subset of
/// all `n` chunks of all objects, in random order; the next pass draws afresh.
/// That is the sampling `eq:sweep` is stated for: a pass misses all `m`
/// corrupted chunks with probability `C(n−m, cn)/C(n, cn) ≤ (1−c)^m`, so `k`
/// passes miss them with probability `≤ (1−c)^{mk}` — PDP's argument for `c`
/// distinct blocks per challenge (`audit/06d` L2-b).
///
/// ⚠️ **It used to draw with replacement and had no pass at all**, which made
/// the paper's bound false for the code: one bad chunk among 100, half the
/// chunks drawn, is missed with probability `0.99^50 = 0.605`, not 0.5; and at
/// `c = 1` a "full pass" missed it 37% of the time. A deployment's priority
/// score reorders attention and is a policy, not a measurement.
#[derive(Debug)]
pub struct Sweeper {
    objects: Vec<StoredObject>,
    /// Cumulative chunk counts, for mapping a global chunk index to an object.
    offsets: Vec<u64>,
    budget_bytes_per_s: u64,
    rng: SplitMix,
    /// Every global chunk index, permuted in place by each pass's partial
    /// Fisher–Yates shuffle.
    order: Vec<u64>,
    /// Chunks checked per pass, `⌈c·n⌉` clamped to `1..=n`.
    per_pass: usize,
    /// The sampled fraction `c`, as configured.
    pub fraction: f64,
    /// Bytes read so far.
    pub bytes_read: u64,
    /// Chunks checked so far.
    pub checks: u64,
    /// Passes begun so far.
    pub passes: u64,
}

impl Sweeper {
    /// A sweeper over `objects` at `budget_bytes_per_s`, checking a fraction
    /// `fraction` of all chunks per pass.
    ///
    /// `fraction` is clamped so a pass checks at least one chunk and at most
    /// all of them; a non-finite value is treated as 1.
    #[must_use]
    pub fn new(
        objects: Vec<StoredObject>,
        budget_bytes_per_s: u64,
        seed: u64,
        fraction: f64,
    ) -> Self {
        let mut offsets = Vec::with_capacity(objects.len());
        let mut acc = 0u64;
        for o in &objects {
            acc += o.d_ev.chunk_count() as u64;
            offsets.push(acc);
        }
        let n = usize::try_from(acc).unwrap_or(usize::MAX);
        Self {
            objects,
            offsets,
            budget_bytes_per_s: budget_bytes_per_s.max(1),
            rng: SplitMix::new(seed),
            order: (0..acc).collect(),
            per_pass: per_pass(n, fraction),
            fraction,
            bytes_read: 0,
            checks: 0,
            passes: 0,
        }
    }

    /// The next pass's chunks: `⌈c·n⌉` distinct global indices, a uniformly
    /// random subset in random order.
    ///
    /// A partial Fisher–Yates shuffle: step `i` swaps a uniform pick from the
    /// positions not yet chosen into place `i`, so the chosen prefix is a
    /// uniform subset whatever order the previous pass left behind. The pick
    /// uses `% (n − i)`, whose bias is at most `n / 2⁶⁴` — immaterial at any
    /// chunk count a store has.
    pub fn next_pass(&mut self) -> &[u64] {
        self.passes += 1;
        let n = self.order.len();
        for i in 0..self.per_pass.min(n) {
            let remaining = (n - i) as u64;
            let j = i + usize::try_from(self.rng.next_u64() % remaining).unwrap_or(0);
            self.order.swap(i, j);
        }
        &self.order[..self.per_pass.min(n)]
    }

    /// Chunks under sweep.
    #[must_use]
    pub fn total_chunks(&self) -> u64 {
        self.offsets.last().copied().unwrap_or(0)
    }

    /// Sweep until `stop()` or a finding. The budget is held as an average
    /// from `start`: after each chunk, wait until the bytes read so far fit.
    ///
    /// # Errors
    ///
    /// An I/O error reading an object.
    pub fn run(&mut self, stop: &dyn Fn() -> bool) -> io::Result<Option<Finding>> {
        let total = self.total_chunks();
        if total == 0 {
            return Ok(None);
        }
        let start = Instant::now();
        let start_bytes = self.bytes_read;
        loop {
            let pass = self.next_pass().to_vec();
            for pick in pass {
                if stop() {
                    return Ok(None);
                }
                let obj_idx = self.offsets.partition_point(|&end| end <= pick);
                let base = if obj_idx == 0 {
                    0
                } else {
                    self.offsets[obj_idx - 1]
                };
                let obj = &self.objects[obj_idx];
                let chunk = pick - base;
                let (n, ok) = check_chunk(obj, chunk)?;
                self.bytes_read += n as u64;
                self.checks += 1;
                if !ok {
                    return Ok(Some(Finding::ChunkMismatch {
                        object: obj.id.clone(),
                        chunk,
                    }));
                }
                let due = budget_time(self.bytes_read - start_bytes, self.budget_bytes_per_s);
                if let Some(wait) = due.checked_sub(start.elapsed()) {
                    std::thread::sleep(wait); // xtask-allow: sleep — holding a real reader to its I/O budget is the mechanism under test, not simulated work
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_epoch::AgentWriter;
    use crate::chunked::digest_file;
    use pqcl_primitives::SoftwareMlDsa;

    fn stores() -> (
        Vec<ControlCapsule>,
        Vec<EvidenceRecord>,
        BTreeMap<u32, Vec<u8>>,
    ) {
        let mut caps = Vec::new();
        let mut recs = Vec::new();
        let mut keys = BTreeMap::new();
        for la in 0..2u32 {
            let mut a = AgentWriter::new(
                la,
                SoftwareMlDsa::generate().expect("keygen"),
                u64::from(la) << 32,
            );
            keys.insert(la, a.public_key().to_vec());
            for e in 0..3u64 {
                for i in 0..4u64 {
                    recs.push(a.append(e * 10 + i, vec![u8::try_from(i).expect("small"); 32]));
                }
                caps.push(a.close(b"u").expect("close"));
            }
        }
        (caps, recs, keys)
    }

    #[test]
    fn an_intact_store_raises_nothing() {
        let (c, r, k) = stores();
        assert!(audit_agent_epochs(&c, &r, &k).is_empty());
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn each_injected_fault_is_named() {
        let (c, r, k) = stores();
        // (i) a record deleted from the middle.
        let mut del = r.clone();
        del.retain(|x| !(x.la_id == 0 && x.epoch_la_id == 1 && x.leaf_index == 2));
        let f = audit_agent_epochs(&c, &del, &k);
        assert!(
            f.contains(&Finding::RecordDeleted {
                la_id: 0,
                epoch: 1,
                leaf_index: 2
            }),
            "{f:?}"
        );
        // truncation: the last record dropped keeps indices contiguous.
        let mut trunc = r.clone();
        trunc.retain(|x| !(x.la_id == 1 && x.epoch_la_id == 0 && x.leaf_index == 3));
        let f = audit_agent_epochs(&c, &trunc, &k);
        assert!(
            f.contains(&Finding::CountMismatch {
                la_id: 1,
                epoch: 0,
                signed: 4,
                held: 3
            }),
            "{f:?}"
        );
        // (ii) a payload altered in place.
        let mut alt = r.clone();
        alt[5].encrypted_payload[0] ^= 1;
        let (la, e, i) = (alt[5].la_id, alt[5].epoch_la_id, alt[5].leaf_index);
        assert!(
            audit_agent_epochs(&c, &alt, &k).contains(&Finding::PayloadAltered {
                la_id: la,
                epoch: e,
                leaf_index: i
            })
        );
        // (iii) payload and hash both rewritten: only the tree catches it.
        let mut rw = r.clone();
        rw[5].encrypted_payload[0] ^= 1;
        rw[5].leaf_hash = leaf_hash(rw[5].leaf_index, &rw[5].encrypted_payload);
        assert!(
            audit_agent_epochs(&c, &rw, &k).contains(&Finding::TreeMismatch {
                la_id: la,
                epoch: e
            })
        );
        // §8a.3: a whole agent-epoch omitted by the aggregator.
        let caps: Vec<ControlCapsule> = c
            .iter()
            .filter(|x| !(x.la_id == 1 && x.epoch_la_id == 1))
            .cloned()
            .collect();
        let recs: Vec<EvidenceRecord> = r
            .iter()
            .filter(|x| !(x.la_id == 1 && x.epoch_la_id == 1))
            .cloned()
            .collect();
        assert_eq!(
            audit_agent_epochs(&caps, &recs, &k),
            vec![Finding::EpochOmitted { la_id: 1, epoch: 1 }]
        );
        // σ_agent under the wrong key.
        let mut wrong = k.clone();
        wrong.insert(0, k[&1].clone());
        assert!(
            audit_agent_epochs(&c, &r, &wrong)
                .contains(&Finding::BadSignature { la_id: 0, epoch: 0 })
        );
    }

    fn object(bytes: &[u8]) -> (StoredObject, PathBuf) {
        let path =
            std::env::temp_dir().join(format!("pqcl-audit-{}-{}", std::process::id(), bytes.len()));
        std::fs::write(&path, bytes).expect("write");
        let d_ev = digest_file(&path, Domain::EvidenceDigest).expect("digest");
        let anchored = *d_ev.root();
        (
            StoredObject::open("obj", path.clone(), &anchored, d_ev).expect("bound"),
            path,
        )
    }

    #[test]
    fn a_read_verifies_only_what_it_touches_and_refuses_damage() {
        let data = vec![5u8; 3 * CHUNK_BYTES];
        let (obj, path) = object(&data);
        assert_eq!(
            read_verified(&obj, 10, 100).expect("intact"),
            CHUNK_BYTES as u64
        );
        let mut bad = data.clone();
        bad[CHUNK_BYTES * 2 + 7] ^= 0xff;
        std::fs::write(&path, &bad).expect("write");
        // Chunk 0 is still fine to read; chunk 2 is refused, and named.
        assert!(read_verified(&obj, 0, 10).is_ok());
        match read_verified(&obj, 2 * CHUNK_BYTES as u64, 10) {
            Err(Ok(f)) => assert_eq!(
                f,
                Finding::ChunkMismatch {
                    object: "obj".into(),
                    chunk: 2
                }
            ),
            other => panic!("expected the read to be refused, got {other:?}"),
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_sweeper_finds_a_corrupt_chunk_and_names_it() {
        let mut data = vec![1u8; 4 * CHUNK_BYTES];
        data[3 * CHUNK_BYTES + 1] ^= 0x80;
        let path = std::env::temp_dir().join(format!("pqcl-sweep-{}", std::process::id()));
        std::fs::write(&path, vec![1u8; 4 * CHUNK_BYTES]).expect("write");
        let d_ev = digest_file(&path, Domain::EvidenceDigest).expect("digest");
        std::fs::write(&path, &data).expect("corrupt");
        let anchored = *d_ev.root();
        let obj = StoredObject::open("cold", path.clone(), &anchored, d_ev).expect("bound");
        let mut s = Sweeper::new(vec![obj], 1 << 40, 7, 0.25);
        let found = s.run(&|| false).expect("io");
        assert_eq!(
            found,
            Some(Finding::ChunkMismatch {
                object: "cold".into(),
                chunk: 3
            })
        );
        let _ = std::fs::remove_file(path);
    }

    /// The budget is a ceiling the sweeper actually holds: the time taken is
    /// never less than bytes read over budget.
    #[test]
    fn the_sweeper_holds_its_budget() {
        let data = vec![2u8; 2 * CHUNK_BYTES];
        let path = std::env::temp_dir().join(format!("pqcl-budget-{}", std::process::id()));
        std::fs::write(&path, &data).expect("write");
        let d_ev = digest_file(&path, Domain::EvidenceDigest).expect("digest");
        let anchored = *d_ev.root();
        let obj = StoredObject::open("b", path.clone(), &anchored, d_ev).expect("bound");
        let budget = 8 * CHUNK_BYTES as u64; // 8 MiB/s
        let mut s = Sweeper::new(vec![obj], budget, 1, 1.0);
        let t = Instant::now();
        let checks = std::cell::Cell::new(0u32);
        let _ = s.run(&|| {
            checks.set(checks.get() + 1);
            checks.get() > 12
        });
        let floor = budget_time(s.bytes_read, budget);
        assert!(
            t.elapsed() + Duration::from_millis(5) >= floor,
            "{:?} < {floor:?}",
            t.elapsed()
        );
        let _ = std::fs::remove_file(path);
    }

    /// A sweeper over `n` single-chunk objects, for sampling tests that need
    /// no I/O: `next_pass` never touches the objects.
    fn sampler(n: usize, fraction: f64, seed: u64) -> Sweeper {
        let mut s = Sweeper::new(Vec::new(), 1, seed, fraction);
        s.order = (0..n as u64).collect();
        s.per_pass = per_pass(n, fraction);
        s
    }

    #[test]
    fn a_pass_draws_distinct_chunks_and_exactly_its_share() {
        for (n, c, want) in [
            (100, 0.05, 5),
            (100, 0.5, 50),
            (7, 0.5, 4),
            (10, 1.0, 10),
            (10, 0.0, 1),
        ] {
            let mut s = sampler(n, c, 3);
            for _ in 0..50 {
                let pass = s.next_pass().to_vec();
                assert_eq!(pass.len(), want, "n={n} c={c}");
                let distinct: std::collections::BTreeSet<_> = pass.iter().collect();
                assert_eq!(distinct.len(), pass.len(), "a pass repeated a chunk");
                assert!(pass.iter().all(|&i| i < n as u64));
            }
        }
    }

    /// ⭐ The property the with-replacement sampler broke most visibly: at
    /// `c = 1` a pass checks every chunk, so it cannot miss. The old sampler
    /// missed one bad chunk in `n` draws about 37% of the time.
    #[test]
    fn a_full_pass_cannot_miss() {
        let mut s = sampler(100, 1.0, 11);
        for _ in 0..200 {
            let pass: std::collections::BTreeSet<u64> = s.next_pass().iter().copied().collect();
            assert_eq!(pass.len(), 100);
        }
    }

    /// ⭐ **Acceptance A13: the per-pass miss rate against the bound.**
    ///
    /// For `m` corrupted chunks among `n`, a pass of `cn` distinct chunks
    /// misses all of them with probability `C(n−m, cn)/C(n, cn)`, which is at
    /// most `(1−c)^m`. Over `T` seeded passes the observed miss rate must sit
    /// within four standard errors of that exact value, and below the bound.
    /// The audit's own counterexample (`n = 100`, `m = 1`, `c = 0.5`, where the
    /// old sampler missed 60.5% of the time) is one of the cases.
    #[test]
    fn the_per_pass_miss_rate_matches_pdps_bound() {
        const T: usize = 20_000;
        for (n, m, c) in [
            (100usize, 1usize, 0.5f64),
            (100, 3, 0.25),
            (200, 2, 0.05),
            (50, 5, 0.1),
        ] {
            let mut s = sampler(n, c, 0xA13 + n as u64 + m as u64);
            let k = s.per_pass;
            let bad: Vec<u64> = (0..m as u64).collect();
            let mut missed = 0usize;
            for _ in 0..T {
                if !s.next_pass().iter().any(|i| bad.contains(i)) {
                    missed += 1;
                }
            }
            #[allow(clippy::cast_precision_loss)]
            let observed = missed as f64 / T as f64;
            // Exact: product over the m bad chunks of (n − k − j)/(n − j).
            #[allow(clippy::cast_precision_loss)]
            let exact: f64 = (0..m)
                .map(|j| (n - k - j) as f64 / (n - j) as f64)
                .product();
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_possible_wrap
            )]
            let bound = (1.0 - k as f64 / n as f64).powi(m as i32);
            #[allow(clippy::cast_precision_loss)]
            let se = (exact * (1.0 - exact) / T as f64).sqrt();
            assert!(
                (observed - exact).abs() <= 4.0 * se + 1e-9,
                "n={n} m={m} c={c}: observed {observed:.4}, exact {exact:.4}"
            );
            assert!(
                observed <= bound + 4.0 * se,
                "n={n} m={m} c={c}: observed {observed:.4} exceeds the bound {bound:.4}"
            );
        }
    }

    /// ⭐ **Acceptance A12: a leaf list rewritten with its chunk is refused.**
    ///
    /// The attack `audit/06d` L2-a describes: whoever can rewrite a stored
    /// chunk can rewrite its stored leaf too, and a spot-check compares the one
    /// against the other. The forged list hashes to a different root, so it is
    /// refused before any spot-check runs; the genuine list is accepted, and the
    /// sweeper over it then finds the damaged chunk.
    #[test]
    fn a_leaf_list_rewritten_with_its_chunk_is_refused() {
        let path = std::env::temp_dir().join(format!("pqcl-a12-{}", std::process::id()));
        std::fs::write(&path, vec![5u8; 3 * CHUNK_BYTES]).expect("write");
        let genuine = digest_file(&path, Domain::EvidenceDigest).expect("digest");
        let anchored = *genuine.root();

        // Rewrite chunk 1, and the leaf list to match it.
        let mut data = vec![5u8; 3 * CHUNK_BYTES];
        data[CHUNK_BYTES + 7] ^= 0x01;
        std::fs::write(&path, &data).expect("tamper");
        let forged = digest_file(&path, Domain::EvidenceDigest).expect("digest");
        assert_eq!(
            forged.chunks()[0],
            genuine.chunks()[0],
            "the untouched chunk's leaf is unchanged"
        );

        assert_eq!(
            StoredObject::open("x", path.clone(), &anchored, forged).map(|o| o.id),
            Err(Unbound { object: "x".into() }),
            "a list that does not hash to the anchored d_ev was accepted"
        );

        let obj = StoredObject::open("x", path.clone(), &anchored, genuine).expect("bound");
        let mut s = Sweeper::new(vec![obj], 1 << 40, 3, 1.0);
        assert_eq!(
            s.run(&|| false).expect("io"),
            Some(Finding::ChunkMismatch {
                object: "x".into(),
                chunk: 1
            })
        );
        let _ = std::fs::remove_file(path);
    }

    // ---------------------------------------------------- heartbeats (M13 A6)

    /// Two agents, three closed epochs each, a beat after every close.
    fn beating() -> (Vec<ControlCapsule>, Vec<Heartbeat>, BTreeMap<u32, Vec<u8>>) {
        let (mut caps, mut beats, mut keys) = (Vec::new(), Vec::new(), BTreeMap::new());
        for la in 0..2u32 {
            let mut a = AgentWriter::new(
                la,
                pqcl_primitives::SoftwareMlDsa::generate().expect("keygen"),
                0,
            );
            keys.insert(la, a.public_key().to_vec());
            for e in 0..3u64 {
                a.append(e * 10, vec![u8::try_from(e).expect("small"); 8]);
                caps.push(a.close(b"u").expect("close"));
                beats.push(a.heartbeat(100 + e * 5).expect("beat"));
            }
        }
        (caps, beats, keys)
    }

    /// ⭐ **Acceptance A6 (a): a dropped last epoch is caught by the next
    /// beat**, where contiguity sees nothing.
    #[test]
    fn a_dropped_tail_epoch_is_caught_by_the_heartbeat_and_not_by_contiguity() {
        let (caps, beats, keys) = beating();
        assert!(
            audit_heartbeats(&caps, &beats, &keys, 110, 5).is_empty(),
            "intact store alarmed"
        );
        let dropped: Vec<ControlCapsule> = caps
            .iter()
            .filter(|c| !(c.la_id == 1 && c.epoch_la_id == 2))
            .cloned()
            .collect();
        assert!(
            !audit_agent_epochs(&dropped, &[], &keys)
                .iter()
                .any(|f| matches!(f, Finding::EpochOmitted { .. })),
            "contiguity saw a dropped tail: the test is not testing the gap A6 closes"
        );
        assert_eq!(
            audit_heartbeats(&dropped, &beats, &keys, 110, 5),
            vec![Finding::TailOmitted { la_id: 1, epoch: 2 }]
        );
    }

    /// ⭐ **Acceptance A6 (b): an interior gap is still caught**, by
    /// contiguity, and the heartbeat adds no false tail for it.
    #[test]
    fn an_interior_gap_is_still_caught_and_is_not_a_tail() {
        let (caps, beats, keys) = beating();
        let dropped: Vec<ControlCapsule> = caps
            .iter()
            .filter(|c| !(c.la_id == 0 && c.epoch_la_id == 1))
            .cloned()
            .collect();
        assert!(
            audit_agent_epochs(&dropped, &[], &keys)
                .contains(&Finding::EpochOmitted { la_id: 0, epoch: 1 })
        );
        assert!(
            audit_heartbeats(&dropped, &beats, &keys, 110, 5).is_empty(),
            "an interior gap was reported as a tail"
        );
    }

    /// Silence longer than `T` alarms, and a forged beat is refused rather
    /// than counted — so a forged count cannot raise or hide a tail.
    #[test]
    fn silence_and_forged_beats_are_findings() {
        let (caps, mut beats, keys) = beating();
        let f = audit_heartbeats(&caps, &beats, &keys, 200, 5);
        assert!(f.contains(&Finding::HeartbeatGap {
            la_id: 0,
            from: Some(110),
            to: 200
        }));
        assert!(f.contains(&Finding::HeartbeatGap {
            la_id: 1,
            from: Some(110),
            to: 200
        }));

        let mut forged = beats[0].clone();
        forged.counter = 9;
        beats.push(forged);
        let f = audit_heartbeats(&caps, &beats, &keys, 110, 5);
        assert!(f.contains(&Finding::BadHeartbeat { la_id: 0, ts: 100 }));
        assert!(
            !f.iter().any(|x| matches!(x, Finding::TailOmitted { .. })),
            "a forged count raised a tail"
        );
    }

    // ---------------------------------------------- the 0x07 leaf (M13 A17)

    /// ⭐ **A17: a control capsule the AIS accepted but kept out of the anchor
    /// is a finding**, and every anchored one passes, verifying against the
    /// epoch's root as a `0x07` leaf.
    #[test]
    fn an_agent_epoch_kept_out_of_the_anchor_is_a_finding() {
        let mut a = AgentWriter::new(4, SoftwareMlDsa::generate().expect("keygen"), 0);
        let mut caps = Vec::new();
        for e in 0..3u64 {
            a.append(e, vec![7; 8]);
            caps.push(a.close(b"u").expect("close"));
        }
        let mut ais = crate::Ais::new();
        // The AIS anchors the first two and withholds the third.
        let at: Vec<_> = caps[..2]
            .iter()
            .map(|c| ais.record_agent_epoch(c))
            .collect();
        let root = ais.close_epoch();
        let proof = ais.prove(&at[1]).expect("anchored");
        assert!(pqcl_forest::tier2::verify(&root, &caps[1].leaf(), &proof));
        assert_eq!(
            caps[1].leaf().domain,
            pqcl_primitives::xof::Domain::AgentEpochRoot
        );

        let anchored: std::collections::HashSet<Digest32> = ais
            .closed_epochs()
            .first()
            .expect("closed epoch")
            .leaf_digests()
            .iter()
            .copied()
            .collect();
        assert!(audit_agent_epochs_anchored(&caps[..2], &anchored).is_empty());
        assert_eq!(
            audit_agent_epochs_anchored(&caps, &anchored),
            vec![Finding::AgentEpochNotAnchored { la_id: 4, epoch: 2 }]
        );
    }
}
