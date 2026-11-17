//! The evidence-plane ingest path of design §8a: an unsigned record stream,
//! one signed control capsule per agent-epoch, and the `0x07` leaf.
//!
//! # Two channels, and only one of them signs (§8a.1)
//!
//! ```text
//! Evidence stream  — per log record, NO signature
//!   { log_id, epoch_la_id, la_id, ts, leaf_index, leaf_hash, encrypted_payload, status }
//! Control capsule  — per agent-epoch, ONE ML-DSA signature
//!   { la_id, epoch_la_id, ts_start, ts_end, log_count, R_agent, storage_uri, σ_agent }
//! ```
//!
//! ⭐ **`σ_agent` covers `log_count`.** Without it, deleting the last `k`
//! records of an epoch leaves `leaf_index` contiguous and the truncation is
//! invisible; with it, the count disagrees.
//!
//! ⚠️ **Vocabulary.** "Agent-epoch tree" and "manager-epoch aggregation" are
//! *not* our Tier 1/2/3. The agent-epoch root enters the
//! Tier-2 MMR as one `0x07` leaf; nothing is renumbered.

use pqcl_capsule::Writer;
use pqcl_forest::{CustodyTree, Leaf};
use pqcl_primitives::xof::{Digest32, Domain, hash_domain};
use pqcl_primitives::{Signer, SoftwareMlDsa};

/// Verification state, a first-class column on both stores (§8a.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Never checked.
    Unverified,
    /// Checked and intact.
    Verified,
    /// Checked and failed: blocks the capsule from disclosure until adjudicated.
    NotMatch,
}

/// One evidence-stream record. Deliberately unsigned (§8a.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// Globally unique record id.
    pub log_id: u64,
    /// The agent that produced it.
    pub la_id: u32,
    /// That agent's epoch counter.
    pub epoch_la_id: u64,
    /// Agent timestamp.
    pub ts: u64,
    /// Position within the agent-epoch, from 0.
    pub leaf_index: u64,
    /// [`leaf_hash`] of the payload.
    pub leaf_hash: Digest32,
    /// The sealed record.
    pub encrypted_payload: Vec<u8>,
    /// Verification state.
    pub status: Status,
}

/// `leaf_hash = H(0x20 ‖ leaf_index ‖ encrypted_payload)`.
///
/// Under the evidence-digest tag with the index bound in, exactly as a chunk
/// leaf is (`chunked::chunk_leaf`): both are digests of ciphertext at a
/// position, and a checker that holds no key can recompute either.
#[must_use]
pub fn leaf_hash(leaf_index: u64, payload: &[u8]) -> Digest32 {
    hash_domain(
        Domain::EvidenceDigest,
        &[&leaf_index.to_le_bytes(), payload],
    )
}

/// The agent-epoch tree root over leaf hashes, in `leaf_index` order.
///
/// Built on the forest's tree, so an unpaired node is promoted, never
/// duplicated (CVE-2012-2459), as everywhere else.
#[must_use]
pub fn r_agent(leaf_hashes: &[Digest32]) -> Digest32 {
    let mut t = CustodyTree::new();
    for h in leaf_hashes {
        t.append_leaf(*h);
    }
    t.root()
        .unwrap_or_else(|| hash_domain(Domain::AgentEpochRoot, &[b"empty agent-epoch"]))
}

/// One agent-epoch's control capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCapsule {
    /// Agent.
    pub la_id: u32,
    /// Its epoch counter — contiguous per agent, or an epoch was dropped.
    pub epoch_la_id: u64,
    /// First record's timestamp.
    pub ts_start: u64,
    /// Last record's timestamp.
    pub ts_end: u64,
    /// Records in the epoch. Signed.
    pub log_count: u64,
    /// Agent-epoch tree root. Signed.
    pub r_agent: Digest32,
    /// Where the records were written. Not signed: storage may move.
    pub storage_uri: Vec<u8>,
    /// ML-DSA-65 over [`ControlCapsule::signed_bytes`].
    pub sig_agent: Vec<u8>,
}

impl ControlCapsule {
    /// What `σ_agent` covers: everything but the storage location and itself,
    /// framed so adjacent fields cannot trade bytes.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(&self.la_id.to_le_bytes())
            .u64(self.epoch_la_id)
            .u64(self.ts_start)
            .u64(self.ts_end)
            .u64(self.log_count)
            .field(&self.r_agent);
        w.finish()
    }

    /// The Tier-2 `0x07` leaf:
    /// `0x07 ‖ H(la_id ‖ epoch_la_id ‖ R_agent ‖ log_count ‖ ts_start ‖ ts_end ‖ σ_agent)`.
    #[must_use]
    pub fn leaf(&self) -> Leaf {
        Leaf::new(
            Domain::AgentEpochRoot,
            &[
                &self.la_id.to_le_bytes(),
                &self.epoch_la_id.to_le_bytes(),
                &self.r_agent,
                &self.log_count.to_le_bytes(),
                &self.ts_start.to_le_bytes(),
                &self.ts_end.to_le_bytes(),
                &self.sig_agent,
            ],
        )
    }
}

/// A signed liveness beat (M13 A6, `audit/06` D5, W36).
///
/// ⭐ **What contiguity cannot see.** `epoch_la_id` contiguity catches a dropped
/// *interior* epoch, because the next one's counter jumps. A dropped **last**
/// epoch leaves every counter the store holds contiguous, so nothing jumps,
/// and the aggregator can hide the agent's most recent work indefinitely. The
/// heartbeat carries the count of epochs the agent has *closed*, signed, every
/// `T ≪ Δ`. A beat whose count runs ahead of the epochs the store holds is the
/// tail omission, and a missing beat is the agent going silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    /// Agent.
    pub la_id: u32,
    /// Epochs this agent has closed when it beat: the next `epoch_la_id`.
    pub counter: u64,
    /// When it beat, in seconds.
    pub ts: u64,
    /// ML-DSA-65 over [`Heartbeat::signed_bytes`], by the agent's own key.
    pub sig_agent: Vec<u8>,
}

impl Heartbeat {
    /// `⟪"pqcl/heartbeat", la_id, counter, ts⟫`. The label is the first field,
    /// so these bytes can never parse as a control capsule's, which the same
    /// key signs.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(b"pqcl/heartbeat")
            .field(&self.la_id.to_le_bytes())
            .u64(self.counter)
            .u64(self.ts);
        w.finish()
    }
}

/// An Edge Log Agent's evidence-plane writer.
pub struct AgentWriter {
    la_id: u32,
    epoch: u64,
    next_log_id: u64,
    signer: SoftwareMlDsa,
    open: Vec<EvidenceRecord>,
}

impl AgentWriter {
    /// An agent with its signing key. `first_log_id` keeps ids unique across
    /// agents.
    #[must_use]
    pub const fn new(la_id: u32, signer: SoftwareMlDsa, first_log_id: u64) -> Self {
        Self {
            la_id,
            epoch: 0,
            next_log_id: first_log_id,
            signer,
            open: Vec::new(),
        }
    }

    /// The agent's verification key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.signer.public_key()
    }

    /// A signed heartbeat at `ts`, carrying the epochs closed so far.
    ///
    /// # Errors
    ///
    /// A signing failure.
    pub fn heartbeat(&self, ts: u64) -> Result<Heartbeat, Box<dyn core::error::Error>> {
        let mut h = Heartbeat {
            la_id: self.la_id,
            counter: self.epoch,
            ts,
            sig_agent: Vec::new(),
        };
        h.sig_agent = self.signer.sign(&h.signed_bytes())?;
        Ok(h)
    }

    /// Emit one record into the open epoch — no signature.
    pub fn append(&mut self, ts: u64, encrypted_payload: Vec<u8>) -> EvidenceRecord {
        let leaf_index = self.open.len() as u64;
        let r = EvidenceRecord {
            log_id: self.next_log_id,
            la_id: self.la_id,
            epoch_la_id: self.epoch,
            ts,
            leaf_index,
            leaf_hash: leaf_hash(leaf_index, &encrypted_payload),
            encrypted_payload,
            status: Status::Unverified,
        };
        self.next_log_id += 1;
        self.open.push(r.clone());
        r
    }

    /// Close the epoch: build `R_agent` from what **this agent sent** — not
    /// from what any store holds — and sign it with the count (§8a.1).
    ///
    /// # Errors
    ///
    /// A signing failure.
    pub fn close(
        &mut self,
        storage_uri: &[u8],
    ) -> Result<ControlCapsule, Box<dyn core::error::Error>> {
        let hashes: Vec<Digest32> = self.open.iter().map(|r| r.leaf_hash).collect();
        let mut c = ControlCapsule {
            la_id: self.la_id,
            epoch_la_id: self.epoch,
            ts_start: self.open.first().map_or(0, |r| r.ts),
            ts_end: self.open.last().map_or(0, |r| r.ts),
            log_count: self.open.len() as u64,
            r_agent: r_agent(&hashes),
            storage_uri: storage_uri.to_vec(),
            sig_agent: Vec::new(),
        };
        c.sig_agent = self.signer.sign(&c.signed_bytes())?;
        self.open.clear();
        self.epoch += 1;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: u32) -> AgentWriter {
        AgentWriter::new(
            id,
            SoftwareMlDsa::generate().expect("keygen"),
            u64::from(id) << 32,
        )
    }

    #[test]
    fn an_epoch_signs_its_root_and_its_count() {
        let mut a = agent(1);
        for i in 0..5u64 {
            a.append(100 + i, vec![u8::try_from(i).expect("small"); 16]);
        }
        let c = a.close(b"s3://store/1/0").expect("close");
        assert_eq!((c.la_id, c.epoch_la_id, c.log_count), (1, 0, 5));
        assert_eq!((c.ts_start, c.ts_end), (100, 104));
        pqcl_primitives::sig::verify(&c.signed_bytes(), &c.sig_agent, a.public_key(), b"")
            .expect("σ_agent verifies");
        // The count is covered: change it and the signature no longer holds.
        let mut truncated = c.clone();
        truncated.log_count = 4;
        assert!(
            pqcl_primitives::sig::verify(
                &truncated.signed_bytes(),
                &truncated.sig_agent,
                a.public_key(),
                b""
            )
            .is_err()
        );
    }

    #[test]
    fn epochs_count_up_and_records_restart_at_leaf_zero() {
        let mut a = agent(2);
        a.append(1, vec![1]);
        let c0 = a.close(b"u").expect("close");
        let r = a.append(2, vec![2]);
        let c1 = a.close(b"u").expect("close");
        assert_eq!((c0.epoch_la_id, c1.epoch_la_id), (0, 1));
        assert_eq!((r.epoch_la_id, r.leaf_index), (1, 0));
    }

    #[test]
    fn the_leaf_is_domain_separated_and_binds_the_signature() {
        let mut a = agent(3);
        a.append(1, vec![9; 8]);
        let c = a.close(b"u").expect("close");
        let mut other = c.clone();
        other.sig_agent[0] ^= 1;
        assert_ne!(c.leaf(), other.leaf());
        // Moving storage does not change what is anchored.
        let mut moved = c.clone();
        moved.storage_uri = b"s3://elsewhere".to_vec();
        assert_eq!(c.leaf(), moved.leaf());
    }
}
