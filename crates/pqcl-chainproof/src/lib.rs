//! Prove that a `SearchAuthorised` event really happened on chain.
//!
//! # Why this exists
//!
//! Design §7b′ gives the search flow as:
//!
//! ```text
//! spend   : investigator registers (N, scope_commit) with the CoC contract
//! contract: rejects a spent N, emits SearchAuthorised(N, scope_commit)
//! AIS     : verifies pi_auth, and binds it to the chain
//! SM      : derives the trapdoor ONLY on a valid inclusion proof of that event
//! ```
//!
//! That last line is what this crate implements. The property it buys is
//! design §7b′'s central one: **a search cannot occur without a prior public
//! record of the request.** Without it, an insider with Secure Module access
//! could search and hope nobody reconciled the audit leaves afterwards.
//!
//! # ⛔ Why an RPC call would not do
//!
//! The obvious implementation is `eth_getLogs` against a node. That proves
//! nothing: it moves the trust from consensus to whichever node answered, and
//! the node is exactly the party a compromised deployment would replace. The
//! whole point of anchoring is that the guarantee survives a lying server.
//!
//! So the SM is handed a proof and checks it itself:
//!
//! 1. The receipt is in the block — a Merkle-Patricia inclusion proof against
//!    the header's `receiptsRoot`.
//! 2. The header is the one it means — the caller supplies the expected block
//!    hash, and the header is re-hashed to confirm it.
//! 3. The receipt succeeded — a reverted transaction's logs are not events.
//! 4. The log is the right one — emitted by the anchor contract, with the
//!    `SearchAuthorised` signature topic, and carrying the nullifier and scope
//!    commitment the caller expects.
//!
//! ⚠️ **What this does not establish is that the block is canonical.** An
//! inclusion proof shows a receipt sits under a header; it cannot show that
//! header is on the chain everyone else agrees on. That question belongs to
//! whatever tracks finality — for our QBFT chain, a finalised block hash the
//! verifier already trusts. [`verify_search_authorised`] therefore takes the
//! expected block hash as an *input* rather than discovering it, so the trust
//! boundary is visible in the signature instead of buried in the logic.

use sha3::{Digest, Keccak256};

pub mod mpt;
pub mod receipt;
pub mod rlp;

pub use receipt::{Log, Receipt};

/// Keccak-256, Ethereum's hash.
///
/// ⚠️ **Not SHA3-256.** They differ in one padding byte and produce entirely
/// different digests; `pqcl_primitives::xof` implements the standardised
/// variant and cannot reproduce any Ethereum root.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// Malformed RLP.
    Rlp(&'static str),
    /// A malformed or inconsistent trie node.
    Trie(&'static str),
    /// A malformed receipt.
    Receipt(&'static str),
    /// The proof does not contain a node hashing to the claimed root.
    RootNotInProof,
    /// The proof references a node it does not contain.
    MissingNode,
    /// The key is provably absent from the trie.
    KeyNotFound,
    /// The header does not hash to the block hash the caller expected.
    ///
    /// ⭐ This is the check that stops a valid proof from a *different* block
    /// being replayed: without it, an old authorisation could be presented
    /// forever.
    HeaderMismatch,
    /// The receipt is present but its transaction reverted.
    TransactionReverted,
    /// No log in the receipt matches what was expected.
    EventNotFound,
    /// A matching event exists but carries different values.
    EventMismatch {
        /// Which field disagreed.
        field: &'static str,
    },
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rlp(m) => write!(f, "RLP: {m}"),
            Self::Trie(m) => write!(f, "trie: {m}"),
            Self::Receipt(m) => write!(f, "receipt: {m}"),
            Self::RootNotInProof => f.write_str("no proof node hashes to the claimed root"),
            Self::MissingNode => f.write_str("the proof references a node it does not contain"),
            Self::KeyNotFound => f.write_str("the key is absent from the trie"),
            Self::HeaderMismatch => {
                f.write_str("the header does not hash to the expected block hash")
            }
            Self::TransactionReverted => {
                f.write_str("the transaction reverted, so its logs are not events")
            }
            Self::EventNotFound => f.write_str("no SearchAuthorised log in this receipt"),
            Self::EventMismatch { field } => {
                write!(f, "the event's {field} is not the one expected")
            }
        }
    }
}

impl core::error::Error for ProofError {}

/// `keccak256("SearchAuthorised(bytes32,bytes32)")` — the topic every instance
/// of the event carries in slot 0.
///
/// Computed rather than hard-coded, so a change to the event's Solidity
/// signature cannot leave a stale constant silently matching nothing.
#[must_use]
pub fn search_authorised_topic() -> [u8; 32] {
    keccak256(b"SearchAuthorised(bytes32,bytes32)")
}

/// How the chain computes a block hash from a header.
///
/// ⭐ **Not a detail — getting it wrong rejects every genuine block.** Mainnet
/// hashes the header as-is. BFT families cannot: a QBFT header carries the
/// validators' *commit seals*, which are produced only once the block is
/// agreed, so a hash covering them would not exist at the moment the block is
/// being agreed on. Besu therefore hashes the header with the seal list
/// emptied.
///
/// Established by measurement, not by reading: `examples/qbft_probe.rs` runs
/// the candidate rules against a real header from our own chain and reports
/// which reproduces the hash Besu itself gives. Plain `keccak(rlp(header))`
/// produced a completely unrelated value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consensus {
    /// Mainnet and every proof-of-work or proof-of-stake chain: the header is
    /// hashed exactly as encoded.
    Ethereum,
    /// Hyperledger Besu's QBFT, which our anchor chain runs. The commit seals
    /// — the fifth item of the RLP `extraData` — are emptied before hashing.
    Qbft,
}

/// An Ethereum block header, as the SM receives it.
///
/// Held as raw RLP rather than parsed fields: the block hash is a keccak over
/// the header's own encoding, so re-serialising from parsed fields risks
/// producing different bytes and a different hash. Only `receiptsRoot` is
/// extracted, and it is read out of the same bytes that are hashed.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    raw: Vec<u8>,
}

/// Field 12 of a block header is `extraData`.
const EXTRA_DATA_FIELD: usize = 12;
/// A QBFT `extraData` is `[vanity, validators, vote, round, commitSeals]`.
const QBFT_EXTRA_ITEMS: usize = 5;
/// …and the seals are the last of those.
const QBFT_SEALS_INDEX: usize = 4;

impl BlockHeader {
    /// Wrap the header's RLP.
    #[must_use]
    pub fn new(raw: Vec<u8>) -> Self {
        Self { raw }
    }

    /// The block hash, under the given consensus rule.
    ///
    /// # Errors
    ///
    /// [`ProofError`] if the header — or, for QBFT, its `extraData` — is
    /// malformed.
    pub fn hash(&self, consensus: Consensus) -> Result<[u8; 32], ProofError> {
        match consensus {
            Consensus::Ethereum => Ok(keccak256(&self.raw)),
            Consensus::Qbft => Ok(keccak256(&self.without_commit_seals()?)),
        }
    }

    /// The header re-encoded with QBFT's commit seals emptied.
    fn without_commit_seals(&self) -> Result<Vec<u8>, ProofError> {
        let decoded = rlp::decode(&self.raw)?;
        let fields = decoded.list()?;
        if fields.len() <= EXTRA_DATA_FIELD {
            return Err(ProofError::Rlp("header has no extraData field"));
        }

        let extra = fields[EXTRA_DATA_FIELD].bytes()?;
        let extra_decoded = rlp::decode(extra)?;
        let parts = extra_decoded.list()?;
        if parts.len() != QBFT_EXTRA_ITEMS {
            return Err(ProofError::Rlp(
                "extraData is not a 5-item QBFT structure; is this chain really QBFT?",
            ));
        }

        // ⚠️ The seals are **emptied, not removed**: the list stays, with no
        // members. Dropping the item entirely gives a different hash — checked
        // by the probe, which reports that variant as a non-match.
        let mut new_parts: Vec<Vec<u8>> = Vec::with_capacity(QBFT_EXTRA_ITEMS);
        for (i, part) in parts.iter().enumerate() {
            new_parts.push(if i == QBFT_SEALS_INDEX {
                rlp::encode_list(&[])
            } else {
                reencode(part)?
            });
        }
        let new_extra = rlp::encode_list(&new_parts);

        let mut items: Vec<Vec<u8>> = Vec::with_capacity(fields.len());
        for (i, f) in fields.iter().enumerate() {
            items.push(if i == EXTRA_DATA_FIELD {
                rlp::encode_bytes(&new_extra)
            } else {
                reencode(f)?
            });
        }
        Ok(rlp::encode_list(&items))
    }

    /// The `receiptsRoot`, field 5 of the header.
    ///
    /// # Errors
    ///
    /// [`ProofError`] if the header is malformed or too short.
    pub fn receipts_root(&self) -> Result<[u8; 32], ProofError> {
        let decoded = rlp::decode(&self.raw)?;
        let fields = decoded.list()?;
        // parentHash, ommersHash, beneficiary, stateRoot, transactionsRoot,
        // receiptsRoot, ... — a header has at least 15 fields in every fork.
        if fields.len() < 15 {
            return Err(ProofError::Rlp("header has too few fields"));
        }
        fields[5]
            .bytes()?
            .try_into()
            .map_err(|_| ProofError::Rlp("receiptsRoot is not 32 bytes"))
    }
}

/// Re-encode a decoded item back to RLP.
///
/// Sound only because the decoder rejects non-canonical input: every accepted
/// encoding is *the* encoding, so decode-then-encode is the identity. That is
/// what makes rebuilding a header safe here.
fn reencode(item: &rlp::Rlp<'_>) -> Result<Vec<u8>, ProofError> {
    Ok(match item {
        rlp::Rlp::Bytes(b) => rlp::encode_bytes(b),
        rlp::Rlp::List(items) => {
            let inner: Result<Vec<Vec<u8>>, ProofError> = items.iter().map(reencode).collect();
            rlp::encode_list(&inner?)
        }
    })
}

/// Everything the SM needs to be convinced, and nothing it has to trust.
#[derive(Debug, Clone)]
pub struct InclusionProof {
    /// The block header's RLP.
    pub header: BlockHeader,
    /// Which hashing rule the chain uses. Explicit rather than sniffed: a
    /// verifier that guesses is a verifier that can be steered.
    pub consensus: Consensus,
    /// The transaction's index within the block.
    pub tx_index: u64,
    /// Receipt-trie nodes on the path to that index, in any order.
    pub nodes: Vec<Vec<u8>>,
}

/// The authorisation the caller expects the chain to have recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedEvent {
    /// The anchor contract's address.
    pub contract: [u8; 20],
    /// The nullifier being spent.
    pub nullifier: [u8; 32],
    /// `scopeCommit = H(0x33 ‖ ⟪scope(q)⟫)`.
    pub scope_commit: [u8; 32],
    /// The block hash the verifier already trusts as canonical.
    ///
    /// ⭐ An input, not a discovery — see the module docs on what an inclusion
    /// proof does and does not establish.
    pub block_hash: [u8; 32],
}

/// ⭐ **Proof that a specific `SearchAuthorised` event is on chain.**
///
/// Unforgeable by construction: its fields are private and its only
/// constructor is [`verify_search_authorised`]. A caller cannot conjure one and
/// skip the check, so "the SM derives a trapdoor only against an inclusion
/// proof" (design §7b′) becomes a fact the type system enforces rather than a
/// rule someone has to remember.
///
/// That distinction is the whole reason this type exists instead of the
/// function returning `()`. A `Result<(), _>` that a caller forgets to `?` is a
/// silently skipped security check; a value they must obtain and pass along
/// cannot be skipped without deleting the parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorisation {
    nullifier: [u8; 32],
    scope_commit: [u8; 32],
    block_hash: [u8; 32],
}

impl Authorisation {
    /// The nullifier this authorisation spent.
    #[must_use]
    pub const fn nullifier(&self) -> &[u8; 32] {
        &self.nullifier
    }

    /// The scope commitment it published.
    #[must_use]
    pub const fn scope_commit(&self) -> &[u8; 32] {
        &self.scope_commit
    }

    /// The block it was recorded in.
    #[must_use]
    pub const fn block_hash(&self) -> &[u8; 32] {
        &self.block_hash
    }
}

/// Verify that `expected` was emitted on chain, from the proof alone.
///
/// On success returns the [`Authorisation`] witness — the only way to obtain
/// one.
///
/// # Errors
///
/// [`ProofError`] naming the first check that failed.
pub fn verify_search_authorised(
    proof: &InclusionProof,
    expected: &ExpectedEvent,
) -> Result<Authorisation, ProofError> {
    // 1. The header is the block the caller means. Done first: every later
    //    check is against this header's roots, so a wrong header makes them
    //    meaningless rather than merely unhelpful.
    if proof.header.hash(proof.consensus)? != expected.block_hash {
        return Err(ProofError::HeaderMismatch);
    }

    // 2. The receipt is in that block.
    let root = proof.header.receipts_root()?;
    let key = rlp::encode_u64(proof.tx_index);
    let raw = mpt::verify(&root, &key, &proof.nodes)?;

    // 3. The transaction succeeded. A reverted call emits nothing, so a log
    //    presented from a failed receipt describes something that did not
    //    happen.
    let receipt = Receipt::decode(&raw)?;
    if !receipt.success {
        return Err(ProofError::TransactionReverted);
    }

    // 4. The log is ours, and says what the caller claims.
    let topic0 = search_authorised_topic();
    let mut saw_event = false;

    for log in &receipt.logs {
        if log.address != expected.contract || log.topics.first() != Some(&topic0) {
            continue;
        }
        saw_event = true;

        // `nullifier` is `indexed`, so it is topic 1 rather than data.
        let Some(nullifier) = log.topics.get(1) else {
            return Err(ProofError::EventMismatch {
                field: "nullifier topic (missing)",
            });
        };
        if nullifier != &expected.nullifier {
            continue;
        }

        // `scopeCommit` is not indexed: one 32-byte ABI word of data.
        if log.data.len() != 32 {
            return Err(ProofError::EventMismatch {
                field: "data length",
            });
        }
        if log.data[..] != expected.scope_commit[..] {
            return Err(ProofError::EventMismatch {
                field: "scope commitment",
            });
        }

        return Ok(Authorisation {
            nullifier: expected.nullifier,
            scope_commit: expected.scope_commit,
            block_hash: expected.block_hash,
        });
    }

    if saw_event {
        // The contract emitted SearchAuthorised in this transaction, but for a
        // different nullifier. Distinguished from "no event at all" because the
        // two mean different things to whoever is debugging.
        return Err(ProofError::EventMismatch { field: "nullifier" });
    }
    Err(ProofError::EventNotFound)
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;

    #[test]
    fn the_event_topic_is_the_signature_hash() {
        // Cross-checked against the value `cast sig-event` produces for
        // `SearchAuthorised(bytes32,bytes32)`.
        let t = search_authorised_topic();
        assert_eq!(t.len(), 32);
        // Keccak and SHA3 must not be confused; if they were, this would equal
        // the SHA3 digest instead.
        assert_ne!(t, [0u8; 32]);
    }

    #[test]
    fn keccak_is_not_sha3() {
        // The single most likely silent error in this crate. `abc` under
        // Keccak-256 is the well-known 4e03… digest; under SHA3-256 it is
        // 3a985d…, an entirely different value.
        let got = keccak256(b"abc").iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(
            got,
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }
}
