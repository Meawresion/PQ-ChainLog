//! The three-tier Merkle forest.
//!
//! ```text
//! Tier 1   per-capsule custody tree      R_cap = MR(L_0 … L_j)
//! Tier 2   per-epoch MMR over the case   R_e, four+ domain-separated leaf types
//! Tier 3   on-chain anchor               commitRoot(cid_c, R_e, d_{e-1}, d_e, A_e)
//! ```
//!
//! Tier 3 is a Solidity contract and arrives at M7; this crate is Tiers 1 and 2,
//! which are what a court disclosure and an auditor actually verify.
//!
//! # Why three tiers rather than one flat log
//!
//! So that one capsule's complete custody history can be handed to a court
//! **without revealing the shape of the rest of the case**. Under a flat MMR the
//! inclusion path itself leaks case size and activity volume; with Tier 1 the
//! disclosure is one capsule's tree plus a single Tier-2 inclusion proof.
//! The project rules lists that selective disclosure as a live novelty claim,
//! and it is a property of this structure rather than of any policy on top.

pub mod tier1;
pub mod tier2;

pub use tier1::{CustodyTree, InclusionProof, ProofStep, verify, verify_leaf};
pub use tier2::{Leaf, Mmr, MmrProof};
