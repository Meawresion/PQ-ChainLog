//! Warrants, scope, the warrant tree and one-time nullifiers.
//!
//! This is draft6's authorization relation `R_auth` (eq. `eq:relauth`) in Rust,
//! minus the SP1 proof — the proof arrives in [`crate::prove`] and proves
//! exactly the clauses [`Warrant::authorizes`] and [`Nullifier`] check here.
//!
//! ```text
//! x = (ρ_W, N, e, H(scope(q)))                    public statement
//! ω = (warrant, s, π, σ_CA)                       private witness
//!
//! R_auth(x, ω) = 1  iff
//!     ML-DSA.Vf(pk_CA, warrant, σ_CA) = 1
//!   ∧ C = H(warrant ‖ s)  ∧  Path(C, π) = ρ_W
//!   ∧ N = H(s ‖ e)        ∧  e = e_current
//!   ∧ scope(q) ⊆ scope(warrant)  ∧  exp > e
//! ```
//!
//! # The property that makes scoping real
//!
//! draft6 §V-D is emphatic, and it is the sentence this crate exists to honour:
//! authority is enforced **by key derivation, not by policy**. An out-of-scope
//! probe *"is not refused, it is underivable, because the trapdoor never
//! contained the key that would produce it."*
//!
//! So [`Scope`] is not a predicate consulted before handing over a general key.
//! It is a **range in the GGM keyword-class space**, and a warrant is delegated
//! as a [`pqcl_ggm::ConstrainedKey`] over that range. `ConstrainedKey::eval`
//! returns `Err` outside its range — the refusal is a property of the key
//! material, not a check some future caller could forget to make.
//!
//! That distinction is worth stating because the weaker design looks identical
//! from the outside: both "refuse out-of-scope queries". Only one of them still
//! holds when the process enforcing it is the one that has been compromised.
//!
//! # Domain tags
//!
//! `C = H(0x30 ‖ ⟪warrant, s⟫)`, `N = H(0x31 ‖ ⟪s, e⟫)`, warrant-tree internal
//! node `0x32`, query scope `0x33`, trapdoor `0x34` — the **authorization
//! block**, settled by the design record.
//!
//! ⚠️ These were first proposed as `0x26`/`0x27` and that was **rejected**:
//! draft6 reserves `0x20`–`0x25` for *record-field commitments*, and an
//! authorization object is not a record field, so appending there would have
//! falsified the paper's own reservation sentence. The block boundary carries
//! meaning even when the individual bytes are free.
//!
//! `pqcl-warrant` also does **not** reuse the forest's `0x11` node tag — see
//! [`crate::tree`] for why that matters when both roots anchor on one chain.

#[cfg(feature = "host")]
pub mod delegate;
pub mod nullifier;
pub mod relation;
pub mod scope;
pub mod tree;
pub mod warrant;
#[cfg(feature = "host")]
pub mod writer;

#[cfg(feature = "host")]
pub use delegate::{Delegation, DelegationError, PlaneRoot};
pub use nullifier::{Nullifier, NullifierLedger, SpendError};
pub use relation::{RelationError, Statement, Witness, check, scope_digest};
pub use scope::{KeywordClass, Scope, ScopeError};
pub use tree::{WarrantPath, WarrantTree};
pub use warrant::{Warrant, WarrantError, WarrantId};
#[cfg(feature = "host")]
pub use writer::{WriterId, WriterSet, WriterTree};
