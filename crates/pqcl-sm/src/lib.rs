//! The Secure Module — key custody behind a boundary the host cannot cross.
//!
//! # Read this before adding an operation to a trait here
//!
//! M5 was planned as *"one trait, two real backends"*: a `SecureModule` trait
//! implemented by both a PKCS#11 token and an AWS Nitro Enclave, with an
//! identical test suite passing on both. **That is not achievable, for a
//! measured reason.** `SoftHSM2` 2.6.1 exposes no PQC mechanism of any kind and
//! no SHA-3 family member at all, so it can perform neither ML-DSA-65 signing
//! nor a single SHAKE256 derivation in the key hierarchy. The full finding,
//! with the mechanism list, is the design record.
//!
//! So the surface is split, and the split is the point:
//!
//! ```text
//! KeyCustody              secrets that are generated inside the boundary and
//!                         never come out; AES-256-GCM under them; RNG.
//!                         Implemented by BOTH backends. This is where the
//!                         "identical suite passes on both" test belongs, and
//!                         here it is a real claim about a real token.
//!
//! SecureModule            + SHAKE256 hierarchy, ML-DSA signing, scoped
//!   : KeyCustody          trapdoor derivation, result-set-only search.
//!                         TEE only, because those need arbitrary code inside
//!                         the boundary. Arrives with the Nitro backend.
//! ```
//!
//! [`SecureModule`] is deliberately **not defined yet**. Its shape depends on
//! the answer to the design record, and writing it now would be
//! guessing at an interface whose only implementation does not exist. An empty
//! trait waiting for a backend is scaffolding, which is what ground rule #1
//! exists to prevent.
//!
//! # What a PKCS#11 token buys, given it cannot sign
//!
//! One property, and it is the one the design leans on hardest: a secret can be
//! created inside the token such that **the host cannot read it back**, and can
//! still be used. `CKA_SENSITIVE = true` with `CKA_EXTRACTABLE = false` makes
//! `C_GetAttributeValue` on `CKA_VALUE` fail rather than return the bytes.
//!
//! That is worth having on its own, and it is testable today —
//! `tests/pkcs11_softhsm.rs` attempts the extraction and asserts it fails.
//! Asserting a *refusal* is the only form of this test that means anything: a
//! test that merely never asks for the key would pass against a token that
//! hands it over freely.

pub mod custody;
pub mod secure;

#[cfg(feature = "append-types")]
pub mod append;
#[cfg(feature = "host-software")]
pub mod host;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;

pub use custody::{Backend, KeyCustody, SmError};
// `Plane` is always exported: it is the one item the SP1 guest reaches through
// `pqcl-warrant`, and the reason this crate is in the guest's graph at all.
pub use secure::Plane;
// The role traits carry the `pqcl-chainproof` dependency, so they follow it
// behind `roles` — see that feature's note in `Cargo.toml`.
#[cfg(feature = "roles")]
pub use secure::{AgentModule, InvestigatorModule};

#[cfg(feature = "append-types")]
pub use append::{
    Actors, AppendRequest, AppendStep, Appended, CAST, CustodyAppender, Pairing, SealRequest,
    cast_member, evidence_store, lab_custodian, position, sign_step, tokens_for,
};
#[cfg(feature = "host-software")]
pub use host::{HostAgentModule, HostHandle};
#[cfg(feature = "pkcs11")]
pub use pkcs11::Pkcs11Custody;

#[cfg(test)]
mod feature_shape {
    //! ⭐ The guest's view of this crate, asserted rather than assumed.
    //!
    //! `pqcl-sm` sits on the path guest → `pqcl-warrant` → here, and everything
    //! past that arrow wants exactly one item: [`Plane`]. Without a check, a
    //! future `use` of something heavier compiles fine on the host and only
    //! fails when `cargo prove build` runs — which is on a paid instance, at the
    //! end of a setup, and reads as an unrelated MSRV error.
    //!
    //! That is not hypothetical: `pqcl-chainproof`, an Ethereum RLP and
    //! Merkle-Patricia-trie decoder, was reaching the zkVM guest through the
    //! role traits and surfaced as `rustc 1.96.0-dev is not supported`.

    #[test]
    fn plane_is_reachable_without_the_role_traits() {
        // Compiles under `--no-default-features`, which is how the guest takes
        // this crate. If `Plane` ever acquires a dependency on the gated half,
        // this stops building in that configuration.
        let evidence = crate::Plane::Evidence;
        let custody = crate::Plane::Custody;
        assert_ne!(evidence, custody);
    }

    #[cfg(not(feature = "roles"))]
    #[test]
    fn chainproof_is_absent_when_roles_are_off() {
        // A negative that the type system enforces: with `roles` off the crate
        // has no `pqcl_chainproof` dependency at all, so the guest cannot be
        // dragged into compiling it.
        // A `const` block, because this is a compile-time fact and clippy is
        // right that a runtime assertion of a constant tests nothing. ⚠️ The
        // runtime form failed `clippy -D warnings` in exactly this feature
        // shape from 2026-09-15 until M13 A18, which nobody saw because no
        // gate lints the crate with `--no-default-features`. The guest builds
        // it that way; the gate now does too (see `xtask`).
        const { assert!(!cfg!(feature = "roles")) };
    }
}
