//! Cryptographic primitives for PQ-ChainLog.
//!
//! This is the **only** crate in the workspace permitted to import a
//! cryptographic library. Every other crate reaches primitives through this
//! API. The rule exists so that a question like "which AES backend produced
//! this number?" or "is our ML-DSA FIPS 204 final or the draft?" has exactly
//! one place to look.
//!
//! # What is here
//!
//! | Module | Primitive | Standard |
//! |---|---|---|
//! | [`xof`] | SHAKE256, domain-separated hashing, PRF | FIPS 202 |
//! | [`aead`] | AES-256-GCM | SP 800-38D |
//! | [`rng`] | OS entropy | — |
//! | [`kem`] | ML-KEM-768 | FIPS 203 |
//! | [`sig`] | ML-DSA-65 | FIPS 204 |
//! | [`slh`] | SLH-DSA-SHAKE-192s | FIPS 205 |
//!
//! All five primitives are present and pass known-answer tests. SLH-DSA comes
//! from a dedicated FIPS-205 crate rather than liboqs, whose SPHINCS+ is **not**
//! FIPS 205 — see [`slh`] for how that crate was chosen.
//!
//! # Known-answer tests are the admission criterion
//!
//! The build plan: *"A primitive that has not passed KATs in our
//! build is not a primitive, it is a guess."* Every primitive exposed here is
//! checked against official NIST ACVP or CAVP vectors in `tests/`, vendored at a
//! pinned upstream commit with a checksum manifest.

// `xof` is unconditional: it is the only module the SP1 guest can compile, and
// the only one it needs. See the `full` feature in Cargo.toml.
pub mod prg;
pub mod xof;

#[cfg(feature = "full")]
pub mod aead;
#[cfg(feature = "full")]
pub mod kem;
#[cfg(feature = "full")]
pub mod platform;
#[cfg(feature = "full")]
pub mod rng;
#[cfg(feature = "full")]
pub mod sig;
#[cfg(feature = "full")]
pub mod slh;

pub use xof::{Digest32, Domain, Label, PrfKey};

#[cfg(feature = "full")]
pub use aead::{AeadError, CustodyKey, RecordKey, SealedRecord};
#[cfg(feature = "full")]
pub use kem::{KemError, KeyPair, SharedSecret};
#[cfg(feature = "full")]
pub use platform::CpuFeatures;
#[cfg(feature = "full")]
pub use rng::RngError;
#[cfg(feature = "full")]
pub use sig::{SigError, Signer, SoftwareMlDsa};
#[cfg(feature = "full")]
pub use slh::{CoSigner, SlhError};

/// Length of every digest, tag, address and PRF output in the system.
///
/// The design fixes `λ = 256` bits (`PQ-DSSE-Formal.md` §9.3): at `λ = 128` the
/// QROM reprogramming term in the security bound is vacuous, so 256 is load
/// bearing rather than conservative.
pub const LAMBDA_BYTES: usize = 32;
