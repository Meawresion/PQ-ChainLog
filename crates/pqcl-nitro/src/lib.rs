//! M5b — the AWS Nitro Enclave Secure Module.
//!
//! # What this is
//!
//! The design record's Secure Module standing rule, condition 3:
//!
//! > The host software module **is** the enclave module minus the boundary —
//! > same source. The enclave binary is this code plus NSM attestation plus KMS
//! > release, and nothing else.
//!
//! So this crate adds exactly three things to
//! [`pqcl_sm::host::HostAgentModule`]:
//!
//! 1. a **vsock server** that answers the protocol in [`proto`] — the framing
//!    in [`session`], the request handling in [`dispatch`], and only the socket
//!    itself in `enclave`;
//! 2. **NSM attestation**, passed through to whoever must be convinced;
//! 3. **KMS release** of `K_mst`, gated on the enclave's PCR measurements.
//!
//! It reimplements none of the module's logic. A second implementation is a
//! second thing to diverge, and if it diverged then local iteration would prove
//! nothing about what AWS runs.
//!
//! # ⚠️ `K_mst` does not "never leave" — it never leaves *in plaintext*
//!
//! The standing rule's correction 2, and it is a paper defect until draft6 is
//! updated. An enclave has no persistent store, so across a restart `K_mst`
//! survives only as a **KMS-wrapped blob** whose key policy conditions release
//! on the enclave's PCR0. It therefore does leave, encrypted, and **AWS KMS
//! joins the recovery TCB**.
//!
//! That is a weaker claim than the absolute one, and it is the true one. The
//! test that checks the property actually claimed is in `nitro/README.md`:
//! **mutate the enclave image and assert KMS refuses the unwrap.**
//!
//! # What is not here, and why
//!
//! ⛔ **No attestation-document verifier.** The party that must be convinced by
//! a Nitro attestation is **KMS**, which verifies it itself when enforcing the
//! key policy. Writing a second COSE/CBOR verifier here would add a weaker
//! checker for a property something else already enforces — and if ours
//! disagreed with theirs, ours would be the wrong one. The document is passed
//! through verbatim.

pub mod appendwire;
pub mod dispatch;
pub mod kms;
pub mod proto;
pub mod session;

pub use proto::{MAX_FRAME, Provision, Request, Response, frame};

#[cfg(all(feature = "enclave", target_os = "linux"))]
pub mod enclave;

#[cfg(all(feature = "enclave", target_os = "linux"))]
pub mod host;

/// The vsock port the enclave listens on.
///
/// Fixed rather than discovered: an enclave has no DNS, no service registry and
/// no way to advertise. The parent must already know where to connect, so the
/// number is part of the interface and is duplicated in `nitro/run-enclave.sh`.
pub const VSOCK_PORT: u32 = 5005;

/// The well-known context id meaning "the parent instance", from the AWS Nitro
/// documentation.
pub const VMADDR_CID_PARENT: u32 = 3;
