//! Answering one request — independent of the transport and of the NSM.
//!
//! ⭐ **Split out of `enclave` for the same reason `session` was.** That module
//! is vsock-only and `enclave`-feature-only, and vsock has no loopback on the
//! development box, so every arm of the request handler would have had its
//! first execution on a billing instance and CI's default test run could not
//! reach any of it. Here it is always compiled, generic over `Read + Write`,
//! and driven over a real loopback socket. The vsock module only binds.
//!
//! That mattered immediately: M13 A18 added four arms, including the one that
//! builds every custody record the paper's ingest numbers come from.
//!
//! # The attester is a parameter, and `no_nsm` is not a stand-in
//!
//! `/dev/nsm` exists only inside a Nitro Enclave. [`no_nsm`] therefore does not
//! stand in for attestation — it is the **true and only answer anywhere
//! else**, and it is byte-for-byte what the real attester returns when
//! `nsm_init` reports a negative descriptor. A test that passes it is
//! exercising the arm honestly; a real enclave passes the NSM.

use std::io::{Read, Write};

use pqcl_sm::custody::KeyCustody;
use pqcl_sm::host::{HostAgentModule, HostHandle};
use pqcl_sm::secure::AgentModule;

use crate::proto::{MAX_FRAME, Request, Response};
use crate::session::{read_frame, write_frame};

/// What an attestation request answers to outside an enclave.
///
/// See the module docs: this is the real off-enclave behaviour, nothing
/// imitated. It is the same text `enclave::attest` produces when `/dev/nsm` is
/// absent, kept in one place so the two cannot drift.
pub fn no_nsm(_nonce: &[u8]) -> Result<Vec<u8>, String> {
    Err(
        "could not open /dev/nsm: this process is not running inside a Nitro \
         Enclave. See nitro/README.md."
            .to_owned(),
    )
}

/// Answer one request.
///
/// `attest` is the attestation document source — the NSM inside an enclave,
/// [`no_nsm`] anywhere else.
pub fn handle<A>(module: &HostAgentModule, req: &Request, attest: &A) -> Response
where
    A: Fn(&[u8]) -> Result<Vec<u8>, String>,
{
    match req {
        Request::Attest { nonce } => match attest(nonce) {
            Ok(doc) => Response::Attestation(doc),
            Err(e) => Response::Error(e),
        },
        Request::CapsulePseudonym {
            case_commitment,
            nonce,
        } => match module.capsule_pseudonym(case_commitment, nonce) {
            Ok(d) => Response::Digest(d),
            // ⚠️ The error text is the module's own, which is written for an
            // operator and names no key material. If that ever stops being true
            // this is the line that leaks it.
            Err(e) => Response::Error(e.to_string()),
        },
        Request::SignDefr { message } => match module.sign_defr(message) {
            Ok(sig) => Response::Bytes(sig),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::DefrPublicKey => match module.defr_public_key() {
            Ok(pk) => Response::Bytes(pk),
            Err(e) => Response::Error(e.to_string()),
        },

        // --- the KeyCustody half -------------------------------------
        Request::GenerateAes { label } => match module.generate_non_extractable_aes256(label) {
            Ok(h) => Response::Handle(h.raw()),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::TryExport { handle } => match module.try_export(HostHandle::from_raw(*handle)) {
            // ⭐ Reaching this arm at all would mean the boundary handed key
            // material to the parent. It is left as an explicit refusal rather
            // than an unreachable, because "cannot happen" is how it happens.
            Ok(_) => Response::Error(
                "the module exported a key it should have refused; this is a boundary failure"
                    .to_owned(),
            ),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::AesGcmEncrypt {
            handle,
            nonce,
            aad,
            plaintext,
        } => match module.aes_gcm_encrypt(HostHandle::from_raw(*handle), nonce, aad, plaintext) {
            Ok(ct) => Response::Bytes(ct),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::AesGcmDecrypt {
            handle,
            nonce,
            aad,
            ciphertext,
        } => match module.aes_gcm_decrypt(HostHandle::from_raw(*handle), nonce, aad, ciphertext) {
            Ok(pt) => Response::Bytes(pt),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::Random { len } => {
            // The parent chooses this length, so it is bounded here for the
            // same reason the frame size is.
            match usize::try_from(*len) {
                Ok(n) if n <= MAX_FRAME => match module.random(n) {
                    Ok(b) => Response::Bytes(b),
                    Err(e) => Response::Error(e.to_string()),
                },
                _ => Response::Error(format!("requested {len} random bytes, over the limit")),
            }
        }

        // --- the custody plane (M13 A18) -----------------------------
        Request::CustodyAppend(q) => match module.custody_append(q) {
            Ok(a) => Response::Appended(Box::new(a)),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::ActorPublicKey { actor } => match module.actor_public_key(actor) {
            Ok(pk) => Response::Bytes(pk),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::Enrolled => Response::Actors(module.enrolled()),
        Request::SealCapsule(q) => match module.seal_capsule(q) {
            Ok(c) => Response::Capsule(Box::new(c)),
            Err(e) => Response::Error(e.to_string()),
        },
        Request::SealDisclosure {
            case_commitment,
            eid,
            court_ek,
        } => match module.sealed_disclosure(case_commitment, eid, court_ek) {
            Ok(s) => Response::SealedDisclosure(Box::new(s)),
            Err(e) => Response::Error(e.to_string()),
        },
    }
}

/// Serve requests on one already-connected stream until it closes.
///
/// A malformed request is answered and the session continues: the parent is
/// outside the boundary, and one bad frame must not end an ingest run that has
/// been going for hours.
pub fn serve_over<S, A>(module: &HostAgentModule, stream: &mut S, attest: &A)
where
    S: Read + Write,
    A: Fn(&[u8]) -> Result<Vec<u8>, String>,
{
    // A closed connection is the normal end of a session, not an error.
    while let Ok(payload) = read_frame(stream) {
        let response = match Request::decode(&payload) {
            Ok(req) => handle(module, &req, attest),
            Err(e) => Response::Error(format!("malformed request: {e}")),
        };

        if write_frame(stream, &response.encode()).is_err() {
            break;
        }
    }
}
