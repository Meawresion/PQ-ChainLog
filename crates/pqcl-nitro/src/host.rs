//! The parent side: an [`AgentModule`] that forwards across the boundary.
//!
//! ⭐ **This is where the boundary becomes real.** `HostAgentModule` and
//! `NitroAgentModule` implement the same trait and answer the same questions,
//! but only this one does so without ever holding `K_mst` in the parent's
//! address space. That is the whole difference, and it is why
//! [`Backend::HostSoftware`] is unpublishable while [`Backend::NitroEnclave`]
//! is not.

use std::sync::Mutex;

use pqcl_capsule::{ActorRef, Capsule};
use pqcl_primitives::xof::Digest32;
use pqcl_sm::append::{AppendRequest, Appended, SealRequest};
use pqcl_sm::custody::{Backend, KeyCustody, SmError};
use pqcl_sm::secure::AgentModule;
use vsock::{VsockAddr, VsockStream};

use crate::VSOCK_PORT;
use crate::proto::{Provision, Request, Response};
use crate::session::{exchange, provision_over};

pub use crate::session::ProvisionError;

/// Send an enclave its one [`Provision`] message and report the outcome.
///
/// Only the vsock connect lives here; the exchange and its classification are
/// [`crate::session`]'s, tested over a real loopback socket.
///
/// # Errors
///
/// [`ProvisionError::Refused`] if the enclave answered with a refusal,
/// [`ProvisionError::Transport`] for anything else.
pub fn provision(cid: u32, p: &Provision) -> Result<(), ProvisionError> {
    let mut stream = VsockStream::connect(&VsockAddr::new(cid, VSOCK_PORT))
        .map_err(|e| ProvisionError::Transport(format!("vsock connect to cid {cid}: {e}")))?;
    provision_over(&mut stream, p)
}

/// An agent-side Secure Module living in an enclave, reached over vsock.
pub struct NitroAgentModule {
    /// One connection, serialised. The enclave handles requests in order on a
    /// stream, so two concurrent callers interleaving frames would desynchronise
    /// request from response — a mutex is the correct shape, not a limitation.
    stream: Mutex<VsockStream>,
}

impl NitroAgentModule {
    /// Connect to an enclave by context id.
    ///
    /// # Errors
    ///
    /// [`SmError::Backend`] if the enclave is not reachable.
    pub fn connect(cid: u32) -> Result<Self, SmError> {
        let stream = VsockStream::connect(&VsockAddr::new(cid, VSOCK_PORT))
            .map_err(|e| SmError::Backend(format!("vsock connect to cid {cid}: {e}")))?;
        Ok(Self {
            stream: Mutex::new(stream),
        })
    }

    /// Send one request and read one response.
    fn call(&self, req: &Request) -> Result<Response, SmError> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| SmError::Backend("enclave connection lock poisoned".to_owned()))?;
        exchange(&mut *stream, &req.encode()).map_err(SmError::Backend)
    }

    /// Fetch an attestation document, bound to `nonce`.
    ///
    /// ⚠️ **Returned, not verified.** Verification belongs to the party the
    /// document must convince — KMS, when it enforces the key policy. See the
    /// crate docs on why a second verifier here would be a liability.
    ///
    /// # Errors
    ///
    /// [`SmError::Backend`] if the enclave refuses or the transport fails.
    pub fn attestation(&self, nonce: &[u8]) -> Result<Vec<u8>, SmError> {
        match self.call(&Request::Attest {
            nonce: nonce.to_vec(),
        })? {
            Response::Attestation(d) => Ok(d),
            Response::Error(m) => Err(SmError::Backend(m)),
            _ => Err(SmError::Backend(
                "enclave answered an attestation request with something else".to_owned(),
            )),
        }
    }

    fn expect_digest(&self, req: &Request) -> Result<Digest32, SmError> {
        match self.call(req)? {
            Response::Digest(d) => Ok(d),
            Response::Error(m) => Err(SmError::Backend(m)),
            _ => Err(SmError::Backend(
                "enclave answered with the wrong response type".to_owned(),
            )),
        }
    }

    fn expect_handle(&self, req: &Request) -> Result<u64, SmError> {
        match self.call(req)? {
            Response::Handle(h) => Ok(h),
            Response::Error(m) => Err(SmError::Backend(m)),
            _ => Err(SmError::Backend(
                "enclave answered with the wrong response type".to_owned(),
            )),
        }
    }

    fn expect_bytes(&self, req: &Request) -> Result<Vec<u8>, SmError> {
        match self.call(req)? {
            Response::Bytes(b) => Ok(b),
            Response::Error(m) => Err(SmError::Backend(m)),
            _ => Err(SmError::Backend(
                "enclave answered with the wrong response type".to_owned(),
            )),
        }
    }

    /// Build, seal, sign and index one custody record inside the enclave —
    /// one round trip per record (M13 A18).
    ///
    /// ⭐ **This is the method that puts the custody plane behind the
    /// boundary.** `K_case`, `K_coc`, `K_S^COC` and the actors' signing keys
    /// never reach this process; what comes back is the record, its 29 `Π_core`
    /// tokens, and the openings a court will need.
    ///
    /// # Errors
    ///
    /// [`SmError::Backend`] carrying the enclave's own refusal — a role that
    /// may not sign the event, no actor enrolled in it, a position already
    /// signed, a timestamp outside the index window — or a transport failure.
    pub fn custody_append(&self, req: &AppendRequest) -> Result<Appended, SmError> {
        match self.call(&Request::CustodyAppend(Box::new(req.clone())))? {
            Response::Appended(a) => Ok(*a),
            Response::Error(m) => Err(SmError::Backend(m)),
            _ => Err(SmError::Backend(
                "enclave answered a custody append with the wrong response type".to_owned(),
            )),
        }
    }

    /// An enrolled actor's **verification** key, for the audit package.
    ///
    /// # Errors
    ///
    /// As [`Self::custody_append`].
    pub fn actor_public_key(&self, actor: &ActorRef) -> Result<Vec<u8>, SmError> {
        self.expect_bytes(&Request::ActorPublicKey {
            actor: actor.clone(),
        })
    }

    /// Which actors the enclave can sign as.
    ///
    /// # Errors
    ///
    /// As [`Self::custody_append`]. A role byte that is not one of the four is
    /// refused by the decoder, so this cannot return one.
    pub fn enrolled(&self) -> Result<Vec<ActorRef>, SmError> {
        match self.call(&Request::Enrolled)? {
            Response::Actors(a) => Ok(a),
            Response::Error(m) => Err(SmError::Backend(m)),
            _ => Err(SmError::Backend(
                "enclave answered an enrolment query with the wrong response type".to_owned(),
            )),
        }
    }
}

impl pqcl_sm::append::CustodyAppender for NitroAgentModule {
    fn backend(&self) -> Backend {
        <Self as KeyCustody>::backend(self)
    }

    fn append(&self, req: &AppendRequest) -> Result<Appended, SmError> {
        self.custody_append(req)
    }

    fn seal(&self, req: &SealRequest) -> Result<Capsule, SmError> {
        match self.call(&Request::SealCapsule(Box::new(req.clone())))? {
            Response::Capsule(c) => Ok(*c),
            Response::Error(m) => Err(SmError::Backend(m)),
            _ => Err(SmError::Backend(
                "enclave answered a seal with the wrong response type".to_owned(),
            )),
        }
    }

    fn verification_key(&self, who: &ActorRef) -> Result<Vec<u8>, SmError> {
        self.actor_public_key(who)
    }

    fn seal_disclosure(
        &self,
        cid_c: &Digest32,
        eid: &Digest32,
        court_ek: &[u8],
    ) -> Result<pqcl_capsule::SealedDisclosure, SmError> {
        match self.call(&Request::SealDisclosure {
            case_commitment: *cid_c,
            eid: *eid,
            court_ek: court_ek.to_vec(),
        })? {
            Response::SealedDisclosure(s) => Ok(*s),
            Response::Error(m) => Err(SmError::Backend(m)),
            _ => Err(SmError::Backend(
                "enclave answered a disclosure with the wrong response type".to_owned(),
            )),
        }
    }
}

impl KeyCustody for NitroAgentModule {
    type Handle = u64;

    fn backend(&self) -> Backend {
        Backend::NitroEnclave
    }

    fn generate_non_extractable_aes256(&self, label: &str) -> Result<u64, SmError> {
        self.expect_handle(&Request::GenerateAes {
            label: label.to_owned(),
        })
    }

    /// ⭐ Must refuse. The enclave never answers this with key bytes, so the
    /// only non-error outcome would be a boundary failure — and the test suite
    /// demands the refusal specifically, which is the only way to tell a module
    /// that protects keys from one nobody ever asked.
    fn try_export(&self, key: u64) -> Result<Vec<u8>, SmError> {
        match self.call(&Request::TryExport { handle: key })? {
            Response::Error(_) => Err(SmError::ExtractionRefused),
            _ => Err(SmError::Backend(
                "the enclave answered an export request with data".to_owned(),
            )),
        }
    }

    fn aes_gcm_encrypt(
        &self,
        key: u64,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SmError> {
        self.expect_bytes(&Request::AesGcmEncrypt {
            handle: key,
            nonce: *nonce,
            aad: aad.to_vec(),
            plaintext: plaintext.to_vec(),
        })
    }

    fn aes_gcm_decrypt(
        &self,
        key: u64,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SmError> {
        self.expect_bytes(&Request::AesGcmDecrypt {
            handle: key,
            nonce: *nonce,
            aad: aad.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, SmError> {
        self.expect_bytes(&Request::Random {
            len: u64::try_from(len)
                .map_err(|_| SmError::Backend("random length overflows u64".to_owned()))?,
        })
    }
}

impl AgentModule for NitroAgentModule {
    fn capsule_pseudonym(
        &self,
        case_commitment: &Digest32,
        nonce: &[u8],
    ) -> Result<Digest32, SmError> {
        self.expect_digest(&Request::CapsulePseudonym {
            case_commitment: *case_commitment,
            nonce: nonce.to_vec(),
        })
    }

    fn sign_defr(&self, message: &[u8]) -> Result<Vec<u8>, SmError> {
        self.expect_bytes(&Request::SignDefr {
            message: message.to_vec(),
        })
    }

    fn defr_public_key(&self) -> Result<Vec<u8>, SmError> {
        self.expect_bytes(&Request::DefrPublicKey)
    }
}
