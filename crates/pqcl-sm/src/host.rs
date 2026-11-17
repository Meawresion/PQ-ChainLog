//! The host-software Secure Module — **no boundary at all**.
//!
//! Approved on the record under four
//! conditions, all of which this module is built to satisfy:
//!
//! 1. Split by role — it implements [`AgentModule`], never a combined trait.
//! 2. No `SecureModule` implementation exists for any PKCS#11 type.
//! 3. **This is the enclave module minus the boundary — the same source.** The
//!    Nitro build at M5b is this code plus NSM attestation plus KMS release,
//!    and nothing else. If the two diverged, local iteration would prove
//!    nothing about what AWS runs.
//! 4. It reports [`Backend::HostSoftware`], whose `is_publishable()` is
//!    `false`, and it lives behind the default-off `host-software` feature.
//!
//! # No enclave is being imitated here
//!
//! Ground rule #1 bans presenting software as hardware. It does not ban running
//! the cryptography without a boundary — which is all this is. The distinction
//! is carried by the type: there is no enclave being impersonated, there is
//! simply no enclave, and [`Backend::HostSoftware`] says so to anything that
//! asks.
//!
//! # What it honestly provides, and what it does not
//!
//! `try_export` refuses, and that refusal is real **at the API level** — the
//! key is a private field and no method returns it. That is the property the
//! shared [`KeyCustody`] suite checks, and it is the same property a PKCS#11
//! token provides through `CKA_SENSITIVE`.
//!
//! What differs is what the refusal is worth against an attacker who is not
//! going through the API. A token answers "no" with the key in the token; this
//! answers "no" with the key in the same address space as the caller, readable
//! by a debugger, a core dump or any code in the process. **That difference is
//! reported, not hidden**, and it is exactly why `is_publishable()` is `false`.

use std::collections::HashMap;
use std::sync::Mutex;

use pqcl_capsule::{ActorRef, Role};
use pqcl_pipeline::{Agent, CaseKeys};
use pqcl_primitives::aead::CustodyKey;
use pqcl_primitives::rng;
use pqcl_primitives::xof::{Digest32, Label, PrfKey, prf};

use crate::append::{self, AppendRequest, AppendState, Appended, tokens_for};
// The trait is implemented below; the inherent methods stay, because a caller
// that has a concrete module should not need the trait in scope.

use crate::custody::{Backend, KeyCustody, SmError};
use crate::secure::AgentModule;

/// A key living in this process's memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostHandle(u64);

impl HostHandle {
    /// The raw handle, for crossing a serialisation boundary.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Rebuild a handle from its raw form.
    ///
    /// ⚠️ **This makes the handle forgeable, and that is why the equivalent does
    /// not exist for PKCS#11.** `KeyCustody::Handle`'s documentation records
    /// that cryptoki's constructor is `unsafe` precisely because a forged handle
    /// can name an object the caller was never given, and the workspace denies
    /// `unsafe_code`.
    ///
    /// It is admissible *here* for one specific reason: this handle names a key
    /// in a single-tenant module's own map. Every key in that map belongs to the
    /// same agent, so naming one the caller was not handed reaches nothing it
    /// was not already entitled to. ⛔ If the module ever becomes multi-tenant,
    /// this constructor must go — the reasoning above stops holding the moment
    /// two principals share a map.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

/// An agent-side Secure Module with no hardware boundary.
pub struct HostAgentModule {
    /// The case master key. Never returned by any method.
    k_mst: PrfKey,
    /// The enrolled cast (M13 A18), addressed by `(role, id)`: a role may
    /// hold several actors, so a transfer can be between two custodians. The
    /// first responder [`Self::new`] takes is the first entry.
    ///
    /// A18's row concedes what this concentrates: *"all actors' keys sit in one
    /// enclave on one host, which is declared"*. It replaces four hosts holding
    /// one signing key each with one boundary holding four -- a smaller attack
    /// surface and a larger blast radius, and the honest way to describe it is
    /// both halves.
    actors: Vec<Agent>,
    /// The custody-append path's state: per-case index clients and per-capsule
    /// positions. See [`crate::append`] on why losing it is not survivable.
    append: Mutex<AppendState>,
    /// Keys created through [`KeyCustody`], by handle.
    keys: Mutex<HashMap<u64, CustodyKey>>,
    /// Next handle to hand out.
    next: Mutex<u64>,
}

impl HostAgentModule {
    /// Build a module around an existing master key and DEFR signing key.
    ///
    /// Takes `k_mst` rather than drawing it, because at M5b the enclave
    /// receives it from a KMS unwrap gated on PCR measurements rather than
    /// generating it locally. Keeping the constructor the same shape in both
    /// places is condition 3 above.
    #[must_use]
    pub fn new(k_mst: PrfKey, defr: Agent) -> Self {
        Self {
            k_mst,
            actors: vec![defr],
            append: Mutex::new(AppendState::default()),
            keys: Mutex::new(HashMap::new()),
            next: Mutex::new(1),
        }
    }

    /// Enrol the rest of the cast whose records this module will sign (M13
    /// A18).
    ///
    /// ⭐ **The first responder is an enrolled actor, not a second key.**
    /// `σ_DEFR` over a capsule and `σ_actor` over the `COLLECT` that opens its
    /// chain are the same responder's signature, so they must come from the
    /// same key — and the way to guarantee that is for there to be only one.
    /// An earlier shape of this kept a separate `defr` field and *checked* that
    /// the enrolled DEFR matched it, which is weaker: a check can be satisfied
    /// by two equal keys and still leaves a second thing to keep in step. Here
    /// there is nothing to disagree with, and [`Self::new`] is the only door a
    /// signing key comes through.
    ///
    /// # Errors
    ///
    /// [`SmError::Config`] if two actors claim one `(role, id)`, or a second
    /// first responder is offered: [`Self::new`] holds the one DEFR, so
    /// `σ_DEFR` and the `COLLECT` that opens a chain cannot name two.
    pub fn with_actors(mut self, actors: Vec<Agent>) -> Result<Self, SmError> {
        for a in actors {
            if a.role() == Role::Defr {
                return Err(SmError::Config(
                    "a second first responder; the module seals with one DEFR key".to_owned(),
                ));
            }
            if self.actors.iter().any(|b| b.actor_ref() == a.actor_ref()) {
                return Err(SmError::Config(format!(
                    "two actors enrolled as {:?}; an actor is enrolled once",
                    a.actor_ref()
                )));
            }
            self.actors.push(a);
        }
        Ok(self)
    }

    /// The actor enrolled as `who`.
    fn actor(&self, who: &ActorRef) -> Result<&Agent, SmError> {
        self.actors
            .iter()
            .find(|a| a.role() == who.role && a.actor_ref() == *who)
            .ok_or_else(|| SmError::NoSuchActor {
                role: who.role.byte(),
                id: who.id.clone(),
            })
    }

    /// The first responder [`Self::new`] enrolled.
    fn first_responder(&self) -> Result<&Agent, SmError> {
        self.actors
            .first()
            .filter(|a| a.role() == Role::Defr)
            .ok_or(SmError::NoSuchActor {
                role: Role::Defr.byte(),
                id: Vec::new(),
            })
    }

    /// The actors this module can sign as.
    #[must_use]
    pub fn enrolled(&self) -> Vec<ActorRef> {
        self.actors.iter().map(Agent::actor_ref).collect()
    }

    /// An enrolled actor's **verification** key, which an auditor needs to
    /// check `sigma_actor` and the roster therefore lists.
    ///
    /// # Errors
    ///
    /// [`SmError::NoSuchActor`] if no actor is enrolled as `who`.
    pub fn actor_public_key(&self, who: &ActorRef) -> Result<Vec<u8>, SmError> {
        Ok(self.actor(who)?.public_key().to_vec())
    }

    /// The case's keys, derived inside the boundary from `cid_c` alone.
    ///
    /// No per-case setup, and no case key at rest: `K_case = F(K_mst, "case"
    /// || cid_c)`, so a request naming its case is enough, and the module
    /// stores nothing a compromise could harvest for cases it is not serving.
    fn case_keys(&self, cid_c: &Digest32) -> CaseKeys {
        CaseKeys {
            cid_c: *cid_c,
            k_case: self.case_key(cid_c),
        }
    }

    /// Build, seal, sign and index one custody record -- all inside the
    /// boundary (M13 A18).
    ///
    /// See [`crate::append`] for what this does and does not check.
    ///
    /// # Errors
    ///
    /// [`SmError::NoSuchActor`] if the named actor is not enrolled;
    /// [`SmError::WrongRole`] if that role may not sign the event;
    /// [`SmError::PositionReused`] if `j` is not past every position already
    /// signed for the capsule; [`SmError::TimestampOutOfWindow`] if the record
    /// cannot be indexed; [`SmError::Backend`] on a signing, sealing or
    /// entropy failure.
    pub fn custody_append(&self, req: &AppendRequest) -> Result<Appended, SmError> {
        let keys = self.case_keys(&req.cid_c);
        let at = (req.cid_c, req.capsule.eid);
        let j = append::position(req);

        // ⭐ The one check this module adds to the shared builder, and the one
        // only a boundary can make: `j` fixes `rid`, and `rid[..12]` is the
        // record body's AEAD nonce (§1br F1), so a reused `j` reuses a nonce.
        if let Some(highest) = self
            .append
            .lock()
            .map_err(|_| Self::lock_err("append state"))?
            .positions
            .get(&at)
            .copied()
            .filter(|h| j <= *h)
        {
            return Err(SmError::PositionReused { j, highest });
        }

        let (signed, pairing) = append::sign_step(self, &keys, req)?;

        // Positions and tokens advance together, under one lock, because a
        // record that was signed but not indexed is a record the custody plane
        // cannot find -- and one indexed twice is a counter that skipped.
        let mut state = self
            .append
            .lock()
            .map_err(|_| Self::lock_err("append state"))?;
        let client = state
            .index
            .entry(req.cid_c)
            .or_insert_with(|| pqcl_dsse::core::Client::new(keys.custody_index_key()));
        let tokens = tokens_for(client, &signed, req.doc)?;
        state.positions.insert(at, j);

        Ok(Appended {
            signed,
            tokens,
            pairing,
        })
    }

    /// Seal one capsule inside the boundary, with the enrolled first responder
    /// and the case keys derived here (M13 A18).
    ///
    /// # Errors
    ///
    /// No DEFR enrolled, or a signing failure.
    pub fn seal_capsule(
        &self,
        req: &crate::append::SealRequest,
    ) -> Result<pqcl_capsule::Capsule, SmError> {
        req.seal(self, &self.case_keys(&req.cid_c))
    }

    /// One capsule's three disclosure keys, derived here from `K_case` and
    /// sealed to `court_ek` before they leave (M13 A18).
    ///
    /// ⭐ Per capsule by construction: `k_eid`, `K_rec^{eid}` and
    /// `K_rid^{eid}` derive nothing about another capsule, and `K_case`,
    /// `K_link` and `K_coc` never leave.
    ///
    /// # Errors
    ///
    /// A malformed court key, or an AEAD failure.
    pub fn sealed_disclosure(
        &self,
        cid_c: &Digest32,
        eid: &Digest32,
        court_ek: &[u8],
    ) -> Result<pqcl_capsule::SealedDisclosure, SmError> {
        let keys = self.case_keys(cid_c).disclosure_keys(eid);
        pqcl_capsule::SealedDisclosure::seal(&keys, *cid_c, *eid, court_ek)
            .map_err(|e| SmError::Backend(e.to_string()))
    }

    /// `K_case = F(K_mst, ⟪"case", cid_c⟫)`.
    ///
    /// Private on purpose, and it must stay private. Returning `K_case` to a
    /// caller would let them derive every key below it, which is the entire
    /// hierarchy — see [`AgentModule`]'s note that no method returns a key.
    fn case_key(&self, case_commitment: &Digest32) -> PrfKey {
        PrfKey::new(prf(&self.k_mst, Label::Case, &[case_commitment]))
    }

    /// A poisoned lock means another thread panicked mid-operation. Report it
    /// rather than propagating the panic — the ingest path runs for hours under
    /// a measurement harness, where a panic loses a run rather than a record.
    fn lock_err(what: &'static str) -> SmError {
        SmError::Backend(format!("{what} lock poisoned by a panicking thread"))
    }
}

impl append::Actors for HostAgentModule {
    fn actor(&self, who: &ActorRef) -> Result<&Agent, SmError> {
        Self::actor(self, who)
    }

    fn first_responder(&self) -> Result<&Agent, SmError> {
        Self::first_responder(self)
    }
}

impl crate::append::CustodyAppender for HostAgentModule {
    fn backend(&self) -> Backend {
        <Self as KeyCustody>::backend(self)
    }

    fn append(&self, req: &AppendRequest) -> Result<Appended, SmError> {
        self.custody_append(req)
    }

    fn seal(&self, req: &crate::append::SealRequest) -> Result<pqcl_capsule::Capsule, SmError> {
        self.seal_capsule(req)
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
        self.sealed_disclosure(cid_c, eid, court_ek)
    }
}

impl KeyCustody for HostAgentModule {
    type Handle = HostHandle;

    fn backend(&self) -> Backend {
        Backend::HostSoftware
    }

    fn generate_non_extractable_aes256(&self, _label: &str) -> Result<HostHandle, SmError> {
        let bytes = rng::secret().map_err(|e| SmError::Backend(e.to_string()))?;

        let mut next = self.next.lock().map_err(|_| Self::lock_err("handle"))?;
        let id = *next;
        *next += 1;
        drop(next);

        self.keys
            .lock()
            .map_err(|_| Self::lock_err("key store"))?
            .insert(id, CustodyKey::new(bytes));
        Ok(HostHandle(id))
    }

    /// Always refuses — see the module docs on what that refusal is and is not
    /// worth.
    fn try_export(&self, _key: HostHandle) -> Result<Vec<u8>, SmError> {
        Err(SmError::ExtractionRefused)
    }

    fn aes_gcm_encrypt(
        &self,
        key: HostHandle,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SmError> {
        self.keys
            .lock()
            .map_err(|_| Self::lock_err("key store"))?
            .get(&key.0)
            .ok_or_else(|| SmError::Backend(format!("no key for handle {}", key.0)))?
            .seal(nonce, aad, plaintext)
            .map_err(|e| SmError::Backend(format!("AES-GCM seal failed: {e}")))
    }

    fn aes_gcm_decrypt(
        &self,
        key: HostHandle,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SmError> {
        self.keys
            .lock()
            .map_err(|_| Self::lock_err("key store"))?
            .get(&key.0)
            .ok_or_else(|| SmError::Backend(format!("no key for handle {}", key.0)))?
            .open(nonce, aad, ciphertext)
            .map_err(|e| SmError::Backend(format!("AES-GCM open failed: {e}")))
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, SmError> {
        let mut buf = vec![0u8; len];
        rng::fill(&mut buf).map_err(|e| SmError::Backend(e.to_string()))?;
        Ok(buf)
    }
}

impl AgentModule for HostAgentModule {
    fn capsule_pseudonym(
        &self,
        case_commitment: &Digest32,
        nonce: &[u8],
    ) -> Result<Digest32, SmError> {
        let k_case = self.case_key(case_commitment);
        Ok(prf(&k_case, Label::Eid, &[nonce]))
    }

    fn sign_defr(&self, message: &[u8]) -> Result<Vec<u8>, SmError> {
        self.first_responder()?
            .sign_defr(message)
            .map_err(|e| SmError::Backend(format!("ML-DSA sign failed: {e}")))
    }

    fn defr_public_key(&self) -> Result<Vec<u8>, SmError> {
        Ok(self.first_responder()?.public_key().to_vec())
    }
}
