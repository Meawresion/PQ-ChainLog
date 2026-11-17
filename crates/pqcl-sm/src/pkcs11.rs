//! A PKCS#11 [`KeyCustody`] backend, driven against a real token.
//!
//! There is no stand-in here and no in-memory fallback. If no token is
//! reachable, construction fails and every test that needs one fails with it —
//! The build plan: *a test that is skipped is indistinguishable
//! from a test that passed.*
//!
//! # Configuring the token
//!
//! `SoftHSM2` reads its configuration from `SOFTHSM2_CONF` at `C_Initialize`
//! time, which is process-global and read before any Rust code here runs. So
//! the environment must be set **outside** the test process — `scripts/
//! softhsm2-init.sh` does it — rather than by the test, which would also mean
//! mutating the environment of a multi-threaded process.
//!
//! This mirrors how the Enron corpus is wired (`PQCL_ENRON`), including the
//! lesson that cost a failed run there: **the path must be absolute**, because
//! a test binary's working directory is its own crate root, not the workspace.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::sync::OnceLock;

use crate::custody::{Backend, KeyCustody, SmError};

/// GCM tag length in bits. Fixed at the maximum; the design's AEAD is
/// AES-256-GCM with a full 128-bit tag and nothing here may weaken it.
const GCM_TAG_BITS: u64 = 128;

/// AES-256, in bytes.
const AES_256_BYTES: u64 = 32;

/// The one PKCS#11 context this process will ever have.
///
/// ⚠️ **Not an optimisation — a correctness requirement, and it cost a
/// SIGSEGV to find.** PKCS#11 permits exactly one `C_Initialize` per process,
/// and `Pkcs11`'s `Drop` calls `C_Finalize`, which tears down state that other
/// live sessions are still using. The first version of this file built a
/// context per [`Pkcs11Custody`]; all five tests passed under
/// `--test-threads=1` and the harness crashed instantly in parallel.
///
/// The tempting fix is to pin the test harness to one thread. That would have
/// hidden the bug rather than fixed it, and left it for the ingest pipeline,
/// which is threaded by design and would have hit the same crash under a
/// measurement run instead of under a test.
///
/// Initialised with `OS_LOCKING_OK`, so the module serialises its own internal
/// state and sessions may be used from several threads.
static CONTEXT: OnceLock<Result<Pkcs11, String>> = OnceLock::new();

/// The module path the process-wide context was built from.
static CONTEXT_MODULE: OnceLock<String> = OnceLock::new();

/// Borrow the process-wide context, initialising it on first use.
fn shared_context(module_path: &str) -> Result<&'static Pkcs11, SmError> {
    let stored = CONTEXT.get_or_init(|| {
        let ctx = Pkcs11::new(module_path)
            .map_err(|e| format!("cannot load PKCS#11 module at {module_path}: {e}"))?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| format!("C_Initialize failed: {e}"))?;
        Ok(ctx)
    });
    let first = CONTEXT_MODULE.get_or_init(|| module_path.to_owned());

    // One context per process means one module per process. Asking for a second
    // is a caller error, and silently handing back the first module's context
    // would be answering a different question than the one asked.
    if first != module_path {
        return Err(SmError::Config(format!(
            "this process is already bound to PKCS#11 module {first}; \
             it cannot also open {module_path}"
        )));
    }

    stored.as_ref().map_err(|e| SmError::Config(e.clone()))
}

/// A live session against a PKCS#11 token.
pub struct Pkcs11Custody {
    session: Session,
    software_only: bool,
}

impl Pkcs11Custody {
    /// Open a session against the token in `slot_index`, and log in as user.
    ///
    /// # Errors
    ///
    /// [`SmError::NoToken`] if the slot has no token, and
    /// [`SmError::Backend`] for any PKCS#11 failure — including a wrong PIN,
    /// which is deliberately not given its own variant, since distinguishing it
    /// is exactly what a PIN-guessing oracle wants.
    pub fn open(module_path: &str, slot_index: usize, pin: &str) -> Result<Self, SmError> {
        let ctx = shared_context(module_path)?;

        let slots = ctx
            .get_slots_with_token()
            .map_err(|e| SmError::Backend(format!("C_GetSlotList failed: {e}")))?;
        let slot = *slots.get(slot_index).ok_or(SmError::NoToken)?;

        let info = ctx
            .get_token_info(slot)
            .map_err(|e| SmError::Backend(format!("C_GetTokenInfo failed: {e}")))?;
        // SoftHSM2 is software. Recording that here, from the token's own
        // manufacturer string, is what stops a SoftHSM2 measurement being
        // presented later as a hardware result.
        let software_only = info.manufacturer_id().contains("SoftHSM");

        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| SmError::Backend(format!("C_OpenSession failed: {e}")))?;
        // PKCS#11 login state belongs to the **application**, not the session:
        // once any session on a token is logged in as User, every other session
        // in the process already is. So a second C_Login returns
        // CKR_USER_ALREADY_LOGGED_IN, which means "you have what you asked
        // for", not "this failed".
        //
        // Treating it as an error is what made the concurrency test fail after
        // the context was shared — the first thread logged in and the other
        // three were rejected for succeeding.
        match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
            Ok(()) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(e) => return Err(SmError::Backend(format!("C_Login failed: {e}"))),
        }

        Ok(Self {
            session,
            software_only,
        })
    }

    /// Look up an object by its `CKA_LABEL`.
    ///
    /// # Errors
    ///
    /// [`SmError::Backend`] if the search fails or matches no object.
    pub fn find_by_label(&self, label: &str) -> Result<ObjectHandle, SmError> {
        let found = self
            .session
            .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])
            .map_err(|e| SmError::Backend(format!("C_FindObjects failed: {e}")))?;
        found
            .first()
            .copied()
            .ok_or_else(|| SmError::Backend(format!("no object labelled {label:?}")))
    }
}

impl KeyCustody for Pkcs11Custody {
    type Handle = ObjectHandle;

    fn backend(&self) -> Backend {
        Backend::Pkcs11 {
            software_only: self.software_only,
        }
    }

    fn generate_non_extractable_aes256(&self, label: &str) -> Result<ObjectHandle, SmError> {
        // SENSITIVE(true) + EXTRACTABLE(false) is the pair that matters.
        // SENSITIVE alone still permits C_WrapKey, so a host could wrap the key
        // under one it controls and decrypt it outside — which would defeat the
        // whole property while every attribute still looked protective.
        let template = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::ValueLen(AES_256_BYTES.into()),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ];
        let handle = self
            .session
            .generate_key(&Mechanism::AesKeyGen, &template)
            .map_err(|e| SmError::Backend(format!("C_GenerateKey failed: {e}")))?;
        Ok(handle)
    }

    fn try_export(&self, key: ObjectHandle) -> Result<Vec<u8>, SmError> {
        match self.session.get_attributes(key, &[AttributeType::Value]) {
            // A conforming token refuses outright: CKR_ATTRIBUTE_SENSITIVE.
            Err(_) => Err(SmError::ExtractionRefused),
            Ok(attrs) => match attrs.first() {
                Some(Attribute::Value(bytes)) => Ok(bytes.clone()),
                // Some tokens answer with the attribute simply absent rather
                // than erroring. That is still a refusal, and treating it as
                // one keeps the test honest across implementations instead of
                // passing only against SoftHSM2's particular choice.
                _ => Err(SmError::ExtractionRefused),
            },
        }
    }

    fn aes_gcm_encrypt(
        &self,
        key: ObjectHandle,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SmError> {
        let mut iv = *nonce;
        let params = GcmParams::new(&mut iv, aad, GCM_TAG_BITS.into())
            .map_err(|e| SmError::Backend(format!("bad GCM parameters: {e}")))?;
        self.session
            .encrypt(&Mechanism::AesGcm(params), key, plaintext)
            .map_err(|e| SmError::Backend(format!("C_Encrypt failed: {e}")))
    }

    fn aes_gcm_decrypt(
        &self,
        key: ObjectHandle,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SmError> {
        let mut iv = *nonce;
        let params = GcmParams::new(&mut iv, aad, GCM_TAG_BITS.into())
            .map_err(|e| SmError::Backend(format!("bad GCM parameters: {e}")))?;
        self.session
            .decrypt(&Mechanism::AesGcm(params), key, ciphertext)
            .map_err(|e| SmError::Backend(format!("C_Decrypt failed: {e}")))
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, SmError> {
        let mut buf = vec![0u8; len];
        self.session
            .generate_random_slice(&mut buf)
            .map_err(|e| SmError::Backend(format!("C_GenerateRandom failed: {e}")))?;
        Ok(buf)
    }
}
