//! The `KeyCustody` trait — the operations every real backend can perform.
//!
//! Membership of this trait is decided by one question: *can a PKCS#11 token
//! and a TEE both do this, honestly?* Anything that fails that test belongs in
//! `SecureModule` instead. See the crate docs and the design record.

use core::fmt;

/// Which boundary a [`KeyCustody`] implementation actually provides.
///
/// This is reported, never inferred, and it is carried into results metadata so
/// a number can never be attributed to a stronger boundary than produced it.
/// The project rules keeps paper numbers to AWS; this is the same
/// principle one level down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// A PKCS#11 token. Real, but **preview only** — the plan bars it from
    /// producing any paper number.
    Pkcs11 {
        /// Whether this token is `SoftHSM2`, which is software and therefore
        /// offers no hardware guarantee whatsoever — only the API's refusal
        /// semantics. A physical HSM reports `false`.
        software_only: bool,
    },
    /// An AWS Nitro Enclave. Produces paper numbers. Arrives at M5b.
    NitroEnclave,
    /// Keys held in this process's own memory, with **no boundary at all**.
    ///
    /// Not a weaker enclave — *no* enclave. It exists so that local iteration
    /// runs the same source the enclave will run, minus the boundary; if the
    /// two implementations diverged, iterating locally would prove nothing
    /// about what AWS executes.
    ///
    /// Gated behind the default-off `host-software` feature, and
    /// [`Backend::is_publishable`] is `false` for it, so it cannot reach a
    /// paper table by accident.
    HostSoftware,
}

impl Backend {
    /// Whether a measurement from this backend may reach the paper.
    ///
    /// `SoftHSM2` is a software token: it enforces `CKA_EXTRACTABLE = false` by
    /// deciding not to answer, with the key sitting in the host's own address
    /// space. That is a faithful exercise of the PKCS#11 *contract*, which is
    /// what makes it useful for testing the trait, and it is worth exactly
    /// nothing as a hardware claim.
    #[must_use]
    pub const fn is_publishable(self) -> bool {
        matches!(self, Self::NitroEnclave)
    }

    /// The name a results record carries in its `secure_module` field (M13
    /// A18).
    ///
    /// ⚠️ `"nitro-enclave"` is also written as
    /// `pqcl_bench::PUBLISHABLE_SECURE_MODULE`, which the publication guard
    /// compares against, because `pqcl-bench` cannot depend on this crate.
    /// `pqcl-exp` checks every variant: the enclave's label must equal that
    /// constant, and no other variant's may.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pkcs11 {
                software_only: true,
            } => "pkcs11-softhsm",
            Self::Pkcs11 {
                software_only: false,
            } => "pkcs11",
            Self::NitroEnclave => "nitro-enclave",
            Self::HostSoftware => "host-software",
        }
    }
}

/// What a Secure Module backend can fail to do.
#[derive(Debug)]
pub enum SmError {
    /// The backend does not implement this operation **and will not pretend
    /// to**.
    ///
    /// This variant is load-bearing rather than defensive. Ground rule #1 bans
    /// a software stand-in dressed as an HSM. The tempting shape for the
    /// PKCS#11 backend is to sign ML-DSA in process behind the same trait,
    /// which would be undetectable in a results table. Returning this instead
    /// is what keeps the boundary honest, so a caller must handle it rather
    /// than receive a plausible answer.
    Unsupported {
        /// The operation asked for.
        operation: &'static str,
        /// The backend that declined.
        backend: Backend,
        /// Why it cannot, concretely — a mechanism name, not a shrug.
        reason: &'static str,
    },
    /// Extraction of a non-extractable key was attempted and correctly refused.
    ///
    /// A distinct variant because a test asserts this **specific** outcome. If
    /// it were folded into `Backend`, a token that failed for an unrelated
    /// reason would pass the extraction-refusal test, which would then be
    /// proving nothing.
    ExtractionRefused,
    /// No token was present in the requested slot.
    NoToken,
    /// No actor is enrolled as the `(role, id)` a request named (M13 A18;
    /// `(role, id)` enrolment, §1br.4).
    ///
    /// Carries the role's **byte** rather than the type, because this enum is
    /// compiled for the SP1 guest, where `pqcl-capsule` is not present. The
    /// same reason applies to [`Self::WrongRole`].
    NoSuchActor {
        /// The role byte asked for.
        role: u8,
        /// The identifier asked for; empty when the request named a role only.
        id: Vec<u8>,
    },
    /// The role may not sign the event — draft8's signer table (M13 A2).
    WrongRole {
        /// The event byte.
        event: u8,
        /// The role byte that tried.
        role: u8,
    },
    /// ⭐ **A record was asked for at a position this module has already
    /// signed** (M13 A18).
    ///
    /// Refused rather than served, because `j` fixes `rid`, whose leading 12
    /// bytes are the record body's AES-GCM nonce under a per-capsule key
    /// (§1br F1): two records at one position are the
    /// same key and the same nonce over different plaintext, which forfeits
    /// authentication entirely. On the host path `j`'s uniqueness was an
    /// honest-client assumption; inside the boundary it is checked.
    PositionReused {
        /// The position asked for.
        j: u64,
        /// The highest this module has already signed for that capsule.
        highest: u64,
    },
    /// The timestamp falls outside the custody plane's range attribute, so the
    /// record could not be indexed under a keyword any query can reach.
    TimestampOutOfWindow {
        /// The offending Unix timestamp.
        ts: u64,
    },
    /// The PKCS#11 module reported a failure.
    Backend(String),
    /// Configuration was missing or unusable.
    Config(String),
}

impl fmt::Display for SmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported {
                operation,
                backend,
                reason,
            } => write!(f, "{backend:?} cannot {operation}: {reason}"),
            Self::ExtractionRefused => {
                f.write_str("key is marked non-extractable and the token refused to release it")
            }
            Self::NoToken => f.write_str("no token present in the requested slot"),
            Self::NoSuchActor { role, id } => write!(
                f,
                "no actor is enrolled as {:?} in role {role}",
                String::from_utf8_lossy(id)
            ),
            Self::WrongRole { event, role } => write!(
                f,
                "role {role} may not sign event {event}: draft8's signer table"
            ),
            Self::PositionReused { j, highest } => write!(
                f,
                "a record at position {j} was already signed for this capsule \
                 (highest {highest}); signing another would reuse an AEAD nonce"
            ),
            Self::TimestampOutOfWindow { ts } => write!(
                f,
                "timestamp {ts} is outside the custody plane's range attribute"
            ),
            Self::Backend(m) => write!(f, "PKCS#11 error: {m}"),
            Self::Config(m) => write!(f, "configuration error: {m}"),
        }
    }
}

impl core::error::Error for SmError {}

/// Key custody: secrets that are born inside the boundary and stay there.
///
/// Every method here is implementable by a PKCS#11 token **and** a TEE, which
/// is the entire membership criterion. Adding a method that only one can honour
/// silently converts the shared test suite into a suite that tests one backend
/// and no-ops on the other.
pub trait KeyCustody {
    /// A backend-native reference to a key inside the boundary.
    ///
    /// An associated type rather than a shared newtype over `u64`, and the
    /// reason is worth recording because the obvious design does not compile
    /// here. Wrapping the raw handle would mean rebuilding a
    /// `cryptoki::object::ObjectHandle` from an integer on the way back in, and
    /// cryptoki makes that constructor **`unsafe`** — deliberately, since a
    /// forged handle can name an object the caller was never given. The
    /// workspace denies `unsafe_code`, so the shared-newtype design is
    /// unavailable, and that is the right outcome: it was laundering an
    /// unforgeable reference through a forgeable one.
    ///
    /// Carries no key material and no means of obtaining any. The host holds a
    /// name, never a secret.
    type Handle: Copy + fmt::Debug;

    /// Which boundary this really is. Never inferred by the caller.
    fn backend(&self) -> Backend;

    /// Generate a 256-bit AES key inside the boundary, marked sensitive and
    /// non-extractable.
    ///
    /// `label` names the object within the token so a test can find it again;
    /// it is not a security parameter.
    fn generate_non_extractable_aes256(&self, label: &str) -> Result<Self::Handle, SmError>;

    /// Attempt to read a key's raw bytes out of the boundary.
    ///
    /// For a key created by [`Self::generate_non_extractable_aes256`] this
    /// **must** return [`SmError::ExtractionRefused`]. It exists precisely so a
    /// test can demand the refusal, which is the only way to distinguish a
    /// token that protects the key from one that was simply never asked.
    fn try_export(&self, key: Self::Handle) -> Result<Vec<u8>, SmError>;

    /// Encrypt under a key that never leaves the boundary.
    ///
    /// Returns ciphertext with the GCM tag appended, matching
    /// `pqcl_primitives::aead`'s layout so the two are interchangeable at the
    /// byte level.
    fn aes_gcm_encrypt(
        &self,
        key: Self::Handle,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SmError>;

    /// Decrypt under a key that never leaves the boundary.
    fn aes_gcm_decrypt(
        &self,
        key: Self::Handle,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SmError>;

    /// Random bytes from the boundary's generator.
    fn random(&self, len: usize) -> Result<Vec<u8>, SmError>;
}
