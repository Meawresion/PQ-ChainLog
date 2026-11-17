//! Where a harness's custody records come from (M13 A18).
//!
//! # The two appenders
//!
//! * [`InProcess`] signs with the harness's own [`Cast`], under case keys the
//!   harness holds in its own memory. There is no boundary, so it reports
//!   [`Backend::HostSoftware`]. Every record it builds is local iteration, and
//!   `mkfigs.py` refuses to publish one.
//! * The enclave, reached through `pqcl_nitro::NitroAgentModule` when the crate
//!   is built with `--features enclave` and `PQCL_SECURE_MODULE=nitro:<cid>`.
//!   It reports [`Backend::NitroEnclave`], the one backend whose records
//!   publish.
//!
//! Both build each record through `pqcl_sm::sign_step` and index it through
//! `pqcl_sm::tokens_for`, so they differ in *where the keys are* and in
//! nothing about *what is built*. That is what makes a local run a fair
//! rehearsal of the campaign.
//!
//! # ⚠️ What `InProcess` does not do
//!
//! It checks no positions. The enclave refuses a second record at a position it
//! has already signed, because `j` is the body's AEAD nonce. `InProcess` is not
//! a boundary and makes no such promise, which is part of why it does not
//! publish.

use std::sync::Mutex;

use pqcl_capsule::{ActorRef, Capsule};
use pqcl_dsse::core::Client;
use pqcl_pipeline::{Ais, CaseKeys};
use pqcl_primitives::kem;
use pqcl_primitives::xof::Digest32;
use pqcl_sm::{
    Actors, AppendRequest, Appended, Backend, CustodyAppender, SealRequest, SmError, sign_step,
    tokens_for,
};

use crate::cast::Cast;

/// The harness's own cast, building records in this process.
pub struct InProcess<'a> {
    cast: &'a Cast,
    keys: &'a CaseKeys,
    /// The case's custody index, under `K_S^COC` from the case keys.
    index: Mutex<Client>,
    /// `eid` → the highest `j` signed: the module's nonce guard, kept here too.
    ///
    /// ⭐ **So a harness that reuses a position fails in CI, not on AWS**
    /// (rule 13). `j` fixes `rid`, whose prefix is the record body's AES-GCM
    /// nonce under the capsule's key (§1br F1). Only the enclave refused a repeat, so the custody harness's timed
    /// transfer loop re-signed positions 1 and 2 of one capsule ten times and
    /// was found by campaign 08's enclave smoke, after every local run had
    /// passed.
    positions: Mutex<std::collections::HashMap<Digest32, u64>>,
}

impl<'a> InProcess<'a> {
    /// An appender over a cast and one case's keys.
    #[must_use]
    pub fn new(cast: &'a Cast, keys: &'a CaseKeys) -> Self {
        Self {
            cast,
            keys,
            index: Mutex::new(Client::new(keys.custody_index_key())),
            positions: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// One appender holds one case; a request for another is a harness bug,
    /// refused rather than signed under the wrong keys.
    fn this_case(&self, cid_c: &pqcl_primitives::xof::Digest32) -> Result<(), SmError> {
        if *cid_c == self.keys.cid_c {
            Ok(())
        } else {
            Err(SmError::Config(
                "this in-process appender holds a different case's keys".to_owned(),
            ))
        }
    }
}

impl CustodyAppender for InProcess<'_> {
    fn backend(&self) -> Backend {
        Backend::HostSoftware
    }

    fn append(&self, req: &AppendRequest) -> Result<Appended, SmError> {
        self.this_case(&req.cid_c)?;
        let eid = req.capsule.eid;
        let j = pqcl_sm::position(req);
        let poisoned = || SmError::Backend("custody position lock poisoned".to_owned());
        if let Some(highest) = self
            .positions
            .lock()
            .map_err(|_| poisoned())?
            .get(&eid)
            .copied()
            .filter(|h| j <= *h)
        {
            return Err(SmError::PositionReused { j, highest });
        }
        let (signed, pairing) = sign_step(self.cast, self.keys, req)?;
        let mut index = self
            .index
            .lock()
            .map_err(|_| SmError::Backend("custody index lock poisoned".to_owned()))?;
        let tokens = tokens_for(&mut index, &signed, req.doc)?;
        self.positions
            .lock()
            .map_err(|_| poisoned())?
            .insert(eid, j);
        Ok(Appended {
            signed,
            tokens,
            pairing,
        })
    }

    fn seal(&self, req: &SealRequest) -> Result<Capsule, SmError> {
        self.this_case(&req.cid_c)?;
        req.seal(self.cast, self.keys)
    }

    fn verification_key(&self, who: &ActorRef) -> Result<Vec<u8>, SmError> {
        Ok(self.cast.actor(who)?.public_key().to_vec())
    }

    fn seal_disclosure(
        &self,
        cid_c: &Digest32,
        eid: &Digest32,
        court_ek: &[u8],
    ) -> Result<pqcl_capsule::SealedDisclosure, SmError> {
        if *cid_c != self.keys.cid_c {
            return Err(SmError::Backend(
                "this in-process appender holds a different case's keys".to_owned(),
            ));
        }
        pqcl_capsule::SealedDisclosure::seal(
            &self.keys.disclosure_keys(eid),
            *cid_c,
            *eid,
            court_ek,
        )
        .map_err(|e| SmError::Backend(e.to_string()))
    }
}

/// The environment variable that chooses the appender.
pub const SECURE_MODULE_VAR: &str = "PQCL_SECURE_MODULE";

/// Choose the appender a run builds its records through.
///
/// * unset, or `in-process` — [`InProcess`];
/// * `nitro:<cid>` — the enclave at vsock context `<cid>`, which needs
///   `--features enclave`.
///
/// ⛔ **Anything else is refused, and so is `nitro:` in a build without the
/// feature.** A silent fallback would be worse than useless: the run would look
/// like a campaign run and produce local numbers, and the only thing standing
/// between them and the paper would be `mkfigs.py`. That guard works, but a run
/// that wastes an instance-hour to be refused at the end is a failure too.
///
/// # Errors
///
/// An unrecognised value, a malformed context id, a `nitro:` request in a build
/// without `enclave`, or an enclave that cannot be reached.
pub fn from_env<'a>(
    cast: &'a Cast,
    keys: &'a CaseKeys,
) -> Result<Box<dyn CustodyAppender + 'a>, Box<dyn core::error::Error>> {
    from_value(
        &std::env::var(SECURE_MODULE_VAR).unwrap_or_default(),
        cast,
        keys,
    )
}

/// [`from_env`], over a value rather than the process environment — which
/// tests share, so they call this instead of setting the variable.
///
/// # Errors
///
/// As [`from_env`].
pub fn from_value<'a>(
    value: &str,
    cast: &'a Cast,
    keys: &'a CaseKeys,
) -> Result<Box<dyn CustodyAppender + 'a>, Box<dyn core::error::Error>> {
    match value {
        "" | "in-process" => Ok(Box::new(InProcess::new(cast, keys))),
        other => match other.strip_prefix("nitro:") {
            Some(cid) => nitro(cid),
            None => Err(format!(
                "{SECURE_MODULE_VAR}={other:?} is not a Secure Module this harness knows; \
                 use `in-process` or `nitro:<cid>`"
            )
            .into()),
        },
    }
}

#[cfg(feature = "enclave")]
fn nitro<'a>(cid: &str) -> Result<Box<dyn CustodyAppender + 'a>, Box<dyn core::error::Error>> {
    let cid: u32 = cid
        .parse()
        .map_err(|e| format!("{SECURE_MODULE_VAR}: {cid:?} is not a vsock context id: {e}"))?;
    Ok(Box::new(pqcl_nitro::host::NitroAgentModule::connect(cid)?))
}

#[cfg(not(feature = "enclave"))]
fn nitro<'a>(cid: &str) -> Result<Box<dyn CustodyAppender + 'a>, Box<dyn core::error::Error>> {
    Err(format!(
        "{SECURE_MODULE_VAR}=nitro:{cid} needs a build with `--features enclave`; \
         this one has no vsock client, and falling back to in-process would produce \
         local numbers that look like campaign ones"
    )
    .into())
}

/// Discloses capsules the way a court receives them, whichever boundary built
/// the case: the appender seals each capsule's three keys to the court, the
/// court opens them, and the AIS assembles the bundle (M13 A18).
///
/// ⭐ **The one path for every harness.** `Ais::disclose(index, &CaseKeys)`
/// derives the keys from the harness's own `K_case`; under Nitro that is not
/// the `K_case` the records were made under, so every bundle came back empty
/// (`"no bundle for the target"`, campaign 08's first enclave smoke). Going
/// through the appender makes the in-process and enclave runs take the same
/// steps, one sealed round trip per disclosed capsule.
pub struct Discloser<'a> {
    appender: &'a dyn CustodyAppender,
    cid_c: Digest32,
    court: kem::KeyPair,
}

impl<'a> Discloser<'a> {
    /// A court with a fresh ML-KEM-768 key pair, receiving disclosures of case
    /// `cid_c` from `appender`.
    ///
    /// # Errors
    ///
    /// Key generation failed.
    pub fn new(
        appender: &'a dyn CustodyAppender,
        cid_c: Digest32,
    ) -> Result<Self, Box<dyn core::error::Error>> {
        Ok(Self {
            appender,
            cid_c,
            court: kem::KeyPair::generate()?,
        })
    }

    /// Capsule `index`'s bundle, or `None` where [`Ais::disclose_with`] has
    /// none.
    ///
    /// # Errors
    ///
    /// The appender's refusal, or a sealed disclosure the court cannot open.
    pub fn disclose(
        &self,
        ais: &Ais,
        index: usize,
    ) -> Result<Option<pqcl_capsule::Bundle>, Box<dyn core::error::Error>> {
        let Some(capsule) = ais.capsule(index) else {
            return Ok(None);
        };
        let sealed = self.appender.seal_disclosure(
            &self.cid_c,
            &capsule.eid,
            self.court.encapsulation_key(),
        )?;
        Ok(ais.disclose_with(index, sealed.open(&self.court)?))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// One of every backend. The `match` has no wildcard, so a new variant does
    /// not compile until it is listed here — and then the test below decides
    /// whether its label is the publishable one.
    fn every_backend() -> Vec<Backend> {
        let all = vec![
            Backend::Pkcs11 {
                software_only: true,
            },
            Backend::Pkcs11 {
                software_only: false,
            },
            Backend::NitroEnclave,
            Backend::HostSoftware,
        ];
        for b in &all {
            match b {
                Backend::Pkcs11 { .. } | Backend::NitroEnclave | Backend::HostSoftware => {}
            }
        }
        all
    }

    /// ⭐ The label is spelled in two crates — `Backend::label` here and
    /// `PUBLISHABLE_SECURE_MODULE` in `pqcl-bench`, which cannot depend on
    /// `pqcl-sm` — so this is the check that they agree. It holds both ways: the
    /// enclave's label is the publishable one, and no other backend's is.
    #[test]
    fn the_publishable_label_is_the_enclave_s_and_only_its() {
        let backends = every_backend();
        for b in &backends {
            assert_eq!(
                b.is_publishable(),
                b.label() == pqcl_bench::PUBLISHABLE_SECURE_MODULE,
                "{b:?}: is_publishable and the publication guard disagree"
            );
        }
        assert_eq!(
            backends.iter().filter(|b| b.is_publishable()).count(),
            1,
            "exactly one backend publishes"
        );
        let labels: std::collections::BTreeSet<_> = backends.iter().map(|b| b.label()).collect();
        assert_eq!(labels.len(), backends.len(), "labels are distinct");
    }

    #[test]
    fn the_in_process_appender_says_it_is_not_a_boundary() {
        let cast = Cast::generate().expect("a cast");
        let keys = CaseKeys::derive(
            &pqcl_primitives::xof::PrfKey::new([7; 32]),
            b"case",
            &[1; 32],
        );
        let a = InProcess::new(&cast, &keys);
        assert_eq!(a.backend(), Backend::HostSoftware);
        assert!(!a.backend().is_publishable());
    }

    #[test]
    fn an_unknown_secure_module_is_refused_not_defaulted() {
        let cast = Cast::generate().expect("a cast");
        let keys = CaseKeys::derive(
            &pqcl_primitives::xof::PrfKey::new([7; 32]),
            b"case",
            &[1; 32],
        );
        let pick = |v: &str| -> Result<Backend, String> {
            from_value(v, &cast, &keys)
                .map(|a| a.backend())
                .map_err(|e| e.to_string())
        };
        assert_eq!(pick("").unwrap(), Backend::HostSoftware);
        assert_eq!(pick("in-process").unwrap(), Backend::HostSoftware);
        assert!(pick("softhsm").is_err());
        assert!(
            pick("nitro").is_err(),
            "no colon, no cid: not the enclave form"
        );
        #[cfg(not(feature = "enclave"))]
        assert!(
            pick("nitro:16").unwrap_err().contains("--features enclave"),
            "a build without the vsock client must say so, not fall back"
        );
    }
}
