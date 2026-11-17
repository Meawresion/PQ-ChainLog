//! The measurement harness, and the anti-fabrication mechanism it exists for.
//!
//! The build plan fixes one path from a run to a printed number:
//!
//! ```text
//! run -> results/<exp>/<utc>-<git-sha>-<instance>.json
//!     -> tools/mkfigs.py
//!     -> paper/generated/*.tex
//!     -> draft6.tex \input{}s them
//! ```
//!
//! Nobody hand-types a measurement. Two rules make that real rather than
//! aspirational, and both are enforced in code rather than remembered:
//!
//! 1. `mkfigs.py` **refuses** to emit paper tables from a record whose
//!    `environment` is not `aws`.
//! 2. `mkfigs.py` **refuses** to emit from a dirty git tree.
//!
//! # Why this crate exists before anything is measured
//!
//! Retrofitting provenance is how records end up missing the one field a
//! reviewer asks about. [`RunMetadata`] is defined now, while it costs nothing,
//! so that the first experiment cannot be run without it.
//!
//! The fields are not decorative. Each corresponds to something that has
//! already gone wrong or could:
//!
//! * [`CpuFeatures`] — AES-GCM and liboqs both pick their backend at runtime. A
//!   software-fallback number looks entirely normal and is ~10x wrong.
//! * `profile` — a debug build measured AES-GCM at 8 MiB/s where release gives
//!   1524 MiB/s, because generic code compiles at the *caller's* opt-level.
//!   A timing without a profile attached is meaningless.
//! * `liboqs_version` — distinguishes FIPS 204 final from the `ipd` draft.
//! * `git_sha` + `git_dirty` — the repo covers paper and implementation
//!   together, so this SHA also covers the table that prints the number.
//!
//! # A guard is only as good as what fills it in
//!
//! For a while this crate held the *consumer* half and nothing else: the
//! refusal rules existed, `mkfigs.py` mirrored them, both were tested — and
//! nothing in the workspace could produce a record for them to read. That is a
//! comfortable state to be in and a false one, because the first person needing
//! to record a number would have hand-written the JSON, and a hand-written
//! `"environment": "aws"` passes every check here.
//!
//! [`provenance`] closes it. The four fields the guard reads are **observed**,
//! not accepted from the caller, and [`results`] writes them to the one path
//! §11 specifies. `RunSpec` deliberately has no field that could flip a
//! refusal.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub mod provenance;
pub mod results;

pub use provenance::{ProvenanceError, RunSpec};
pub use results::{RunRecord, WriteError, write_run};

/// Where a run happened. Only [`Environment::Aws`] may reach the paper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// A developer machine or WSL. Fine for deciding whether something is worth
    /// running on AWS, and for nothing else.
    Local,
    /// The instance that produces published numbers.
    Aws,
}

/// Build profile. A timing without one attached cannot be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Unoptimised. Never valid for a measurement.
    Debug,
    /// Optimised.
    Release,
}

impl Profile {
    /// The profile this binary was compiled with.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(debug_assertions) {
            Self::Debug
        } else {
            Self::Release
        }
    }
}

/// Everything needed to trace a number back to what produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMetadata {
    /// Commit the run was made from.
    pub git_sha: String,
    /// Whether the tree had uncommitted changes. **A dirty run cannot be
    /// published** — the SHA would not describe the code that ran.
    pub git_dirty: bool,
    /// `local` or `aws`.
    pub environment: Environment,
    /// `debug` or `release`.
    pub profile: Profile,
    /// EC2 instance type, when on AWS.
    pub instance_type: Option<String>,
    /// AWS region, when on AWS.
    pub region: Option<String>,
    /// `uname -r`.
    pub kernel: String,
    /// Rust toolchain, pinned in `rust-toolchain.toml`.
    pub rustc_version: String,
    /// liboqs version string — the one that settles FIPS 204 final vs `ipd`.
    pub liboqs_version: String,
    /// Runtime-detected CPU features, e.g. `aes+pclmulqdq+avx2`.
    pub cpu_features: String,
    /// CPU model, observed from `/proc/cpuinfo` (§1q.6: campaign 04 runs on two
    /// instance types, and the paper quotes each record's host from the record).
    /// `None` where no model line exists. Default for records written before it.
    #[serde(default)]
    pub cpu_model: Option<String>,
    /// SHA-256 of every dataset the run consumed, by name.
    pub dataset_checksums: BTreeMap<String, String>,
    /// RNG seeds, so the run can be repeated exactly.
    pub rng_seeds: Vec<u64>,
    /// Repetitions. §12 requires ≥10, reported as median and IQR.
    pub iterations: u32,
    /// UTC start time, RFC 3339.
    pub started_utc: String,
    /// ⭐ **Which Secure Module built the records this run measured**, by the
    /// backend's own label (`pqcl_sm::Backend::label`) — or `None` for a run
    /// that builds nothing through one (M13 A18).
    ///
    /// `None` is not a loophole, and the reason is structural rather than a
    /// promise: a harness that builds custody records gets its records from a
    /// `CustodyAppender`, which names its backend, and `pqcl_exp::emit_custody`
    /// is the only writer that takes one. A source test asserts every harness
    /// building a case writes through it.
    ///
    /// Only [`PUBLISHABLE_SECURE_MODULE`] passes the guard: The project rules locks
    /// AWS Nitro Enclaves for every paper number, and before this field a
    /// record could not say whether it came from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_module: Option<String>,
}

/// The one Secure Module backend whose records may be published:
/// `pqcl_sm::Backend::NitroEnclave`'s label.
///
/// ⚠️ **Spelled twice, and checked.** This crate cannot depend on `pqcl-sm`, so
/// the label is written here as well as in `Backend::label`.
/// `pqcl-exp`'s `the_publishable_label_is_the_enclave_s_and_only_its` walks
/// every backend and fails if the two disagree, or if any backend other than
/// the enclave carries this label.
pub const PUBLISHABLE_SECURE_MODULE: &str = "nitro-enclave";

/// Why a record may not be published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalReason {
    /// The run did not happen on AWS.
    NotAws(Environment),
    /// The tree had uncommitted changes, so `git_sha` does not describe it.
    DirtyTree(String),
    /// The run was unoptimised.
    DebugBuild,
    /// Too few repetitions to report a median and spread.
    TooFewIterations {
        /// What the run did.
        got: u32,
        /// What §12 requires.
        required: u32,
    },
    /// ⭐ The records were built through a Secure Module that is not the
    /// enclave — the host-software module, or a PKCS#11 token (M13 A18).
    SecureModuleNotEnclave(String),
}

impl RefusalReason {
    /// The snake-case key `tools/mkfigs.py` prefixes the same refusal with.
    ///
    /// Exhaustive with no wildcard, so a new reason cannot be added without
    /// naming its Python twin — and `refusal_kinds_match_the_python_guard`
    /// then reads `mkfigs.py`'s `REFUSAL_KINDS` and fails if the twin is
    /// missing there.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NotAws(_) => "not_aws",
            Self::DirtyTree(_) => "dirty_tree",
            Self::DebugBuild => "debug_build",
            Self::TooFewIterations { .. } => "too_few_iterations",
            Self::SecureModuleNotEnclave(_) => "secure_module_not_enclave",
        }
    }
}

impl core::fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAws(e) => write!(
                f,
                "environment is {e:?}, not Aws: local numbers may decide whether \
                 something is worth running on AWS, and nothing else"
            ),
            Self::DirtyTree(sha) => write!(
                f,
                "tree was dirty at {sha}, so the SHA does not describe the code \
                 that ran"
            ),
            Self::DebugBuild => f.write_str(
                "run was unoptimised; generic code compiles at the caller's \
                 opt-level, so a debug timing can be off by two orders of magnitude",
            ),
            Self::TooFewIterations { got, required } => write!(
                f,
                "{got} iterations, need at least {required} to report a median and IQR"
            ),
            Self::SecureModuleNotEnclave(backend) => write!(
                f,
                "records were built through the {backend} Secure Module, not \
                 {PUBLISHABLE_SECURE_MODULE}: paper numbers come from the enclave"
            ),
        }
    }
}

impl core::error::Error for RefusalReason {}

/// Minimum repetitions, the build plan.
pub const MIN_ITERATIONS: u32 = 10;

impl RunMetadata {
    /// Whether this record may be turned into a paper table or figure.
    ///
    /// The same rules `tools/mkfigs.py` applies, expressed once here so the
    /// Rust side and the Python side cannot drift apart. Returns every reason,
    /// not just the first, so a run is not fixed one complaint at a time.
    #[must_use]
    pub fn publication_refusals(&self) -> Vec<RefusalReason> {
        let mut out = Vec::new();
        if self.environment != Environment::Aws {
            out.push(RefusalReason::NotAws(self.environment));
        }
        if self.git_dirty {
            out.push(RefusalReason::DirtyTree(self.git_sha.clone()));
        }
        if self.profile != Profile::Release {
            out.push(RefusalReason::DebugBuild);
        }
        if self.iterations < MIN_ITERATIONS {
            out.push(RefusalReason::TooFewIterations {
                got: self.iterations,
                required: MIN_ITERATIONS,
            });
        }
        if let Some(backend) = &self.secure_module
            && backend != PUBLISHABLE_SECURE_MODULE
        {
            out.push(RefusalReason::SecureModuleNotEnclave(backend.clone()));
        }
        out
    }

    /// Record which Secure Module built this run's records.
    ///
    /// Takes the backend's label rather than the backend, because this crate
    /// does not depend on `pqcl-sm`; `pqcl_exp::emit_custody` is the one
    /// caller, and it passes `appender.backend().label()`.
    #[must_use]
    pub fn through_secure_module(mut self, label: &str) -> Self {
        self.secure_module = Some(label.to_owned());
        self
    }

    /// Convenience: may this record be published at all?
    #[must_use]
    pub fn is_publishable(&self) -> bool {
        self.publication_refusals().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use pqcl_primitives::platform::CpuFeatures;

    use super::*;

    fn aws_release() -> RunMetadata {
        RunMetadata {
            git_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            git_dirty: false,
            environment: Environment::Aws,
            profile: Profile::Release,
            instance_type: Some("m7i.4xlarge".into()),
            region: Some("ap-southeast-1".into()),
            kernel: "6.8.0-1021-aws".into(),
            rustc_version: "1.97.1".into(),
            liboqs_version: "FIPS204".into(),
            cpu_features: CpuFeatures::detect().summary(),
            cpu_model: Some("fixture CPU model".into()),
            dataset_checksums: BTreeMap::new(),
            rng_seeds: vec![42],
            iterations: 10,
            started_utc: "2026-09-09T12:00:00Z".into(),
            secure_module: None,
        }
    }

    /// One of every refusal, for the cross-language check.
    ///
    /// ⚠️ Kept beside [`RefusalReason::kind`]'s exhaustive match: a new variant
    /// will not compile until `kind` names it, and the Python check below then
    /// fails until `mkfigs.py` names it too. Forgetting to add it *here* as well
    /// is caught the same way, because the Python side will have one more kind
    /// than this list.
    fn one_of_each() -> Vec<RefusalReason> {
        vec![
            RefusalReason::NotAws(Environment::Local),
            RefusalReason::DirtyTree("x".into()),
            RefusalReason::DebugBuild,
            RefusalReason::TooFewIterations {
                got: 1,
                required: MIN_ITERATIONS,
            },
            RefusalReason::SecureModuleNotEnclave("host-software".into()),
        ]
    }

    /// ⭐ **Rule 14 across the language boundary.** `mkfigs.py` used to check
    /// its own `REFUSAL_KINDS` against a Python literal of the same four names,
    /// which can never notice the Rust side changing. This reads the tuple out
    /// of the script itself and compares it with the kinds this enum produces.
    #[test]
    fn refusal_kinds_match_the_python_guard() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tools")
            .join("mkfigs.py");
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let line = src
            .lines()
            .find(|l| l.starts_with("REFUSAL_KINDS = ("))
            .unwrap_or_else(|| panic!("no `REFUSAL_KINDS = (` line in {}", path.display()));
        let python: BTreeSet<&str> = line.split('"').skip(1).step_by(2).collect();
        let rust: BTreeSet<&str> = one_of_each().iter().map(RefusalReason::kind).collect();
        assert!(!python.is_empty(), "parsed nothing from {line:?}");
        assert_eq!(
            rust,
            python,
            "RefusalReason and mkfigs.py's REFUSAL_KINDS disagree ({})",
            path.display()
        );
    }

    #[test]
    fn a_run_that_names_no_secure_module_makes_no_claim_and_is_not_refused() {
        assert!(aws_release().is_publishable());
    }

    #[test]
    fn a_run_through_the_enclave_is_publishable() {
        let m = aws_release().through_secure_module(PUBLISHABLE_SECURE_MODULE);
        assert!(m.is_publishable(), "{:?}", m.publication_refusals());
    }

    #[test]
    fn a_run_through_any_other_secure_module_is_refused() {
        for other in ["host-software", "pkcs11-softhsm", "pkcs11", ""] {
            let m = aws_release().through_secure_module(other);
            assert_eq!(
                m.publication_refusals(),
                vec![RefusalReason::SecureModuleNotEnclave(other.to_owned())],
                "{other:?} must not publish"
            );
        }
    }

    #[test]
    fn the_field_survives_the_json_the_python_side_reads() {
        let m = aws_release().through_secure_module("host-software");
        let v = serde_json::to_value(&m).expect("serialises");
        assert_eq!(v["secure_module"], "host-software");
        // And a record written before the field existed still parses, as "no
        // claim" rather than as an error.
        let mut old = serde_json::to_value(aws_release()).expect("serialises");
        old.as_object_mut()
            .expect("an object")
            .remove("secure_module");
        let back: RunMetadata = serde_json::from_value(old).expect("an old record parses");
        assert_eq!(back.secure_module, None);
    }

    #[test]
    fn a_clean_aws_release_run_is_publishable() {
        assert!(aws_release().is_publishable());
    }

    #[test]
    fn refuses_a_local_run() {
        let mut m = aws_release();
        m.environment = Environment::Local;
        assert_eq!(
            m.publication_refusals(),
            vec![RefusalReason::NotAws(Environment::Local)]
        );
    }

    #[test]
    fn refuses_a_dirty_tree() {
        let mut m = aws_release();
        m.git_dirty = true;
        assert!(matches!(
            m.publication_refusals().as_slice(),
            [RefusalReason::DirtyTree(_)]
        ));
    }

    #[test]
    fn refuses_a_debug_build() {
        // The 8 MiB/s vs 1524 MiB/s AES-GCM gap is why this rule exists.
        let mut m = aws_release();
        m.profile = Profile::Debug;
        assert_eq!(m.publication_refusals(), vec![RefusalReason::DebugBuild]);
    }

    #[test]
    fn refuses_too_few_iterations() {
        let mut m = aws_release();
        m.iterations = 3;
        assert_eq!(
            m.publication_refusals(),
            vec![RefusalReason::TooFewIterations {
                got: 3,
                required: MIN_ITERATIONS
            }]
        );
    }

    #[test]
    fn reports_every_reason_at_once() {
        // So a bad run is not fixed one complaint at a time.
        let mut m = aws_release();
        m.environment = Environment::Local;
        m.git_dirty = true;
        m.profile = Profile::Debug;
        m.iterations = 1;
        m.secure_module = Some("host-software".into());
        assert_eq!(m.publication_refusals().len(), 5);
    }

    #[test]
    fn round_trips_through_json() {
        // The Python side reads exactly these bytes; a rename that breaks it
        // must break here first.
        let m = aws_release();
        let json = serde_json::to_string_pretty(&m).expect("serialize");
        assert!(json.contains("\"environment\": \"aws\""));
        assert!(json.contains("\"profile\": \"release\""));
        let back: RunMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, back);
    }
}
