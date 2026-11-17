//! Writing a run to `results/`, in the one layout `tools/mkfigs.py` reads.
//!
//! The path in the build plan is
//! `results/<exp>/<utc>-<git-sha>-<instance>.json`, and until this module
//! existed nothing in the workspace could produce it. The consumer side —
//! `mkfigs.py` and [`crate::RunMetadata::publication_refusals`] — was complete
//! and correct, which is a trap worth naming: a guard with no producer reads as
//! a working pipeline right up to the moment someone needs to record a number
//! and hand-writes the JSON instead.
//!
//! ⛔ **There is no "publish anyway" flag, and adding one defeats the crate.**
//! [`write_run`] writes any record, publishable or not — a local run is worth
//! keeping, it just may not be printed. The refusal happens at
//! `mkfigs.py`, on the way *into* the paper. Recording and publishing are
//! separate decisions and the separation is deliberate.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Environment, RunMetadata};

/// One experiment's output: provenance, plus whatever it measured.
///
/// `measurements` is deliberately untyped. Ten experiments report ten different
/// shapes, and forcing them into one enum would mean editing this crate to add
/// a data point — which is how a harness acquires a reason to be bypassed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRecord {
    /// Experiment identifier, e.g. `exp2-conjunctive-latency`. Becomes the
    /// subdirectory.
    pub experiment: String,
    /// Where, when, from what commit, under which compiler.
    #[serde(flatten)]
    pub metadata: RunMetadata,
    /// The measurements themselves.
    pub measurements: serde_json::Value,
}

/// Why a record could not be written.
#[derive(Debug)]
pub enum WriteError {
    /// The experiment name would not make a safe single path component.
    BadExperimentName(String),
    /// Serialisation failed.
    Encode(serde_json::Error),
    /// The filesystem refused.
    Io(std::io::Error),
}

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadExperimentName(n) => write!(
                f,
                "experiment name {n:?} is not a safe path component: use \
                 lowercase letters, digits and hyphens"
            ),
            Self::Encode(e) => write!(f, "encoding the record: {e}"),
            Self::Io(e) => write!(f, "writing the record: {e}"),
        }
    }
}

impl core::error::Error for WriteError {}

impl From<serde_json::Error> for WriteError {
    fn from(e: serde_json::Error) -> Self {
        Self::Encode(e)
    }
}

impl From<std::io::Error> for WriteError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Experiment names become directory names, so they are constrained rather than
/// sanitised. Silently rewriting `../../etc` into something safe would hide the
/// bug; refusing it does not.
fn check_name(name: &str) -> Result<(), WriteError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(WriteError::BadExperimentName(name.to_owned()))
    }
}

/// Timestamps go in filenames, so `:` has to go — it is illegal on Windows and
/// awkward everywhere.
fn filename_stamp(started_utc: &str) -> String {
    started_utc.replace(':', "")
}

/// Write one run under `root`, returning the path written.
///
/// The filename carries the UTC start, the commit and the instance type, so a
/// directory listing alone answers "when, from what, on what" without opening
/// anything. Off AWS the instance slot reads `local`; on AWS with no type
/// detected it reads `aws-unknown`. Both come from the *observed* environment,
/// so the word is a reliable signal rather than a courtesy — see the comment in
/// the body for the run where it was not.
///
/// # Errors
///
/// [`WriteError`] if the name is unsafe, encoding fails, or the write fails.
pub fn write_run(root: &Path, record: &RunRecord) -> Result<PathBuf, WriteError> {
    check_name(&record.experiment)?;

    let dir = root.join(&record.experiment);
    std::fs::create_dir_all(&dir)?;

    // ⛔ The fallback follows the **observed environment**, never the mere
    // absence of an instance type. Writing "local" into the name of a file
    // produced on AWS is a false claim in the one place a reader looks first —
    // and this crate's own docs assert that word is trustworthy *because* the
    // environment is observed. It was not, until this: the first real AWS run
    // emitted `…-local.json`.
    let instance =
        record
            .metadata
            .instance_type
            .as_deref()
            .unwrap_or(match record.metadata.environment {
                Environment::Aws => "aws-unknown",
                Environment::Local => "local",
            });
    let short_sha: String = record.metadata.git_sha.chars().take(12).collect();
    let name = format!(
        "{}-{}-{}.json",
        filename_stamp(&record.metadata.started_utc),
        short_sha,
        instance
    );

    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string_pretty(record)?)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::Profile;

    fn record(experiment: &str) -> RunRecord {
        RunRecord {
            experiment: experiment.to_owned(),
            metadata: RunMetadata {
                git_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                git_dirty: false,
                environment: Environment::Aws,
                profile: Profile::Release,
                instance_type: Some("m7i.4xlarge".into()),
                region: Some("ap-southeast-1".into()),
                kernel: "6.8.0-1021-aws".into(),
                rustc_version: "rustc 1.97.1".into(),
                liboqs_version: "0.13.0".into(),
                cpu_features: "aes+avx2".into(),
                cpu_model: None,
                dataset_checksums: BTreeMap::new(),
                rng_seeds: vec![42],
                iterations: 10,
                started_utc: "2026-09-15T08:30:00Z".into(),
                secure_module: None,
            },
            measurements: serde_json::json!({ "median_us": 1234 }),
        }
    }

    #[test]
    fn writes_the_layout_mkfigs_expects() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_run(tmp.path(), &record("exp2-conjunctive-latency")).expect("write");

        assert_eq!(
            path.parent().and_then(|p| p.file_name()),
            Some(std::ffi::OsStr::new("exp2-conjunctive-latency"))
        );
        let name = path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        assert_eq!(name, "2026-09-15T083000Z-0123456789ab-m7i.4xlarge.json");
    }

    #[test]
    fn the_written_json_is_what_the_python_side_reads() {
        // mkfigs.py reads these keys at the top level, so the `flatten` on
        // metadata is load-bearing. A refactor that nests it must fail here
        // rather than at the end of an AWS campaign.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = write_run(tmp.path(), &record("exp1-ingestion")).expect("write");
        let text = std::fs::read_to_string(&path).expect("read back");
        let v: serde_json::Value = serde_json::from_str(&text).expect("parse");

        for key in [
            "environment",
            "git_dirty",
            "profile",
            "iterations",
            "git_sha",
        ] {
            assert!(
                v.get(key).is_some(),
                "missing top-level key {key:?} in {text}"
            );
        }
        assert_eq!(v["environment"], "aws");
        assert_eq!(v["profile"], "release");
    }

    #[test]
    fn a_local_record_is_written_but_names_itself_local() {
        // Recording and publishing are separate: the run is kept, and the
        // filename says what it is.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut r = record("exp1-ingestion");
        r.metadata.environment = Environment::Local;
        r.metadata.instance_type = None;

        let path = write_run(tmp.path(), &r).expect("write");
        assert!(
            path.to_string_lossy().ends_with("-local.json"),
            "expected a local-tagged filename, got {}",
            path.display()
        );
        assert!(!r.metadata.is_publishable());
    }

    #[test]
    fn an_aws_record_never_names_itself_local() {
        // ⭐ Regression. The first real AWS run wrote `…-local.json` because
        // `instance_type` was None and the fallback keyed off that rather than
        // off the observed environment — a false claim in the one field a
        // reader checks first. The fallback now follows the environment.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut r = record("exp1-ingestion");
        r.metadata.environment = Environment::Aws;
        r.metadata.instance_type = None;

        let path = write_run(tmp.path(), &r).expect("write");
        let name = path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        assert!(
            !name.contains("local"),
            "an AWS record named itself local: {name}"
        );
        assert!(
            name.ends_with("-aws-unknown.json"),
            "unexpected name: {name}"
        );
    }

    #[test]
    fn refuses_an_experiment_name_that_would_escape_the_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for bad in ["../escape", "exp2/sub", "", "Exp2", "exp 2"] {
            assert!(
                matches!(
                    write_run(tmp.path(), &record(bad)),
                    Err(WriteError::BadExperimentName(_))
                ),
                "accepted {bad:?} as an experiment name"
            );
        }
    }

    #[test]
    fn two_runs_of_one_experiment_do_not_overwrite_each_other() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = write_run(tmp.path(), &record("exp6-anchoring")).expect("write");

        let mut second = record("exp6-anchoring");
        second.metadata.started_utc = "2026-09-15T09:00:00Z".into();
        let second = write_run(tmp.path(), &second).expect("write");

        assert_ne!(first, second);
        assert!(first.exists() && second.exists());
    }

    #[test]
    fn round_trips() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let original = record("exp9-custody");
        let path = write_run(tmp.path(), &original).expect("write");
        let back: RunRecord =
            serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("parse");
        assert_eq!(original, back);
    }
}
