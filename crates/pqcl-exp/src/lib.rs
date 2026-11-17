//! The paper's experiments.
//!
//! One binary per experiment under `src/bin/`. Each one does the same three
//! things and nothing else:
//!
//! 1. builds a workload from the shared [`corpus`] loader,
//! 2. measures, repeating at least [`pqcl_bench::MIN_ITERATIONS`] times and
//!    summarising as a median with an IQR ([`stats`]),
//! 3. writes a provenance-stamped record through [`pqcl_bench::write_run`].
//!
//! ⛔ **No experiment prints a number for a human to copy.** The path from a
//! run to a printed figure is `results/*.json → tools/mkfigs.py →
//! paper/generated/*.tex`, and it is the only one. An experiment that also
//! printed a nicely formatted table would create a second path, and the second
//! path is the one that gets used at 2 a.m.
//!
//! # Why a separate crate from `pqcl-bench`
//!
//! `pqcl-bench` decides whether a number may be published. It should not depend
//! on the things being measured, or the judge and the defendant share a
//! dependency graph. This crate depends on both.

pub mod appender;
pub mod baseline_ingest;
#[cfg(feature = "chain")]
pub mod bdems;
pub mod case;
pub mod cast;
#[cfg(feature = "chain")]
pub mod chain;
pub mod corpus;
pub mod custody_stream;
#[cfg(feature = "chain")]
pub mod evm;
pub mod stats;

/// The collection-size axis `N` shared by Exp. 1's Zuo'22 passes (where it is
/// the bitmap width `y`) and Exp. 7's range sweep, so both range tables read
/// one median. `PQCL_COLLECTION_N` overrides
/// the local default; the campaign adds 65 536.
#[must_use]
pub fn collection_axis() -> Vec<usize> {
    let mut v: Vec<usize> = std::env::var("PQCL_COLLECTION_N").map_or_else(
        |_| vec![256, 1_024, 4_096, 16_384],
        |s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
    );
    v.sort_unstable();
    v
}

/// The operating collection size both range tables report at: **4 096**,
/// declared in the design record before any number existed.
///
/// ⛔ **Not the axis's median.** It used to be `axis[len / 2]`, which was 4 096
/// for every axis campaign 03 ran; §1q.2's denser 13-point exp1 axis would have
/// moved it to 8 192, silently re-choosing the table's operating point after
/// the densification. The point is fixed; the axis only has to contain it.
pub const OPERATING_COLLECTION: usize = 4_096;

/// [`OPERATING_COLLECTION`], after checking the axis actually measures it.
///
/// # Panics
///
/// If the axis does not contain the operating point: a run whose table cells
/// would have to come from a point it never measured must not start.
#[must_use]
pub fn collection_median() -> usize {
    let axis = collection_axis();
    assert!(
        axis.contains(&OPERATING_COLLECTION),
        "PQCL_COLLECTION_N = {axis:?} omits the declared operating point {OPERATING_COLLECTION}"
    );
    OPERATING_COLLECTION
}

/// Emit a record, or explain why it cannot be.
///
/// Wraps the `collect` → `write_run` pair every experiment repeats, so the
/// provenance step cannot be forgotten in one binary and present in the others.
///
/// # Errors
///
/// Propagates provenance collection and write failures. Both are fatal to an
/// experiment: a measurement nobody can trace is not a measurement.
pub fn emit(
    experiment: &str,
    spec: pqcl_bench::RunSpec,
    iterations: u32,
    measurements: serde_json::Value,
) -> Result<std::path::PathBuf, Box<dyn core::error::Error>> {
    write(experiment, spec, iterations, measurements, None)
}

/// [`emit`], for a run that built custody records — and so must say **which
/// Secure Module built them** (M13 A18).
///
/// ⭐ `backend` has no default and no `Option`. A harness that builds a case
/// writes through this or does not compile its record; a source test
/// (`tests/custody_writers.rs`) makes every harness that builds one use it.
/// That is what lets a record without `secure_module` mean "built nothing
/// through a module" rather than "forgot to say".
///
/// # Errors
///
/// As [`emit`].
pub fn emit_custody(
    experiment: &str,
    spec: pqcl_bench::RunSpec,
    iterations: u32,
    measurements: serde_json::Value,
    backend: pqcl_sm::Backend,
) -> Result<std::path::PathBuf, Box<dyn core::error::Error>> {
    let mut measurements = measurements;
    if backend == pqcl_sm::Backend::NitroEnclave {
        // ⭐ A18: "record the enclave's vCPU and memory split in every result".
        // Read from the hypervisor's own account of the running enclave, not
        // from a configured value, so the record cannot claim a split the run
        // did not have; and a run that cannot say refuses to write at all.
        let enclave = enclave_description()?;
        match measurements.as_object_mut() {
            Some(m) => {
                m.insert("enclave".to_owned(), enclave);
            }
            None => {
                measurements = serde_json::json!({ "result": measurements, "enclave": enclave });
            }
        }
    }
    write(
        experiment,
        spec,
        iterations,
        measurements,
        Some(backend.label()),
    )
}

/// `nitro-cli describe-enclaves`: each running enclave's CID, vCPU count and
/// IDs, memory and state, as the Nitro CLI reports them.
///
/// # Errors
///
/// The CLI is missing, fails, or reports no running enclave — any of which
/// means the record could not say what produced it.
fn enclave_description() -> Result<serde_json::Value, Box<dyn core::error::Error>> {
    let out = std::process::Command::new("nitro-cli")
        .arg("describe-enclaves")
        .output()
        .map_err(|e| format!("nitro-cli describe-enclaves could not run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "nitro-cli describe-enclaves failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    if v.as_array().is_none_or(Vec::is_empty) {
        return Err("records were built through the enclave, but no enclave is running".into());
    }
    Ok(v)
}

/// The one writer both entry points share.
fn write(
    experiment: &str,
    spec: pqcl_bench::RunSpec,
    iterations: u32,
    measurements: serde_json::Value,
    secure_module: Option<&str>,
) -> Result<std::path::PathBuf, Box<dyn core::error::Error>> {
    let mut metadata = pqcl_bench::RunMetadata::collect(spec, iterations)?;
    if let Some(label) = secure_module {
        metadata = metadata.through_secure_module(label);
    }

    // Reported, not enforced. Writing a local record is right — it is how an
    // experiment is developed at all — and `mkfigs.py` is what refuses to
    // *print* it. Conflating the two would make the harness unusable off AWS.
    let refusals = metadata.publication_refusals();

    let record = pqcl_bench::RunRecord {
        experiment: experiment.to_owned(),
        measurements,
        metadata,
    };

    let path = pqcl_bench::write_run(std::path::Path::new("results"), &record)?;
    eprintln!("wrote {}", path.display());

    if refusals.is_empty() {
        eprintln!("publishable: yes");
    } else {
        eprintln!("publishable: no");
        for r in &refusals {
            eprintln!("  - {r}");
        }
    }

    Ok(path)
}
