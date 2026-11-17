//! Emit one provenance-only record, to prove the producer and `mkfigs.py` agree.
//!
//! The two halves of the results pipeline are written in different languages
//! and tested separately: the Rust side checks that it writes the keys it means
//! to, the Python side checks that it refuses the records it means to. Nothing
//! had ever handed a Rust-written file to `mkfigs.py`. This closes that, and it
//! is the first thing to run on a fresh AWS instance:
//!
//! ```text
//! cargo run --release --example emit_record -- results/ --require-aws
//! python3 tools/mkfigs.py --check results/
//! ```
//!
//! ⛔ **`--require-aws` makes it a hard gate**: the process exits non-zero if
//! the record would be unpublishable. The campaign script passes it, so a
//! failed detection stops the run instead of printing a warning into a log
//! nobody reads under time pressure. Omit it locally, where a refusal is the
//! expected and correct outcome.
//!
//! ⭐ **On AWS the expected outcome is silence** — a clean release run on an
//! instance is publishable, so `--check` passes. Anywhere else the expected
//! outcome is a refusal naming `not_aws`, and *that* is the result worth
//! seeing: it proves the environment is being observed rather than assumed.
//!
//! The record carries no measurement. It exists to exercise provenance, and it
//! says so in its own payload so that a stray copy cannot be mistaken for data.

use std::path::PathBuf;

use pqcl_bench::provenance::{RunSpec, detect_environment};
use pqcl_bench::{RunMetadata, RunRecord, write_run};

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let require_aws = args.iter().any(|a| a == "--require-aws");

    // Skip flags when picking the output root, so `--require-aws` is not
    // silently used as a directory name.
    let root: PathBuf = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "results".to_owned())
        .into();

    // `iterations` is what a run actually did. Ten is the minimum the guard
    // accepts, passed here so the only refusal left on AWS is a genuine one.
    let metadata = RunMetadata::collect(
        RunSpec {
            liboqs_version: "pipeline-rehearsal".to_owned(),
            ..RunSpec::default()
        },
        10,
    )?;

    let record = RunRecord {
        experiment: "pipeline-rehearsal".to_owned(),
        measurements: serde_json::json!({
            "note": "No measurement. This record exists to check that the \
                     producer and mkfigs.py agree on the schema and the rules.",
        }),
        metadata,
    };

    let path = write_run(&root, &record)?;
    println!("wrote {}", path.display());

    println!("environment detected as {:?}", detect_environment());
    println!(
        "git {} dirty={}",
        record.metadata.git_sha, record.metadata.git_dirty
    );
    println!("kernel {}", record.metadata.kernel);
    println!("{}", record.metadata.rustc_version);

    let refusals = record.metadata.publication_refusals();
    if refusals.is_empty() {
        println!("publishable: yes");
    } else {
        println!("publishable: no");
        for r in &refusals {
            println!("  - {r}");
        }
    }

    // ⛔ Off AWS a refusal is the correct outcome, and exiting non-zero for it
    // would make a healthy local run look broken. `--require-aws` is what the
    // campaign script passes.
    if refusals.is_empty() || !require_aws {
        return Ok(());
    }

    // ⭐ A hard gate, not a printed warning a human is trusted to read.
    //
    // `detect_environment` has never returned `Aws` — it reads SMBIOS strings
    // that do not exist off EC2 — so the single most likely way this campaign
    // silently wastes its money is the detector being wrong and nobody
    // noticing until the results are refused at the end. A check whose
    // enforcement is "somebody looks at stdout" is the same class of control
    // that let `RunMetadata` go unconstructed.
    eprintln!(
        "\nREFUSING to proceed: this run would be unpublishable, and \
         --require-aws says the campaign depends on it.\n\
         Every number measured from here would be rejected by mkfigs.py.\n\
         Fix the cause above before running any experiment."
    );
    std::process::exit(1);
}
