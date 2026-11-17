//! Filling in [`RunMetadata`] from the machine, rather than from an assertion.
//!
//! ⭐ **This module is the difference between a guard and a decoration.**
//! [`crate::RunMetadata::publication_refusals`] refuses a local run, a dirty
//! tree, a debug build and a short run — but a refusal is only worth anything
//! if the fields it reads were *observed*. A record whose `environment` field
//! was typed in by whoever wanted the number published enforces nothing at all.
//!
//! So the four fields the guard reads are **all detected here, and none of them
//! can be supplied by the caller**:
//!
//! | Guard field | Detected from |
//! |---|---|
//! | `environment` | SMBIOS/DMI vendor strings, then the Xen hypervisor UUID |
//! | `git_dirty` | `git status --porcelain` |
//! | `profile` | `cfg!(debug_assertions)` at compile time |
//! | `iterations` | counted by the harness, not declared |
//!
//! [`RunSpec`] carries only what genuinely cannot be observed — the seeds and
//! dataset checksums the caller chose, and the liboqs version string. Those are
//! descriptive; none of them can make an unpublishable run publishable.
//!
//! # The failure direction is deliberate
//!
//! Every detector here fails to [`Environment::Local`], never to
//! [`Environment::Aws`]. An undetected AWS instance therefore produces an
//! *unpublishable* record: loud, immediate, and fixed by one line. The opposite
//! default would silently promote a laptop timing into the paper, which is the
//! exact failure this crate exists to prevent.
//!
//! ⚠️ **The EC2 detector is unverified until the AWS run.** It reads SMBIOS
//! strings that cannot be produced on a developer machine, so
//! [`detect_environment`] returning `Aws` has never been observed — only its
//! `Local` branch has. That is stated rather than hidden, and the fail-safe
//! direction above is what makes an unverified detector tolerable: if it is
//! wrong, the AWS run refuses to publish and says so.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use pqcl_primitives::platform::CpuFeatures;

use crate::{Environment, Profile, RunMetadata};

/// The compiler that built this crate, captured by `build.rs`.
pub const RUSTC_VERSION: &str = env!("PQCL_RUSTC_VERSION");

/// Why provenance could not be collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// `git` could not be run, or reported failure.
    ///
    /// Not recoverable and deliberately not defaulted: without a commit there
    /// is nothing to trace a number back to, and a record with a placeholder
    /// SHA is worse than no record.
    Git(String),
}

impl core::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Git(m) => write!(
                f,
                "could not determine the commit under measurement: {m}. A results \
                 record without a SHA cannot be traced to the code that produced it"
            ),
        }
    }
}

impl core::error::Error for ProvenanceError {}

/// The parts of a record that cannot be observed and must be supplied.
///
/// Note what is *absent*: `environment`, `git_dirty` and `profile`. Those are
/// the fields the publication guard reads, and leaving them out of this struct
/// is what stops a caller asserting its way past the guard.
#[derive(Debug, Clone, Default)]
pub struct RunSpec {
    /// liboqs version string. Declared: the `oqs` crate exposes no accessor for
    /// it, and the FIPS 204 final-versus-`ipd` question this field records is
    /// settled by the ACVP vectors rather than by the string.
    pub liboqs_version: String,
    /// SHA-256 of every dataset consumed, by name.
    pub dataset_checksums: BTreeMap<String, String>,
    /// RNG seeds, so the run can be repeated exactly.
    pub rng_seeds: Vec<u64>,
    /// EC2 instance type. Descriptive only — it names the hardware in the
    /// paper's setup table and the guard never reads it.
    pub instance_type: Option<String>,
    /// AWS region. Descriptive only, as above.
    pub region: Option<String>,
}

/// Read a sysfs string, trimmed. `None` if absent or unreadable.
fn sysfs(path: &str) -> Option<String> {
    std::fs::read_to_string(Path::new(path))
        .ok()
        .map(|s| s.trim().to_owned())
}

/// Whether this host is an EC2 instance.
///
/// Two independent signals, both local: no network call, no IMDS round trip and
/// no credentials, so this works inside a stripped enclave and cannot be
/// defeated by a VPC without an IMDS route.
///
/// * SMBIOS vendor strings. Nitro instances report an Amazon vendor in
///   `sys_vendor`, and older instance families in `bios_vendor`.
/// * The Xen hypervisor UUID, which on pre-Nitro instances begins `ec2`.
///
/// ✅ Verified in the `Aws` direction on campaigns 02 and 03 (m7i.4xlarge).
#[must_use]
pub fn detect_environment() -> Environment {
    const DMI: &str = "/sys/devices/virtual/dmi/id";
    classify(
        &|field| sysfs(&format!("{DMI}/{field}")),
        sysfs("/sys/hypervisor/uuid").as_deref(),
    )
}

/// The decision itself, over injected readings, so both directions are
/// testable on any machine. `dmi(field)` reads an SMBIOS field.
fn classify(dmi: &dyn Fn(&str) -> Option<String>, hypervisor_uuid: Option<&str>) -> Environment {
    for field in ["sys_vendor", "bios_vendor", "board_vendor"] {
        if dmi(field).is_some_and(|v| v.to_ascii_lowercase().contains("amazon")) {
            return Environment::Aws;
        }
    }
    if hypervisor_uuid.is_some_and(|u| u.to_ascii_lowercase().starts_with("ec2")) {
        return Environment::Aws;
    }
    Environment::Local
}

/// EC2 instance type, read from SMBIOS.
///
/// ⭐ **Observed, not declared.** `product_name` carries the instance type
/// verbatim on Nitro — confirmed on the campaign instance, which reports
/// `m7i.2xlarge`. That makes the hardware in the paper's setup table a measured
/// fact rather than something an operator typed, which matters because the
/// boundary-overhead and proving numbers are only interpretable against the
/// machine that produced them.
///
/// Preferred over IMDS deliberately: no network round trip, no token dance, no
/// dependency on an IMDS route existing in the VPC, and it works inside a
/// stripped enclave. IMDS returned nothing on the very instance where DMI
/// answered immediately.
///
/// Returns `None` off EC2, where `product_name` describes some other
/// hypervisor and would be a misleading thing to record as an instance type.
#[must_use]
pub fn detect_instance_type() -> Option<String> {
    if detect_environment() != Environment::Aws {
        return None;
    }
    sysfs("/sys/devices/virtual/dmi/id/product_name").filter(|s| !s.is_empty())
}

/// Kernel release, as `uname -r` reports it.
/// The CPU model: the first `model name` line of `/proc/cpuinfo`.
#[must_use]
pub fn detect_cpu_model() -> Option<String> {
    let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    parse_cpu_model(&text)
}

fn parse_cpu_model(cpuinfo: &str) -> Option<String> {
    cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn detect_kernel() -> String {
    sysfs("/proc/sys/kernel/osrelease")
        .or_else(|| {
            Command::new("uname")
                .arg("-r")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn git(args: &[&str]) -> Result<String, ProvenanceError> {
    let out = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| ProvenanceError::Git(format!("running `git {}`: {e}", args.join(" "))))?;

    if !out.status.success() {
        return Err(ProvenanceError::Git(format!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    String::from_utf8(out.stdout)
        .map(|s| s.trim_end().to_owned())
        .map_err(|e| {
            ProvenanceError::Git(format!("`git {}` output is not UTF-8: {e}", args.join(" ")))
        })
}

/// The commit under measurement, and whether the tree matches it.
///
/// ⚠️ **Untracked files count as dirty.** An untracked `.rs` file can be
/// compiled into the binary being measured, so the SHA would not describe what
/// ran. Untracked *build artefacts inside submodules* are excluded via
/// `ignore = untracked` in `.gitmodules` — running `forge test` drops a
/// `foundry.lock` into a vendored dependency, and letting that invalidate a
/// whole AWS campaign would be absurd. See the comment at the top of
/// `.gitmodules` for why the exemption stops there.
///
/// # Errors
///
/// [`ProvenanceError::Git`] if `git` cannot be run or reports failure.
pub fn detect_commit() -> Result<(String, bool), ProvenanceError> {
    let sha = git(&["rev-parse", "HEAD"])?;
    let status = git(&["status", "--porcelain"])?;
    Ok((sha, !status.trim().is_empty()))
}

/// Civil date from a Unix day number. Howard Hinnant's `civil_from_days`.
///
/// Written out rather than pulled in as a dependency: it is twenty lines, it is
/// exercised by the tests below against known dates, and a results record's
/// timestamp is not worth a transitive dependency tree.
///
/// Kept entirely in `i64`. The original is written over unsigned intermediates,
/// but every one of those conversions is a lint the workspace denies, and
/// silencing four of them around date arithmetic — where an off-by-one is
/// invisible — is a worse trade than the two extra bits of range. `doe` is in
/// `[0, 146096]` and `yoe` in `[0, 399]` by construction, so nothing here can
/// go negative anyway.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format Unix seconds as an RFC 3339 UTC timestamp.
#[must_use]
pub fn rfc3339_utc(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let secs = unix_seconds.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Now, as an RFC 3339 UTC timestamp.
#[must_use]
pub fn now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    rfc3339_utc(secs)
}

impl RunMetadata {
    /// Observe the machine and assemble a record.
    ///
    /// `iterations` is passed separately from [`RunSpec`] because the harness
    /// counts it: it is what the run *did*, not what it intended, and the guard
    /// reads it.
    ///
    /// # Errors
    ///
    /// [`ProvenanceError::Git`] if the commit cannot be determined.
    pub fn collect(spec: RunSpec, iterations: u32) -> Result<Self, ProvenanceError> {
        let (git_sha, git_dirty) = detect_commit()?;

        Ok(Self {
            git_sha,
            git_dirty,
            environment: detect_environment(),
            profile: Profile::current(),
            // Caller's value wins if given, but the fallback is *observed*
            // rather than empty — so a harness that forgets to set it still
            // records the truth instead of an unlabelled record.
            instance_type: spec.instance_type.or_else(detect_instance_type),
            region: spec.region,
            kernel: detect_kernel(),
            rustc_version: RUSTC_VERSION.to_owned(),
            liboqs_version: spec.liboqs_version,
            cpu_features: CpuFeatures::detect().summary(),
            cpu_model: detect_cpu_model(),
            dataset_checksums: spec.dataset_checksums,
            rng_seeds: spec.rng_seeds,
            iterations,
            started_utc: now_utc(),
            // No claim until a custody writer makes one; see the field.
            secure_module: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_instants() {
        // Cross-checked against `date -u -d @<n> +%Y-%m-%dT%H:%M:%SZ`.
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339_utc(1_757_894_400), "2025-09-15T00:00:00Z");
        // A leap day, which is where a hand-written calendar goes wrong.
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        // End of a leap year.
        assert_eq!(rfc3339_utc(1_735_689_599), "2024-12-31T23:59:59Z");
    }

    #[test]
    fn now_is_not_the_epoch() {
        // Catches a clock read that silently fell back to zero, which would
        // make every record sort as 1970 and collide on filename.
        assert!(now_utc().as_str() > "2026-01-01T00:00:00Z");
    }

    #[test]
    fn the_commit_is_observed_and_the_tree_state_with_it() {
        let (sha, _dirty) = detect_commit().expect("this crate lives in a git repo");
        assert_eq!(sha.len(), 40, "expected a full SHA-1, got {sha:?}");
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_developer_machine_is_not_mistaken_for_aws() {
        // ⚠️ This read the real machine until M12, so it failed on AWS, where
        // its premise is false: a test of *this host* is not a test of the
        // detector. Both directions now run everywhere, on injected readings.
        let none = |_: &str| None;
        let dev = |f: &str| match f {
            "sys_vendor" => Some("Micro-Star International Co., Ltd.".to_owned()),
            "bios_vendor" => Some("American Megatrends International, LLC.".to_owned()),
            _ => None,
        };
        assert_eq!(classify(&none, None), Environment::Local);
        assert_eq!(classify(&dev, None), Environment::Local);
        // A Xen UUID that is not EC2's.
        assert_eq!(classify(&dev, Some("3f2a0c1e-0000")), Environment::Local);
    }

    #[test]
    fn an_ec2_instance_is_recognised_by_either_signal() {
        let nitro = |f: &str| (f == "sys_vendor").then(|| "Amazon EC2".to_owned());
        let old_bios = |f: &str| (f == "bios_vendor").then(|| "Amazon.com".to_owned());
        assert_eq!(classify(&nitro, None), Environment::Aws);
        assert_eq!(classify(&old_bios, None), Environment::Aws);
        assert_eq!(
            classify(&|_| None, Some("ec2e1916-9099-7caf")),
            Environment::Aws
        );
    }

    #[test]
    fn the_cpu_model_is_the_first_model_name_line() {
        let text = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Platinum 8488C\n\nprocessor\t: 1\nmodel name\t: other\n";
        assert_eq!(
            parse_cpu_model(text).as_deref(),
            Some("Intel(R) Xeon(R) Platinum 8488C")
        );
        assert_eq!(parse_cpu_model("processor\t: 0\n"), None);
        assert_eq!(parse_cpu_model("model name\t:   \n"), None);
    }

    #[test]
    fn the_rustc_version_is_captured_at_build_time() {
        assert!(
            RUSTC_VERSION.starts_with("rustc "),
            "build.rs did not capture a compiler version: {RUSTC_VERSION:?}"
        );
    }

    #[test]
    fn a_collected_record_is_refused_locally() {
        // ⭐ The point of the whole module. Collected on a developer machine,
        // the record must be unpublishable *without anyone having said so* —
        // the environment is observed, not declared. On AWS (M12 runs the
        // suite there) the same record must carry the observed `Aws` and no
        // not-AWS refusal: the assertion follows the host, it does not skip.
        let m = RunMetadata::collect(RunSpec::default(), 100).expect("collect");
        let not_aws = m
            .publication_refusals()
            .iter()
            .any(|r| matches!(r, crate::RefusalReason::NotAws(_)));
        if detect_environment() == Environment::Local {
            assert!(
                !m.is_publishable(),
                "a locally-collected record was publishable; the guard is not reading observed fields"
            );
            assert!(
                not_aws,
                "expected a not-AWS refusal, got {:?}",
                m.publication_refusals()
            );
        } else {
            assert!(!not_aws, "an AWS-collected record was refused as not-AWS");
        }
    }

    #[test]
    fn iterations_come_from_the_harness_not_the_spec() {
        // A caller cannot declare its way to ten iterations: the count is a
        // separate argument, supplied by whatever actually looped.
        let m = RunMetadata::collect(RunSpec::default(), 3).expect("collect");
        assert_eq!(m.iterations, 3);
        assert!(
            m.publication_refusals()
                .iter()
                .any(|r| matches!(r, crate::RefusalReason::TooFewIterations { got: 3, .. }))
        );
    }

    #[test]
    fn the_kernel_is_observed() {
        let k = detect_kernel();
        assert_ne!(k, "unknown", "could not read a kernel release");
        assert!(!k.is_empty());
    }
}
