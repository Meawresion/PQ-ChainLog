//! Run a real forensic tool against a real artefact, and record what ran.
//!
//! The build plan, on the custody plane:
//!
//! > No public corpus of custody records exists; real ones are confidential by
//! > construction. **Do not invent them.** Instead derive custody records from
//! > forensic operations we actually perform: run The Sleuth Kit over the real
//! > disk images, Volatility 3 over the real memory dumps, and Zeek/tshark over
//! > the real PCAPs, and emit a Custody Record per real tool invocation. Then
//! > `params_c = H(tool ‖ version ‖ params ‖ justification)` commits to a real
//! > command that really ran.
//!
//! That last sentence is why this module shells out to a container rather than
//! parsing a stored transcript. `params_c` goes inside a signed custody record,
//! so the tool name, its **version**, and its exact arguments are claims the
//! system makes under signature. A version read from anywhere other than the
//! binary that ran would make the commitment a statement about nothing.
//!
//! ⛔ **There is no canned-transcript mode and there must not be one.** Ground
//! rule #1 forbids standing in for work that did not happen, and a replay path
//! here would be exactly that — it would let the whole pipeline pass its
//! acceptance test without a forensic tool ever running.

use std::path::{Path, PathBuf};
use std::process::Command;

use pqcl_capsule::Params;
use pqcl_primitives::xof::{Digest32, Domain, hash_domain};

/// What one real tool invocation produced.
#[derive(Debug, Clone)]
pub struct ToolRun {
    /// Tool name as invoked, e.g. `fls`, `vol`, `tshark`.
    pub tool: String,
    /// The version line the container reported for that tool.
    pub version: String,
    /// Arguments, exactly as passed.
    pub args: Vec<String>,
    /// Digest of the tool's stdout. The output itself can be large — an `fls`
    /// listing of a full image is megabytes — and the custody record commits to
    /// what the run produced, not to the bytes themselves.
    pub stdout_digest: Digest32,
    /// Bytes of stdout, kept so a caller can index or inspect the output.
    pub stdout: Vec<u8>,
    /// Exit status.
    pub success: bool,
}

/// Something went wrong invoking the tooling.
#[derive(Debug)]
pub enum ForensicsError {
    /// `forensics/run.sh` could not be executed at all.
    Spawn(String),
    /// The tool ran and failed.
    ToolFailed {
        /// Tool name.
        tool: String,
        /// Its stderr, trimmed.
        stderr: String,
    },
    /// The container reported no version for a tool we asked about, which means
    /// the image is not the one this code expects.
    UnknownTool(String),
}

impl core::fmt::Display for ForensicsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Spawn(m) => write!(f, "could not run forensics/run.sh: {m}"),
            Self::ToolFailed { tool, stderr } => {
                write!(f, "{tool} failed: {stderr}")
            }
            Self::UnknownTool(t) => write!(
                f,
                "the forensics image reports no version for {t}; it is not the expected image"
            ),
        }
    }
}

impl core::error::Error for ForensicsError {}

/// A handle on the pinned forensic container.
#[derive(Debug, Clone)]
pub struct Forensics {
    runner: PathBuf,
    artefact_dir: PathBuf,
    versions: Vec<(String, String)>,
}

impl Forensics {
    /// Bind to the container and read its tool versions once.
    ///
    /// Reading versions up front rather than per call is deliberate: every
    /// custody record in a run then commits to the *same* observed version, and
    /// a container swapped mid-run would be a changed handle rather than a
    /// silent drift between records.
    ///
    /// # Errors
    ///
    /// [`ForensicsError::Spawn`] if the runner cannot be executed.
    pub fn new(runner: &Path, artefact_dir: &Path) -> Result<Self, ForensicsError> {
        let out = Command::new(runner)
            .arg("--versions")
            .output()
            .map_err(|e| ForensicsError::Spawn(e.to_string()))?;

        if !out.status.success() {
            return Err(ForensicsError::Spawn(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ));
        }

        let versions = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect();

        Ok(Self {
            runner: runner.to_path_buf(),
            artefact_dir: artefact_dir.to_path_buf(),
            versions,
        })
    }

    /// The version string the container reported for a package.
    #[must_use]
    pub fn version_of(&self, package: &str) -> Option<&str> {
        self.versions
            .iter()
            .find(|(k, _)| k == package)
            .map(|(_, v)| v.as_str())
    }

    /// Which package provides a tool. Used to attach an observed version to a
    /// run rather than inventing one.
    ///
    /// Not `const`: matching on `&str` in a const function is unstable.
    fn package_for(tool: &str) -> Option<&'static str> {
        match tool {
            "fls" | "icat" | "mmls" | "fsstat" | "istat" => Some("sleuthkit"),
            "ewfinfo" | "ewfverify" => Some("ewf-tools"),
            "tshark" => Some("tshark"),
            "vol" => Some("volatility3"),
            _ => None,
        }
    }

    /// Run one tool, and return what it produced.
    ///
    /// # Errors
    ///
    /// [`ForensicsError::UnknownTool`] if the tool is not one the image
    /// provides, [`ForensicsError::Spawn`] if the runner cannot start, or
    /// [`ForensicsError::ToolFailed`] if the tool exits non-zero.
    pub fn run(&self, tool: &str, args: &[&str]) -> Result<ToolRun, ForensicsError> {
        let package =
            Self::package_for(tool).ok_or_else(|| ForensicsError::UnknownTool(tool.to_owned()))?;
        let version = self
            .version_of(package)
            .ok_or_else(|| ForensicsError::UnknownTool(tool.to_owned()))?
            .to_owned();

        let out = Command::new(&self.runner)
            .arg(&self.artefact_dir)
            .arg(tool)
            .args(args)
            .output()
            .map_err(|e| ForensicsError::Spawn(e.to_string()))?;

        if !out.status.success() {
            return Err(ForensicsError::ToolFailed {
                tool: tool.to_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }

        Ok(ToolRun {
            tool: tool.to_owned(),
            version,
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            stdout_digest: hash_domain(Domain::EvidenceDigest, &[&out.stdout]),
            stdout: out.stdout,
            success: true,
        })
    }
}

impl ToolRun {
    /// What this run commits to in a custody record: `⟪tool, ver, args, just⟫`,
    /// for the signer to blind with a fresh `r_p` (M13 A2).
    ///
    /// ⚠️ **It no longer returns the commitment.** It used to, and the caller
    /// passed the blind — in the one real path that existed, a **constant**
    /// `digest256(b"r_p")`, which makes `params_c` a deterministic function of
    /// the tool run and so openable by anyone who can guess a command line.
    /// Handing back the fields and letting [`crate::Agent`] draw `r_p` is what
    /// makes the commitment hiding in fact and not only in the equation.
    ///
    /// ⚠️ Fields stay separate, so `ParamsOpening::commit` frames each one.
    /// Concatenating them would make `("fls", "-r")` and `("fls-", "r")`
    /// collide, and the design record records that exact defect
    /// being found in draft6's own commitments.
    #[must_use]
    pub fn params(&self, justification: &[u8]) -> Params {
        Params {
            tool: self.tool.clone().into_bytes(),
            ver: self.version.clone().into_bytes(),
            args: self.args.join("\u{1f}").into_bytes(),
            just: justification.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcl_capsule::ParamsOpening;

    #[test]
    fn tools_map_to_the_packages_that_provide_them() {
        assert_eq!(Forensics::package_for("fls"), Some("sleuthkit"));
        assert_eq!(Forensics::package_for("icat"), Some("sleuthkit"));
        assert_eq!(Forensics::package_for("vol"), Some("volatility3"));
        assert_eq!(Forensics::package_for("tshark"), Some("tshark"));
        assert_eq!(Forensics::package_for("ewfinfo"), Some("ewf-tools"));
        assert_eq!(Forensics::package_for("rm"), None);
    }

    /// `params_c` for a run, with an explicit blind, so the framing tests below
    /// read as they did before `params_commit` became `params` (M13 A2).
    fn commit(run: &ToolRun, just: &[u8], r_p: &Digest32) -> Digest32 {
        ParamsOpening {
            params: run.params(just),
            r_p: *r_p,
        }
        .commit()
    }

    fn run_of(tool: &str, version: &str, args: &[&str]) -> ToolRun {
        ToolRun {
            tool: tool.to_owned(),
            version: version.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            stdout_digest: hash_domain(Domain::EvidenceDigest, &[b"out"]),
            stdout: b"out".to_vec(),
            success: true,
        }
    }

    /// The version is inside the commitment, so the same command under a
    /// different tool build must commit differently. Otherwise a custody record
    /// could not distinguish two runs whose outputs legitimately differ.
    #[test]
    fn the_tool_version_changes_the_commitment() {
        let b = Digest32::default();
        let a = run_of("fls", "4.11.1", &["-r", "img.E01"]);
        let c = run_of("fls", "4.12.0", &["-r", "img.E01"]);
        assert_ne!(commit(&a, b"triage", &b), commit(&c, b"triage", &b));
    }

    #[test]
    fn the_arguments_change_the_commitment() {
        let b = Digest32::default();
        let a = run_of("fls", "4.11.1", &["-r", "img.E01"]);
        let c = run_of("fls", "4.11.1", &["-p", "img.E01"]);
        assert_ne!(commit(&a, b"triage", &b), commit(&c, b"triage", &b));
    }

    #[test]
    fn the_justification_changes_the_commitment() {
        let b = Digest32::default();
        let a = run_of("fls", "4.11.1", &["-r"]);
        assert_ne!(commit(&a, b"triage", &b), commit(&a, b"export", &b));
    }

    /// Framing, not concatenation. Without it these two runs collide.
    #[test]
    fn argument_boundaries_cannot_be_shifted() {
        let b = Digest32::default();
        let a = run_of("fls", "1", &["ab", "c"]);
        let c = run_of("fls", "1", &["a", "bc"]);
        assert_ne!(
            commit(&a, b"j", &b),
            commit(&c, b"j", &b),
            "argument boundaries are not being framed"
        );
    }

    /// The blinding factor is what stops an adversary confirming a guessed
    /// command by recomputing the commitment.
    #[test]
    fn the_blinding_factor_changes_the_commitment() {
        let a = run_of("fls", "1", &["-r"]);
        let b1 = hash_domain(Domain::ParamsCommit, &[b"r1"]);
        let b2 = hash_domain(Domain::ParamsCommit, &[b"r2"]);
        assert_ne!(commit(&a, b"j", &b1), commit(&a, b"j", &b2));
    }
}
