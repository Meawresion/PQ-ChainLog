//! Repository automation for PQ-ChainLog.
//!
//! `cargo xtask ci` is the single entry point for correctness checks and is what
//! the pre-push hook runs. It deliberately checks **correctness only**: every
//! performance number in the paper comes from an AWS run through the results
//! pipeline, so nothing here may ever
//! become the source of a published figure.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("ci") => run(&[
            Check::Fmt,
            Check::NoStubs,
            Check::Clippy,
            Check::Test,
            Check::Pipeline,
            Check::Contracts,
            Check::Demo,
        ]),
        Some("no-stubs") => run(&[Check::NoStubs]),
        Some("fmt") => run(&[Check::Fmt]),
        Some("clippy") => run(&[Check::Clippy]),
        Some("test") => run(&[Check::Test]),
        Some("pipeline") => run(&[Check::Pipeline]),
        Some("contracts") => run(&[Check::Contracts]),
        Some("zk") => run(&[Check::Zk]),
        Some("demo") => run(&[Check::Demo]),
        Some("interop-fixture") => interop_fixture(),
        _ => {
            eprintln!(
                "usage: cargo xtask <ci|no-stubs|fmt|clippy|test|zk|demo|interop-fixture>\n\
                 \n\
                 ci               fmt --check, no-stubs gate, clippy -D warnings, tests, pipeline\n\
                 no-stubs         enforce ground rule #1 (no stubs, mocks, or simulation)\n\
                 pipeline         tools/mkfigs.py --selftest: the publication refusal rules\n\
                 contracts        forge test: the Solidity suite, incl. the binding ACVP gate\n\
                 zk               build the SP1 guest and run the proof-of-warrant tests\n\
                 demo             the M8b demo's scripted walkthrough, D1-D6, on a live chain\n\
                 interop-fixture  sign with our liboqs ML-DSA-65 and emit the Solidity gate input\n"
            );
            ExitCode::FAILURE
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Check {
    Fmt,
    Clippy,
    Test,
    NoStubs,
    Pipeline,
    Contracts,
    Zk,
    Demo,
}

fn run(checks: &[Check]) -> ExitCode {
    let root = workspace_root();
    let mut failed = Vec::new();

    for check in checks {
        let (name, ok) = match check {
            Check::Fmt => ("fmt", cargo(&root, &["fmt", "--all", "--", "--check"])),
            Check::Clippy => (
                "clippy",
                cargo(
                    &root,
                    &[
                        "clippy",
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                        "--locked",
                        "--",
                        "-D",
                        "warnings",
                    ],
                ) && reduced_shapes(&root, "clippy"),
            ),
            Check::Test => (
                "test",
                cargo(
                    &root,
                    &["test", "--workspace", "--all-features", "--locked"],
                ) && reduced_shapes(&root, "test"),
            ),
            Check::NoStubs => ("no-stubs", no_stubs(&root)),
            // ⭐ `mkfigs.py` holds the publication refusal rules and the one
            // AWS-only carve-out, and it carries its own tests. Until this step
            // existed **nothing ran them** — they fired only when a human
            // typed the command.
            //
            // That is the same defect as `RunMetadata`, which was defined,
            // serialised, unit-tested and constructed nowhere: a complete guard
            // that no automation exercises is indistinguishable from a working
            // one right up to the moment it matters. The carve-out's condition
            // 3 says "enforced in the pipeline, not by convention" — a test
            // suite nobody runs is a convention.
            Check::Pipeline => ("pipeline", mkfigs_selftest(&root)),
            // ⭐ The Solidity suite was reachable from **no automation at all**
            // — not `xtask`, not the pre-push hook — so it ran only when
            // somebody typed `forge test`.
            //
            // That is the fourth instance of this pattern after `RunMetadata`,
            // the carve-out self-tests and the `mkfigs.py` selftest, and it is
            // the worst of the four: `MLDSA65Gate.t.sol` is the **binding**
            // ACVP-65 gate from the ETHDILITHIUM standing rule, whose whole
            // point is that no gas number leaves an unvalidated verifier. A
            // binding gate nobody runs is a comment.
            Check::Contracts => ("contracts", forge_test(&root)),
            // The midterm demo (plan M8b, constraint 6): a broken demo must
            // fail CI, not the presentation. Needs Docker, like `test`.
            Check::Demo => ("demo", demo_walk(&root)),
            // `zk/warrant-host` is deliberately outside the workspace: sp1-sdk
            // pulls 608 crates and needs `protoc`, so as a member it would
            // break `cargo build --workspace` on any machine lacking that
            // system package — including crates with no connection to proving.
            //
            // ⚠️ The cost of excluding it is that `--workspace` never reaches
            // it, and an acceptance test nobody runs reports green forever.
            // This step is what pays that cost, so it must stay wired up.
            // Building the host also builds the guest, via its build script.
            Check::Zk => (
                "zk",
                cargo(
                    &root.join("zk").join("warrant-host"),
                    // `--test-threads=1`: each test spins up a full zkVM
                    // executor, and five at once on this box is both slower
                    // wall-clock and a memory risk — proving in this crate has
                    // already OOM-killed the VM once. Serial is the shape these
                    // actually pass in.
                    //
                    // `--release`: a debug-build zkVM executor is unusably
                    // slow, the same trap recorded for the crypto crates.
                    &["test", "--release", "--", "--test-threads=1"],
                ),
            ),
        };
        if ok {
            println!("  ok   {name}");
        } else {
            println!("  FAIL {name}");
            failed.push(name);
        }
    }

    if failed.is_empty() {
        println!("\nall checks passed");
        ExitCode::SUCCESS
    } else {
        eprintln!("\nfailed: {}", failed.join(", "));
        ExitCode::FAILURE
    }
}

fn workspace_root() -> PathBuf {
    // xtask lives at <root>/xtask, so CARGO_MANIFEST_DIR's parent is the root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

/// Regenerate the Rust→Solidity interop fixture.
///
/// Deliberately **not** part of `ci`. The fixture is a committed artefact, not
/// a derived one: liboqs exposes no seeded key generation and its ML-DSA
/// signing is hedged, so a regeneration produces a different-but-equally-valid
/// file. Running this on every CI pass would rewrite a tracked file each time
/// and leave the tree dirty, which the results pipeline refuses (§11) — for
/// good reason, since a dirty tree means the SHA stamped on a measurement does
/// not describe the code that produced it.
///
/// The Python half needs the ETHDILITHIUM reference venv; see
/// `contracts/tools/acvp_to_fixture.py` for the one-time setup.
fn interop_fixture() -> ExitCode {
    let root = workspace_root();

    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let signed = Command::new(cargo_bin)
        .current_dir(&root)
        .args(["run", "-q", "-p", "pqcl-interop"])
        .output();

    let signed = match signed {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            eprintln!(
                "pqcl-interop failed:\n{}",
                String::from_utf8_lossy(&o.stderr)
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("could not run pqcl-interop: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The venv is where `dilithium_py` lives; a bare `python3` will not have it.
    let python = std::env::var("PQCL_PYTHON")
        .unwrap_or_else(|_| format!("{}/.pqcl-venv-ethd/bin/python3", home()));

    let mut child = match Command::new(&python)
        .current_dir(root.join("contracts"))
        .arg("tools/rust_interop_fixture.py")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "could not run {python}: {e}\n\
                 set PQCL_PYTHON to an interpreter with dilithium_py installed"
            );
            return ExitCode::FAILURE;
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        if let Err(e) = stdin.write_all(&signed) {
            eprintln!("could not pipe the signature to the converter: {e}");
            return ExitCode::FAILURE;
        }
    }

    match child.wait() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| ".".into())
}

/// `pqcl-sm` in the feature shapes `--all-features` never reaches.
///
/// ⭐ **Every gate above runs with `--all-features`, and that hides exactly the
/// shapes that matter here** (found at M13 A18). The SP1 guest takes `pqcl-sm`
/// with `--no-default-features`, so the shape the circuit is built from was
/// never linted. Its own guard, `chainproof_is_absent_when_roles_are_off`, is
/// `#[cfg(not(feature = "roles"))]`, so it had **never run** under any gate. It
/// had also been failing `clippy -D warnings` since 2026-09-15, which nobody
/// saw. That is rule 13's second shape: a check running correctly against
/// nothing.
///
/// The second shape is `append-types` alone: what a harness takes in order to
/// build records through a Secure Module without being one. If it ever stopped
/// compiling without `host-software`, the harness would have to enable the
/// key-holding module to build, which row 11b forbids on the paper path.
///
/// `verb` is `clippy` or `test`, so both gates cover both shapes.
fn reduced_shapes(root: &Path, verb: &str) -> bool {
    let shapes: [&[&str]; 2] = [
        &["--no-default-features"],
        &["--no-default-features", "--features", "append-types"],
    ];
    shapes.iter().all(|features| {
        let mut args = vec![verb, "-p", "pqcl-sm", "--all-targets", "--locked"];
        args.extend_from_slice(features);
        if verb == "clippy" {
            args.extend_from_slice(&["--", "-D", "warnings"]);
        }
        eprintln!("xtask: {verb} pqcl-sm {}", features.join(" "));
        cargo(root, &args)
    })
}

fn cargo(root: &Path, args: &[&str]) -> bool {
    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    Command::new(cargo_bin)
        .current_dir(root)
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

/// Run `forge test` over `contracts/`.
///
/// ⛔ **A missing `forge` fails the check, it does not skip it** — same rule as
/// the Python selftest, and for a stronger reason. The suite contains the ACVP
/// conformance gate for our ported ML-DSA-65 verifier, and the standing rule
/// that gate implements is that no gas number may come from a verifier which
/// has not passed it. "Foundry was not installed" is not a state in which that
/// rule is satisfied.
/// Where Foundry's installer puts `forge`.
///
/// ⚠️ Searched explicitly because `foundryup` appends to the *interactive*
/// shell profile, so a non-interactive `bash -c` — which is how CI and every
/// scripted invocation run — does not see it. That turned a gate which must
/// never be skipped into one that was skipped every time it was automated, and
/// the message told the reader to fix their PATH rather than fixing itself.
///
/// ⛔ This does not weaken the rule: a genuinely absent `forge` still fails the
/// check. It only looks in the one place the official installer uses.
fn forge_command() -> Command {
    if let Some(home) = std::env::var_os("HOME") {
        let installed = Path::new(&home).join(".foundry").join("bin").join("forge");
        if installed.is_file() {
            return Command::new(installed);
        }
    }
    Command::new("forge")
}

fn forge_test(root: &Path) -> bool {
    let contracts = root.join("contracts");

    match forge_command().current_dir(&contracts).arg("test").status() {
        Ok(status) => status.success(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "forge not found, so the Solidity suite — including the binding \
                 ACVP-65 conformance gate — was not run.\n\
                 Install Foundry (https://getfoundry.sh) rather than skipping \
                 this: an unvalidated verifier must not produce a gas number.\n\
                 If it is installed, it is probably not on PATH: \
                 export PATH=\"$HOME/.foundry/bin:$PATH\""
            );
            false
        }
        Err(e) => {
            eprintln!("running forge test in {}: {e}", contracts.display());
            false
        }
    }
}

/// Run `scripts/demo.sh --walk`: every demo step, in order, against a fresh
/// one-validator chain. A missing `bash` fails the check; it never skips.
fn demo_walk(root: &Path) -> bool {
    match Command::new("bash")
        .current_dir(root)
        .args(["scripts/demo.sh", "--walk"])
        .status()
    {
        Ok(status) => status.success(),
        Err(e) => {
            eprintln!("running scripts/demo.sh --walk: {e}");
            false
        }
    }
}

/// Run `tools/mkfigs.py --selftest`.
///
/// ⛔ **A missing interpreter fails the check, it does not skip it.** The rules
/// being tested here are what stand between a local number and the paper, and
/// a gate that quietly passes when it cannot run is the failure mode this whole
/// file exists to prevent.
fn mkfigs_selftest(root: &Path) -> bool {
    let script = root.join("tools").join("mkfigs.py");

    // `python3` on Linux and macOS, `python` on Windows where the former is
    // usually a Store shim that exits non-zero. Try both rather than making the
    // check platform-specific.
    for python in ["python3", "python"] {
        match Command::new(python)
            .current_dir(root)
            .arg(&script)
            .arg("--selftest")
            .status()
        {
            Ok(status) => return status.success(),
            // Only an interpreter that is absent justifies trying the next
            // name. A selftest that ran and failed is a failure.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!("running {python} {}: {e}", script.display());
                return false;
            }
        }
    }

    eprintln!(
        "no Python interpreter found, so the publication refusal rules in {} \
         were not checked. Install python3 rather than skipping this: these \
         rules are what keep a local measurement out of the paper.",
        script.display()
    );
    false
}

// ---------------------------------------------------------------------------
// Ground rule #1, enforced by the build rather than by memory.
//
// The build plan: "No stubs, no mocks, no simulation. [...]
// Specifically banned: simulated blockchain, simulated HSM/TEE, simulated
// network, hard-coded 'representative' timings, sleep() standing in for work,
// and any `if cfg!(test)` branch that changes measured behaviour."
//
// A legitimate use (waiting for a real block to be mined is real waiting, not
// fake work) is permitted via an explicit, greppable escape hatch:
//
//     std::thread::sleep(poll_interval); // xtask-allow: sleep — polling a real
//                                        // Besu node for block inclusion
//
// The point is that every exception is justified in the source and can be
// audited, rather than the gate being switched off wholesale.
// ---------------------------------------------------------------------------

/// Substrings that indicate faked work. Matched case-insensitively.
const BANNED: &[(&str, &str)] = &[
    ("todo!", "unfinished code"),
    ("unimplemented!", "unfinished code"),
    ("thread::sleep", "sleep() must not stand in for work"),
    ("tokio::time::sleep", "sleep() must not stand in for work"),
    ("mock", "mocks are banned; build the real thing or cut it"),
    (
        "simulat",
        "simulation is banned; build the real thing or cut it",
    ),
    ("dummy", "placeholder data must not enter a measured path"),
    ("fake", "placeholder data must not enter a measured path"),
    ("hardcoded_timing", "measurements are never hard-coded"),
    // ⭐ The post-quantum claim the entire paper rests on.
    //
    // SP1 can wrap a STARK in a Groth16 or PLONK proof to shrink on-chain
    // verification. Both wrappers are **pairing-based**, so either one silently
    // reintroduces an assumption Shor breaks — into the one component whose
    // whole purpose (design §7b) is to keep the system free of algebraic
    // assumptions. Nothing would fail; the proofs would verify; the claim would
    // simply be false.
    //
    // The build plan (M6) requires a test that the pipeline "has no
    // Groth16/PLONK path compiled in at all". A grep for the call is stronger
    // than a runtime assertion, because a runtime assertion only fires on the
    // path that happens to execute.
    (
        "groth16",
        "pairing-based SNARK wrapper destroys the post-quantum claim; STARK only",
    ),
    (
        "plonk",
        "pairing-based SNARK wrapper destroys the post-quantum claim; STARK only",
    ),
];

/// Banned **outside one directory**, rather than everywhere.
///
/// ⭐ `p256` is a legitimate bench dependency and an illegitimate system one.
/// Exp. 1 needs ECDSA-P256 as the classical comparison point (§1d): without it
/// the paper can say what signatures cost against no signatures, but not what
/// *post-quantum* signatures cost against classical ones — which is the
/// comparison its systems argument rests on. ⛔ The same crate reaching the
/// data path would put a classical signature inside a post-quantum system.
///
/// So the ban is scoped rather than absolute. Ruled in the design record
/// §1d: *"a control, not a convention"* — the feature being default-off is a
/// convention, this is what makes it a control.
const PATH_SCOPED_BANNED: &[(&str, &str, &str)] = &[
    (
        "p256",
        "crates/pqcl-exp/",
        "ECDSA-P256 is the bench-only classical baseline; a classical signature \
         must not be reachable from the data path of a post-quantum system",
    ),
    // M10 H2: the chain driver signs Ethereum transaction envelopes with
    // secp256k1. Same scope, same reason — it must never sign evidence.
    (
        "k256",
        "crates/pqcl-exp/",
        "secp256k1 signs Ethereum transaction envelopes in the bench chain driver \
         only; a classical signature must not be reachable from the data path",
    ),
];

const ALLOW_MARKER: &str = "xtask-allow:";

fn no_stubs(root: &Path) -> bool {
    let mut files = BTreeSet::new();
    collect_rs(root, &mut files);

    let mut report = String::new();
    let mut hits = 0usize;

    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let rel_str = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let scoped = check_scoped(&text, &rel_str);

        for (lineno, needle, why, line) in check_text(&text).into_iter().chain(scoped) {
            hits += 1;
            let rel = path.strip_prefix(root).unwrap_or(path);
            let _ = writeln!(
                report,
                "  {}:{}: `{}` — {}\n      {}",
                rel.display(),
                lineno,
                needle,
                why,
                line.trim()
            );
        }
    }

    if hits > 0 {
        eprintln!(
            "\nno-stubs gate: {hits} violation(s) of ground rule #1\n\n{report}\n\
             If a use is genuinely real work, annotate the line with\n\
             `// {ALLOW_MARKER} <pattern> — <reason>` so the exception is auditable.\n"
        );
        return false;
    }
    true
}

/// Find ground-rule-#1 violations in one file's text.
///
/// Returns `(line number, matched pattern, why it is banned, the line)`.
/// Separated from [`no_stubs`] so the matching logic is testable without
/// touching the filesystem — a gate nobody has watched fail is not a gate.
fn check_scoped<'a>(
    text: &'a str,
    rel_path: &str,
) -> Vec<(usize, &'static str, &'static str, &'a str)> {
    let mut out = Vec::new();
    for (needle, allowed_dir, why) in PATH_SCOPED_BANNED {
        if rel_path.contains(allowed_dir) {
            continue;
        }
        for (lineno, line) in scan(text) {
            let lower = line.to_ascii_lowercase();
            if lower.contains(ALLOW_MARKER) {
                continue;
            }
            if contains_word(&lower, needle) {
                out.push((lineno, *needle, *why, line));
            }
        }
    }
    out
}

/// `needle` as a whole identifier, not as a substring of one.
///
/// ⚠️ A crate name is matched on word boundaries. Substring matching made the
/// `k256` ban fire on every `keccak256` (M10 H2, 18 false violations in
/// `pqcl-chainproof`) — the same trap the project rules names for counting terms,
/// where `RSA` matched adve**rsa**rial. It also means `p256` no longer matches
/// inside `secp256k1`.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    haystack.match_indices(needle).any(|(i, _)| {
        let before = haystack[..i].chars().next_back();
        let after = haystack[i + needle.len()..].chars().next();
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

fn check_text(text: &str) -> Vec<(usize, &'static str, &'static str, &str)> {
    let mut out = Vec::new();
    for (lineno, line) in scan(text) {
        let lower = line.to_ascii_lowercase();
        if lower.contains(ALLOW_MARKER) {
            continue;
        }
        for (needle, why) in BANNED {
            if lower.contains(needle) {
                out.push((lineno, *needle, *why, line));
                break;
            }
        }
    }
    out
}

/// Collect `.rs` files subject to the gate.
///
/// Excluded: `target/`, `xtask/` (this file names every banned pattern as a
/// string literal), and `tests/` directories — integration tests are permitted
/// to construct adversarial and placeholder inputs, that is their job.
fn collect_rs(dir: &Path, out: &mut BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(
                name.as_ref(),
                "target" | ".git" | "xtask" | "tests" | "benches"
            ) {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") && name != "tests.rs" {
            out.insert(path);
        }
    }
}

/// Yield `(1-based line number, line)` for lines outside `#[cfg(test)]` blocks.
///
/// Brace counting is deliberately naive — it does not parse string literals. It
/// therefore errs toward *reporting* rather than skipping, which is the safe
/// direction for a gate: a false positive is annotated away in one line, a false
/// negative is a stub that reaches a measurement.
fn scan(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut pending_cfg_test = false;
    let mut skip_until: Option<i32> = None;

    for (idx, line) in text.lines().enumerate() {
        let entry_depth = depth;
        depth += count(line, '{') - count(line, '}');

        if let Some(target) = skip_until {
            if depth <= target {
                skip_until = None;
            }
            continue;
        }

        if pending_cfg_test && depth > entry_depth {
            pending_cfg_test = false;
            skip_until = Some(entry_depth);
            continue;
        }

        let stripped = line.trim_start();
        if stripped.starts_with("#[cfg(test)]") || stripped.starts_with("#[cfg(all(test") {
            pending_cfg_test = true;
            continue;
        }

        out.push((idx + 1, line));
    }
    out
}

fn count(s: &str, c: char) -> i32 {
    i32::try_from(s.chars().filter(|&x| x == c).count()).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::check_text;

    /// A gate nobody has watched fail is not a gate. These fixtures are the
    /// evidence that ground rule #1 is actually enforced rather than declared.
    #[test]
    fn catches_each_banned_pattern() {
        for src in [
            "fn f() { todo!() }",
            "fn f() { unimplemented!() }",
            "fn f() { std::thread::sleep(d); }",
            "fn f() { tokio::time::sleep(d).await; }",
            "struct MockServer;",
            "fn simulate_chain() {}",
            "let dummy = 0;",
            "let fake_latency = 3;",
            // The SNARK wrappers. Both are pairing-based; either would void the
            // post-quantum claim while every test still passed.
            "let p = client.prove(&pk, stdin).groth16().run();",
            "let p = client.prove(&pk, stdin).plonk().run();",
        ] {
            assert_eq!(check_text(src).len(), 1, "gate failed to flag: {src}");
        }
    }

    /// The STARK modes must NOT be flagged, or the gate would forbid the only
    /// proof types we are allowed to produce.
    #[test]
    fn stark_proof_modes_are_not_flagged() {
        for src in [
            "let p = client.prove(&pk, stdin).core().run();",
            "let p = client.prove(&pk, stdin).compressed().run();",
        ] {
            assert!(
                check_text(src).is_empty(),
                "gate wrongly flagged a permitted STARK mode: {src}"
            );
        }
    }

    #[test]
    fn clean_code_passes() {
        let src = "fn seal(k: Key) -> Vec<u8> { aead.encrypt(&k) }";
        assert!(check_text(src).is_empty());
    }

    /// The classical crates are banned everywhere but the bench crate. Until
    /// M10 H2 this scoping had no test at all, so a broken `allowed_dir` match
    /// would have silently let ECDSA into the data path.
    #[test]
    fn classical_crates_are_confined_to_the_bench_crate() {
        use super::check_scoped;
        for src in [
            "use p256::ecdsa::SigningKey;",
            "use k256::ecdsa::SigningKey;",
        ] {
            assert_eq!(
                check_scoped(src, "crates/pqcl-pipeline/src/lib.rs").len(),
                1,
                "gate failed to flag outside the bench crate: {src}"
            );
            assert!(
                check_scoped(src, "crates/pqcl-exp/src/evm.rs").is_empty(),
                "gate wrongly flagged inside the bench crate: {src}"
            );
        }
    }

    /// Word boundaries, not substrings: `keccak256` is not `k256`, and
    /// `secp256k1` is not `p256`. The substring version fired 18 times on
    /// `pqcl-chainproof`'s Keccak calls.
    #[test]
    fn classical_crate_names_match_as_words_only() {
        use super::check_scoped;
        for src in [
            "pub fn keccak256(data: &[u8]) -> [u8; 32] {",
            "// the secp256k1 curve",
            "let tag = keccak256(b\"x\");",
        ] {
            assert!(
                check_scoped(src, "crates/pqcl-chainproof/src/lib.rs").is_empty(),
                "gate flagged a substring: {src}"
            );
        }
        assert_eq!(
            check_scoped("k256::ecdsa::SigningKey::random()", "crates/x/src/lib.rs").len(),
            1
        );
    }

    #[test]
    fn cfg_test_blocks_are_exempt() {
        // Tests legitimately construct adversarial and placeholder inputs.
        let src = "\
fn real() { work() }

#[cfg(test)]
mod tests {
    struct MockServer;
    fn f() { todo!() }
}
";
        assert!(check_text(src).is_empty());
    }

    #[test]
    fn code_after_a_cfg_test_block_is_still_scanned() {
        // The brace tracker must resume, or a stub placed after any test module
        // would slip through — which would make the gate worse than useless.
        let src = "\
#[cfg(test)]
mod tests {
    fn f() { todo!() }
}

fn shipped() { unimplemented!() }
";
        let hits = check_text(src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "unimplemented!");
    }

    #[test]
    fn allow_marker_exempts_one_line_only() {
        let src = "\
fn poll() {
    std::thread::sleep(d); // xtask-allow: sleep — polling a real Besu node
    std::thread::sleep(d);
}
";
        let hits = check_text(src);
        assert_eq!(hits.len(), 1, "only the unannotated line should be flagged");
        assert_eq!(hits[0].0, 3);
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(check_text("struct SIMULATEDHsm;").len(), 1);
    }
}
