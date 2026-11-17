//! ⭐ **M13 A18 clause (d): a record stamped with a Secure Module holds nothing
//! built outside it.**
//!
//! `RunMetadata::secure_module` is set only by `emit_custody`, from the backend
//! of the `CustodyAppender` the run built through, and `mkfigs.py` publishes
//! only `nitro-enclave`. Two things would make that a false label, and this
//! file forbids both in every harness that builds a case:
//!
//! 1. **writing through `emit`** — the record would carry no `secure_module`,
//!    which the guard reads as "built nothing through a module";
//! 2. **building a capsule or a record outside the appender** — the record
//!    would say `nitro-enclave` while some of its custody records were signed
//!    by keys in the harness's own memory. `tamper.rs`'s payload-deletion class
//!    and `custody.rs`'s transfer benchmark both did exactly this until A18.
//!
//! These are reading tests, so each carries its own true positive, and the
//! universe is **found** in the source tree rather than listed — rule 14: a
//! hand-kept list of harnesses is the thing that goes stale.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

/// Every `.rs` file under `dir` (relative to the crate) that builds a case.
fn builds_a_case(dir: &str) -> Vec<(PathBuf, String)> {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for entry in std::fs::read_dir(here.join(dir)).unwrap_or_else(|e| panic!("list {dir}: {e}")) {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_some_and(|x| x == "rs") {
            let src = std::fs::read_to_string(&path).expect("readable");
            if src.contains("CaseBuilder::new") {
                out.push((path, src));
            }
        }
    }
    out.sort();
    out
}

/// The source with all whitespace removed, so a call split across lines by
/// rustfmt (`cast\n    .defr\n    .seal(`) reads the same as one written on a
/// single line.
fn squeezed(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Calls that build a capsule or a custody record without an appender, as they
/// read with whitespace removed.
///
/// `Agent::new(` is here because a harness that constructs an agent of its own
/// has a signing key outside the appender, whatever it then does with it —
/// which is how `custody.rs`'s second custodian and `tamper.rs`'s class-5 cast
/// arose.
const OUTSIDE_THE_APPENDER: &[&str] = &[
    "Agent::new(",
    ".defr.seal(",
    ".collect_record(",
    ".append_record(",
    ".dispose_record(",
    ".countersign(",
    "handoff::release(",
    "handoff::receive(",
];

/// Which of [`OUTSIDE_THE_APPENDER`] appear in `src`, comments excluded.
///
/// Comments are dropped line by line before squeezing: several harnesses
/// *describe* `handoff::release` in prose, and a test that failed on the word
/// would be teaching people to stop writing the explanation.
fn signs_outside(src: &str) -> Vec<&'static str> {
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let code = squeezed(&code);
    OUTSIDE_THE_APPENDER
        .iter()
        .copied()
        .filter(|p| code.contains(p))
        .collect()
}

/// Whether `src` writes its record through `emit_custody` and never `emit`.
fn writes_through_emit_custody(src: &str) -> bool {
    let code = squeezed(src);
    // `emit_custody(` does not contain `emit(`, so the two are distinguishable
    // as substrings; a bare `emit(` is a plain write.
    code.contains("emit_custody(") && !code.contains("emit(")
}

#[test]
fn every_case_building_binary_writes_through_emit_custody() {
    let bins = builds_a_case("src/bin");
    assert!(
        bins.len() >= 3,
        "found only {} case-building binaries; the universe should not shrink silently: {:?}",
        bins.len(),
        bins.iter().map(|(p, _)| p).collect::<Vec<_>>()
    );
    for (path, src) in &bins {
        assert!(
            writes_through_emit_custody(src),
            "{} builds a case but does not write through `emit_custody`, so its \
             record cannot say which Secure Module built it",
            path.display()
        );
    }

    // ⭐ The true positives: the check must see both failures.
    assert!(!writes_through_emit_custody(
        "    emit(\n  \"x\",\n  spec,\n )?;"
    ));
    assert!(!writes_through_emit_custody(
        "emit_custody(\"x\", s, 1, m, b)?;\nemit(\"y\", s, 1, m)?;"
    ));
    assert!(writes_through_emit_custody(
        "emit_custody(\n \"x\", s, 1, m, b,\n)?;"
    ));
}

#[test]
fn no_case_building_harness_signs_outside_its_appender() {
    let mut found = builds_a_case("src/bin");
    found.extend(builds_a_case("examples"));
    assert!(
        found.len() >= 5,
        "found only {} case-building harnesses",
        found.len()
    );
    for (path, src) in &found {
        let bad = signs_outside(src);
        assert!(
            bad.is_empty(),
            "{} builds a case through an appender but also signs outside it ({bad:?}). \
             Its record would name the appender's Secure Module while holding custody \
             records the appender never saw",
            path.display()
        );
    }

    // ⭐ The true positives, one per pattern, including the split-line form
    // rustfmt produces — the form `custody.rs` actually had.
    assert_eq!(
        signs_outside("let c = cast\n    .defr\n    .seal(keys, cm, &ip)?;"),
        vec![".defr.seal("]
    );
    assert_eq!(
        signs_outside("let receiver = Agent::new(key, b\"lab-1\", Role::Custodian);"),
        vec!["Agent::new("]
    );
    for p in OUTSIDE_THE_APPENDER {
        let planted = format!("let x = y{p}z);");
        assert_eq!(signs_outside(&planted), vec![*p], "cannot see {p}");
    }
    // And a comment naming the call is not a call.
    assert!(signs_outside("// routes a pair through `handoff::release`").is_empty());
}
