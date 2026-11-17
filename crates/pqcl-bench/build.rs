//! Captures the compiler that built this crate, so `rustc_version` in a results
//! record is what actually compiled the binary rather than what
//! `rust-toolchain.toml` asked for. Those differ whenever someone overrides the
//! toolchain on the command line, and a results record that reports the
//! intention rather than the fact is the kind of provenance a reviewer is right
//! to distrust.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");

    // Cargo sets RUSTC to the compiler it is using for this build, so this is
    // the compiler, not merely *a* compiler on PATH.
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());

    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(
            // Not a panic. A build that cannot run its own compiler is
            // pathological, but failing the build here would be a worse outcome
            // than an honestly-labelled unknown that the publication guard can
            // still reason about.
            || "unknown".to_owned(),
            |s| s.trim().to_owned(),
        );

    println!("cargo:rustc-env=PQCL_RUSTC_VERSION={version}");
}
