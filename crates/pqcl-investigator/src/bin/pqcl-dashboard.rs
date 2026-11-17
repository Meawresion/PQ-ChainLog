//! Start the investigator dashboard:
//! `pqcl-dashboard [--port N] [--course] [--no-warm-up] [--live-stark] [--walk | --walk-corners]`.
//!
//! * default: serve the dashboard on `127.0.0.1:<port>` (default 8080). The
//!   worker first runs the warm-up, labelling
//!   every panel it produces "pre-run"; `--no-warm-up` skips it, leaving the
//!   walkthrough to be stepped by hand;
//! * `--course`: skip D6, court-ordered redaction, to match deliverable4
//!   (§1dc.1);
//! * `--live-stark`: verify the saved warrant STARKs live (7.1 GB peak)
//!   instead of showing the stored AWS result with its label;
//! * `--walk`: run every walkthrough step in order without a browser and print
//!   each panel; exits non-zero on the first failing step;
//! * `--walk-corners`: run the warm-up, then a fixed script through all three
//!   corners, and exit non-zero on any failure, any search that disagrees with
//!   its plaintext oracle, or an out-of-scope search that is not refused.
//!
//! Environment: `PQCL_RPC` (default `http://127.0.0.1:8545`), `PQCL_DEMO_STORE`
//! (default `target/demo-store`). Run from the repository root.

use std::path::PathBuf;

use pqcl_investigator::demo::{Config, Demo, WARM_UP};
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    let port = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080u16);
    let repo = std::env::current_dir()?;
    if !repo.join("datasets/artefacts").is_dir() {
        return Err("run from the repository root: datasets/artefacts is not here".into());
    }
    let cfg = Config {
        store: std::env::var("PQCL_DEMO_STORE")
            .map_or_else(|_| repo.join("target/demo-store"), PathBuf::from),
        rpc: std::env::var("PQCL_RPC").unwrap_or_else(|_| "http://127.0.0.1:8545".into()),
        repo,
        course: flag("--course"),
        live_stark: flag("--live-stark"),
    };

    if flag("--walk") {
        let mut demo = Demo::new(cfg);
        while let Some(step) = demo.next_step() {
            let t = std::time::Instant::now();
            let out = demo
                .run(step)
                .map_err(|e| format!("step {step} failed: {e}"))?;
            println!("=== {step} ({:.1} s)", t.elapsed().as_secs_f64());
            println!("{}", serde_json::to_string_pretty(&out["panel"])?);
        }
        let state = demo.state();
        println!("=== state");
        println!("{}", serde_json::to_string_pretty(&state["capsules"])?);
        println!(
            "{}",
            serde_json::to_string_pretty(&state["graph"]["paths"])?
        );
        return Ok(());
    }

    if flag("--walk-corners") {
        return walk_corners(cfg);
    }

    pqcl_investigator::web::serve(cfg, port, !flag("--no-warm-up"))?;
    Ok(())
}

/// The corners' scripted walk: what a presenter would click, in order, with a
/// check on each answer. Runs in CI next to `--walk`, so a broken corner fails
/// a build rather than the presentation.
fn walk_corners(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut demo = Demo::new(cfg);
    demo.set_warming(true);
    for step in WARM_UP {
        let out = demo
            .run(step)
            .map_err(|e| format!("warm-up step {step} failed: {e}"))?;
        println!(
            "=== warm-up {step} ({:.1} s, {})",
            out["took_s"].as_f64().unwrap_or(0.0),
            out["mode"]
        );
    }
    demo.set_warming(false);

    let script: Vec<(&str, Value)> = vec![
        ("ingest", json!({"lines": 300, "mix": "mixed"})),
        // Pending: the new lines sit in the open epoch.
        ("search", json!({"s": "log:auth", "psi": "act:login-fail"})),
        // Out of scope: network identifiers are not in the evidence warrant.
        ("search", json!({"s": "log:auth", "psi": "ip:203.0.113.66"})),
        ("release", json!({"capsule": 2})),
        ("receive", json!({})),
        ("anchor", json!({})),
        // Now covered: the same question finds the burst's lines.
        (
            "search",
            json!({"s": "log:auth", "psi": "act:login-fail AND user:mallory"}),
        ),
        (
            "search",
            json!({"s": "log:web", "psi": "bytes:1_000_000..1_999_999 AND NOT status:404"}),
        ),
        (
            "search",
            json!({"s": "log:fw", "psi": "act:deny OR dur:600..3600"}),
        ),
        ("custody-search", json!({"event": "TRANSFER"})),
        (
            "custody-search",
            json!({"event": "COLLECT", "actor": "first-responder-1"}),
        ),
        // Role choice (§1dc.7): the evidence store hands the burst to the
        // lab's locker, the second analyst examines the disk image, and the
        // investigator records a read.
        ("release", json!({"capsule": 2, "from": 1, "to": 5})),
        ("receive", json!({})),
        ("analyze", json!({"actor": 7})),
        ("access", json!({"capsule": 2, "actor": 3})),
        ("anchor", json!({})),
        ("verify", json!({"capsule": 2})),
        ("tamper", json!({"capsule": 1})),
    ];
    // Refusals that must happen, each before anything is signed: an analyst
    // may not take custody (the library's role table), and only the holder
    // may release (this client's possession rule).
    let refusals: Vec<(&str, Value, &str)> = vec![
        (
            "release",
            json!({"capsule": 2, "from": 5, "to": 2}),
            "role table",
        ),
        (
            "release",
            json!({"capsule": 2, "from": 0, "to": 6}),
            "does not hold",
        ),
        ("access", json!({"capsule": 2, "actor": 1}), "role table"),
    ];
    for (i, (action, body)) in script.iter().enumerate() {
        let out = demo
            .act(action, body)
            .map_err(|e| format!("corner action {i} ({action}) failed: {e}"))?;
        let panel = &out["panel"];
        println!(
            "=== {action} ({:.2} s)",
            out["took_s"].as_f64().unwrap_or(0.0)
        );
        println!("{}", serde_json::to_string_pretty(panel)?);
        let out_of_scope = body["psi"].as_str().is_some_and(|p| p.starts_with("ip:"));
        if out_of_scope && panel["refused"] != true {
            return Err(
                format!("corner action {i}: an out-of-scope search was not refused").into(),
            );
        }
        if panel["oracle_equal"] == false {
            return Err(format!(
                "corner action {i}: the search disagrees with its plaintext oracle"
            )
            .into());
        }
    }
    for (action, body, why) in &refusals {
        match demo.act(action, body) {
            Ok(_) => return Err(format!("{action} {body} was not refused").into()),
            Err(e) if e.contains(why) => println!("=== refused as expected: {e}"),
            Err(e) => {
                return Err(format!("{action} {body} refused for the wrong reason: {e}").into());
            }
        }
    }
    Ok(())
}
