//! The midterm demo's warrant proofs (case (b)).
//!
//! ```text
//! warrant-demo prove  <dir>     on AWS: build the demo's two warrants, prove a core
//!                               STARK for each, verify it, save proofs + vk + bundle
//! warrant-demo verify <dir> <name> <nullifier> <scope_commit> <warrant_root> <epoch>
//!                               locally, during D4: verify one saved proof and bind
//!                               it to the values the AIS took from the chain
//! ```
//!
//! A core proof needs 13.2 GiB peak to *prove* (M6), which no developer box
//! here has, so the proofs are made once on AWS and **verified live** in the
//! demo. `verify` takes the published values as arguments, never from the
//! bundle, so the binding it reports is against what the chain says.
//!
//! ⛔ Never shown as a proof: an SP1 *execute* run. There is no execute path in
//! this binary.

use std::path::Path;
use std::time::Instant;

use pqcl_primitives::rng;
use pqcl_primitives::xof::{Digest32, Domain, hash_domain};
use pqcl_sm::Plane;
use pqcl_warrant::relation::{Witness, scope_digest};
use pqcl_warrant::{Nullifier, Scope, Warrant, WarrantTree};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1VerifyingKey};
use warrant_host::{ProofMode, SearchAuthorisation, prove, verify_authorised};

/// The epoch the demo searches in: epoch 1 is anchored in D3, so 2 is open.
const EPOCH: u64 = 2;
const CASE_ID: &str = "CASE-DEMO-2026-10";

/// (name, plane, warrant scope, query scope). The evidence warrant covers the
/// file-system and numeric classes 1-12, not the network classes 20-22; the
/// custody warrant is the separate, default-deny grant.
const SPECS: &[(&str, &str, (u64, u64), (u64, u64))] = &[
    ("evidence", "evidence", (1, 12), (4, 10)),
    ("custody", "custody", (1, 11), (1, 2)),
];

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Res<Digest32> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return Err(format!("expected 32 bytes of hex, got {s}").into());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}

fn plane(p: &str) -> Plane {
    if p == "custody" { Plane::Custody } else { Plane::Evidence }
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove") => prove_all(Path::new(args.get(2).ok_or("prove <dir>")?)),
        Some("verify") if args.len() == 8 => verify_one(&args[2..]),
        _ => Err("usage: warrant-demo prove <dir> | verify <dir> <name> <N> <scopeCommit> <rho_W> <epoch>".into()),
    }
}

fn prove_all(dir: &Path) -> Res<()> {
    std::fs::create_dir_all(dir)?;
    let r_case = rng::secret()?;
    // cid = H(0x14 ‖ ⟪case_id, r_c⟫), exactly as `pqcl_pipeline::CaseKeys::derive`.
    let cid = hash_domain(Domain::CaseId, &[CASE_ID.as_bytes(), &r_case]);
    let inv_id = hash_domain(Domain::ActorCommit, &[b"investigator-1", &[4u8], &rng::secret()?]);

    let mut warrants = Vec::new();
    let mut tree = WarrantTree::new();
    let mut others = Vec::new();
    for (i, (name, p, (lo, hi), _)) in SPECS.iter().enumerate() {
        // Another investigator's warrant ahead of each of ours, so every path
        // is non-trivial.
        let other = rng::secret()?;
        let at_other = tree.insert(other);
        others.push(serde_json::json!({"index": at_other, "commitment": hex(&other)}));
        let w = Warrant {
            inv_id,
            cid_c: cid,
            role: 4,
            scope: Scope::new(plane(p), *lo, *hi)?,
            window: (0, 1_000),
            expiry: 1_000,
            nonce: rng::secret()?,
        };
        let secret = rng::secret()?;
        let at = tree.insert(pqcl_warrant::tree::leaf(&w.encode(), &secret));
        warrants.push((i, *name, w, secret, at));
    }
    let root = tree.root().ok_or("empty warrant tree")?;

    let mut out = Vec::new();
    let mut vk_saved = false;
    for (i, name, w, secret, at) in &warrants {
        let (_, p, _, (qlo, qhi)) = SPECS[*i];
        let query = Scope::new(plane(p), qlo, qhi)?;
        let witness = Witness { warrant: w.clone(), secret: *secret, path: tree.path(*at).ok_or("path")?, query };
        let t = Instant::now();
        let (proof, vk) = prove(&witness, root, EPOCH, ProofMode::Core)?;
        let prove_s = t.elapsed().as_secs_f64();
        if !matches!(proof.proof, SP1Proof::Core(_)) {
            return Err("the proof is not a core STARK".into());
        }
        proof.save(dir.join(format!("{name}.proof")))?;
        if !vk_saved {
            std::fs::write(dir.join("vk.bin"), bincode::serialize(&vk)?)?;
            vk_saved = true;
        }
        out.push(serde_json::json!({
            "name": name, "plane": p, "index": at,
            "inv_id": hex(&w.inv_id), "role": w.role, "scope": [w.scope.bounds().0, w.scope.bounds().1],
            "window": [w.window.0, w.window.1], "expiry": w.expiry, "nonce": hex(&w.nonce),
            "secret": hex(secret), "query": [qlo, qhi],
            "nullifier": hex(&Nullifier::new(secret, EPOCH).0), "scope_commit": hex(&scope_digest(&query)),
            "prove_seconds": prove_s,
        }));
        eprintln!("{name}: core STARK proved and verified in {prove_s:.1} s");
    }

    let bundle = serde_json::json!({
        "what": "PQ-ChainLog midterm demo warrant bundle. Demo only: no paper number.",
        "case_id": CASE_ID, "r_case": hex(&r_case), "cid": hex(&cid), "epoch": EPOCH,
        "warrant_root": hex(&root), "tree_order": "other, evidence, other, custody",
        "others": others, "warrants": out,
        "instance": std::env::var("PQCL_INSTANCE").unwrap_or_default(),
        "git_sha": std::env::var("PQCL_GIT_SHA").unwrap_or_default(),
    });
    std::fs::write(dir.join("bundle.json"), serde_json::to_vec_pretty(&bundle)?)?;
    Ok(())
}

fn verify_one(a: &[String]) -> Res<()> {
    let dir = Path::new(&a[0]);
    let mut proof = SP1ProofWithPublicValues::load(dir.join(format!("{}.proof", a[1])))?;
    let vk: SP1VerifyingKey = bincode::deserialize(&std::fs::read(dir.join("vk.bin"))?)?;
    let published = SearchAuthorisation {
        nullifier: unhex(&a[2])?,
        scope_commit: unhex(&a[3])?,
        warrant_root: unhex(&a[4])?,
        epoch: a[5].parse()?,
    };
    let bytes = std::fs::metadata(dir.join(format!("{}.proof", a[1])))?.len();
    let t = Instant::now();
    let result = verify_authorised(&mut proof, &vk, &published);
    let ms = t.elapsed().as_secs_f64() * 1e3;
    let out = match result {
        Ok(s) => serde_json::json!({"ok": true, "variant": "core STARK", "proof_bytes": bytes, "verify_ms": ms,
            "statement": {"warrant_root": hex(&s.warrant_root), "nullifier": hex(&s.nullifier.0),
                          "epoch": s.epoch, "scope_digest": hex(&s.scope_digest)}}),
        Err(e) => serde_json::json!({"ok": false, "error": e.to_string(), "proof_bytes": bytes, "verify_ms": ms}),
    };
    println!("{out}");
    Ok(())
}
