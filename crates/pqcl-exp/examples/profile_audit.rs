//! Where a full-case custody audit spends its time — the design record.
//!
//! Splits `Bundle::verify` over every capsule into its parts: the chain-link
//! hashes, the Tier-1 recomputation, and the Tier-2 proof walk. Local figures
//! for the fix decision only.
//!
//! ```text
//! cargo run --release -p pqcl-exp --example profile_audit
//! ```

#![allow(clippy::expect_used, clippy::cast_precision_loss)]

use std::time::Instant;

use pqcl_capsule::Event;
use pqcl_exp::appender::InProcess;
use pqcl_exp::case::CaseBuilder;
use pqcl_exp::cast::Cast;
use pqcl_exp::custody_stream::{StreamParams, custody_stream};
use pqcl_pipeline::{Ais, CaseKeys};
use pqcl_primitives::xof::{PrfKey, digest256};

/// The Tier-2 walk on its own: every segment's `0x02` leaf against the epoch
/// root, with the leaves computed outside the timer.
fn tier2_phase(bundles: &[pqcl_capsule::Bundle], root: &[u8; 32]) -> std::time::Duration {
    let leaves: Vec<_> = bundles
        .iter()
        .flat_map(|b| b.segments.iter().map(|s| s.custody_leaf().expect("leaf")))
        .collect();
    let t = Instant::now();
    for (s, l) in bundles.iter().flat_map(|b| b.segments.iter()).zip(&leaves) {
        assert!(pqcl_forest::tier2::verify(root, l, &s.anchor_proof));
    }
    t.elapsed()
}

/// The stream's wall-clock base, so every record's timestamp lands inside the
/// `ts` attribute's range tree (M13 A2).
const TS_BASE: u64 = 1_757_000_000;

fn main() {
    let stream = custody_stream(&StreamParams {
        capsules: 1_200,
        active: 64,
        ..StreamParams::default()
    });
    let cast = Cast::generate().expect("keygen");
    let keys = CaseKeys::derive(&PrfKey::new(digest256(b"K")), b"case", &digest256(b"r"));
    let mut ais = Ais::new();
    // Every record through the library, transfers through `handoff`
    // (M13 A2/A14): `CaseBuilder` is shared with the harnesses, so a profile
    // measures the audit over the records the experiments actually produce.
    // A profile, never a paper number, so it is built in process; the same
    // `CaseBuilder` takes the enclave when a harness is pointed at one.
    let appender = InProcess::new(&cast, &keys);
    let mut build = CaseBuilder::new(&appender, &keys);
    for (i, e) in stream.iter().enumerate() {
        if e.event == Event::Collect {
            let nonce = digest256(&e.capsule.to_le_bytes());
            let c = build
                .seal(nonce, digest256(b"cm"), digest256(&nonce), b"x", b"p", 0)
                .expect("seal");
            build.insert_capsule(e.capsule, c.clone());
            let a = build.feed(e, TS_BASE + i as u64, 0, None).expect("sign");
            ais.accept(c, a.signed.record);
        } else {
            let a = build.feed(e, TS_BASE + i as u64, 0, None).expect("sign");
            ais.append(a.signed.record);
        }
    }
    let root = ais.close_epoch();
    let roots = ais.epoch_roots();
    let bundles: Vec<_> = (0..ais.len())
        .filter_map(|k| ais.disclose(k, &keys))
        .collect();
    let records: usize = bundles.iter().map(pqcl_capsule::Bundle::record_count).sum();
    println!("{} capsules, {records} records", bundles.len());

    let t = Instant::now();
    for b in &bundles {
        b.verify(&roots).expect("verifies");
    }
    let total = t.elapsed();

    let t = Instant::now();
    for b in &bundles {
        for r in b.records() {
            std::hint::black_box(r.chain_link());
        }
    }
    let links = t.elapsed();

    let t = Instant::now();
    for b in &bundles {
        for s in &b.segments {
            std::hint::black_box(s.tier1_root());
        }
    }
    let tier1 = t.elapsed();

    let tier2 = tier2_phase(&bundles, &root);

    let t = Instant::now();
    for b in &bundles {
        for r in b.records() {
            std::hint::black_box(r.encode());
        }
    }
    let encode = t.elapsed();

    let pct = |d: std::time::Duration| 100.0 * d.as_secs_f64() / total.as_secs_f64();
    println!("full audit (Bundle::verify, every capsule): {total:?}");
    println!(
        "  chain-link hashes (encode + hash):  {links:?}  {:.0}%",
        pct(links)
    );
    println!(
        "  Tier-1 roots (encode + hash + tree): {tier1:?}  {:.0}%",
        pct(tier1)
    );
    println!(
        "  Tier-2 proof walks:                 {tier2:?}  {:.0}%",
        pct(tier2)
    );
    println!(
        "  (record encodes alone, once:        {encode:?}  {:.0}%)",
        pct(encode)
    );
}
