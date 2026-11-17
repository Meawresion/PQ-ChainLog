//! Why the full-case audit scales worse than the flat MMR's — §1q.5 / §1p.3.
//!
//! On AWS (16 vCPU) ours sped up 1.8× from one core to all, the flat MMR 2.6×.
//! This times, over one case and 1…N threads:
//!
//! * ours with a node memo per shard (as `custody` measures it);
//! * ours without a memo (`Bundle::verify`), to see whether the memo is what
//!   stops it scaling;
//! * the flat MMR split into its two parts: leaf hashing (sharded) and the
//!   ordered appends (sequential, and inherently so).
//!
//! Local figures for the diagnosis only (the local RAM rule: ~25k records).
//!
//! ```text
//! cargo run --release -p pqcl-exp --example profile_audit_scaling
//! ```

#![allow(
    clippy::expect_used,
    clippy::cast_precision_loss,
    clippy::too_many_lines
)]

use std::time::{Duration, Instant};

use pqcl_capsule::{Bundle, CustodyRecord, Event};
use pqcl_exp::appender::InProcess;
use pqcl_exp::case::CaseBuilder;
use pqcl_exp::cast::Cast;
use pqcl_exp::custody_stream::{StreamParams, custody_stream};
use pqcl_forest::tier2::{Leaf, Mmr, NodeMemo};
use pqcl_pipeline::{Ais, CaseKeys};
use pqcl_primitives::xof::{Digest32, Domain, PrfKey, digest256, hash_domain};

fn sharded<T: Sync>(items: &[T], threads: usize, f: impl Fn(&[T]) + Sync) {
    let shard = items.len().div_ceil(threads).max(1);
    let f = &f;
    std::thread::scope(|s| {
        for part in items.chunks(shard) {
            s.spawn(move || f(part));
        }
    });
}

fn best_of(n: usize, mut f: impl FnMut()) -> Duration {
    (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .min()
        .expect("n > 0")
}

/// The stream's wall-clock base, so every record's timestamp lands inside the
/// `ts` attribute's range tree (M13 A2).
const TS_BASE: u64 = 1_757_000_000;

fn main() {
    let stream = custody_stream(&StreamParams {
        capsules: 3_000,
        active: 64,
        ..StreamParams::default()
    });
    let cast = Cast::generate().expect("keygen");
    let keys = CaseKeys::derive(&PrfKey::new(digest256(b"K")), b"case", &digest256(b"r"));
    let mut ais = Ais::new();
    let mut records: Vec<CustodyRecord> = Vec::new();
    // Every record through the library, transfers through `handoff`
    // (M13 A2/A14): `CaseBuilder` is shared with the harnesses, so a profile
    // measures the audit over the records the experiments actually produce.
    // A profile, never a paper number, so it is built in process; the same
    // `CaseBuilder` takes the enclave when a harness is pointed at one.
    let appender = InProcess::new(&cast, &keys);
    let mut build = CaseBuilder::new(&appender, &keys);
    for (i, e) in stream.iter().enumerate() {
        let r = if e.event == Event::Collect {
            let nonce = digest256(&e.capsule.to_le_bytes());
            let c = build
                .seal(nonce, digest256(b"cm"), digest256(&nonce), b"x", b"p", 0)
                .expect("seal");
            build.insert_capsule(e.capsule, c.clone());
            let a = build.feed(e, TS_BASE + i as u64, 0, None).expect("sign");
            ais.accept(c, a.signed.record.clone());
            a.signed.record
        } else {
            let a = build.feed(e, TS_BASE + i as u64, 0, None).expect("sign");
            ais.append(a.signed.record.clone());
            a.signed.record
        };
        records.push(r);
    }
    ais.close_epoch();
    let roots = ais.epoch_roots();
    let bundles: Vec<Bundle> = (0..ais.len())
        .filter_map(|i| ais.disclose(i, &keys))
        .collect();
    let flat_leaf = |r: &CustodyRecord| Leaf::new(Domain::CustodyRecord, &[&r.encode()]);
    println!("{} records over {} capsules", records.len(), bundles.len());
    // Encoded once, outside every timer: isolates hashing from `encode()`'s
    // per-record allocation, the one thing all three paths share.
    let encoded: Vec<Vec<u8>> = records.iter().map(CustodyRecord::encode).collect();

    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let mut axis: Vec<usize> = [1, 2, 4, 8].into_iter().filter(|t| *t < cores).collect();
    axis.push(cores);
    println!(
        "{:>7} {:>12} {:>12} {:>14} {:>14} {:>14}",
        "threads", "ours+memo", "ours plain", "flat leaves", "flat appends", "hash only"
    );
    for &t in &axis {
        let memo = best_of(3, || {
            sharded(&bundles, t, |part| {
                let mut m = NodeMemo::default();
                for b in part {
                    b.verify_memo(&roots, &mut m).expect("verify");
                }
            });
        });
        let plain = best_of(3, || {
            sharded(&bundles, t, |part| {
                for b in part {
                    b.verify(&roots).expect("verify");
                }
            });
        });
        let mut leaves: Vec<Leaf> = Vec::new();
        let leaf_t = best_of(3, || {
            let out: std::sync::Mutex<Vec<(usize, Vec<Leaf>)>> = std::sync::Mutex::new(Vec::new());
            let shard = records.len().div_ceil(t).max(1);
            let chunks: Vec<(usize, &[CustodyRecord])> =
                records.chunks(shard).enumerate().collect();
            sharded(&chunks, t, |part| {
                for (k, rs) in part {
                    let v: Vec<Leaf> = rs.iter().map(flat_leaf).collect();
                    out.lock().expect("lock").push((*k, v));
                }
            });
            let mut v = out.into_inner().expect("lock");
            v.sort_by_key(|(k, _)| *k);
            leaves = v.into_iter().flat_map(|(_, l)| l).collect();
        });
        let append_t = best_of(3, || {
            let mut m = Mmr::new();
            for l in &leaves {
                m.append(l);
            }
            let _root: Option<Digest32> = m.root();
        });
        let hash_only = best_of(3, || {
            sharded(&encoded, t, |part| {
                for e in part {
                    std::hint::black_box(hash_domain(Domain::CustodyRecord, &[e]));
                }
            });
        });
        println!(
            "{t:>7} {:>10.1}ms {:>10.1}ms {:>12.1}ms {:>12.1}ms {:>12.1}ms",
            memo.as_secs_f64() * 1e3,
            plain.as_secs_f64() * 1e3,
            leaf_t.as_secs_f64() * 1e3,
            append_t.as_secs_f64() * 1e3,
            hash_only.as_secs_f64() * 1e3
        );
    }
}
