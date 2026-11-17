//! Where the range-ingest **remainder** goes — the design record.
//!
//! M12's AWS breakdown left 1.89 µs of a 3.90 µs range token unattributed:
//! client map operations, the server's inserts, and per-event work. This splits
//! the two sides with the real code, not a model of it:
//!
//! 1. **end to end**: `XtClient::update` into an `HonestServer`, the path exp1
//!    times (cache sized to the stream, as M12 R2 does);
//! 2. **server alone**: the exact tokens and cross-tag batches from (1),
//!    recorded, then replayed into a fresh `HonestServer` and timed;
//! 3. **client** = (1) − (2).
//!
//! The stream is exp1-shaped: four range trees at depths 24/20/32/32, one value
//! per tree per event, drawn from a fixed-seed generator. ⛔ Local figures for
//! the fix decision only (the local RAM rule: ~2 048 events, a few hundred MB).
//!
//! ```text
//! cargo run --release -p pqcl-dsse --example profile_range_ingest
//! ```

// A profiling example: display-only float casts, and a failed update aborts.
#![allow(clippy::cast_precision_loss, clippy::expect_used)]

use std::collections::HashSet;
use std::time::Instant;

use pqcl_dsse::core::{Client, Edb, Op, SearchResponse, SearchToken, UpdateToken};
use pqcl_dsse::range::RangeTree;
use pqcl_dsse::xt::{Epoch, HonestServer, Transcript, XSetStore, XTag, XtClient};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

const EVENTS: u64 = 2_048;
const DEPTHS: [u32; 4] = [24, 20, 32, 32];
const BETA: usize = 256;
/// ⚠️ Values drawn from a pool of POOL per tree, not uniformly over the
/// domain: uniform 32-bit values make ~61 % of tokens first uses, while
/// exp1's real stream has ~4 % distinct keywords (19 025 of 458 752 on AWS).
/// A pool of 96 lands near that ratio, which is what the remainder is about.
const POOL: usize = 96;

/// Records what the server is sent, so it can be replayed into a real server.
#[derive(Default)]
struct Recording {
    tokens: Vec<UpdateToken>,
    batches: Vec<(Epoch, Vec<XTag>)>,
}

impl Edb for Recording {
    fn insert(&mut self, token: &UpdateToken) {
        self.tokens.push(token.clone());
    }
    fn search(&self, _token: &SearchToken) -> SearchResponse {
        SearchResponse(Vec::new())
    }
    fn len(&self) -> usize {
        self.tokens.len()
    }
}

impl XSetStore for Recording {
    fn add_xtags(&mut self, epoch: Epoch, tags: &[XTag]) {
        self.batches.push((epoch, tags.to_vec()));
    }
    fn probe(&self, _transcript: &Transcript) -> Vec<bool> {
        Vec::new()
    }
    fn xtag_count(&self) -> usize {
        self.batches.iter().map(|(_, b)| b.len()).sum()
    }
    fn seal_epoch(&mut self, _epoch: Epoch) {}
    fn reset(&mut self) {
        self.batches.clear();
    }
}

fn stream() -> Vec<(u64, Vec<u8>)> {
    let trees: Vec<RangeTree> = DEPTHS
        .iter()
        .enumerate()
        .map(|(i, d)| RangeTree::new(&format!("attr{i}"), *d))
        .collect();
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        x >> 11
    };
    let pools: Vec<Vec<u64>> = DEPTHS
        .iter()
        .map(|d| (0..POOL).map(|_| next() & ((1u64 << d) - 1)).collect())
        .collect();
    let mut out = Vec::new();
    for id in 0..EVENTS {
        for (t, pool) in trees.iter().zip(&pools) {
            let v = pool[usize::try_from(next() % POOL as u64).unwrap_or(0)];
            for kw in t.index_keywords(v) {
                out.push((id, kw));
            }
        }
    }
    out
}

fn client(capacity: usize) -> XtClient {
    XtClient::new(
        Client::with_path_cache(PrfKey::new([0x11; LAMBDA_BYTES]), capacity),
        PrfKey::new([0x12; LAMBDA_BYTES]),
        BETA,
    )
}

fn main() {
    let s = stream();
    let distinct = s
        .iter()
        .map(|(_, k)| k.as_slice())
        .collect::<HashSet<_>>()
        .len();
    let n = s.len() as f64;
    println!("{} tokens, {distinct} distinct keywords", s.len());

    // (1) end to end, best of three.
    let mut e2e = f64::MAX;
    for _ in 0..3 {
        let mut c = client(distinct);
        let mut server = HonestServer::new();
        let t = Instant::now();
        for (id, kw) in &s {
            c.update(&mut server, Op::Add, kw, *id).expect("update");
        }
        c.close_epoch(&mut server);
        e2e = e2e.min(t.elapsed().as_nanos() as f64);
    }

    // Record exactly what (1) sends.
    let mut c = client(distinct);
    let mut rec = Recording::default();
    for (id, kw) in &s {
        c.update(&mut rec, Op::Add, kw, *id).expect("update");
    }
    c.close_epoch(&mut rec);

    // (2) the server alone, best of three, EDB and XSet separately.
    let (mut edb, mut xset) = (f64::MAX, f64::MAX);
    for _ in 0..3 {
        let mut server = HonestServer::new();
        let t = Instant::now();
        for tok in &rec.tokens {
            server.insert(tok);
        }
        edb = edb.min(t.elapsed().as_nanos() as f64);
        let t = Instant::now();
        for (e, b) in &rec.batches {
            server.add_xtags(*e, b);
        }
        xset = xset.min(t.elapsed().as_nanos() as f64);
    }

    println!("per token, best of three:");
    println!("  end to end                       {:8.1} ns", e2e / n);
    println!("  server EDB insert                {:8.1} ns", edb / n);
    println!("  server XSet insert               {:8.1} ns", xset / n);
    println!(
        "  client (end to end − server)     {:8.1} ns",
        (e2e - edb - xset) / n
    );
}
