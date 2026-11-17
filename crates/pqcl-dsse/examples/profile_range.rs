//! Where a `Π_RANGE` search spends its time — M10 P2's profile.
//!
//! Rebuilds exp7's depth-14 index (every value updated once under its prefix
//! path, documents `i % 512`) and times one 50%-width range query phase by
//! phase: cover, search tokens, server expansion, client verify-and-decrypt,
//! and the union. Local figures, for the fix decision only.
//!
//! ```text
//! cargo run --release -p pqcl-dsse --example profile_range
//! ```

// A profiling example, not library code; see profile_update.rs.
#![allow(clippy::cast_precision_loss, clippy::expect_used)]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use pqcl_dsse::core::{Client, Edb, Op};
use pqcl_dsse::range::RangeTree;
use pqcl_dsse::xt::HonestServer;
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

const DEPTH: u32 = 14;
const RECORDS: u64 = 512;

fn main() {
    let tree = RangeTree::new("ts", DEPTH);
    let domain = tree.domain();
    let mut core_client = Client::new(PrfKey::new([0x71; LAMBDA_BYTES]));
    let mut server = HonestServer::new();

    let t = Instant::now();
    let mut postings = 0u64;
    for v in 0..domain {
        for kw in tree.index_keywords(v) {
            let tok = core_client
                .update(Op::Add, &kw, v % RECORDS)
                .expect("update");
            server.insert(&tok);
            postings += 1;
        }
    }
    println!(
        "built depth {DEPTH}: {domain} values, {postings} postings, {:?}",
        t.elapsed()
    );
    // `XtClient::candidates` is exactly search_token -> search -> finish on
    // this client, so the phases are timed on it directly.
    let client = core_client;

    for pct in [1u64, 10, 50] {
        let width = (domain * pct / 100).max(1);
        let lo = domain / 4;
        let hi = (lo + width - 1).min(domain - 1);

        let t = Instant::now();
        let cover = tree.cover_keywords(lo, hi);
        let t_cover = t.elapsed();

        let (mut t_tok, mut t_srv, mut t_fin, mut t_union) = (
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
        );
        let mut slots = 0usize;
        let mut hits = BTreeSet::new();
        let total = Instant::now();
        for kw in &cover {
            let t = Instant::now();
            let token = client.search_token(kw).expect("cover node has history");
            t_tok += t.elapsed();

            let t = Instant::now();
            let response = server.search(&token);
            t_srv += t.elapsed();
            slots += response.0.len();

            let t = Instant::now();
            let ids = client.finish(kw, &token, &response).expect("verifies");
            t_fin += t.elapsed();

            let t = Instant::now();
            hits.extend(ids);
            t_union += t.elapsed();
        }
        let t_total = total.elapsed();
        let per = |d: Duration| d.as_nanos() as f64 / slots as f64 / 1_000.0;
        println!(
            "\n{pct:>2}% width: cover {} nodes, {slots} postings, {} distinct docs, total {:.2} ms",
            cover.len(),
            hits.len(),
            t_total.as_secs_f64() * 1e3
        );
        println!(
            "  cover computation     {:>8.3} ms",
            t_cover.as_secs_f64() * 1e3
        );
        println!(
            "  search tokens         {:>8.3} ms",
            t_tok.as_secs_f64() * 1e3
        );
        println!(
            "  server search         {:>8.3} ms   {:.3} µs/posting",
            t_srv.as_secs_f64() * 1e3,
            per(t_srv)
        );
        println!(
            "  client verify+decrypt {:>8.3} ms   {:.3} µs/posting",
            t_fin.as_secs_f64() * 1e3,
            per(t_fin)
        );
        println!(
            "  union into result set {:>8.3} ms   {:.3} µs/posting",
            t_union.as_secs_f64() * 1e3,
            per(t_union)
        );
        println!(
            "  total per posting                   {:.3} µs",
            per(t_total)
        );
    }
}
