//! **Experiment 7** — Boolean and range query latency, `Π_RANGE` vs Zuo'22.
//!
//! A clean symmetric-only like-for-like: neither scheme uses a group operation,
//! so the comparison is between two designs rather than between two primitive
//! families.
//!
//! # Two constraints that decide whether this experiment means anything
//!
//! Both were found by reading the TDSC paper, and both are pinned by tests in
//! `baselines/zuo22/tests/against_oracle.rs`. Both make *our* position worse.
//!
//! ⛔ **1. Every value is updated once.** Zuo'22's `Search` returns `⊥` for the
//! **whole query** if any node of the best range cover has no update history
//! (Algorithm 2, lines 5–7) — not a partial answer. A sparse workload would
//! therefore let it answer many queries by *not answering them*, which is fast
//! for a reason unrelated to its design and would flatter it enormously. The
//! authors' own setup says: *"We update one time for each value."* So does this.
//!
//! ⛔ **2. Cold and warm searches are reported separately.** Their search is
//! **destructive and compacting**: the server deletes every entry it walked and
//! writes back a single summary, explicitly *"in order to save the server
//! storage"*. A second search over the same node therefore does dramatically
//! less work. Reporting their warm number against our cold one — or the reverse
//! — would be a fabricated comparison, so both are measured under one convention
//! applied to both schemes.
//!
//! # Domains are the committed ones
//!
//! Design §6b′ fixes them, and the plan says not to re-derive: timestamp `2²⁴`
//! (default) or `2³⁰` (fine), duration `2²⁰`, bytes `2³²`, amount `2³²`. This
//! sweeps a smaller domain than production because Zuo'22 materialises a bitmap
//! **per value in the domain**, and `2³²` values is not a workload, it is a
//! denial of service against the experiment.
//!
//! # Running it
//!
//! ```text
//! cargo run --release -p pqcl-exp --bin exp7
//! ```
//!
//! Needs no corpus: the workload is numeric values, which are ours to choose.

use std::time::Instant;

use baseline_dsse_skq as skq;
use baseline_mdrsse as mdrsse;
use baseline_sdsse_cq as sdsse;
use baseline_zuo22 as zuo;
use pqcl_bench::{MIN_ITERATIONS, RunSpec};
use pqcl_dsse::core::{Client, Op};
use pqcl_dsse::range::RangeTree;
use pqcl_dsse::xt::{HonestServer, XtClient};
use pqcl_exp::stats::Summary;
use pqcl_exp::{emit, stats};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

/// Domain depths to sweep. `2^d` values each, and **every one is updated**.
///
/// Capped at 2¹⁴ because Zuo'22 holds a bitmap per value: at 2²⁰ the setup alone
/// would dominate the run, and at the committed 2³² it is not runnable at all.
/// That is a property of their design worth stating, not a shortcut — see the
/// `domain_note` in the record.
const DEPTHS: &[u32] = &[8, 10, 12, 14];

/// Records in the bitmap — Zuo'22's `y`, the number of documents.
const RECORDS: usize = 512;

/// Range widths as a fraction of the domain, in percent.
///
/// A narrow range is the case range covers are good at; a wide one approaches a
/// full scan and is where any advantage should disappear. Reporting only narrow
/// ranges would be choosing the result.
const RANGE_WIDTH_PCT: &[u64] = &[1, 10, 50];

/// Cross-tag upload batch size.
const BETA: usize = 256;

/// M10 H5: the collection-size axis. Depth fixed here, `N` swept.
const N_AXIS_DEPTH: u32 = 10;

/// The `N` axis: `pqcl_exp::collection_axis`, shared with Exp. 1's Zuo'22
/// passes (§1l.3). Zuo'22 stores an `N`-bit bitmap per updated node --
/// `max(D, N)·(depth+1)` nodes -- so its memory is `O(N²)` here: ~360 MB at
/// 16 384, ~6 GB at 65 536.
fn n_axis() -> Vec<usize> {
    pqcl_exp::collection_axis()
}

/// ⭐ M10 H5 — cost against **collection size `N`**, at a fixed depth.
///
/// Zuo'22's bitmap is `N` bits per cover node, so its search grows with `N`;
/// ours grows with the postings that match. The paper predicts a crossover and
/// **commits to reporting it wherever it lands**, so `N` is a fixed sweep, never
/// tuned. Every value is still updated at least once (constraint 1): there are
/// `max(D, N)` updates, value `i mod D` to document `i mod N`, identically for
/// both schemes, and cold and warm stay apart (constraint 2).
fn n_axis_rows(
    rng: &mut impl rand::Rng,
) -> Result<Vec<serde_json::Value>, Box<dyn core::error::Error>> {
    let depth = N_AXIS_DEPTH;
    let domain = 1u64 << depth;
    let tree = RangeTree::new("v", depth);
    let mut rows = Vec::new();
    for records in n_axis() {
        let updates = usize::try_from(domain).unwrap_or(usize::MAX).max(records);
        let values: Vec<u64> = (0..updates as u64).map(|i| i % domain).collect();
        eprintln!("N axis: {records} documents, {updates} updates at depth {depth}");
        let (ours, our_server, _) = build_ours(&tree, &values, records)?;
        let (zuo_client, mut zuo_edb) = build_zuo(depth, &values, records, rng);
        let (skq_client, mut skq_edb) = build_skq(depth, &values, records);
        let md = build_mdrsse(&values, records)?;
        for &pct in RANGE_WIDTH_PCT {
            let cell = Cell {
                tree: &tree,
                depth,
                domain,
                pct,
            };
            let mut row = cell.measure(
                &ours,
                &our_server,
                &zuo_client,
                &mut zuo_edb,
                &skq_client,
                &mut skq_edb,
            );
            row["mdrsse"] = md.measure(&values, records, &row)?;
            row["records"] = serde_json::json!(records);
            row["updates"] = serde_json::json!(updates);
            rows.push(row);
        }
    }
    Ok(rows)
}

/// Seed for Zuo'22's update randomness, recorded in the results.
const ZUO_RNG_SEED: u64 = 0x5EED_0007;

/// Build our index: every value updated once, indexed under its prefix path.
fn build_ours(
    tree: &RangeTree,
    values: &[u64],
    records: usize,
) -> Result<(XtClient, HonestServer, usize), Box<dyn core::error::Error>> {
    let core = Client::new(PrfKey::new([0x71u8; LAMBDA_BYTES]));
    let mut client = XtClient::new(core, PrfKey::new([0x72u8; LAMBDA_BYTES]), BETA);
    let mut server = HonestServer::new();

    // ⛔ `i % RECORDS`, matching Zuo'22's bitmap width exactly.
    //
    // A first version used `i` directly, giving one document per value — so at
    // depth 14 our index held 16 384 documents while their bitmap covered 512.
    // Our side then returned up to 32× more results for the same query, and the
    // latency comparison was measuring two different workloads. The two schemes
    // must index the same corpus or the numbers mean nothing.
    let mut tokens = 0usize;
    for (i, v) in values.iter().enumerate() {
        let doc = (i % records) as u64;
        for kw in tree.index_keywords(*v) {
            client.update(&mut server, Op::Add, &kw, doc)?;
            tokens += 1;
        }
    }
    client.flush(&mut server);
    client.close_epoch(&mut server);
    Ok((client, server, tokens))
}

/// Build Zuo'22's index: one update per value, as their own experiment does.
fn build_zuo(
    depth: u32,
    values: &[u64],
    records: usize,
    rng: &mut impl rand::Rng,
) -> (zuo::Client, zuo::Edb) {
    let mut client = zuo::Client::setup([0x73u8; 32], 1u64 << depth, records);
    let mut edb = zuo::Edb::new();

    for (i, v) in values.iter().enumerate() {
        let delta = zuo::BitString::insert_delta(records, i % records);
        let msgs = client.update(*v, &delta, rng);
        zuo::server_update(&mut edb, &msgs);
    }
    (client, edb)
}

/// `DSSE_SKQ` over the same values and documents as ours and Zuo'22. One
/// dimension: the Hilbert curve of one dimension is the identity.
fn build_skq(depth: u32, values: &[u64], records: usize) -> (skq::Client, skq::Edb) {
    let mut client = skq::Client::setup([0x75u8; 32], records, &[1u64 << depth]);
    // More values than documents means a document holds several, which the paper
    // never has. Below that the printed protocol runs untouched.
    if (1usize << depth) > records {
        client = client.multi_valued();
    }
    let mut edb = skq::Edb::default();
    let mut seen = std::collections::HashSet::new();
    for (i, v) in values.iter().enumerate() {
        edb.apply(client.update_point_once(0, *v, i % records, &mut seen));
    }
    (client, edb)
}

/// One timed range query on our scheme.
///
/// ⭐ **A range reduces to a disjunction, and a disjunction is a union — not a
/// probe.** `Π_BOOL`'s anchor rule (design §6a′) says the candidate set is the
/// union of the anchoring *clause's* postings. A range cover is a single
/// all-positive clause, so there is no s-term to anchor on and nothing to
/// cross-tag: the answer is exactly the union of the cover nodes' postings.
///
/// A first version of this function anchored on one cover node and probed the
/// rest as x-terms, which is the *conjunctive* shape. It would have returned
/// only documents present under the anchor — silently dropping every document
/// whose value falls in a different part of the range, and reporting a
/// conjunction's cost for a disjunction's query.
///
/// So the cost is `O(|cover|)` `Π_core` searches, which is the `O(log D)` the
/// design claims, and the leakage argument is unchanged: the server sees
/// `|cover|` ordinary single-keyword searches.
fn search_ours(
    client: &XtClient,
    server: &HonestServer,
    tree: &RangeTree,
    lo: u64,
    hi: u64,
) -> usize {
    let cover = tree.cover_keywords(lo, hi);
    let mut hits = std::collections::BTreeSet::new();
    for kw in &cover {
        if let Ok(ids) = client.candidates(server, kw) {
            hits.extend(ids);
        }
    }
    hits.len()
}

/// One `(depth, range-width)` cell: both schemes, cold and warm kept apart.
struct Cell<'a> {
    tree: &'a RangeTree,
    depth: u32,
    domain: u64,
    pct: u64,
}

impl Cell<'_> {
    fn measure(
        &self,
        ours: &XtClient,
        our_server: &HonestServer,
        zuo_client: &zuo::Client,
        zuo_edb: &mut zuo::Edb,
        skq_client: &skq::Client,
        skq_edb: &mut skq::Edb,
    ) -> serde_json::Value {
        let width = (self.domain * self.pct / 100).max(1);
        let lo = self.domain / 4;
        let hi = (lo + width - 1).min(self.domain - 1);
        let cover_size = self.tree.cover_keywords(lo, hi).len();

        // Ours is non-destructive, so cold and warm are the same measurement.
        let mut our_samples = Vec::new();
        let mut our_hits = 0;
        for i in 0..MIN_ITERATIONS {
            let t = Instant::now();
            let n = search_ours(ours, our_server, self.tree, lo, hi);
            our_samples.push(t.elapsed());
            if i == 0 {
                our_hits = n;
            }
        }

        // ⛔ Constraint 2: Zuo'22's FIRST search is cold. It compacts, so every
        // later one is warm. Two different measurements, kept apart.
        let t = Instant::now();
        let cold_result = zuo_client.search(lo, hi, zuo_edb);
        let zuo_cold = t.elapsed();

        let mut zuo_warm_samples = Vec::new();
        for _ in 0..MIN_ITERATIONS {
            let t = Instant::now();
            let _ = zuo_client.search(lo, hi, zuo_edb);
            zuo_warm_samples.push(t.elapsed());
        }

        // ⛔ The same convention for DSSE_SKQ: its search compacts too (Alg. 2
        // lines 21–22), so the first is timed once, cold, as Zuo'22's is.
        let t = Instant::now();
        let skq_cold_result = skq::search(skq_client, skq_edb, Some((0, lo, hi)), &[]);
        let skq_cold = t.elapsed();
        let skq_hits = skq_cold_result.as_ref().map(|(br, _)| br.files().len());
        assert_eq!(
            skq_hits,
            Some(our_hits),
            "DSSE_SKQ and Pi_RANGE disagree on [{lo}, {hi}]: no timing here means anything"
        );
        let mut skq_warm_samples = Vec::new();
        for _ in 0..MIN_ITERATIONS {
            let t = Instant::now();
            let _ = skq::search(skq_client, skq_edb, Some((0, lo, hi)), &[]);
            skq_warm_samples.push(t.elapsed());
        }

        let ours_s = Summary::of(&our_samples);
        let zuo_warm = Summary::of(&zuo_warm_samples);
        let skq_warm = Summary::of(&skq_warm_samples);

        eprintln!(
            "  width {:>2}%  cover {cover_size:>3}  ours {} ms  zuo cold {} ms  warm {} ms",
            self.pct,
            stats::as_ms(ours_s.median_ns),
            stats::as_ms(zuo_cold.as_nanos()),
            stats::as_ms(zuo_warm.median_ns),
        );

        serde_json::json!({
            "depth": self.depth,
            "domain": self.domain,
            "range_width_pct": self.pct,
            "range": [lo, hi],
            "cover_size": cover_size,
            "pi_range": {
                "search_ns": ours_s,
                "hits": our_hits,
                "destructive": false,
                "cold_equals_warm": true,
                "cold_equals_warm_reason":
                    "Our search does not mutate the index, so there is no cold/warm \
                     distinction to report. Stated so the asymmetry with Zuo'22 is \
                     visible rather than looking like an omission.",
            },
            "dsse_skq": {
                "cold_search_ns": skq_cold.as_nanos(),
                "warm_search_ns": skq_warm,
                "returned_empty": skq_cold_result.is_none(),
                "destructive": true,
                "several_values_per_document": self.domain > skq_client.width() as u64,
            },
            "zuo22": {
                "cold_search_ns": zuo_cold.as_nanos(),
                "warm_search_ns": zuo_warm,
                "returned_bottom": cold_result.is_none(),
                "destructive": true,
                "destructive_reason":
                    "Algorithm 2's server deletes every entry it walked and writes back \
                     one summary, 'in order to save the server storage'. The first search \
                     is therefore a different measurement from every later one.",
            },
        })
    }
}

/// **Boolean-form latency** — `tab:exp7`'s three query-shape rows.
///
/// ⭐ Ruled in the design record. `thm:bool` shows the *server* cannot
/// tell a conjunction from a disjunction; this is what puts a **number** behind
/// "negation is free", which the transcript test cannot.
///
/// ⚠️ **If the three rows come out near-identical, that is the result**, not a
/// failed measurement — which is exactly why `client_eval_ns` is reported beside
/// the totals. Without it a reader cannot distinguish *"the rows match because
/// the formula never reaches the server"* from *"the harness did not vary
/// anything"*. The evaluation is the only part that differs, so isolating it is
/// what makes the null result readable.
fn boolean_forms(client: &mut XtClient, server: &HonestServer) -> Vec<serde_json::Value> {
    use pqcl_dsse::xt::Formula;

    let forms: [(&str, Formula); 3] = [
        ("w1 AND w2", Formula::conjunction(2)),
        (
            "w1 AND (w2 OR w3)",
            Formula::Or(vec![Formula::Term(0), Formula::Term(1)]),
        ),
        ("w1 AND NOT w2", Formula::Not(Box::new(Formula::Term(0)))),
    ];

    let x_terms: Vec<&[u8]> = vec![b"w2", b"w3"];
    let mut out = Vec::new();

    for (label, formula) in &forms {
        let mut totals = Vec::new();
        let mut evals = Vec::new();
        let mut hits = 0usize;

        for _ in 0..MIN_ITERATIONS {
            let t = Instant::now();
            let Ok(cand) = client.candidates(server, b"w1") else {
                continue;
            };
            let (transcript, map) = client.probe(&cand, &x_terms);
            let bits = pqcl_dsse::XSetStore::probe(server, &transcript);

            // The only part that depends on the formula.
            let te = Instant::now();
            let result = client.evaluate(&cand, x_terms.len(), &map, &bits, formula);
            evals.push(te.elapsed());

            totals.push(t.elapsed());
            hits = result.len();
        }

        if totals.is_empty() {
            continue;
        }
        out.push(serde_json::json!({
            "form": label,
            "rounds": 2,
            "hits": hits,
            "total_ns": Summary::of(&totals),
            "client_eval_ns": Summary::of(&evals),
        }));
    }
    out
}

/// `w_1 ∧ ts∈[t_0,t_1]` — a conjunction whose x-terms are a range cover.
///
/// ⭐ This is what `Π_RANGE` actually is: the range reduces to a disjunction
/// over the cover's prefix keywords, and `Π_BOOL` evaluates that disjunction
/// client-side against the same bit matrix a conjunction would use. So the row
/// measures the composition rather than a third mechanism — which is the claim
/// `Π_RANGE` makes and which nothing had put a number against.
fn conj_range_form(depth: u32, records: usize) -> Option<serde_json::Value> {
    use pqcl_dsse::xt::Formula;

    let tree = RangeTree::new("ts", depth);
    let domain = 1u64 << depth;

    let mut client = XtClient::new(
        Client::new(PrfKey::new([0x73u8; LAMBDA_BYTES])),
        PrfKey::new([0x74u8; LAMBDA_BYTES]),
        BETA,
    );
    let mut server = HonestServer::new();

    for i in 0..records as u64 {
        client.update(&mut server, Op::Add, b"w1", i).ok()?;
        for kw in tree.index_keywords(i % domain) {
            client.update(&mut server, Op::Add, &kw, i).ok()?;
        }
    }
    client.flush(&mut server);
    client.close_epoch(&mut server);

    // A tenth of the domain, so the cover is several prefixes rather than one.
    let cover = tree.cover_keywords(0, domain / 10);
    if cover.is_empty() {
        return None;
    }
    let x_terms: Vec<&[u8]> = cover.iter().map(Vec::as_slice).collect();
    let formula = Formula::Or((0..x_terms.len()).map(Formula::Term).collect());

    let mut totals = Vec::new();
    let mut evals = Vec::new();
    let mut hits = 0usize;
    for _ in 0..MIN_ITERATIONS {
        let t = Instant::now();
        let cand = client.candidates(&server, b"w1").ok()?;
        let (transcript, map) = client.probe(&cand, &x_terms);
        let bits = pqcl_dsse::XSetStore::probe(&server, &transcript);
        let te = Instant::now();
        let result = client.evaluate(&cand, x_terms.len(), &map, &bits, &formula);
        evals.push(te.elapsed());
        totals.push(t.elapsed());
        hits = result.len();
    }

    Some(serde_json::json!({
        "form": "w1 AND range",
        "rounds": 2,
        "hits": hits,
        "cover_size": x_terms.len(),
        "total_ns": Summary::of(&totals),
        "client_eval_ns": Summary::of(&evals),
    }))
}

/// `tab:exp-range`'s query-shape rows for `DSSE_SKQ`, on the same fixture as ours.
///
/// Every form is §4.2's: the client decrypts each keyword's bitmap, combines them,
/// and ANDs with the range result. So every row is defined. Cold and warm are apart,
/// since the first search of a form compacts its chains.
///
/// ⚠️ Each form searches **its own copy** of the index. The first three share their
/// labels, so on one index the second and third would time chains the first had
/// already compacted, and their `cold` would be warm.
///
/// # Errors
///
/// A form whose hits differ from what the fixture's definition gives.
#[allow(clippy::items_after_statements, clippy::type_complexity)] // a local table
fn skq_forms(records: usize) -> Result<Vec<serde_json::Value>, String> {
    let mut client = skq::Client::setup([0x76u8; 32], records, &[1u64 << N_AXIS_DEPTH]);
    let mut base = skq::Edb::default();
    let domain = 1u64 << N_AXIS_DEPTH;
    for i in 0..records {
        let id = i as u64;
        let mut words: Vec<&[u8]> = vec![b"w1"];
        if id.is_multiple_of(2) {
            words.push(b"w2");
        }
        if id.is_multiple_of(3) {
            words.push(b"w3");
        }
        base.apply(client.update(
            &[(0, id % domain)],
            &words,
            &skq::BitString::insert_delta(records, i),
        ));
    }

    type Combine = fn(&skq::BitString, &[skq::BitString]) -> skq::BitString;
    // ⭐ The same term multiset as ours in every form: `boolean_forms` probes w2 and
    // w3 under every formula, so its first row is the three-term conjunction whatever
    // its label says. Comparing a two-term conjunction with it would be two queries.
    let three: Vec<&[u8]> = vec![b"w1", b"w2", b"w3"];
    let forms: [(&str, Option<(usize, u64, u64)>, Vec<&[u8]>, Combine); 4] = [
        ("w1 AND w2", None, three.clone(), |_, b| {
            skq::and(&b[0], &skq::and(&b[1], &b[2]))
        }),
        ("w1 AND (w2 OR w3)", None, three.clone(), |_, b| {
            skq::and(&b[0], &skq::or(&b[1], &b[2]))
        }),
        ("w1 AND NOT w2", None, three, |_, b| {
            skq::and(&b[0], &skq::not(&b[1]))
        }),
        (
            "w1 AND range",
            Some((0, 0, domain / 10)),
            vec![b"w1"],
            |r, b| skq::and(r, &b[0]),
        ),
    ];

    let mut out = Vec::new();
    for (label, range, words, combine) in forms {
        let mut edb = base.clone();
        let in_form = |i: u64| match label {
            "w1 AND w2" => i.is_multiple_of(6),
            "w1 AND (w2 OR w3)" => i.is_multiple_of(2) || i.is_multiple_of(3),
            "w1 AND NOT w2" => !i.is_multiple_of(2),
            _ => i % domain <= domain / 10,
        };
        let want = (0..records as u64).filter(|i| in_form(*i)).count();
        let once = |edb: &mut skq::Edb| -> Result<(usize, std::time::Duration, std::time::Duration), String> {
            let t = Instant::now();
            let token = client
                .search_token(range, &words)
                .ok_or_else(|| format!("{label}: a label was never updated"))?;
            let reply = skq::server_search(edb, &token, records);
            let (br, bw) = client.decrypt(&token, &reply);
            let te = Instant::now();
            let result = combine(&br, &bw);
            let eval = te.elapsed();
            let total = t.elapsed();
            Ok((result.files().len(), total, eval))
        };
        let (hits, cold, _) = once(&mut edb)?;
        if hits != want {
            return Err(format!(
                "DSSE_SKQ {label}: {hits} hits, the fixture gives {want}"
            ));
        }
        let (mut totals, mut evals) = (Vec::new(), Vec::new());
        for _ in 0..MIN_ITERATIONS {
            let (_, total, eval) = once(&mut edb)?;
            totals.push(total);
            evals.push(eval);
        }
        out.push(serde_json::json!({
            "form": label,
            "rounds": 1,
            "hits": hits,
            "cold_total_ns": cold.as_nanos(),
            "warm_total_ns": Summary::of(&totals),
            "client_eval_ns": Summary::of(&evals),
        }));
    }
    Ok(out)
}

/// The Boolean half of `tab:exp7`. A keyword fixture rather than the range
/// index: the three rows compare *query shapes* over the same term multiset,
/// which is the comparison `thm:bool` is about.
fn boolean_rows(records: usize) -> Result<Vec<serde_json::Value>, Box<dyn core::error::Error>> {
    let mut bool_client = XtClient::new(
        Client::new(PrfKey::new([0x71u8; LAMBDA_BYTES])),
        PrfKey::new([0x72u8; LAMBDA_BYTES]),
        BETA,
    );
    let mut bool_server = HonestServer::new();
    for id in 0..records as u64 {
        bool_client.update(&mut bool_server, Op::Add, b"w1", id)?;
        if id.is_multiple_of(2) {
            bool_client.update(&mut bool_server, Op::Add, b"w2", id)?;
        }
        if id.is_multiple_of(3) {
            bool_client.update(&mut bool_server, Op::Add, b"w3", id)?;
        }
    }
    bool_client.flush(&mut bool_server);
    bool_client.close_epoch(&mut bool_server);
    let mut boolean = boolean_forms(&mut bool_client, &bool_server);
    if let Some(row) = conj_range_form(N_AXIS_DEPTH, records) {
        boolean.push(row);
    }
    Ok(boolean)
}

/// MDRSSE over one axis point's `(value, document)` points, built once.
struct Mdrsse {
    client: mdrsse::Client,
    server: mdrsse::Server,
    build_s: f64,
}

/// `values[i]` belongs to document `i mod records`, as for every other arm.
fn build_mdrsse(values: &[u64], records: usize) -> Result<Mdrsse, Box<dyn core::error::Error>> {
    let points: Vec<mdrsse::Point> = values
        .iter()
        .enumerate()
        .map(|(i, v)| (*v, (i % records) as u64))
        .collect();
    let t = Instant::now();
    let (client, server) = mdrsse::setup(&points, &[0x7D; 32], mdrsse::GAMMA, true)
        .map_err(|_| "MDRSSE setup: AES-GCM failed")?;
    Ok(Mdrsse {
        client,
        server,
        build_s: t.elapsed().as_secs_f64(),
    })
}

impl Mdrsse {
    /// The same range as the row `exp7` just measured, checked against the plaintext
    /// answer and against our hit count before it is timed. Static and
    /// non-destructive, so there is no cold/warm split.
    fn measure(
        &self,
        values: &[u64],
        records: usize,
        row: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let lo = row["range"][0].as_u64().ok_or("row has no range")?;
        let hi = row["range"][1].as_u64().ok_or("row has no range")?;
        let want: std::collections::BTreeSet<u64> = values
            .iter()
            .enumerate()
            .filter(|(_, v)| (lo..=hi).contains(*v))
            .map(|(i, _)| (i % records) as u64)
            .collect();
        if row["pi_range"]["hits"].as_u64() != Some(want.len() as u64) {
            return Err(format!(
                "Pi_RANGE's hits differ from the oracle on [{lo}, {hi}]"
            ));
        }
        let got = self.client.search(&self.server, lo, hi);
        if got != want {
            return Err(format!("MDRSSE disagrees with the oracle on [{lo}, {hi}]"));
        }
        let mut samples = Vec::new();
        let mut leaves = 0;
        for _ in 0..MIN_ITERATIONS {
            let t = Instant::now();
            let token = self.client.token(lo, hi);
            let er = self.server.search(&token);
            let found = self.client.decrypt(&token, &er);
            samples.push(t.elapsed());
            leaves = token.leaves();
            core::hint::black_box(found);
        }
        let (ciphertexts, bytes) = self.server.stored();
        Ok(serde_json::json!({
            "search_ns": Summary::of(&samples),
            "hits": want.len(),
            "leaves_in_cover": leaves,
            "leaves_total": self.client.leaves(),
            "gamma": mdrsse::GAMMA,
            "padded": true,
            "stored_ciphertexts": ciphertexts,
            "stored_bytes": bytes,
            "build_s": self.build_s,
            "rounds": 1,
            "static": true,
            "destructive": false,
        }))
    }
}

/// Seed for SDSSE's key refreshes on the conjunction row.
const SDSSE_RNG_SEED: u64 = 0x5EED_0414;

/// ⭐ M15/c15: SDSSE-CQ and -S on `tab:exp-range`'s first row, `w1 AND w2 AND w3`,
/// over the fixture `boolean_rows` builds for ours (w1 on every document, w2 on the
/// even ones, w3 on multiples of three) and the same three terms.
///
/// First and repeat are apart (Aura's cache), with SDSSE's rollback rule. `hits` is
/// emitted beside `want` (§1db.6 (a)): a Bloom false positive may lose a hit, never
/// add one, so only `hits > want` refuses.
///
/// # Errors
///
/// A result above the fixture's answer.
fn sdsse_conjunction(records: usize) -> Result<Vec<serde_json::Value>, String> {
    use rand::SeedableRng as _;
    let want = (0..records as u64).filter(|i| i.is_multiple_of(6)).count();
    let mut out = Vec::new();
    for variant in [sdsse::Variant::Cq, sdsse::Variant::CqS] {
        let mut rng = rand::rngs::StdRng::seed_from_u64(SDSSE_RNG_SEED);
        let mut c = sdsse::Client::setup(variant, &[0x74; 32], std::collections::HashMap::new());
        let mut s = sdsse::Server::default();
        for id in 0..records as u64 {
            c.update(&mut s, Op::Add, b"w1", id, &mut rng);
            if id.is_multiple_of(2) {
                c.update(&mut s, Op::Add, b"w2", id, &mut rng);
            }
            if id.is_multiple_of(3) {
                c.update(&mut s, Op::Add, b"w3", id, &mut rng);
            }
        }
        let q: Vec<Vec<u8>> = vec![b"w1".to_vec(), b"w2".to_vec(), b"w3".to_vec()];
        let terms = c.order_terms(&q);
        let (mut first, mut repeat) = (Vec::new(), Vec::new());
        let mut hits = 0;
        for i in 0..MIN_ITERATIONS {
            let mut rb = c.checkpoint(&terms);
            let t = Instant::now();
            let token = c
                .search_token(&terms, &mut rng)
                .ok_or("an indexed term came back empty")?;
            let res = s.search(&token, &mut rb, None);
            let found = sdsse::Client::finalise(&token, &res);
            first.push(t.elapsed());
            if i == 0 {
                hits = found.len();
            }
            c.rollback(&mut s, rb);
        }
        let mut rb = c.checkpoint(&terms);
        let token = c.search_token(&terms, &mut rng).ok_or("indexed")?;
        let _ = s.search(&token, &mut rb, None);
        for _ in 0..MIN_ITERATIONS {
            let mut spent = sdsse::Rollback::default();
            let t = Instant::now();
            let token = c.search_token(&terms, &mut rng).ok_or("indexed")?;
            let res = s.search(&token, &mut spent, None);
            core::hint::black_box(sdsse::Client::finalise(&token, &res));
            repeat.push(t.elapsed());
        }
        c.rollback(&mut s, rb);
        if hits > want {
            return Err(format!(
                "{}: {hits} hits, the fixture gives {want}",
                variant.name()
            ));
        }
        out.push(serde_json::json!({
            "arm": variant.name(),
            "form": "w1 AND w2",
            "form_is": "w1 AND w2 AND w3, as ours: boolean_forms probes w2 and w3 under every formula",
            "rounds": 1,
            "hits": hits,
            "want": want,
            "first_total_ns": Summary::of(&first),
            "repeat_total_ns": Summary::of(&repeat),
        }));
    }
    Ok(out)
}

#[allow(clippy::too_many_lines)] // the axes, then one JSON record
fn main() -> Result<(), Box<dyn core::error::Error>> {
    use rand::SeedableRng as _;
    let mut rng = rand::rngs::StdRng::seed_from_u64(ZUO_RNG_SEED);
    let mut rows = Vec::new();
    let mut index_rows = Vec::new();

    for &depth in DEPTHS {
        let domain = 1u64 << depth;
        let tree = RangeTree::new("v", depth);

        // ⛔ Constraint 1: every value in the domain, updated once.
        let values: Vec<u64> = (0..domain).collect();
        eprintln!("depth {depth} — {domain} values, each updated once");

        let (ours, our_server, range_tokens) = build_ours(&tree, &values, RECORDS)?;
        let (zuo_client, mut zuo_edb) = build_zuo(depth, &values, RECORDS, &mut rng);
        let (skq_client, mut skq_edb) = build_skq(depth, &values, RECORDS);
        let md = build_mdrsse(&values, RECORDS)?;

        // ⭐ `tab:exp7`'s `Index (x)` denominator. The 1.00 rows index one
        // token per value; range indexing stores one per prefix on the path, so
        // the ratio is exactly the cover expansion and nothing else. Counted
        // rather than derived from `depth`, because a counted number survives a
        // change to `index_keywords` and a derived one silently does not.
        let keyword_only_tokens = values.len();
        index_rows.push(serde_json::json!({
            "depth": depth,
            "keyword_only_tokens": keyword_only_tokens,
            "range_tokens": range_tokens,
            "index_ratio_milli": range_tokens * 1000 / keyword_only_tokens.max(1),
            // ⚠️ Zuo'22 stores one EDB entry per updated node, against our
            // one token per prefix, so the two counts are the same unit and the
            // ratio is meaningful. Counted, not derived: their update path is
            // theirs and may store more than the obvious one entry.
            "zuo_entries": zuo_edb.len(),
            "zuo_index_ratio_milli": zuo_edb.len() * 1000 / keyword_only_tokens.max(1),
            "skq_entries": skq_edb.len(),
            "skq_index_ratio_milli": skq_edb.len() * 1000 / keyword_only_tokens.max(1),
        }));

        for &pct in RANGE_WIDTH_PCT {
            let cell = Cell {
                tree: &tree,
                depth,
                domain,
                pct,
            };
            let mut row = cell.measure(
                &ours,
                &our_server,
                &zuo_client,
                &mut zuo_edb,
                &skq_client,
                &mut skq_edb,
            );
            row["mdrsse"] = md.measure(&values, RECORDS, &row)?;
            rows.push(row);
        }
    }

    // ⭐ `tab:exp-range` reads "at the median configuration of
    // fig:exp-range": the middle N of the axis, the middle width, the axis
    // depth. Every row of that table is measured there, the Boolean fixture
    // included, so its rows and the figure describe one collection.
    let median_n = pqcl_exp::collection_median();
    eprintln!("boolean forms at the median N = {median_n}");
    let boolean = boolean_rows(median_n)?;
    let skq_boolean = skq_forms(median_n)?;
    for row in &skq_boolean {
        let ours = boolean.iter().find(|r| r["form"] == row["form"]);
        if ours.is_some_and(|r| r["hits"] != row["hits"]) {
            return Err(format!("Pi_BOOL and DSSE_SKQ disagree on {}", row["form"]).into());
        }
    }
    let sdsse_boolean = sdsse_conjunction(median_n)?;
    let n_rows = n_axis_rows(&mut rng)?;

    let measurements = serde_json::json!({
        "rows": rows,
        "n_axis_rows": n_rows,
        "median_configuration": {
            "records": median_n,
            "range_width_pct": RANGE_WIDTH_PCT[RANGE_WIDTH_PCT.len() / 2],
            "depth": N_AXIS_DEPTH,
            "boolean_forms_measured_at": median_n,
        },
        "n_axis_note":
            "M10 H5: N swept at fixed depth, never tuned; the crossover is reported \
             wherever it lands. Zuo'22's cost carries an N-bit bitmap per cover node, \
             ours the matching postings.",
        "index_sizes": index_rows,
        "index_note":
            "tab:exp7's Index (x) column. The denominator is the keyword-only              token count -- one per value, which is what the 1.00 rows index --              so the ratio is the range cover's expansion and nothing else.              Counted during the build rather than derived from the depth,              because a counted number survives a change to index_keywords.",
        "boolean_forms": boolean,
        "boolean_forms_dsse_skq": skq_boolean,
        "boolean_forms_sdsse": sdsse_boolean,
        "mdrsse_note": "M15/c15: MDRSSE (Inf. Sci. 652, 2024), one dimension, gamma = 500, padding on, \
             static; built once per depth and per N over the same (value, document) points; the \
             client filters each returned leaf to the range (UPGRADES.md). Its cost is per \
             returned leaf, ours per returned posting.",
        "boolean_note":
            "tab:exp7's query-shape rows. client_eval_ns is reported beside the              totals because if the three forms come out near-identical THAT IS              THE RESULT -- the formula never reaches the server (thm:bool) -- and              without isolating the one stage that does depend on the formula a              reader cannot tell that from a harness that varied nothing.",
        "records": RECORDS,
        "records_note":
            "Both schemes index exactly RECORDS documents. Zuo'22's bitmap width is \
             fixed at that value, so ours must map values onto the same document set \
             or the two are answering queries over different corpora -- which an \
             earlier version of this harness did, giving our side up to 32x more \
             results for the same range.",
        "constraints": {
            "every_value_updated_once": true,
            "every_value_updated_once_reason":
                "Zuo'22 Algorithm 2 lines 5-7 return BOTTOM for the whole query if any \
                 cover node has no history. A sparse workload would let it answer \
                 queries by not answering them -- fast for a reason unrelated to its \
                 design. The authors' own setup updates one time for each value.",
            "cold_and_warm_separated": true,
            "cold_and_warm_separated_reason":
                "Their search compacts the server index, so a repeated query does far \
                 less work. Reporting their warm number against our cold one, or the \
                 reverse, would be a fabricated comparison.",
        },
        "domain_note":
            "Depths are capped at 2^14 because Zuo'22 materialises a bitmap per value in \
             the domain, so the committed 2^32 is not runnable. That is a property of \
             their design and is reported as one, not worked around.",
    });

    emit(
        "exp7-range-latency",
        RunSpec {
            liboqs_version: "n/a: symmetric-only on both sides".to_owned(),
            rng_seeds: vec![0x71, 0x72, 0x73, ZUO_RNG_SEED, SDSSE_RNG_SEED],
            ..RunSpec::default()
        },
        MIN_ITERATIONS,
        measurements,
    )?;

    Ok(())
}
