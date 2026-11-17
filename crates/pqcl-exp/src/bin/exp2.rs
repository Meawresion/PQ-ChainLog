//! **Experiment 2** — conjunctive search latency, `Π_XT` against SDSSE-CQ/-S,
//! VCFB and the Doris follow-up (ODXT only with `PQCL_EXP2_ODXT=1`).
//!
//! ⭐ **Two passes**: `PQCL_EXP2_PASS=main`
//! (the default) is ours, SDSSE-CQ/-S and VCFB at every tier, one record;
//! `PQCL_EXP2_PASS=doris-fu` is the Doris follow-up alone, one record per tier
//! (`m15-doris-fu-search`). `mkfigs` merges them, refusing a different commit,
//! instance type or query set. The sections below predate the split and still
//! hold for the main pass.
//!
//! The paper's headline comparison, and the one a reviewer attacks first.
//!
//! # The constraint that shapes the whole workload
//!
//! ⛔ **Deletions are document-granular.** ODXT registers a deletion only when
//! it appears in the *s-term's* update list, and its update rule assumes
//! document-level deletion — an edited file is re-inserted under a fresh
//! identifier (NDSS'21 §III-C fn. 3). Our schemes delete individual
//! keyword/document pairs. A workload exercising that finer granularity would
//! make ODXT return **stale matches**, and we would be measuring a defect our
//! own workload had manufactured: a strawman in *our* favour.
//!
//! So this deletes whole documents throughout, forgoing a capability advantage
//! we hold. `baselines/UPGRADES.md` records the finding and
//! `baselines/odxt/tests/against_oracle.rs` pins the behaviour.
//!
//! # What is compared, and what is not
//!
//! ⚠️ **Rust against Rust, on one host.** Both schemes are reimplementations in
//! this workspace using the same primitives. Nothing from the Python Doris
//! stack appears in any latency figure — plan §5.
//!
//! ⚠️ **Cryptographic search latency, no chain round-trip.** Anchoring is
//! Experiment 6's subject; including it here would bury a microsecond-scale
//! comparison under a block interval.
//!
//! # The honest caveat this experiment must not obscure
//!
//! We lose **asymptotically** to fp-GA-ODXT — `O(n + c_w1)` in one round
//! against our `O(a_w1 + n_w1·n·E)` in two. We win on the constant factor: a
//! keyed hash against an isogeny group action. ⛔ Never let a favourable
//! wall-clock number here be written up as an asymptotic win.
//!
//! # Running it
//!
//! ```text
//! PQCL_ENRON=datasets/enron/maildir \
//!   cargo run --release -p pqcl-exp --bin exp2
//! ```

use std::collections::BTreeSet;
use std::time::Instant;

use baseline_doris_fu::search as dfu;
use baseline_odxt as odxt;
use baseline_sdsse_cq as sdsse;
use baseline_vcfb as vcfb;
use pqcl_bench::{MIN_ITERATIONS, RunSpec};
// `Op` is `pqcl_dsse`'s own type; ODXT imports the same one rather than
// defining a parallel enum, so a single value drives both schemes and they
// cannot disagree about what a deletion is.
use pqcl_dsse::core::{Client, Op};
use pqcl_dsse::xt::{Formula, HonestServer, XtClient};
use pqcl_exp::{corpus, emit, stats::Summary};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

/// Corpus tiers, in documents.
///
/// ⭐ `n` and `E` are swept **independently** (plan §500): our probe cost is
/// `O(a_w1 + n_w1·n·E)`, so the product is what grows and a single combined
/// sweep cannot say which factor is responsible. This binary sweeps `n`; the
/// `E` factor is Experiment 4's subject and is held at one closed epoch here.
///
/// M10 H3: `PQCL_EXP2_TIERS` extends the sweep to the largest tier the
/// instance can hold — the campaign sets it from measured memory per pair.
/// These are the defaults; every tier is recorded with its pair count.
const DOC_TIERS: &[usize] = &[1_000, 5_000, 20_000];

fn doc_tiers() -> Vec<usize> {
    std::env::var("PQCL_EXP2_TIERS").map_or_else(
        |_| DOC_TIERS.to_vec(),
        |s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
    )
}

/// Conjunction widths to measure. Two is the common case; six shows whether
/// cost grows in the number of x-terms as the construction predicts.
const CONJUNCTION_WIDTHS: &[usize] = &[2, 3, 6];

/// Fraction of documents deleted, at document granularity. Roughly ODXT's own
/// evaluation shape, and enough that deletion filtering is actually exercised.
const DELETE_FRACTION: usize = 10;

/// Cross-tag upload batch size.
const BETA: usize = 256;

/// ⭐ **The epoch size, in documents** (M13 A21). Fixed, so it does not grow
/// with the case: a 20 000-document tier closes 20 epochs, a 1 000-document
/// tier closes one. `Δ` in the registration is a period in seconds; this is its
/// ingest-side expression for a harness with no clock.
///
/// ⚠️ Changing it changes what every row of `tab:exp2` measures.
const DELTA_DOCS: usize = 1_000;

/// Seed of the corpus permutation behind the nested tiers (§1aa.4).
const CORPUS_SEED: u64 = 0x0E2_C0A9;

/// Queries per measured tier. Each is timed `MIN_ITERATIONS` times.
const QUERIES: usize = 12;

/// Build queries that actually match something, by drawing each one's terms
/// from a single document.
///
/// ⭐ **Queries must return hits, or the experiment measures the wrong thing.**
/// The first version of this function sampled terms at spread-out positions in
/// the frequency ranking. It produced conjunctions of six unrelated words,
/// which in Enron co-occur essentially never — so every width-3 and width-6 row
/// returned **zero** documents and timed a candidate scan followed by an
/// evaluation over an empty result. The interesting half of both schemes' work
/// never ran.
///
/// Drawing all `width` terms from one document guarantees at least that
/// document matches, and it is also the realistic shape: an investigator's
/// conjunction comes from one case, not from six independent draws over the
/// vocabulary.
///
/// ⚠️ Stopwords are still excluded. Terms above `STOPWORD_RANK` in the
/// frequency ranking appear in nearly every document, so an s-term chosen from
/// them makes the candidate set the whole corpus and measures the corpus rather
/// than the scheme.
fn queries(
    docs: &[corpus::Document],
    ranked: &[(String, usize)],
    width: usize,
    count: usize,
) -> Vec<Vec<String>> {
    /// Ranks above this are treated as stopwords.
    const STOPWORD_RANK: usize = 200;

    let rank: std::collections::BTreeMap<&str, usize> = ranked
        .iter()
        .enumerate()
        .map(|(i, (w, _))| (w.as_str(), i))
        .collect();

    let mut out = Vec::new();
    // Spread the source documents through the corpus rather than taking the
    // first `count`, which would all come from one mailbox.
    let stride = (docs.len() / count.max(1)).max(1);

    for d in docs.iter().step_by(stride) {
        if out.len() >= count {
            break;
        }
        let mut terms: Vec<&String> = d
            .keywords
            .iter()
            .filter(|k| rank.get(k.as_str()).is_some_and(|r| *r >= STOPWORD_RANK))
            .collect();
        if terms.len() < width {
            continue;
        }
        // Rarest first, so the s-term selector has a genuinely low-volume
        // option — which is the case the construction is designed for.
        terms.sort_by_key(|k| std::cmp::Reverse(rank.get(k.as_str()).copied().unwrap_or(0)));
        out.push(terms.into_iter().take(width).cloned().collect());
    }
    out
}

/// Build both indexes over the same documents, with the same deletions.
struct Workload {
    docs: Vec<corpus::Document>,
    deleted: BTreeSet<u64>,
}

impl Workload {
    fn build(mut docs: Vec<corpus::Document>) -> Self {
        // ⭐ `id = (e, j)` (draft8 Phase 4 Step 1): document `i` is ingested in
        // epoch `i / DELTA_DOCS`, the epoch `build_ours` has open when it gets
        // there. Π_XT refuses an insertion whose id names another epoch, which is
        // how campaign 08 found the raw corpus index here (`WrongEpoch` at the
        // first document of epoch 1). ODXT and the oracle see the same ids.
        for (i, d) in docs.iter_mut().enumerate() {
            d.id = pqcl_dsse::xt::doc_id((i / DELTA_DOCS) as u64, d.id);
        }
        // Deterministic: every Nth document, so the deletion set is a function
        // of the corpus and the tier, not of a seed nobody recorded.
        let deleted = docs
            .iter()
            .enumerate()
            .filter(|(i, _)| i % DELETE_FRACTION == 0)
            .map(|(_, d)| d.id)
            .collect();
        Self { docs, deleted }
    }

    /// ⛔ Document-granular: every keyword of a deleted document is deleted.
    /// This is the constraint the module docs explain, expressed in one place.
    fn deletions_for(&self, d: &corpus::Document) -> bool {
        self.deleted.contains(&d.id)
    }
}

fn build_ours(w: &Workload) -> Result<(XtClient, HonestServer), pqcl_dsse::xt::XtUpdateError> {
    let core = Client::new(PrfKey::new([0x21u8; LAMBDA_BYTES]));
    let mut client = XtClient::new(core, PrfKey::new([0x22u8; LAMBDA_BYTES]), BETA);
    let mut server = HonestServer::new();

    // ⭐ **Δ-bounded epochs** (M13 A21): an epoch closes every `DELTA_DOCS`
    // documents, so the epoch size is **fixed** and the number of epochs grows
    // with the case. Holding the whole corpus in one epoch, as this harness did
    // before, models an epoch that grows with the case — the exact shape A21
    // takes off the chain, so measuring search against it would have been
    // measuring a configuration the system no longer anchors.
    //
    // Under D3 a candidate is probed **once, under its own epoch's key**, so
    // the probe count does not depend on how many epochs there are. That is
    // what this workload now puts to the test rather than assuming.
    let mut since_close = 0usize;
    for d in &w.docs {
        for k in &d.keywords {
            client.update(&mut server, Op::Add, k.as_bytes(), d.id)?;
        }
        since_close += 1;
        if since_close == DELTA_DOCS {
            client.flush(&mut server);
            client.close_epoch(&mut server);
            since_close = 0;
        }
    }
    for d in &w.docs {
        if w.deletions_for(d) {
            for k in &d.keywords {
                client.update(&mut server, Op::Del, k.as_bytes(), d.id)?;
            }
        }
    }

    // The tail. At least one epoch must be closed either way: the open epoch is
    // never probed (forward privacy), so without closing one there is nothing
    // to search and the measurement would be of an empty probe list.
    client.flush(&mut server);
    client.close_epoch(&mut server);
    Ok((client, server))
}

fn build_odxt(w: &Workload) -> (odxt::SecretKey, odxt::ClientState, odxt::Edb) {
    let sk = odxt::SecretKey::from_bytes(&[0x33u8; 128]);
    let mut st = odxt::ClientState::default();
    let mut edb = odxt::Edb::new();

    for d in &w.docs {
        for k in &d.keywords {
            let t = odxt::update(&sk, &mut st, Op::Add, d.id, k.as_bytes());
            edb.apply(&t);
        }
    }
    for d in &w.docs {
        if w.deletions_for(d) {
            for k in &d.keywords {
                let t = odxt::update(&sk, &mut st, Op::Del, d.id, k.as_bytes());
                edb.apply(&t);
            }
        }
    }
    (sk, st, edb)
}

/// One timed search on our scheme: candidates, probe, evaluate. Returns the set
/// `evaluate` already built; the timed callers take its length in the same
/// statement, so the work timed is what it was before c15 (M15: the oracle check
/// needs the set now that ODXT is not re-run).
fn search_ours(client: &mut XtClient, server: &HonestServer, q: &[String]) -> BTreeSet<u64> {
    let terms: Vec<&[u8]> = q.iter().map(String::as_bytes).collect();
    let Some(s_idx) = client.select_s_term(&terms) else {
        return BTreeSet::new();
    };
    let Ok(candidates) = client.candidates(server, terms[s_idx]) else {
        return BTreeSet::new();
    };
    let x_terms: Vec<&[u8]> = terms
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != s_idx)
        .map(|(_, t)| t)
        .copied()
        .collect();

    let (transcript, map) = client.probe(&candidates, &x_terms);
    let bits = pqcl_dsse::xt::XSetStore::probe(server, &transcript);
    client.evaluate(
        &candidates,
        x_terms.len(),
        &map,
        &bits,
        &Formula::conjunction(x_terms.len()),
    )
}

/// Seed for ODXT's search-token permutation. Fixed and recorded, so a run is
/// repeatable without the permutation cost being removed from the measurement.
const ODXT_RNG_SEED: u64 = 0x5EED_0002;

/// Everything ODXT needs to answer a query.
struct OdxtCtx {
    sk: odxt::SecretKey,
    st: odxt::ClientState,
    edb: odxt::Edb,
}

/// One cell's measurements: **one median per query**, not a pooled sample set.
struct Cell {
    ours: Vec<std::time::Duration>,
    odxt: Vec<std::time::Duration>,
    our_hits: usize,
    odxt_hits: usize,
    /// `Π_CD` (§1q.3's third series): per-query medians and hits.
    cd: Vec<std::time::Duration>,
    cd_hits: usize,
}

/// Time every query `MIN_ITERATIONS` times and reduce each to its own median.
///
/// ⭐ **Per-query medians, then a summary over those — not one pooled pile of
/// samples.** Pooling was the first version and it made the IQR meaningless:
/// queries have genuinely different s-term volumes, so a pooled spread measures
/// *how much queries differ from each other*, which a reader will misread as
/// measurement precision. It showed an IQR larger than the median while the
/// underlying timings were perfectly stable.
///
/// Reducing each query to its median first removes per-iteration noise; the
/// summary over those medians then honestly answers "how much does query cost
/// vary across this workload", which is the quantity the paper wants.
fn measure(
    ours: &mut XtClient,
    our_server: &HonestServer,
    odxt_ctx: Option<&OdxtCtx>,
    qs: &[Vec<String>],
    rng: &mut impl rand::Rng,
) -> Result<Cell, pqcl_dsse::core::SearchError> {
    let mut cell = Cell {
        ours: Vec::new(),
        odxt: Vec::new(),
        our_hits: 0,
        odxt_hits: 0,
        cd: Vec::new(),
        cd_hits: 0,
    };

    for q in qs {
        let terms: Vec<Vec<u8>> = q.iter().map(|s| s.as_bytes().to_vec()).collect();
        let mut our_iters = Vec::new();
        let mut odxt_iters = Vec::new();
        let mut cd_iters = Vec::new();
        let term_refs: Vec<&[u8]> = terms.iter().map(Vec::as_slice).collect();

        for i in 0..MIN_ITERATIONS {
            let t0 = Instant::now();
            let hits = search_ours(ours, our_server, q).len();
            our_iters.push(t0.elapsed());
            if i == 0 {
                cell.our_hits += hits;
            }

            // The RNG is inside the timed region on purpose: Fig. 9 step 5(e)
            // permutes the cross-tokens, so drawing that permutation is part of
            // ODXT's search cost. Excluding it would flatter ODXT by removing
            // work its own construction requires.
            if let Some(o) = odxt_ctx {
                let t1 = Instant::now();
                let found = odxt::search(&o.sk, &o.st, &o.edb, &terms, rng);
                odxt_iters.push(t1.elapsed());
                if i == 0 {
                    cell.odxt_hits += found.len();
                }
            }

            // Π_CD over the same client and server: one Π_core search per
            // conjunct, intersected by the client.
            let t2 = Instant::now();
            // An honest server's responses verify; a failure is a finding.
            let cd = pqcl_dsse::cd_search(&ours.core, our_server, &term_refs)?;
            cd_iters.push(t2.elapsed());
            if i == 0 {
                cell.cd_hits += cd.len();
            }
        }

        cell.ours.push(std::time::Duration::from_nanos(
            u64::try_from(Summary::of(&our_iters).median_ns).unwrap_or(u64::MAX),
        ));
        if !odxt_iters.is_empty() {
            cell.odxt.push(std::time::Duration::from_nanos(
                u64::try_from(Summary::of(&odxt_iters).median_ns).unwrap_or(u64::MAX),
            ));
        }
        cell.cd.push(std::time::Duration::from_nanos(
            u64::try_from(Summary::of(&cd_iters).median_ns).unwrap_or(u64::MAX),
        ));
    }

    Ok(cell)
}

/// One `rows` entry: the cross-checks, then the three schemes' summaries.
#[allow(clippy::too_many_arguments)]
fn row(
    tier: usize,
    pairs: usize,
    width: usize,
    queries: usize,
    ours: &XtClient,
    our_server: &HonestServer,
    odxt_ctx: Option<&OdxtCtx>,
    m: Cell,
) -> serde_json::Value {
    let (our_samples, odxt_samples, cd_samples) = (m.ours, m.odxt, m.cd);
    let (our_results, odxt_results) = (m.our_hits, m.odxt_hits);
    assert_eq!(
        our_results, m.cd_hits,
        "Π_XT and Π_CD disagree at {tier} docs, width {width}: no timing below \
         is meaningful until that is resolved"
    );

    // ⭐ A free correctness cross-check, and the strongest one available
    // here: two independently written schemes over the same workload
    // must return the same documents. A latency comparison between a
    // correct scheme and a broken one is meaningless, so this is
    // asserted rather than merely recorded.
    if odxt_ctx.is_some() {
        assert_eq!(
            our_results, odxt_results,
            "Π_XT and ODXT disagree at {tier} docs, width {width}: {our_results} vs \
             {odxt_results} hits. One of them is wrong, and no timing below is meaningful \
             until that is resolved."
        );
    }

    // ⚠️ Zero-hit queries measure a candidate scan, not a search. They
    // are not fatal — some rows legitimately match nothing — but a row
    // of them means the query selector is broken, as it once was.
    if our_results == 0 {
        eprintln!(
            "  ⚠️  width {width} at {tier} docs matched nothing: this row times an \
             empty search"
        );
    }

    let mut row = serde_json::json!({
        "documents": tier,
        "pairs": pairs,
        "conjunction_width": width,
        "queries": queries,
        "closed_epochs": ours.closed_epochs(),
        "epoch_size_docs": DELTA_DOCS,
        "epochs_are": "Δ-bounded (M13 A21): one epoch per DELTA_DOCS documents, so the epoch size does not grow with the case and the epoch count does",
        // Each summary is over one median per query, so its spread is
        // query-to-query variation rather than per-iteration noise.
        "summary_over": "per-query medians",
        "iterations_per_query": MIN_ITERATIONS,
        "pi_xt": {
            "search_ns": Summary::of(&our_samples),
            "rounds": 2,
            "total_hits_first_iteration": our_results,
            "xtag_count": pqcl_dsse::xt::XSetStore::xtag_count(our_server),
        },
        "pi_cd": {
            "search_ns": Summary::of(&cd_samples),
            "rounds": 1,
            "total_hits_first_iteration": m.cd_hits,
        },
    });
    if let Some(o) = odxt_ctx {
        row["odxt"] = serde_json::json!({
            "search_ns": Summary::of(&odxt_samples),
            "rounds": 1,
            "total_hits_first_iteration": odxt_results,
            "tset_len": o.edb.tset_len(),
            "xset_len": o.edb.xset_len(),
        });
    }
    row
}

/// Seed for SDSSE's key refreshes, in the timed region as ODXT's RNG is.
const SDSSE_RNG_SEED: u64 = 0x5EED_0014;

/// ⭐ §1cs.5 item 3: both arms, one arm per build. An SDSSE entry is about 1 KB
/// over `TSet` and `XSet`, so they are never held at once beside ours.
const SDSSE_ARMS: [sdsse::Variant; 2] = [sdsse::Variant::Cq, sdsse::Variant::CqS];

/// Build one SDSSE arm over the same documents and deletions as the others.
///
/// Each keyword's Bloom filter is sized for its own deletion count, the kindest
/// setting there is (§1cu.2): a real client cannot know it in advance.
fn build_sdsse(
    w: &Workload,
    variant: sdsse::Variant,
    rng: &mut impl rand::Rng,
) -> (sdsse::Client, sdsse::Server) {
    let mut deletions: std::collections::HashMap<Vec<u8>, usize> = std::collections::HashMap::new();
    for d in &w.docs {
        if w.deletions_for(d) {
            for k in &d.keywords {
                *deletions.entry(k.as_bytes().to_vec()).or_insert(0) += 1;
            }
        }
    }
    let mut client = sdsse::Client::setup(variant, &[0x2D; 32], deletions);
    let mut server = sdsse::Server::default();
    for d in &w.docs {
        for k in &d.keywords {
            client.update(&mut server, Op::Add, k.as_bytes(), d.id, rng);
        }
    }
    for d in &w.docs {
        if w.deletions_for(d) {
            for k in &d.keywords {
                client.update(&mut server, Op::Del, k.as_bytes(), d.id, rng);
            }
        }
    }
    (client, server)
}

/// The plaintext answer to each query, from the documents directly.
fn oracle(w: &Workload, qs: &[Vec<String>]) -> Vec<BTreeSet<u64>> {
    let wanted: std::collections::HashSet<&str> = qs.iter().flatten().map(String::as_str).collect();
    let mut inv: std::collections::HashMap<&str, BTreeSet<u64>> = std::collections::HashMap::new();
    for d in &w.docs {
        if w.deletions_for(d) {
            continue;
        }
        for k in &d.keywords {
            if wanted.contains(k.as_str()) {
                inv.entry(k.as_str()).or_default().insert(d.id);
            }
        }
    }
    qs.iter()
        .map(|q| {
            q.iter()
                .map(|t| inv.get(t.as_str()).cloned().unwrap_or_default())
                .reduce(|a, b| a.intersection(&b).copied().collect())
                .unwrap_or_default()
        })
        .collect()
}

/// One SDSSE arm over one query set: **first and repeat kept apart** (§1cu.2).
///
/// A first search decrypts the keyword's entries and moves them to the server's
/// cache, and a later search reads the cache, so ten iterations of one search
/// would time the cache nine times. So each timed **first** search is rolled back
/// outside the timed region, leaving every query first-seen for the next
/// iteration and the next query. Then, without rolling back, the repeat is timed.
///
/// # Errors
///
/// A result the oracle does not have. A **missing** result is a Bloom false
/// positive, which the scheme allows at rate `p`: it is counted and recorded.
fn measure_sdsse(
    client: &mut sdsse::Client,
    server: &mut sdsse::Server,
    qs: &[Vec<String>],
    want: &[BTreeSet<u64>],
    rng: &mut impl rand::Rng,
) -> Result<serde_json::Value, String> {
    let (mut first, mut repeat, mut wire) = (Vec::new(), Vec::new(), Vec::new());
    let (mut hits, mut shortfall) = (0usize, 0usize);
    let mut volumes = Vec::new();
    for (q, oracle_set) in qs.iter().zip(want) {
        let qb: Vec<Vec<u8>> = q.iter().map(|s| s.as_bytes().to_vec()).collect();
        let terms = client.order_terms(&qb);
        volumes.push(
            terms
                .iter()
                .map(|t| client.counter(t).map_or(0, |c| c + 1))
                .collect::<Vec<u64>>(),
        );

        let mut iters = Vec::new();
        for i in 0..MIN_ITERATIONS {
            let mut rb = client.checkpoint(&terms);
            let t0 = Instant::now();
            let Some(token) = client.search_token(&terms, rng) else {
                return Err(format!("an indexed query came back empty: {q:?}"));
            };
            let res = server.search(&token, &mut rb, None);
            let found = sdsse::Client::finalise(&token, &res);
            iters.push(t0.elapsed());
            if i == 0 {
                wire.push(token.wire_bytes_up() as u64);
                if let Some(extra) = found.difference(oracle_set).next() {
                    return Err(format!("{q:?} returned {extra}, which the oracle lacks"));
                }
                hits += found.len();
                shortfall += oracle_set.difference(&found).count();
            }
            client.rollback(server, rb);
        }
        first.push(std::time::Duration::from_nanos(
            u64::try_from(Summary::of(&iters).median_ns).unwrap_or(u64::MAX),
        ));

        // One real first search, kept, then the repeats, then undo the lot.
        let mut rb = client.checkpoint(&terms);
        let Some(token) = client.search_token(&terms, rng) else {
            return Err(format!("an indexed query came back empty: {q:?}"));
        };
        let _ = server.search(&token, &mut rb, None);
        let mut iters = Vec::new();
        for _ in 0..MIN_ITERATIONS {
            let mut spent = sdsse::Rollback::default();
            let t0 = Instant::now();
            let Some(token) = client.search_token(&terms, rng) else {
                return Err(format!("an indexed query came back empty: {q:?}"));
            };
            let res = server.search(&token, &mut spent, None);
            let found = sdsse::Client::finalise(&token, &res);
            iters.push(t0.elapsed());
            core::hint::black_box(found);
        }
        repeat.push(std::time::Duration::from_nanos(
            u64::try_from(Summary::of(&iters).median_ns).unwrap_or(u64::MAX),
        ));
        client.rollback(server, rb);
    }
    let (t_entries, x_entries) = server.entries();
    let (t_bytes, x_bytes) = server.stored_bytes();
    Ok(serde_json::json!({
        "first_search_ns": Summary::of(&first),
        "repeat_search_ns": Summary::of(&repeat),
        "rounds": 1,
        "total_hits_first_iteration": hits,
        "oracle_shortfall_bloom_false_positives": shortfall,
        "wire_bytes_up_per_query": wire,
        "term_updates_per_query": volumes,
        "term_updates_are": "updates per term with the s-term first: the search fetches every xtag of the x-terms, so cost grows with them (their Fig. 3)",
        "tset_entries": t_entries,
        "xset_entries": x_entries,
        "tset_stored_bytes": t_bytes,
        "xset_stored_bytes": x_bytes,
        "client_bytes": client.client_bytes(),
    }))
}

/// `PQCL_EXP2_ODXT=1` re-runs ODXT. Off by default since c15: its macros were
/// retired, and the plan for c15 does not re-run it.
fn odxt_enabled() -> bool {
    std::env::var("PQCL_EXP2_ODXT").is_ok_and(|v| v == "1")
}

/// The `rows` entry for one tier and width, which ours has already written.
fn row_at(
    rows: &mut [serde_json::Value],
    tier: usize,
    width: usize,
) -> Result<&mut serde_json::Value, String> {
    rows.iter_mut()
        .find(|r| r["documents"] == tier && r["conjunction_width"] == width)
        .ok_or_else(|| format!("no row for {tier} docs, width {width}"))
}

/// VCFB over the same documents and deletions as the other arms (M15).
fn build_vcfb(w: &Workload) -> (vcfb::Client, vcfb::Server) {
    let (mut c, mut s) = vcfb::Client::setup(&[0x2B; 32]);
    for d in &w.docs {
        for k in &d.keywords {
            s.apply(&c.update(k.as_bytes(), d.id, Op::Add));
        }
    }
    for d in &w.docs {
        if w.deletions_for(d) {
            for k in &d.keywords {
                s.apply(&c.update(k.as_bytes(), d.id, Op::Del));
            }
        }
    }
    (c, s)
}

/// VCFB over one query set, **first and repeat kept apart** (§1db.6 (b)), under
/// SDSSE's rule: each timed first search is rolled back outside the timed region,
/// then one first search is kept and the repeats are timed.
///
/// # Errors
///
/// Any query whose answer differs from the oracle, first or repeat.
fn measure_vcfb(
    c: &mut vcfb::Client,
    s: &mut vcfb::Server,
    qs: &[Vec<String>],
    want: &[BTreeSet<u64>],
) -> Result<serde_json::Value, String> {
    let (mut first, mut repeat, mut wire, mut cands) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut hits = 0usize;
    for (q, oracle_set) in qs.iter().zip(want) {
        let qb: Vec<Vec<u8>> = q.iter().map(|x| x.as_bytes().to_vec()).collect();
        let terms = c.order_terms(&qb);
        let mut iters = Vec::new();
        for i in 0..MIN_ITERATIONS {
            let up = c.up_tag();
            let mut undo = vcfb::Undo::default();
            let t0 = Instant::now();
            let token = c
                .token(&terms)
                .ok_or_else(|| format!("an indexed s-term has no updates: {q:?}"))?;
            let reply = s.search(&token, &mut undo, None);
            let found = c.finalise(&token, &reply);
            iters.push(t0.elapsed());
            if i == 0 {
                if &found != oracle_set {
                    return Err(format!("VCFB disagrees with the oracle on {q:?}"));
                }
                hits += found.len();
                wire.push(token.wire_bytes_up() as u64);
                cands.push(token.candidates() as u64);
            }
            s.undo(undo);
            c.set_up_tag(up);
        }
        first.push(std::time::Duration::from_nanos(
            u64::try_from(Summary::of(&iters).median_ns).unwrap_or(u64::MAX),
        ));
        let up = c.up_tag();
        let token = c.token(&terms).ok_or("indexed")?;
        let mut kept = vcfb::Undo::default();
        let _ = s.search(&token, &mut kept, None);
        let mut iters = Vec::new();
        for _ in 0..MIN_ITERATIONS {
            let mut spent = vcfb::Undo::default();
            let t0 = Instant::now();
            let token = c.token(&terms).ok_or("indexed")?;
            let reply = s.search(&token, &mut spent, None);
            let found = c.finalise(&token, &reply);
            iters.push(t0.elapsed());
            if &found != oracle_set {
                return Err(format!(
                    "VCFB's repeat search disagrees with the oracle on {q:?}"
                ));
            }
        }
        repeat.push(std::time::Duration::from_nanos(
            u64::try_from(Summary::of(&iters).median_ns).unwrap_or(u64::MAX),
        ));
        s.undo(kept);
        c.set_up_tag(up);
    }
    let (t_entries, x_entries) = s.entries();
    Ok(serde_json::json!({
        "first_search_ns": Summary::of(&first),
        "repeat_search_ns": Summary::of(&repeat),
        "first_search_is": "the deferred decoding of every xtag' uploaded since the last search, plus the search",
        "rounds": 1,
        "total_hits_first_iteration": hits,
        "candidates_per_query": cands,
        "wire_bytes_up_per_query": wire,
        "tset_entries": t_entries,
        "xset_entries": x_entries,
        "stored_bytes": s.stored_bytes(),
        "oracle": "every query equal, first and repeat",
    }))
}

/// Seed for the Doris follow-up's fresh `K` per token, in the timed region as
/// ODXT's RNG is.
const DORIS_FU_RNG_SEED: u64 = 0x5EED_0015;

/// ⭐ **The Doris follow-up's stop size in Exp. 2, decided before c15** (user,
/// 2026-11-09, the design record (a)). Its `XSet` holds one tag per
/// (keyword, other keyword) of a document, so it grows with the square of a
/// document's keywords: the M15 smoke stored 1.62 GB at 10³ documents and 2.97 GB at
/// 2·10³ (about 10 kB per pair), and peaked at 6.45 GB. On c15r (r7i.8xlarge,
/// 256 GiB) that admits 5·10⁴ documents (≈ 2.1·10⁹ tags, ≈ 180 GB modelled) and not
/// 10⁵ (≈ 4.2·10⁹ tags: over the filter's 32-bit index and ≈ 360 GB).
const DORIS_FU_MAX_DOCS: usize = 50_000;

/// Modelled peak bytes per tag of the build: the tag vector (32), the filter
/// (`b ≈ 1.125–1.23` slots of 32), the peeling counters and queue (≈ 18). The
/// smoke's 6.45 GB peak over ≈ 8.2·10⁷ tags is ≈ 80 B per tag, so 85 is above it.
const DORIS_FU_PEAK_BYTES_PER_TAG: u64 = 85;

/// The share of the host's memory a Doris build may plan to use.
const DORIS_FU_MEMORY_SHARE: f64 = 0.85;

fn doris_fu_stop_note() -> String {
    format!(
        "run at tiers <= {DORIS_FU_MAX_DOCS} documents whose modelled peak ({DORIS_FU_PEAK_BYTES_PER_TAG} B per tag, \
         tags counted exactly before building) fits {DORIS_FU_MEMORY_SHARE} of MemTotal; a skipped tier \
         records why. Its XSet grows with the square of a document's keywords."
    )
}

fn mem_total_bytes() -> Option<u64> {
    let info = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = info.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

/// Whether the Doris follow-up runs at this tier: `Ok` with what was admitted, or
/// `Err` with the record's reason. `PQCL_EXP2_DORIS_FU_MAX_DOCS` may only lower the
/// stop size (a local smoke sets it below its tiers).
fn doris_fu_admit(
    tier: usize,
    live: &[(u64, Vec<String>)],
) -> Result<serde_json::Value, serde_json::Value> {
    let cap = std::env::var("PQCL_EXP2_DORIS_FU_MAX_DOCS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(DORIS_FU_MAX_DOCS, |v| v.min(DORIS_FU_MAX_DOCS));
    let tags = dfu::xset_tags(live);
    let peak = tags.saturating_mul(DORIS_FU_PEAK_BYTES_PER_TAG);
    let mem = mem_total_bytes();
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let budget = mem.map(|m| (m as f64 * DORIS_FU_MEMORY_SHARE) as u64);
    let reason = if tier > cap {
        Some(format!(
            "stop size: {tier} documents is above {cap}, the largest tier its memory allows (DORIS_FU_MAX_DOCS)"
        ))
    } else if !usize::try_from(tags).is_ok_and(baseline_doris_fu::index_fits) {
        Some(format!(
            "{tags} tags give {} slots, past the filter's 32-bit index",
            usize::try_from(tags).map_or(u64::MAX, |n| baseline_doris_fu::filter_shape(n).0 as u64)
        ))
    } else if budget.is_none_or(|b| peak > b) {
        Some(format!(
            "modelled peak {peak} B exceeds {DORIS_FU_MEMORY_SHARE} of MemTotal ({mem:?} B)"
        ))
    } else {
        None
    };
    let v = serde_json::json!({
        "xset_tags": tags,
        "filter_slots": usize::try_from(tags).ok().map(|n| baseline_doris_fu::filter_shape(n).0),
        "modelled_peak_bytes": peak,
        "mem_total_bytes": mem,
        "stop_documents": cap,
    });
    match reason {
        Some(r) => {
            let mut v = v;
            v["skipped"] = serde_json::json!(true);
            v["reason"] = serde_json::json!(r);
            Err(v)
        }
        None => Ok(v),
    }
}

/// The Doris follow-up over one query set. Static, so there is no first/repeat
/// distinction: every search does the same work.
///
/// # Errors
///
/// Any query whose answer differs from the oracle.
fn measure_doris_fu(
    c: &dfu::Client,
    edb: &dfu::Edb,
    qs: &[Vec<String>],
    want: &[BTreeSet<u64>],
    rng: &mut impl rand::Rng,
) -> Result<serde_json::Value, String> {
    let (mut times, mut cands, mut wire) = (Vec::new(), Vec::new(), Vec::new());
    let mut hits = 0usize;
    for (q, oracle_set) in qs.iter().zip(want) {
        let qb: Vec<&[u8]> = q.iter().map(String::as_bytes).collect();
        let mut iters = Vec::new();
        for i in 0..MIN_ITERATIONS {
            let t0 = Instant::now();
            let (sterm, rest) = c.choose(&qb).ok_or("no terms")?;
            let t = edb.retrieve(&c.stag(sterm));
            let toks = c.xtokens(sterm, &rest, t.len(), rng);
            let res = edb.decide(&t, &toks, None);
            let found = c.decrypt(sterm, &res);
            iters.push(t0.elapsed());
            if i == 0 {
                if &found != oracle_set {
                    return Err(format!(
                        "the Doris follow-up disagrees with the oracle on {q:?}"
                    ));
                }
                hits += found.len();
                cands.push(t.len() as u64);
                wire.push((32 + toks.iter().map(dfu::XToken::wire_bytes).sum::<usize>()) as u64);
            }
        }
        times.push(std::time::Duration::from_nanos(
            u64::try_from(Summary::of(&iters).median_ns).unwrap_or(u64::MAX),
        ));
    }
    Ok(serde_json::json!({
        "search_ns": Summary::of(&times),
        "rounds": 1,
        "static": true,
        "built_over": "the tier's live documents (the post-deletion state the dynamic arms hold)",
        "total_hits_first_iteration": hits,
        "candidates_per_query": cands,
        "wire_bytes_up_per_query": wire,
        "tset_entries": edb.entries(),
        "stored_bytes": edb.stored_bytes(),
        "oracle": "every query equal",
    }))
}

/// The experiment name pass 2 writes. ⚠️ Not `exp2-…`: `figspec._latest("exp2")`
/// takes any `exp2-` record, and a Doris record must never stand in for pass 1's.
const DORIS_FU_EXPERIMENT: &str = "m15-doris-fu-search";

/// Reset this process's peak RSS to its current value (Linux `clear_refs` 5), so
/// each tier's `VmHWM` is that tier's. `false` if the kernel refused.
fn reset_peak_rss() -> bool {
    std::fs::write("/proc/self/clear_refs", "5").is_ok()
}

/// `VmHWM`, the process's peak RSS since the last reset, in bytes.
fn peak_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

/// One Doris follow-up cell per conjunction width.
type DorisCells = std::collections::BTreeMap<usize, serde_json::Value>;

/// The Doris follow-up at one tier: one cell per width, never an `Err` for its own
/// failures. A skip, a peel failure or an oracle mismatch is a cell with its
/// reason; mismatches are also returned, so the pass can exit non-zero after the
/// record is written.
fn doris_tier(
    w: &Workload,
    tier: usize,
    fixed: &std::collections::BTreeMap<usize, Vec<Vec<String>>>,
    rng: &mut impl rand::Rng,
) -> (DorisCells, Vec<String>) {
    let widths: Vec<usize> = CONJUNCTION_WIDTHS
        .iter()
        .copied()
        .filter(|w| fixed.get(w).is_some_and(|q| !q.is_empty()))
        .collect();
    let mut cells = std::collections::BTreeMap::new();
    let mut mismatches = Vec::new();
    let live: Vec<(u64, Vec<String>)> = w
        .docs
        .iter()
        .filter(|d| !w.deletions_for(d))
        .map(|d| (d.id, d.keywords.clone()))
        .collect();
    let admitted = match doris_fu_admit(tier, &live) {
        Err(skip) => {
            eprintln!("  doris-fu: not run at {tier} docs: {}", skip["reason"]);
            for &width in &widths {
                cells.insert(width, skip.clone());
            }
            return (cells, mismatches);
        }
        Ok(a) => a,
    };
    let t0 = Instant::now();
    let Some((dc, dedb)) = dfu::setup(&live, &[0x2C; 32], 0xD0F0) else {
        eprintln!("  doris-fu: the filter did not peel at {tier} docs");
        for &width in &widths {
            cells.insert(
                width,
                serde_json::json!({
                    "error": "the filter did not peel within MAX_ATTEMPTS seeds, or its shape exceeds the 32-bit index",
                    "admission": admitted.clone(),
                }),
            );
        }
        return (cells, mismatches);
    };
    let build_s = t0.elapsed().as_secs_f64();
    eprintln!(
        "  doris-fu: built in {build_s:.1} s, {} B stored",
        dedb.stored_bytes()
    );
    for &width in &widths {
        let qs = fixed.get(&width).cloned().unwrap_or_default();
        let want = oracle(w, &qs);
        let cell = match measure_doris_fu(&dc, &dedb, &qs, &want, rng) {
            Ok(mut cell) => {
                cell["build_s"] = serde_json::json!(build_s);
                cell["admission"] = admitted.clone();
                eprintln!(
                    "    doris-fu width {width}: {} ns",
                    cell["search_ns"]["median_ns"]
                );
                cell
            }
            Err(e) => {
                eprintln!("  ⛔ doris-fu width {width}: {e}");
                mismatches.push(format!("{tier} docs, width {width}: {e}"));
                serde_json::json!({ "oracle_mismatch": e, "admission": admitted.clone() })
            }
        };
        cells.insert(width, cell);
    }
    (cells, mismatches)
}

/// Pass 2: the Doris follow-up alone, **one record per tier** (written as each
/// tier finishes, so a crash at the top tier keeps the lower ones; the campaign
/// also runs one tier per process). An oracle mismatch is written into the record
/// and makes the pass exit non-zero; `mkfigs` refuses to merge such a record.
fn doris_pass() -> Result<(), Box<dyn core::error::Error>> {
    use rand::SeedableRng as _;
    let mut rng = rand::rngs::StdRng::seed_from_u64(DORIS_FU_RNG_SEED);
    let tiers = doc_tiers();
    let q_tier = query_tier(&tiers)?;
    let fixed = fixed_queries(q_tier)?;
    let mut all_mismatches = Vec::new();
    for tier in tiers {
        let reset = reset_peak_rss();
        let docs = corpus::load_nested(tier, CORPUS_SEED)?;
        let selection = corpus::fingerprint(&docs);
        let pairs = corpus::pair_count(&docs);
        let w = Workload::build(docs);
        eprintln!("doris-fu pass, tier {tier} docs, {pairs} pairs");
        let (cells, mismatches) = doris_tier(&w, tier, &fixed, &mut rng);
        let peak = peak_rss_bytes();
        let rows: Vec<serde_json::Value> = cells
            .into_iter()
            .map(|(width, mut cell)| {
                cell["peak_rss_bytes"] = serde_json::json!(peak);
                serde_json::json!({
                    "documents": tier,
                    "pairs": pairs,
                    "conjunction_width": width,
                    "queries": fixed.get(&width).map_or(0, Vec::len),
                    "doris_fu": cell,
                })
            })
            .collect();
        let measurements = serde_json::json!({
            "pass": "doris-fu: pass 2 of exp2, merged into exp2-conjunctive-latency's rows by mkfigs",
            "rows": rows,
            "oracle_mismatch": mismatches,
            "peak_rss_is": "VmHWM of this process over this tier (corpus load, workload, build and search), reset at the tier's start",
            "peak_rss_reset": reset,
            "workload": {
                "corpus_seed": CORPUS_SEED,
                "query_tier": q_tier,
                "queries_by_width": fixed,
                "doris_fu_stop": doris_fu_stop_note(),
                "deletion_granularity": "document; the Doris follow-up is static and built over the tier's live documents",
            },
        });
        emit(
            DORIS_FU_EXPERIMENT,
            RunSpec {
                liboqs_version: "n/a: symmetric-only search path".to_owned(),
                rng_seeds: vec![DORIS_FU_RNG_SEED],
                dataset_checksums: [(format!("enron-selection-{tier}"), selection)].into(),
                ..RunSpec::default()
            },
            MIN_ITERATIONS,
            measurements,
        )?;
        all_mismatches.extend(mismatches);
    }
    if all_mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the Doris follow-up disagreed with the oracle; the records say where and are refused by mkfigs: {all_mismatches:?}"
        )
        .into())
    }
}

fn main() -> Result<(), Box<dyn core::error::Error>> {
    // ⭐ c15 (fix A): two passes on one host and commit.
    // Pass 1 (the default) is ours, SDSSE-CQ/-S and VCFB at every tier, as its own
    // record. Pass 2 is the Doris follow-up alone, run after pass 1's record is on
    // disk, writing one record per tier, so its memory (an OOM kill cannot be
    // caught in process) can never cost the other arms' work.
    match std::env::var("PQCL_EXP2_PASS").as_deref() {
        Err(_) | Ok("main") => main_pass(),
        Ok("doris-fu") => doris_pass(),
        Ok(other) => Err(format!("PQCL_EXP2_PASS={other}: expected `main` or `doris-fu`").into()),
    }
}

/// §1aa.4: one query set for every tier, drawn once from one (nested) tier, so
/// the curve shows the index growing under a fixed workload. Re-drawing per tier
/// made the 10^5 point a different, far less selective query set (239 hits at
/// width 2, against 36 and 71 either side). The tier is the smallest one run,
/// unless `PQCL_EXP2_QUERY_TIER` names it: pass 2 runs one tier per process, and
/// must draw the queries pass 1 drew (`mkfigs` refuses a merge where they differ).
fn query_tier(tiers: &[usize]) -> Result<usize, String> {
    match std::env::var("PQCL_EXP2_QUERY_TIER") {
        Ok(v) => v
            .trim()
            .parse()
            .map_err(|_| format!("PQCL_EXP2_QUERY_TIER={v} is not a number")),
        Err(_) => tiers
            .iter()
            .min()
            .copied()
            .ok_or_else(|| "no tiers".to_owned()),
    }
}

/// Each conjunction width's fixed query list.
type QuerySet = std::collections::BTreeMap<usize, Vec<Vec<String>>>;

fn fixed_queries(query_tier: usize) -> Result<QuerySet, Box<dyn core::error::Error>> {
    let docs = corpus::load_nested(query_tier, CORPUS_SEED)?;
    let ranked = corpus::by_frequency(&docs);
    Ok(CONJUNCTION_WIDTHS
        .iter()
        .map(|&w| (w, queries(&docs, &ranked, w, QUERIES)))
        .collect())
}

/// Pass 1: ours, SDSSE-CQ/-S and VCFB at every tier, one record.
#[allow(clippy::too_many_lines)] // the tiers, then each arm in turn
fn main_pass() -> Result<(), Box<dyn core::error::Error>> {
    use rand::SeedableRng as _;
    let mut rng = rand::rngs::StdRng::seed_from_u64(ODXT_RNG_SEED);
    let mut sdsse_rng = rand::rngs::StdRng::seed_from_u64(SDSSE_RNG_SEED);
    let mut rows = Vec::new();
    let mut selections = std::collections::BTreeMap::new();

    let tiers = doc_tiers();
    let q_tier = query_tier(&tiers)?;
    let fixed = fixed_queries(q_tier)?;

    for tier in tiers {
        let docs = corpus::load_nested(tier, CORPUS_SEED)?;
        selections.insert(
            format!("enron-selection-{tier}"),
            corpus::fingerprint(&docs),
        );
        let pairs = corpus::pair_count(&docs);
        let w = Workload::build(docs);

        eprintln!(
            "tier {tier} docs, {pairs} pairs, {} deleted",
            w.deleted.len()
        );

        let (mut ours, our_server) = build_ours(&w)?;
        let odxt_ctx = odxt_enabled().then(|| {
            let (sk, st, edb) = build_odxt(&w);
            OdxtCtx { sk, st, edb }
        });

        for &width in CONJUNCTION_WIDTHS {
            let qs = fixed.get(&width).cloned().unwrap_or_default();
            if qs.is_empty() {
                continue;
            }

            // ⭐ c15: ours is checked against the plaintext oracle before it is
            // timed, as every comparator arm is (ODXT's agreement check used to
            // do this job, and ODXT is no longer re-run).
            for (q, want) in qs.iter().zip(oracle(&w, &qs)) {
                let got = search_ours(&mut ours, &our_server, q);
                if got != want {
                    return Err(format!(
                        "Π_XT disagrees with the oracle at {tier} docs on {q:?}: {} vs {}",
                        got.len(),
                        want.len()
                    )
                    .into());
                }
            }
            let m = measure(&mut ours, &our_server, odxt_ctx.as_ref(), &qs, &mut rng)?;
            rows.push(row(
                tier,
                pairs,
                width,
                qs.len(),
                &ours,
                &our_server,
                odxt_ctx.as_ref(),
                m,
            ));

            eprintln!("  width {width}: {} queries measured", qs.len());
        }

        // ⭐ Sequential, with the earlier arms freed first: at the top tier an
        // SDSSE build is about 40 GB, and the arms are never timed side by side.
        drop(ours);
        drop(our_server);
        drop(odxt_ctx);
        for variant in SDSSE_ARMS {
            let t0 = Instant::now();
            let (mut client, mut server) = build_sdsse(&w, variant, &mut sdsse_rng);
            eprintln!(
                "  {}: built in {:.1} s, {:?} entries",
                variant.name(),
                t0.elapsed().as_secs_f64(),
                server.entries()
            );
            for &width in CONJUNCTION_WIDTHS {
                let qs = fixed.get(&width).cloned().unwrap_or_default();
                if qs.is_empty() {
                    continue;
                }
                let want = oracle(&w, &qs);
                let cell = measure_sdsse(&mut client, &mut server, &qs, &want, &mut sdsse_rng)?;
                eprintln!(
                    "    width {width}: first {} ns, repeat {} ns, shortfall {}",
                    cell["first_search_ns"]["median_ns"],
                    cell["repeat_search_ns"]["median_ns"],
                    cell["oracle_shortfall_bloom_false_positives"]
                );
                let row = rows
                    .iter_mut()
                    .find(|r| r["documents"] == tier && r["conjunction_width"] == width)
                    .ok_or("no row for this tier and width")?;
                row[variant.name()] = cell;
            }
        }

        // ⭐ M15 / c15: VCFB, built once per tier, every tier.
        let t0 = Instant::now();
        let (mut vc, mut vs) = build_vcfb(&w);
        eprintln!(
            "  vcfb: built in {:.1} s, {:?} entries",
            t0.elapsed().as_secs_f64(),
            vs.entries()
        );
        for &width in CONJUNCTION_WIDTHS {
            let qs = fixed.get(&width).cloned().unwrap_or_default();
            if qs.is_empty() {
                continue;
            }
            let want = oracle(&w, &qs);
            let cell = measure_vcfb(&mut vc, &mut vs, &qs, &want)?;
            eprintln!(
                "    vcfb width {width}: first {} ns, repeat {} ns",
                cell["first_search_ns"]["median_ns"], cell["repeat_search_ns"]["median_ns"]
            );
            row_at(&mut rows, tier, width)?["vcfb"] = cell;
        }
        drop((vc, vs));
    }

    let measurements = serde_json::json!({
        "rows": rows,
        "workload": {
            "tiers": "nested: one seeded permutation of the corpus, tier N its first N files (corpus::load_nested)",
            "corpus_seed": CORPUS_SEED,
            "query_set": "fixed across tiers: drawn once from the query tier (the smallest unless PQCL_EXP2_QUERY_TIER), whose documents every tier contains",
            "query_tier": q_tier,
            "pass": "main: ours, SDSSE-CQ/-S, VCFB",
            "queries_by_width": fixed,
            "sdsse_bloom": "h = 5, p = 1e-4 (their 5.1); each keyword's filter sized for its own deletions, floor 10: kinder than the authors' one d for all",
            "sdsse_first_and_repeat": "each first search is timed and rolled back outside the timed region; the repeat is timed after one kept first search",
            "vcfb_first_and_repeat": "as SDSSE's: the first search decodes every xtag' uploaded since the last search (Alg. 1 Search lines 3-11), O(pairs), and is rolled back outside the timed region; the repeat is timed after one kept first search",
            "odxt": if odxt_enabled() { "re-run (PQCL_EXP2_ODXT=1)" } else { "not re-run: its macros were retired; ours is checked against the plaintext oracle instead" },
            "doris_fu": "pass 2: record m15-doris-fu-search (PQCL_EXP2_PASS=doris-fu), one per tier, run after this record is on disk; mkfigs merges it into these rows and refuses another commit, instance type or query set",
            "deletion_granularity": "document",
            "deletion_granularity_reason":
                "ODXT registers a deletion only under the s-term and assumes \
                 document-level deletion (NDSS'21 III-C fn.3). Per-pair deletion \
                 would make it return stale matches -- a strawman in our favour.",
            "delete_fraction_denominator": DELETE_FRACTION,
            "beta": BETA,
            "chain_round_trip": false,
            "language": "rust-vs-rust on one host; no Python figure appears here",
        },
        "caveat":
            "We lose asymptotically to fp-GA-ODXT and win on the constant factor. \
             No wall-clock result here may be written up as an asymptotic win.",
    });

    emit(
        "exp2-conjunctive-latency",
        RunSpec {
            liboqs_version: "n/a: symmetric-only search path".to_owned(),
            rng_seeds: vec![0x21, 0x22, 0x33, ODXT_RNG_SEED, SDSSE_RNG_SEED],
            dataset_checksums: selections,
            ..RunSpec::default()
        },
        MIN_ITERATIONS,
        measurements,
    )?;

    Ok(())
}
