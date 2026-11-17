//! **Experiments 3, 4 and 5** — leakage, epoch/compaction, and the Bloom `XSet`.
//!
//! Three sweeps over the same index, run from one binary because they share a
//! corpus load and an index build. They emit three separate records, because
//! they answer three separate questions and a reader should be able to discard
//! one without discarding the others.
//!
//! # Experiment 3 — leakage quantification
//!
//! `EqPat` and `HitLink` growth as a function of query count per case, plus the
//! empirical `XHitCnt` distribution. The point is that `Π_XT` leaks *s-term
//! volume and nothing per-conjunct*, whereas `Π_CD` leaks a volume per conjunct
//! — Theorem `thm:incomp`, shown empirically rather than only proved.
//!
//! ⚠️ This measures **what the server sees**, so it reads the transcript, not
//! the result. A leakage experiment that inspected the answer would be measuring
//! the wrong side of the protocol.
//!
//! # Experiment 4 — epoch and compaction trade-off
//!
//! Probe cost as a function of `E`, the number of closed epochs, and the cost of
//! compaction itself. Round-two probe count is `2·|Cand|·(n−1)·E`, so `E` is a
//! direct multiplier on the server's work and on the transcript — which is why
//! compaction exists and why its cost has to be stated next to its benefit.
//!
//! # Experiment 5 — Bloom `XSet`
//!
//! Server storage and the cost of false positives across `ε ∈ {10⁻¹…10⁻⁴}`,
//! measured at **two** levels: probe and answer.
//!
//! ⛔ **`HonestXSet` is the oracle and stays the oracle.** Every Bloom probe is
//! compared against the exact answer, and the false positives are *counted*
//! rather than assumed to match the configured `ε`. A filter that answered
//! `true` unconditionally would look perfect on recall alone.
//!
//! ⚠️ **Corrected 2026-09-16.** This experiment used to stop at the probe level
//! and describe the cost as retrieval overhead. That was wrong: round two
//! decides membership with `add && !del`, so a false positive on a `Del`
//! cross-tag silently drops a true match. `answer_dropped` is now measured and
//! is the number that matters. See `crates/pqcl-dsse/tests/bloom_vs_oracle.rs`,
//! which found it, and `pqcl_dsse::bloom`'s module doc, which carried the wrong
//! claim.
//!
//! # Running it
//!
//! ```text
//! PQCL_ENRON=datasets/enron/maildir cargo run --release -p pqcl-exp --bin exp345
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use pqcl_bench::{MIN_ITERATIONS, RunSpec};
use pqcl_dsse::bloom::{BloomXSet, sizing};
use pqcl_dsse::core::{Client, Op};
use pqcl_dsse::xt::{Formula, HonestServer, HonestXSet, ProbeMap, Transcript, XSetStore, XtClient};
use pqcl_exp::stats::Summary;
use pqcl_exp::{corpus, emit};
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

/// Documents indexed for all three experiments.
const DOCS: usize = 4_000;

/// Keywords per document.
const KEYWORDS: usize = 20;

/// Queries issued while watching leakage accumulate (Exp. 3). §1q.2's denser
/// axis, fixed before campaign 04: 1-2-5 steps; the table reads 1, 10 and 50.
const QUERY_COUNTS: &[usize] = &[1, 2, 5, 10, 20, 50, 100, 200];

/// Closed-epoch counts to sweep (Exp. 4). §1q.2: up to the operating 24; the
/// table cells read E = 16.
const EPOCH_COUNTS: &[u64] = &[1, 2, 4, 8, 12, 16, 20, 24];

/// False-positive rates to sweep (Exp. 5).
const EPSILONS: &[f64] = &[1e-1, 1e-2, 1e-3, 1e-4];

/// §1l.1's operating point: `tab:params`' `E <= 24` and the widest conjunction
/// the paper evaluates, `n = 6`.
const OPERATING_EPOCHS: u64 = 24;
const OPERATING_WIDTH: usize = 6;

/// Target answer losses `δ` for the fixed-δ rows (M10 H9): ε is derived per
/// `E` from the loss bound instead of swept.
const TARGET_LOSSES: &[f64] = &[1e-2, 1e-3];

/// Cross-tag upload batch size.
const BETA: usize = 256;

/// Conjunction width for the leakage and epoch sweeps.
const WIDTH: usize = 3;

/// Fraction of documents deleted, so compaction has something to reclaim.
///
/// ⛔ **Without deletions, compaction cannot shrink anything.** The first run of
/// Exp. 4 reported `80000 → 80000` cross-tags: every pair was live, so
/// compaction re-keyed the set and reclaimed nothing. The measurement was
/// correct and told us nothing, because the benefit compaction exists for — a
/// rebuilt `XSet` carrying no tombstone history — only appears when there *is*
/// tombstone history. A tenth is enough to make the effect unmistakable.
const DELETE_FRACTION: usize = 10;

/// Build an index whose cross-tags are spread over `epochs` closed epochs.
fn build(
    docs: &[corpus::Document],
    epochs: u64,
) -> Result<(XtClient, HonestServer), Box<dyn core::error::Error>> {
    let core = Client::new(PrfKey::new([0x31u8; LAMBDA_BYTES]));
    let mut client = XtClient::new(core, PrfKey::new([0x32u8; LAMBDA_BYTES]), BETA);
    let mut server = HonestServer::new();

    let per_epoch = docs
        .len()
        .div_ceil(usize::try_from(epochs).unwrap_or(1).max(1))
        .max(1);
    // `id = (e, j)` (draft8 D3): a document's identifier names the epoch it
    // was ingested in; epochs close between documents, so a record never
    // straddles two. Kept so the deletions below name the same record.
    let mut ids = Vec::with_capacity(docs.len());
    for (i, d) in docs.iter().enumerate() {
        let id = pqcl_dsse::xt::doc_id(client.epoch(), d.id);
        ids.push(id);
        for k in d.keywords.iter().take(KEYWORDS) {
            client.update(&mut server, Op::Add, k.as_bytes(), id)?;
        }
        // Close an epoch every `per_epoch` documents, so `E` is the sweep
        // variable rather than an accident of the batch size — but at most
        // `E − 1` times here: the last epoch also takes the deletions below
        // and is closed after them.
        if (i + 1) % per_epoch == 0 && client.closed_epochs() + 1 < epochs {
            client.flush(&mut server);
            client.close_epoch(&mut server);
        }
    }
    // Deletions, at document granularity, so compaction has tombstone history
    // to reclaim. Deterministic: every Nth document, a function of the corpus
    // rather than of an unrecorded seed.
    for (d, id) in docs.iter().zip(&ids).step_by(DELETE_FRACTION) {
        for k in d.keywords.iter().take(KEYWORDS) {
            client.update(&mut server, Op::Del, k.as_bytes(), *id)?;
        }
    }

    // ⛔ Always close the final epoch, and require exactly `epochs` closed.
    // The first version closed only at whole multiples of `per_epoch` and then
    // only if NONE had closed, so a corpus not divisible by `E` produced
    // `E − 1` closed epochs with the deletions stranded in an open one. Every
    // Exp. 4/5 row said `closed_epochs` 1/1/3/7/15 for a sweep of 1/2/4/8/16,
    // and the E = 16 cells the paper asks for did not exist. Found on AWS
    // campaign 02 by `mkfigs`'s coverage report (since removed, §1an.3).
    client.flush(&mut server);
    client.close_epoch(&mut server);
    if client.closed_epochs() != epochs {
        return Err(format!(
            "asked for {epochs} closed epochs, built {} — the sweep variable is wrong",
            client.closed_epochs()
        )
        .into());
    }
    Ok((client, server))
}

/// Queries drawn from single documents, as Exp. 2 established they must be.
fn queries(docs: &[corpus::Document], width: usize, count: usize) -> Vec<Vec<String>> {
    let stride = (docs.len() / count.max(1)).max(1);
    docs.iter()
        .step_by(stride)
        .filter(|d| d.keywords.len() >= width)
        .take(count)
        .map(|d| d.keywords.iter().take(width).cloned().collect())
        .collect()
}

/// Run one conjunctive search, returning its transcript for inspection.
fn search_transcript(
    client: &mut XtClient,
    server: &HonestServer,
    q: &[String],
) -> Option<(pqcl_dsse::xt::Transcript, usize)> {
    let terms: Vec<&[u8]> = q.iter().map(String::as_bytes).collect();
    let s_idx = client.select_s_term(&terms)?;
    let candidates = client.candidates(server, terms[s_idx]).ok()?;
    let x_terms: Vec<&[u8]> = terms
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != s_idx)
        .map(|(_, t)| t)
        .copied()
        .collect();
    let (transcript, _map) = client.probe(&candidates, &x_terms);
    Some((transcript, candidates.len()))
}

/// A query with everything round two needs to produce an *answer*, not just a
/// transcript.
///
/// [`search_transcript`] deliberately throws the probe map away, because
/// Experiments 3 and 4 measure what the server sees and must not be able to
/// look at the result. Experiment 5 is the opposite: the whole question is what
/// the client ends up believing, so it needs the map back.
struct Probed {
    candidates: Vec<u64>,
    transcript: Transcript,
    map: ProbeMap,
    x_terms: usize,
}

fn search_full(client: &mut XtClient, server: &HonestServer, q: &[String]) -> Option<Probed> {
    let terms: Vec<&[u8]> = q.iter().map(String::as_bytes).collect();
    let s_idx = client.select_s_term(&terms)?;
    let candidates = client.candidates(server, terms[s_idx]).ok()?;
    let x_terms: Vec<&[u8]> = terms
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != s_idx)
        .map(|(_, t)| t)
        .copied()
        .collect();
    let (transcript, map) = client.probe(&candidates, &x_terms);
    Some(Probed {
        candidates,
        transcript,
        map,
        x_terms: x_terms.len(),
    })
}

/// ODXT over the same documents and deletions as [`build`] — the H6 baseline.
struct Odxt {
    sk: baseline_odxt::SecretKey,
    st: baseline_odxt::ClientState,
    edb: baseline_odxt::Edb,
}

fn build_odxt(docs: &[corpus::Document]) -> Odxt {
    let sk = baseline_odxt::SecretKey::from_bytes(&[0x34; 128]);
    let mut st = baseline_odxt::ClientState::default();
    let mut edb = baseline_odxt::Edb::new();
    for d in docs {
        for k in d.keywords.iter().take(KEYWORDS) {
            edb.apply(&baseline_odxt::update(
                &sk,
                &mut st,
                Op::Add,
                d.id,
                k.as_bytes(),
            ));
        }
    }
    for d in docs.iter().step_by(DELETE_FRACTION) {
        for k in d.keywords.iter().take(KEYWORDS) {
            edb.apply(&baseline_odxt::update(
                &sk,
                &mut st,
                Op::Del,
                d.id,
                k.as_bytes(),
            ));
        }
    }
    Odxt { sk, st, edb }
}

/// ⭐ M10 H6 — **associations**, defined once for all three schemes: a pair
/// (server-visible document handle, x-term handle) whose membership outcome
/// the server observes **and can attribute to that handle**. Counted distinct
/// over the whole query log, so repeats across queries accumulate only once.
///
/// * ODXT: the handle is candidate `j`'s `TSet` address, and every x-term
///   lookup for `j` is made against it — read off ODXT's own server loop
///   (`search_server_observed`). Its xtags are deterministic per (x-term,
///   document), so the same association is recognisable in every query.
/// * `Π_XT`: a probe is `(epoch, xtag)`, shuffled across every candidate and
///   x-term and answered as an unordered bit vector — no probe carries a
///   document handle, so none is attributable. Measured from the transcript's
///   own type, which has no such field.
/// * `Π_CD`: one `Π_core` search per conjunct; addresses are per (keyword,
///   counter), so no handle spans two conjuncts.
fn odxt_associations(o: &Odxt, qs: &[Vec<String>], rng: &mut impl rand::Rng) -> serde_json::Value {
    let mut assoc: BTreeSet<([u8; 32], [u8; 32])> = BTreeSet::new();
    let mut positive: BTreeSet<([u8; 32], [u8; 32])> = BTreeSet::new();
    let mut handles: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut lookups = 0usize;
    for q in qs {
        let qb: Vec<Vec<u8>> = q.iter().map(|w| w.as_bytes().to_vec()).collect();
        let Some(token) = baseline_odxt::search_token(&o.sk, &o.st, &qb, rng) else {
            continue;
        };
        let (_, view) = baseline_odxt::search_server_observed(&o.edb, &token);
        for v in view {
            handles.insert(v.stag_addr);
            for (xtag, hit) in v.lookups {
                lookups += 1;
                assoc.insert((v.stag_addr, xtag));
                if hit {
                    positive.insert((v.stag_addr, xtag));
                }
            }
        }
    }
    serde_json::json!({
        "associations": assoc.len(),
        "positive_associations": positive.len(),
        "document_handles": handles.len(),
        "lookups_total": lookups,
        "per_candidate_intersection_count_revealed": handles.len(),
    })
}

/// `SDSSE-CQ` or `-S` over the same documents and deletions as ODXT above.
fn build_sdsse(
    docs: &[corpus::Document],
    variant: baseline_sdsse_cq::Variant,
) -> (baseline_sdsse_cq::Client, baseline_sdsse_cq::Server) {
    use rand::SeedableRng as _;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x0D14);
    let mut deletions: std::collections::HashMap<Vec<u8>, usize> = std::collections::HashMap::new();
    for d in docs.iter().step_by(DELETE_FRACTION) {
        for k in d.keywords.iter().take(KEYWORDS) {
            *deletions.entry(k.as_bytes().to_vec()).or_insert(0) += 1;
        }
    }
    let mut client = baseline_sdsse_cq::Client::setup(variant, &[0x35; 32], deletions);
    let mut server = baseline_sdsse_cq::Server::default();
    for d in docs {
        for k in d.keywords.iter().take(KEYWORDS) {
            client.update(&mut server, Op::Add, k.as_bytes(), d.id, &mut rng);
        }
    }
    for d in docs.iter().step_by(DELETE_FRACTION) {
        for k in d.keywords.iter().take(KEYWORDS) {
            client.update(&mut server, Op::Del, k.as_bytes(), d.id, &mut rng);
        }
    }
    (client, server)
}

/// ⭐ the design record: Exp. 5's counts for an SDSSE arm, read off
/// **its own server loop** (`baseline_sdsse_cq::Server::search`), not ODXT's.
///
/// `associations` carries over unchanged: a (document handle, x-term handle) pair
/// whose outcome the server observes for that handle. The handle is `e`, in the
/// clear after `Aura.Search`; the x-term handle is the element it computes.
///
/// `reuse_*` is what separates Type-O from Type-O⁻ (the authors' Fig. 2), and it is
/// measured by doing it. After the log, for each query `(s, x, …)`: a document
/// holding `s` but not `x` gains `x`, a **later** query with another s-term fetches
/// `x`'s set, and the server tests the elements it kept from the first query against
/// that set. A hit is a membership outcome no query asked for.
fn sdsse_view(
    built: &(baseline_sdsse_cq::Client, baseline_sdsse_cq::Server),
    docs: &[corpus::Document],
    qs: &[Vec<String>],
) -> serde_json::Value {
    use rand::SeedableRng as _;
    let (mut client, mut server) = built.clone();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x0E14);
    let mut assoc: BTreeSet<(Vec<u8>, [u8; 32])> = BTreeSet::new();
    let mut positive: BTreeSet<(Vec<u8>, [u8; 32])> = BTreeSet::new();
    let mut handles: BTreeSet<Vec<u8>> = BTreeSet::new();
    let (mut lookups, mut wire) = (0usize, 0usize);
    // (s-term, first x-term, the elements that came back negative).
    #[allow(clippy::type_complexity)]
    let mut kept: Vec<(Vec<u8>, Vec<u8>, Vec<[u8; 32]>)> = Vec::new();

    for q in qs {
        let qb: Vec<Vec<u8>> = q.iter().map(|w| w.as_bytes().to_vec()).collect();
        let terms = client.order_terms(&qb);
        let Some(token) = client.search_token(&terms, &mut rng) else {
            continue;
        };
        wire += token.wire_bytes_up();
        let mut rb = baseline_sdsse_cq::Rollback::default();
        let mut seen = baseline_sdsse_cq::Observer::default();
        let _ = server.search(&token, &mut rb, Some(&mut seen));
        let mut negatives = Vec::new();
        for o in seen.tuples {
            handles.insert(o.e.clone());
            for (j, (elt, hit)) in o.lookups.iter().enumerate() {
                lookups += 1;
                assoc.insert((o.e.clone(), *elt));
                if *hit {
                    positive.insert((o.e.clone(), *elt));
                } else if j == 0 {
                    negatives.push(*elt);
                }
            }
        }
        if terms.len() >= 2 {
            kept.push((terms[0].to_vec(), terms[1].to_vec(), negatives));
        }
    }

    // The plaintext answer, to pick the document that gains the x-term.
    let mut inv: BTreeMap<&[u8], BTreeSet<u64>> = BTreeMap::new();
    for (i, d) in docs.iter().enumerate() {
        if i % DELETE_FRACTION == 0 {
            continue;
        }
        for k in d.keywords.iter().take(KEYWORDS) {
            inv.entry(k.as_bytes()).or_default().insert(d.id);
        }
    }
    let (mut trials, mut hits) = (0usize, 0usize);
    let empty = BTreeSet::new();
    for (s, x, negatives) in &kept {
        let holds_x = inv.get(x.as_slice()).unwrap_or(&empty);
        let Some(target) = inv
            .get(s.as_slice())
            .and_then(|ids| ids.iter().find(|id| !holds_x.contains(id)))
            .copied()
        else {
            continue;
        };
        // Any other indexed keyword serves as the later query's s-term.
        let Some(other) = inv
            .keys()
            .find(|w| **w != s.as_slice() && **w != x.as_slice())
            .map(|w| w.to_vec())
        else {
            continue;
        };
        client.update(&mut server, Op::Add, x, target, &mut rng);
        let terms: [&[u8]; 2] = [&other, x];
        let Some(token) = client.search_token(&terms, &mut rng) else {
            continue;
        };
        let mut rb = baseline_sdsse_cq::Rollback::default();
        let mut seen = baseline_sdsse_cq::Observer::default();
        let _ = server.search(&token, &mut rb, Some(&mut seen));
        let fetched: std::collections::HashSet<[u8; 32]> = seen.fetched.into_iter().collect();
        trials += 1;
        hits += negatives.iter().filter(|e| fetched.contains(*e)).count();
    }

    serde_json::json!({
        "associations": assoc.len(),
        "positive_associations": positive.len(),
        "document_handles": handles.len(),
        "lookups_total": lookups,
        "wire_bytes_up_total": wire,
        "reuse_trials": trials,
        "reuse_hits": hits,
    })
}

/// VCFB over the same documents and deletions as ODXT above (M15, §1db.1).
fn build_vcfb(docs: &[corpus::Document]) -> (baseline_vcfb::Client, baseline_vcfb::Server) {
    let (mut c, mut s) = baseline_vcfb::Client::setup(&[0x35; 32]);
    for d in docs {
        for k in d.keywords.iter().take(KEYWORDS) {
            s.apply(&c.update(k.as_bytes(), d.id, Op::Add));
        }
    }
    for d in docs.iter().step_by(DELETE_FRACTION) {
        for k in d.keywords.iter().take(KEYWORDS) {
            s.apply(&c.update(k.as_bytes(), d.id, Op::Del));
        }
    }
    (c, s)
}

/// The live documents' first `KEYWORDS` keywords: what the static Doris follow-up
/// is built over (the post-deletion state the dynamic arms hold).
fn live_docs(docs: &[corpus::Document]) -> Vec<(u64, Vec<String>)> {
    docs.iter()
        .enumerate()
        .filter(|(i, _)| i % DELETE_FRACTION != 0)
        .map(|(_, d)| (d.id, d.keywords.iter().take(KEYWORDS).cloned().collect()))
        .collect()
}

/// Both new arms answer every query of the row's log exactly as the plaintext does,
/// before anything is counted from them.
fn check_m15_arms(
    vb: &(baseline_vcfb::Client, baseline_vcfb::Server),
    dfu: &(
        baseline_doris_fu::search::Client,
        baseline_doris_fu::search::Edb,
    ),
    live: &[(u64, Vec<String>)],
    qs: &[Vec<String>],
) -> Result<(), String> {
    use rand::SeedableRng as _;
    let (mut vc, mut vs) = vb.clone();
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    for q in qs {
        let want: BTreeSet<u64> = live
            .iter()
            .filter(|(_, ws)| q.iter().all(|w| ws.contains(w)))
            .map(|(id, _)| *id)
            .collect();
        let qb: Vec<Vec<u8>> = q.iter().map(|w| w.as_bytes().to_vec()).collect();
        if vc.search(&mut vs, &qb) != want {
            return Err(format!("VCFB disagrees with the oracle on {q:?}"));
        }
        let qr: Vec<&[u8]> = q.iter().map(String::as_bytes).collect();
        if dfu.0.search(&dfu.1, &qr, &mut rng) != want {
            return Err(format!(
                "the Doris follow-up disagrees with the oracle on {q:?}"
            ));
        }
    }
    Ok(())
}

/// ⭐ the design record's VCFB rule (committed in `871e0ed`, before any
/// count), read off `baseline_vcfb::Server::search`'s own loop. The handle is
/// `addr_j`, the x-term handle `vxtag^{add}` (one association per candidate and
/// x-term: the `del` element of the same lookup is the same association), and the
/// reuse trial is `sdsse_view`'s: any later query opens the new bucket.
fn vcfb_view(
    built: &(baseline_vcfb::Client, baseline_vcfb::Server),
    docs: &[corpus::Document],
    qs: &[Vec<String>],
) -> serde_json::Value {
    let (mut c, mut s) = built.clone();
    let mut assoc: BTreeSet<([u8; 32], [u8; 32])> = BTreeSet::new();
    let mut positive: BTreeSet<([u8; 32], [u8; 32])> = BTreeSet::new();
    let mut handles: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut lookups = 0usize;
    #[allow(clippy::type_complexity)]
    let mut kept: Vec<(Vec<u8>, Vec<u8>, Vec<[u8; 32]>)> = Vec::new();
    for q in qs {
        let qb: Vec<Vec<u8>> = q.iter().map(|w| w.as_bytes().to_vec()).collect();
        let terms = c.order_terms(&qb);
        let Some(token) = c.token(&terms) else {
            continue;
        };
        let mut seen = Vec::new();
        let _ = s.search(&token, &mut baseline_vcfb::Undo::default(), Some(&mut seen));
        let mut negatives = Vec::new();
        for o in seen {
            handles.insert(o.addr);
            for (j, (elt, add_in, del_in)) in o.lookups.iter().enumerate() {
                lookups += 1;
                assoc.insert((o.addr, *elt));
                if *add_in && !*del_in {
                    positive.insert((o.addr, *elt));
                } else if j == 0 && !*add_in {
                    negatives.push(*elt);
                }
            }
        }
        if terms.len() >= 2 {
            kept.push((terms[0].to_vec(), terms[1].to_vec(), negatives));
        }
    }
    let mut inv: BTreeMap<&[u8], BTreeSet<u64>> = BTreeMap::new();
    for (i, d) in docs.iter().enumerate() {
        if i % DELETE_FRACTION == 0 {
            continue;
        }
        for k in d.keywords.iter().take(KEYWORDS) {
            inv.entry(k.as_bytes()).or_default().insert(d.id);
        }
    }
    let (mut trials, mut hits) = (0usize, 0usize);
    let empty = BTreeSet::new();
    for (sterm, x, negatives) in &kept {
        let holds_x = inv.get(x.as_slice()).unwrap_or(&empty);
        let Some(target) = inv
            .get(sterm.as_slice())
            .and_then(|ids| ids.iter().find(|id| !holds_x.contains(id)))
            .copied()
        else {
            continue;
        };
        let Some(other) = inv
            .keys()
            .find(|w| **w != sterm.as_slice() && **w != x.as_slice())
            .map(|w| w.to_vec())
        else {
            continue;
        };
        s.apply(&c.update(x, target, Op::Add));
        let terms: [&[u8]; 2] = [&other, x];
        let Some(token) = c.token(&terms) else {
            continue;
        };
        let _ = s.search(&token, &mut baseline_vcfb::Undo::default(), None);
        trials += 1;
        hits += negatives.iter().filter(|e| s.xset_contains(e)).count();
    }
    serde_json::json!({
        "associations": assoc.len(),
        "positive_associations": positive.len(),
        "document_handles": handles.len(),
        "lookups_total": lookups,
        "unattributable_links": 0,
        "reuse_trials": trials,
        "reuse_hits": hits,
    })
}

/// ⭐ the design record's Doris follow-up rule (committed in `871e0ed`,
/// before any count), read off `Edb::decide`'s own loop: one outcome per candidate
/// for the whole conjunction. Attributed only within the query that produced it (a
/// positive attributes every x-term; a negative only when there is one x-term).
/// Elimination across queries is reported apart and never in `associations`.
fn doris_fu_view(
    dfu: &(
        baseline_doris_fu::search::Client,
        baseline_doris_fu::search::Edb,
    ),
    qs: &[Vec<String>],
) -> serde_json::Value {
    use rand::SeedableRng as _;
    type S = [usize; 3];
    let (c, edb) = dfu;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x0E15);
    let mut direct: BTreeSet<([u8; 32], S)> = BTreeSet::new();
    let mut direct_pos: BTreeSet<([u8; 32], S)> = BTreeSet::new();
    let mut handles: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut s_in_queries: BTreeMap<S, BTreeSet<usize>> = BTreeMap::new();
    let mut negative_tokens: Vec<([u8; 32], Vec<S>)> = Vec::new();
    let mut candidates = 0usize;
    for (qi, q) in qs.iter().enumerate() {
        let qb: Vec<&[u8]> = q.iter().map(String::as_bytes).collect();
        let Some((sterm, rest)) = c.choose(&qb) else {
            continue;
        };
        let t = edb.retrieve(&c.stag(sterm));
        let toks = c.xtokens(sterm, &rest, t.len(), &mut rng);
        let mut seen = Vec::new();
        let _ = edb.decide(&t, &toks, Some(&mut seen));
        for o in seen {
            candidates += 1;
            handles.insert(o.e);
            for sx in &o.s {
                s_in_queries.entry(*sx).or_default().insert(qi);
            }
            if o.hit {
                for sx in &o.s {
                    direct.insert((o.e, *sx));
                    direct_pos.insert((o.e, *sx));
                }
            } else if o.s.len() == 1 {
                direct.insert((o.e, o.s[0]));
            } else {
                negative_tokens.push((o.e, o.s.clone()));
            }
        }
    }
    let mut inferred: BTreeSet<([u8; 32], S)> = BTreeSet::new();
    for (e, ss) in &negative_tokens {
        let unknown: Vec<&S> = ss
            .iter()
            .filter(|sx| !direct_pos.contains(&(*e, **sx)))
            .collect();
        if unknown.len() == 1 && !direct.contains(&(*e, *unknown[0])) {
            inferred.insert((*e, *unknown[0]));
        }
    }
    let attributed: BTreeSet<S> = direct.iter().map(|(_, s)| *s).collect();
    let links: Vec<&BTreeSet<usize>> = s_in_queries
        .iter()
        .filter(|(s, _)| !attributed.contains(*s))
        .map(|(_, q)| q)
        .collect();
    serde_json::json!({
        "associations": direct.len(),
        "positive_associations": direct_pos.len(),
        "document_handles": handles.len(),
        "candidates_total": candidates,
        "inferred_by_elimination": inferred.len(),
        "unattributable_links_distinct": links.len(),
        "unattributable_links_in_two_or_more_queries": links.iter().filter(|q| q.len() >= 2).count(),
        "reuse": "n/a: static",
    })
}

/// **Experiment 3** — how leakage accumulates with query count.
fn exp3(docs: &[corpus::Document]) -> Result<serde_json::Value, Box<dyn core::error::Error>> {
    use rand::SeedableRng as _;
    let (mut client, server) = build(docs, 4)?;
    let odxt = build_odxt(docs);
    let cq = build_sdsse(docs, baseline_sdsse_cq::Variant::Cq);
    let cq_s = build_sdsse(docs, baseline_sdsse_cq::Variant::CqS);
    // M15/c15: VCFB and the Doris follow-up (static, over the live documents).
    let vb = build_vcfb(docs);
    let live = live_docs(docs);
    let dfu = baseline_doris_fu::search::setup(&live, &[0x36; 32], 0xD0F5)
        .ok_or("the Doris follow-up's filter did not peel")?;
    let mut rows = Vec::new();

    for &n_queries in QUERY_COUNTS {
        let qs = queries(docs, WIDTH, n_queries);
        check_m15_arms(&vb, &dfu, &live, &qs)?;
        // Same seed per row: each row replays its own query log from scratch.
        let odxt_view = odxt_associations(&odxt, &qs, &mut rand::rngs::StdRng::seed_from_u64(0x0D));
        let cq_view = sdsse_view(&cq, docs, &qs);
        let cq_s_view = sdsse_view(&cq_s, docs, &qs);
        let vcfb_view = vcfb_view(&vb, docs, &qs);
        let doris_fu_view = doris_fu_view(&dfu, &qs);

        // EqPat: distinct s-terms seen. HitLink: distinct (epoch, xtag) pairs
        // the server has now observed across all queries — the accumulating
        // cross-query linkage that matters, and the reason this is swept in
        // query count rather than measured once.
        let mut eq_pat: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut hit_link: BTreeMap<pqcl_dsse::xt::XTag, usize> = BTreeMap::new();
        // §1db.1 reading (b), beside the count above: tags seen in >= 2 queries.
        let mut seen_in: BTreeMap<pqcl_dsse::xt::XTag, usize> = BTreeMap::new();
        let mut xhit_counts = Vec::new();
        let mut probe_total = 0usize;
        let mut wire_total = 0usize;

        for q in &qs {
            let terms: Vec<&[u8]> = q.iter().map(String::as_bytes).collect();
            if let Some(s) = client.select_s_term(&terms) {
                eq_pat.insert(terms[s].to_vec());
            }
            if let Some((t, cand)) = search_transcript(&mut client, &server, q) {
                probe_total += t.len();
                wire_total += t.wire_bytes_up();
                xhit_counts.push(cand);
                for (k, v) in t.multiset() {
                    *hit_link.entry(k).or_insert(0) += v;
                    *seen_in.entry(k).or_insert(0) += 1;
                }
            }
        }

        // Π_CD's leakage for the same queries: a volume per conjunct, which is
        // what Theorem thm:incomp says is incomparable rather than smaller.
        let cd_volumes: usize = qs
            .iter()
            .map(|q| {
                q.iter()
                    .map(|w| client.estimated_volume(w.as_bytes()) as usize)
                    .sum::<usize>()
            })
            .sum();

        rows.push(serde_json::json!({
            "queries": qs.len(),
            "eq_pat_distinct_s_terms": eq_pat.len(),
            "hit_link_distinct_pairs": hit_link.len(),
            "hit_link_in_two_or_more_queries": seen_in.values().filter(|n| **n >= 2).count(),
            "probe_count_total": probe_total,
            "wire_bytes_up_total": wire_total,
            "xhit_cnt": {
                "min": xhit_counts.iter().min().copied().unwrap_or(0),
                "max": xhit_counts.iter().max().copied().unwrap_or(0),
                "values": xhit_counts,
            },
            "pi_cd_conjunct_volumes_total": cd_volumes,
            // M10 H6: the association count, one definition for all three.
            "associations": {
                "odxt": odxt_view,
                "sdsse_cq": cq_view,
                "sdsse_cq_s": cq_s_view,
                "vcfb": vcfb_view,
                "doris_fu": doris_fu_view,
                "pi_xt": 0,
                "pi_xt_reason": "a probe is (epoch, xtag) with no document handle, shuffled across candidates and x-terms",
                "pi_cd": 0,
                "pi_cd_reason": "per-conjunct Pi_core addresses are per (keyword, counter); no handle spans two conjuncts",
            },
        }));
    }

    Ok(serde_json::json!({
        "rows": rows,
        "conjunction_width": WIDTH,
        "measured_from": "the server's transcript, never the result set",
        "m15_definition":
            "the design record, committed in 871e0ed before any count. VCFB: handle addr_j, \
             x-term handle vxtag^add, every lookup attributable, reuse as SDSSE's. Doris follow-up: \
             handle e_c, x-term handle its location set S_x; one outcome per candidate for the whole \
             conjunction, attributed only within its query; elimination across queries reported apart \
             (inferred_by_elimination); links: distinct S_x never attributed, and those in >= 2 queries.",
        "sdsse_definition":
            "the design record. Associations as defined below, with handle e and \
             x-term handle the element the server computes. reuse_hits: elements kept \
             from one query that a later query's fetched x-term set confirms, after that \
             x-term was added to a document; Type-O allows it, Type-O- does not.",
        "association_definition":
            "a (server-visible document handle, x-term handle) pair whose membership \
             outcome the server observes and can attribute to that handle; counted \
             distinct over the query log. ODXT's handle is candidate j's TSet address, \
             read off its own server loop (search_server_observed).",
        "incomparability":
            "Π_XT leaks s-term volume and an unordered bit vector; Π_CD leaks a \
             volume per conjunct. Neither dominates the other -- thm:incomp -- so \
             both are reported and no ratio between them is presented as an \
             improvement.",
    }))
}

/// Selectivity strata for Exp. 4's queries.
const STRATA: usize = 5;

/// Queries per stratum: `STRATA × this` ≥ 100 (M10 H9).
const PER_STRATUM: usize = 24;

/// A query with its true s-term volume — the smallest document frequency
/// among its terms, which is what bounds `|Cand|` and so the probe list.
struct Stratified {
    terms: Vec<String>,
    s_volume: usize,
    stratum: usize,
}

/// ⭐ M10 H9: ≥ 100 queries **stratified by s-term selectivity**, not 8 taken
/// by document stride. Campaign 02's 8 gave an IQR of 310–4 763 µs at E = 16
/// — a spread driven by which s-terms happened to be drawn, too thin to read a
/// trend in `E` through. Quantile strata over the whole candidate pool, equal
/// counts per stratum, evenly spaced within each: every selectivity band is
/// represented at every `E`, and the same queries are asked at every `E`.
fn stratified_queries(docs: &[corpus::Document], width: usize) -> Vec<Stratified> {
    let mut df: BTreeMap<&str, usize> = BTreeMap::new();
    for d in docs {
        for k in d.keywords.iter().take(KEYWORDS) {
            *df.entry(k.as_str()).or_default() += 1;
        }
    }
    let mut pool: Vec<(usize, Vec<String>)> = docs
        .iter()
        .filter(|d| d.keywords.len() >= width)
        .map(|d| {
            let terms: Vec<String> = d.keywords.iter().take(width).cloned().collect();
            let vol = terms
                .iter()
                .map(|t| df.get(t.as_str()).copied().unwrap_or(0))
                .min()
                .unwrap_or(0);
            (vol, terms)
        })
        .collect();
    pool.sort();
    pool.dedup_by(|a, b| a.1 == b.1);
    let band = pool.len() / STRATA;
    let mut out = Vec::new();
    for s in 0..STRATA {
        let slice = &pool[s * band..(s + 1) * band];
        let step = (slice.len() / PER_STRATUM).max(1);
        for (vol, terms) in slice.iter().step_by(step).take(PER_STRATUM) {
            out.push(Stratified {
                terms: terms.clone(),
                s_volume: *vol,
                stratum: s,
            });
        }
    }
    out
}

fn median(v: &mut [usize]) -> usize {
    v.sort_unstable();
    v.get(v.len() / 2).copied().unwrap_or(0)
}

/// **Experiment 4** — probe cost against `E`, and what compaction costs.
fn exp4(docs: &[corpus::Document]) -> Result<serde_json::Value, Box<dyn core::error::Error>> {
    let mut rows = Vec::new();
    let qs = stratified_queries(docs, WIDTH);
    if qs.len() < 100 {
        return Err(format!("only {} stratified queries; H9 requires >= 100", qs.len()).into());
    }

    for &epochs in EPOCH_COUNTS {
        let (mut client, mut server) = build(docs, epochs)?;

        let mut probe_counts = Vec::new();
        let mut wire = Vec::new();
        let mut samples = Vec::new();
        let mut by_stratum: BTreeMap<usize, (Vec<Duration>, Vec<usize>, usize, usize)> =
            BTreeMap::new();

        for q in &qs {
            // Search is read-only, so each query is repeated and its median
            // kept: one sample per query was part of campaign 02's spread.
            let mut reps = Vec::new();
            let mut transcript = None;
            for _ in 0..MIN_ITERATIONS {
                let t0 = Instant::now();
                transcript = search_transcript(&mut client, &server, &q.terms);
                reps.push(t0.elapsed());
            }
            let Some((t, _)) = transcript else { continue };
            reps.sort_unstable();
            let med = reps[reps.len() / 2];
            samples.push(med);
            probe_counts.push(t.len());
            wire.push(t.wire_bytes_up());
            let e = by_stratum
                .entry(q.stratum)
                .or_insert_with(|| (Vec::new(), Vec::new(), usize::MAX, 0));
            e.0.push(med);
            e.1.push(t.len());
            e.2 = e.2.min(q.s_volume);
            e.3 = e.3.max(q.s_volume);
        }
        let strata: Vec<serde_json::Value> = by_stratum
            .into_iter()
            .map(|(s, (ns, mut probes, lo, hi))| {
                serde_json::json!({
                    "stratum": s,
                    "s_term_volume_range": [lo, hi],
                    "queries": ns.len(),
                    "probe_count_median": median(&mut probes),
                    "search_ns": Summary::of(&ns),
                })
            })
            .collect();

        let before = server.xtag_count();
        let t = Instant::now();
        client.compact(&mut server, PrfKey::new([0x33u8; LAMBDA_BYTES]));
        let compaction_ns = t.elapsed().as_nanos();
        let after = server.xtag_count();

        rows.push(serde_json::json!({
            "closed_epochs": epochs,
            // ⚠️ Fixed in M10 H9: these two were `sum / len` — means, under a
            // "median" label, on a distribution skewed by the rare large
            // candidate sets. They are medians now, and the strata below say
            // where the spread comes from.
            "queries": samples.len(),
            "probe_count_median": median(&mut probe_counts),
            "wire_bytes_up_median": median(&mut wire),
            "search_ns": if samples.is_empty() { serde_json::Value::Null }
                         else { serde_json::to_value(Summary::of(&samples))? },
            "search_ns_is": "summary over per-query medians, each of MIN_ITERATIONS repetitions",
            "strata": strata,
            "compaction": {
                "xtags_before": before,
                "xtags_after": after,
                "elapsed_ns": compaction_ns,
                "note":
                    "Compaction rebuilds XSet from live pairs only, so it shrinks the \
                     set rather than merely re-keying it. The shrinkage is the benefit; \
                     elapsed_ns is the cost it has to be weighed against.",
            },
        }));
    }

    Ok(serde_json::json!({
        "rows": rows,
        "probe_formula": "2*|Cand|*(n-1)*E",
        "why_E_matters":
            "E multiplies the round-two probe list directly, so epoch length trades \
             forward privacy against server work and transcript size. That trade is \
             the operating point tab:params recommends.",
    }))
}

/// The fixed-δ rows for one group: ε derived from the loss bound at the
/// group's `(n−1)·E`, and the answer's drops checked against δ's 99%
/// binomial upper bound (the same form as P3's false-positive test).
fn fixed_delta_rows(group: &Group) -> Vec<serde_json::Value> {
    TARGET_LOSSES
        .iter()
        .map(|&delta| {
            let eps = pqcl_dsse::bloom::max_epsilon(delta, group.x_terms, group.closed_epochs);
            let mut row = group.bloom_row(eps);
            row["target_loss"] = serde_json::json!(delta);
            let exact = row["answer_exact_total"].as_u64().unwrap_or(0);
            let dropped = row["answer_dropped"].as_u64().unwrap_or(0);
            let (_, hi, _) = fp_acceptance(0, usize::try_from(exact).unwrap_or(usize::MAX), delta);
            row["loss_ci99_upper_drops"] = serde_json::json!(hi);
            #[expect(
                clippy::cast_precision_loss,
                reason = "document counts, far below 2^53"
            )]
            let within = (dropped as f64) <= hi;
            row["loss_within_ci99"] = serde_json::json!(within);
            row["epsilon_derived_from"] = serde_json::json!("max_epsilon(target_loss, n-1, E)");
            row
        })
        .collect()
}

/// **Experiment 5** — Bloom `XSet` storage and false-positive overhead.
fn exp5(docs: &[corpus::Document]) -> Result<serde_json::Value, Box<dyn core::error::Error>> {
    let mut rows = Vec::new();

    // ⭐ **Jointly with `E`, and that is the point of the experiment.** Ruled in
    // The design record: the loss model is `1 − (1−ε)^((n−1)E)`, and
    // four points at a single `E` cannot tell that exponent from a neighbouring
    // form. Sweeping both is what turns Exp. 5 from "a curve measured on Enron"
    // into a validation of a corpus-independent design rule.
    let mut fixed_delta = Vec::new();
    for &epochs in EPOCH_COUNTS {
        let group = Group::build(docs, epochs, WIDTH)?;
        for &eps in EPSILONS {
            rows.push(group.bloom_row(eps));
        }
        fixed_delta.extend(fixed_delta_rows(&group));
    }
    // ⭐ §1l.1: the operating point the deployment ADMITS, not the heaviest one
    // the sweep happens to reach -- `tab:params`' E <= 24 and the widest
    // evaluated conjunction n = 6, so (n-1)E = 120. Validated for loss here,
    // not only sized.
    let op = Group::build(docs, OPERATING_EPOCHS, OPERATING_WIDTH)?;
    let operating_point = fixed_delta_rows(&op);

    Ok(serde_json::json!({
        "rows": rows,
        "fixed_delta_rows": fixed_delta,
        "operating_point": {
            "n": OPERATING_WIDTH,
            "closed_epochs": OPERATING_EPOCHS,
            "x_terms_times_epochs": (OPERATING_WIDTH - 1) as u64 * OPERATING_EPOCHS,
            "rows": operating_point,
        },
        "model":
            "answer loss = 1 - (1-epsilon)^((n-1)*E); max epsilon for target loss delta \
             is 1 - (1-delta)^(1/((n-1)*E)), about delta/((n-1)*E). Implemented as \
             pqcl_dsse::bloom::{predicted_loss,max_epsilon}.",
        "how_to_read_the_exponent":
            "`fitted_exponent` is ln(retained)/ln(1-epsilon) from the measured loss, and \
             should track `del_probes_per_document` = (n-1)*E. If it does not, the model \
             is WRONG and must not become a design rule -- that is the finding, not an \
             artefact to smooth over. Rows where nothing was dropped carry no information \
             about the exponent and report null.",
        "read_the_observed_fp_column_first":
            "Our per-epoch sizing over-provisions, because epochs do not hold equal \
             numbers of tags, so the filters run at roughly 0.8x their configured epsilon. \
             A fit against the CONFIGURED epsilon is depressed by exactly that factor and \
             will look like a wrong exponent. `fitted_exponent_at_observed_fp` divides it \
             out and is the number that tests the model.",
        "validation_outcome_2026-09-16":
            "Exponent CONFIRMED as (n-1)E on the 4000-document Enron sample, 637 true \
             matches. At eps=1e-1, fitted_exponent_at_observed_fp reads 1.9 / 4.8 / 8.4 / \
             16.6 / 31.8 against (n-1)E = 2 / 4 / 8 / 16 / 32 -- across a 16x range of E. \
             predicted_loss_at_observed_fp tracks observed_loss throughout (E=16, eps=0.1: \
             93.66% predicted, 93.56% observed). The configured-epsilon form OVER-predicts \
             loss, so max_epsilon is conservative rather than optimistic, which is the \
             safe direction for a design bound.",
        "which_rows_carry_signal":
            "The fit is only meaningful where enough documents were dropped to estimate a \
             rate. The eps=1e-1 rows (95-596 drops of 637) are the evidence; eps=1e-3 and \
             1e-4 drop 0-12 and their fitted exponents are noise -- the 146.2 at E=16, \
             eps=1e-4 comes from two dropped documents. Do not read those as the model \
             failing at small eps; they are small-count artefacts, which is the expected \
             shape and not a finding.",
        "why_E_is_swept_here":
            "Ruled in the design record. Four epsilon points at a single E cannot \
             distinguish (n-1)E from neighbouring forms, and the whole value of the bound \
             is that it is corpus-independent. Sweeping E jointly is what validates it.",
        "oracle": "pqcl_dsse::xt::HonestXSet",
        "oracle_note":
            "Every Bloom answer is compared against the exact set. False positives are \
             counted rather than assumed to match the configured epsilon, and false \
             negatives are asserted to be zero -- a filter that answered true \
             unconditionally would score perfectly on recall alone.",
        "answer_loss":
            "CORRECTED 2026-09-16. This experiment previously reported only probe-level \
             false positives and claimed the cost was retrieval work and never a wrong \
             answer. That is false. Round two decides membership with `add && !del`, so \
             a false positive on a Del cross-tag makes a live document look deleted and \
             the client drops it -- silently, since nothing is fetched and nothing fails \
             to decrypt. `answer_dropped` counts those. Found by \
             crates/pqcl-dsse/tests/bloom_vs_oracle.rs.",
        "why_cardinality_hides_it":
            "Dropped and spurious partially cancel in the result size, so \
             answer_returned_total can look close to answer_exact_total while much of \
             the answer has been replaced. Read answer_dropped, not the totals.",
        "epsilon_is_not_free":
            "Consequence for tab:params: epsilon trades space against ANSWER CORRECTNESS, \
             not against retrieval overhead alone. It is a DERIVED BOUND, not a constant. \
             The 1e-1 end of this sweep is kept precisely because it breaks -- a sweep in \
             which nothing fails locates no boundary.",
        "do_not_lock_1e-3":
            "Ruled in the design record. 1e-3 is safe at E=2 and loses 4.69% (n-1=2) \
             to 9.16% (n-1=4) of the true answer at E=24, which tab:params permits. It \
             must not be written down as a default in code, docs or the paper.",
        "compaction_has_a_second_purpose":
            "The bound tightens linearly in E, so resetting E is not only a storage \
             optimisation -- it is what keeps epsilon attainable. Exp. 4 measures the cost \
             of compaction; this is the other half of its justification.",
        "this_is_a_cost_of_being_dynamic":
            "A Bloom filter has one-sided error per tag. The client's `add AND NOT del` \
             rule negates one of the two tests, making the error two-sided at the answer \
             level. The static symmetric-only schemes that filter an XSet -- HXT's Bloom, \
             Doris's XOR filter -- carry no deletion tags and do not pay this.",
    }))
}

/// Everything Exp. 5 needs at **one** value of `E`, prepared once.
///
/// A struct rather than nine arguments because these are not independent knobs:
/// they are one oracle state, computed together, and every ε in the group must
/// see exactly the same one. Passing them separately invited an ε to be measured
/// against a differently-built index, which is the one error an oracle
/// comparison cannot survive.
struct Group {
    client: XtClient,
    honest: HonestXSet,
    probed: Vec<Probed>,
    truth: Vec<Vec<bool>>,
    exact_answers: Vec<BTreeSet<u64>>,
    exact_total: usize,
    closed_epochs: u64,
    x_terms: usize,
}

impl Group {
    fn build(
        docs: &[corpus::Document],
        epochs: u64,
        width: usize,
    ) -> Result<Self, Box<dyn core::error::Error>> {
        let (mut client, honest_server) = build(docs, epochs)?;
        // M10 H9: the 120 stratified queries, not 12. With 12, one dropped
        // document was ~0.2% of the true answer, so a target loss of 1e-3 was
        // below the measurement's resolution and 1e-2 could not be told from
        // noise.
        let qs: Vec<Vec<String>> = stratified_queries(docs, width)
            .into_iter()
            .map(|q| q.terms)
            .collect();

        // Probe once per `E`, so the only variable across a row group is ε.
        let mut probed = Vec::new();
        for q in &qs {
            if let Some(p) = search_full(&mut client, &honest_server, q) {
                probed.push(p);
            }
        }

        // The exact answers, from the oracle — both as bit vectors (probe level)
        // and as document sets (answer level). ⭐ The second of those is what
        // the first version of this experiment was missing.
        let honest = honest_server.xset;
        let truth: Vec<Vec<bool>> = probed
            .iter()
            .map(|p| XSetStore::probe(&honest, &p.transcript))
            .collect();
        let exact_answers: Vec<BTreeSet<u64>> = probed
            .iter()
            .zip(&truth)
            .map(|(p, bits)| {
                client.evaluate(
                    &p.candidates,
                    p.x_terms,
                    &p.map,
                    bits,
                    &Formula::conjunction(p.x_terms),
                )
            })
            .collect();

        let closed_epochs = client.closed_epochs();
        // Every query in this group has the same width, so `n−1` is a constant
        // of the sweep rather than something to average over.
        let x_terms = probed.first().map_or(width - 1, |p| p.x_terms);

        Ok(Self {
            exact_total: exact_answers.iter().map(BTreeSet::len).sum(),
            client,
            honest,
            probed,
            truth,
            exact_answers,
            closed_epochs,
            x_terms,
        })
    }
}

/// ⭐ M10 P3 acceptance for one `(ε, E)` cell: the observed false-positive
/// count must sit inside the 99% two-sided binomial interval of `ε` over the
/// negative probes (normal approximation, `z = 2.576`). Returns the interval
/// and the verdict, recorded per row so the check is read off the record
/// rather than re-derived by hand.
fn fp_acceptance(false_positives: usize, true_negatives: usize, eps: f64) -> (f64, f64, bool) {
    #[expect(
        clippy::cast_precision_loss,
        reason = "probe counts are far below 2^53"
    )]
    let (n, fps) = (
        (false_positives + true_negatives) as f64,
        false_positives as f64,
    );
    let half = 2.576 * (n * eps * (1.0 - eps)).sqrt();
    let (lo, hi) = ((n * eps - half).max(0.0), n * eps + half);
    (lo, hi, (lo..=hi).contains(&fps))
}

/// ⭐ The exponent fitted against the rate the filter **achieved**, not the one
/// it was configured with. With each epoch sized from its own load the two
/// should agree (the P3 acceptance, recorded as `fp_within_ci99`); fitting
/// against the achieved rate keeps the exponent test honest if they ever do
/// not. Returns `(observed rate, fitted exponent, predicted loss at it)`.
fn fit_at_observed_fp(
    false_positives: usize,
    true_negatives: usize,
    dropped: usize,
    retained: f64,
    x_terms: usize,
    closed_epochs: u64,
) -> (f64, Option<f64>, Option<f64>) {
    let denom = false_positives + true_negatives;
    #[expect(
        clippy::cast_precision_loss,
        reason = "probe counts are millions at most, far below 2^53"
    )]
    let observed_fp = if denom == 0 {
        0.0
    } else {
        false_positives as f64 / denom as f64
    };
    if !(observed_fp > 0.0 && observed_fp < 1.0) {
        return (observed_fp, None, None);
    }
    let probes = pqcl_dsse::bloom::del_probes_per_document(x_terms, closed_epochs);
    let pred = 1.0 - (1.0 - observed_fp).powi(i32::try_from(probes).unwrap_or(i32::MAX));
    let fit = if dropped == 0 || retained <= 0.0 {
        None
    } else {
        Some(retained.ln() / (1.0 - observed_fp).ln())
    };
    (observed_fp, fit, Some(pred))
}

/// Probe- and answer-level counts for one ε.
#[derive(Default)]
struct Tally {
    false_positives: usize,
    true_negatives: usize,
    /// The same, over **distinct** `(epoch, tag)` negatives. A tag probed by
    /// several queries is one Bernoulli trial of the filter, not several; the
    /// acceptance test needs independent trials (M10 H9).
    distinct_false_positives: usize,
    distinct_true_negatives: usize,
    false_negatives: usize,
    probes: usize,
    dropped: usize,
    spurious: usize,
    returned_total: usize,
}

impl Group {
    /// Count what one Bloom store gets right and wrong, at both levels.
    fn tally(&self, bloom: &BloomXSet) -> Tally {
        let mut t = Tally::default();
        let mut seen: BTreeSet<pqcl_dsse::xt::XTag> = BTreeSet::new();

        for ((p, want), exact_answer) in
            self.probed.iter().zip(&self.truth).zip(&self.exact_answers)
        {
            let bits = bloom.probe(&p.transcript);
            for ((got, exact), probe) in bits.iter().zip(want).zip(&p.transcript.probes) {
                t.probes += 1;
                if !*exact && seen.insert(*probe) {
                    if *got {
                        t.distinct_false_positives += 1;
                    } else {
                        t.distinct_true_negatives += 1;
                    }
                }
                match (*got, *exact) {
                    (true, false) => t.false_positives += 1,
                    (false, false) => t.true_negatives += 1,
                    // ⛔ Must be zero. A Bloom filter cannot produce a false
                    // negative, so a non-zero count here is a bug in the filter,
                    // not a tuning question.
                    (false, true) => t.false_negatives += 1,
                    (true, true) => {}
                }
            }

            // ⭐ The answer-level count. Before draft8 D3 a probe-level false
            // positive on a `Del` cross-tag made a live document look deleted
            // (`add && !del`) and dropped it silently. Since D3 there are no
            // delete tags and membership is one bit, so a false positive can
            // only ADMIT under the conjunction measured here: `dropped` must
            // now read zero, and a non-zero count is a bug. Under a negated
            // term the same false positive drops a true match (§VII, Bloom),
            // which `tests/bloom_vs_oracle.rs` shows deterministically.
            let answer = self.client.evaluate(
                &p.candidates,
                p.x_terms,
                &p.map,
                &bits,
                &Formula::conjunction(p.x_terms),
            );
            t.dropped += exact_answer.difference(&answer).count();
            t.spurious += answer.difference(exact_answer).count();
            t.returned_total += answer.len();
        }

        assert_eq!(
            t.false_negatives, 0,
            "the Bloom XSet produced {} false negatives, which is impossible \
             for a correct filter",
            t.false_negatives
        );
        t
    }

    /// One ε: build the filter, tally it, and fit the exponent.
    fn bloom_row(&self, eps: f64) -> serde_json::Value {
        // Rebuild the same tags into a Bloom store, each epoch's filter sized
        // from that epoch's own load when sealed — what a deployment does at
        // close. ⛔ M10 P3: this used to size every epoch at the AVERAGE load;
        // the last epoch also carries the deletions, overfilled, and the
        // observed FP rate ran 33x over ε at E = 16.
        let mut bloom = BloomXSet::new(eps);
        for (e, tags) in self.honest.all_epochs() {
            bloom.add_xtags(e, &tags);
        }
        bloom.seal_all();

        let Tally {
            false_positives,
            true_negatives,
            distinct_false_positives,
            distinct_true_negatives,
            false_negatives,
            probes,
            dropped,
            spurious,
            returned_total,
        } = self.tally(&bloom);
        let (exact_total, x_terms, closed_epochs) =
            (self.exact_total, self.x_terms, self.closed_epochs);

        // ⭐ Fit the exponent rather than assume it. `retained = (1−ε)^x` inverts to
        // `x = ln(retained)/ln(1−ε)`, so a measured loss yields the exponent
        // directly. A row that dropped nothing carries no information about `x` —
        // reporting 0 there would drag any aggregate towards a wrong answer, so it
        // reports null instead.
        #[expect(
            clippy::cast_precision_loss,
            reason = "counts here are at most a few thousand documents, far below \
                  the 2^53 where f64 loses integer precision"
        )]
        let retained = if exact_total == 0 {
            1.0
        } else {
            (exact_total - dropped) as f64 / exact_total as f64
        };
        let fitted_exponent = if dropped == 0 || retained <= 0.0 {
            None
        } else {
            Some(retained.ln() / (1.0 - eps).ln())
        };

        let (observed_fp, fitted_exponent_at_observed_fp, predicted_loss_at_observed_fp) =
            fit_at_observed_fp(
                false_positives,
                true_negatives,
                dropped,
                retained,
                x_terms,
                closed_epochs,
            );

        let (_, k) = sizing(1, eps);
        // ⭐ Over distinct tags. Per-probe counts repeat a tag once per query
        // that probes it, so they are overdispersed and a binomial interval over
        // them is too narrow: with 120 stratified queries, 3 of 30 cells fell
        // outside a 99% interval, against ~0.3 expected by chance.
        let (ci_lo, ci_hi, fp_within_ci99) =
            fp_acceptance(distinct_false_positives, distinct_true_negatives, eps);
        let epoch_loads: Vec<usize> = bloom.observed_load().iter().map(|(_, n, _)| *n).collect();
        serde_json::json!({
            "epsilon": eps,
            "closed_epochs": closed_epochs,
            "distinct_false_positives": distinct_false_positives,
            "distinct_true_negatives": distinct_true_negatives,
            "fp_ci99_counts_over": "distinct (epoch, tag) negatives",
            "x_terms": x_terms,

            // The model, and the measurement that either confirms or breaks it.
            "del_probes_per_document":
                pqcl_dsse::bloom::del_probes_per_document(x_terms, closed_epochs),
            "predicted_loss":
                pqcl_dsse::bloom::predicted_loss(eps, x_terms, closed_epochs),
            "observed_loss": 1.0 - retained,
            "fitted_exponent": fitted_exponent,
            "observed_fp_rate": observed_fp,
            "predicted_loss_at_observed_fp": predicted_loss_at_observed_fp,
            "fitted_exponent_at_observed_fp": fitted_exponent_at_observed_fp,
            "max_epsilon_for_1e-3_loss":
                pqcl_dsse::bloom::max_epsilon(1e-3, x_terms, closed_epochs),
            "hash_positions_k": k,
            "epoch_loads": epoch_loads,
            "late_tags": bloom.late_tags(),
            "fp_ci99_count": [ci_lo, ci_hi],
            "fp_within_ci99": fp_within_ci99,
            "total_bits": bloom.total_bits(),
            "bits_per_tag_milli": bloom.bits_per_tag_milli(),
            "exact_bits_per_tag": 256,
            "probes": probes,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives,
            "observed_fp_rate_ppm":
                (false_positives * 1_000_000)
                    .checked_div(true_negatives + false_positives)
                    .unwrap_or(0),

            // Answer level. `answer_dropped` is the one that matters: those are
            // true matches the client never learns about.
            "answer_exact_total": exact_total,
            "answer_returned_total": returned_total,
            "answer_dropped": dropped,
            "answer_spurious": spurious,
            "answer_loss_ppm":
                (dropped * 1_000_000).checked_div(exact_total).unwrap_or(0),
        })
    }
}

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let docs = corpus::load(DOCS)?;
    eprintln!(
        "{} documents, {} pairs",
        docs.len(),
        corpus::pair_count(&docs)
    );

    let selection = corpus::fingerprint(&docs);
    let spec = || RunSpec {
        liboqs_version: "n/a: symmetric-only index path".to_owned(),
        rng_seeds: vec![0x31, 0x32, 0x33],
        dataset_checksums: [("enron-selection".to_owned(), selection.clone())].into(),
        ..RunSpec::default()
    };

    eprintln!("exp3: leakage");
    emit("exp3-leakage", spec(), MIN_ITERATIONS, exp3(&docs)?)?;

    eprintln!("exp4: epoch and compaction");
    emit(
        "exp4-epoch-compaction",
        spec(),
        MIN_ITERATIONS,
        exp4(&docs)?,
    )?;

    eprintln!("exp5: bloom xset");
    emit("exp5-bloom-xset", spec(), MIN_ITERATIONS, exp5(&docs)?)?;

    Ok(())
}
