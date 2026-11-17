//! **Index size, head to head** (M10 H4, `sec:exp-size`).
//!
//! Bytes per keyword–document pair for ours and ODXT, over **the same pairs
//! the Doris structural records measured** — Doris's own `enron_inverted{t}` /
//! `enwiki_inverted{t}` files, tier `t` holding exactly `10^(t+2)` pairs — so
//! these rows sit beside OXT, HXT, `ConjFilter` and Doris from
//! `baselines/doris/results/` without a conversion.
//!
//! # The same convention as those records
//!
//! Doris's `cal_size` sums **occupied** `TSet` slots, each a lookup label plus
//! its value; an exact `XSet` is 32 B per tag and a Bloom one is its bits / 8
//! (`baselines/UPGRADES.md`, "Their size formulas"). So, at canonical widths:
//!
//! * **ours** — `EDB`: 32-B address + sealed value per entry
//!   (`HonestEdb::stored_bytes`); `XSet`: 32 B per cross-tag exact, or the Bloom
//!   store's bits / 8.
//! * **ODXT** — `TSet`: 32-B address + 16-B value + 32-B scalar `α` per entry;
//!   `XSet`: 32-B compressed point per tag exact, or bits / 8 as a Bloom filter
//!   (its paper's choice, §VII).
//!
//! # Which ε, for the Bloom rows
//!
//! ODXT's paper uses a Bloom `XSet` but states no false-positive rate. Each
//! scheme is therefore sized at the ε the **same** answer-loss bound derives
//! for **its own** structure: `max_epsilon(δ, n−1, E)` — ours at `E` closed
//! epochs, ODXT at `E = 1` since it has none. That charges our epochs to us.
//! Rows at Doris's `10⁻⁶` (its OXT/HXT convention) are recorded too.

use std::path::{Path, PathBuf};

use pqcl_bench::{MIN_ITERATIONS, RunSpec};
use pqcl_dsse::bloom::{BloomXSet, max_epsilon};
use pqcl_dsse::core::{Client, Op};
use pqcl_dsse::xt::{HonestServer, XSetStore, XtClient};
use pqcl_exp::emit;
use pqcl_primitives::LAMBDA_BYTES;
use pqcl_primitives::xof::PrfKey;

type Res<T> = Result<T, Box<dyn core::error::Error>>;

/// Doris's `TIER_PAIRS` (`baselines/doris/metrics.py`).
const TIER_PAIRS: [usize; 5] = [100, 1_000, 10_000, 100_000, 1_000_000];

/// Target answer losses for the derived-ε Bloom rows.
const TARGET_LOSSES: &[f64] = &[1e-2, 1e-3];

/// `(n−1, E)` design points for our derived ε: a two-keyword conjunction in
/// one epoch, a three-keyword one across sixteen, and **the operating point
/// the deployment admits** (§1l.1): `n_max = 6` at `tab:params`' `E = 24`.
const OUR_POINTS: &[(usize, u64)] = &[(1, 1), (2, 16), (N_MAX - 1, 24)];

/// The widest conjunction the paper evaluates (`tab:params`' `n_max`).
const N_MAX: usize = 6;

/// Doris's Bloom rate for OXT/HXT, `setup_exp.py:98`.
const DORIS_EPSILON: f64 = 1e-6;

/// Canonical widths, in bytes.
const ADDR: usize = 32;
const ODXT_VAL: usize = 16;
const SCALAR: usize = 32;
const TAG: usize = 32;

fn data_dir() -> PathBuf {
    Path::new("baselines/doris/upstream/data").to_path_buf()
}

/// Doris's inverted file: `keyword,id,id,…` per line.
fn load(dataset: &str, tier: usize) -> Res<Vec<(String, Vec<u64>)>> {
    let path = data_dir().join(format!("{dataset}_inverted{tier}.csv"));
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "{}: {e} (the Doris upstream data must be present)",
            path.display()
        )
    })?;
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.split(',');
        let kw = parts.next().ok_or("empty line")?.to_owned();
        let ids = parts
            .map(|p| {
                p.trim()
                    .parse::<u64>()
                    .map_err(|e| format!("{}: bad id {p:?}: {e}", path.display()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        out.push((kw, ids));
    }
    let pairs: usize = out.iter().map(|(_, ids)| ids.len()).sum();
    if pairs != TIER_PAIRS[tier] {
        return Err(format!(
            "{}: {pairs} pairs, but Doris's tier {tier} is {} -- not the rows the Doris records measured",
            path.display(),
            TIER_PAIRS[tier]
        )
        .into());
    }
    Ok(out)
}

fn bloom_bytes(tags: &[(u64, Vec<pqcl_dsse::xt::XTag>)], eps: f64) -> usize {
    let mut b = BloomXSet::new(eps);
    for (e, t) in tags {
        b.add_xtags(*e, t);
    }
    b.seal_all();
    b.total_bits().div_ceil(8)
}

fn ours(inv: &[(String, Vec<u64>)]) -> Res<serde_json::Value> {
    let mut client = XtClient::new(
        Client::new(PrfKey::new([0x51u8; LAMBDA_BYTES])),
        PrfKey::new([0x52u8; LAMBDA_BYTES]),
        256,
    );
    let mut server = HonestServer::new();
    for (kw, ids) in inv {
        for id in ids {
            client.update(&mut server, Op::Add, kw.as_bytes(), *id)?;
        }
    }
    client.close_epoch(&mut server);
    let tags = server.xset.all_epochs();
    let n_tags: usize = tags.iter().map(|(_, t)| t.len()).sum();
    let edb = server.edb.stored_bytes();
    let mut bloom = Vec::new();
    for &delta in TARGET_LOSSES {
        for &(x, e) in OUR_POINTS {
            let eps = max_epsilon(delta, x, e);
            bloom.push(serde_json::json!({
                "target_loss": delta, "x_terms": x, "closed_epochs": e,
                "epsilon": eps, "xset_bytes": bloom_bytes(&tags, eps),
            }));
        }
    }
    Ok(serde_json::json!({
        "edb_bytes": edb,
        "xset_tags": n_tags,
        "xset_exact_bytes": n_tags * TAG,
        "xset_bloom": bloom,
        "xset_bloom_doris_epsilon_bytes": bloom_bytes(&tags, DORIS_EPSILON),
    }))
}

fn odxt(inv: &[(String, Vec<u64>)]) -> serde_json::Value {
    let sk = baseline_odxt::SecretKey::from_bytes(&[0x53; 128]);
    let mut st = baseline_odxt::ClientState::default();
    let mut edb = baseline_odxt::Edb::new();
    for (kw, ids) in inv {
        for id in ids {
            edb.apply(&baseline_odxt::update(
                &sk,
                &mut st,
                Op::Add,
                *id,
                kw.as_bytes(),
            ));
        }
    }
    let (t, x) = (edb.tset_len(), edb.xset_len());
    // Its XSet elements are curve points, not our tags, but a Bloom filter
    // stores bits, not elements: sized by the same formula over the same count.
    let bloom_bits = |eps: f64| pqcl_dsse::bloom::sizing(x, eps).0.div_ceil(8);
    let bloom: Vec<serde_json::Value> = TARGET_LOSSES
        .iter()
        .map(|&delta| {
            // ODXT has no epochs: the same n_max, at E = 1.
            let eps = max_epsilon(delta, N_MAX - 1, 1);
            serde_json::json!({"target_loss": delta, "x_terms": N_MAX - 1, "closed_epochs": 1,
                               "epsilon": eps, "xset_bytes": bloom_bits(eps)})
        })
        .collect();
    serde_json::json!({
        "tset_entries": t,
        "tset_bytes": t * (ADDR + ODXT_VAL + SCALAR),
        "xset_tags": x,
        "xset_exact_bytes": x * TAG,
        "xset_bloom": bloom,
        "xset_bloom_doris_epsilon_bytes": bloom_bits(DORIS_EPSILON),
    })
}

/// M14: `SDSSE-CQ` or `-S`, counted from a real build. This corpus deletes
/// nothing, so each filter has its floor size.
fn sdsse(inv: &[(String, Vec<u64>)], variant: baseline_sdsse_cq::Variant) -> serde_json::Value {
    use rand::SeedableRng as _;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x54);
    let mut client =
        baseline_sdsse_cq::Client::setup(variant, &[0x54; 32], std::collections::HashMap::new());
    let mut server = baseline_sdsse_cq::Server::default();
    for (kw, ids) in inv {
        for id in ids {
            client.update(&mut server, Op::Add, kw.as_bytes(), *id, &mut rng);
        }
    }
    let (t_entries, x_entries) = server.entries();
    let (t_bytes, x_bytes) = server.stored_bytes();
    serde_json::json!({
        "tset_entries": t_entries,
        "tset_bytes": t_bytes,
        "xset_entries": x_entries,
        "xset_bytes": x_bytes,
        "client_bytes": client.client_bytes(),
    })
}

/// Doris's own record for this cell, `(tset_bytes, xset_bytes)`, if it has one.
fn doris_record(dataset: &str, tier: usize) -> Res<Option<(u64, u64)>> {
    for name in ["doris-structural.json", "doris-structural-tier4.json"] {
        let path = Path::new("baselines/doris/results").join(name);
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        let rows = v
            .get("rows")
            .or_else(|| v.get("measurements").and_then(|m| m.get("rows")))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("{}: no rows", path.display()))?;
        for r in rows {
            if r["scheme"] == "Doris" && r["dataset"] == dataset && r["tier"] == tier {
                let get = |k: &str| r[k].as_u64().ok_or_else(|| format!("{name}: no {k}"));
                return Ok(Some((get("tset_bytes")?, get("xset_bytes")?)));
            }
        }
    }
    Ok(None)
}

/// M14 B-3: the Doris follow-up, counted from a real filter, twice under different
/// keys and seeds as the determinism check, and against Doris's own record for the
/// same pairs: both have one `e` per pair and the same `XSet` below `10⁷` tags.
///
/// ⛔ No use of the Doris carve-out (§1cs.5 item 6). This is our reimplementation;
/// it runs here and goes through the pipeline. Doris's record is only compared with.
fn doris_fu(inv: &[(String, Vec<u64>)], dataset: &str, tier: usize) -> Res<serde_json::Value> {
    let a = baseline_doris_fu::count(inv, &[0x55; 32], 0x55).ok_or("XEBFF would not peel")?;
    let b = baseline_doris_fu::count(inv, &[0x56; 32], 0x56).ok_or("XEBFF would not peel")?;
    if (a.tset_bytes, a.xset_tags, a.xset_bytes) != (b.tset_bytes, b.xset_tags, b.xset_bytes) {
        return Err(
            format!("{dataset} tier {tier}: counts differ between keys: {a:?} {b:?}").into(),
        );
    }
    let doris = doris_record(dataset, tier)?;
    if let Some((tset, xset)) = doris {
        if a.tset_bytes as u64 != tset {
            return Err(format!(
                "{dataset} tier {tier}: TSet {} B against Doris's {tset} B",
                a.tset_bytes
            )
            .into());
        }
        // Below 10^7 tags both are 1.23|S| + 32 slots. Doris's tags are not quite
        // the same set: `prf(kx, w + w_tmp + str(i))` concatenates with no framing,
        // so a few distinct triples collide and its `|S|` runs slightly lower (14
        // of 2.1M at Enron tier 3). A gap beyond 0.1% would be a real difference.
        if a.xset_tags < baseline_doris_fu::BFF_THRESHOLD
            && (a.xset_bytes as u64).abs_diff(xset) > (xset / 1000).max(64)
        {
            return Err(format!(
                "{dataset} tier {tier}: XSet {} B against Doris's {xset} B",
                a.xset_bytes
            )
            .into());
        }
    }
    Ok(serde_json::json!({
        "tset_entries": a.tset_entries,
        "tset_bytes": a.tset_bytes,
        "xset_tags": a.xset_tags,
        "filter_slots": a.filter_slots,
        "segments": a.segments,
        "xset_bytes": a.xset_bytes,
        "attempts": [a.attempts, b.attempts],
        "determinism": "two builds under different keys and seeds gave these counts",
        "doris_record": doris.map(|(t, x)| serde_json::json!({"tset_bytes": t, "xset_bytes": x})),
    }))
}

/// The first `pairs` (keyword, document) pairs of an inverted file, in file
/// order: whole keyword lines, then a prefix of the line that crosses the
/// count. §1q.2's 1-2-5 points between Doris's decade tiers come from the
/// **next** tier's real rows, truncated, never from generated data.
fn truncate(inv: &[(String, Vec<u64>)], pairs: usize) -> Vec<(String, Vec<u64>)> {
    let mut out = Vec::new();
    let mut left = pairs;
    for (kw, ids) in inv {
        if left == 0 {
            break;
        }
        let take = ids.len().min(left);
        out.push((kw.clone(), ids[..take].to_vec()));
        left -= take;
    }
    out
}

/// §1q.2's intermediate steps per decade, ×2 and ×5.
const STEPS: [usize; 2] = [2, 5];

fn main() -> Res<()> {
    let tiers: Vec<usize> = std::env::var("PQCL_SIZE_TIERS").map_or_else(
        |_| (0..TIER_PAIRS.len()).collect(),
        |s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
    );
    let mut rows = Vec::new();
    for dataset in ["enron", "enwiki"] {
        for &tier in &tiers {
            let inv = load(dataset, tier)?;
            eprintln!("{dataset} tier {tier}: {} pairs", TIER_PAIRS[tier]);
            rows.push(serde_json::json!({
                "dataset": dataset,
                "tier": tier,
                "pairs": TIER_PAIRS[tier],
                "keywords": inv.len(),
                "ours": ours(&inv)?,
                "odxt": odxt(&inv),
                "sdsse_cq": sdsse(&inv, baseline_sdsse_cq::Variant::Cq),
                "sdsse_cq_s": sdsse(&inv, baseline_sdsse_cq::Variant::CqS),
                "doris_fu": doris_fu(&inv, dataset, tier)?,
            }));
            // 1-2-5 per decade (§1q.2): ×2 and ×5 of this tier, cut from the
            // next tier's file. Ours and ODXT only; Doris's family stays on its
            // own tier files.
            if tier + 1 < TIER_PAIRS.len() {
                let next = load(dataset, tier + 1)?;
                for step in STEPS {
                    let pairs = TIER_PAIRS[tier] * step;
                    let cut = truncate(&next, pairs);
                    let got: usize = cut.iter().map(|(_, ids)| ids.len()).sum();
                    if got != pairs {
                        return Err(format!(
                            "{dataset}: cut {got} pairs from tier {}, wanted {pairs}",
                            tier + 1
                        )
                        .into());
                    }
                    eprintln!("{dataset} {pairs} pairs (tier {} truncated)", tier + 1);
                    rows.push(serde_json::json!({
                        "dataset": dataset,
                        "tier": null,
                        "truncated_from_tier": tier + 1,
                        "pairs": pairs,
                        "keywords": cut.len(),
                        "ours": ours(&cut)?,
                        "odxt": odxt(&cut),
                        "sdsse_cq": sdsse(&cut, baseline_sdsse_cq::Variant::Cq),
                        "sdsse_cq_s": sdsse(&cut, baseline_sdsse_cq::Variant::CqS),
                    }));
                }
            }
        }
    }
    let measurements = serde_json::json!({
        "rows": rows,
        "convention": "Doris's: occupied TSet/EDB entries at label + value, exact XSet 32 B per tag, Bloom XSet bits/8, canonical widths",
        "widths_bytes": {"addr": ADDR, "odxt_val": ODXT_VAL, "odxt_alpha": SCALAR, "tag": TAG},
        "source_pairs": "baselines/doris/upstream/data/{dataset}_inverted{tier}.csv, checked equal to Doris's TIER_PAIRS; the x2 and x5 rows are the next tier's file truncated to its first pairs, in file order",
        "bloom_epsilon": "each scheme at max_epsilon(delta, n-1, E) for its own structure; ODXT has no epochs (E = 1); ODXT's paper states no rate",
        "sizes_are_structural": "byte counts, deterministic; no wall clock is reported here",
    });
    emit(
        "index-size",
        RunSpec {
            liboqs_version: "n/a: index structures only".to_owned(),
            rng_seeds: vec![0x51, 0x52, 0x53, 0x54, 0x55, 0x56],
            ..RunSpec::default()
        },
        MIN_ITERATIONS,
        measurements,
    )?;
    Ok(())
}
