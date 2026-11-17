//! M10 H1 — the published schemes ingesting **the same event stream** as ours.
//!
//! Experiment 1 is now head-to-head (`sec:exp-ingest`): ODXT indexes each
//! event's keywords, Zuo'22 its numeric attributes at the **same tree depths**
//! as ours, and the composed pass does both per event — the only way the
//! baselines answer our query class, and still not a keyword ∧ range
//! conjunction (the paper footnotes that).
//!
//! ⛔ **Every pass is validated against the plaintext oracle before it is
//! timed**: a fast, wrong baseline is a strawman in
//! our favour. The `validate_*` functions build once, query, and compare with
//! the oracle; `exp1` refuses to time a baseline whose validation failed.
//!
//! Single-threaded, like every head-to-head throughput (`par:workload` (iii)).

use std::collections::{BTreeMap, BTreeSet};

use baseline_dsse_skq as skq;
use baseline_odxt as odxt;
use baseline_sdsse_cq as sdsse;
use baseline_zuo22 as zuo;
use pqcl_dsse::core::Op;
use rand::SeedableRng;
use rand::rngs::StdRng;

/// ODXT's key material. Fixed so runs are reproducible; the value does not
/// affect cost.
const ODXT_KEY: [u8; 128] = [0x21; 128];

/// Seed for ODXT's search-token permutation and Zuo'22's update randomness.
pub const BASELINE_RNG_SEED: u64 = 0x5EED_0001;

/// ODXT after ingest: what its client keeps and what its server holds.
pub struct OdxtBuilt {
    sk: odxt::SecretKey,
    st: odxt::ClientState,
    edb: odxt::Edb,
    /// Keyword–document pairs indexed — one update each.
    pub pairs: usize,
}

/// ODXT's `Update` for every keyword of every event, document id = event index.
#[must_use]
pub fn odxt_ingest(keywords: &[Vec<String>]) -> OdxtBuilt {
    let sk = odxt::SecretKey::from_bytes(&ODXT_KEY);
    let mut st = odxt::ClientState::default();
    let mut edb = odxt::Edb::new();
    let mut pairs = 0usize;
    for (i, kws) in keywords.iter().enumerate() {
        for w in kws {
            let t = odxt::update(&sk, &mut st, Op::Add, i as u64, w.as_bytes());
            edb.apply(&t);
            pairs += 1;
        }
    }
    OdxtBuilt { sk, st, edb, pairs }
}

impl ZuoBuilt {
    /// Server bytes over every attribute's `EDB` (`zuo::Edb::stored_bytes`).
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.edbs.iter().map(zuo::Edb::stored_bytes).sum()
    }
}

/// Zuo'22 after ingest: one client and server per numeric attribute.
pub struct ZuoBuilt {
    clients: Vec<zuo::Client>,
    edbs: Vec<zuo::Edb>,
    /// Attribute values indexed — one `Update` (a root-to-leaf path) each.
    pub values: usize,
    /// Tree nodes updated, `Σ |TPath(v)|` — `depth + 1` per value, the same
    /// count as our prefix keywords at the same depth. The query-class guard
    /// compares the two.
    pub nodes: usize,
}

/// Zuo'22's `Update` for every numeric attribute of every event: one tree per
/// attribute over `[0, domain)`, bitmap width = the stream's event count.
///
/// # Panics
///
/// If a value lies outside its attribute's domain — a malformed stream, which
/// Zuo'22's own `update` also refuses.
#[must_use]
pub fn zuo_ingest(numerics: &[Vec<u64>], domains: &[u64]) -> ZuoBuilt {
    let y = numerics.len();
    let mut rng = StdRng::seed_from_u64(BASELINE_RNG_SEED);
    let mut clients: Vec<zuo::Client> = domains
        .iter()
        .enumerate()
        .map(|(a, d)| zuo::Client::setup([0x30 + u8::try_from(a).unwrap_or(0); 32], *d, y))
        .collect();
    let mut edbs: Vec<zuo::Edb> = domains.iter().map(|_| zuo::Edb::new()).collect();
    let (mut values, mut nodes) = (0usize, 0usize);
    for (i, vs) in numerics.iter().enumerate() {
        let delta = zuo::BitString::insert_delta(y, i);
        for ((client, edb), v) in clients.iter_mut().zip(edbs.iter_mut()).zip(vs) {
            let msgs = client.update(*v, &delta, &mut rng);
            zuo::server_update(edb, &msgs);
            values += 1;
            nodes += msgs.len();
        }
    }
    ZuoBuilt {
        clients,
        edbs,
        values,
        nodes,
    }
}

/// ODXT and Zuo'22 **per event**, in one loop: the composed baseline.
#[must_use]
pub fn composed_ingest(
    keywords: &[Vec<String>],
    numerics: &[Vec<u64>],
    domains: &[u64],
) -> (OdxtBuilt, ZuoBuilt) {
    let sk = odxt::SecretKey::from_bytes(&ODXT_KEY);
    let mut st = odxt::ClientState::default();
    let mut edb = odxt::Edb::new();
    let y = numerics.len();
    let mut rng = StdRng::seed_from_u64(BASELINE_RNG_SEED);
    let mut clients: Vec<zuo::Client> = domains
        .iter()
        .enumerate()
        .map(|(a, d)| zuo::Client::setup([0x30 + u8::try_from(a).unwrap_or(0); 32], *d, y))
        .collect();
    let mut edbs: Vec<zuo::Edb> = domains.iter().map(|_| zuo::Edb::new()).collect();
    let (mut pairs, mut values, mut nodes) = (0usize, 0usize, 0usize);
    for (i, (kws, vs)) in keywords.iter().zip(numerics).enumerate() {
        for w in kws {
            edb.apply(&odxt::update(&sk, &mut st, Op::Add, i as u64, w.as_bytes()));
            pairs += 1;
        }
        let delta = zuo::BitString::insert_delta(y, i);
        for ((client, zedb), v) in clients.iter_mut().zip(edbs.iter_mut()).zip(vs) {
            let msgs = client.update(*v, &delta, &mut rng);
            zuo::server_update(zedb, &msgs);
            values += 1;
            nodes += msgs.len();
        }
    }
    (
        OdxtBuilt { sk, st, edb, pairs },
        ZuoBuilt {
            clients,
            edbs,
            values,
            nodes,
        },
    )
}

/// Validate ODXT against the plaintext oracle: every single keyword of the
/// first `sample` events, plus the conjunction of each such event's first two
/// keywords. Returns the number of queries checked.
///
/// # Errors
///
/// The first query whose answer differs from the oracle, named.
pub fn validate_odxt(
    keywords: &[Vec<String>],
    built: &OdxtBuilt,
    sample: usize,
) -> Result<usize, String> {
    let mut oracle: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
    for (i, kws) in keywords.iter().enumerate() {
        for w in kws {
            oracle.entry(w.as_str()).or_default().insert(i as u64);
        }
    }
    let mut rng = StdRng::seed_from_u64(BASELINE_RNG_SEED);
    let mut checked = 0usize;
    for kws in keywords.iter().take(sample) {
        let mut queries: Vec<Vec<&str>> = kws.iter().map(|w| vec![w.as_str()]).collect();
        if kws.len() >= 2 {
            queries.push(vec![kws[0].as_str(), kws[1].as_str()]);
        }
        for q in queries {
            let want: BTreeSet<u64> = q
                .iter()
                .map(|w| oracle.get(w).cloned().unwrap_or_default())
                .reduce(|a, b| a.intersection(&b).copied().collect())
                .unwrap_or_default();
            let qb: Vec<Vec<u8>> = q.iter().map(|w| w.as_bytes().to_vec()).collect();
            let got = odxt::search(&built.sk, &built.st, &built.edb, &qb, &mut rng);
            if got != want {
                return Err(format!(
                    "ODXT disagrees with the oracle on {q:?}: {} results, oracle {}",
                    got.len(),
                    want.len()
                ));
            }
            checked += 1;
        }
    }
    Ok(checked)
}

/// Validate Zuo'22 against the plaintext oracle. Per attribute: a point
/// query on event 0's value, the full domain, and the quarter-, half- and
/// mid-domain ranges. Returns the number of range queries **answered**.
///
/// Zuo'22 returns `⊥` when any node of the best range cover was never updated
/// (Algorithm 2 lines 5–7, `baselines/UPGRADES.md` Zuo'22 item 2). That is
/// faithful, so a `⊥` is accepted **only** when the oracle confirms a cover
/// node with no value beneath it; a `⊥` over a fully-populated cover is a bug.
/// At least two queries per attribute must be answered, or the check has
/// checked nothing.
///
/// ⚠️ Zuo'22's search is destructive (it compacts the walked nodes), so this
/// consumes `built`. Validation runs on its own build, never on a timed one.
///
/// # Errors
///
/// The first range whose answer differs from the oracle, an unjustified `⊥`,
/// or an attribute with too few answered queries — each named.
pub fn validate_zuo(
    numerics: &[Vec<u64>],
    domains: &[u64],
    mut built: ZuoBuilt,
) -> Result<usize, String> {
    let mut answered = 0usize;
    for (a, d) in domains.iter().enumerate() {
        let column: Vec<u64> = numerics
            .iter()
            .filter_map(|vs| vs.get(a).copied())
            .collect();
        let v0 = column.first().copied().unwrap_or(0);
        let ranges = [
            (v0, v0),
            (0, d - 1),
            (0, d / 4),
            (0, d / 2),
            (d / 3, (2 * d / 3).max(d / 3)),
        ];
        let mut here = 0usize;
        for (lo, hi) in ranges {
            let want: BTreeSet<usize> = numerics
                .iter()
                .enumerate()
                .filter(|(_, vs)| vs.get(a).is_some_and(|v| (lo..=hi).contains(v)))
                .map(|(i, _)| i)
                .collect();
            if let Some(bs) = built.clients[a].search(lo, hi, &mut built.edbs[a]) {
                let got: BTreeSet<usize> = bs.files().into_iter().collect();
                if got != want {
                    return Err(format!(
                        "Zuo'22 disagrees with the oracle on attribute {a}, [{lo}, {hi}]: {} results, oracle {}",
                        got.len(),
                        want.len()
                    ));
                }
                here += 1;
            } else {
                let justified = built.clients[a]
                    .tree()
                    .cover(lo, hi)
                    .iter()
                    .any(|n| !column.iter().any(|v| (n.a..=n.b).contains(v)));
                if !justified {
                    return Err(format!(
                        "Zuo'22 returned ⊥ on attribute {a}, [{lo}, {hi}], but every cover node holds a value"
                    ));
                }
            }
        }
        if here < 2 {
            return Err(format!(
                "Zuo'22 answered only {here} of {} queries on attribute {a}: the check checked nothing",
                ranges.len()
            ));
        }
        answered += here;
    }
    Ok(answered)
}

/// `SDSSE-CQ` or `SDSSE-CQ-S` after ingest.
pub struct SdsseBuilt {
    /// The client.
    pub client: sdsse::Client,
    /// The server.
    pub server: sdsse::Server,
    /// Keyword–document pairs indexed.
    pub pairs: usize,
}

/// `Update` for every keyword of every event, document id = event index.
///
/// This stream deletes nothing, so every filter has the floor size.
#[must_use]
pub fn sdsse_ingest(variant: sdsse::Variant, keywords: &[Vec<String>]) -> SdsseBuilt {
    let mut rng = StdRng::seed_from_u64(BASELINE_RNG_SEED);
    let mut client = sdsse::Client::setup(variant, &[0x2C; 32], std::collections::HashMap::new());
    let mut server = sdsse::Server::default();
    let mut pairs = 0usize;
    for (i, kws) in keywords.iter().enumerate() {
        for w in kws {
            client.update(&mut server, Op::Add, w.as_bytes(), i as u64, &mut rng);
            pairs += 1;
        }
    }
    SdsseBuilt {
        client,
        server,
        pairs,
    }
}

/// Validate SDSSE against the plaintext oracle, as [`validate_odxt`] does ODXT:
/// every keyword of the first `sample` events alone, and each such event's first
/// two keywords together. Destructive, so on its own build.
///
/// A single keyword is searched as a one-term conjunction, whose x-term list is
/// empty and which returns the s-term's whole list.
///
/// # Errors
///
/// A query whose answer differs from the oracle. A Bloom false positive could
/// only lose a result, so a shortfall is named here as an error too: at this
/// stream's size, with a deletion filter holding one tag at most, it means a bug.
pub fn validate_sdsse(
    keywords: &[Vec<String>],
    built: &mut SdsseBuilt,
    sample: usize,
) -> Result<usize, String> {
    let mut oracle: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
    for (i, kws) in keywords.iter().enumerate() {
        for w in kws {
            oracle.entry(w.as_str()).or_default().insert(i as u64);
        }
    }
    let mut rng = StdRng::seed_from_u64(BASELINE_RNG_SEED);
    let mut checked = 0usize;
    for kws in keywords.iter().take(sample) {
        let mut queries: Vec<Vec<&str>> = kws.iter().map(|w| vec![w.as_str()]).collect();
        if kws.len() >= 2 {
            queries.push(vec![kws[0].as_str(), kws[1].as_str()]);
        }
        for q in queries {
            let want: BTreeSet<u64> = q
                .iter()
                .map(|w| oracle.get(w).cloned().unwrap_or_default())
                .reduce(|a, b| a.intersection(&b).copied().collect())
                .unwrap_or_default();
            let qb: Vec<Vec<u8>> = q.iter().map(|w| w.as_bytes().to_vec()).collect();
            let got = built.client.search(&mut built.server, &qb, &mut rng);
            if got != want {
                return Err(format!(
                    "SDSSE disagrees with the oracle on {q:?}: {} results, oracle {}",
                    got.len(),
                    want.len()
                ));
            }
            checked += 1;
        }
    }
    Ok(checked)
}

/// `DSSE_SKQ` after ingest.
pub struct SkqBuilt {
    /// The client.
    pub client: skq::Client,
    /// The server.
    pub edb: skq::Edb,
    /// Keyword–document pairs indexed.
    pub pairs: usize,
    /// Prefix labels updated: one per tree node, the count ours and Zuo'22 have.
    pub nodes: usize,
}

/// `Update` per event: one scheme indexing the keywords and every numeric
/// attribute. Bitmap width = the stream's event count, as Zuo'22 has it.
#[must_use]
pub fn skq_ingest(keywords: &[Vec<String>], numerics: &[Vec<u64>], domains: &[u64]) -> SkqBuilt {
    let y = keywords.len().max(numerics.len());
    let mut client = skq::Client::setup([0x3C; 32], y, domains);
    let mut edb = skq::Edb::default();
    let (mut pairs, mut nodes) = (0usize, 0usize);
    let empty_kw: Vec<String> = Vec::new();
    let empty_num: Vec<u64> = Vec::new();
    for i in 0..y {
        let kws = keywords.get(i).unwrap_or(&empty_kw);
        let vs = numerics.get(i).unwrap_or(&empty_num);
        let points: Vec<(usize, u64)> = vs.iter().copied().enumerate().collect();
        let words: Vec<&[u8]> = kws.iter().map(String::as_bytes).collect();
        let msgs = client.update(&points, &words, &skq::BitString::insert_delta(y, i));
        pairs += words.len();
        nodes += msgs.len() - words.len();
        edb.apply(msgs);
    }
    SkqBuilt {
        client,
        edb,
        pairs,
        nodes,
    }
}

/// Validate `DSSE_SKQ` against the plaintext oracle: a keyword of each of the
/// first `sample` events, then per attribute the ranges [`validate_zuo`] uses,
/// alone and with a keyword (the conjunction no composed baseline could answer).
///
/// `return ∅` is accepted only where a cover node truly has no value beneath it.
///
/// # Errors
///
/// The first query whose answer differs from the oracle, or an unjustified `∅`.
#[allow(clippy::single_match_else)] // both arms are long, and read as the two outcomes
pub fn validate_skq(
    keywords: &[Vec<String>],
    numerics: &[Vec<u64>],
    domains: &[u64],
    built: &mut SkqBuilt,
    sample: usize,
) -> Result<usize, String> {
    let mut oracle: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
    for (i, kws) in keywords.iter().enumerate() {
        for w in kws {
            oracle.entry(w.as_str()).or_default().insert(i);
        }
    }
    let mut checked = 0usize;
    for kws in keywords.iter().take(sample) {
        for w in kws {
            let got = skq::search(&built.client, &mut built.edb, None, &[w.as_bytes()])
                .ok_or_else(|| format!("DSSE_SKQ: a keyword it indexed came back empty: {w}"))?;
            let have: BTreeSet<usize> = got.1[0].files().into_iter().collect();
            if Some(&have) != oracle.get(w.as_str()) {
                return Err(format!("DSSE_SKQ disagrees with the oracle on keyword {w}"));
            }
            checked += 1;
        }
    }
    let probe = keywords.first().and_then(|k| k.first());
    for (a, d) in domains.iter().enumerate() {
        let column: Vec<u64> = numerics
            .iter()
            .filter_map(|vs| vs.get(a).copied())
            .collect();
        let v0 = column.first().copied().unwrap_or(0);
        for (lo, hi) in [(v0, v0), (0, d - 1), (0, d / 4), (0, d / 2)] {
            let in_range = |i: &usize| {
                numerics
                    .get(*i)
                    .and_then(|vs| vs.get(a))
                    .is_some_and(|v| (lo..=hi).contains(v))
            };
            let words: Vec<&[u8]> = probe.iter().map(|w| w.as_bytes()).collect();
            match skq::search(&built.client, &mut built.edb, Some((a, lo, hi)), &words) {
                Some((br, bw)) => {
                    let range: BTreeSet<usize> = br.files().into_iter().collect();
                    let want: BTreeSet<usize> =
                        (0..numerics.len()).filter(|i| in_range(i)).collect();
                    if range != want {
                        return Err(format!("DSSE_SKQ disagrees on attribute {a}, [{lo}, {hi}]"));
                    }
                    if let (Some(w), Some(bw0)) = (probe, bw.first()) {
                        let both: BTreeSet<usize> =
                            skq::and(&br, bw0).files().into_iter().collect();
                        let want_both: BTreeSet<usize> = oracle
                            .get(w.as_str())
                            .into_iter()
                            .flatten()
                            .copied()
                            .filter(|i| in_range(i))
                            .collect();
                        if both != want_both {
                            return Err(format!(
                                "DSSE_SKQ disagrees on {w} AND attribute {a} in [{lo}, {hi}]"
                            ));
                        }
                    }
                    checked += 1;
                }
                None => {
                    let tree = zuo::BinaryTree::new(*d);
                    let justified = tree
                        .cover(lo, hi)
                        .iter()
                        .any(|n| !column.iter().any(|v| (n.a..=n.b).contains(v)));
                    if !justified {
                        return Err(format!(
                            "DSSE_SKQ returned empty on attribute {a}, [{lo}, {hi}], but every cover node holds a value"
                        ));
                    }
                }
            }
        }
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream() -> (Vec<Vec<String>>, Vec<Vec<u64>>, Vec<u64>) {
        let keywords: Vec<Vec<String>> = (0..40u64)
            .map(|i| {
                (0..4)
                    .map(|k| format!("w{}", (i * 7 + k * 3) % 23))
                    .collect()
            })
            .collect();
        let numerics: Vec<Vec<u64>> = (0..40u64)
            .map(|i| vec![(i * 13) % 256, (i * 5) % 64])
            .collect();
        (keywords, numerics, vec![256, 64])
    }

    #[test]
    fn odxt_passes_its_oracle_check() {
        let (kw, _, _) = stream();
        let built = odxt_ingest(&kw);
        assert_eq!(built.pairs, 160);
        assert!(validate_odxt(&kw, &built, 10).expect("ODXT agrees with the oracle") >= 40);
    }

    #[test]
    fn zuo_passes_its_oracle_check() {
        let (_, num, dom) = stream();
        let built = zuo_ingest(&num, &dom);
        assert_eq!(built.values, 80);
        assert_eq!(built.nodes, 40 * (9 + 7), "depth + 1 nodes per value");
        let answered = validate_zuo(&num, &dom, built).expect("Zuo'22 agrees with the oracle");
        assert!(answered >= 4, "only {answered} queries answered");
    }

    /// A `⊥` over a cover whose nodes all hold values is a bug, and the check
    /// must say so rather than accept it as Zuo'22's faithful abort.
    #[test]
    fn an_unjustified_bottom_fails_validation() {
        let (_, num, dom) = stream();
        // Every event built at event 0's value, validated against the real
        // stream: cover nodes the oracle sees as populated were never updated.
        let collapsed = vec![num[0].clone(); num.len()];
        assert!(validate_zuo(&num, &dom, zuo_ingest(&collapsed, &dom)).is_err());
    }

    #[test]
    fn the_composed_pass_builds_both_correctly() {
        let (kw, num, dom) = stream();
        let (o, z) = composed_ingest(&kw, &num, &dom);
        validate_odxt(&kw, &o, 10).expect("composed ODXT agrees");
        validate_zuo(&num, &dom, z).expect("composed Zuo'22 agrees");
    }

    /// ⭐ The oracle check must be able to fail, or it is not a check.
    #[test]
    fn a_wrong_baseline_fails_validation() {
        let (kw, num, dom) = stream();
        let mut wrong_kw = kw.clone();
        wrong_kw[0].clear(); // ODXT built without event 0's keywords
        assert!(validate_odxt(&kw, &odxt_ingest(&wrong_kw), 10).is_err());
        let mut wrong_num = num.clone();
        wrong_num[0] = vec![255, 63]; // Zuo'22 built with event 0 moved
        assert!(validate_zuo(&num, &dom, zuo_ingest(&wrong_num, &dom)).is_err());
    }

    /// M14: the SDSSE check passes on a faithful build and fails on a wrong one,
    /// for both arms, or `exp1` and `exp2`'s guard checks nothing.
    #[test]
    fn sdsse_passes_its_oracle_check_and_a_wrong_build_fails_it() {
        let (kw, _, _) = stream();
        for variant in [sdsse::Variant::Cq, sdsse::Variant::CqS] {
            let mut built = sdsse_ingest(variant, &kw);
            assert_eq!(built.pairs, 160);
            let checked =
                validate_sdsse(&kw, &mut built, 10).expect("SDSSE agrees with the oracle");
            assert_eq!(
                checked, 50,
                "{variant:?}: four keywords and one conjunction per event"
            );
            let mut wrong_kw = kw.clone();
            wrong_kw[0].clear(); // built without event 0's keywords
            assert!(validate_sdsse(&kw, &mut sdsse_ingest(variant, &wrong_kw), 10).is_err());
        }
    }

    /// M14: the same for `DSSE_SKQ`, on its keyword half and its range half.
    #[test]
    fn skq_passes_its_oracle_check_and_a_wrong_build_fails_it() {
        let (kw, num, dom) = stream();
        let mut built = skq_ingest(&kw, &num, &dom);
        assert_eq!(built.pairs, 160);
        assert_eq!(
            built.nodes,
            40 * (9 + 7),
            "the same tree depths as Zuo'22 and ours"
        );
        let checked =
            validate_skq(&kw, &num, &dom, &mut built, 10).expect("DSSE_SKQ agrees with the oracle");
        assert!(checked >= 40, "only {checked} queries checked");
        let mut wrong_kw = kw.clone();
        wrong_kw[0].clear();
        assert!(validate_skq(&kw, &num, &dom, &mut skq_ingest(&wrong_kw, &num, &dom), 10).is_err());
        let mut wrong_num = num.clone();
        wrong_num[0] = vec![255, 63];
        assert!(validate_skq(&kw, &num, &dom, &mut skq_ingest(&kw, &wrong_num, &dom), 10).is_err());
    }
}
