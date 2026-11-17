//! **Experiment 9 — court-ordered redaction against ODXT** (`sec:exp-redaction`,
//! the design record). Not `exp8910`'s internal "Experiment 9".
//!
//! **Job:** make a redacted document unfindable in a dynamic conjunctive index,
//! including by an adversary who later obtains the **current** key state and
//! every piece of server state ever retained. **Comparator:** ODXT
//! (`baselines/odxt`, Rust, same host, same primitives), in **two rows**, both
//! required for fairness:
//!
//! * **ODXT `del`** — one deletion update per pair. Fast, erases nothing: the
//!   cross-tags stay in `XSet` and the keys that confirm them are current.
//! * **ODXT rebuild** — ODXT's honest route to the same guarantee: `Setup` over
//!   the live pairs under fresh keys, the old ones destroyed. No compaction is
//!   added to ODXT; it is not in its paper (`baselines/UPGRADES.md`).
//!
//! Against ours under each scope, through `pqcl_pipeline::redaction::execute`
//! (the gate included: `σ_CO` verified, the order recorded, the target proved).
//!
//! # Fixed before measuring (rules 20 and 21)
//!
//! * Case size in `(w, id)` pairs on Exp. 3's axis from 10³ to 10⁶: Doris's
//!   Enron tiers 1–4, the files `size` reads. Operating point **10⁵, k = 1**.
//! * Sweep `k ∈ {1, 10, 10², 10³}` capsules under one `FULL` order, at 10⁵.
//! * Our index closes an epoch every `pairs / E` updates, `E = 24`
//!   (`tab:params`); `β = 256` as Exp. 3–5.
//! * The redacted document: among documents with at least two keywords, the
//!   median keyword count, ties to the lowest id. The sweep's `k` documents:
//!   a seeded shuffle of all documents, first `k`, always including that one.
//! * **Residual**: redacted `(w, id)` pairs the adversary above can confirm — a
//!   pair counts if any cross-tag derivable from the current key state is in a
//!   retained or current `XSet`. **Search after**: one surviving conjunctive
//!   query, the redacted document's two keywords of highest document frequency.
//! * Detection matrix: `N = 100` deletions per cell, half under a recorded
//!   order; a compromised AIS appends an entry for every unauthorised deletion
//!   to any list it can write (for ours: forged orders under its own key, their
//!   `0x05` leaves, and `DISPOSE`s referencing them).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use baseline_odxt as odxt;
use pqcl_bench::{MIN_ITERATIONS, RunSpec};
use pqcl_capsule::redaction::{Mode, Order, Scope, Target};
use pqcl_dsse::core::{Client, DocId, Op};
use pqcl_dsse::{Formula, HonestServer, XSetStore, XTag, XtClient};
use pqcl_exp::{emit, stats::Summary};
use pqcl_pipeline::redaction::{
    AnchoredPayload, ClaimedOrder, DisposalClaim, Openings, PayloadStore, Redactee, Unaccounted,
    account, execute,
};
use pqcl_primitives::kem;
use pqcl_primitives::xof::{Digest32, PrfKey, digest256};
use pqcl_primitives::{Signer, SoftwareMlDsa};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

type Res<T> = Result<T, Box<dyn core::error::Error>>;

/// Doris's `TIER_PAIRS`, as `size` checks them.
const TIER_PAIRS: [usize; 5] = [100, 1_000, 10_000, 100_000, 1_000_000];
/// Exp. 3's axis from 10³ up; `PQCL_EXP9_TIERS` overrides (smoke only).
const TIERS: &[usize] = &[1, 2, 3, 4];
/// The table's operating point, 10⁵ pairs.
const OPERATING_TIER: usize = 3;
/// Sweep sizes under one `FULL` order.
const SWEEP_K: &[usize] = &[1, 10, 100, 1_000];
/// `tab:params`' epoch count.
const EPOCHS: usize = 24;
/// Cross-tag batch, as Exp. 3–5.
const BETA: usize = 256;
/// Deletions per detection-matrix cell.
const DETECT_N: usize = 100;
/// Bytes of each redacted document's stored ciphertext.
const PAYLOAD_BYTES: usize = 4_096;
/// Seed for every choice above.
const SEED: u64 = 0x0009_5EDA;

fn data_dir() -> PathBuf {
    Path::new("baselines/doris/upstream/data").to_path_buf()
}

/// One Doris Enron tier: document → keywords, and every pair in file order.
struct Corpus {
    docs: BTreeMap<DocId, Vec<Vec<u8>>>,
    pairs: Vec<(Vec<u8>, DocId)>,
    doc_freq: BTreeMap<Vec<u8>, usize>,
}

fn load(tier: usize) -> Res<Corpus> {
    let path = data_dir().join(format!("enron_inverted{tier}.csv"));
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "{}: {e} (the Doris upstream data must be present)",
            path.display()
        )
    })?;
    let mut c = Corpus {
        docs: BTreeMap::new(),
        pairs: Vec::new(),
        doc_freq: BTreeMap::new(),
    };
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.split(',');
        let kw = parts.next().ok_or("empty line")?.as_bytes().to_vec();
        let mut n = 0;
        for p in parts {
            let id: DocId = p
                .trim()
                .parse()
                .map_err(|e| format!("{}: bad id {p:?}: {e}", path.display()))?;
            c.docs.entry(id).or_default().push(kw.clone());
            c.pairs.push((kw.clone(), id));
            n += 1;
        }
        c.doc_freq.insert(kw, n);
    }
    if c.pairs.len() != TIER_PAIRS[tier] {
        return Err(format!(
            "{}: {} pairs, but Doris's tier {tier} is {}",
            path.display(),
            c.pairs.len(),
            TIER_PAIRS[tier]
        )
        .into());
    }
    Ok(c)
}

impl Corpus {
    /// The redacted document: median keyword count among documents with at
    /// least two keywords, ties to the lowest id.
    fn target(&self) -> Res<DocId> {
        let mut v: Vec<(usize, DocId)> = self
            .docs
            .iter()
            .filter(|(_, k)| k.len() >= 2)
            .map(|(d, k)| (k.len(), *d))
            .collect();
        v.sort_unstable();
        v.get(v.len() / 2)
            .map(|(_, d)| *d)
            .ok_or_else(|| "no document with two keywords".into())
    }

    /// `k` documents for a sweep: the target, then a seeded shuffle.
    fn sweep(&self, k: usize, target: DocId) -> Res<Vec<DocId>> {
        let mut rest: Vec<DocId> = self.docs.keys().copied().filter(|d| *d != target).collect();
        if rest.len() + 1 < k {
            return Err(format!(
                "a sweep of {k} needs {k} documents; the tier has {}",
                rest.len() + 1
            )
            .into());
        }
        rest.shuffle(&mut StdRng::seed_from_u64(SEED));
        let mut out = vec![target];
        out.extend(rest.into_iter().take(k - 1));
        Ok(out)
    }

    /// The surviving query: the target's two keywords of highest frequency.
    fn query(&self, target: DocId) -> Res<[Vec<u8>; 2]> {
        let mut k = self.docs.get(&target).ok_or("no target")?.clone();
        k.sort_by_key(|w| std::cmp::Reverse(self.doc_freq.get(w).copied().unwrap_or(0)));
        match k.as_slice() {
            [a, b, ..] => Ok([a.clone(), b.clone()]),
            _ => Err("the target has fewer than two keywords".into()),
        }
    }

    /// Live pairs once `gone` are erased, in file order: what a rebuild ingests.
    fn live(&self, gone: &HashSet<DocId>) -> impl Iterator<Item = &(Vec<u8>, DocId)> {
        self.pairs.iter().filter(move |(_, d)| !gone.contains(d))
    }
}

/// Our index over the corpus, an epoch closed about every `pairs / E`
/// updates, **on a document boundary**.
///
/// ⚠️ draft8 D3: `id = (e, j)` names one epoch,
/// so a record's insertions are record-granular, like its deletion. The file
/// is keyword-major (an inverted index), and closing every `pairs / E` pairs
/// in file order split documents across epochs. Our side therefore ingests
/// document-major and closes only between documents, at the same cadence.
/// ODXT's ingest (`odxt_build`, `Corpus::live`) is unchanged. Flagged under
/// rule 20 before measuring (§1ap).
///
/// Returns each document's identifier `(e, d)` as well.
fn ours_build(c: &Corpus) -> Res<(XtClient, HonestServer, BTreeMap<DocId, DocId>)> {
    let mut x = XtClient::new(
        Client::new(PrfKey::new(digest256(b"K_S exp9"))),
        PrfKey::new(digest256(b"K_X^(0) exp9")),
        BETA,
    );
    let mut s = HonestServer::new();
    let per = c.pairs.len().div_ceil(EPOCHS).max(1);
    let mut ids = BTreeMap::new();
    let mut since_close = 0usize;
    for (d, kws) in &c.docs {
        let id = pqcl_dsse::xt::doc_id(x.epoch(), *d);
        ids.insert(*d, id);
        for w in kws {
            x.update(&mut s, Op::Add, w, id)?;
        }
        since_close += kws.len();
        if since_close >= per {
            x.close_epoch(&mut s);
            since_close = 0;
        }
    }
    x.close_epoch(&mut s);
    Ok((x, s, ids))
}

fn server_tags(s: &HonestServer) -> HashSet<XTag> {
    s.xset
        .all_epochs()
        .into_iter()
        .flat_map(|(_, t)| t)
        .collect()
}

fn fresh_key() -> PrfKey {
    PrfKey::new(rand::thread_rng().r#gen())
}

fn odxt_key() -> odxt::SecretKey {
    let mut m = [0u8; 128];
    rand::thread_rng().fill(&mut m[..]);
    odxt::SecretKey::from_bytes(&m)
}

fn odxt_build<'a>(
    sk: &odxt::SecretKey,
    pairs: impl Iterator<Item = &'a (Vec<u8>, DocId)>,
) -> (odxt::ClientState, odxt::Edb) {
    let mut st = odxt::ClientState::default();
    let mut edb = odxt::Edb::new();
    for (w, d) in pairs {
        edb.apply(&odxt::update(sk, &mut st, Op::Add, *d, w));
    }
    (st, edb)
}

/// The court, the chain's record of its orders, and the lab's stores.
struct Court {
    key: SoftwareMlDsa,
    kem: kem::KeyPair,
    now: u64,
}

impl Court {
    fn new() -> Res<Self> {
        Ok(Self {
            key: SoftwareMlDsa::generate()?,
            kem: kem::KeyPair::generate()?,
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        })
    }

    fn order(&self, n: u64, docs: &[DocId], scope: Scope) -> Res<(Order, Target)> {
        let target = Target::new(&docs.iter().map(|d| eid(*d)).collect::<Vec<_>>());
        let o = Order::issue(
            &self.key,
            digest256(&[b"exp9 order".as_slice(), &n.to_le_bytes()].concat()),
            target.root(),
            scope,
            Mode::Erased,
            self.now,
            self.now + 86_400,
        )?;
        Ok((o, target))
    }
}

fn eid(d: DocId) -> Digest32 {
    digest256(&[b"exp9 capsule".as_slice(), &d.to_le_bytes()].concat())
}

/// One measured redaction of ours: erase time, residual, search after.
struct Measured {
    erase: Duration,
    residual: usize,
    search: Duration,
}

#[allow(clippy::too_many_arguments)]
fn ours_once(
    c: &Corpus,
    court: &Court,
    scope: Scope,
    docs: &[DocId],
    query: &[Vec<u8>; 2],
    dir: &Path,
    n: u64,
    measure_search: bool,
) -> Res<Measured> {
    let (mut index, mut server, ids) = ours_build(c)?;
    let retained = server_tags(&server);
    let payloads = PayloadStore::open(dir)?;
    let mut openings = Openings::new();
    for d in docs {
        payloads.put(&eid(*d), &[0xA5; PAYLOAD_BYTES])?;
        openings.insert(eid(*d), rand::thread_rng().r#gen());
    }
    let (order, target) = court.order(n, docs, scope)?;
    let registry = HashMap::from([(order.oid, order.leaf().digest)]);
    let redactees = docs
        .iter()
        .map(|d| {
            Ok(Redactee {
                eid: eid(*d),
                doc: *ids.get(d).ok_or("a document our index never ingested")?,
                membership: target.prove(&eid(*d)).ok_or("untargeted")?,
                keywords: c.docs.get(d).ok_or("no document")?.clone(),
            })
        })
        .collect::<Res<Vec<_>>>()?;
    let seed = fresh_key();
    let started = Instant::now();
    execute(
        &order,
        court.key.public_key(),
        court.now,
        &registry,
        &redactees,
        &payloads,
        &mut openings,
        court.kem.encapsulation_key(),
        &mut index,
        &mut server,
        || seed,
    )?;
    let erase = started.elapsed();

    // The adversary: current key state, every retained and current XSet.
    let now_tags = server_tags(&server);
    let residual = redactees
        .iter()
        .flat_map(|r| r.keywords.iter().map(move |w| (w, r.doc)))
        .filter(|(w, d)| {
            index
                .derivable_xtags(w, *d)
                .iter()
                .any(|t| retained.contains(t) || now_tags.contains(t))
        })
        .count();

    let mut search = Duration::ZERO;
    if measure_search {
        let started = Instant::now();
        let terms: Vec<&[u8]> = query.iter().map(Vec::as_slice).collect();
        let s_ix = index.select_s_term(&terms).ok_or("no s-term")?;
        let cand = index.candidates(&server, terms[s_ix])?;
        let x_terms: Vec<&[u8]> = vec![terms[1 - s_ix]];
        let (tr, map) = index.probe(&cand, &x_terms);
        let bits = XSetStore::probe(&server, &tr);
        let got = index.evaluate(&cand, 1, &map, &bits, &Formula::conjunction(1));
        search = started.elapsed();
        let found = got.contains(ids.get(&docs[0]).ok_or("no target id")?);
        if found == scope.touches_index() {
            return Err(
                format!("{scope:?}: the redacted document found = {found} after erasure").into(),
            );
        }
    }
    Ok(Measured {
        erase,
        residual,
        search,
    })
}

/// ODXT `del`, or ODXT rebuild under fresh keys.
fn odxt_once(c: &Corpus, target: DocId, query: &[Vec<u8>; 2], rebuild: bool) -> Res<Measured> {
    let sk = odxt_key();
    let (mut st, mut edb) = odxt_build(&sk, c.pairs.iter());
    let retained = edb.xset_snapshot();
    let kws = c.docs.get(&target).ok_or("no target")?.clone();
    let gone = HashSet::from([target]);
    let t = Instant::now();
    let sk_now = if rebuild {
        let fresh = odxt_key();
        let (st2, edb2) = odxt_build(&fresh, c.live(&gone));
        st = st2;
        edb = edb2;
        fresh
    } else {
        for w in &kws {
            edb.apply(&odxt::update(&sk, &mut st, Op::Del, target, w));
        }
        sk
    };
    let erase = t.elapsed();
    let residual = kws
        .iter()
        .filter(|w| {
            let x = odxt::xtag_of(&sk_now, w, target, Op::Add);
            retained.contains(&x) || edb.xset_contains(&x)
        })
        .count();
    let mut rng = StdRng::seed_from_u64(SEED);
    let t = Instant::now();
    let got = odxt::search(&sk_now, &st, &edb, query, &mut rng);
    let search = t.elapsed();
    if got.contains(&target) {
        return Err("ODXT still returns the redacted document".into());
    }
    Ok(Measured {
        erase,
        residual,
        search,
    })
}

fn summarise(ms: &[Measured]) -> serde_json::Value {
    let erase: Vec<Duration> = ms.iter().map(|m| m.erase).collect();
    let search: Vec<Duration> = ms.iter().map(|m| m.search).collect();
    let residual: Vec<usize> = ms.iter().map(|m| m.residual).collect();
    serde_json::json!({
        "erase_ns": Summary::of(&erase),
        "search_after_ns": Summary::of(&search),
        "residual": residual,
    })
}

fn one_tier(tier: usize, court: &Court, dir: &Path) -> Res<serde_json::Value> {
    let c = load(tier)?;
    let target = c.target()?;
    let query = c.query(target)?;
    let kws = c.docs.get(&target).map_or(0, Vec::len);
    eprintln!(
        "tier {tier}: {} pairs, {} documents, target {target} ({kws} keywords)",
        c.pairs.len(),
        c.docs.len()
    );
    let iters = MIN_ITERATIONS as usize;
    let mut rows = serde_json::Map::new();
    for (name, rebuild) in [("odxt_del", false), ("odxt_rebuild", true)] {
        let ms = (0..iters)
            .map(|_| odxt_once(&c, target, &query, rebuild))
            .collect::<Res<Vec<_>>>()?;
        eprintln!("  {name}: erase {:?}", ms[0].erase);
        rows.insert(name.into(), summarise(&ms));
    }
    for (name, scope) in [
        ("ours_payload", Scope::Payload),
        ("ours_payload_index", Scope::PayloadIndex),
        ("ours_full", Scope::Full),
    ] {
        let ms = (0..iters)
            .map(|i| ours_once(&c, court, scope, &[target], &query, dir, i as u64, true))
            .collect::<Res<Vec<_>>>()?;
        eprintln!("  {name}: erase {:?}", ms[0].erase);
        rows.insert(name.into(), summarise(&ms));
    }
    let mut sweep = Vec::new();
    if tier == OPERATING_TIER {
        for &k in SWEEP_K {
            let docs = c.sweep(k, target)?;
            let ms = (0..iters)
                .map(|i| {
                    ours_once(
                        &c,
                        court,
                        Scope::Full,
                        &docs,
                        &query,
                        dir,
                        1_000 + i as u64,
                        false,
                    )
                })
                .collect::<Res<Vec<_>>>()?;
            eprintln!("  sweep k={k}: erase {:?}", ms[0].erase);
            sweep.push(serde_json::json!({"k": k, "ours_full": summarise(&ms)}));
        }
    }
    Ok(serde_json::json!({
        "tier": tier,
        "pairs": c.pairs.len(),
        "documents": c.docs.len(),
        "target_document": target,
        "target_keywords": kws,
        "query": query.iter().map(|w| String::from_utf8_lossy(w).into_owned()).collect::<Vec<_>>(),
        "rows": rows,
        "sweep": sweep,
    }))
}

/// What `0x05` accounting reads off a `DISPOSE` for `e` referencing `oid`.
///
/// ⭐ **A [`DisposalClaim`], not a fabricated record** (M13 A1). The previous
/// version invented a `CustodyRecord` with zeroed commitments and an empty
/// signature purely to reach one field — a private record-building path, which
/// M13 A2 forbids, and a shape no real chain contains. Accounting reads only
/// `eid_e` and `order_ref`, so narrowing its input made the
/// stand-in unnecessary rather than merely tidier.
///
/// `ts` is no longer taken: accounting never read it.
fn dispose_ref(e: Digest32, oid: Digest32) -> (Digest32, DisposalClaim) {
    (
        e,
        DisposalClaim {
            eid_e: e,
            order_ref: Some(oid),
        },
    )
}

/// The single epoch the detection workload anchors in: capsules and orders
/// alike, so `eq:vred`'s `e′ ≥ e` holds with equality and is not what decides.
const DETECT_EPOCH: u64 = 0;

/// What `0x05` accounting reads: claimed orders, verified `0x05` leaves with
/// their epochs, the chain's recorded order digests, DISPOSEs.
type Ledger = (
    Vec<ClaimedOrder>,
    HashMap<Digest32, u64>,
    HashMap<Digest32, Digest32>,
    Vec<(Digest32, DisposalClaim)>,
);

/// What a compromised AIS adds for every unauthorised deletion: an order under
/// its own key, that order's `0x05` leaf, its digest recorded on chain (it
/// holds the case's anchoring account, so the contract takes it — M13 A16
/// binds the caller, not the court), and a `DISPOSE` referencing it.
fn compromised(
    court: &Court,
    unauthorised: &[DocId],
    (claimed, leaves, registry, disposals): &Ledger,
) -> Res<Ledger> {
    let rogue = SoftwareMlDsa::generate()?;
    let (mut c2, mut l2, mut r2, mut d2) = (
        claimed.clone(),
        leaves.clone(),
        registry.clone(),
        disposals.clone(),
    );
    for d in unauthorised {
        let t = Target::new(&[eid(*d)]);
        let o = Order::issue(
            &rogue,
            digest256(&d.to_le_bytes()),
            t.root(),
            Scope::Payload,
            Mode::Erased,
            court.now,
            court.now + 9,
        )?;
        c2.push(ClaimedOrder {
            order: o.clone(),
            covers: vec![(eid(*d), t.prove(&eid(*d)).ok_or("untargeted")?)],
        });
        l2.insert(o.leaf().digest, DETECT_EPOCH);
        r2.insert(o.oid, o.leaf().digest);
        d2.push(dispose_ref(eid(*d), o.oid));
    }
    Ok((c2, l2, r2, d2))
}

/// `tab:exp-redact-detect`: missed unauthorised / false alarms on lawful.
fn detection(court: &Court, dir: &Path) -> Res<serde_json::Value> {
    let payloads = PayloadStore::open(&dir.join("detect"))?;
    let docs: Vec<DocId> = (0..DETECT_N as u64).collect();
    for d in &docs {
        payloads.put(&eid(*d), &[0x5A; 64])?;
    }
    let anchored: Vec<AnchoredPayload> = docs
        .iter()
        .map(|d| AnchoredPayload {
            eid: eid(*d),
            path: payloads.path(&eid(*d)),
            epoch: DETECT_EPOCH,
        })
        .collect();
    let (lawful, unauthorised): (Vec<DocId>, Vec<DocId>) = docs.iter().partition(|d| *d % 2 == 0);
    let mut claimed = Vec::new();
    let mut leaves = HashMap::new();
    let mut registry = HashMap::new();
    let mut disposals = Vec::new();
    for d in &lawful {
        let (o, t) = court.order(10_000 + d, &[*d], Scope::Payload)?;
        claimed.push(ClaimedOrder {
            order: o.clone(),
            covers: vec![(eid(*d), t.prove(&eid(*d)).ok_or("untargeted")?)],
        });
        leaves.insert(o.leaf().digest, DETECT_EPOCH);
        registry.insert(o.oid, o.leaf().digest);
        disposals.push(dispose_ref(eid(*d), o.oid));
    }
    for d in &docs {
        payloads.erase(&eid(*d))?;
    }
    let lawful_set: HashSet<Digest32> = lawful.iter().map(|d| eid(*d)).collect();
    let tally = |flagged: &HashSet<Digest32>| {
        let missed = unauthorised
            .iter()
            .filter(|d| !flagged.contains(&eid(**d)))
            .count();
        let false_alarms = lawful
            .iter()
            .filter(|d| flagged.contains(&eid(**d)))
            .count();
        serde_json::json!({"missed_unauthorised": missed, "false_alarms_on_lawful": false_alarms})
    };
    let ours_flags = |(c, l, r, ds): &Ledger| -> HashSet<Digest32> {
        account(&anchored, c, l, r, ds, court.key.public_key())
            .into_iter()
            .filter_map(|u| match u {
                Unaccounted::PayloadDeleted { eid } => Some(eid),
                Unaccounted::RedactedPayloadPresent { .. } => None,
            })
            .collect()
    };
    // Re-hash + list: a missing object alarms unless the operator's list names it.
    let rehash_flags = |list: &HashSet<Digest32>| -> HashSet<Digest32> {
        anchored
            .iter()
            .filter(|a| !a.path.exists() && !list.contains(&a.eid))
            .map(|a| a.eid)
            .collect()
    };
    let benign: Ledger = (claimed, leaves, registry, disposals);
    let benign_ours = ours_flags(&benign);
    let benign_rehash = rehash_flags(&lawful_set);

    // Compromised AIS: forged orders under its own key, their leaves, DISPOSEs.
    let compromised_ours = ours_flags(&compromised(court, &unauthorised, &benign)?);
    let mut padded = lawful_set.clone();
    padded.extend(unauthorised.iter().map(|d| eid(*d)));
    let compromised_rehash = rehash_flags(&padded);
    Ok(serde_json::json!({
        "n": DETECT_N,
        "lawful": lawful.len(),
        "unauthorised": unauthorised.len(),
        "benign_ais": {"ours_0x05": tally(&benign_ours), "rehash_with_list": tally(&benign_rehash)},
        "compromised_ais": {"ours_0x05": tally(&compromised_ours), "rehash_with_list": tally(&compromised_rehash)},
        "compromised_means": "appends an entry for every unauthorised deletion to any list it can write: for ours, a forged order under its own key, its 0x05 leaf and a DISPOSE",
    }))
}

fn main() -> Res<()> {
    let tiers: Vec<usize> = std::env::var("PQCL_EXP9_TIERS").map_or_else(
        |_| TIERS.to_vec(),
        |s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
    );
    let dir = std::env::temp_dir().join(format!("pqcl-exp9-{}", std::process::id()));
    let court = Court::new()?;
    let result = (|| -> Res<serde_json::Value> {
        let cases = tiers
            .iter()
            .map(|t| one_tier(*t, &court, &dir))
            .collect::<Res<Vec<_>>>()?;
        Ok(serde_json::json!({
            "cases": cases,
            "operating_tier": OPERATING_TIER,
            "operating_pairs": TIER_PAIRS[OPERATING_TIER],
            "sweep_k": SWEEP_K,
            "epochs": EPOCHS,
            "beta": BETA,
            "payload_bytes": PAYLOAD_BYTES,
            "detection": detection(&court, &dir)?,
            "method": {
                "erase": "from a recorded order to erasure complete; ours through pqcl_pipeline::redaction::execute, gate included; ODXT del: one Del update per pair; ODXT rebuild: Setup over the live pairs under a fresh key",
                "residual": "redacted pairs whose Add cross-tag, derivable from the current key state, is in a retained or current XSet",
                "search_after": "one surviving conjunctive query, the redacted document's two keywords of highest document frequency; for PAYLOAD+INDEX with tombstones pending compaction",
                "odxt_no_compaction": "not added: not in ODXT's paper (baselines/UPGRADES.md)",
            },
        }))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    let measurements = result?;
    emit(
        "exp9redact",
        RunSpec {
            liboqs_version: "ML-DSA-65 via liboqs".to_owned(),
            rng_seeds: vec![SEED],
            ..RunSpec::default()
        },
        MIN_ITERATIONS,
        measurements,
    )?;
    Ok(())
}
