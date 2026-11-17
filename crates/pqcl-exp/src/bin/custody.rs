//! **Court disclosure, head to head** (M10 H7, `sec:exp-custody`).
//!
//! A court asks for **one capsule's complete custody history**. Three ways to
//! answer it, over **the same custody records** — real, ML-DSA-signed records
//! from the shared stream (`pqcl_exp::custody_stream`):
//!
//! | scheme | the court receives | it learns about the rest of the case |
//! |---|---|---|
//! | **ours** — Tier 1 per capsule, Tier 2 per epoch | the capsule, its chain, one Tier-2 proof | nothing |
//! | **flat per-case MMR** — every record a leaf of one tree | the capsule, its records, one inclusion proof each | the case size (every proof carries the leaf count) |
//! | **hash-chain replay** — one chain over the case, head anchored | every record from genesis | everything |
//! | **PQ-ABL** (TCC 2026) — one Merkle tree per epoch, root anchored | the capsule and its records, one path each | each epoch's log count |
//! | **`GlassDB`** (PVLDB 2023) — two-level POS-tree ledger | the record key's version history, current value at the last block | neighbouring entries of each disclosed node |
//!
//! The last two are SAC Exp. 2's comparators (2023 or later,
//! the design record); draft8 keeps the flat MMR and replay.
//!
//! For each: disclosed bytes, and the time to verify from the anchored root,
//! at case sizes up to 10⁵ records locally (`PQCL_CUSTODY_SIZES` for more).
//!
//! # What "verify" means here, for all three alike
//!
//! Integrity from the anchor, at hash level: links, the recomputed root, the
//! inclusion proof. Checking each disclosed record's ML-DSA signature is a
//! per-record cost common to every scheme — `k` records for ours and the flat
//! MMR, all `N` for replay — so it is measured once (`record_signature_verify_ns`)
//! rather than folded into one column and not another.
//!
//! # Also measured
//!
//! * **Full replay** — an auditor verifying the whole case, each scheme's way.
//! * **Bilateral transfer** — sender record, receiver's witness counter-signature,
//!   receiver's receipt record: what a two-party `TRANSFER` costs over a
//!   one-party one.
//! * **A redacted capsule** (§1v.4, `tab:exp-custody`'s lower block). The
//!   stream's `DISPOSE`s execute one retention-sweep order (FULL, ERASED) over
//!   every capsule it disposes. Ours: sealing epochs of [`EPOCH_RECORDS`]
//!   records each, closed by count in stream order, hold every record but the
//!   `DISPOSE`s; the redaction epoch after them holds the disposed capsules'
//!   `DISPOSE`s and the order's `0x05` leaf. The flat MMR carries the same `0x05` leaf, before
//!   the `DISPOSE` records; replay records the order as a chain entry. Each
//!   discloses a redacted capsule its own way; each full-case audit includes the
//!   redactions with `0x05` accounting (order genuine, anchored, targeting every
//!   disposed capsule, referenced by every `DISPOSE`).
//! * **Committee size `M`** — an epoch root endorsed by `M` custodians as `M`
//!   independent ML-DSA-65 signatures. ⚠️ Not a threshold signature: the
//!   available threshold implementation is Go and plan §5 forbids a
//!   cross-language wall clock, so this is the **upper bound** a threshold
//!   scheme would reduce to one signature's size.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pqcl_bench::{MIN_ITERATIONS, RunSpec};
use pqcl_capsule::redaction::{Mode, Order, Scope, Target, targets};
use pqcl_capsule::{Capsule, CustodyRecord, Event, Params, Role};
use pqcl_exp::appender::{Discloser, from_env};
use pqcl_exp::case::{self, CaseBuilder};
use pqcl_exp::cast::Cast;
use pqcl_exp::custody_stream::{CustodyEvent, StreamParams, custody_stream, event_counts};
use pqcl_exp::{emit_custody, stats::Summary};
use pqcl_forest::tier2::{self, Leaf, Mmr, MmrProof};
use pqcl_pipeline::{Ais, CaseKeys, RecordParams, record_signed_bytes};
use pqcl_primitives::sig::verify as mldsa_verify;
use pqcl_primitives::xof::{Digest32, Domain, PrfKey, digest256, hash_domain};
use pqcl_primitives::{Signer, SoftwareMlDsa};
use pqcl_sm::{AppendRequest, AppendStep, Backend, CustodyAppender, SealRequest};

type Res<T> = Result<T, Box<dyn core::error::Error>>;

/// Target case sizes in records; `PQCL_CUSTODY_SIZES` overrides.
const DEFAULT_SIZES: &[usize] = &[1_000, 10_000, 100_000];

/// Committee sizes for the endorsement measurement.
const COMMITTEES: &[usize] = &[1, 3, 5, 7];

/// Records per sealing epoch, closed by count in stream order (§1ci.5 item 2):
/// inside PQ-ABL's evaluated range of 1,000 to 50,000 logs per epoch (p. 15),
/// fixed before any measurement. `PQCL_CASE_EPOCH_RECORDS` overrides it for a
/// local smoke run, and the record says which ran.
const EPOCH_RECORDS: usize = 10_000;

fn epoch_records() -> usize {
    std::env::var("PQCL_CASE_EPOCH_RECORDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(EPOCH_RECORDS)
}

/// Average records per capsule under the default stream mix, in tenths, used
/// only to pick a capsule count; the realised record count is what is reported.
const RECORDS_PER_CAPSULE_X10: usize = 86;

/// One case: its capsules and every record in stream order.
struct Case {
    capsules: Vec<Capsule>,
    /// `(capsule, record)` in stream order.
    records: Vec<(u32, CustodyRecord)>,
    /// Each record's epoch, parallel to `records`: sealing epochs of
    /// `epoch_records()` records, then the redaction epoch.
    epochs: Vec<u64>,
    /// Sealing epochs; the redaction epoch is this number.
    sealing_epochs: u64,
    /// Records per sealing epoch this case was built with.
    epoch_records: usize,
    build: Duration,
    /// The retention sweep every `DISPOSE` executes.
    order: Order,
    /// The Court Authority's verification key.
    court_pk: Vec<u8>,
    /// The order's target, for membership proofs.
    target: Target,
    /// Capsules whose chain ends in `DISPOSE`, ascending.
    disposed: Vec<u32>,
}

/// The sweep order's id, fixed before any `DISPOSE` references it.
fn sweep_oid() -> Digest32 {
    digest256(b"custody retention sweep")
}

impl Case {
    /// The sealing epoch's records: everything but the `DISPOSE`s.
    ///
    /// ⭐ **Classified by `order_ref`, which is keyless** (M13 A1). The event
    /// now lives inside `C_rec`, and every `DISPOSE` this harness produces is
    /// court-ordered — it is built with `sweep_oid()` — so `order_ref.is_some()`
    /// is an exact classifier here and needs no key. ⚠️ It would **not** be
    /// exact on a stream containing retention-driven disposals, which carry no
    /// order; such a stream needs the body key.
    fn sealing(&self) -> impl Iterator<Item = &(u32, CustodyRecord)> {
        self.records.iter().filter(|(_, r)| r.order_ref.is_none())
    }

    /// The `DISPOSE` records, in stream order.
    fn disposals(&self) -> impl Iterator<Item = &(u32, CustodyRecord)> {
        self.records.iter().filter(|(_, r)| r.order_ref.is_some())
    }

    /// Phase 10's `0x05` accounting, less the anchoring check each structure
    /// makes its own way: the order verifies under the court key, targets
    /// every disposed capsule, and every `DISPOSE` references it.
    fn account(&self) -> Res<()> {
        self.order
            .verify(&self.court_pk, self.order.ts)
            .map_err(|e| format!("order: {e}"))?;
        for c in &self.disposed {
            let eid = self.capsules[*c as usize].eid;
            let p = self
                .target
                .prove(&eid)
                .ok_or("a disposed capsule is not targeted")?;
            if !targets(&self.order.tgt, &eid, &p) {
                return Err("membership proof does not verify".into());
            }
        }
        if self
            .disposals()
            .any(|(_, r)| r.order_ref != Some(self.order.oid))
        {
            return Err("a DISPOSE does not reference the order".into());
        }
        Ok(())
    }

    /// One disposed capsule's `DISPOSE` references the order and the order
    /// targets it: the per-capsule half of [`Case::account`].
    ///
    /// ⚠️ `disclosed` is the chain the verifier **holds**: the bundle's for ours,
    /// the disclosed records for the flat MMR, the whole case for replay. The
    /// first campaign-05 pass scanned the whole case here for every scheme, an
    /// O(N) cost a court verifying a disclosure never pays (§1z).
    fn account_one<'a>(
        &self,
        c: u32,
        membership: &pqcl_forest::InclusionProof,
        disclosed: impl IntoIterator<Item = &'a CustodyRecord>,
    ) -> Res<()> {
        let eid = self.capsules[c as usize].eid;
        if !targets(&self.order.tgt, &eid, membership) {
            return Err("the order does not target the capsule".into());
        }
        // `order_ref` alone, for the same reason as `disposals()`: it is the
        // keyless marker of a court-ordered disposal.
        let ok = disclosed
            .into_iter()
            .any(|r| r.order_ref == Some(self.order.oid));
        if ok {
            Ok(())
        } else {
            Err("no DISPOSE references the order".into())
        }
    }
}

/// `size` names the case among the sizes one run builds. It enters every
/// capsule's nonce, so no two cases share a capsule: the enclave outlives a
/// case, and its position guard refused the second size's capsule 0 as a
/// re-signing of the first's (campaign 08, c08c's first attempt).
fn build_case(
    appender: &dyn CustodyAppender,
    keys: &CaseKeys,
    stream: &[CustodyEvent],
    size: usize,
) -> Res<Case> {
    let start = Instant::now();
    // Capsules interleave in the stream, so they are filed by index, not by
    // arrival.
    let mut capsules: Vec<Option<Capsule>> = Vec::new();
    // ⭐ **Every record through the library** (M13 A2/A14). The builder signs
    // each event with the agent whose role draft8 makes accountable for it, and
    // routes a `TRANSFER` pair through `handoff::release` and
    // `handoff::receive` — which this harness used to sign as two ordinary
    // records, so the bilateral half of §3a was never in anything measured.
    //
    // `j` comes from `CustodyEvent::seq`, the stream's own "position within
    // that capsule's chain". The harness kept a second counter for it, and a
    // second derivation of a value `rid` commits to is a second chance to
    // disagree with the generator.
    let mut build = CaseBuilder::new(appender, keys);
    let mut records = Vec::with_capacity(stream.len());
    // Sealing epochs close by record count in stream order; the redaction
    // epoch follows the last of them (§1ci.5 item 2).
    let per_epoch = epoch_records();
    let sealing = stream.iter().filter(|e| e.event != Event::Dispose).count();
    let sealing_epochs = sealing.div_ceil(per_epoch).max(1) as u64;
    let mut epochs = Vec::with_capacity(stream.len());
    let mut sealed = 0usize;
    for (i, e) in stream.iter().enumerate() {
        // ⭐ **The redaction epoch is a real epoch** (M13 A20). A `DISPOSE` is
        // written in it, so it lands in a segment of its own with its own
        // pseudonym, and the capsule's earlier records stay in their sealing
        // epochs' segments. Before A20 both anchors shared one `eid_e` and the
        // second was over the whole chain again.
        let epoch = if e.event == Event::Dispose {
            sealing_epochs
        } else {
            sealed += 1;
            ((sealed - 1) / per_epoch) as u64
        };
        if e.event == Event::Collect {
            let nonce = digest256(&[&size.to_le_bytes()[..], &e.capsule.to_le_bytes()].concat());
            let c = build.seal(
                nonce,
                hash_domain(Domain::PlaintextCommit, &[&nonce]),
                hash_domain(Domain::EvidenceDigest, &[&nonce]),
                b"disk-image",
                b"s3://evidence/capsule",
                epoch,
            )?;
            let slot = e.capsule as usize;
            if capsules.len() <= slot {
                capsules.resize(slot + 1, None);
            }
            if capsules[slot].replace(c.clone()).is_some() {
                return Err(format!("capsule {slot} collected twice").into());
            }
            build.insert_capsule(e.capsule, c);
        }
        let a = build.feed(e, 1_700_000_000 + i as u64, epoch, Some(&sweep_oid()))?;
        records.push((e.capsule, a.signed.record));
        epochs.push(epoch);
    }
    let capsules = capsules
        .into_iter()
        .collect::<Option<Vec<Capsule>>>()
        .ok_or("a capsule index was never collected")?;
    let build = start.elapsed();
    // The court's sweep, over every capsule the stream disposes. Outside the
    // build timer: the court is not the pipeline.
    let mut disposed: Vec<u32> = records
        .iter()
        .filter(|(_, r)| r.order_ref.is_some())
        .map(|(c, _)| *c)
        .collect();
    disposed.sort_unstable();
    disposed.dedup();
    if disposed.is_empty() {
        return Err("the stream disposed nothing, so there is no redacted capsule".into());
    }
    let eids: Vec<Digest32> = disposed.iter().map(|c| capsules[*c as usize].eid).collect();
    let target = Target::new(&eids);
    let court = SoftwareMlDsa::generate()?;
    let ts = 1_700_000_000 + records.len() as u64;
    let order = Order::issue(
        &court,
        sweep_oid(),
        target.root(),
        Scope::Full,
        Mode::Erased,
        ts,
        ts + 30 * 24 * 3600,
    )?;
    Ok(Case {
        capsules,
        records,
        epochs,
        sealing_epochs,
        epoch_records: per_epoch,
        build,
        order,
        court_pk: court.public_key().to_vec(),
        target,
        disposed,
    })
}

fn timed<T>(mut f: impl FnMut() -> Res<T>) -> Res<(Summary, T)> {
    let mut samples = Vec::new();
    let mut out = None;
    for _ in 0..MIN_ITERATIONS {
        let t = Instant::now();
        out = Some(f()?);
        samples.push(t.elapsed());
    }
    Ok((Summary::of(&samples), out.ok_or("no iterations")?))
}

/// One capsule as the full-case audit checks it: its bundle, which carries one
/// segment per epoch the capsule was touched in.
///
/// ⭐ **M13 A20 collapsed this type.** It used to carry the earlier epoch's
/// `0x02` separately, because a capsule anchored in two epochs was anchored
/// twice over *prefixes of one chain* under one pseudonym — the structure that
/// handed the AIS the cross-epoch link (`audit/07` D1). Now each epoch is its
/// own segment inside the bundle and one call checks them all.
struct Audited {
    bundle: pqcl_capsule::Bundle,
}

impl Audited {
    fn verify(
        &self,
        roots: &[(u64, Digest32)],
        memo: &mut pqcl_forest::tier2::NodeMemo,
    ) -> Result<(), pqcl_capsule::DisclosureError> {
        self.bundle.verify_memo(roots, memo)
    }
}

/// File `records` into `ais`, accepting a capsule the first time it appears.
/// Returns where each capsule landed in the server's capsule store.
fn file_into<'a>(
    ais: &mut Ais,
    case: &Case,
    records: impl Iterator<Item = &'a (u32, CustodyRecord)>,
    slot: &mut BTreeMap<u32, usize>,
) {
    for (c, r) in records {
        if slot.contains_key(c) {
            ais.append(r.clone());
        } else {
            slot.insert(*c, ais.len());
            ais.accept(case.capsules[*c as usize].clone(), r.clone());
        }
    }
}

/// Ours: the sealing epoch, the redaction epoch, and the target capsule's
/// bundle from the first.
#[allow(clippy::too_many_lines)]
fn ours(case: &Case, court: &Discloser<'_>, target: u32, redacted: u32) -> Res<serde_json::Value> {
    // One server. The sealing epochs hold every record but the `DISPOSE`s,
    // each closed after its records; the redaction epoch holds the
    // `DISPOSE`s — one new segment per disposed capsule — and the order's
    // `0x05` leaf.
    let mut ais = Ais::new();
    let mut slot: BTreeMap<u32, usize> = BTreeMap::new();
    for (rec, e) in case.records.iter().zip(&case.epochs) {
        if rec.1.order_ref.is_some() {
            continue;
        }
        while ais.epoch() < *e {
            ais.close_epoch();
        }
        file_into(&mut ais, case, std::iter::once(rec), &mut slot);
    }
    ais.close_epoch();
    if ais.epoch() != case.sealing_epochs {
        return Err("the sealing epochs did not close where the case put them".into());
    }
    file_into(&mut ais, case, case.disposals(), &mut slot);
    let at05 = ais.record_order(&case.order);
    let root_r = ais.close_epoch();
    let proof05 = ais.prove(&at05).ok_or("no proof for the 0x05 leaf")?;
    let roots = ais.epoch_roots();
    let k = *slot.get(&target).ok_or("target capsule missing")?;
    let bundle = court.disclose(&ais, k)?.ok_or("no bundle for the target")?;
    let (verify, ()) = timed(|| bundle.verify(&roots).map_err(Into::into))?;
    // Full replay: an auditor checks every anchored custody leaf of both
    // epochs. A disposed capsule has a segment in each, and each record is
    // hashed once (M12's leaf reuse, kept).
    let bundles: Vec<Audited> = (0..ais.len())
        .map(|i| {
            court
                .disclose(&ais, i)?
                .map(|bundle| Audited { bundle })
                .ok_or_else(|| "a capsule has no bundle".into())
        })
        .collect::<Res<_>>()?;
    let accounting = || -> Res<()> {
        if !tier2::verify(&root_r, &case.order.leaf(), &proof05) {
            return Err("the 0x05 leaf is not anchored".into());
        }
        case.account()
    };
    let redacted_block = ours_redacted(
        case, court, redacted, &ais, &slot, &roots, &root_r, &proof05,
    )?;
    // Full-case audit: the Tier-2 walks go through one shared node memo
    // (§1l.4). Identical decisions by construction; the per-capsule audit is
    // timed beside it so the gain is visible. ⚠️ Measured: ~94 % of this audit
    // is hashing each record twice (chain link + Tier-1 leaf), which no memo
    // removes -- the flat MMR and replay hash each record once.
    let (full, hits) = timed(|| {
        let mut memo = pqcl_forest::tier2::NodeMemo::default();
        for a in &bundles {
            a.verify(&roots, &mut memo)?;
        }
        accounting()?;
        Ok(memo.hits)
    })?;
    let (full_plain, ()) = timed(|| {
        for a in &bundles {
            a.verify(&roots, &mut pqcl_forest::tier2::NodeMemo::default())?;
        }
        accounting()
    })?;
    // §1o.3 F2: capsule histories are independent, so the audit shards across
    // cores, each shard with its own memo. Same decisions as above.
    let threads = audit_threads();
    let (full_parallel, _) = timed(|| {
        let out = sharded(&bundles, threads, |part| {
            let mut memo = pqcl_forest::tier2::NodeMemo::default();
            for a in part {
                a.verify(&roots, &mut memo).map_err(|e| e.to_string())?;
            }
            Ok(())
        })?;
        accounting()?;
        Ok(out)
    })?;
    let mut scaling = Vec::new();
    for t in cores_axis() {
        let (s, _) = timed(|| {
            let out = sharded(&bundles, t, |part| {
                let mut memo = pqcl_forest::tier2::NodeMemo::default();
                for a in part {
                    a.verify(&roots, &mut memo).map_err(|e| e.to_string())?;
                }
                Ok(())
            })?;
            accounting()?;
            Ok(out)
        })?;
        scaling.push(serde_json::json!({"threads": t, "full_replay_ns": s}));
    }
    Ok(serde_json::json!({
        "full_replay_parallel_ns": full_parallel,
        "audit_threads": threads,
        "audit_scaling": scaling,
        "full_replay_unmemoised_ns": full_plain,
        "full_replay_memo_hits": hits,
        "disclosed_bytes": bundle.encode().len(),
        "disclosed_records": bundle.record_count(),
        "disclosed_segments": bundle.segments.len(),
        "verify_ns": verify,
        "full_replay_ns": full,
        "full_replay_bytes": bundles.iter().map(|a| a.bundle.encode().len()).sum::<usize>()
            + case.order.encode().len() + proof05.wire_bytes(),
        "audit_includes": "every epoch's bundles and 0x05 accounting (order anchored at R_e', genuine, targeting every disposed capsule, referenced by every DISPOSE)",
        "exposed": "none",
        "redacted": redacted_block,
    }))
}

/// Ours, the lower block: disclose a redacted capsule — its Tier-1 chain with
/// the `0x02` proof at `R_{e'}`, the `0x05` proof at `R_{e'}`, the order and
/// the capsule's membership in its target.
#[allow(clippy::too_many_arguments)]
fn ours_redacted(
    case: &Case,
    court: &Discloser<'_>,
    redacted: u32,
    ais: &Ais,
    slot: &BTreeMap<u32, usize>,
    roots: &[(u64, Digest32)],
    root_r: &Digest32,
    proof05: &MmrProof,
) -> Res<serde_json::Value> {
    let k = *slot.get(&redacted).ok_or("redacted capsule missing")?;
    let bundle = court
        .disclose(ais, k)?
        .ok_or("no bundle for the redacted capsule")?;
    let eid = case.capsules[redacted as usize].eid;
    let membership = case
        .target
        .prove(&eid)
        .ok_or("redacted capsule not targeted")?;
    let (verify, ()) = timed(|| {
        bundle.verify(roots)?;
        if !tier2::verify(root_r, &case.order.leaf(), proof05) {
            return Err("the 0x05 leaf is not anchored".into());
        }
        case.account_one(redacted, &membership, bundle.records())
    })?;
    Ok(serde_json::json!({
        "verify_ns": verify,
        "disclosed_bytes": bundle.encode().len()
            + proof05.wire_bytes()
            + case.order.encode().len()
            + membership.wire_bytes(),
        "disclosed_records": bundle.record_count(),
        "disclosed_segments": bundle.segments.len(),
        "carries": "one Tier-1 segment per epoch with its own 0x02 proof, the 0x05 proof at R_e', the order, target membership",
    }))
}

/// One leaf of the flat MMR.
///
/// ⭐ **The seal leaves are new in M13 A3.** The flat baseline anchored custody
/// records and the order, but never the capsules — so a disclosure from it
/// proved a history beside an unanchored artefact, which is a weaker claim than
/// ours was making and an unfair comparison in *our* favour. It now anchors the
/// same three leaf kinds we do, and its disclosure carries the capsule's proof.
#[derive(Clone, Copy)]
enum FlatLeaf<'a> {
    /// A capsule's `0x01` seal leaf.
    Seal(&'a Capsule),
    /// A custody record's leaf, with the capsule it belongs to.
    Record(&'a (u32, CustodyRecord)),
    /// The redaction order's `0x05` leaf.
    Order,
}

/// The flat MMR's leaf sequence: every capsule's seal leaf, every record but
/// the `DISPOSE`s, the order's `0x05` leaf (recorded before deletion), then the
/// `DISPOSE`s.
fn flat_sequence(case: &Case) -> Vec<FlatLeaf<'_>> {
    case.capsules
        .iter()
        .map(FlatLeaf::Seal)
        .chain(case.sealing().map(FlatLeaf::Record))
        .chain(std::iter::once(FlatLeaf::Order))
        .chain(case.disposals().map(FlatLeaf::Record))
        .collect()
}

/// Flat per-case MMR: every record a leaf, plus the order's `0x05` leaf.
#[allow(clippy::too_many_lines)]
fn flat_mmr(case: &Case, target: u32, redacted: u32) -> Res<serde_json::Value> {
    // §1r.2: the same streamed leaf our audit uses (the flat MMR's leaf is
    // H(0x10 || <<CR>>), exactly the Tier-1 leaf), so both structures get the fix.
    let leaf = |r: &CustodyRecord| Leaf {
        domain: Domain::CustodyRecord,
        digest: r.tier1_leaf(),
    };
    let order_leaf = case.order.leaf();
    let seq = flat_sequence(case);
    let leaf_at = |x: FlatLeaf<'_>| match x {
        FlatLeaf::Seal(c) => c.seal_leaf(),
        FlatLeaf::Record((_, r)) => leaf(r),
        FlatLeaf::Order => order_leaf.clone(),
    };
    let mut mmr = Mmr::new();
    for x in &seq {
        mmr.append(&leaf_at(*x));
    }
    let root = mmr.root().ok_or("empty case")?;
    let at05 = seq
        .iter()
        .position(|x| matches!(x, FlatLeaf::Order))
        .ok_or("no 0x05 leaf")? as u64;
    let proof05 = mmr.prove(at05).ok_or("no proof for the 0x05 leaf")?;
    let accounting = || -> Res<()> {
        if !tier2::verify(&root, &order_leaf, &proof05) {
            return Err("the 0x05 leaf is not anchored".into());
        }
        case.account()
    };
    let positions = |c: u32| -> Vec<(u64, &CustodyRecord)> {
        seq.iter()
            .enumerate()
            .filter_map(|(i, x)| match x {
                FlatLeaf::Record((k, r)) if *k == c => Some((i as u64, r)),
                _ => None,
            })
            .collect()
    };
    // The capsule's own seal leaf is at its index in `case.capsules`, since the
    // sequence starts with them.
    let seal_at = |c: u32| u64::from(c);
    let mine = positions(target);
    // A3 (c): the baseline proves its seal entry too, so both structures
    // disclose the same three things — the capsule, its records, and the order.
    let target_capsule = case
        .capsules
        .get(target as usize)
        .ok_or("target capsule missing")?;
    // ⭐ **One batched proof** for the seal leaf and every record (M13 A8,
    // `audit/06` D7): shared siblings and peaks once, as a flat-log system
    // disclosing one capsule would send them. The seal is position
    // `target`, before every record, so the leaves are already in order.
    let mut want = vec![seal_at(target)];
    want.extend(mine.iter().map(|(i, _)| *i));
    let batch = mmr.prove_many(&want).ok_or("no batched MMR proof")?;
    if batch.indices != want {
        return Err("the batched proof reordered the disclosed leaves".into());
    }
    // ⭐ The court hashes what it was handed **inside** the timer, as ours does
    // (`Segment::checked_leaves` absorbs every record, `Bundle::verify` the seal
    // leaf). Campaign 08 built these leaves before the timer, so the flat MMR's
    // check skipped hashing ~35 KB of records and seal that ours paid for
    //
    let (verify, ()) = timed(|| {
        let mut leaves = vec![target_capsule.seal_leaf()];
        leaves.extend(mine.iter().map(|(_, r)| leaf(r)));
        if !tier2::verify_many(&root, &leaves, &batch) {
            return Err("flat-MMR batched proof does not verify".into());
        }
        Ok(())
    })?;
    let (full, ()) = timed(|| {
        let mut m = Mmr::new();
        for x in &seq {
            m.append(&leaf_at(*x));
        }
        if m.root() != Some(root) {
            return Err("flat-MMR rebuild differs".into());
        }
        accounting()
    })?;
    // §1o.3 F2, the same parallelism its structure allows: leaf hashing is
    // per record and shards; the MMR appends are ordered and stay sequential.
    let threads = audit_threads();
    let (full_parallel, ()) = timed(|| {
        let shards = sharded(&seq, threads, |part| {
            Ok(part.iter().copied().map(leaf_at).collect::<Vec<Leaf>>())
        })?;
        let mut m = Mmr::new();
        for l in shards.iter().flatten() {
            m.append(l);
        }
        if m.root() != Some(root) {
            return Err("flat-MMR parallel rebuild differs".into());
        }
        accounting()
    })?;
    let bytes = target_capsule.encode().len()
        + batch.wire_bytes()
        + mine.iter().map(|(_, r)| r.encode().len()).sum::<usize>();
    let mut scaling = Vec::new();
    for t in cores_axis() {
        let (s, ()) = timed(|| {
            let shards = sharded(&seq, t, |part| {
                Ok(part.iter().copied().map(leaf_at).collect::<Vec<Leaf>>())
            })?;
            let mut m = Mmr::new();
            for l in shards.iter().flatten() {
                m.append(l);
            }
            if m.root() != Some(root) {
                return Err("flat-MMR parallel rebuild differs".into());
            }
            accounting()
        })?;
        scaling.push(serde_json::json!({"threads": t, "full_replay_ns": s}));
    }
    Ok(serde_json::json!({
        "full_replay_parallel_ns": full_parallel,
        "audit_threads": threads,
        "audit_scaling": scaling,
        "disclosed_bytes": bytes,
        "disclosed_records": mine.len(),
        "verify_ns": verify,
        "full_replay_ns": full,
        "full_replay_bytes": case.records.iter().map(|(_, r)| r.encode().len()).sum::<usize>()
            + case.order.encode().len(),
        "exposed": "case size: every proof carries the MMR's leaf count",
        "leaf_count_in_every_proof": batch.count,
        "proof_form": "one batched MMR proof per disclosure (shared siblings and peaks), M13 A8",
        "redacted": flat_redacted(case, redacted, &mmr, &root, at05, &positions(redacted))?,
    }))
}

/// Flat MMR, the lower block: the redacted capsule's records and the order's
/// `0x05` leaf under **one batched proof** (M13 A8), the order, and the
/// capsule's target membership.
fn flat_redacted(
    case: &Case,
    redacted: u32,
    mmr: &Mmr,
    root: &Digest32,
    at05: u64,
    mine: &[(u64, &CustodyRecord)],
) -> Res<serde_json::Value> {
    let leaf = |r: &CustodyRecord| Leaf {
        domain: Domain::CustodyRecord,
        digest: r.tier1_leaf(),
    };
    // The verifier pairs leaves with positions in increasing order, and the
    // `0x05` leaf sits between the sealing records and the `DISPOSE`s.
    // Positions only, here: the leaves are hashed inside the timer below, as
    // in `flat_mmr` (§1bz).
    let place = || -> Vec<(u64, Leaf)> {
        let mut placed: Vec<(u64, Leaf)> = mine.iter().map(|(i, r)| (*i, leaf(r))).collect();
        placed.push((at05, case.order.leaf()));
        placed.sort_by_key(|(i, _)| *i);
        placed
    };
    let mut want: Vec<u64> = mine.iter().map(|(i, _)| *i).collect();
    want.push(at05);
    want.sort_unstable();
    let batch = mmr.prove_many(&want).ok_or("no batched MMR proof")?;
    let eid = case.capsules[redacted as usize].eid;
    let membership = case
        .target
        .prove(&eid)
        .ok_or("redacted capsule not targeted")?;
    let (verify, ()) = timed(|| {
        let leaves: Vec<Leaf> = place().into_iter().map(|(_, l)| l).collect();
        if !tier2::verify_many(root, &leaves, &batch) {
            return Err("flat-MMR batched proof does not verify".into());
        }
        case.account_one(redacted, &membership, mine.iter().map(|(_, r)| *r))
    })?;
    let bytes = case.capsules[redacted as usize].encode().len()
        + mine.iter().map(|(_, r)| r.encode().len()).sum::<usize>()
        + batch.wire_bytes()
        + case.order.encode().len()
        + membership.wire_bytes();
    Ok(serde_json::json!({
        "verify_ns": verify,
        "disclosed_bytes": bytes,
        "disclosed_records": mine.len(),
        "carries": "the capsule's records and the 0x05 leaf under one batched proof, the order, target membership",
    }))
}

/// §1q.2's audit-cores ablation axis, capped at the host's cores: the
/// scaling question of §1p.3 as a measured curve rather than two points.
const AUDIT_CORES: &[usize] = &[1, 2, 4, 8, 16];

fn cores_axis() -> Vec<usize> {
    let host = audit_threads();
    AUDIT_CORES.iter().copied().filter(|&t| t <= host).collect()
}

/// Threads for the all-cores audit columns (§1o.3 F2): the host's cores.
fn audit_threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Run `f` over `items` in `threads` contiguous shards, failing if any shard
/// fails or panics. Shards are independent: no shared state crosses threads.
fn sharded<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    f: impl Fn(&[T]) -> Result<R, String> + Sync,
) -> Res<Vec<R>> {
    let shard = items.len().div_ceil(threads.max(1)).max(1);
    let f = &f;
    std::thread::scope(|s| {
        let hs: Vec<_> = items
            .chunks(shard)
            .map(|part| s.spawn(move || f(part)))
            .collect();
        hs.into_iter()
            .map(|h| {
                h.join()
                    .map_err(|_| "an audit thread panicked".to_owned())?
            })
            .collect::<Result<Vec<R>, String>>()
    })
    .map_err(Into::into)
}

/// Hash-chain replay: one chain over the whole case, its head anchored. The
/// order is a chain entry, recorded before the `DISPOSE`s it authorises.
fn replay(case: &Case, target: u32, redacted: u32) -> Res<serde_json::Value> {
    let encoded: Vec<Vec<u8>> = case
        .sealing()
        .map(|(_, r)| r.encode())
        .chain(std::iter::once(case.order.encode()))
        .chain(case.disposals().map(|(_, r)| r.encode()))
        .collect();
    let chain = |recs: &[Vec<u8>]| {
        recs.iter().fold(digest256(b"case genesis"), |h, r| {
            hash_domain(Domain::ChainLink, &[&h, r])
        })
    };
    let head: Digest32 = chain(&encoded);
    let (verify, found) = timed(|| {
        if chain(&encoded) != head {
            return Err("replayed chain does not reach the anchored head".into());
        }
        // Only after the whole case replays can the court select its capsule.
        Ok(case.records.iter().filter(|(c, _)| *c == target).count())
    })?;
    // The whole-case audit is the replay plus 0x05 accounting over the order entry.
    let (full, ()) = timed(|| {
        if chain(&encoded) != head {
            return Err("replayed chain does not reach the anchored head".into());
        }
        case.account()
    })?;
    let eid = case.capsules[redacted as usize].eid;
    let membership = case
        .target
        .prove(&eid)
        .ok_or("redacted capsule not targeted")?;
    let (verify_r, ()) = timed(|| {
        if chain(&encoded) != head {
            return Err("replayed chain does not reach the anchored head".into());
        }
        case.account_one(
            redacted,
            &membership,
            case.records
                .iter()
                .filter(|(k, _)| *k == redacted)
                .map(|(_, r)| r),
        )
    })?;
    let bytes =
        case.capsules[target as usize].encode().len() + encoded.iter().map(Vec::len).sum::<usize>();
    Ok(serde_json::json!({
        "disclosed_bytes": bytes,
        "disclosed_records": encoded.len(),
        "target_records": found,
        "verify_ns": verify,
        "full_replay_ns": full,
        "full_replay_parallel_ns": null,
        "parallel_note": "inherently sequential: each link needs the previous head, so the all-cores audit is the one-core audit",
        "full_replay_bytes": bytes,
        "exposed": "all records of the case",
        "redacted": {
            "verify_ns": verify_r,
            "disclosed_bytes": bytes + membership.wire_bytes(),
            "disclosed_records": encoded.len(),
            "carries": "every record and the order entry, plus target membership",
        },
    }))
}

/// The stored objects of one capsule in a per-object structure: its seal
/// object first, then its records in stream order.
fn capsule_objects(case: &Case, c: u32) -> impl Iterator<Item = &CustodyRecord> {
    case.records
        .iter()
        .filter(move |(k, _)| *k == c)
        .map(|(_, r)| r)
}

/// **PQ-ABL** (Fugkeaw et al., IEEE TCC 2026; SAC `b23`): one independent
/// Merkle tree per epoch over `h_n = H(CT_n)`, one leaf per stored object, the
/// epoch root anchored. Its epochs are ours: each sealing epoch holds the seal
/// object of every capsule collected in it (just before its `COLLECT`) and its
/// records in stream order; the redaction epoch holds the order and the
/// `DISPOSE`s. The court receives each object with its own `O(log N)` path
/// (Phase 5 Step 3, standalone membership); the auditor runs full-epoch
/// verification over every epoch (eq. (1)).
#[allow(clippy::too_many_lines)]
fn pq_abl(case: &Case, target: u32, redacted: u32) -> Res<serde_json::Value> {
    use baseline_pqabl::{EpochTree, Path, leaf, verify, verify_epoch, verify_epoch_parallel};
    // The stored ciphertext objects per epoch, as bytes: what the auditor
    // downloads. `at[i]` is record `i`'s `(epoch, position)`, `cap_at[c]` the
    // capsule object's.
    let red_e = usize::try_from(case.sealing_epochs)?;
    let mut epochs: Vec<Vec<Vec<u8>>> = vec![Vec::new(); red_e + 1];
    epochs[red_e].push(case.order.encode());
    let mut at: Vec<(usize, usize)> = Vec::with_capacity(case.records.len());
    let mut cap_at: BTreeMap<u32, (usize, usize)> = BTreeMap::new();
    for ((c, r), e) in case.records.iter().zip(&case.epochs) {
        let e = usize::try_from(*e)?;
        if r.order_ref.is_none() && !cap_at.contains_key(c) {
            cap_at.insert(*c, (e, epochs[e].len()));
            epochs[e].push(case.capsules[*c as usize].encode());
        }
        at.push((e, epochs[e].len()));
        epochs[e].push(r.encode());
    }
    let trees = epochs
        .iter()
        .map(|objs| {
            EpochTree::build(objs.iter().map(|o| leaf(o)).collect()).ok_or("an empty PQ-ABL epoch")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let roots: Vec<Digest32> = trees.iter().map(EpochTree::root).collect();
    // One capsule's disclosure: (epoch root, object bytes, path) per object.
    let disclose = |c: u32| -> Res<Vec<(Digest32, Vec<u8>, Path)>> {
        let (ce, ci) = *cap_at.get(&c).ok_or("capsule object missing")?;
        let mut out = vec![(
            roots[ce],
            epochs[ce][ci].clone(),
            trees[ce].prove(ci).ok_or("no seal path")?,
        )];
        for (i, (k, _)) in case.records.iter().enumerate() {
            if *k == c {
                let (e, j) = at[i];
                out.push((
                    roots[e],
                    epochs[e][j].clone(),
                    trees[e].prove(j).ok_or("no path")?,
                ));
            }
        }
        Ok(out)
    };
    let check = |objs: &[(Digest32, Vec<u8>, Path)]| -> Res<()> {
        for (root, o, p) in objs {
            if !verify(root, &leaf(o), p) {
                return Err("PQ-ABL membership path does not verify".into());
            }
        }
        Ok(())
    };
    let wire = |objs: &[(Digest32, Vec<u8>, Path)]| {
        objs.iter()
            .map(|(_, o, p)| o.len() + p.wire_bytes())
            .sum::<usize>()
    };
    let mine = disclose(target)?;
    let (verify_t, ()) = timed(|| check(&mine))?;
    // The redacted capsule: its objects across its epochs, the order with its
    // redaction-epoch path, and the capsule's membership in the order's target.
    let red = disclose(redacted)?;
    let order_path = trees[red_e].prove(0).ok_or("no order path")?;
    let eid = case.capsules[redacted as usize].eid;
    let membership = case
        .target
        .prove(&eid)
        .ok_or("redacted capsule not targeted")?;
    let red_records: Vec<&CustodyRecord> = capsule_objects(case, redacted).collect();
    let (verify_r, ()) = timed(|| {
        check(&red)?;
        if !verify(&roots[red_e], &leaf(&epochs[red_e][0]), &order_path) {
            return Err("PQ-ABL order path does not verify".into());
        }
        case.account_one(redacted, &membership, red_records.iter().copied())
    })?;
    let accounting = || case.account();
    let (full, ()) = timed(|| {
        if !epochs.iter().zip(&roots).all(|(o, r)| verify_epoch(o, r)) {
            return Err("PQ-ABL epoch validation failed".into());
        }
        accounting()
    })?;
    // Epochs are independent, so the threads go across them first and inside
    // an epoch only when there are fewer epochs than threads: the most
    // parallelism the structure allows.
    let ids: Vec<usize> = (0..epochs.len()).collect();
    let audit_on = |t: usize| -> Res<()> {
        let inner = (t / epochs.len()).max(1);
        sharded(&ids, t, |part| {
            if part
                .iter()
                .all(|&e| verify_epoch_parallel(&epochs[e], &roots[e], inner))
            {
                Ok(())
            } else {
                Err("PQ-ABL parallel epoch validation failed".to_owned())
            }
        })?;
        accounting()
    };
    let threads = audit_threads();
    let (full_parallel, ()) = timed(|| audit_on(threads))?;
    let mut scaling = Vec::new();
    for t in cores_axis() {
        let (s, ()) = timed(|| audit_on(t))?;
        scaling.push(serde_json::json!({"threads": t, "full_replay_ns": s}));
    }
    Ok(serde_json::json!({
        "disclosed_bytes": wire(&mine),
        "disclosed_records": mine.len() - 1,
        "disclosed_paths": mine.len(),
        "verify_ns": verify_t,
        "full_replay_ns": full,
        "full_replay_parallel_ns": full_parallel,
        "audit_threads": threads,
        "audit_scaling": scaling,
        "full_replay_bytes": epochs.iter().flatten().map(Vec::len).sum::<usize>(),
        "epoch_logs": epochs.iter().map(Vec::len).collect::<Vec<_>>(),
        "exposed": "each epoch's log count: every path carries it, and fixes the tree's shape",
        "proof_form": "one standalone O(log N) path per object against its epoch root (Phase 5 Step 3)",
        "audit": "full-epoch verification of every epoch: recompute every h_n, rebuild, compare (eq. (1)), plus order accounting",
        "redacted": {
            "verify_ns": verify_r,
            "disclosed_bytes": wire(&red) + epochs[red_e][0].len() + order_path.wire_bytes() + membership.wire_bytes(),
            "disclosed_records": red.len() - 1,
            "carries": "seal object and every record with its own path against its own epoch's root (the DISPOSE against the redaction epoch's), the order with its path, target membership",
        },
    }))
}

/// A `GlassDB` key: the capsule's stable intake number, then the kind (`0` the
/// capsule object, `1` its custody record). Big-endian, so key order is intake
/// order; the order's key sorts first.
fn glass_key(c: u32, kind: u8) -> Vec<u8> {
    let mut k = (c + 1).to_be_bytes().to_vec();
    k.push(kind);
    k
}

/// **`GlassDB`** (Yue et al., PVLDB 16(6) 2023; SAC `b32`): a two-level POS-tree
/// ledger. The custody records are versions of one key per capsule, the
/// capsule object and the order are keys of their own, and writes are persisted
/// in stream order in blocks of `BATCH` (the order before the `DISPOSE`s). The
/// court receives the capsule's current value and the record key's full
/// version history at the last block; the auditor runs `VerifyBlock` over every
/// block.
#[allow(clippy::too_many_lines)]
fn glassdb(case: &Case, target: u32, redacted: u32) -> Res<serde_json::Value> {
    use baseline_glassdb::{Ledger, Write};
    use std::sync::Arc;
    let order_key = vec![0, 0, 0, 0, 2];
    let mut writes: Vec<Write> = Vec::with_capacity(case.records.len() + case.capsules.len() + 1);
    let mut opened = vec![false; case.capsules.len()];
    for (c, r) in case.sealing() {
        let c = *c;
        if !std::mem::replace(&mut opened[c as usize], true) {
            writes.push((glass_key(c, 0), case.capsules[c as usize].encode().into()));
        }
        writes.push((glass_key(c, 1), Arc::from(r.encode())));
    }
    writes.push((order_key.clone(), case.order.encode().into()));
    for (c, r) in case.disposals() {
        writes.push((glass_key(*c, 1), Arc::from(r.encode())));
    }
    let start = Instant::now();
    let mut ledger = Ledger::new();
    ledger.persist(&writes);
    let build = start.elapsed();
    let digest = ledger.digest().ok_or("an empty GlassDB ledger")?;
    let n_blocks = ledger.blocks().len();
    // The court: one capsule's object and its record key's history.
    let (cap_k, rec_k) = (glass_key(target, 0), glass_key(target, 1));
    let proof = ledger
        .prove(&[&cap_k], &[&rec_k])
        .ok_or("no GlassDB proof")?;
    let (verify_t, got) = timed(|| {
        Ledger::verify(&digest, &proof, &[&cap_k], &[&rec_k])
            .ok_or_else(|| "GlassDB history proof does not verify".into())
    })?;
    if got.history[0].len() != capsule_objects(case, target).count()
        || got.current[0] != case.capsules[target as usize].encode()
    {
        return Err("GlassDB history is not the capsule's chain".into());
    }
    // The redacted capsule: also the order's current value, and membership.
    let (rcap_k, rrec_k) = (glass_key(redacted, 0), glass_key(redacted, 1));
    let rproof = ledger
        .prove(&[&rcap_k, &order_key], &[&rrec_k])
        .ok_or("no GlassDB proof")?;
    let eid = case.capsules[redacted as usize].eid;
    let membership = case
        .target
        .prove(&eid)
        .ok_or("redacted capsule not targeted")?;
    let red_records: Vec<&CustodyRecord> = capsule_objects(case, redacted).collect();
    let (verify_r, ()) = timed(|| {
        let v = Ledger::verify(&digest, &rproof, &[&rcap_k, &order_key], &[&rrec_k])
            .ok_or("GlassDB history proof does not verify")?;
        if v.history[0].len() != red_records.len() {
            return Err("GlassDB history is not the capsule's chain".into());
        }
        case.account_one(redacted, &membership, red_records.iter().copied())
    })?;
    // `VerifyBlock` over every block. One auditor keeps the nodes it has
    // already hashed (they are immutable and named by hash), as ours keeps its
    // Tier-2 node memo.
    let all_blocks: Vec<usize> = (0..n_blocks).collect();
    let audit = |blocks: &[usize]| -> Result<(), String> {
        let mut memo = std::collections::HashSet::new();
        for &b in blocks {
            if !ledger.verify_block(b, &digest, &mut memo) {
                return Err(format!("GlassDB VerifyBlock failed at block {b}"));
            }
        }
        Ok(())
    };
    let (full, ()) = timed(|| {
        audit(&all_blocks)?;
        case.account()
    })?;
    let threads = audit_threads();
    let audit_on = |t: usize| -> Res<()> {
        sharded(&all_blocks, t, |part| audit(part))?;
        case.account()
    };
    let (full_parallel, ()) = timed(|| audit_on(threads))?;
    let mut scaling = Vec::new();
    for t in cores_axis() {
        let (s, ()) = timed(|| audit_on(t))?;
        scaling.push(serde_json::json!({"threads": t, "full_replay_ns": s}));
    }
    Ok(serde_json::json!({
        "disclosed_bytes": proof.wire_bytes(),
        "disclosed_records": got.history[0].len(),
        "disclosed_nodes": proof.nodes.len(),
        "verify_ns": verify_t,
        "full_replay_ns": full,
        "full_replay_parallel_ns": full_parallel,
        "audit_threads": threads,
        "audit_scaling": scaling,
        "full_replay_bytes": writes.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>(),
        "blocks": n_blocks,
        "batch": baseline_glassdb::BATCH,
        "stored_nodes": ledger.stored_nodes(),
        "build_ns": build.as_nanos(),
        "exposed": "the neighbouring entries of every disclosed leaf node (other capsules' sealed records and intake numbers), and the block count",
        "proof_form": "current-value proof at the last block (upper path, data block, lower path) plus each earlier version through its H_prev pointer",
        "audit": "VerifyBlock over every block (block proof against the digest, every written key included with its value), plus order accounting",
        "redacted": {
            "verify_ns": verify_r,
            "disclosed_bytes": rproof.wire_bytes() + membership.wire_bytes(),
            "disclosed_records": red_records.len(),
            "carries": "the capsule object, the order and the record key's full history under one de-duplicated node set, target membership",
        },
    }))
}

/// The capsule with the median chain length among those `keep` admits — the
/// typical court request.
fn median_capsule(case: &Case, keep: impl Fn(u32) -> bool) -> Res<u32> {
    let mut len: BTreeMap<u32, usize> = BTreeMap::new();
    for (c, _) in case.records.iter().filter(|(c, _)| keep(*c)) {
        *len.entry(*c).or_default() += 1;
    }
    let mut v: Vec<(usize, u32)> = len.into_iter().map(|(c, n)| (n, c)).collect();
    v.sort_unstable();
    v.get(v.len() / 2)
        .map(|(_, c)| *c)
        .ok_or_else(|| "empty case".into())
}

fn one_size(target_records: usize) -> Res<(serde_json::Value, Backend)> {
    let capsules = u32::try_from(
        (target_records * 10)
            .div_ceil(RECORDS_PER_CAPSULE_X10)
            .max(1),
    )?;
    let params = StreamParams {
        capsules,
        active: 64,
        ..StreamParams::default()
    };
    let stream = custody_stream(&params);
    let cast = Cast::generate()?;
    let keys = CaseKeys::derive(
        &PrfKey::new(digest256(b"K_mst (custody)")),
        b"case",
        &digest256(b"r_case"),
    );
    let appender = from_env(&cast, &keys)?;
    let backend = appender.backend();
    let case = build_case(&*appender, &keys, &stream, target_records)?;
    let is_disposed = |c: u32| case.disposed.binary_search(&c).is_ok();
    let target = median_capsule(&case, |c| !is_disposed(c))?;
    let redacted = median_capsule(&case, is_disposed)?;
    eprintln!(
        "  {} records over {} capsules ({} disposed), target capsule {target}, redacted {redacted}",
        case.records.len(),
        case.capsules.len(),
        case.disposed.len()
    );
    Ok((
        serde_json::json!({
            "records": case.records.len(),
            "capsules": case.capsules.len(),
            "stream": {"params": params, "counts": event_counts(&stream)},
            "record_build_total_ns": case.build.as_nanos(),
            "target_capsule": target,
            "redacted_capsule": redacted,
            "disposed_capsules": case.disposed.len(),
            "epoch_records": case.epoch_records,
            "sealing_epochs": case.sealing_epochs,
            "epochs_are": "sealing epochs of epoch_records records each, closed by count in stream order, then one redaction epoch (the design record item 2); GlassDB keeps its own 1,000-write blocks",
            "order": {"scope": "FULL", "mode": "ERASED", "one_sweep_over_every_disposal": true,
                      "encoded_bytes": case.order.encode().len()},
            "ours": ours(&case, &Discloser::new(&*appender, keys.cid_c)?, target, redacted)?,
            "flat_mmr": flat_mmr(&case, target, redacted)?,
            "hash_chain_replay": replay(&case, target, redacted)?,
            "pq_abl": pq_abl(&case, target, redacted)?,
            "glassdb": glassdb(&case, target, redacted)?,
        }),
        backend,
    ))
}

/// Per-record signature verification: the term common to every scheme.
fn record_signature_verify() -> Res<serde_json::Value> {
    let signer = SoftwareMlDsa::generate()?;
    let msg = digest256(b"a custody record's signed bytes");
    let sig = signer.sign(&msg)?;
    let (v, ()) = timed(|| {
        mldsa_verify(&msg, &sig, signer.public_key(), b"")?;
        Ok(())
    })?;
    Ok(serde_json::to_value(v)?)
}

/// One sealed capsule and its opening `COLLECT` per timed iteration, all made
/// before the timer starts.
///
/// ⭐ **A fresh capsule for every timed iteration** (campaign 08, round 2). Each
/// transfer arm used to re-sign positions 1 and 2 of *one* capsule
/// `MIN_ITERATIONS` times. Position `j` is the body's AES-GCM nonce under that
/// capsule's key, so in process that was real nonce reuse, different
/// plaintexts under one (key, nonce), and the enclave's position guard refused
/// it on the first repeat. Signing cost does not depend on which capsule is
/// signed, so no number moves for it.
fn fresh_capsules(
    appender: &dyn CustodyAppender,
    keys: &CaseKeys,
    label: &[u8],
) -> Res<std::vec::IntoIter<(Capsule, CustodyRecord)>> {
    let mut out = Vec::new();
    for k in 0..MIN_ITERATIONS {
        let nonce = digest256(&[label, &u64::from(k).to_le_bytes()].concat());
        let capsule = appender.seal(&SealRequest {
            cid_c: keys.cid_c,
            cm_ev: digest256(b"cm"),
            nonce,
            epoch: 0,
            artefact_type: b"disk-image".to_vec(),
            d_ev: hash_domain(Domain::EvidenceDigest, &[&nonce]),
            ptr: b"s3://evidence/capsule".to_vec(),
        })?;
        let collect = appender
            .append(&AppendRequest {
                cid_c: keys.cid_c,
                capsule: capsule.eid.into(),
                actor: pqcl_sm::cast_member(Role::Defr),
                doc: 0,
                params: RecordParams::at(0, 1).with_params(Params::justified(&1u64.to_le_bytes())),
                step: AppendStep::Collect,
            })?
            .signed
            .record;
        out.push((capsule, collect));
    }
    Ok(out.into_iter())
}

/// A two-party `TRANSFER` against a one-party one, both through one appender.
///
/// ⭐ **Both arms through the same `CustodyAppender`** (M13 A18), so on the
/// campaign instance both cross the enclave boundary and the difference is the
/// protocol's: a second record, the descriptor, the counter-signature and the
/// `d_ev` re-check. Each arm has its own capsule, because the enclave refuses a
/// second record at a position it has signed, and the two arms would otherwise
/// both claim position 1 of one chain.
///
/// ⭐ **Two custodians, two keys** (`(role, id)` enrolment, §1br.4). The
/// evidence store signs the release; the lab's custodian witnesses it and signs
/// the receipt. Between A18 and this change one custodian key signed all
/// three, because an appender enrolled one actor per role.
fn bilateral_transfer() -> Res<(serde_json::Value, Backend)> {
    let cast = Cast::generate()?;
    let keys = CaseKeys::derive(
        &PrfKey::new(digest256(b"K_mst (transfer)")),
        b"case",
        &digest256(b"r"),
    );
    let appender = from_env(&cast, &keys)?;
    let rp =
        |j: u64, ts: u64| RecordParams::at(j, ts).with_params(Params::justified(&ts.to_le_bytes()));

    let fresh = |label: &[u8]| fresh_capsules(&*appender, &keys, label);

    // The baseline: one record, no descriptor, no receipt. Named in `case.rs`
    // so no harness writes a lone transfer by accident (M13 A14).
    let mut ones = fresh(b"capsule (unilateral)")?;
    let (one, ()) = timed(|| {
        let (one_capsule, one_collect) = ones.next().ok_or("ran out of fresh capsules")?;
        case::unilateral_transfer(&*appender, &keys, &one_capsule, &one_collect, &rp(1, 2))?;
        Ok(())
    })?;

    // ⭐ **The bilateral form, through the appender** — `handoff::release` and
    // `handoff::receive` run by `pqcl_sm::sign_step`, the release witnessed
    // before it is returned because the receipt's link covers the Tier-1 leaf
    // that signature sits in (M13 A14).
    let mut twos = fresh(b"capsule (bilateral)")?;
    let (two, witnessed) = timed(|| {
        let (capsule, collect) = twos.next().ok_or("ran out of fresh capsules")?;
        let release = appender.append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: capsule.eid.into(),
            actor: pqcl_sm::evidence_store(),
            doc: 0,
            params: rp(1, 2),
            step: AppendStep::Release {
                capsule: Box::new(capsule.clone()),
                chain: vec![collect.clone()],
                cond: hash_domain(Domain::HandoffDescriptor, &[b"cond", b"sealed bag"]),
                witness: pqcl_sm::lab_custodian(),
            },
        })?;
        let pairing = release
            .pairing
            .clone()
            .ok_or("a release came back without its pairing")?;
        let receipt = appender.append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: capsule.eid.into(),
            actor: pqcl_sm::lab_custodian(),
            doc: 0,
            params: rp(2, 3),
            step: AppendStep::Receipt {
                capsule: Box::new(capsule.clone()),
                chain: vec![collect.clone(), release.signed.record.clone()],
                recomputed: capsule.d_ev,
                pairing,
            },
        })?;
        Ok((release.signed.record, receipt.signed.record, capsule.eid))
    })?;
    // Both signatures on the sender's record must verify, or this measured
    // something that is not a bilateral transfer.
    let (out, receipt, release_eid) = witnessed;
    // Outside the timer. Both signatures are inside `C_rec` since §1br F2, so
    // the check opens the release under the capsule's body key first.
    let store = appender.verification_key(&pqcl_sm::evidence_store())?;
    let lab = appender.verification_key(&pqcl_sm::lab_custodian())?;
    if store == lab {
        return Err("the two custodians share a key; the transfer would be one party's".into());
    }
    // ⭐ The body key comes from the Secure Module, sealed to a court key, as a
    // disclosure would carry it (M13 A18). `keys.record_body_key` is the
    // harness's own derivation and matches only the host backend: inside the
    // enclave `K_case` derives from the enclave's `K_mst`, and campaign 08's
    // c08c2 failed here with `Authentication` after every case had run.
    let court = pqcl_primitives::kem::KeyPair::generate()?;
    let k_rec = appender
        .seal_disclosure(&keys.cid_c, &release_eid, court.encapsulation_key())?
        .open(&court)?
        .k_rec;
    let o = out.open(&pqcl_primitives::aead::CustodyKey::new(k_rec))?;
    let signed = record_signed_bytes(&out, &o.body);
    mldsa_verify(&signed, &o.sigs.actor, &store, b"")?;
    mldsa_verify(
        &signed,
        o.sigs.witness.as_deref().ok_or("no witness")?,
        &lab,
        b"",
    )?;
    Ok((
        serde_json::json!({
            "unilateral_ns": one,
            "bilateral_ns": two,
            "bilateral_records": 2,
            "bilateral_signatures": 3,
            "bilateral_bytes": out.encode().len() + receipt.encode().len(),
            "custodian_keys": 2,
            "custodian_keys_note": "actors enrolled by (role, id): the evidence store signs the release, the lab custodian witnesses it and signs the receipt; both keys checked distinct and both signatures verified outside the timer",
            "both_arms_indexed": "each record's 29 custody tokens are produced inside the timed call, as the enclave does in the same round trip",
        }),
        appender.backend(),
    ))
}

/// An epoch root endorsed by `M` custodians as `M` independent signatures.
fn committee() -> Res<serde_json::Value> {
    let root = digest256(b"epoch root");
    let mut rows = Vec::new();
    for &m in COMMITTEES {
        let members = (0..m)
            .map(|_| SoftwareMlDsa::generate())
            .collect::<Result<Vec<_>, _>>()?;
        let (sign, sigs) = timed(|| {
            members
                .iter()
                .map(|s| s.sign(&root).map_err(Into::into))
                .collect::<Res<Vec<_>>>()
        })?;
        let (verify, ()) = timed(|| {
            for (s, sig) in members.iter().zip(&sigs) {
                mldsa_verify(&root, sig, s.public_key(), b"")?;
            }
            Ok(())
        })?;
        rows.push(serde_json::json!({
            "members": m,
            "sign_ns": sign,
            "verify_ns": verify,
            "signature_bytes": sigs.iter().map(Vec::len).sum::<usize>(),
        }));
    }
    Ok(serde_json::json!(rows))
}

fn main() -> Res<()> {
    let sizes: Vec<usize> = std::env::var("PQCL_CUSTODY_SIZES").map_or_else(
        |_| DEFAULT_SIZES.to_vec(),
        |s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
    );
    let mut cases = Vec::new();
    // ⭐ Every part of the run that builds custody records reports the backend
    // it actually used, and the run is refused if they differ: a record stamped
    // with one Secure Module must not hold numbers from another.
    let mut backends = std::collections::BTreeSet::new();
    for n in &sizes {
        eprintln!("case of ~{n} records");
        let (case, backend) = one_size(*n)?;
        backends.insert(backend.label());
        cases.push(case);
    }
    let (transfer, backend) = bilateral_transfer()?;
    backends.insert(backend.label());
    if backends.len() != 1 {
        return Err(format!("one run built through several Secure Modules: {backends:?}").into());
    }
    let measurements = serde_json::json!({
        "cases": cases,
        "record_signature_verify_ns": record_signature_verify()?,
        "bilateral_transfer": transfer,
        "committee": committee()?,
        "method": {
            "same_records": "each case's records are built once and every scheme discloses from them",
            "verify": "hash-level integrity from the anchored root for all three; ML-DSA verification of the disclosed records is common and reported once",
            "target": "the capsule with the median chain length",
            "committee_is_not_threshold": "M independent ML-DSA-65 signatures: the upper bound a threshold scheme reduces to one signature",
        },
    });
    emit_custody(
        "custody-disclosure",
        RunSpec {
            liboqs_version: "ML-DSA-65 via liboqs".to_owned(),
            rng_seeds: vec![StreamParams::default().seed],
            ..RunSpec::default()
        },
        MIN_ITERATIONS,
        measurements,
        backend,
    )?;
    Ok(())
}
