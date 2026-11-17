//! **Experiment 8 — tamper detection and response** (M10 H8, `sec:exp-tamper`).
//!
//! A running pipeline over the **real M8 artefacts** (the E01, the RAM
//! capture, the pcap), sealed chunk-wise so every check below reads
//! ciphertext and holds no key. Four injection classes, each timed from the
//! moment of injection to the alert:
//!
//! | class | ours | baselines |
//! |---|---|---|
//! | payload altered at rest | Q3 sampled sweep | full re-hash **at the same read budget**; verify-on-access |
//! | payload altered, then read | Q2 chunk check on read | flat verify-on-access (hash the whole object); re-hash |
//! | custody record edited | epoch auditor (Tier 1 → Tier 2 → anchored root) | verify-on-access (only on disclosure) |
//! | agent-epoch omitted | `epoch_la_id` contiguity (§8a.3) | re-hash n/a; verify-on-access never |
//! | payload deleted, no order | `0x05` accounting at the auditor's period | full re-hash **given the operator's deletion list**; verify-on-access never |
//!
//! Also: bytes read to the alert, and **localisation** — the fraction of the
//! artefact still admissible.
//!
//! # Parameters, fixed before measuring
//!
//! * Read budget `PQCL_TAMPER_BUDGET`, default **50 MB/s** — design §14.3's
//!   own example. Shared by the sweep and the full re-hash, never by Q2: a
//!   read's verification is the reader's own I/O.
//! * Audit period `PQCL_AUDIT_PERIOD_S`, default 10 s — the epoch length that
//!   bounds §8a's detection latency.
//! * Trials `PQCL_TAMPER_TRIALS`, default 20 (the M4b acceptance's floor).
//!
//! ⚠️ "Never" is a result, not a gap: a verify-on-access baseline whose object
//! nobody reads raises no alert, and the record says so with `null` plus the
//! window observed, not with a large number standing in for infinity.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pqcl_bench::RunSpec;
use pqcl_capsule::{Bundle, Event, Params, Role};
use pqcl_exp::appender::from_env;
use pqcl_exp::case::CaseBuilder;
use pqcl_exp::cast::Cast;
use pqcl_exp::custody_stream::{StreamParams, custody_stream};
use pqcl_exp::{emit_custody, stats::Summary};
use pqcl_pipeline::agent_epoch::{AgentWriter, ControlCapsule, EvidenceRecord, Heartbeat};
use pqcl_pipeline::audit::{
    Finding, SplitMix, StoredObject, Sweeper, audit_agent_epochs, audit_heartbeats, budget_time,
    read_verified,
};
use pqcl_pipeline::chunked::{CHUNK_BYTES, digest_file};
use pqcl_pipeline::{Ais, CaseKeys, RecordParams};
use pqcl_primitives::SoftwareMlDsa;
use pqcl_primitives::aead::RecordKey;
use pqcl_primitives::xof::{Domain, PrfKey, digest256};
use pqcl_sm::{AppendRequest, AppendStep, Backend, CustodyAppender, SealRequest};

type Res<T> = Result<T, Box<dyn core::error::Error>>;

const ARTEFACTS: &[&str] = &[
    "nps-2009-canon2-gen6.E01",
    "charlie-2009-12-03.mddramimage",
    "multifile_25_21.pcap",
];

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Plaintext per sealed record: one `d_ev` chunk less the GCM tag (M13 A9).
///
/// ⭐ **So each GCM record is exactly one `d_ev` chunk.** Records used to hold
/// 1 MiB of plaintext, so with the tag each was 1 MiB + 16 B of ciphertext and
/// straddled two 1 MiB digest chunks: a damaged digest chunk did not map to one
/// undecryptable record, and the localisation the paper claims — the damaged
/// region fails alone, the rest stays readable — was not what the store did.
const PLAIN_CHUNK: usize = CHUNK_BYTES - pqcl_primitives::aead::TAG_BYTES;

/// The key and associated data of sealed record `i`.
fn record_key(seed: &[u8], i: u64) -> RecordKey {
    RecordKey::new(digest256(&[seed, &i.to_le_bytes()].concat()))
}

/// Open sealed record `i` of `path`: the `d_ev` chunk at the same index.
///
/// Test-only: the harness never decrypts, since the sweeper and the auditor are
/// keyless; the test uses it to show the damaged record fails alone.
#[cfg(test)]
fn open_record(path: &Path, seed: &[u8], i: u64) -> Res<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(i * CHUNK_BYTES as u64))?;
    let mut buf = Vec::with_capacity(CHUNK_BYTES);
    f.take(CHUNK_BYTES as u64).read_to_end(&mut buf)?;
    let sealed = pqcl_primitives::aead::SealedRecord::from_bytes(buf);
    Ok(record_key(seed, i).open(&i.to_le_bytes(), &sealed)?)
}

/// Seal an artefact chunk-wise (AES-256-GCM, a key per chunk) into `out`, and
/// return its anchored `d_ev` over the ciphertext.
fn seal_artefact(src: &Path, out: &Path, seed: &[u8]) -> Res<StoredObject> {
    let mut r = std::fs::File::open(src).map_err(|e| format!("{}: {e}", src.display()))?;
    let mut w = std::io::BufWriter::new(std::fs::File::create(out)?);
    let mut buf = vec![0u8; PLAIN_CHUNK];
    for i in 0u64.. {
        let n = read_full(&mut r, &mut buf)?;
        if n == 0 {
            break;
        }
        w.write_all(
            record_key(seed, i)
                .seal(&i.to_le_bytes(), &buf[..n])?
                .as_bytes(),
        )?;
    }
    w.flush()?;
    drop(w);
    let d_ev = digest_file(out, Domain::EvidenceDigest)?;
    // The anchor *is* this seal-time root: the capsule is sealed over it, so
    // here the binding check holds by construction. In a deployment the root
    // comes from the anchored capsule and the leaf list from storage, and the
    // check is what stops a rewritten list (M13 A12).
    let anchored = *d_ev.root();
    Ok(StoredObject::open(
        src.file_name()
            .map_or_else(String::new, |s| s.to_string_lossy().into_owned()),
        out.to_path_buf(),
        &anchored,
        d_ev,
    )?)
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Flip one byte in place; returns the original so the trial can restore it.
fn flip(path: &Path, offset: u64) -> Res<u8> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut b = [0u8; 1];
    f.read_exact(&mut b)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&[b[0] ^ 0x5a])?;
    f.sync_data()?;
    Ok(b[0])
}

fn restore(path: &Path, offset: u64, original: u8) -> Res<()> {
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&[original])?;
    f.sync_data()?;
    Ok(())
}

/// A uniformly random byte across every object.
fn pick_byte(objs: &[StoredObject], rng: &mut SplitMix) -> (usize, u64) {
    let total: u64 = objs.iter().map(|o| o.d_ev().byte_len()).sum();
    let mut at = rng.next_u64() % total.max(1);
    for (i, o) in objs.iter().enumerate() {
        if at < o.d_ev().byte_len() {
            return (i, at);
        }
        at -= o.d_ev().byte_len();
    }
    (0, 0)
}

/// The full re-hash baseline: hash each whole object in turn at the budget,
/// compare only the whole-object root — the verdict a flat digest gives, at
/// the same I/O and hashing cost. It starts at a uniformly random phase of its
/// cycle, reading (without a verdict) the rest of the object it is inside.
fn rehash_until_detect(
    objs: &[StoredObject],
    budget: u64,
    target: usize,
    flip_at: u64,
    rng: &mut SplitMix,
) -> Res<(Duration, u64)> {
    let total: u64 = objs.iter().map(|o| o.d_ev().byte_len()).sum();
    rehash_from_phase(objs, budget, target, flip_at, rng.next_u64() % total.max(1))
}

/// [`rehash_until_detect`] at a given phase: the byte of its cycle the
/// re-hasher is at when the tamper happens.
fn rehash_from_phase(
    objs: &[StoredObject],
    budget: u64,
    target: usize,
    flip_at: u64,
    phase: u64,
) -> Res<(Duration, u64)> {
    let (mut idx, mut skip) = (0usize, phase);
    while skip >= objs[idx].d_ev().byte_len() {
        skip -= objs[idx].d_ev().byte_len();
        idx += 1;
    }

    // ⭐ **A verdict on the object in progress when the damage lies ahead of
    // the phase** (M13 A11, `audit/06d` L5-a). The re-hasher was already
    // reading this object when the flip happened: everything before `skip` it
    // hashed beforehand, and the flip — if it lies at or past `skip` — is in
    // the part it reads now, so its digest at the object's end is the damaged
    // one. The baseline used to read the remainder and give no verdict, which
    // made it wait a whole further cycle about 46% of the time here (the RAM
    // image is 96% of the bytes): a handicap of the harness, not of re-hashing.
    //
    // The prefix is hashed **before the clock starts**, since in the modelled
    // run it was hashed before the tamper; only the remainder is charged.
    if idx == target && flip_at >= skip {
        let prefix = chunk_leaves(&objs[idx].path, skip)?;
        let start = Instant::now();
        let mut read = 0u64;
        let root = paced_digest_from(&objs[idx].path, prefix, budget, &mut read, start)?;
        if root == *objs[idx].d_ev().root() {
            return Err(format!(
                "the re-hash read the damaged part of {} and found it intact",
                objs[idx].id
            )
            .into());
        }
        return Ok((start.elapsed(), read));
    }

    let start = Instant::now();
    let mut read = 0u64;
    // The remainder of the object the cycle is inside, the damage behind the
    // phase or elsewhere: read, no verdict — its digest covers bytes hashed
    // before the tamper.
    let rest = objs[idx].d_ev().byte_len() - skip;
    stream(&objs[idx].path, skip, rest, budget, &mut read, start)?;
    loop {
        idx = (idx + 1) % objs.len();
        let o = &objs[idx];
        let d = paced_digest(&o.path, budget, &mut read, start)?;
        if d != *o.d_ev().root() {
            if idx != target {
                return Err(format!(
                    "re-hash flagged {} but the injection was in {}",
                    o.id, objs[target].id
                )
                .into());
            }
            return Ok((start.elapsed(), read));
        }
    }
}

/// Read `[from, from+len)` at the budget, discarding it.
fn stream(
    path: &Path,
    from: u64,
    len: u64,
    budget: u64,
    read: &mut u64,
    start: Instant,
) -> Res<()> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(from))?;
    let mut left = len;
    let mut buf = vec![0u8; CHUNK_BYTES];
    while left > 0 {
        let want = usize::try_from(left.min(CHUNK_BYTES as u64)).unwrap_or(CHUNK_BYTES);
        let n = read_full(&mut f, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        left -= n as u64;
        *read += n as u64;
        pace(*read, budget, start);
    }
    Ok(())
}

/// The object's chunked root, read at the budget.
fn paced_digest(path: &Path, budget: u64, read: &mut u64, start: Instant) -> Res<[u8; 32]> {
    paced_digest_from(path, Vec::new(), budget, read, start)
}

/// The chunk leaves of a file's first `upto` bytes, rounded down to whole
/// chunks — what a re-hasher that has read that far already holds. Unpaced:
/// it models work done before the clock starts.
fn chunk_leaves(path: &Path, upto: u64) -> Res<Vec<[u8; 32]>> {
    let whole = upto / CHUNK_BYTES as u64;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; CHUNK_BYTES];
    let mut leaves = Vec::new();
    for i in 0..whole {
        let n = read_full(&mut f, &mut buf)?;
        leaves.push(pqcl_pipeline::chunked::chunk_leaf(
            Domain::EvidenceDigest,
            i,
            &buf[..n],
        ));
    }
    Ok(leaves)
}

/// [`paced_digest`], continuing from leaves already held: reads from the
/// first chunk not in `leaves`, at the budget.
///
/// ⚠️ It resumes at a **chunk** boundary, so up to one chunk before the phase
/// is re-read and charged. That is at most 1 MiB against a cycle of gigabytes,
/// and it errs against the baseline, never for it.
fn paced_digest_from(
    path: &Path,
    mut leaves: Vec<[u8; 32]>,
    budget: u64,
    read: &mut u64,
    start: Instant,
) -> Res<[u8; 32]> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(leaves.len() as u64 * CHUNK_BYTES as u64))?;
    let mut buf = vec![0u8; CHUNK_BYTES];
    loop {
        let n = read_full(&mut f, &mut buf)?;
        if n == 0 {
            break;
        }
        leaves.push(pqcl_pipeline::chunked::chunk_leaf(
            Domain::EvidenceDigest,
            leaves.len() as u64,
            &buf[..n],
        ));
        *read += n as u64;
        pace(*read, budget, start);
        if n < CHUNK_BYTES {
            break;
        }
    }
    Ok(pqcl_pipeline::chunked::merkle_root(&leaves))
}

fn pace(read: u64, budget: u64, start: Instant) {
    if let Some(wait) = budget_time(read, budget).checked_sub(start.elapsed()) {
        std::thread::sleep(wait); // xtask-allow: sleep — holding a real reader to its I/O budget is the mechanism under test
    }
}

fn ms(d: &[Duration]) -> serde_json::Value {
    serde_json::to_value(Summary::of(d)).unwrap_or(serde_json::Value::Null)
}

/// The sampled fraction `c` per sweep pass (M13 A13): `PQCL_SWEEP_FRACTION`,
/// default 0.05.
///
/// ⭐ **Fixed before measuring, from the design** (rule 21): §14.3's worked
/// deployment is "a 5% sample is a pass every ~2.8 hours". It is a parameter
/// that moves the time to detection — a full shuffled pass (`c = 1`) finds one
/// bad chunk in about half the reads a 5% pass does — so it is recorded, and
/// never chosen after seeing which value wins.
fn sweep_fraction() -> f64 {
    std::env::var("PQCL_SWEEP_FRACTION")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.05)
}

/// How many of `obj`'s chunks still verify against its anchored leaves, and
/// how many it has. Unpaced and untimed: an observation made after detection.
fn admissible(obj: &StoredObject) -> Res<(u64, u64)> {
    let chunks = obj.d_ev().chunk_count() as u64;
    let mut verified = 0u64;
    for c in 0..chunks {
        if pqcl_pipeline::audit::check_chunk(obj, c)?.1 {
            verified += 1;
        }
    }
    Ok((verified, chunks))
}

/// Class 1 — payload altered at rest.
fn at_rest(
    objs: &[StoredObject],
    budget: u64,
    trials: u64,
    rng: &mut SplitMix,
) -> Res<serde_json::Value> {
    let fraction = sweep_fraction();
    let (mut ours_t, mut ours_b, mut ours_checks, mut re_t, mut re_b) =
        (vec![], vec![], vec![], vec![], vec![]);
    let mut ours_passes = vec![];
    let mut admissible_counts = vec![];
    let mut localisation = vec![];
    for trial in 0..trials {
        let (i, off) = pick_byte(objs, rng);
        let orig = flip(&objs[i].path, off)?;
        let t0 = Instant::now();
        let mut s = Sweeper::new(objs.to_vec(), budget, rng.next_u64(), fraction);
        let found = s.run(&|| false)?;
        let dt = t0.elapsed();
        let want = Finding::ChunkMismatch {
            object: objs[i].id.clone(),
            chunk: off / CHUNK_BYTES as u64,
        };
        if found.as_ref() != Some(&want) {
            restore(&objs[i].path, off, orig)?;
            return Err(
                format!("trial {trial}: sweep reported {found:?}, injected {want:?}").into(),
            );
        }
        ours_t.push(dt);
        ours_b.push(s.bytes_read);
        ours_checks.push(s.checks);
        ours_passes.push(s.passes);
        // ⭐ **Admissibility, observed** (M13 A9, `audit/06d` L5-e). It used
        // to be `(chunks − 1)/chunks` — what *should* survive one damaged
        // chunk. Now every chunk of the damaged object is re-checked against
        // the anchored leaves and the ones that verify are counted, outside the
        // detection timer, so the record says what the store actually still
        // proves.
        let (verified, chunks) = admissible(&objs[i])?;
        localisation.push(verified * 1_000_000 / chunks.max(1));
        admissible_counts.push(serde_json::json!({
            "object": objs[i].id,
            "chunks": chunks,
            "verified": verified,
        }));
        let (rt, rb) = rehash_until_detect(objs, budget, i, off, rng)?;
        re_t.push(rt);
        re_b.push(rb);
        restore(&objs[i].path, off, orig)?;
        eprintln!("  at rest {trial}: sweep {dt:.1?}, re-hash {rt:.1?}");
    }
    let total_chunks: u64 = objs.iter().map(|o| o.d_ev().chunk_count() as u64).sum();
    let per = pqcl_pipeline::audit::per_pass(
        usize::try_from(total_chunks).unwrap_or(usize::MAX),
        fraction,
    ) as u64;
    Ok(serde_json::json!({
        "trials": trials,
        "ours_sampled_sweep": {
            "detect_ns": ms(&ours_t),
            "bytes_read": ours_b,
            "chunk_checks": ours_checks,
            "passes": ours_passes,
            "fraction_c": fraction,
            "chunks_per_pass": per,
            "total_chunks": total_chunks,
            // One bad chunk, passes of `s` distinct chunks: every pass before
            // the hitting one checks `s`, and within it the bad chunk is at a
            // uniform position, so E = N − s + (s + 1)/2. The old
            // with-replacement sampler's expectation was N.
            "expected_checks_one_bad_chunk": total_chunks.saturating_sub(per) + per.div_ceil(2),
            "admissible_ppm_of_object": localisation,
            "admissible_observed": admissible_counts,
        },
        "full_rehash_same_budget": {
            "detect_ns": ms(&re_t),
            "bytes_read": re_b,
            "admissible_ppm_of_object": 0,
            "phase": "uniformly random in its cycle; a verdict on the object in progress when the damage lies at or past the phase (prefix hashed before the clock, M13 A11), otherwise at the damaged object's next whole pass",
        },
        "verify_on_access": {"detect_ns": null, "reason": "nobody read the object during the trial window: no access, no check"},
    }))
}

/// Class 2 — payload altered, then read.
fn then_read(objs: &[StoredObject], trials: u64, rng: &mut SplitMix) -> Res<serde_json::Value> {
    let (mut ours_t, mut ours_b, mut flat_t, mut flat_b) = (vec![], vec![], vec![], vec![]);
    for trial in 0..trials {
        let (i, off) = pick_byte(objs, rng);
        let orig = flip(&objs[i].path, off)?;
        // A 64 KiB read around the damaged byte.
        let from = off.saturating_sub(32 * 1024);
        let t0 = Instant::now();
        let r = read_verified(&objs[i], from, 64 * 1024);
        let dt = t0.elapsed();
        match r {
            Err(Ok(Finding::ChunkMismatch { .. })) => {}
            other => {
                restore(&objs[i].path, off, orig)?;
                return Err(format!("trial {trial}: Q2 read returned {other:?}").into());
            }
        }
        ours_t.push(dt);
        let touched = (from + 64 * 1024 - 1) / CHUNK_BYTES as u64 - from / CHUNK_BYTES as u64 + 1;
        ours_b.push(touched * CHUNK_BYTES as u64);
        // Flat verify-on-access: the whole object must hash before one byte is
        // trusted — unthrottled, it is the reader's own I/O.
        let t0 = Instant::now();
        let mut read = 0u64;
        let root = paced_digest(&objs[i].path, u64::MAX, &mut read, t0)?;
        if root == *objs[i].d_ev().root() {
            restore(&objs[i].path, off, orig)?;
            return Err(format!("trial {trial}: flat verification missed the damage").into());
        }
        flat_t.push(t0.elapsed());
        flat_b.push(read);
        restore(&objs[i].path, off, orig)?;
    }
    Ok(serde_json::json!({
        "trials": trials,
        "ours_q2_chunk_on_read": {"detect_ns": ms(&ours_t), "bytes_read": ours_b, "read_bytes": 64 * 1024},
        "flat_verify_on_access": {"detect_ns": ms(&flat_t), "bytes_read": flat_b, "admissible_ppm_of_object": 0},
        "full_rehash": "as for payload at rest: a read does not trigger it",
    }))
}

/// `(epoch, R_e)` for every closed epoch — the public chain data a bundle is
/// checked against, one entry per epoch since M13 A20.
type EpochRoots = Vec<(u64, [u8; 32])>;

/// The stream's wall-clock base. Realistic, because a record's timestamp is
/// indexed under the `ts` attribute's range tree and a value near zero is
/// outside no window but describes 1970 (M13 A2).
const TS_BASE: u64 = 1_757_000_000;

/// A custody case whose bundles the epoch auditor re-verifies, and the
/// Secure Module that built it.
fn custody_case() -> Res<(Vec<Bundle>, EpochRoots, Backend)> {
    let stream = custody_stream(&StreamParams {
        capsules: 100,
        ..StreamParams::default()
    });
    let cast = Cast::generate()?;
    let keys = CaseKeys::derive(
        &PrfKey::new(digest256(b"K_mst (tamper)")),
        b"case",
        &digest256(b"r"),
    );
    let mut ais = Ais::new();
    // ⭐ Every capsule and record through one `CustodyAppender` — in process,
    // or the enclave on the campaign instance (M13 A18) — and through
    // `CaseBuilder`, the one implementation of the event routing, shared with
    // `custody.rs` and `exp6chain.rs`.
    let appender = from_env(&cast, &keys)?;
    let mut build = CaseBuilder::new(&*appender, &keys);
    for (i, e) in stream.iter().enumerate() {
        if e.event == Event::Collect {
            let nonce = digest256(&e.capsule.to_le_bytes());
            let c = build.seal(nonce, digest256(b"cm"), digest256(&nonce), b"x", b"p", 0)?;
            build.insert_capsule(e.capsule, c.clone());
            let a = build.feed(e, TS_BASE + i as u64, 0, None)?;
            ais.accept(c, a.signed.record);
        } else {
            let a = build.feed(e, TS_BASE + i as u64, 0, None)?;
            ais.append(a.signed.record);
        }
    }
    let backend = build.backend();
    ais.close_epoch();
    let court = pqcl_exp::appender::Discloser::new(&*appender, keys.cid_c)?;
    let mut bundles = Vec::with_capacity(ais.len());
    for k in 0..ais.len() {
        bundles.extend(court.disclose(&ais, k)?);
    }
    Ok((bundles, ais.epoch_roots(), backend))
}

/// Run `detect` every `period` until it reports, returning the time from
/// `t0` — the auditor's real cadence, not a formula for it.
fn audit_loop(
    t0: Instant,
    period: Duration,
    phase: Duration,
    mut detect: impl FnMut() -> bool,
) -> Duration {
    let mut next = phase;
    loop {
        if let Some(w) = next.checked_sub(t0.elapsed()) {
            std::thread::sleep(w); // xtask-allow: sleep — the auditor's real cadence between runs
        }
        if detect() {
            return t0.elapsed();
        }
        next += period;
    }
}

/// Class 5 — a payload deleted with no recorded order (§1v.4, draft7 Phase 10).
///
/// Each trial has one **lawful** deletion (a genuine court order over that
/// capsule, its `0x05` leaf anchored, a `DISPOSE` referencing it) and one
/// **unauthorised** deletion of another artefact, timed from the moment it
/// happens. Ours: keyless `0x05` accounting (`pqcl_pipeline::redaction::account`)
/// at the auditor's period, from a uniformly random phase. Re-hash: its cycle at
/// the read budget, given the operator's deletion list so the lawful deletion
/// does not alarm it (fixed before measuring, §1v.4); a missing object is
/// found when the cycle reaches it. Deletion is a rename, undone after.
///
/// ⭐ The lawful deletion is of `lawful`, an extra sealed object **outside**
/// the measured artefacts (§1z.3, approved before measuring). The first version
/// drew it from the three artefacts, so whenever it removed the 2.1 GB image the
/// re-hash's cycle shrank to 84 MB: the store under test changed per trial,
/// which class 1 never allows.
fn payload_deleted(
    objs: &[StoredObject],
    lawful: &StoredObject,
    budget: u64,
    period: Duration,
    trials: u64,
    rng: &mut SplitMix,
) -> Res<(serde_json::Value, Backend)> {
    use pqcl_pipeline::redaction::Unaccounted;
    use pqcl_primitives::Signer;

    if objs.is_empty() {
        return Err("payload deletion needs an artefact to delete".into());
    }
    // Anchored: the measured artefacts and the lawful extra. Swept by the
    // re-hash: the measured artefacts only, the same store every trial.
    let all: Vec<StoredObject> = objs.iter().cloned().chain([lawful.clone()]).collect();
    let j = objs.len();
    // The DEFR seals and opens each chain; the custodian disposes (M13 A2).
    // Both through the run's appender (M13 A18), so a record stamped with a
    // Secure Module holds no custody record built outside it.
    let cast = Cast::generate()?;
    let court = SoftwareMlDsa::generate()?;
    let keys = CaseKeys::derive(
        &PrfKey::new(digest256(b"K_mst (tamper)")),
        b"case-5",
        &digest256(b"r"),
    );
    let appender = from_env(&cast, &keys)?;
    let sealed = all
        .iter()
        .map(|o| seal_one(&*appender, &keys, o, 0))
        .collect::<Res<Vec<_>>>()?;
    let mut anchored: Vec<_> = all
        .iter()
        .zip(&sealed)
        .map(|(o, (c, _))| at_epoch(c, o, 0))
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (mut ours_t, mut re_t, mut re_b) = (vec![], vec![], vec![]);
    for trial in 0..trials {
        let i = usize::try_from(rng.next_u64() % objs.len() as u64).unwrap_or(0);
        // The lawful deletion: order, 0x05 anchored in an epoch, DISPOSE.
        //
        // ⭐ **A fresh capsule for the lawful object every trial** (M13 A18).
        // Each trial used to dispose the same capsule at position 1 under a new
        // order, which re-signs one position — the AEAD nonce the enclave
        // refuses to reuse, so the second trial would have failed on the
        // campaign instance. The object on disk is the same; its capsule, and
        // so its anchored entry, is the trial's own. The accounting reads one
        // entry per anchored payload either way, so nothing measured changes.
        let lawful_now = seal_one(&*appender, &keys, &all[j], trial + 1)?;
        anchored[j] = at_epoch(&lawful_now.0, &all[j], trial + 1);
        let ledger = lawful_order(&court, &*appender, &keys, &lawful_now, trial, now)?;
        let aside = |k: usize| all[k].path.with_extension("deleted");
        std::fs::rename(&all[j].path, aside(j))?;
        let audit = || audit_ledger(&anchored, &ledger, court.public_key());
        if !audit().is_empty() {
            std::fs::rename(aside(j), &all[j].path)?;
            return Err(format!("trial {trial}: a lawful deletion alarmed").into());
        }
        // The unauthorised deletion, and the clock.
        let phase =
            Duration::from_nanos(rng.next_u64() % u64::try_from(period.as_nanos()).unwrap_or(1));
        std::fs::rename(&objs[i].path, aside(i))?;
        let t0 = Instant::now();
        let want = vec![Unaccounted::PayloadDeleted {
            eid: sealed[i].0.eid,
        }];
        let mut wrong = None;
        let dt = audit_loop(t0, period, phase, || {
            let got = audit();
            if !got.is_empty() && got != want {
                wrong = Some(got.clone());
            }
            !got.is_empty()
        });
        // No listed object inside the swept store: pass an index past its end.
        let re = rehash_missing(objs, budget, i, objs.len(), &aside(i), rng);
        std::fs::rename(aside(i), &all[i].path)?;
        std::fs::rename(aside(j), &all[j].path)?;
        if let Some(w) = wrong {
            return Err(
                format!("trial {trial}: accounting reported {w:?}, injected {want:?}").into(),
            );
        }
        let (rt, rb) = re?;
        ours_t.push(dt);
        re_t.push(rt);
        re_b.push(rb);
        eprintln!("  deleted {trial}: 0x05 accounting {dt:.1?}, re-hash {rt:.1?}");
    }
    Ok((
        serde_json::json!({
            "trials": trials,
            "ours_0x05_accounting": {
                "detect_ns": ms(&ours_t),
                "audit_period_ns": period.as_nanos(),
                "bytes_read": 0,
                "check": "stat every anchored payload; an absence needs a genuine anchored order targeting it and a DISPOSE referencing it",
            },
            "full_rehash_same_budget": {
                "detect_ns": ms(&re_t),
                "bytes_read": re_b,
                "given_deletion_list": true,
                "phase": "uniform in bytes over its cycle, as class 1; a read in progress on the deleted object finishes through its open descriptor, so the absence is found when the next cycle opens it",
                "swept_store": "the measured artefacts, identical every trial (the lawful deletion is an extra object outside it, §1z.3)",
            },
            "verify_on_access": {"detect_ns": null, "reason": "nobody read the object during the trial window: no access, no check"},
            "lawful_deletion_per_trial": "an extra sealed object outside the measured artefacts, under a genuine recorded order: no alarm from either side",
            "lawful_object_bytes": lawful.d_ev().byte_len(),
        }),
        appender.backend(),
    ))
}

/// One anchored payload for `0x05` accounting: `c`'s seal anchored in `epoch`.
///
/// The measured artefacts are anchored in epoch 0; each class-5 trial's lawful
/// capsule, and its order, in the trial's own later epoch, so `eq:vred`'s
/// `e′ ≥ e` is checked against a capsule that is not from the first epoch
/// (M13 A7).
fn at_epoch(
    c: &pqcl_capsule::Capsule,
    o: &StoredObject,
    epoch: u64,
) -> pqcl_pipeline::redaction::AnchoredPayload {
    pqcl_pipeline::redaction::AnchoredPayload {
        eid: c.eid,
        path: o.path.clone(),
        epoch,
    }
}

/// `0x05` accounting over one ledger.
fn audit_ledger(
    anchored: &[pqcl_pipeline::redaction::AnchoredPayload],
    (claimed, leaves, registry, disposals): &Ledger,
    court_pk: &[u8],
) -> Vec<pqcl_pipeline::redaction::Unaccounted> {
    pqcl_pipeline::redaction::account(anchored, claimed, leaves, registry, disposals, court_pk)
}

/// What `0x05` accounting reads: the orders an AIS presents, the `0x05` leaves
/// verified against anchored roots with their epochs, the digests the chain
/// recorded per order id, and the `DISPOSE` records.
type Ledger = (
    Vec<pqcl_pipeline::redaction::ClaimedOrder>,
    std::collections::HashMap<[u8; 32], u64>,
    std::collections::HashMap<[u8; 32], [u8; 32]>,
    Vec<([u8; 32], pqcl_pipeline::redaction::DisposalClaim)>,
);

/// A genuine order over one capsule, its `0x05` leaf anchored in the trial's
/// epoch (`trial + 1`, the capsule's own) and checked against that epoch's
/// root, its digest recorded on chain, and a `DISPOSE` referencing it.
fn lawful_order(
    court: &SoftwareMlDsa,
    appender: &dyn CustodyAppender,
    keys: &CaseKeys,
    sealed: &(pqcl_capsule::Capsule, pqcl_capsule::CustodyRecord),
    trial: u64,
    now: u64,
) -> Res<Ledger> {
    use pqcl_capsule::redaction::{Mode, Order, Scope, Target};
    let (c, first) = sealed;
    let target = Target::new(&[c.eid]);
    let order = Order::issue(
        court,
        digest256(&trial.to_le_bytes()),
        target.root(),
        Scope::Payload,
        Mode::Sealed,
        now,
        now + 86_400,
    )?;
    let mut ais = Ais::new();
    ais.accept(c.clone(), first.clone());
    let at = ais.record_order(&order);
    let root = ais.close_epoch();
    let proof = ais.prove(&at).ok_or("no 0x05 proof")?;
    if !pqcl_forest::tier2::verify(&root, &order.leaf(), &proof) {
        return Err("the 0x05 leaf does not verify against its epoch".into());
    }
    let dispose = appender
        .append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: c.eid.into(),
            actor: pqcl_sm::cast_member(Role::Custodian),
            doc: 0,
            params: acted(1, 2, b"dispose"),
            step: AppendStep::Dispose {
                previous: Box::new(first.clone()),
                order_id: Some(order.oid),
            },
        })?
        .signed
        .record;
    let claimed = vec![pqcl_pipeline::redaction::ClaimedOrder {
        order: order.clone(),
        covers: vec![(c.eid, target.prove(&c.eid).ok_or("untargeted")?)],
    }];
    Ok((
        claimed,
        std::collections::HashMap::from([(order.leaf().digest, trial + 1)]),
        std::collections::HashMap::from([(order.oid, order.leaf().digest)]),
        vec![(c.eid, pqcl_pipeline::redaction::DisposalClaim::of(&dispose))],
    ))
}

/// One record's parameters: position, time and what the act was. The agent
/// adds `r_a` and `r_p` (M13 A2).
fn acted(j: u64, ts: u64, just: &[u8]) -> RecordParams {
    RecordParams::at(j, ts).with_params(Params::justified(just))
}

/// The object each class-5 trial deletes lawfully: 1 MiB, sealed like the
/// artefacts, outside the measured store (§1z.3).
fn lawful_extra(work: &Path) -> Res<StoredObject> {
    let src = work.join("lawful-extra.plain");
    let bytes: Vec<u8> = (0u32..1 << 20)
        .map(|k| u8::try_from((k.wrapping_mul(31)) % 251).unwrap_or(0))
        .collect();
    std::fs::write(&src, bytes)?;
    seal_artefact(&src, &work.join("lawful-extra"), b"lawful-extra")
}

/// A capsule for a stored artefact, `d_ev` its anchored root, and the record
/// that opens its chain — both through the appender.
///
/// `salt` picks the capsule: 0 for an artefact's standing capsule, a trial
/// number for a lawful object re-sealed per trial.
fn seal_one(
    appender: &dyn CustodyAppender,
    keys: &CaseKeys,
    o: &StoredObject,
    salt: u64,
) -> Res<(pqcl_capsule::Capsule, pqcl_capsule::CustodyRecord)> {
    let nonce = digest256(&[o.id.as_bytes(), &salt.to_le_bytes()].concat());
    let c = appender.seal(&SealRequest {
        cid_c: keys.cid_c,
        cm_ev: digest256(&[b"cm".as_slice(), &nonce].concat()),
        nonce,
        epoch: 0,
        artefact_type: b"artefact".to_vec(),
        d_ev: *o.d_ev().root(),
        ptr: o.path.to_string_lossy().into_owned().into_bytes(),
    })?;
    let first = appender
        .append(&AppendRequest {
            cid_c: keys.cid_c,
            capsule: c.eid.into(),
            actor: pqcl_sm::cast_member(Role::Defr),
            doc: 0,
            params: acted(0, 1, b"on-scene"),
            step: AppendStep::Collect,
        })?
        .signed
        .record;
    Ok((c, first))
}

/// The full re-hash's cycle over objects that may be missing, given the
/// operator's deletion list (`listed`). Returns when it reaches `deleted`.
///
/// ⭐ Its position when the deletion happens is **uniform in bytes** over its
/// cycle (the objects it still hashes, the listed one excluded), exactly as
/// class 1 places it: a cycle spends its time in proportion to size.
/// Corrected in campaign 05 (§1z): the first version started at a uniformly
/// random *object boundary*, and with objects of 31 MB, 2.1 GB and 53 MB it
/// usually landed right on the deleted one and "detected" it in microseconds.
///
/// If the phase falls inside the deleted object, the reader already holds it
/// open: on Linux an open descriptor survives a rename or unlink, so it reads
/// the rest (`aside`, where the harness moved it), learns nothing, and notices
/// the absence only when its next cycle opens the path again.
fn rehash_missing(
    objs: &[StoredObject],
    budget: u64,
    deleted: usize,
    listed: usize,
    aside: &Path,
    rng: &mut SplitMix,
) -> Res<(Duration, u64)> {
    let start = Instant::now();
    let cycle: u64 = objs
        .iter()
        .enumerate()
        .filter(|(k, _)| *k != listed)
        .map(|(_, o)| o.d_ev().byte_len())
        .sum();
    let mut phase = rng.next_u64() % cycle.max(1);
    let mut idx = 0usize;
    loop {
        if idx != listed {
            if phase < objs[idx].d_ev().byte_len() {
                break;
            }
            phase -= objs[idx].d_ev().byte_len();
        }
        idx += 1;
    }
    let mut read = 0u64;
    // The remainder of the object the cycle is inside: read, no verdict.
    let held = if idx == deleted {
        aside
    } else {
        objs[idx].path.as_path()
    };
    stream(
        held,
        phase,
        objs[idx].d_ev().byte_len() - phase,
        budget,
        &mut read,
        start,
    )?;
    loop {
        idx = (idx + 1) % objs.len();
        let o = &objs[idx];
        if idx == listed {
            continue;
        }
        if !o.path.exists() {
            if idx != deleted {
                return Err(format!("re-hash found {} missing, not the deleted one", o.id).into());
            }
            return Ok((start.elapsed(), read));
        }
        if paced_digest(&o.path, budget, &mut read, start)? != *o.d_ev().root() {
            return Err(format!("re-hash flagged {} with nothing injected", o.id).into());
        }
    }
}

/// Class 3 — a custody record edited in storage.
fn custody_edit(
    period: Duration,
    trials: u64,
    rng: &mut SplitMix,
) -> Res<(serde_json::Value, Backend)> {
    let (bundles, roots, backend) = custody_case()?;
    let mut times = vec![];
    let mut read_bytes = vec![];
    for _ in 0..trials {
        let mut store = bundles.clone();
        let k = usize::try_from(rng.next_u64() % store.len() as u64).unwrap_or(0);
        let j = usize::try_from(rng.next_u64() % store[k].segments[0].records.len() as u64)
            .unwrap_or(0);
        let phase =
            Duration::from_nanos(rng.next_u64() % u64::try_from(period.as_nanos()).unwrap_or(1));
        let t0 = Instant::now();
        // The edit. `ts` is inside `C_rec` from M13 A1 on, and the Tier-1 leaf
        // covers the ciphertext, so flipping a ciphertext byte is the same
        // tamper against the same commitment.
        store[k].segments[0].records[j].body[0] ^= 1;
        let dt = audit_loop(t0, period, phase, || {
            store.iter().any(|b| b.verify(&roots).is_err())
        });
        times.push(dt);
        read_bytes.push(store.iter().map(|b| b.encode().len()).sum::<usize>());
    }
    Ok((
        serde_json::json!({
            "trials": trials,
            "capsules": bundles.len(),
            "ours_epoch_auditor": {"detect_ns": ms(&times), "bytes_read": read_bytes, "audit_period_ns": period.as_nanos()},
            "verify_on_access": {"detect_ns": null, "reason": "only a disclosure of that capsule would check it; none in the window"},
            "full_rehash": "not applicable: there is no evidence object to re-hash, and custody records are not in d_ev",
        }),
        backend,
    ))
}

/// Wall-clock seconds, what a heartbeat's `ts` carries.
fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Class 4's tail row (M13 A6): the aggregator drops an agent's **last**
/// epoch as it arrives. Contiguity cannot see it, which the row checks rather
/// than assumes; the agent's next heartbeat, signed on its own thread every
/// `beat`, counts the epoch the store lacks. Timed from the drop to the first
/// audit that reports it, from uniformly random heartbeat and audit phases.
#[allow(clippy::too_many_arguments)]
fn tail_omitted(
    agents: &[AgentWriter],
    caps: &[ControlCapsule],
    recs: &[EvidenceRecord],
    pre_beats: &[Heartbeat],
    keys: &BTreeMap<u32, Vec<u8>>,
    period: Duration,
    beat: Duration,
    trials: u64,
    rng: &mut SplitMix,
) -> Res<serde_json::Value> {
    let last = agents.first().map_or(0, |_| 5u64);
    let mut times = vec![];
    let mut contiguity_saw = 0u64;
    for _ in 0..trials {
        let la = u32::try_from(rng.next_u64() % agents.len() as u64).unwrap_or(0);
        let agent = agents.get(la as usize).ok_or("no agent")?;
        let kept_caps: Vec<ControlCapsule> = caps
            .iter()
            .filter(|c| !(c.la_id == la && c.epoch_la_id == last))
            .cloned()
            .collect();
        let kept_recs: Vec<EvidenceRecord> = recs
            .iter()
            .filter(|r| !(r.la_id == la && r.epoch_la_id == last))
            .cloned()
            .collect();
        if audit_agent_epochs(&kept_caps, &kept_recs, keys)
            .iter()
            .any(|f| matches!(f, Finding::EpochOmitted { .. }))
        {
            contiguity_saw += 1;
        }
        let want = Finding::TailOmitted {
            la_id: la,
            epoch: last,
        };
        let audit_phase =
            Duration::from_nanos(rng.next_u64() % u64::try_from(period.as_nanos()).unwrap_or(1));
        let beat_phase =
            Duration::from_nanos(rng.next_u64() % u64::try_from(beat.as_nanos()).unwrap_or(1));
        let beats = std::sync::Mutex::new(pre_beats.to_vec());
        let stop = std::sync::atomic::AtomicBool::new(false);
        let t0 = Instant::now();
        let dt = std::thread::scope(|sc| -> Res<Duration> {
            let beating = sc.spawn(|| -> Result<(), String> {
                let mut next = beat_phase;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Some(w) = next.checked_sub(t0.elapsed()) {
                        std::thread::sleep(w.min(Duration::from_millis(50))); // xtask-allow: sleep — the agent's real heartbeat cadence
                        continue;
                    }
                    let h = agent.heartbeat(now_s()).map_err(|e| e.to_string())?;
                    beats.lock().map_err(|_| "beats lock")?.push(h);
                    next += beat;
                }
                Ok(())
            });
            let dt = audit_loop(t0, period, audit_phase, || {
                beats.lock().is_ok_and(|b| {
                    audit_heartbeats(&kept_caps, &b, keys, now_s(), beat.as_secs().max(1))
                        .contains(&want)
                })
            });
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            beating
                .join()
                .map_err(|_| "the heartbeat thread panicked")??;
            Ok(dt)
        })?;
        times.push(dt);
    }
    Ok(serde_json::json!({
        "trials": trials,
        "dropped_epoch": last,
        "ours_heartbeat": {"detect_ns": ms(&times), "audit_period_ns": period.as_nanos(), "heartbeat_period_ns": beat.as_nanos()},
        "ours_epoch_la_id_contiguity": {"detected_trials": contiguity_saw, "reason": "a dropped last epoch leaves every held counter contiguous"},
        "verify_on_access": {"detect_ns": null, "reason": "the records are gone: nothing is ever accessed, so nothing is checked"},
        "full_rehash": "not applicable: an omitted epoch leaves no object to re-hash",
    }))
}

/// Class 4 — the aggregator drops a whole agent-epoch.
fn epoch_omitted(
    objs: &[StoredObject],
    period: Duration,
    trials: u64,
    rng: &mut SplitMix,
) -> Res<serde_json::Value> {
    // Four agents, six epochs each, records cut from the real pcap's sealed bytes.
    let pcap = objs
        .iter()
        .find(|o| o.id == "multifile_25_21.pcap")
        .ok_or("no pcap")?;
    let mut src = std::fs::File::open(&pcap.path)?;
    let (mut caps, mut recs, mut keys) = (
        Vec::<ControlCapsule>::new(),
        Vec::<EvidenceRecord>::new(),
        BTreeMap::new(),
    );
    let (mut agents, mut pre_beats) = (Vec::new(), Vec::new());
    for la in 0..4u32 {
        let mut a = AgentWriter::new(la, SoftwareMlDsa::generate()?, u64::from(la) << 40);
        keys.insert(la, a.public_key().to_vec());
        for e in 0..6u64 {
            for i in 0..64u64 {
                let mut rec = vec![0u8; 4096];
                if read_full(&mut src, &mut rec)? < rec.len() {
                    src.seek(SeekFrom::Start(0))?;
                }
                recs.push(a.append(e * 1000 + i, rec));
            }
            // The last beat before the last epoch closes counts five: what
            // an auditor holds when the drop happens (M13 A6).
            if e == 5 {
                pre_beats.push(a.heartbeat(now_s())?);
            }
            caps.push(a.close(format!("s3://store/{la}/{e}").as_bytes())?);
        }
        agents.push(a);
    }
    if !audit_agent_epochs(&caps, &recs, &keys).is_empty() {
        return Err("the intact store raised findings".into());
    }
    let mut times = vec![];
    for _ in 0..trials {
        let la = u32::try_from(rng.next_u64() % 4).unwrap_or(0);
        let ep = 1 + rng.next_u64() % 4; // an interior epoch: a gap, not a truncated tail
        let phase =
            Duration::from_nanos(rng.next_u64() % u64::try_from(period.as_nanos()).unwrap_or(1));
        let dropped = std::cell::RefCell::new((caps.clone(), recs.clone()));
        let t0 = Instant::now();
        {
            let mut d = dropped.borrow_mut();
            d.0.retain(|c| !(c.la_id == la && c.epoch_la_id == ep));
            d.1.retain(|r| !(r.la_id == la && r.epoch_la_id == ep));
        }
        let want = Finding::EpochOmitted {
            la_id: la,
            epoch: ep,
        };
        let dt = audit_loop(t0, period, phase, || {
            let d = dropped.borrow();
            audit_agent_epochs(&d.0, &d.1, &keys).contains(&want)
        });
        times.push(dt);
    }
    let beat = Duration::from_secs(env_u64("PQCL_HEARTBEAT_S", 5));
    let tail = tail_omitted(
        &agents, &caps, &recs, &pre_beats, &keys, period, beat, trials, rng,
    )?;
    Ok(serde_json::json!({
        "trials": trials,
        "agents": 4, "epochs_per_agent": 6, "records_per_epoch": 64, "record_bytes": 4096,
        "tail_omitted": tail,
        "ours_epoch_la_id_contiguity": {"detect_ns": ms(&times), "audit_period_ns": period.as_nanos()},
        "verify_on_access": {"detect_ns": null, "reason": "the records are gone: nothing is ever accessed, so nothing is checked"},
        "full_rehash": "not applicable: an omitted epoch leaves no object to re-hash",
    }))
}

fn main() -> Res<()> {
    let budget = env_u64("PQCL_TAMPER_BUDGET", 50_000_000);
    let period = Duration::from_secs(env_u64("PQCL_AUDIT_PERIOD_S", 10));
    let trials = env_u64("PQCL_TAMPER_TRIALS", 20);
    let src = PathBuf::from(
        std::env::var("PQCL_ARTEFACTS").unwrap_or_else(|_| "datasets/artefacts".into()),
    );
    let work = std::env::temp_dir().join(format!("pqcl-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;
    let result = (|| -> Res<(serde_json::Value, Backend)> {
        let mut objs = Vec::new();
        for name in ARTEFACTS {
            eprintln!("sealing {name}");
            objs.push(seal_artefact(
                &src.join(name),
                &work.join(name),
                name.as_bytes(),
            )?);
        }
        let mut rng = SplitMix::new(0x7A3_9E12);
        eprintln!("class 1: at rest ({trials} trials, budget {budget} B/s)");
        let c1 = at_rest(&objs, budget, trials, &mut rng)?;
        eprintln!("class 2: then read");
        let c2 = then_read(&objs, trials, &mut rng)?;
        eprintln!("class 3: custody edit");
        let (c3, backend) = custody_edit(period, trials, &mut rng)?;
        eprintln!("class 4: epoch omitted");
        let c4 = epoch_omitted(&objs, period, trials, &mut rng)?;
        eprintln!("class 5: payload deleted without an order");
        let lawful = lawful_extra(&work)?;
        let (c5, backend5) = payload_deleted(&objs, &lawful, budget, period, trials, &mut rng)?;
        // One record, one boundary: classes 3 and 5 build custody records, and
        // both must have built them through the same Secure Module.
        if backend5 != backend {
            return Err(format!(
                "classes 3 and 5 built through different Secure Modules: {backend:?}, {backend5:?}"
            )
            .into());
        }
        Ok((
            serde_json::json!({
                "read_budget_bytes_per_s": budget,
                "audit_period_ns": period.as_nanos(),
                "artefacts": objs.iter().map(|o| serde_json::json!({"id": o.id, "sealed_bytes": o.d_ev().byte_len(), "chunks": o.d_ev().chunk_count()})).collect::<Vec<_>>(),
                "payload_at_rest": c1,
                "payload_then_read": c2,
                "custody_record_edited": c3,
                "agent_epoch_omitted": c4,
                "payload_deleted": c5,
                "method": {
                    "sealed": "each artefact AES-256-GCM sealed per 1 MiB chunk; every check reads ciphertext and holds no key",
                    "sampling": "passes without replacement: each pass checks ceil(c*N) distinct chunks, a uniform subset in random order, the case the (1-c)^{mk} bound is stated for (M13 A13); c = PQCL_SWEEP_FRACTION, default 0.05 from design §14.3, fixed before measuring",
                    "rehash_verdict": "whole-object root only, the verdict a flat digest gives at the same I/O",
                    "never": "null detect_ns means no alert within the trial window, not an unmeasured cell",
                },
            }),
            backend,
        ))
    })();
    let _ = std::fs::remove_dir_all(&work);
    let (measurements, backend) = result?;
    emit_custody(
        "exp8-tamper-response",
        RunSpec {
            liboqs_version: "ML-DSA-65 via liboqs".to_owned(),
            rng_seeds: vec![0x7A3_9E12],
            ..RunSpec::default()
        },
        u32::try_from(trials).unwrap_or(u32::MAX),
        measurements,
        backend,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Two objects of `chunks` chunks each, sealed and digested, the first
    /// with one byte flipped at `flip_at` after its digest was taken.
    fn store(tag: &str, chunks: usize, flip_at: u64) -> Vec<StoredObject> {
        let dir = std::env::temp_dir().join(format!("pqcl-a11-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let mut objs = Vec::new();
        for k in 0..2u8 {
            let path = dir.join(format!("o{k}"));
            std::fs::write(&path, vec![k + 1; chunks * CHUNK_BYTES]).expect("write");
            let d_ev =
                pqcl_pipeline::chunked::digest_file(&path, Domain::EvidenceDigest).expect("digest");
            let anchored = *d_ev.root();
            objs.push(StoredObject::open(format!("o{k}"), path, &anchored, d_ev).expect("bound"));
        }
        flip(&objs[0].path, flip_at).expect("flip");
        objs
    }

    /// ⭐ **Acceptance A6, end to end:** a dropped last epoch, invisible to
    /// contiguity, is found from the agent's own heartbeat thread.
    #[test]
    fn a_dropped_tail_epoch_is_found_by_the_heartbeat_thread() {
        let (mut caps, mut recs, mut keys) = (Vec::new(), Vec::new(), BTreeMap::new());
        let (mut agents, mut pre) = (Vec::new(), Vec::new());
        for la in 0..2u32 {
            let mut a = AgentWriter::new(la, SoftwareMlDsa::generate().expect("keygen"), 0);
            keys.insert(la, a.public_key().to_vec());
            for e in 0..6u64 {
                recs.push(a.append(e, vec![u8::try_from(e).expect("small"); 16]));
                if e == 5 {
                    pre.push(a.heartbeat(now_s()).expect("beat"));
                }
                caps.push(a.close(b"u").expect("close"));
            }
            agents.push(a);
        }
        let r = tail_omitted(
            &agents,
            &caps,
            &recs,
            &pre,
            &keys,
            Duration::from_millis(20),
            Duration::from_millis(100),
            3,
            &mut SplitMix::new(7),
        )
        .expect("tail row");
        assert_eq!(
            r["ours_heartbeat"]["detect_ns"]["n"], 3,
            "every trial detected"
        );
        assert_eq!(
            r["ours_epoch_la_id_contiguity"]["detected_trials"], 0,
            "contiguity saw a dropped tail: the row is not testing what A6 adds"
        );
    }

    /// ⭐ **Acceptance A9 (a): one flipped byte is one bad chunk, which fails to
    /// decrypt alone.** With records aligned to `d_ev` chunks the damage, the
    /// digest mismatch and the undecryptable record are the same chunk, and
    /// every other record still opens.
    #[test]
    fn one_flipped_byte_is_one_bad_chunk_that_fails_to_decrypt_alone() {
        let dir = std::env::temp_dir().join(format!("pqcl-a9-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let src = dir.join("plain");
        let plain: Vec<u8> = (0u32..3 * 1024 * 1024 + 4321)
            .map(|k| u8::try_from(k % 251).unwrap_or(0))
            .collect();
        std::fs::write(&src, &plain).expect("write");
        let obj = seal_artefact(&src, &dir.join("sealed"), b"seed").expect("seal");
        let chunks = obj.d_ev().chunk_count() as u64;
        assert_eq!(
            chunks,
            plain.len().div_ceil(PLAIN_CHUNK) as u64,
            "one d_ev chunk per sealed record"
        );

        // Flip a byte in the middle of chunk 2.
        let at = 2 * CHUNK_BYTES as u64 + 777;
        flip(&obj.path, at).expect("flip");
        let (verified, total) = admissible(&obj).expect("check");
        assert_eq!(
            (verified, total),
            (chunks - 1, chunks),
            "exactly one bad chunk"
        );
        for i in 0..chunks {
            let opened = open_record(&obj.path, b"seed", i);
            if i == 2 {
                assert!(opened.is_err(), "the damaged record decrypted");
            } else {
                let k = usize::try_from(i).expect("small");
                let want = &plain[k * PLAIN_CHUNK..((k + 1) * PLAIN_CHUNK).min(plain.len())];
                assert_eq!(opened.expect("an intact record opens"), want);
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// ⭐ **Acceptance A11.** With the re-hasher partway through the damaged
    /// object and the damage ahead of it, the verdict comes at the end of
    /// *that* object: it reads at most the rest of it, plus the one chunk it
    /// resumes from. With the damage behind it, it must finish the object, read
    /// the other, and come round again — a full cycle and more.
    #[test]
    fn the_rehash_judges_the_object_it_is_reading_when_the_damage_is_ahead() {
        let chunks = 4usize;
        let len = (chunks * CHUNK_BYTES) as u64;
        let budget = 1u64 << 40; // effectively unpaced: this checks bytes, not time

        // Phase at 1.5 chunks into object 0, damage at 3 chunks: ahead.
        let phase = (3 * CHUNK_BYTES / 2) as u64;
        let ahead = store("ahead", chunks, (3 * CHUNK_BYTES) as u64);
        let (_, read) =
            rehash_from_phase(&ahead, budget, 0, 3 * CHUNK_BYTES as u64, phase).expect("detected");
        assert!(
            read <= len - phase + CHUNK_BYTES as u64,
            "read {read} bytes for damage ahead of the phase; the rest of the object is {}",
            len - phase
        );

        // Damage at chunk 0, behind the same phase: a full further cycle.
        let behind = store("behind", chunks, 10);
        let (_, read) = rehash_from_phase(&behind, budget, 0, 10, phase).expect("detected");
        assert!(
            read >= (len - phase) + len + len,
            "read only {read} bytes for damage behind the phase"
        );
        for o in ahead.iter().chain(&behind) {
            let _ = std::fs::remove_file(&o.path);
        }
    }
}
