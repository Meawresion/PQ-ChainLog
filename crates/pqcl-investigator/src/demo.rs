//! The demo case: draft7's Phases 1–11, one step at a time, every step live.
//!
//! Two sides are kept apart **by type**, because the gap between them is the
//! paper's argument and the dashboard shows both:
//!
//! * [`Client`] — the investigator's side: case keys, openings, decrypted
//!   records, the custody graph. Lives in this process.
//! * [`Ais`] — what the Aggregation & Index Server holds: encoded capsules and
//!   records, ciphertext files, the two encrypted indices, the epoch MMR. Every
//!   server-view panel is rendered from this struct and nothing else, and the
//!   client hands it bytes, never keys.
//!
//! ⚠️ For the demo both run in one process; the AIS is not a separate server.
//! What the server view shows is exactly what [`Ais`] received.

mod corners;
mod flows;

pub use corners::WARM_UP;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use pqcl_capsule::redaction::Order;
use pqcl_capsule::{Capsule, CustodyRecord, Event, Params, Role};
use pqcl_dsse::core::{
    Client as CoreClient, DocId, Edb, HonestEdb, Op, SearchResponse, SearchToken, UpdateToken,
};
use pqcl_dsse::xt::{Epoch, HonestServer, Transcript, XSetStore, XTag, XtClient};
use pqcl_forest::{CustodyTree, Leaf, Mmr, MmrProof};
use pqcl_pipeline::checkpoint::{self, ApprovalSet, Registration};
use pqcl_pipeline::forensics::Forensics;
use pqcl_pipeline::handoff::{self, Handoff};
use pqcl_pipeline::redaction::PayloadStore;
use pqcl_pipeline::{
    Agent, CaseKeys, IngestParams, RecordParams, Signed, chunked, custody_keywords,
    record_signed_bytes,
};
use pqcl_primitives::xof::{Digest32, Domain, Label, PrfKey, digest256, hash_domain, prf};
use pqcl_primitives::{CoSigner, KeyPair, RecordKey, Signer, SoftwareMlDsa, kem, rng, sig};
use serde_json::{Value, json};

use crate::chain::{Anchored, ChainSession, Receipt};
use crate::docs::{self, Document};
use crate::graph::{self, ChainView, Opening, hex};
use crate::perf;

/// Anything a step can fail with, as text for the page.
pub type StepResult = Result<Value, String>;

fn e2s<E: core::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn short(d: &[u8]) -> String {
    graph::hex_bytes(&d[..6.min(d.len())]) + "…"
}

/// Where the demo reads and writes.
#[derive(Debug, Clone)]
pub struct Config {
    /// The repository root, for `datasets/`, `forensics/` and `contracts/out/`.
    pub repo: PathBuf,
    /// The AIS's payload store directory (wiped at start).
    pub store: PathBuf,
    /// The node's JSON-RPC URL.
    pub rpc: String,
    /// Course mode: the walkthrough skips D6,
    /// court-ordered redaction, to match deliverable4. A skip, not a stub:
    /// the D6 code is untouched and still runs without this flag.
    pub course: bool,
    /// Verify the saved warrant STARKs live (7.1 GB peak, `verify-rss.log`)
    /// instead of showing the stored AWS result with a label. Off by default:
    /// the laptop route caps the whole demo at 8 GB (§1dc.4).
    pub live_stark: bool,
}

/// The two real artefacts the first responder collects.
pub const DISK_IMAGE: &str = "nps-2009-canon2-gen6.E01";
/// Network capture.
pub const PCAP: &str = "multifile_25_21.pcap";

// ---------------------------------------------------------------- the server

/// A probe list as the server received it, and the bits it answered.
pub type ProbeLog = (Vec<XTag>, Vec<bool>);

/// An encrypted index as the server holds it, with a log of exactly what
/// arrived, so the server view is the server's real input.
#[derive(Debug, Default)]
pub struct LoggedStore<S> {
    inner: S,
    /// Which plane this index serves, for the Performance page's seam counts.
    pub plane: &'static str,
    /// Every `(addr, |val|)` received, in arrival order.
    pub received: Vec<(Digest32, usize)>,
    /// Running digest of every `(addr, val)` received, for the `0x03` leaf.
    pub entries_digest: Vec<u8>,
    /// Cross-tags received per epoch, in arrival (shuffled-batch) order.
    pub xtags: Vec<(Epoch, XTag)>,
    /// The last search request: (token wire bytes, count, payloads returned).
    pub last_search: RefCell<Option<(usize, u64, usize)>>,
    /// The last probe list and the bits the server answered.
    pub last_probe: RefCell<Option<ProbeLog>>,
}

impl<S: Edb> Edb for LoggedStore<S> {
    fn insert(&mut self, token: &UpdateToken) {
        let _store = perf::on(perf::Side::Store);
        let kind = if self.plane == "custody" {
            "custody index token"
        } else {
            "evidence index token"
        };
        perf::seam(perf::Dir::Up, kind, token.addr.len() + token.val.len());
        self.received.push((token.addr, token.val.len()));
        self.entries_digest.extend_from_slice(&token.addr);
        self.entries_digest
            .extend_from_slice(&digest256(token.val.as_bytes()));
        self.inner.insert(token);
    }
    fn search(&self, token: &SearchToken) -> SearchResponse {
        let _store = perf::on(perf::Side::Store);
        perf::seam(perf::Dir::Up, "search token", token.wire_bytes());
        let r = self.inner.search(token);
        let returned = r.0.iter().filter(|x| x.is_some()).count();
        let down: usize = r.0.iter().flatten().map(|x| x.as_bytes().len()).sum();
        perf::seam(perf::Dir::Down, "search answer", down);
        *self.last_search.borrow_mut() = Some((token.wire_bytes(), token.count, returned));
        r
    }
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<S: XSetStore> XSetStore for LoggedStore<S> {
    fn add_xtags(&mut self, epoch: Epoch, tags: &[XTag]) {
        let _store = perf::on(perf::Side::Store);
        perf::seam(
            perf::Dir::Up,
            "cross-tag batch",
            core::mem::size_of_val(tags),
        );
        self.xtags.extend(tags.iter().map(|t| (epoch, *t)));
        self.inner.add_xtags(epoch, tags);
    }
    fn probe(&self, transcript: &Transcript) -> Vec<bool> {
        let _store = perf::on(perf::Side::Store);
        perf::seam(
            perf::Dir::Up,
            "probe list",
            core::mem::size_of_val(transcript.probes.as_slice()),
        );
        let bits = self.inner.probe(transcript);
        perf::seam(perf::Dir::Down, "probe bits", bits.len().div_ceil(8));
        *self.last_probe.borrow_mut() = Some((transcript.probes.clone(), bits.clone()));
        bits
    }
    fn xtag_count(&self) -> usize {
        self.inner.xtag_count()
    }
    fn seal_epoch(&mut self, epoch: Epoch) {
        self.inner.seal_epoch(epoch);
    }
    fn reset(&mut self) {
        self.inner.reset();
    }
}

/// One Tier-2 leaf as the server appended it.
#[derive(Debug, Clone)]
pub struct LeafEntry {
    /// The type tag, `0x01`–`0x05`.
    pub tag: u8,
    /// Its digest.
    pub digest: Digest32,
    /// Which epoch it was appended in.
    pub epoch: u64,
}

/// Everything the Aggregation & Index Server holds. No key is ever stored here.
#[derive(Debug)]
pub struct Ais {
    /// Capsules, as encoded bytes.
    pub capsules: Vec<Vec<u8>>,
    /// Custody records per capsule, as encoded bytes, filed under `eid_e`.
    pub chains: Vec<(Digest32, Vec<Vec<u8>>)>,
    /// Ciphertext files.
    pub payloads: PayloadStore,
    /// Evidence-plane index (`Π_XT`: EDB plus per-epoch cross-tag sets).
    pub evidence: LoggedStore<HonestServer>,
    /// Custody-plane index (`Π_core`, searched by `Π_CD`).
    pub custody: LoggedStore<HonestEdb>,
    /// The **open** epoch's Tier-2 MMR. ⭐ One per epoch since M13 A20/A21,
    /// not one per case: `R_e` covers that epoch's leaves alone and `n_e` is
    /// that epoch's own count.
    pub mmr: Mmr,
    /// Closed epochs' MMRs, kept because a disclosure made later still needs
    /// their inclusion proofs.
    pub closed: Vec<(u64, Mmr)>,
    /// Every leaf appended, in order, across every epoch.
    pub leaves: Vec<LeafEntry>,
}

impl Ais {
    fn append(&mut self, leaf: &Leaf, tag: u8, epoch: u64) -> u64 {
        let at = self.mmr.leaf_count();
        self.mmr.append(leaf);
        self.leaves.push(LeafEntry {
            tag,
            digest: leaf.digest,
            epoch,
        });
        at
    }

    /// Close `epoch`: keep its MMR for later proofs and start the next one
    /// empty. Called after the epoch's proofs have been taken.
    fn close(&mut self, epoch: u64) {
        let mmr = core::mem::take(&mut self.mmr);
        self.closed.push((epoch, mmr));
    }
}

// ---------------------------------------------------------------- the client

/// A custodian: an identity, a role, and an ML-DSA key.
///
/// ⚠️ **No `actor_c` field any more** (M13 A2). It held one commitment, reused
/// in every record that custodian signed — so the server could group a
/// custodian's records by equality, which is the activity profile the design
/// denies it. The agent now draws a fresh `r_a` per record and hands back the
/// opening, which the client keeps in [`Held::actors`].
#[derive(Debug)]
pub struct Custodian {
    /// Who they are (the opening's `actor_id`).
    pub actor_id: String,
    /// Their role, as the panels name it.
    pub role: String,
    /// Their signer, which knows its own role and refuses events it may not
    /// sign.
    pub agent: Agent,
}

impl Custodian {
    fn new(actor_id: &str, role: &str, which: Role) -> Result<Self, String> {
        Ok(Self {
            actor_id: actor_id.to_owned(),
            role: role.to_owned(),
            agent: Agent::new(
                SoftwareMlDsa::generate().map_err(e2s)?,
                actor_id.as_bytes(),
                which,
            ),
        })
    }
}

/// A capsule as the client holds it.
#[derive(Debug)]
pub struct Held {
    /// The sealed capsule.
    pub capsule: Capsule,
    /// The artefact's file name (the client opened it).
    pub file: String,
    /// What kind of artefact.
    pub kind: String,
    /// `wrap_eid`: ML-KEM ciphertext plus `K_ev` sealed under the shared secret.
    pub wrap: (Vec<u8>, Vec<u8>),
    /// The custody chain, verified.
    pub chain: Vec<CustodyRecord>,
    /// The opened bodies, index for index with `chain`.
    ///
    /// ⭐ The dashboard is the investigator's own loopback client and holds the
    /// case keys (design §13.1), so it can keep these. Since M13 A1 the event,
    /// actor and parameter commitments are inside `C_rec`, and every badge,
    /// edge and index keyword below is computed from the opened body — none of
    /// it is computable by the server that stores the record.
    pub bodies: Vec<pqcl_capsule::RecordBody>,
    /// Which custodian signed each record (index into `custodians`).
    pub signers: Vec<usize>,
    /// The opening of each record's `actor_c` (M13 A2).
    ///
    /// ⭐ **Identity lives here, not in the records.** Each `actor_c` is
    /// blinded per record, so the custody graph, the index keywords and any
    /// "who held this" question are answered from these openings — by the
    /// client, which is the only party that has them.
    pub actors: Vec<pqcl_capsule::ActorOpening>,
    /// Where its `0x01` seal leaf is, in the epoch that sealed it.
    pub seal_leaf: u64,
    /// That epoch (M13 A3). The capsule is sealed before its chain opens, so
    /// this need not be any segment's epoch.
    pub seal_epoch: u64,
    /// The seal leaf's Tier-2 proof, once its epoch closed. A disclosure
    /// carries it, so a court checks the capsule itself and not only its
    /// history.
    pub seal_proof: Option<MmrProof>,
    /// Its anchored **segments**, oldest first (M13 A20).
    ///
    /// ⭐ One `0x02` leaf per epoch the capsule was touched in, each covering
    /// that epoch's records alone. Before A20 this was a single leaf per
    /// capsule, re-anchored over a longer prefix each epoch under one
    /// pseudonym — which is what let the server link the epochs
    /// (`audit/07` D1).
    pub anchored: Vec<AnchoredSegment>,
    /// The last integrity check: (recomputed `d_ev`, matches).
    pub integrity: Option<(Digest32, bool)>,
    /// Per-chunk digests of the ciphertext as sealed, to localise damage.
    pub chunks: Vec<Digest32>,
    /// The opening of `cm_ev` (`r_ev`), held by the client, never the AIS.
    pub opening: pqcl_pipeline::PlaintextOpening,
    /// Set when the payload was erased under a court order (its `oid`).
    pub erased: Option<Digest32>,
    /// Who holds custody now (index into `custodians`): the collector, then
    /// each completed transfer's receiver. The dashboard lets only the holder
    /// release; the library does not track possession.
    pub holder: usize,
}

impl Held {
    /// How many of this capsule's records are covered by an anchored `0x02`
    /// leaf — the end of the last anchored segment.
    #[must_use]
    pub fn committed_len(&self) -> usize {
        self.anchored.last().map_or(0, |a| a.to)
    }
}

/// One segment of a capsule's chain, as anchored in its own epoch.
#[derive(Debug, Clone)]
pub struct AnchoredSegment {
    /// The epoch whose MMR holds the `0x02` leaf.
    pub epoch: u64,
    /// The pseudonym the segment is filed under.
    pub eid_e: Digest32,
    /// Range of the capsule's chain this segment covers, `from..to`.
    pub from: usize,
    /// End of that range, exclusive.
    pub to: usize,
    /// Where the `0x02` leaf landed in that epoch's MMR.
    pub at: u64,
    /// Its Tier-2 proof, filled when the epoch closes.
    pub proof: Option<MmrProof>,
}

/// One closed epoch.
#[derive(Debug, Clone)]
pub struct EpochClose {
    /// Epoch number.
    pub e: u64,
    /// `R_e`.
    pub root: Digest32,
    /// `n_e` — leaves in **this epoch's** MMR. Committed inside `d_e`; not on
    /// chain since M13 A21.
    pub leaf_count: u64,
    /// The anchoring transaction.
    pub receipt: Receipt,
    /// What `latestEpoch` read back.
    pub on_chain: Anchored,
    /// Each held capsule's `0x02` proof as of this root: (capsule, leaf index, proof).
    pub proofs: Vec<(usize, u64, MmrProof)>,
    /// Leaf tags appended in this epoch.
    pub tags: Vec<u8>,
    /// (capsule, chain length) each `0x02` proof commits.
    pub committed: Vec<(usize, usize)>,
}

/// The investigator's side of the case.
pub struct Client {
    case_id: String,
    keys: CaseKeys,
    ca_kem: KeyPair,
    /// The court / Case Authority's ML-DSA key: warrants and redaction orders.
    ca_sig: SoftwareMlDsa,
    court: SoftwareMlDsa,
    /// The N registered custodians who approve checkpoints (M of them do).
    committee: Vec<SoftwareMlDsa>,
    /// Each custodian's own view of the case's checkpoint chain (M13 A5): what
    /// it last approved, so it approves only an extension of that.
    views: Vec<checkpoint::ChainView>,
    cosigner: CoSigner,
    /// What was registered once, before the first checkpoint (`eq:reg`).
    reg: Registration,
    /// The last checkpoint anchored, `d_{e−1}` for the next epoch.
    last_d: Digest32,
    /// Custodians, in a fixed order: DEFR, lab custodian, analyst.
    pub custodians: Vec<Custodian>,
    evidence: XtClient,
    custody: CoreClient,
    /// Next custody-plane document id.
    custody_ids: DocId,
    /// Evidence documents, by id.
    pub docs: Vec<Document>,
    /// Capsules held.
    pub held: Vec<Held>,
    handoffs: HashMap<Digest32, Handoff>,
    /// The release awaiting its receipt: the capsule, the descriptor, and the
    /// receiver's published commitment (M13 A2 — the receipt must be signed
    /// under the opening the descriptor binds).
    pending: Option<(usize, Handoff, handoff::Receiving, usize)>,
    /// Closed epochs.
    pub epochs: Vec<EpochClose>,
    /// The open epoch.
    pub epoch: u64,
    /// The AWS proof bundle, if one was made.
    bundle: Option<Value>,
    /// Custody-plane document id → (capsule, record index).
    custody_docs: Vec<(usize, usize)>,
    warrants: Vec<flows::Issued>,
    rho_w: Option<Digest32>,
    /// The warrant root's checkpoint and approval digest, as anchored.
    warrant_anchor: Option<(Digest32, Digest32)>,
    evidence_hits: Vec<DocId>,
    order: Option<Order>,
    /// Each warrant's STARK status as the warrant step left it: (name, text).
    stark: Vec<(String, Value)>,
    /// Synthetic-log bursts ingested by the ingestion corner.
    bursts: u64,
    /// Synthetic lines ingested, across every burst.
    synthetic_lines: u64,
    /// The last burst's summary, for the ingestion corner.
    last_burst: Option<Value>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("case_id", &self.case_id)
            .field("held", &self.held.len())
            .finish_non_exhaustive()
    }
}

/// Indices into [`Client::custodians`].
pub const DEFR: usize = 0;
/// The evidence-store custodian.
pub const LAB: usize = 1;
/// The digital-evidence specialist.
pub const ANALYST: usize = 2;
/// The investigator, who reads under warrant (M13 A2: `ACCESS` is theirs).
pub const INVESTIGATOR: usize = 3;

// The roles the demo's cast plays. The bytes they commit to are
// `Role::byte()`'s, from the library's own table (M13 A2).

// ---------------------------------------------------------------- the demo

/// The steps, in the order the walkthrough runs them.
pub const STEPS: &[(&str, &str, &str, &str)] = &[
    (
        "init",
        "D1",
        "1–2",
        "System initialisation, case keys, enrolment, contract",
    ),
    (
        "capture",
        "D1",
        "3–4",
        "Capture, seal and index two real artefacts",
    ),
    (
        "analyze",
        "D2",
        "5",
        "A specialist analyses the disk image (real tool run)",
    ),
    (
        "release",
        "D2",
        "6",
        "First responder releases the disk image to the evidence store",
    ),
    (
        "receive",
        "D2",
        "6",
        "The evidence store re-verifies d_ev and signs the receipt",
    ),
    (
        "anchor",
        "D3",
        "7",
        "Close the epoch and anchor its root on the live chain",
    ),
    (
        "warrant",
        "D4",
        "8",
        "The court issues warrants; ρ_W is anchored; both searches are registered",
    ),
    (
        "search",
        "D4",
        "8–9",
        "Warranted Boolean and range search on the evidence plane, two rounds",
    ),
    (
        "custody-search",
        "D4",
        "9",
        "Custody-plane search and the client-side join",
    ),
    (
        "audit",
        "D5",
        "10",
        "An auditor verifies a capsule's history from public data alone",
    ),
    (
        "tamper",
        "D5",
        "10",
        "One byte of a stored payload changes; the check catches and localises it",
    ),
    (
        "order",
        "D6",
        "11",
        "The court orders the disk image erased; the order is recorded on chain first",
    ),
    (
        "erase",
        "D6",
        "11",
        "Erase, DISPOSE, anchor 0x05: the search forgets it, the old anchor still verifies",
    ),
];

/// The whole demo: client, server, chain, and the log of what has run.
pub struct Demo {
    cfg: Config,
    /// Steps run so far, each with its panel.
    pub log: Vec<Value>,
    /// Corner actions run so far, newest last (capped).
    pub corner_log: Vec<Value>,
    /// Set while the warm-up runs, so each panel it produces is labelled
    /// "pre-run" with the time it ran and how long it took (§1dc.4).
    warming: bool,
    client: Option<Client>,
    ais: Option<Ais>,
    chain: Option<ChainSession>,
}

/// The walkthrough steps this configuration runs: all of them, or all but D6
/// in course mode.
fn steps_for(
    course: bool,
) -> Vec<&'static (&'static str, &'static str, &'static str, &'static str)> {
    STEPS.iter().filter(|s| !(course && s.1 == "D6")).collect()
}

impl core::fmt::Debug for Demo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Demo")
            .field("steps_run", &self.log.len())
            .finish_non_exhaustive()
    }
}

impl Demo {
    /// A demo that has run nothing yet.
    #[must_use]
    pub const fn new(cfg: Config) -> Self {
        Self {
            cfg,
            log: Vec::new(),
            corner_log: Vec::new(),
            warming: false,
            client: None,
            ais: None,
            chain: None,
        }
    }

    /// The next step the walkthrough expects, if any.
    #[must_use]
    pub fn next_step(&self) -> Option<&'static str> {
        steps_for(self.cfg.course).get(self.log.len()).map(|s| s.0)
    }

    /// Mark what runs next as warm-up ("pre-run") or as live.
    pub fn set_warming(&mut self, on: bool) {
        self.warming = on;
    }

    /// Whether the warm-up has reached the end of [`WARM_UP`], so the corners
    /// have a case, an anchored epoch and a registered warrant to work on.
    #[must_use]
    pub fn warmed_up(&self) -> bool {
        self.log.len() >= WARM_UP.len()
    }

    /// How the panel was produced: during the warm-up, or now.
    fn mode(&self) -> &'static str {
        if self.warming { "pre-run" } else { "live" }
    }

    /// Run one step. Steps run in order; an out-of-order request is refused,
    /// because each phase consumes the state the previous one produced.
    ///
    /// # Errors
    ///
    /// The step's own failure, as text, or an out-of-order request.
    pub fn run(&mut self, step: &str) -> StepResult {
        if self.next_step() != Some(step) {
            return Err(format!(
                "step {step} is not next; next is {}",
                self.next_step()
                    .unwrap_or("nothing (the walkthrough is complete)")
            ));
        }
        let ran_at = now();
        let started = std::time::Instant::now();
        let name = STEPS
            .iter()
            .find(|s| s.0 == step)
            .map_or("walkthrough step", |s| s.3);
        let _span = perf::span(perf::Side::Client, name);
        let panel = match step {
            "init" => self.init(),
            "capture" => self.capture(),
            "analyze" => self.analyze(),
            "release" => self.release(),
            "receive" => self.receive(),
            "anchor" => self.anchor(),
            "warrant" => self.warrant(),
            "search" => self.search(),
            "custody-search" => self.custody_search(),
            "audit" => self.audit(),
            "tamper" => self.tamper(),
            "order" => self.order(),
            "erase" => self.erase(),
            other => Err(format!("unknown step {other}")),
        }?;
        let meta = STEPS.iter().find(|s| s.0 == step).map_or(
            json!({}),
            |s| json!({"id": s.0, "flow": s.1, "phases": s.2, "title": s.3}),
        );
        // ⭐ Every entry carries when it ran, how long it took and whether it
        // ran during the warm-up, so a panel produced before the audience
        // arrived can never be shown as if it ran on the button (§1dc.4).
        let entry = json!({"step": meta, "panel": panel, "ran_at": ran_at,
                           "took_s": started.elapsed().as_secs_f64(), "mode": self.mode()});
        self.log.push(entry.clone());
        Ok(entry)
    }

    fn parts(&mut self) -> Result<(&mut Client, &mut Ais, &mut ChainSession), String> {
        match (&mut self.client, &mut self.ais, &mut self.chain) {
            (Some(c), Some(a), Some(ch)) => Ok((c, a, ch)),
            _ => Err("the case is not initialised".into()),
        }
    }

    // ------------------------------------------------------------ D1: Phases 1–2

    // One phase, narrated as one panel: splitting it would scatter the story.
    #[allow(clippy::too_many_lines)]
    fn init(&mut self) -> StepResult {
        // Phase 1 Step 1: the authorities' keys, generated now.
        let ca_kem = KeyPair::generate().map_err(e2s)?;
        let ca_sig = SoftwareMlDsa::generate().map_err(e2s)?;
        let court = SoftwareMlDsa::generate().map_err(e2s)?;
        let committee = (0..3)
            .map(|_| SoftwareMlDsa::generate().map_err(e2s))
            .collect::<Result<Vec<_>, _>>()?;
        let cosigner = CoSigner::generate().map_err(e2s)?;

        // Phase 1 Step 2: K_mst drawn fresh; everything else descends from it.
        let k_mst = PrfKey::new(rng::secret().map_err(e2s)?);
        let case_id = "CASE-DEMO-2026-10".to_owned();
        // With an AWS proof bundle, the case commitment must be the one its
        // warrants name, so r_c comes from the bundle; otherwise it is fresh.
        let bundle: Option<Value> = std::fs::read(self.cfg.repo.join("zk/demo-proof/bundle.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        let r_case = match bundle.as_ref().and_then(|b| b["r_case"].as_str()) {
            Some(h) => flows::unhex(h)?,
            None => rng::secret().map_err(e2s)?,
        };
        let keys = CaseKeys::derive(&k_mst, case_id.as_bytes(), &r_case);
        // ⭐ Through `CaseKeys`, not hashed here (M13 A18). These two lines
        // used to spell the plane `b"evidence"` / `b"custody"` while
        // `PlaneRoot::derive` spelled it `0x00` / `0x01`, so the index the
        // demo built and the authority a warrant delegates over it were
        // keyed differently — invisibly, because no test crossed between
        // them.
        let k_s_ev = keys.evidence_index_key();
        let k_s_coc = keys.custody_index_key();
        // K_X^(0) is an independent draw, never derived from K_mst (eq:keys).
        let k_x0 = PrfKey::new(rng::secret().map_err(e2s)?);
        let evidence = XtClient::new(CoreClient::new(k_s_ev), k_x0, 16);
        let custody = CoreClient::new(k_s_coc);

        // Phase 2: the agent enrols by ML-KEM (no Diffie–Hellman) and receives
        // only its GGM leaf K_1 of the case tree.
        let device = KeyPair::generate().map_err(e2s)?;
        let (ct, ss) = kem::encapsulate(device.encapsulation_key()).map_err(e2s)?;
        let ss_dev = device.decapsulate(&ct).map_err(e2s)?;
        let paired = ss.as_bytes() == ss_dev.as_bytes();
        let k_1 = pqcl_ggm::MasterKey::new(*keys.k_case.as_bytes()).eval(1);

        let custodians = vec![
            Custodian::new("first-responder-1", "DEFR", Role::Defr)?,
            Custodian::new("evidence-store-1", "custodian", Role::Custodian)?,
            Custodian::new("analyst-1", "DES", Role::Des)?,
            // M13 A2: the investigator signs ACCESS, which no other role may.
            Custodian::new("investigator-1", "investigator", Role::Investigator)?,
            // The rest of the cast, for the custody corner's handoffs: a second
            // first responder, a second store (the lab's locker), the court's
            // evidence room, and a second examiner. All enrolled in ρ_c below.
            Custodian::new("first-responder-2", "DEFR", Role::Defr)?,
            Custodian::new("lab-locker-1", "custodian", Role::Custodian)?,
            Custodian::new("court-clerk-1", "custodian", Role::Custodian)?,
            Custodian::new("analyst-2", "DES", Role::Des)?,
        ];

        // Phase 1 Step 3: the contract that will anchor this case.
        let mut chain = ChainSession::connect(&self.cfg.rpc).map_err(e2s)?;
        let validators = chain.validators().unwrap_or(0);
        let deploy = chain
            .deploy_anchor(&self.cfg.repo.join("contracts/out/Anchor.sol/Anchor.json"))
            .map_err(e2s)?;
        // Phase 1 Step 3 (eq:reg): the keys and the M-of-N policy, fixed once.
        let reg = Registration {
            cid: keys.cid_c,
            pk_sig: ca_sig.public_key().to_vec(),
            pk_kem: ca_kem.encapsulation_key().to_vec(),
            pk_slh: cosigner.public_key().to_vec(),
            custodians: committee.iter().map(|c| c.public_key().to_vec()).collect(),
            m: 2,
            delta: 600,
            // ρ_c (§1br F3): the actors this case enrols, committed so a court
            // can check the roster it is later handed.
            roster: pqcl_pipeline::accept::Roster {
                entries: custodians
                    .iter()
                    .map(|c| pqcl_pipeline::accept::RosterEntry {
                        actor: c.agent.actor_ref(),
                        pk: c.agent.public_key().to_vec(),
                    })
                    .collect(),
            }
            .digest(),
        };
        let reg_digest = reg.digest();
        let registered = chain.register_case(&keys.cid_c, &reg_digest).map_err(e2s)?;

        if self.cfg.store.exists() {
            std::fs::remove_dir_all(&self.cfg.store).map_err(e2s)?;
        }
        let payloads = PayloadStore::open(&self.cfg.store).map_err(e2s)?;

        let panel = json!({
            "live": "live: every key below was generated in this step; the contract was deployed to the running chain",
            "client": [
                ["Secure Module", "host-software backend (pqcl-sm Backend::HostSoftware): keys live in this process. Allowed for a demo, never publishable"],
                ["case_id (private)", case_id],
                ["cid = H(case ‖ case_id ‖ r_c)", hex(&keys.cid_c)],
                ["K_case = F(K_mst, case ‖ cid)", "derived, held in the Secure Module"],
                ["K_S^ev, K_S^coc", "two index keys, one per plane"],
                ["K_X^(0)", "independent draw (not derived from K_mst), ratchets per epoch"],
                ["custodian committee", format!("N = 3 ML-DSA-65 keys ({} B each); M = 2 approve each checkpoint", committee[0].public_key().len())],
                ["SLH-DSA-SHAKE-192s co-signer", "generated"],
                ["ML-KEM-768 case key", format!("{} B encapsulation key", ca_kem.encapsulation_key().len())],
                ["Phase 2: agent enrolment", format!("ML-KEM-768 ciphertext {} B; both sides derived the same secret: {paired}", ct.len())],
                ["Phase 2: writer key K_1 = GGM(K_case, 1)", short(&k_1)],
                ["custodians (openings held here)", custodians.iter().map(|c| format!("{} ({})", c.actor_id, c.role)).collect::<Vec<_>>().join(", ")],
            ],
            "server": [
                ["chain", format!("Hyperledger Besu QBFT, chain id {}, {validators} validator(s) — one validator, not the four Exp. 6 measured on: a real chain without fault tolerance", chain.chain_id())],
                ["Anchor.sol", format!("deployed at block {} ({} gas), configuration A: signatures stored for an off-chain auditor, as measured", deploy.block, deploy.gas_used)],
                ["contract address", chain.anchor.map(|a| pqcl_exp::evm::to_hex(&a)).unwrap_or_default()],
                ["registerCase(cid, reg)", format!("block {}: reg = {}", registered.block, hex(&reg_digest))],
                ["what the chain knows about the case", "a commitment cid and the digest reg of its keys and policy, nothing else"],
                ["custodian identities on chain or server", "none: only commitments actor_c will ever appear"],
            ],
        });

        // Bound before the literal below moves `keys`.
        let views = committee
            .iter()
            .map(|_| checkpoint::ChainView::new(keys.cid_c, reg_digest))
            .collect();
        self.client = Some(Client {
            case_id,
            keys,
            ca_kem,
            ca_sig,
            court,
            views,
            committee,
            cosigner,
            reg,
            last_d: reg_digest,
            custodians,
            evidence,
            custody,
            custody_ids: 0,
            docs: Vec::new(),
            held: Vec::new(),
            handoffs: HashMap::new(),
            pending: None,
            epochs: Vec::new(),
            epoch: 1,
            bundle,
            custody_docs: Vec::new(),
            warrants: Vec::new(),
            rho_w: None,
            warrant_anchor: None,
            evidence_hits: Vec::new(),
            order: None,
            stark: Vec::new(),
            bursts: 0,
            synthetic_lines: 0,
            last_burst: None,
        });
        self.ais = Some(Ais {
            capsules: Vec::new(),
            chains: Vec::new(),
            payloads,
            evidence: LoggedStore {
                plane: "evidence",
                ..LoggedStore::default()
            },
            custody: LoggedStore {
                plane: "custody",
                ..LoggedStore::default()
            },
            mmr: Mmr::new(),
            closed: Vec::new(),
            leaves: Vec::new(),
        });
        self.chain = Some(chain);
        Ok(panel)
    }

    // ------------------------------------------------------------ D1: Phases 3–4

    // One phase, narrated as one panel, with its tool runs named for the profiler.
    #[allow(clippy::too_many_lines)]
    fn capture(&mut self) -> StepResult {
        let repo = self.cfg.repo.clone();
        let forensics = Forensics::new(
            &repo.join("forensics/run.sh"),
            &repo.join("datasets/artefacts"),
        )
        .map_err(|e| format!("the pinned forensic container is unavailable: {e}"))?;

        // Real tool runs: the documents are what the tools reported.
        let fls = {
            let _tool = perf::span(
                perf::Side::Tool,
                "fls over the disk image (pinned container)",
            );
            forensics
                .run("fls", &["-o", "51", "-r", "-p", "-m", "/", DISK_IMAGE])
                .map_err(e2s)?
        };
        let conv = {
            let _tool = perf::span(
                perf::Side::Tool,
                "tshark over the capture (pinned container)",
            );
            forensics
                .run("tshark", &["-r", PCAP, "-q", "-z", "conv,ip"])
                .map_err(e2s)?
        };

        let (client, ais, _) = self.parts()?;
        let mut next: DocId = 0;
        let mut d0 = docs::from_fls_body(&String::from_utf8_lossy(&fls.stdout), 0, &mut next);
        let d1 = docs::from_tshark_conv(&String::from_utf8_lossy(&conv.stdout), 1, &mut next);
        if d0.is_empty() || d1.is_empty() {
            return Err(
                "a tool produced no documents; refusing to seal an artefact nothing describes"
                    .into(),
            );
        }

        let mut rows = Vec::new();
        for (ci, (file, kind, run)) in [(DISK_IMAGE, "disk-image", &fls), (PCAP, "pcap", &conv)]
            .into_iter()
            .enumerate()
        {
            let held = seal_artefact(
                client,
                ais,
                &repo.join("datasets/artefacts").join(file),
                file,
                kind,
            )?;
            rows.push(json!([format!("capsule {ci}: {file}"), format!(
                "{} B plaintext → AES-256-GCM under a fresh K_ev; K_ev wrapped by ML-KEM-768 ({} B ct); tool: {} {}",
                std::fs::metadata(repo.join("datasets/artefacts").join(file)).map_or(0, |m| m.len()),
                held.wrap.0.len(), run.tool, run.version)]));
            client.held.push(held);
        }

        // Phase 4: index every document under the evidence plane's key.
        d0.extend(d1);
        let index_span = perf::span(
            perf::Side::Client,
            "index documents: tokens and cross-tags (Π_XT)",
        );
        let mut tokens = 0usize;
        for d in &d0 {
            for w in d.index_keywords() {
                client
                    .evidence
                    .update(&mut ais.evidence, Op::Add, &w, d.id)
                    .map_err(e2s)?;
                tokens += 1;
            }
        }
        client.evidence.flush(&mut ais.evidence);
        drop(index_span);
        let sample: Vec<String> = d0
            .iter()
            .take(4)
            .map(|d| format!("#{} {} — {}", d.id, d.label, d.keywords.join(" ")))
            .collect();
        client.docs = d0;

        // Phase 5 for the opening records: COLLECT by the first responder.
        open_chains(client, ais)?;

        let first_addr = ais
            .evidence
            .received
            .first()
            .map(|(a, _)| short(a))
            .unwrap_or_default();
        let ct_head = std::fs::read(ais.payloads.path(&client.held[0].capsule.eid))
            .map(|b| short(&b[..16.min(b.len())]))
            .unwrap_or_default();
        Ok(json!({
            "live": "live: both tools ran now in the pinned forensic container; sealing, signing and indexing ran now",
            "client": [
                rows[0].clone(), rows[1].clone(),
                ["documents (from tool output)", format!("{} file-system entries + {} IP conversations", client.docs.iter().filter(|d| d.capsule == 0).count(), client.docs.iter().filter(|d| d.capsule == 1).count())],
                ["sample documents", sample.join("\n")],
                ["index updates", format!("{tokens} (keywords plus every range prefix of size, mtime, duration)")],
                ["custody", "two COLLECT records, signed by first-responder-1 (ML-DSA-65)"],
            ],
            "server": [
                ["capsule 0 ciphertext (first bytes)", ct_head],
                ["capsule 0 d_ev (ciphertext digest)", hex(&client.held[0].capsule.d_ev)],
                ["capsule 0 eid (pseudonymous)", hex(&client.held[0].capsule.eid)],
                ["what a capsule names", "no file name, no case name: type, digests, signature, pointer"],
                ["EDB entries received", format!("{} (addr, val) pairs; first addr {first_addr}; each val {} B of AES-GCM", ais.evidence.received.len(), ais.evidence.received.first().map_or(0, |x| x.1))],
                ["cross-tags received", format!("{} in shuffled batches of 16, cross-tag epoch {}", ais.evidence.xtags.len(), ais.evidence.xtags.last().map_or(0, |x| x.0))],
                ["custody records received", format!("{} opaque records under eid_e pseudonyms", ais.chains.iter().map(|c| c.1.len()).sum::<usize>())],
                ["Tier-2 leaves so far", format!("{} × 0x01 (capsule seals)", ais.leaves.iter().filter(|l| l.tag == 1).count())],
            ],
        }))
    }

    // ------------------------------------------------------------ D2: Phases 5–6

    fn analyze(&mut self) -> StepResult {
        self.analyze_by(ANALYST)
    }

    /// Phase 5 Step 2 on the disk image, signed by custodian `who`. Refused
    /// before the tool runs unless the library's role table lets `who` sign
    /// `ANALYZE`.
    fn analyze_by(&mut self, who: usize) -> StepResult {
        {
            let (client, _, _) = self.parts()?;
            let c = client.custodians.get(who).ok_or("no such actor")?;
            refuse_role(c, Event::Analyze)?;
        }
        let repo = self.cfg.repo.clone();
        let forensics = Forensics::new(
            &repo.join("forensics/run.sh"),
            &repo.join("datasets/artefacts"),
        )
        .map_err(|e| format!("the pinned forensic container is unavailable: {e}"))?;
        let run = {
            let _tool = perf::span(perf::Side::Tool, "fsstat in the pinned forensic container");
            forensics
                .run("fsstat", &["-o", "51", DISK_IMAGE])
                .map_err(e2s)?
        };
        let (client, ais, _) = self.parts()?;
        let c = &client.custodians[who];
        let prev = client.held[0].chain.last().ok_or("empty chain")?.clone();
        let signed = c
            .agent
            .append_record(
                &client.keys,
                &client.held[0].capsule,
                Event::Analyze,
                &prev,
                &RecordParams::at(client.held[0].chain.len() as u64, now())
                    .with_params(run.params(b"examination under the case warrant"))
                    .in_epoch(client.epoch),
            )
            .map_err(e2s)?;
        let r = signed.record.clone();
        let params_c = signed.body.params_c;
        append_record(client, ais, 0, signed, who)?;
        let by = format!(
            "ANALYZE by {} ({}), who never takes custody: transfer-only models cannot record this",
            c_name(client, who),
            client.custodians[who].role
        );
        let fs_type = String::from_utf8_lossy(&run.stdout)
            .lines()
            .find(|l| l.starts_with("File System Type"))
            .unwrap_or("")
            .to_owned();
        Ok(json!({
            "live": "live: fsstat ran now; the record commits to the version the binary reported",
            "client": [
                ["tool", format!("{} {} {}", run.tool, run.version, run.args.join(" "))],
                ["tool reported", fs_type],
                ["params_c = H(0x23 ‖ ⟪tool, ver, args, just, r_p⟫)", hex(&params_c)],
                ["record", by],
                ["h_prev = H(0x24 ‖ L_{j-1})", hex(&r.h_prev)],
            ],
            "server": [
                ["record received", format!("{} B, of which {} B ciphertext body; rid {}…", r.encode().len(), r.body.len(), short(&r.rid))],
                ["what it reveals", "a pseudonym, a chain link and a ciphertext. Since M13 A1 the event, the timestamp, the actor and the tool parameters are all inside C_rec: the server cannot name the tool, the analyst, or even that this was an ANALYZE"],
                ["custody index entries", ais.custody.received.len().to_string()],
            ],
        }))
    }

    fn release(&mut self) -> StepResult {
        self.release_capsule(0)
    }

    /// The walkthrough's handoff: the holder releases capsule `ci` to the
    /// evidence store.
    fn release_capsule(&mut self, ci: usize) -> StepResult {
        let from = self
            .parts()?
            .0
            .held
            .get(ci)
            .ok_or("no such capsule")?
            .holder;
        self.release_to(ci, from, LAB)
    }

    /// Phase 6 Step 1 for capsule `ci`: custodian `from` releases it to
    /// custodian `to`. Refused unless `from` holds it now, and unless the
    /// library's role table lets both sign `TRANSFER` (the DES and the
    /// investigator examine and read but never take custody).
    fn release_to(&mut self, ci: usize, from: usize, to_who: usize) -> StepResult {
        let (client, ais, _) = self.parts()?;
        if ci >= client.held.len() {
            return Err(format!("no capsule {ci}"));
        }
        if client.pending.is_some() {
            return Err("a transfer is already in transit: receive it first".into());
        }
        let n = client.custodians.len();
        if from >= n || to_who >= n {
            return Err("no such actor".into());
        }
        refuse_role(&client.custodians[from], Event::Transfer)?;
        refuse_role(&client.custodians[to_who], Event::Transfer)?;
        if from == to_who {
            return Err("a transfer needs two parties: pick a different receiver".into());
        }
        let holder = client.held[ci].holder;
        if from != holder {
            return Err(format!(
                "refused by this client: {} does not hold {}; the holder is {}",
                c_name(client, from),
                client.held[ci].file,
                c_name(client, holder)
            ));
        }
        let cond = hash_domain(
            Domain::HandoffDescriptor,
            &[
                b"cond",
                b"tamper-evident bag 0042, seal intact",
                &rng::secret().map_err(e2s)?,
            ],
        );
        let defr = &client.custodians[from];
        // ⭐ The receiving custodian commits **first** (M13 A2): `D` binds `to`,
        // so the evidence store publishes a fresh commitment, the first
        // responder binds it into the descriptor, and the receipt is signed
        // under that same opening.
        let receiving = handoff::Receiving {
            actor: client.custodians[to_who]
                .agent
                .commit_actor()
                .map_err(e2s)?,
        };
        let to = receiving.to();
        let (out, h) = handoff::release(
            &defr.agent,
            &client.keys,
            &client.held[ci].capsule,
            &handoff::OpenChain::open(
                &client.held[ci].chain,
                &client.keys.record_body_key(&client.held[ci].capsule.eid),
            )
            .map_err(e2s)?,
            &handoff::Terms {
                to,
                cond,
                ts: now(),
                epoch: client.epoch,
            },
            None,
        )
        .map_err(e2s)?;
        client.handoffs.insert(h.descriptor(), h);
        client.pending = Some((ci, h, receiving, to_who));
        let out = {
            let record = out.record.clone();
            append_record(client, ais, ci, out, from)?;
            record
        };
        let parties = format!(
            "{} ({}) → {} ({}), openings held here",
            c_name(client, from),
            client.custodians[from].role,
            c_name(client, to_who),
            client.custodians[to_who].role
        );
        Ok(json!({
            "live": "live: the release record was signed now",
            "client": [
                ["capsule", client.held[ci].file.clone()],
                ["D = H(0x26 ‖ ⟪eid_e, from, to, cond, R_cap⟫)", hex(&h.descriptor())],
                ["from → to", parties],
                ["R_cap at release", hex(&h.r_cap)],
                ["state", "IN TRANSIT: a release with no receipt; the graph shows a pending edge"],
            ],
            "server": [
                ["record received", format!("a {} B record under pseudonym {}…, body {} B", out.encode().len(), short(&out.eid_e), out.body.len())],
                ["what it reveals", "that *a* record was appended to some capsule pseudonym. Not that it was a transfer, not the descriptor, not either party"],
            ],
        }))
    }

    fn receive(&mut self) -> StepResult {
        let (client, ais, _) = self.parts()?;
        let (ci, h, receiving, to_who) = client.pending.take().ok_or("nothing is in transit")?;
        // The receiver recomputes d_ev over the ciphertext the server stores.
        let path = ais.payloads.path(&client.held[ci].capsule.eid);
        let recomputed = {
            let _s = perf::span(
                perf::Side::Client,
                "recompute d_ev over the stored ciphertext",
            );
            *chunked::digest_file(&path, Domain::EvidenceDigest)
                .map_err(e2s)?
                .root()
        };
        client.held[ci].integrity = Some((recomputed, recomputed == client.held[ci].capsule.d_ev));
        let release = client.held[ci].chain.last().ok_or("empty chain")?.clone();
        let lab = &client.custodians[to_who];
        let body_key = client.keys.record_body_key(&client.held[ci].capsule.eid);
        let release_body = release.open_body(&body_key).map_err(e2s)?;
        let inn = handoff::receive(
            &lab.agent,
            &client.keys,
            &client.held[ci].capsule,
            &handoff::Release {
                record: &release,
                body: &release_body,
            },
            &h,
            &handoff::Receipt {
                recomputed,
                j: client.held[ci].chain.len() as u64,
                ts: now(),
                epoch: client.epoch,
                receiving,
            },
        )
        .map_err(e2s)?;
        let inn = {
            let record = inn.record.clone();
            append_record(client, ais, ci, inn, to_who)?;
            record
        };
        client.held[ci].holder = to_who;
        let holder = format!(
            "{} now holds {}",
            c_name(client, to_who),
            client.held[ci].file
        );
        Ok(json!({
            "live": "live: d_ev recomputed now over the stored ciphertext; receipt signed now",
            "client": [
                ["recomputed d_ev", hex(&recomputed)],
                ["anchored d_ev", hex(&client.held[ci].capsule.d_ev)],
                ["integrity re-verified at handoff", (recomputed == client.held[ci].capsule.d_ev).to_string()],
                ["receipt h_prev = H(0x24 ‖ L_release) — same segment, so the clear link is the real one", hex(&inn.h_prev)],
                ["state", "complete: two linked records over one descriptor, each signed by its own custodian".to_owned()],
                ["custody", holder],
            ],
            "server": [
                ["record received", format!("a second {} B record chained to the first, body {} B", inn.encode().len(), inn.body.len())],
                ["what it reveals", "that two records are chained. That they share a descriptor is now invisible too: D lives inside both ciphertexts"],
            ],
        }))
    }

    // ------------------------------------------------------------ D3: Phase 7

    // One phase, narrated as one panel: splitting it would scatter the story.
    #[allow(clippy::too_many_lines)]
    fn anchor(&mut self) -> StepResult {
        let (client, ais, chain) = self.parts()?;
        let e = client.epoch;

        // 0x02: one leaf per **segment** closed in this epoch — the records
        // appended since the last close, which all carry this epoch's
        // pseudonym (M13 A20). A capsule with no activity this epoch gets no
        // leaf, and the leaf it does get covers its segment and not the chain.
        for ci in 0..client.held.len() {
            let h = &client.held[ci];
            let from = h.committed_len();
            if from == h.chain.len() {
                continue;
            }
            let segment = &h.chain[from..];
            let eid_e = segment[0].eid_e;
            let root = handoff::running_root(segment);
            let leaf = Leaf::new(
                Domain::CustodyRoot,
                &[&eid_e, &root, &(segment.len() as u64).to_le_bytes()],
            );
            let at = ais.append(&leaf, 2, e);
            let to = h.chain.len();
            client.held[ci].anchored.push(AnchoredSegment {
                epoch: e,
                eid_e,
                from,
                to,
                at,
                proof: None,
            });
        }

        // 0x03: the index epoch — the sorted cross-tag set and the EDB digest.
        let x_epoch = client.evidence.closed_epochs();
        client.evidence.close_epoch(&mut ais.evidence);
        let mut xs: Vec<XTag> = ais
            .evidence
            .xtags
            .iter()
            .filter(|(ep, _)| *ep == x_epoch)
            .map(|(_, t)| *t)
            .collect();
        xs.sort_unstable();
        let mut t = CustodyTree::new();
        for x in &xs {
            t.append_leaf(*x);
        }
        let x_root = t.root().unwrap_or([0; 32]);
        let edb_digest = digest256(&ais.evidence.entries_digest);
        let leaf3 = Leaf::new(
            Domain::IndexEpoch,
            &[&e.to_le_bytes(), &x_root, &edb_digest],
        );
        ais.append(&leaf3, 3, e);

        // Phase 7 Steps 2–4: bag the MMR, checkpoint it onto the last one,
        // approve 2-of-3, co-sign, anchor the digests.
        let root = ais.mmr.root().ok_or("empty MMR")?;
        // ⭐ `n_e`, this epoch's own leaf count (M13 A21). The MMR is per epoch
        // now, so this *is* the epoch's count rather than a running total —
        // and it is committed inside `d_e` and nowhere on chain.
        let n_e = ais.mmr.leaf_count();
        let d_prev = client.last_d;
        let d_e = checkpoint::checkpoint(&client.keys.cid_c, e, &root, n_e, &d_prev);
        // ⭐ Each approving custodian recomputes `R_e` and `n_e` from the
        // epoch's leaves and checks the link to what *it* last approved before
        // signing (`eq:validcp`, M13 A5).
        let leaves = ais.mmr.leaf_digests().to_vec();
        let approve_span = perf::span(
            perf::Side::Client,
            "2-of-3 custodians validate and approve (ML-DSA-65)",
        );
        let approvals = [0u32, 1]
            .iter()
            .map(|&j| {
                let v = client.views[j as usize]
                    .validate(&checkpoint::Proposal {
                        cid: client.keys.cid_c,
                        e,
                        root,
                        n_e,
                        d_prev,
                        d_e,
                        over: checkpoint::Committed::Epoch(&leaves),
                    })
                    .map_err(e2s)?;
                checkpoint::approve(&client.committee[j as usize], j, &v).map_err(e2s)
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(approve_span);
        let started = std::time::Instant::now();
        let set = {
            let _s = perf::span(perf::Side::Client, "SLH-DSA-SHAKE-192s co-signature");
            ApprovalSet::new(approvals, &client.cosigner, &d_e).map_err(e2s)?
        };
        let slh_s = started.elapsed().as_secs_f64();
        let a_e = set.digest();
        let receipt = chain
            .commit_root(&client.keys.cid_c, &root, &d_prev, &d_e, &a_e)
            .map_err(e2s)?;
        let on_chain = chain.latest_epoch(&client.keys.cid_c).map_err(e2s)?;
        // The auditor's check of the approval set, against what the chain holds.
        let approved = set.verify(&client.reg, &on_chain.checkpoint, &on_chain.approval);
        client.last_d = d_e;

        // The capsule's own `0x01` proof, in the epoch that sealed it (M13 A3).
        for ci in 0..client.held.len() {
            if client.held[ci].seal_proof.is_none() && client.held[ci].seal_epoch == e {
                let at = client.held[ci].seal_leaf;
                client.held[ci].seal_proof = Some(ais.mmr.prove(at).ok_or("no seal proof")?);
            }
        }

        let mut proofs = Vec::new();
        for ci in 0..client.held.len() {
            let Some(k) = client.held[ci].anchored.iter().rposition(|a| a.epoch == e) else {
                continue;
            };
            let at = client.held[ci].anchored[k].at;
            let proof = ais.mmr.prove(at).ok_or("no proof")?;
            client.held[ci].anchored[k].proof = Some(proof.clone());
            proofs.push((ci, at, proof));
        }
        // Every leaf appended while this epoch was open, seals included.
        let tags: Vec<u8> = ais
            .leaves
            .iter()
            .filter(|l| l.epoch == e)
            .map(|l| l.tag)
            .collect();
        client.epochs.push(EpochClose {
            e,
            root,
            leaf_count: n_e,
            receipt: receipt.clone(),
            on_chain,
            proofs,
            tags: tags.clone(),
            committed: client
                .held
                .iter()
                .enumerate()
                .filter(|(_, h)| !h.anchored.is_empty())
                .map(|(ci, h)| (ci, h.committed_len()))
                .collect(),
        });
        // The epoch's proofs are taken above, so its MMR can be retired and the
        // next one started empty (M13 A20/A21).
        ais.close(e);
        client.epoch += 1;

        Ok(json!({
            "live": "live: the transaction was mined just now; the root shown on the right was read back from chain state",
            "client": [
                ["epoch", e.to_string()],
                ["leaves appended this epoch", tags.iter().map(|t| format!("0x0{t}")).collect::<Vec<_>>().join(", ")],
                ["R_e (bagged MMR peaks)", hex(&root)],
                ["n_e (this epoch's leaves; committed in d_e, not on chain)", n_e.to_string()],
                ["d_{e−1} (the last checkpoint, or reg)", hex(&d_prev)],
                ["d_e = H(0x12 ‖ ⟪cid, e, R_e, n_e, d_{e−1}⟫)", hex(&d_e)],
                ["approval set S_e", format!("2 of 3 custodians (ML-DSA-65) + SLH-DSA co-signature in {slh_s:.1} s: {} B, kept off chain", set.wire_bytes())],
                ["auditor: approvals valid against reg and A_e", approved.map_or_else(|e| format!("REFUSED: {e}"), |n| format!("{n} of 3, threshold 2"))],
                ["0x03 leaf: MR(sorted XSet_e)", format!("{} over {} cross-tags", short(&x_root), xs.len())],
            ],
            "server": [
                ["commitRoot transaction", format!("{} in block {}, {} gas, {} B on the wire", receipt.tx_hash, receipt.block, receipt.gas_used, receipt.tx_bytes)],
                ["latestEpoch(cid) on chain", format!("root {}, block {} — and no leaf count, which is M13 A21: a public running total made case size public", hex(&on_chain.root), on_chain.block)],
                ["chain accepted it because", "d_{e−1} equals the checkpoint it last stored (or reg): the link is the whole check (M13 A21); n_e is committed inside d_e and checked off chain"],
                ["chain root and checkpoint equal the client's", (on_chain.root == root && on_chain.checkpoint == d_e).to_string()],
                ["what the chain learns", "six 32-byte words: no signature, no capsule, no custodian"],
            ],
        }))
    }

    // ------------------------------------------------------------ the page's state

    /// Everything the page draws: steps, the custody graph, each capsule's
    /// timeline with live badges, the epochs.
    #[must_use]
    pub fn state(&self) -> Value {
        let steps: Vec<Value> = steps_for(self.cfg.course)
            .iter()
            .enumerate()
            .map(|(i, s)| {
                json!({"id": s.0, "flow": s.1, "phases": s.2, "title": s.3,
                                 "done": i < self.log.len(), "next": i == self.log.len()})
            })
            .collect();
        let Some(client) = &self.client else {
            return json!({"steps": steps, "log": self.log, "rpc": self.cfg.rpc,
                          "course": self.cfg.course, "warmed_up": false,
                          "warm_up": WARM_UP, "corner_log": self.corner_log});
        };

        let views: Vec<ChainView<'_>> = client
            .held
            .iter()
            .map(|h| ChainView {
                label: &h.file,
                chain: &h.chain,
                bodies: &h.bodies,
            })
            .collect();
        // ⭐ One entry per **record**, not per custodian (M13 A2): `actor_c`
        // carries a fresh `r_a` every time, so the graph resolves a node from
        // the opening the client kept beside the record. A server holding every
        // body still cannot do this, which is what blinding buys.
        let openings: HashMap<Digest32, Opening> = client
            .held
            .iter()
            .flat_map(|h| h.actors.iter())
            .map(|a| {
                (
                    a.commit(),
                    Opening {
                        actor_id: String::from_utf8_lossy(&a.id).into_owned(),
                        role: format!("{:?}", a.role),
                    },
                )
            })
            .collect();
        let graph = graph::build(&views, &openings, &client.handoffs);

        let capsules: Vec<Value> = client
            .held
            .iter()
            .enumerate()
            .map(|(ci, h)| capsule_view(client, ci, h))
            .collect();

        let epochs: Vec<Value> = client
            .epochs
            .iter()
            .map(|ep| {
                json!({
            "e": ep.e, "root": hex(&ep.root), "leaf_count": ep.leaf_count, "tx": ep.receipt.tx_hash,
            "block": ep.receipt.block, "gas": ep.receipt.gas_used,
            "tags": ep.tags, "on_chain_matches": ep.on_chain.root == ep.root,
            "checkpoint": hex(&ep.on_chain.checkpoint), "approval": hex(&ep.on_chain.approval)})
            })
            .collect();

        json!({"steps": steps, "log": self.log, "rpc": self.cfg.rpc, "graph": graph,
               "capsules": capsules, "epochs": epochs, "documents": client.docs.len(),
               "cid": hex(&client.keys.cid_c), "open_epoch": client.epoch,
               "known": flows::known_values(client),
               "course": self.cfg.course, "warmed_up": self.warmed_up(), "warm_up": WARM_UP,
               "corner_log": self.corner_log, "corners": self.corner_state()})
    }
}

// ---------------------------------------------------------------- helpers

/// The library's role table (`Event::signers`) decides; this only turns its
/// answer into a refusal the page can show before anything is signed.
fn refuse_role(c: &Custodian, event: Event) -> Result<(), String> {
    let role = c.agent.role();
    if role.may(event) {
        return Ok(());
    }
    let allowed: Vec<String> = event.signers().iter().map(|r| format!("{r:?}")).collect();
    Err(format!(
        "refused by the role table (Event::signers): {} is {:?}, and {} may be signed only by {}",
        c.actor_id,
        role,
        graph::event_name(event),
        allowed.join(" or ")
    ))
}

fn c_name(client: &Client, i: usize) -> &str {
    client
        .custodians
        .get(i)
        .map_or("?", |c| c.actor_id.as_str())
}

/// Phase 5 Step 1 for each new capsule: the first responder's `COLLECT`.
fn open_chains(client: &mut Client, ais: &mut Ais) -> Result<(), String> {
    for ci in 0..client.held.len() {
        open_chain(client, ais, ci, b"on-scene collection")?;
    }
    Ok(())
}

/// Phase 5 Step 1 for one capsule: the first responder's `COLLECT`. The
/// ingestion corner calls this for each synthetic-log capsule it seals.
fn open_chain(client: &mut Client, ais: &mut Ais, ci: usize, why: &[u8]) -> Result<(), String> {
    let c = &client.custodians[DEFR];
    let signed = c
        .agent
        .collect_record(
            &client.keys,
            &client.held[ci].capsule,
            &RecordParams::at(0, now())
                .with_params(Params::justified(why))
                .in_epoch(client.epoch),
        )
        .map_err(e2s)?;
    append_record(client, ais, ci, signed, DEFR)
}

/// One capsule's timeline with its live badges, each recomputed now.
fn capsule_view(client: &Client, ci: usize, h: &Held) -> Value {
    let tier1_root = handoff::running_root(&h.chain);
    let mut t = CustodyTree::new();
    for r in &h.chain {
        t.append(&r.encode());
    }
    let records: Vec<Value> = h.chain.iter().enumerate().map(|(j, r)| {
        let signer = &client.custodians[h.signers[j]];
        // `σ_actor` is inside `C_rec` (§1br F2); the demo client holds the key.
        let sig_ok = r.open(&client.keys.record_body_key(&h.capsule.eid)).is_ok_and(|o| {
            sig::verify(&record_signed_bytes(r, &o.body), &o.sigs.actor, signer.agent.public_key(), &[]).is_ok()
        });
        // ⭐ The link badge reads the **body's** link (M13 A20): the real
        // chain link is inside `C_rec`, and the cleartext `h_prev` is a
        // segment-local value. The demo client holds the key, so it checks the
        // real one — which is exactly the split the panels narrate.
        let link_ok = h.bodies[j].link
            == if j == 0 { CustodyRecord::genesis_link(&h.capsule.eid) } else { h.chain[j - 1].chain_link() };
        let in_tier1 = t.prove(j).is_some_and(|p| pqcl_forest::tier1::verify(&tier1_root, &r.encode(), &p));
        // Which segment holds this record, and the epoch that anchored it
        // (M13 A20): the Tier-2 check is against that segment's own leaf in
        // that epoch's root, not against a running prefix of the chain.
        let seg = h.anchored.iter().find(|a| (a.from..a.to).contains(&j));
        let tier2 = seg.is_some_and(|a| {
            let Some(p) = a.proof.as_ref() else { return false };
            let Some(ep) = client.epochs.iter().find(|ep| ep.e == a.epoch) else { return false };
            let root_then = handoff::running_root(&h.chain[a.from..a.to]);
            let leaf = Leaf::new(Domain::CustodyRoot, &[&a.eid_e, &root_then, &((a.to - a.from) as u64).to_le_bytes()]);
            pqcl_forest::tier2::verify(&ep.root, &leaf, p)
        });
        let on_chain = seg.is_some_and(|a| {
            client.epochs.iter().any(|ep| ep.e == a.epoch && ep.on_chain.root == ep.root)
        });
        let b = &h.bodies[j];
        json!({"index": j, "event": graph::event_name(b.event), "actor": signer.actor_id, "role": signer.role, "ts": b.ts,
               "epoch": seg.map_or(client.epoch, |a| a.epoch),
               "badges": {"signature": sig_ok, "h_prev": link_ok, "tier1": in_tier1,
                          "tier2": tier2, "on_chain": on_chain}})
    }).collect();
    json!({"index": ci, "file": h.file, "kind": h.kind, "eid": hex(&h.capsule.eid),
           "d_ev": hex(&h.capsule.d_ev), "integrity": h.integrity.map(|(d, ok)| json!({"recomputed": hex(&d), "ok": ok})),
           "erased": h.erased.map(|o| hex(&o)),
           "holder": c_name(client, h.holder),
           "in_transit": handoff::in_transit(&handoff::OpenChain {
               records: &h.chain,
               bodies: h.bodies.clone(),
           }), "records": records})
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Phase 3 Steps 1–2 for one artefact: name it, encrypt it under a fresh
/// `K_ev`, store the ciphertext, bind `d_ev` over the ciphertext and `cm_ev`
/// over the plaintext, wrap `K_ev` by ML-KEM, and let the DEFR sign.
fn seal_artefact(
    client: &Client,
    ais: &mut Ais,
    path: &Path,
    file: &str,
    kind: &str,
) -> Result<Held, String> {
    let _span = perf::span(
        perf::Side::Client,
        "seal artefact (AES-256-GCM, ML-KEM wrap, ML-DSA sign)",
    );
    let nonce: Digest32 = rng::secret().map_err(e2s)?;
    let eid = prf(&client.keys.k_case, Label::Eid, &[&nonce]);
    let plaintext = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let k_ev = rng::secret().map_err(e2s)?;
    let c_ev = RecordKey::new(k_ev).seal(&eid, &plaintext).map_err(e2s)?;
    drop(plaintext);
    {
        let _store = perf::on(perf::Side::Store);
        perf::seam(perf::Dir::Up, "evidence ciphertext", c_ev.as_bytes().len());
        ais.payloads.put(&eid, c_ev.as_bytes()).map_err(e2s)?;
    }
    let ct_digest =
        chunked::digest_file(&ais.payloads.path(&eid), Domain::EvidenceDigest).map_err(e2s)?;
    let d_ev = *ct_digest.root();

    let (ct, ss) = kem::encapsulate(client.ca_kem.encapsulation_key()).map_err(e2s)?;
    let wrapped = RecordKey::new(*ss.as_bytes())
        .seal(&eid, &k_ev)
        .map_err(e2s)?;

    let ptr = format!("ais://payload/{}", hex(&eid));
    let defr = &client.custodians[DEFR];
    let (capsule, opening) = defr
        .agent
        .ingest(
            &client.keys,
            path,
            &IngestParams {
                artefact_type: kind.as_bytes(),
                d_ev,
                ptr: ptr.as_bytes(),
                epoch: client.epoch,
                nonce: &nonce,
            },
        )
        .map_err(e2s)?;
    if capsule.eid != eid {
        return Err("the agent named the capsule differently from the ciphertext's binding".into());
    }
    let seal_leaf = {
        let _store = perf::on(perf::Side::Store);
        let encoded = capsule.encode();
        perf::seam(perf::Dir::Up, "capsule", encoded.len());
        ais.capsules.push(encoded);
        ais.append(&capsule.seal_leaf(), 1, client.epoch)
    };
    let seal_epoch = client.epoch;
    Ok(Held {
        capsule,
        bodies: Vec::new(),
        actors: Vec::new(),
        file: file.to_owned(),
        kind: kind.to_owned(),
        wrap: (ct, wrapped.as_bytes().to_vec()),
        chain: Vec::new(),
        signers: Vec::new(),
        seal_leaf,
        seal_epoch,
        seal_proof: None,
        anchored: Vec::new(),
        integrity: None,
        chunks: ct_digest.chunks().to_vec(),
        opening,
        erased: None,
        holder: DEFR,
    })
}

/// Hand a signed record to the server and index it on the custody plane under
/// its own key: event, actor commitment, capsule pseudonym, time prefixes.
fn append_record(
    client: &mut Client,
    ais: &mut Ais,
    ci: usize,
    signed: Signed,
    signer: usize,
) -> Result<(), String> {
    let id = client.custody_ids;
    client.custody_ids += 1;
    // ⭐ **The library's index set, all 29 keywords** (M13 A2):
    // `{eid_e, evt, actor:⟪id, role⟫, role} ∪ anc(ts)`. The demo used to build
    // its own three-term set, one of whose terms was `actor_c` — a value that
    // now differs in every record and so indexes nothing searchable. The actor
    // keyword is the **opening**, which is why only the client can do this.
    let Signed {
        record,
        body,
        actor,
        ..
    } = signed;
    let keywords = custody_keywords(&record.eid_e, &body, &actor)
        .ok_or("the record's timestamp is outside the ts attribute's window")?;
    for w in keywords {
        let tok = client.custody.update(Op::Add, &w, id).map_err(e2s)?;
        ais.custody.insert(&tok);
    }
    {
        let _store = perf::on(perf::Side::Store);
        let encoded = record.encode();
        perf::seam(perf::Dir::Up, "custody record", encoded.len());
        if ci >= ais.chains.len() {
            ais.chains.push((record.eid_e, Vec::new()));
        }
        ais.chains[ci].1.push(encoded);
    }
    client.held[ci].chain.push(record);
    client.held[ci].bodies.push(body);
    client.held[ci].actors.push(actor);
    client
        .custody_docs
        .push((ci, client.held[ci].chain.len() - 1));
    client.held[ci].signers.push(signer);
    Ok(())
}
