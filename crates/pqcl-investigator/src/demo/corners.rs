//! The course demo's three corners:
//! **ingestion**, **chain of custody** and **search**, over one live case.
//!
//! The warm-up runs the walkthrough's first steps ([`WARM_UP`]) before the
//! audience arrives, and labels every panel it produces "pre-run" with the
//! time it ran and how long it took. After that each corner button runs live:
//!
//! * **ingestion** — a seeded generator writes synthetic log lines (auth, web,
//!   firewall, system). The *lines* are generated; everything done to them is
//!   the real pipeline: the burst is sealed into a capsule (AES-256-GCM,
//!   ML-KEM-wrapped key, ML-DSA signature), its custody chain opens with a
//!   signed `COLLECT`, and every line is indexed under `Π_XT` (tokens and
//!   cross-tags) with its range prefixes;
//! * **chain of custody** — release and receipt (a pending edge until the
//!   receipt), analysis, epoch close and anchoring on the live chain,
//!   verification of any capsule's history from public data, and tamper
//!   detection;
//! * **search** — a typed Boolean/range query on the evidence plane (two
//!   rounds), or an event/actor query on the custody plane (`Π_CD`), each
//!   gated by its warrant's scope, and each checked against a plaintext
//!   oracle in the same step.
//!
//! ⛔ No number shown here reaches any document: one validator, a
//! host-software Secure Module, a laptop.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Instant;

use pqcl_capsule::Event;
use pqcl_dsse::core::{DocId, Op};
use pqcl_dsse::range::{Attribute, RangeTree};
use pqcl_dsse::xt::{Formula, XSetStore, doc_id};
use pqcl_sm::Plane;
use serde_json::{Value, json};

use super::flows::{class_of, scope_of};
use super::{
    ANALYST, Demo, INVESTIGATOR, LAB, StepResult, append_record, c_name, e2s, now, open_chain,
    refuse_role, seal_artefact, short,
};
use crate::docs::{self, Document};
use crate::graph::{self, hex};
use crate::perf;

/// The walkthrough steps the warm-up runs, in order: initialisation, the two
/// real artefacts with their real tool runs, one handoff, one anchored epoch,
/// and the warrants with both searches registered on chain.
pub const WARM_UP: &[&str] = &[
    "init", "capture", "analyze", "release", "receive", "anchor", "warrant",
];

/// Most lines one burst may carry, so a click cannot take minutes.
const MAX_BURST: u64 = 5_000;

impl Demo {
    /// Run one corner action. Refused until the warm-up has finished, because
    /// every corner works on the case the warm-up set up.
    ///
    /// # Errors
    ///
    /// The action's own failure, as text, or an unknown action.
    pub fn act(&mut self, action: &str, body: &Value) -> StepResult {
        if !self.warmed_up() {
            return Err("the warm-up has not finished yet".into());
        }
        let ran_at = now();
        let started = Instant::now();
        let _span = perf::span(perf::Side::Client, action_name(action));
        let (corner, panel) = match action {
            "ingest" => ("ingestion", self.ingest(body)?),
            "release" => {
                let ci = capsule_arg(body)?;
                let holder = self
                    .parts()?
                    .0
                    .held
                    .get(ci)
                    .ok_or("no such capsule")?
                    .holder;
                let from = actor_arg(body, "from")?.unwrap_or(holder);
                let to = actor_arg(body, "to")?.unwrap_or(LAB);
                ("coc", self.release_to(ci, from, to)?)
            }
            "receive" => ("coc", self.receive()?),
            "analyze" => (
                "coc",
                self.analyze_by(actor_arg(body, "actor")?.unwrap_or(ANALYST))?,
            ),
            "access" => (
                "coc",
                self.access_by(
                    capsule_arg(body)?,
                    actor_arg(body, "actor")?.unwrap_or(INVESTIGATOR),
                )?,
            ),
            "anchor" => ("coc", self.anchor()?),
            "verify" => ("coc", self.audit_capsule(capsule_arg(body)?)?),
            "tamper" => ("coc", self.tamper_capsule(capsule_arg(body)?)?),
            "search" => ("search", self.free_search(body)?),
            "custody-search" => ("search", self.free_custody_search(body)?),
            other => return Err(format!("unknown action {other}")),
        };
        let entry = json!({"corner": corner, "action": action, "ran_at": ran_at,
                           "took_s": started.elapsed().as_secs_f64(), "mode": self.mode(),
                           "panel": panel});
        self.corner_log.push(entry.clone());
        if self.corner_log.len() > 40 {
            self.corner_log.remove(0);
        }
        Ok(entry)
    }

    // ------------------------------------------------------------ ingestion

    /// Generate one burst of synthetic log lines and put it through the real
    /// pipeline: seal, `COLLECT`, index.
    #[allow(clippy::too_many_lines)]
    fn ingest(&mut self, body: &Value) -> StepResult {
        let lines = body["lines"].as_u64().unwrap_or(200).clamp(1, MAX_BURST);
        let mix = LogMix::parse(body["mix"].as_str().unwrap_or("mixed"))?;
        let dir = self.cfg.store.with_file_name("demo-synthetic");
        std::fs::create_dir_all(&dir).map_err(e2s)?;
        let (client, ais, _) = self.parts()?;
        let burst = client.bursts + 1;
        let generated = generate(lines, mix, burst, now());

        // The burst becomes one artefact: a log file the edge agent collected.
        let file = format!("synthetic-burst-{burst:03}.log");
        let path = dir.join(&file);
        let text = generated
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, text.as_bytes()).map_err(e2s)?;

        let t_seal = Instant::now();
        let held = seal_artefact(client, ais, &path, &file, "synthetic-log")?;
        client.held.push(held);
        let ci = client.held.len() - 1;
        open_chain(
            client,
            ais,
            ci,
            b"synthetic log burst, collected by the edge agent",
        )?;
        let seal_s = t_seal.elapsed().as_secs_f64();

        // Phase 4: every line is a document on the evidence plane, under the
        // open cross-tag epoch, so it is pending until the epoch closes.
        let x_epoch = client.evidence.epoch();
        let entries_before = ais.evidence.received.len();
        let xtags_before = ais.evidence.xtags.len();
        let t_index = Instant::now();
        let index_span = perf::span(
            perf::Side::Client,
            "index lines: tokens and cross-tags (Π_XT)",
        );
        let mut updates = 0usize;
        let mut new_docs: Vec<Document> = Vec::with_capacity(generated.len());
        let sample: Vec<String> = generated.iter().take(5).map(|l| l.text.clone()).collect();
        let first_keywords = generated
            .first()
            .map(|l| l.keywords.join(" "))
            .unwrap_or_default();
        for l in generated {
            let id = doc_id(x_epoch, (client.docs.len() + new_docs.len()) as u64);
            let d = Document {
                id,
                capsule: ci,
                label: l.text,
                keywords: l.keywords,
                numbers: l.numbers,
            };
            for w in d.index_keywords() {
                client
                    .evidence
                    .update(&mut ais.evidence, Op::Add, &w, d.id)
                    .map_err(e2s)?;
                updates += 1;
            }
            new_docs.push(d);
        }
        client.evidence.flush(&mut ais.evidence);
        drop(index_span);
        let index_s = t_index.elapsed().as_secs_f64();
        let n_docs = new_docs.len();
        client.docs.extend(new_docs);
        client.bursts = burst;
        client.synthetic_lines += lines;

        let entries = ais.evidence.received.len() - entries_before;
        let xtags = ais.evidence.xtags.len() - xtags_before;
        let first_addr = ais
            .evidence
            .received
            .get(entries_before)
            .map(|(a, len)| format!("{} ({len} B value)", short(a)))
            .unwrap_or_default();
        let ct_head = std::fs::read(ais.payloads.path(&client.held[ci].capsule.eid))
            .map(|b| short(&b[..16.min(b.len())]))
            .unwrap_or_default();
        let summary = json!({"burst": burst, "lines": lines, "updates": updates,
                             "xtags": xtags, "seal_s": seal_s, "index_s": index_s,
                             "capsule": ci, "file": file});
        client.last_burst = Some(summary);

        Ok(json!({
            "live": "live: the lines are synthetic (generated now by a seeded generator); sealing, signing, the COLLECT record and indexing are the real pipeline and ran now",
            "client": [
                ["burst", format!("#{burst}: {lines} {} lines → capsule {ci} ({file})", mix.name())],
                ["sample lines (plaintext, client only)", sample.join("\n")],
                ["first line's keywords", first_keywords],
                ["sealed", format!("AES-256-GCM under a fresh K_ev, K_ev wrapped by ML-KEM-768, signed by first-responder-1 (ML-DSA-65); COLLECT record signed; {seal_s:.2} s")],
                ["indexed", format!("{n_docs} documents, {updates} index updates (keywords plus range prefixes of ts, bytes, dur) in {index_s:.2} s")],
                ["searchable", "not yet: they sit in the open epoch, so a search reports them as pending until the custody corner closes and anchors it".to_owned()],
            ],
            "server": [
                ["capsule ciphertext (first bytes)", ct_head],
                ["capsule eid (pseudonymous)", hex(&client.held[ci].capsule.eid)],
                ["EDB entries received", format!("{entries} (addr, val) pairs; first addr {first_addr}")],
                ["cross-tags received", format!("{xtags}, in shuffled batches of 16")],
                ["what the server cannot read", "the lines, the user names, the IPs, the hosts: only addresses, ciphertext values and opaque tags arrive"],
            ],
        }))
    }

    // ------------------------------------------------------------ search

    /// Evidence-plane search: `s ∧ ψ`, `s` one keyword, `ψ` any Boolean
    /// formula over keywords and ranges (`Π_BOOL`, `Π_RANGE`).
    #[allow(clippy::too_many_lines)]
    fn free_search(&mut self, body: &Value) -> StepResult {
        let s_term = body["s"].as_str().unwrap_or("").trim().to_owned();
        let psi_text = body["psi"].as_str().unwrap_or("").trim().to_owned();
        if s_term.is_empty()
            || s_term.contains(char::is_whitespace)
            || !s_term.contains(':')
            || s_term.contains("..")
        {
            return Err("the first term must be one keyword, field:value, e.g. log:auth".into());
        }
        if ["bytes:", "ts:", "dur:"]
            .iter()
            .any(|p| s_term.starts_with(p))
        {
            return Err("the first term must be a plain keyword; put ranges in the filter".into());
        }
        let at = now();
        let psi = parse_filter(&psi_text, at)?;

        // The scope this query needs: the classes of every term in it.
        let mut needed = vec![s_term.clone()];
        if let Some(e) = &psi {
            e.class_keywords(&mut needed);
        }
        let needed_refs: Vec<&str> = needed.iter().map(String::as_str).collect();
        let scope = scope_of(Plane::Evidence, &needed_refs)?;
        let (q_lo, q_hi) = scope.bounds();

        let (client, ais, _) = self.parts()?;
        let w = client
            .warrants
            .first()
            .ok_or("no evidence warrant")?
            .clone();
        let (w_lo, w_hi) = w.warrant.scope.bounds();
        let outside: Vec<String> = needed
            .iter()
            .filter(|k| {
                let c = class_of(k);
                c < w_lo || c > w_hi
            })
            .map(|k| k.split(':').next().unwrap_or("").to_owned() + ":…")
            .collect();
        if let Err(e) = w.warrant.check_scope_and_expiry(&scope, client.epoch) {
            return Ok(json!({
                "refused": true,
                "live": "live: the investigator's module checked the query against the signed warrant now and refused it; nothing was sent to the server",
                "client": [
                    ["query", format!("{s_term} AND ({psi_text})")],
                    ["classes the query needs", format!("{q_lo}–{q_hi}")],
                    ["the evidence warrant covers", format!("classes {w_lo}–{w_hi} (file system, log fields, numeric), not network identifiers")],
                    ["outside the warrant", outside.join(", ")],
                    ["refused", e.to_string()],
                ],
                "server": [
                    ["what the server received", "nothing: no trapdoor exists for a refused query"],
                ],
            }));
        }

        // Round 1: the s-term's constrained key. Cleared first, so a keyword
        // nothing was ever indexed under does not show the previous search.
        *ais.evidence.last_search.borrow_mut() = None;
        let t1 = Instant::now();
        let cand = {
            let _s = perf::span(
                perf::Side::Client,
                "round 1: constrained key, decrypt candidates",
            );
            client
                .evidence
                .candidates(&ais.evidence, s_term.as_bytes())
                .map_err(e2s)?
        };
        let round1_ms = t1.elapsed().as_secs_f64() * 1e3;
        let round1 = ais.evidence.last_search.borrow().unwrap_or((0, 0, 0));

        // Round 2: one shuffled probe list; the formula never leaves here.
        let mut terms: Vec<Vec<u8>> = Vec::new();
        let mut ix: HashMap<Vec<u8>, usize> = HashMap::new();
        let formula = psi.as_ref().map_or_else(
            || Formula::And(Vec::new()),
            |e| e.compile(&mut terms, &mut ix),
        );
        let x_terms: Vec<&[u8]> = terms.iter().map(Vec::as_slice).collect();
        let t2 = Instant::now();
        let round2_span = perf::span(
            perf::Side::Client,
            "round 2: shuffled probes, evaluate formula",
        );
        let (transcript, map) = client.evidence.probe(&cand, &x_terms);
        let bits = ais.evidence.probe(&transcript);
        let result: BTreeSet<DocId> =
            client
                .evidence
                .evaluate(&cand, x_terms.len(), &map, &bits, &formula);
        drop(round2_span);
        let round2_ms = t2.elapsed().as_secs_f64() * 1e3;
        let pending = client.evidence.pending(&cand).len();
        let oracle_span = perf::span(perf::Side::Client, "plaintext oracle check (demo only)");

        // The plaintext oracle over the same documents, covered ones only
        // (a pending document is never evaluated, by design).
        let oracle: BTreeSet<DocId> = client
            .docs
            .iter()
            .filter(|d| client.evidence.is_covered(d.id))
            .filter(|d| d.keywords.contains(&s_term))
            .filter(|d| psi.as_ref().is_none_or(|e| e.holds(d)))
            .map(|d| d.id)
            .collect();
        drop(oracle_span);
        let labels: Vec<String> = result
            .iter()
            .filter_map(|id| client.docs.iter().find(|d| d.id == *id))
            .take(12)
            .map(|d| d.label.clone())
            .collect();
        let more = result.len().saturating_sub(labels.len());
        let ones = bits.iter().filter(|b| **b).count();
        let sample: Vec<String> = transcript.probes.iter().take(3).map(|t| short(t)).collect();
        let stark = client.stark.first().map_or_else(
            || "no warrant STARK recorded".to_owned(),
            |(_, v)| v.as_str().unwrap_or("").to_owned(),
        );

        Ok(json!({
            "refused": false,
            "results": result.len(),
            "oracle_equal": result == oracle,
            "live": "live: both rounds ran now against the server's encrypted index; the result is checked against a plaintext oracle in the same step",
            "client": [
                ["query", if psi_text.is_empty() { s_term.clone() } else { format!("{s_term} AND ({psi_text})") }],
                ["authorisation", format!("the module checked classes {q_lo}–{q_hi} against the signed evidence warrant (classes {w_lo}–{w_hi}, expiry epoch {}) now. The warrant's search was registered on chain with its STARK during the warm-up; a fresh proof per query is not made here (proving needs about 15 GB)", w.warrant.expiry)],
                ["warrant STARK", stark],
                ["round 1: candidates for the first term", format!("{} documents, decrypted and filtered here, {round1_ms:.1} ms", cand.len())],
                ["round 2: filter evaluated here", format!("{} x-terms (range covers expanded), {round2_ms:.1} ms", x_terms.len())],
                ["result", if labels.is_empty() { "(none)".to_owned() } else if more > 0 { format!("{}\n… and {more} more", labels.join("\n")) } else { labels.join("\n") }],
                ["equals the plaintext oracle", (result == oracle).to_string()],
                ["pending (open epoch, not evaluated)", pending.to_string()],
            ],
            "server": [
                ["round 1 received", format!("one constrained key ({} B) for count {}; returned {} encrypted payloads", round1.0, round1.1, round1.2)],
                ["round 2 received", if transcript.probes.is_empty() { "no probes: no candidate from an anchored epoch to test (open-epoch candidates are reported pending)".to_owned() } else { format!("{} probes, shuffled, e.g. {}", transcript.probes.len(), sample.join(", ")) }],
                ["round 2 answered", format!("{} bits, {ones} of them 1", bits.len())],
                ["what the server never saw", "the keywords, the formula, the ranges, which probe belongs to which candidate, or the result"],
            ],
        }))
    }

    /// Custody-plane search (`Π_CD`): records by event and/or actor, under
    /// the separate, default-deny custody warrant.
    #[allow(clippy::too_many_lines)]
    fn free_custody_search(&mut self, body: &Value) -> StepResult {
        let event = body["event"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        let actor = body["actor"].as_str().unwrap_or("").trim().to_owned();
        let (client, ais, _) = self.parts()?;
        let w = client.warrants.get(1).ok_or("no custody warrant")?.clone();

        let mut keywords: Vec<Vec<u8>> = Vec::new();
        let mut needed: Vec<&str> = Vec::new();
        let mut shown: Vec<String> = Vec::new();
        let ev = if event.is_empty() {
            None
        } else {
            let e = parse_event(&event)?;
            keywords.push(pqcl_pipeline::event_keyword(e));
            needed.push("evt:");
            shown.push(format!("evt:{event}"));
            Some(event.clone())
        };
        let who = if actor.is_empty() {
            None
        } else {
            let c = client
                .custodians
                .iter()
                .find(|c| c.actor_id == actor)
                .ok_or_else(|| format!("no custodian {actor}"))?;
            keywords.push(pqcl_pipeline::actor_keyword(
                c.actor_id.as_bytes(),
                c.agent.role(),
            ));
            needed.push("actor:");
            shown.push(format!("actor = {actor}"));
            Some(actor.clone())
        };
        if keywords.is_empty() {
            return Err("choose an event, an actor, or both".into());
        }
        let scope = scope_of(Plane::Custody, &needed)?;
        w.warrant
            .check_scope_and_expiry(&scope, client.epoch)
            .map_err(|e| format!("refused by the custody warrant: {e}"))?;

        let refs: Vec<&[u8]> = keywords.iter().map(Vec::as_slice).collect();
        let t = Instant::now();
        let ids = {
            let _s = perf::span(
                perf::Side::Client,
                "custody search (Π_CD), one round per keyword",
            );
            pqcl_dsse::cd_search(&client.custody, &ais.custody, &refs).map_err(e2s)?
        };
        let ms = t.elapsed().as_secs_f64() * 1e3;
        let found: BTreeSet<(usize, usize)> = ids
            .iter()
            .filter_map(|id| client.custody_docs.get(usize::try_from(*id).ok()?).copied())
            .collect();

        // The oracle: the same question asked of the decrypted bodies.
        let ev_ref = ev.as_deref();
        let who_ref = who.as_deref();
        let custodians = &client.custodians;
        let oracle: BTreeSet<(usize, usize)> = client
            .held
            .iter()
            .enumerate()
            .flat_map(|(ci, h)| {
                h.bodies.iter().enumerate().filter_map(move |(j, b)| {
                    let name = graph::event_name(b.event);
                    let ev_ok = ev_ref.is_none_or(|e| e == name);
                    let who_ok = who_ref.is_none_or(|a| custodians[h.signers[j]].actor_id == a);
                    (ev_ok && who_ok).then_some((ci, j))
                })
            })
            .collect();
        let rows: Vec<String> = found
            .iter()
            .take(15)
            .map(|(ci, j)| {
                let h = &client.held[*ci];
                format!(
                    "{} record #{j}: {} by {}",
                    h.file,
                    graph::event_name(h.bodies[*j].event),
                    client.custodians[h.signers[*j]].actor_id
                )
            })
            .collect();
        Ok(json!({
            "refused": false,
            "results": found.len(),
            "oracle_equal": found == oracle,
            "live": "live: Π_core searches ran now against the custody index; the intersection ran here",
            "client": [
                ["custody query (Π_CD)", shown.join(" ∧ ")],
                ["authorisation", format!("the custody warrant is a separate, default-deny grant (classes {}–{}); checked now", w.warrant.scope.bounds().0, w.warrant.scope.bounds().1)],
                ["matching records", if rows.is_empty() { "(none)".to_owned() } else { rows.join("\n") }],
                ["equals the plaintext oracle", (found == oracle).to_string()],
                ["time", format!("{ms:.1} ms")],
            ],
            "server": [
                ["requests", format!("{} single-keyword searches on the custody index, under a different key from the evidence index", refs.len())],
                ["what the server cannot do", "tell which event or custodian was asked for, or join the result to the evidence plane"],
            ],
        }))
    }

    // ------------------------------------------------------------ access

    /// An `ACCESS` record on capsule `ci`, signed by `who`: the investigator
    /// (or a DES) reads the evidence under warrant. Refused unless the
    /// library's role table lets `who` sign `ACCESS`.
    fn access_by(&mut self, ci: usize, who: usize) -> StepResult {
        let (client, ais, _) = self.parts()?;
        let c = client.custodians.get(who).ok_or("no such actor")?;
        refuse_role(c, Event::Access)?;
        let h = client.held.get(ci).ok_or("no such capsule")?;
        if client.pending.as_ref().is_some_and(|p| p.0 == ci) {
            return Err("this item is in transit: receive it before anyone reads it".into());
        }
        let prev = h.chain.last().ok_or("empty chain")?.clone();
        let signed = c
            .agent
            .append_record(
                &client.keys,
                &h.capsule,
                Event::Access,
                &prev,
                &pqcl_pipeline::RecordParams::at(h.chain.len() as u64, now())
                    .with_params(pqcl_capsule::Params::justified(
                        b"read under the evidence warrant",
                    ))
                    .in_epoch(client.epoch),
            )
            .map_err(e2s)?;
        let r = signed.record.clone();
        append_record(client, ais, ci, signed, who)?;
        Ok(json!({
            "live": "live: the ACCESS record was signed now",
            "client": [
                ["capsule", client.held[ci].file.clone()],
                ["record", format!("ACCESS by {} ({}); custody stays with {}", c_name(client, who), client.custodians[who].role, c_name(client, client.held[ci].holder))],
                ["h_prev = H(0x24 ‖ L_{j-1})", hex(&r.h_prev)],
            ],
            "server": [
                ["record received", format!("{} B under pseudonym {}…", r.encode().len(), short(&r.eid_e))],
                ["what it reveals", "that a record was appended; not that it was a read, nor who read"],
            ],
        }))
    }

    // ------------------------------------------------------------ the page

    /// What the three corners draw beyond the walkthrough's state.
    pub(super) fn corner_state(&self) -> Value {
        let (Some(client), Some(ais)) = (&self.client, &self.ais) else {
            return Value::Null;
        };
        let height = self.chain.as_ref().and_then(|c| c.block_number().ok());
        let pending_docs = client
            .docs
            .iter()
            .filter(|d| !client.evidence.is_covered(d.id))
            .count();
        let warrants: Vec<Value> = client
            .warrants
            .iter()
            .map(|w| {
                let stark = client
                    .stark
                    .iter()
                    .find(|(n, _)| *n == w.name)
                    .map_or(Value::Null, |(_, v)| v.clone());
                json!({"name": w.name, "scope": w.warrant.scope.bounds(),
                       "registered_scope": w.query.bounds(), "expiry": w.warrant.expiry,
                       "stark": stark})
            })
            .collect();
        json!({
            "ingest": {
                "bursts": client.bursts, "lines": client.synthetic_lines,
                "documents": client.docs.len(), "pending": pending_docs,
                "edb_entries": ais.evidence.received.len(),
                "xtags": ais.evidence.xtags.len(),
                "open_xt_epoch": client.evidence.epoch(),
                "last": client.last_burst,
            },
            "chain": {
                "height": height, "open_epoch": client.epoch,
                "anchored": client.epochs.len(),
                "in_transit": client.pending.as_ref().map(|p| p.0),
                "in_transit_to": client.pending.as_ref().map(|p| c_name(client, p.3)),
            },
            "custodians": client.custodians.iter().enumerate().map(|(i, c)| {
                let r = c.agent.role();
                json!({"i": i, "id": c.actor_id, "role": c.role,
                       "may": {"transfer": r.may(Event::Transfer), "analyze": r.may(Event::Analyze),
                               "access": r.may(Event::Access)}})
            }).collect::<Vec<_>>(),
            "storage": storage(client, ais),
            "vocab": vocabulary(client),
            "warrants": warrants,
            "classes": [
                ["src kind dir ext state", "1–5", true],
                ["log host user act status", "6–9", true],
                ["bytes ts dur (ranges)", "10–12", true],
                ["ip net", "20–21", false],
                ["proto", "22", false],
            ],
        })
    }
}

/// One source's share of the query vocabulary.
#[derive(Default)]
struct Source {
    docs: usize,
    /// field → value → documents carrying `field:value`.
    fields: BTreeMap<String, HashMap<String, usize>>,
    /// Range attribute → (lowest, highest) indexed value.
    ranges: BTreeMap<&'static str, (u64, u64)>,
}

/// The Query reference page: every field and value the evidence index can be
/// asked about, and every event and person on the custody plane, derived from
/// what the client holds now (its documents, its opened records) so the page
/// cannot drift from the data. Each field's values are capped for display;
/// `distinct` says how many there are.
fn vocabulary(client: &super::Client) -> Value {
    const SHOW: usize = 40;
    const NAMES: [&str; 4] = ["Synthetic logs", "Disk image", "Network capture", "Other"];
    let in_scope = |idx: usize, field: &str| {
        client.warrants.get(idx).is_some_and(|w| {
            let (lo, hi) = w.warrant.scope.bounds();
            (lo..=hi).contains(&class_of(field))
        })
    };

    let mut src: [Source; 4] = Default::default();
    for d in &client.docs {
        let has = |p: &str| d.keywords.iter().any(|k| k.starts_with(p));
        let i = if has("src:disk-image") {
            1
        } else if has("src:pcap") {
            2
        } else if has("log:") {
            0
        } else {
            3
        };
        let s = &mut src[i];
        s.docs += 1;
        for k in &d.keywords {
            if let Some((f, v)) = k.split_once(':') {
                *s.fields
                    .entry(f.to_owned())
                    .or_default()
                    .entry(v.to_owned())
                    .or_default() += 1;
            }
        }
        for (a, v) in &d.numbers {
            let e = s.ranges.entry(a.name()).or_insert((*v, *v));
            e.0 = e.0.min(*v);
            e.1 = e.1.max(*v);
        }
    }
    let sources: Vec<Value> = NAMES
        .iter()
        .zip(&src)
        .filter(|(_, s)| s.docs > 0)
        .map(|(name, s)| {
            let fields: Vec<Value> = s
                .fields
                .iter()
                .map(|(f, vals)| {
                    let mut v: Vec<(&String, &usize)> = vals.iter().collect();
                    v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                    let shown: Vec<Value> =
                        v.iter().take(SHOW).map(|(k, n)| json!([k, n])).collect();
                    json!({"field": f, "class": class_of(f), "allowed": in_scope(0, f),
                           "distinct": v.len(), "values": shown})
                })
                .collect();
            let ranges: Vec<Value> = s
                .ranges
                .iter()
                .map(|(a, (lo, hi))| {
                    json!({"attr": a, "class": class_of(a), "allowed": in_scope(0, a),
                           "min": lo, "max": hi})
                })
                .collect();
            json!({"name": name, "docs": s.docs, "fields": fields, "ranges": ranges})
        })
        .collect();
    let (events, people) = custody_vocabulary(client);
    json!({
        "evidence_scope": client.warrants.first().map(|w| w.warrant.scope.bounds()),
        "custody_scope": client.warrants.get(1).map(|w| w.warrant.scope.bounds()),
        "custody_allowed": {"evt": in_scope(1, "evt"), "actor": in_scope(1, "actor")},
        "sources": sources,
        "events": events,
        "people": people,
    })
}

/// The custody plane's vocabulary: every event a record can carry, with how
/// many the opened bodies hold, and every enrolled person with the records
/// they signed.
fn custody_vocabulary(client: &super::Client) -> (Vec<Value>, Vec<Value>) {
    let all = [
        Event::Collect,
        Event::Transfer,
        Event::Access,
        Event::Analyze,
        Event::Export,
        Event::Seal,
        Event::Dispose,
    ];
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut signed = vec![0usize; client.custodians.len()];
    for h in &client.held {
        for b in &h.bodies {
            *counts.entry(graph::event_name(b.event)).or_default() += 1;
        }
        for &s in &h.signers {
            if let Some(n) = signed.get_mut(s) {
                *n += 1;
            }
        }
    }
    let events: Vec<Value> = all
        .iter()
        .map(|e| {
            let n = graph::event_name(*e);
            json!([n, counts.get(n).copied().unwrap_or(0)])
        })
        .collect();
    let people: Vec<Value> = client
        .custodians
        .iter()
        .zip(&signed)
        .map(|(c, n)| json!({"id": c.actor_id, "role": c.role, "records": n}))
        .collect();
    (events, people)
}

/// Bytes each side holds now, by what they are. Counted from the structures
/// themselves (encoded lengths), not estimated. The ciphertext files are on
/// disk and measured by the Performance page's sampler.
fn storage(client: &super::Client, ais: &super::Ais) -> Value {
    let records: usize = ais
        .chains
        .iter()
        .flat_map(|c| c.1.iter())
        .map(Vec::len)
        .sum();
    let capsules: usize = ais.capsules.iter().map(Vec::len).sum();
    let edb_ev: usize = ais.evidence.received.iter().map(|(a, v)| a.len() + v).sum();
    let edb_coc: usize = ais.custody.received.iter().map(|(a, v)| a.len() + v).sum();
    let xtags = ais.evidence.xtags.len() * 32;
    let leaves = ais.leaves.len() * 32;
    let bodies: usize = client
        .held
        .iter()
        .flat_map(|h| h.bodies.iter())
        .map(|b| b.encode().len())
        .sum();
    let mirrored: usize = client
        .held
        .iter()
        .flat_map(|h| h.chain.iter())
        .map(|r| r.encode().len())
        .sum();
    let openings: usize = client
        .held
        .iter()
        .map(|h| {
            h.actors
                .iter()
                .map(|a| a.id.len() + 1 + a.r_a.len())
                .sum::<usize>()
                + h.wrap.0.len()
                + h.wrap.1.len()
                + h.chunks.len() * 32
        })
        .sum();
    let plaintext: usize = client
        .docs
        .iter()
        .map(|d| d.label.len() + d.keywords.iter().map(String::len).sum::<usize>())
        .sum();
    json!({
        "store": [
            ["custody records (encrypted)", records],
            ["capsules", capsules],
            ["evidence index (EDB)", edb_ev],
            ["cross-tags", xtags],
            ["custody index", edb_coc],
            ["Tier-2 leaves", leaves],
        ],
        "client": [
            ["opened record bodies", bodies],
            ["record copies (to verify)", mirrored],
            ["openings, key wraps, chunk digests", openings],
            ["plaintext lines (search oracle, demo only)", plaintext],
        ],
    })
}

/// An optional actor index in the request body.
fn actor_arg(body: &Value, key: &str) -> Result<Option<usize>, String> {
    match &body[key] {
        Value::Null => Ok(None),
        Value::String(s) if s.is_empty() => Ok(None),
        v => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .and_then(|c| usize::try_from(c).ok())
            .map(Some)
            .ok_or_else(|| format!("{key} must be an actor number")),
    }
}

/// A fixed name per corner action, for the profiler's tree.
fn action_name(action: &str) -> &'static str {
    match action {
        "ingest" => "ingest a burst",
        "release" => "release (TRANSFER, first half)",
        "receive" => "receive (TRANSFER, second half)",
        "analyze" => "analyse the disk image",
        "access" => "record an ACCESS",
        "anchor" => "close the epoch and anchor",
        "verify" => "verify a history from public data",
        "tamper" => "tamper and detect",
        "search" => "evidence search (two rounds)",
        "custody-search" => "custody search",
        _ => "unknown action",
    }
}

fn capsule_arg(body: &Value) -> Result<usize, String> {
    body["capsule"]
        .as_u64()
        .and_then(|c| usize::try_from(c).ok())
        .ok_or_else(|| "choose a capsule".to_owned())
}

fn parse_event(name: &str) -> Result<Event, String> {
    Ok(match name {
        "COLLECT" => Event::Collect,
        "TRANSFER" => Event::Transfer,
        "ACCESS" => Event::Access,
        "ANALYZE" => Event::Analyze,
        "EXPORT" => Event::Export,
        "SEAL" => Event::Seal,
        "DISPOSE" => Event::Dispose,
        other => return Err(format!("unknown event {other}")),
    })
}

// ---------------------------------------------------------------- the filter

/// A parsed filter `ψ`, with every range already resolved to its attribute's
/// domain, so the client's formula and the plaintext oracle read the same
/// bounds.
#[derive(Debug, Clone)]
enum Expr {
    /// A plain keyword, `field:value`.
    Kw(String),
    /// A range over one attribute, inclusive, in the attribute's own units.
    Range(Attribute, u64, u64),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

impl Expr {
    /// The formula over x-terms, interning each keyword once. A range becomes
    /// the disjunction of its canonical cover (`Π_RANGE`).
    fn compile(&self, terms: &mut Vec<Vec<u8>>, ix: &mut HashMap<Vec<u8>, usize>) -> Formula {
        match self {
            Self::Kw(k) => Formula::Term(intern(k.as_bytes().to_vec(), terms, ix)),
            Self::Range(attr, lo, hi) => Formula::Or(
                RangeTree::profile(*attr)
                    .cover_keywords(*lo, *hi)
                    .into_iter()
                    .map(|w| Formula::Term(intern(w, terms, ix)))
                    .collect(),
            ),
            Self::Not(e) => Formula::Not(Box::new(e.compile(terms, ix))),
            Self::And(v) => Formula::And(v.iter().map(|e| e.compile(terms, ix)).collect()),
            Self::Or(v) => Formula::Or(v.iter().map(|e| e.compile(terms, ix)).collect()),
        }
    }

    /// The same formula over a document's plaintext: the oracle.
    fn holds(&self, d: &Document) -> bool {
        match self {
            Self::Kw(k) => d.keywords.iter().any(|x| x == k),
            Self::Range(attr, lo, hi) => d
                .numbers
                .iter()
                .any(|(a, v)| a == attr && (*lo..=*hi).contains(v)),
            Self::Not(e) => !e.holds(d),
            Self::And(v) => v.iter().all(|e| e.holds(d)),
            Self::Or(v) => v.iter().any(|e| e.holds(d)),
        }
    }

    /// One `field:` keyword per term, for the scope check.
    fn class_keywords(&self, out: &mut Vec<String>) {
        match self {
            Self::Kw(k) => out.push(k.clone()),
            Self::Range(attr, _, _) => out.push(format!("{}:", attr.name())),
            Self::Not(e) => e.class_keywords(out),
            Self::And(v) | Self::Or(v) => v.iter().for_each(|e| e.class_keywords(out)),
        }
    }
}

/// The x-term index of `w`, adding it the first time it is seen.
fn intern(w: Vec<u8>, terms: &mut Vec<Vec<u8>>, ix: &mut HashMap<Vec<u8>, usize>) -> usize {
    if let Some(&i) = ix.get(&w) {
        return i;
    }
    terms.push(w.clone());
    ix.insert(w, terms.len() - 1);
    terms.len() - 1
}

/// Parse `ψ`: keywords `field:value`, ranges `bytes:LO..HI`, `dur:LO..HI`
/// and `ts:last:Nh`, combined with `AND`, `OR`, `NOT` and parentheses.
/// Adjacent terms are joined by `AND`. An empty filter is `None`.
fn parse_filter(text: &str, now_unix: u64) -> Result<Option<Expr>, String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch == '(' || ch == ')' || ch.is_whitespace() {
            if !cur.is_empty() {
                toks.push(core::mem::take(&mut cur));
            }
            if ch == '(' || ch == ')' {
                toks.push(ch.to_string());
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        toks.push(cur);
    }
    if toks.is_empty() {
        return Ok(None);
    }
    let mut p = Parser {
        toks,
        at: 0,
        now: now_unix,
    };
    let e = p.or()?;
    if p.at < p.toks.len() {
        return Err(format!("unexpected '{}'", p.toks[p.at]));
    }
    Ok(Some(e))
}

struct Parser {
    toks: Vec<String>,
    at: usize,
    now: u64,
}

impl Parser {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.at).map(String::as_str)
    }

    fn eat(&mut self, word: &str) -> bool {
        if self.peek().is_some_and(|t| t.eq_ignore_ascii_case(word)) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut v = vec![self.and()?];
        while self.eat("OR") {
            v.push(self.and()?);
        }
        Ok(if v.len() == 1 {
            v.remove(0)
        } else {
            Expr::Or(v)
        })
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut v = vec![self.unary()?];
        // An explicit AND, or a juxtaposed term (implicit AND).
        while self.eat("AND")
            || self
                .peek()
                .is_some_and(|t| t != ")" && !t.eq_ignore_ascii_case("OR"))
        {
            v.push(self.unary()?);
        }
        Ok(if v.len() == 1 {
            v.remove(0)
        } else {
            Expr::And(v)
        })
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat("NOT") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if self.eat("(") {
            let e = self.or()?;
            if !self.eat(")") {
                return Err("missing ')'".into());
            }
            return Ok(e);
        }
        let tok = self.peek().ok_or("the filter ends too early")?.to_owned();
        self.at += 1;
        self.atom(&tok)
    }

    fn atom(&self, tok: &str) -> Result<Expr, String> {
        if let Some(hours) = tok.strip_prefix("ts:last:") {
            let n: u64 = hours
                .trim_end_matches('h')
                .parse()
                .map_err(|_| format!("{tok}: write ts:last:24h"))?;
            let lo = docs::ts_value(self.now.saturating_sub(n.saturating_mul(3600)))
                .ok_or("that time is outside the ts attribute's window")?;
            let hi = docs::ts_value(self.now).ok_or("now is outside the ts attribute's window")?;
            return Ok(Expr::Range(Attribute::Timestamp, lo, hi));
        }
        if let Some((field, range)) = tok.split_once(':')
            && let Some((lo, hi)) = range.split_once("..")
        {
            let attr = match field {
                "bytes" => Attribute::Bytes,
                "dur" => Attribute::Duration,
                _ => {
                    return Err(format!(
                        "{tok}: ranges are bytes:LO..HI, dur:LO..HI or ts:last:Nh"
                    ));
                }
            };
            let num = |s: &str| {
                s.replace('_', "")
                    .parse::<u64>()
                    .map_err(|_| format!("{tok}: not a number"))
            };
            let (lo, hi) = (num(lo)?, num(hi)?);
            if lo > hi {
                return Err(format!("{tok}: the low end is above the high end"));
            }
            return Ok(Expr::Range(attr, lo, hi));
        }
        if tok.contains(':') && !tok.starts_with(':') && !tok.ends_with(':') {
            return Ok(Expr::Kw(tok.to_owned()));
        }
        Err(format!(
            "'{tok}': keywords are field:value, e.g. user:mallory"
        ))
    }
}

// ---------------------------------------------------------------- the generator

/// Which kinds of log line a burst carries.
#[derive(Debug, Clone, Copy)]
enum LogMix {
    Mixed,
    Auth,
    Web,
    Firewall,
    System,
}

impl LogMix {
    fn parse(s: &str) -> Result<Self, String> {
        Ok(match s {
            "mixed" => Self::Mixed,
            "auth" => Self::Auth,
            "web" => Self::Web,
            "fw" => Self::Firewall,
            "sys" => Self::System,
            other => return Err(format!("unknown log mix {other}")),
        })
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Mixed => "mixed",
            Self::Auth => "auth",
            Self::Web => "web",
            Self::Firewall => "firewall",
            Self::System => "system",
        }
    }
}

/// One generated line: its text and the keywords and numbers Phase 3 Step 1
/// extracts from it.
struct Line {
    text: String,
    keywords: Vec<String>,
    numbers: Vec<(Attribute, u64)>,
}

/// `SplitMix64`: a tiny seeded generator, so a burst is reproducible from
/// its number. It chooses log content only and never touches key material,
/// which comes from `pqcl_primitives::rng`.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }

    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        let i = usize::try_from(self.below(xs.len() as u64)).unwrap_or(0);
        xs.get(i).copied().unwrap_or("")
    }

    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }
}

const HOSTS: &[&str] = &["web-01", "web-02", "db-01", "ws-07", "ws-12"];
const USERS: &[&str] = &["alice", "bob", "carol", "dave", "root", "svc-backup"];
const PATHS: &[&str] = &[
    "/",
    "/login",
    "/api/orders",
    "/admin",
    "/static/app.js",
    "/reports/q3.pdf",
];
/// The person of interest the generated story follows.
const SUSPECT: &str = "mallory";
/// A documentation-range address (RFC 5737), never a real host.
const SUSPECT_IP: &str = "203.0.113.66";

fn internal_ip(r: &mut Seeded) -> String {
    format!("10.0.{}.{}", 1 + r.below(3), 2 + r.below(60))
}

fn external_ip(r: &mut Seeded) -> String {
    format!("198.51.100.{}", 1 + r.below(250))
}

fn net_of(ip: &str) -> String {
    ip.rsplit_once('.')
        .map_or_else(String::new, |(n, _)| format!("net:{n}.0/24"))
}

/// Generate `n` lines for burst `burst`, timestamped within the day before
/// `now_unix`. Deterministic in `burst` apart from those timestamps.
fn generate(n: u64, mix: LogMix, burst: u64, now_unix: u64) -> Vec<Line> {
    let mut r = Seeded(burst.wrapping_mul(0xD1B5_4A32_D192_ED03));
    (0..n)
        .map(|_| {
            let kind = match mix {
                LogMix::Mixed => match r.below(10) {
                    0..=3 => LogMix::Auth,
                    4..=6 => LogMix::Web,
                    7..=8 => LogMix::Firewall,
                    _ => LogMix::System,
                },
                other => other,
            };
            let ts = now_unix.saturating_sub(r.below(24 * 3600));
            let mut l = match kind {
                LogMix::Auth | LogMix::Mixed => auth_line(&mut r),
                LogMix::Web => web_line(&mut r),
                LogMix::Firewall => fw_line(&mut r),
                LogMix::System => sys_line(&mut r),
            };
            l.text = format!("{} {}", iso8601(ts), l.text);
            if let Some(v) = docs::ts_value(ts) {
                l.numbers.push((Attribute::Timestamp, v));
            }
            l.keywords.sort();
            l.keywords.dedup();
            l
        })
        .collect()
}

fn auth_line(r: &mut Seeded) -> Line {
    let host = r.pick(HOSTS);
    let (user, ip, act) = if r.chance(6) {
        // The story: repeated failures from one outside address, now and then
        // a success.
        (
            SUSPECT.to_owned(),
            SUSPECT_IP.to_owned(),
            if r.chance(8) {
                "login-ok"
            } else {
                "login-fail"
            },
        )
    } else {
        let act = r.pick(&[
            "login-ok",
            "login-ok",
            "login-ok",
            "login-fail",
            "sudo",
            "logout",
        ]);
        (r.pick(USERS).to_owned(), internal_ip(r), act)
    };
    let msg = match act {
        "login-ok" => format!("Accepted password for {user} from {ip}"),
        "login-fail" => format!("Failed password for {user} from {ip}"),
        "sudo" => format!("{user} : TTY=pts/0 ; COMMAND=/usr/bin/systemctl restart nginx"),
        _ => format!("session closed for user {user}"),
    };
    Line {
        text: format!("{host} sshd: {msg}"),
        keywords: vec![
            "log:auth".to_owned(),
            format!("host:{host}"),
            format!("user:{user}"),
            format!("act:{act}"),
            format!("ip:{ip}"),
            net_of(&ip),
        ],
        numbers: Vec::new(),
    }
}

fn web_line(r: &mut Seeded) -> Line {
    let host = r.pick(&["web-01", "web-02"]);
    let (user, ip, method, path, status, bytes) = if r.chance(10) {
        // The story continues: large exports by the same account.
        (
            SUSPECT.to_owned(),
            SUSPECT_IP.to_owned(),
            "GET",
            "/api/export?all=1",
            200,
            1_200_000 + r.below(800_000),
        )
    } else {
        let status =
            [200u64, 200, 200, 302, 403, 404, 500][usize::try_from(r.below(7)).unwrap_or(0)];
        let user = if r.chance(3) {
            "-".to_owned()
        } else {
            r.pick(USERS).to_owned()
        };
        (
            user,
            if r.chance(4) {
                external_ip(r)
            } else {
                internal_ip(r)
            },
            r.pick(&["GET", "GET", "POST"]),
            r.pick(PATHS),
            status,
            200 + r.below(400_000),
        )
    };
    let mut keywords = vec![
        "log:web".to_owned(),
        format!("host:{host}"),
        format!("act:{}", method.to_ascii_lowercase()),
        format!("status:{status}"),
        format!("ip:{ip}"),
        net_of(&ip),
    ];
    if user != "-" {
        keywords.push(format!("user:{user}"));
    }
    Line {
        text: format!("{host} nginx: {ip} {user} \"{method} {path}\" {status} {bytes}"),
        keywords,
        numbers: vec![(Attribute::Bytes, bytes)],
    }
}

fn fw_line(r: &mut Seeded) -> Line {
    let (src, act) = if r.chance(5) {
        (
            SUSPECT_IP.to_owned(),
            if r.chance(3) { "allow" } else { "deny" },
        )
    } else {
        (
            if r.chance(2) {
                external_ip(r)
            } else {
                internal_ip(r)
            },
            r.pick(&["allow", "allow", "deny"]),
        )
    };
    let dst = internal_ip(r);
    let port = r.pick(&["22", "443", "3306", "8080"]);
    let dur = if act == "deny" { 0 } else { r.below(3_600) };
    Line {
        text: format!(
            "fw-01 kernel: {} TCP {src} -> {dst}:{port} {dur}s",
            act.to_ascii_uppercase()
        ),
        keywords: vec![
            "log:fw".to_owned(),
            "host:fw-01".to_owned(),
            format!("act:{act}"),
            format!("ip:{src}"),
            format!("ip:{dst}"),
            net_of(&src),
            net_of(&dst),
        ],
        numbers: vec![(Attribute::Duration, dur)],
    }
}

fn sys_line(r: &mut Seeded) -> Line {
    let host = r.pick(HOSTS);
    let user = r.pick(USERS);
    let act = r.pick(&["usb-insert", "service-restart", "cron", "kernel-warn"]);
    let msg = match act {
        "usb-insert" => format!("usb 1-1: new mass-storage device, session of {user}"),
        "service-restart" => "systemd: nginx.service restarted".to_owned(),
        "cron" => format!("CRON[{}]: ({user}) CMD (backup.sh)", 1000 + r.below(9000)),
        _ => "kernel: EXT4-fs warning: mounting fs with errors".to_owned(),
    };
    Line {
        text: format!("{host} {msg}"),
        keywords: vec![
            "log:sys".to_owned(),
            format!("host:{host}"),
            format!("user:{user}"),
            format!("act:{act}"),
        ],
        numbers: Vec::new(),
    }
}

/// `YYYY-MM-DDThh:mm:ssZ` for a Unix time (days-from-civil, inverted).
fn iso8601(unix: u64) -> String {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    // Howard Hinnant's civil_from_days, on the unsigned range we need.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let doe = shifted - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_matches_known_instants() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_795_000_000), "2026-11-18T11:06:40Z");
    }

    #[test]
    fn a_burst_is_reproducible_from_its_number() {
        let a = generate(50, LogMix::Mixed, 3, 1_795_000_000);
        let b = generate(50, LogMix::Mixed, 3, 1_795_000_000);
        assert_eq!(
            a.iter().map(|l| &l.text).collect::<Vec<_>>(),
            b.iter().map(|l| &l.text).collect::<Vec<_>>()
        );
        assert!(
            a.iter()
                .all(|l| l.keywords.iter().any(|k| k.starts_with("log:")))
        );
    }

    #[test]
    fn the_filter_parses_precedence_and_ranges() {
        let e = parse_filter(
            "act:login-fail OR act:sudo AND NOT user:root",
            1_795_000_000,
        )
        .unwrap()
        .unwrap();
        // OR binds looser than AND.
        assert!(matches!(&e, Expr::Or(v) if v.len() == 2 && matches!(v[1], Expr::And(_))));
        let r = parse_filter("bytes:1_000_000..1_999_999", 0)
            .unwrap()
            .unwrap();
        assert!(matches!(
            r,
            Expr::Range(Attribute::Bytes, 1_000_000, 1_999_999)
        ));
        assert!(parse_filter("(user:alice", 0).is_err());
        assert!(parse_filter("alice", 0).is_err());
        assert!(parse_filter("", 0).unwrap().is_none());
    }

    #[test]
    fn the_formula_and_the_oracle_agree_on_a_document() {
        let d = Document {
            id: 0,
            capsule: 0,
            label: String::new(),
            keywords: vec!["user:mallory".into(), "act:login-fail".into()],
            numbers: vec![(Attribute::Bytes, 1_500_000)],
        };
        let e = parse_filter(
            "user:mallory AND bytes:1_000_000..1_999_999 AND NOT act:sudo",
            0,
        )
        .unwrap()
        .unwrap();
        assert!(e.holds(&d));
        let mut terms = Vec::new();
        let mut ix = HashMap::new();
        let _ = e.compile(&mut terms, &mut ix);
        // Every term in the compiled formula is a keyword the index can hold.
        assert!(terms.iter().any(|t| t == b"user:mallory"));
        assert!(terms.iter().any(|t| t.starts_with(b"bytes:")));
    }

    #[test]
    fn the_new_log_classes_sit_inside_the_evidence_warrant_and_network_does_not() {
        for k in [
            "log:auth",
            "host:web-01",
            "user:alice",
            "act:get",
            "status:403",
        ] {
            assert!((6..=9).contains(&class_of(k)), "{k}");
        }
        assert_eq!(class_of("ip:10.0.1.2"), 20);
        // The classes the saved AWS proofs commit to did not move.
        assert_eq!(class_of("ext:jpg"), 4);
        assert_eq!(class_of("state:deleted"), 5);
        assert_eq!(class_of("bytes:0:0"), 10);
        assert_eq!(class_of("evt:x"), 1);
        assert_eq!(class_of("actor:x"), 2);
    }
}
