//! D4–D6: warranted search (Phases 8–9), audit and tamper (Phase 10),
//! court-ordered redaction (Phase 11).

use std::collections::{BTreeSet, HashMap};
use std::process::Command;

use pqcl_capsule::disclosure::SealProof;
use pqcl_capsule::redaction::{Mode, Order, Scope as RedactionScope, Target};
use pqcl_capsule::{ActorOpening, Bundle, Event, Params, Role, Segment};
use pqcl_dsse::core::DocId;
use pqcl_dsse::range::{Attribute, RangeTree};
use pqcl_dsse::xt::{Formula, XSetStore};
use pqcl_forest::Leaf;
use pqcl_pipeline::redaction::{self, ClaimedOrder, Openings, Redactee, Unaccounted};
use pqcl_pipeline::{RecordParams, chunked, record_signed_bytes};
use pqcl_primitives::xof::{Digest32, Domain, PrfKey, digest256, hash_domain};
use pqcl_primitives::{RecordKey, Signer, rng, sig};
use pqcl_sm::Plane;
use pqcl_warrant::relation::scope_digest;
use pqcl_warrant::{Nullifier, Scope, Warrant, WarrantTree};
use serde_json::{Value, json};

use pqcl_pipeline::checkpoint::{self, ApprovalSet};
use pqcl_pipeline::retrieval;

use super::{Client, Demo, LAB, StepResult, e2s, now, short};
use crate::graph::hex;

/// A warrant as issued: the warrant, its CA signature, the investigator's
/// secret `s`, its position in the warrant tree, and the query scope it gates.
#[derive(Debug, Clone)]
pub(super) struct Issued {
    /// `evidence` or `custody`.
    pub(super) name: String,
    /// The warrant tuple.
    pub(super) warrant: Warrant,
    /// `σ_CA` over it.
    pub(super) sig: Vec<u8>,
    /// `s`, known only to the investigator.
    pub(super) secret: Digest32,
    /// Its leaf index in the warrant tree.
    pub(super) index: usize,
    /// The scope of the query it will be used for.
    pub(super) query: Scope,
}

/// Keyword classes: a warrant's scope is a range over these (`pqcl-warrant`).
/// Evidence: file-system fields 1–5, log fields 6–9, numeric 10–12, network
/// 20–22. Custody: event 1, actor 2, pseudonym 3, time 11.
///
/// ⚠️ Classes 6–9 were added for the ingestion corner's synthetic logs
/// No existing prefix moved: the saved AWS
/// proofs commit to the scope digests of `ext`/`bytes`/`state` (4–10) and
/// `evt`/`actor` (1–2), and those must not change.
pub(super) fn class_of(keyword: &str) -> u64 {
    match keyword.split(':').next().unwrap_or("") {
        "src" | "evt" => 1,
        "kind" | "actor" => 2,
        "dir" | "eid_e" => 3,
        "ext" => 4,
        "state" => 5,
        "log" => 6,
        "host" => 7,
        "user" => 8,
        "act" | "status" => 9,
        "bytes" => 10,
        "ts" => 11,
        "dur" => 12,
        "ip" => 20,
        "net" => 21,
        _ => 22,
    }
}

pub(super) fn scope_of(plane: Plane, keywords: &[&str]) -> Result<Scope, String> {
    let lo = keywords.iter().map(|k| class_of(k)).min().unwrap_or(0);
    let hi = keywords.iter().map(|k| class_of(k)).max().unwrap_or(0);
    Scope::new(plane, lo, hi).map_err(e2s)
}

/// The evidence query: `ext:jpg ∧ (1 MB ≤ size < 2 MB) ∧ ¬state:deleted`.
const SIZE_LO: u64 = 1_000_000;
const SIZE_HI: u64 = 1_999_999;

fn proof_dir(d: &Demo) -> std::path::PathBuf {
    d.cfg.repo.join("zk/demo-proof")
}

impl Demo {
    // ------------------------------------------------------------ D4: Phase 8

    // One phase, narrated as one panel: splitting it would scatter the story.
    #[allow(clippy::too_many_lines)]
    pub(super) fn warrant(&mut self) -> StepResult {
        let dir = proof_dir(self);
        let live = self.cfg.live_stark;
        let (client, _, chain) = self.parts()?;
        let epoch = client.epoch;
        let cid = client.keys.cid_c;

        // Phase 8 Step 1: the court issues both warrants (the custody grant
        // is separate and default-deny), from the AWS bundle if one exists,
        // since its proofs commit to these exact warrants.
        let ev_query = scope_of(Plane::Evidence, &["ext:jpg", "bytes:0:0", "state:deleted"])?;
        let coc_query = scope_of(Plane::Custody, &["evt:TRANSFER", "actor:x"])?;
        let mut tree = WarrantTree::new();
        let mut issued = Vec::new();
        let specs = [
            ("evidence", Plane::Evidence, (1, 12), ev_query),
            ("custody", Plane::Custody, (1, 11), coc_query),
        ];
        let bundle = client.bundle.clone();
        for (i, (name, plane, (lo, hi), query)) in specs.into_iter().enumerate() {
            let from = bundle.as_ref().and_then(|b| {
                b["warrants"]
                    .as_array()?
                    .iter()
                    .find(|w| w["name"] == name)
                    .cloned()
            });
            let (other, warrant, secret) = match (&bundle, &from) {
                (Some(b), Some(w)) => (
                    unhex(b["others"][i]["commitment"].as_str().unwrap_or(""))?,
                    Warrant {
                        inv_id: unhex(w["inv_id"].as_str().unwrap_or(""))?,
                        cid_c: cid,
                        role: u8::try_from(w["role"].as_u64().unwrap_or(0)).map_err(e2s)?,
                        scope: Scope::new(plane, lo, hi).map_err(e2s)?,
                        window: (
                            w["window"][0].as_u64().unwrap_or(0),
                            w["window"][1].as_u64().unwrap_or(0),
                        ),
                        expiry: w["expiry"].as_u64().unwrap_or(0),
                        nonce: unhex(w["nonce"].as_str().unwrap_or(""))?,
                    },
                    unhex(w["secret"].as_str().unwrap_or(""))?,
                ),
                _ => (
                    rng::secret().map_err(e2s)?,
                    Warrant {
                        // Through the library's own opening type (M13 A2), so
                        // the warrant's identity commitment and a record's
                        // `actor_c` cannot drift apart.
                        inv_id: ActorOpening {
                            id: b"investigator-1".to_vec(),
                            role: Role::Investigator,
                            r_a: rng::secret().map_err(e2s)?,
                        }
                        .commit(),
                        cid_c: cid,
                        role: 4,
                        scope: Scope::new(plane, lo, hi).map_err(e2s)?,
                        window: (0, 1_000),
                        expiry: 1_000,
                        nonce: rng::secret().map_err(e2s)?,
                    },
                    rng::secret().map_err(e2s)?,
                ),
            };
            tree.insert(other);
            let sig = warrant.sign(&client.ca_sig).map_err(e2s)?;
            warrant
                .verify(client.ca_sig.public_key(), &sig)
                .map_err(e2s)?;
            let index = tree.insert(pqcl_warrant::tree::leaf(&warrant.encode(), &secret));
            issued.push(Issued {
                name: name.to_owned(),
                warrant,
                sig,
                secret,
                index,
                query,
            });
        }
        let rho = tree.root().ok_or("empty warrant tree")?;
        if let Some(b) = &bundle
            && b["warrant_root"].as_str() != Some(hex(&rho).as_str())
        {
            return Err("the rebuilt warrant tree does not match the proof bundle's root".into());
        }

        // Phase 8 Step 2: ρ_W anchored on chain, through the same registry and
        // checkpoint rule as an epoch root (D4): its own namespace, registered
        // under the case's reg, one checkpoint, approved 2-of-3.
        let ns = warrant_namespace(&cid);
        let reg = client.reg.digest();
        chain.register_case(&ns, &reg).map_err(e2s)?;
        let leaves = tree.len() as u64;
        let d_w = checkpoint::checkpoint(&ns, 0, &rho, leaves, &reg);
        // ⭐ Each approving custodian validates first (M13 A5). The warrant
        // tree is `pqcl-warrant`'s, so the custodian's own recomputation is the
        // tree it just rebuilt from the issued warrants (`rho`, checked against
        // the proof bundle above) — not a value taken from the proposer.
        let approvals = [0u32, 1]
            .iter()
            .map(|&j| {
                let v = checkpoint::ChainView::new(ns, reg)
                    .validate(&checkpoint::Proposal {
                        cid: ns,
                        e: 0,
                        root: rho,
                        n_e: leaves,
                        d_prev: reg,
                        d_e: d_w,
                        over: checkpoint::Committed::Own {
                            root: tree.root().ok_or("empty warrant tree")?,
                            count: tree.len() as u64,
                        },
                    })
                    .map_err(e2s)?;
                checkpoint::approve(&client.committee[j as usize], j, &v).map_err(e2s)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let set = ApprovalSet::new(approvals, &client.cosigner, &d_w).map_err(e2s)?;
        let anchor_rx = chain
            .commit_root(&ns, &rho, &reg, &d_w, &set.digest())
            .map_err(e2s)?;
        client.warrant_anchor = Some((d_w, set.digest()));

        // An out-of-scope query cannot even be formed: the network classes
        // are outside the evidence warrant.
        let wide = scope_of(Plane::Evidence, &["ext:jpg", "ip:192.168.123.101"])?;
        let refused = issued[0]
            .warrant
            .check_scope_and_expiry(&wide, epoch)
            .err()
            .map(|e| e.to_string());

        // Register each search: N = H(0x31 ‖ ⟪s, e⟫) and the scope commitment.
        let mut regs = Vec::new();
        for w in &issued {
            let n = Nullifier::new(&w.secret, epoch);
            let sc = scope_digest(&w.query);
            let rx = chain.authorise_search(&n.0, &sc).map_err(e2s)?;
            regs.push((w.name.clone(), n, sc, rx));
        }
        // Spending the same N twice is refused by consensus.
        let replay = chain
            .authorise_search(&regs[0].1.0, &regs[0].2)
            .err()
            .map(|e| revert_name(&e.to_string(), "NullifierAlreadySpent(bytes32)"));

        // The AIS verifies π_auth and binds it to what the chain published.
        // Live only when asked (7.1 GB); otherwise the stored AWS result, with
        // its statement checked now against what the chain registered.
        let on_chain_rho = chain.latest_epoch(&ns).map_err(e2s)?.root;
        let mut proofs = Vec::new();
        for (name, n, sc, _) in &regs {
            proofs.push(if live {
                verify_proof(&dir, name, n, sc, &on_chain_rho, epoch, bundle.is_some())
            } else {
                stored_proof(&dir, name, n, sc, &on_chain_rho, epoch, bundle.as_ref())
            });
        }
        client.warrants.clone_from(&issued);
        client.rho_w = Some(rho);
        client.stark = regs
            .iter()
            .map(|r| r.0.clone())
            .zip(proofs.iter().cloned())
            .collect();

        Ok(json!({
            "live": if live {
                "live: warrants signed and the tree built now; ρ_W anchored and both searches registered in transactions mined now; the saved proofs verified now"
            } else {
                "live: warrants signed and the tree built now; ρ_W anchored and both searches registered in transactions mined now. The STARKs were proved and verified on AWS beforehand and are NOT re-verified here (7.1 GB); their stored statements are checked now against the chain"
            },
            "client": [
                ["evidence warrant", format!("ML-DSA-65 signed by the court; scope: evidence-plane keyword classes {}–{} (file system and numeric, not network); window epochs 0–1000", issued[0].warrant.scope.bounds().0, issued[0].warrant.scope.bounds().1)],
                ["σ_CA on each warrant (ML-DSA-65)", format!("{} B and {} B; both verify", issued[0].sig.len(), issued[1].sig.len())],
                ["custody warrant", "a separate, default-deny grant on the custody plane"],
                ["our leaves in the warrant tree", format!("{} and {}; the other two are other investigators' commitments", issued[0].index, issued[1].index)],
                ["warrant tree (4 leaves, two of them other investigators')", format!("ρ_W = {}", hex(&rho))],
                ["out-of-scope query (ext:jpg ∧ ip:…)", format!("refused before any trapdoor exists: {}", refused.unwrap_or_else(|| "NOT refused".into()))],
                ["nullifier N = H(0x31 ‖ ⟪s, e⟫), evidence", hex(&regs[0].1.0)],
                ["scope digest H(0x33 ‖ ⟪scope(q)⟫), evidence", hex(&regs[0].2)],
            ],
            "server": [
                ["ρ_W on chain", format!("commitRoot in block {}; read back {}", anchor_rx.block, hex(&on_chain_rho))],
                ["authoriseSearch (evidence, custody)", format!("blocks {} and {}: the chain records N and a scope digest, not whose warrant", regs[0].3.block, regs[1].3.block)],
                ["same N again", replay.map_or_else(|| "NOT refused".to_owned(), |e| format!("refused by consensus: {e}"))],
                ["π_auth, evidence (STARK)", proofs[0].clone()],
                ["π_auth, custody (STARK)", proofs[1].clone()],
            ],
        }))
    }

    // ------------------------------------------------------------ D4: Phases 8–9

    pub(super) fn search(&mut self) -> StepResult {
        let (client, ais, _) = self.parts()?;
        let w = client
            .warrants
            .first()
            .ok_or("no evidence warrant")?
            .clone();
        let tree = RangeTree::profile(Attribute::Bytes);
        let cover = tree.cover_keywords(SIZE_LO, SIZE_HI);
        // The query's own classes must sit inside the warrant; checked here
        // too, on the client, before a trapdoor is built.
        w.warrant
            .check_scope_and_expiry(&w.query, client.epoch)
            .map_err(e2s)?;

        // Round 1: the s-term's constrained key; the server returns payloads,
        // the client decrypts and filters them into Cand.
        let s_term: &[u8] = b"ext:jpg";
        let cand = client
            .evidence
            .candidates(&ais.evidence, s_term)
            .map_err(e2s)?;
        let round1 = ais.evidence.last_search.borrow().unwrap_or((0, 0, 0));

        // Round 2: one shuffled probe list for every candidate × x-term ×
        // closed epoch × {add, del}; the server answers bits.
        let mut x_terms: Vec<&[u8]> = cover.iter().map(Vec::as_slice).collect();
        x_terms.push(b"state:deleted");
        let k = cover.len();
        let formula = Formula::And(vec![
            Formula::Or((0..k).map(Formula::Term).collect()),
            Formula::Not(Box::new(Formula::Term(k))),
        ]);
        let (transcript, map) = client.evidence.probe(&cand, &x_terms);
        let bits = ais.evidence.probe(&transcript);
        let result: BTreeSet<DocId> =
            client
                .evidence
                .evaluate(&cand, x_terms.len(), &map, &bits, &formula);

        // Plaintext oracle, over the same documents: the answer must equal it.
        let oracle: BTreeSet<DocId> = client
            .docs
            .iter()
            .filter(|d| {
                d.keywords.iter().any(|k| k == "ext:jpg")
                    && !d.keywords.iter().any(|k| k == "state:deleted")
                    && d.numbers
                        .iter()
                        .any(|(a, v)| *a == Attribute::Bytes && (SIZE_LO..=SIZE_HI).contains(v))
            })
            .map(|d| d.id)
            .collect();

        // The trapdoor as the AIS received it: round one's count and the probe
        // list (eq:leaves, H(0x34 ‖ ⟪td⟫)).
        let td_bytes: Vec<u8> = round1
            .1
            .to_le_bytes()
            .iter()
            .copied()
            .chain(transcript.probes.iter().flat_map(|t| t.to_vec()))
            .collect();
        let td = retrieval::trapdoor_digest(&td_bytes);
        let n = Nullifier::new(&w.secret, client.epoch);
        let pending = client.evidence.pending(&cand).len();

        // Phase 9 Step 4: recover one result's artefact: unwrap K_ev, decrypt,
        // check the plaintext against cm_ev.
        let recovered = recover(client, ais, 0)?;
        let labels: Vec<String> = result
            .iter()
            .filter_map(|id| client.docs.iter().find(|d| d.id == *id))
            .map(|d| d.label.clone())
            .collect();
        client.evidence_hits = result.iter().copied().collect();

        // P6 (eq:rres): commit to exactly what was disclosed, with a fresh
        // r_res the investigator keeps; the 0x04 leaf, emitted AFTER the
        // search, anchors it with the warrant id (N) and the trapdoor digest.
        let r_res = rng::secret().map_err(e2s)?;
        let r_commit = retrieval::commit_results(&n.0, &td, &client.evidence_hits, &r_res);
        ais.append(
            &retrieval::audit_leaf(&n.0, &td, &r_commit, now()),
            4,
            client.epoch,
        );
        let opened = retrieval::opens(&r_commit, &n.0, &td, &client.evidence_hits, &r_res);
        let substituted: Vec<DocId> = client.evidence_hits.iter().map(|i| i + 1).collect();
        let refused = !retrieval::opens(&r_commit, &n.0, &td, &substituted, &r_res);

        let ones = bits.iter().filter(|b| **b).count();
        let sample: Vec<String> = transcript.probes.iter().take(3).map(|t| short(t)).collect();
        Ok(json!({
            "live": "live: both rounds ran now against the server's encrypted index; the result is checked against a plaintext oracle in the same step",
            "client": [
                ["query", "ext:jpg ∧ (1 000 000 ≤ size ≤ 1 999 999 bytes) ∧ ¬ state:deleted"],
                ["range → canonical cover", format!("{k} prefix keywords, e.g. {}", cover.first().map(|c| String::from_utf8_lossy(c).into_owned()).unwrap_or_default())],
                ["round 1: candidates Cand = DB(ext:jpg)", format!("{} documents, decrypted and filtered here", cand.len())],
                ["round 2: formula evaluated here", "(OR of the cover terms) AND NOT state:deleted"],
                ["result", labels.join("\n")],
                ["equals the plaintext oracle", (result == oracle).to_string()],
                ["pending (open epoch, not evaluated)", pending.to_string()],
                ["R_res = H(0x35 ‖ ⟪N, H(0x34‖⟪td⟫), sorted(R), r_res⟫)", hex(&r_commit)],
                ["an auditor opens R_res with (R, r_res)", format!("{opened}; with one id substituted: refused {refused}")],
                ["Phase 9 Step 4: recovery", recovered],
            ],
            "server": [
                ["round 1 received", format!("one constrained key ({} B) for count {}; returned {} encrypted payloads", round1.0, round1.1, round1.2)],
                ["round 2 received", format!("{} probes, shuffled, e.g. {}", transcript.probes.len(), sample.join(", "))],
                ["round 2 answered", format!("{} bits, {ones} of them 1", bits.len())],
                ["what the server never saw", "the keyword, the formula, the range, which probe belongs to which candidate, or the result"],
                ["0x04 leaf appended after the search", format!("⟪N, H(0x34‖⟪td⟫), R_res, ts⟫: the server learns nothing from R_res; MMR now {} leaves", ais.mmr.leaf_count())],
            ],
        }))
    }

    pub(super) fn custody_search(&mut self) -> StepResult {
        let (client, ais, _) = self.parts()?;
        let w = client.warrants.get(1).ok_or("no custody warrant")?.clone();
        w.warrant
            .check_scope_and_expiry(&w.query, client.epoch)
            .map_err(e2s)?;
        // ⭐ The actor keyword is `actor:⟪id, role⟫` (M13 A2), which a searcher
        // can form from who it is looking for. It used to be `actor:{actor_c}`,
        // which now differs in every record — so the old search would match
        // nothing, and its matching before was the sign that `actor_c` was
        // being reused.
        let lab = pqcl_pipeline::actor_keyword(
            client.custodians[LAB].actor_id.as_bytes(),
            client.custodians[LAB].agent.role(),
        );
        let transfer = pqcl_pipeline::event_keyword(Event::Transfer);
        let kws: [&[u8]; 2] = [&transfer, &lab];
        let ids = pqcl_dsse::cd_search(&client.custody, &ais.custody, &kws).map_err(e2s)?;
        let records: Vec<(usize, usize)> = ids
            .iter()
            .filter_map(|id| client.custody_docs.get(usize::try_from(*id).ok()?).copied())
            .collect();
        let received: BTreeSet<usize> = records.iter().map(|(ci, _)| *ci).collect();

        // The join, on the client: evidence hits whose capsule the evidence
        // store received.
        let joined: Vec<String> = client
            .evidence_hits
            .iter()
            .filter_map(|id| client.docs.iter().find(|d| d.id == *id))
            .filter(|d| received.contains(&d.capsule))
            .map(|d| format!("{} (in {})", d.label, client.held[d.capsule].file))
            .collect();
        Ok(json!({
            "live": "live: two Π_core searches ran now against the custody index; the intersection and the join ran here",
            "client": [
                ["custody query (Π_CD)", "evt:TRANSFER ∧ actor = evidence-store-1"],
                ["matching records", records.iter().map(|(ci, j)| format!("{} record #{j}", client.held[*ci].file)).collect::<Vec<_>>().join(", ")],
                ["cross-plane join (client-side)", format!("JPEGs in range that the evidence store received:\n{}", joined.join("\n"))],
            ],
            "server": [
                ["requests", "two separate single-keyword searches on the custody index, under a different key from the evidence index"],
                ["what the server cannot do", "join the planes: it never sees which evidence results the custody results relate to"],
            ],
        }))
    }

    // ------------------------------------------------------------ D5: Phase 10

    pub(super) fn audit(&mut self) -> StepResult {
        self.audit_capsule(0)
    }

    /// Phase 10 for capsule `ci`: verify its history from public data alone.
    /// The custody corner's "verify" button calls this for any anchored capsule.
    #[allow(clippy::too_many_lines)]
    pub(super) fn audit_capsule(&mut self, ci: usize) -> StepResult {
        let (client, _, chain) = self.parts()?;
        if ci >= client.held.len() {
            return Err(format!("no capsule {ci}"));
        }
        // The first epoch that holds one of this capsule's segments.
        let ep = client
            .epochs
            .iter()
            .find(|ep| ep.proofs.iter().any(|p| p.0 == ci))
            .ok_or("this capsule has no anchored segment yet: close and anchor an epoch first")?
            .clone();
        let h = &client.held[ci];
        let at = ep
            .proofs
            .iter()
            .find(|p| p.0 == ci)
            .ok_or("capsule not in epoch")?
            .1;
        // ⭐ One `Segment` per anchored segment (M13 A20), each with its own
        // Tier-2 path into its own epoch's root. Assembling this is a **keyed**
        // step — the AIS cannot tell which segments are one capsule's — and the
        // three per-capsule keys travel in the bundle so the court can open the
        // bodies and check the links between segments itself.
        let segments: Vec<Segment> = h
            .anchored
            .iter()
            .filter_map(|a| {
                Some(Segment::new(
                    a.eid_e,
                    a.epoch,
                    h.chain[a.from..a.to].to_vec(),
                    a.proof.clone()?,
                ))
            })
            .collect();
        // The capsule's own seal proof travels with the segments (M13 A3), so
        // the auditor checks the artefact's commitments and not only its
        // history — the swapped-`d_ev`/`cm_ev` probe is refused keylessly.
        let bundle = Bundle::new(
            h.capsule.clone(),
            segments,
            SealProof {
                epoch: h.seal_epoch,
                proof: h
                    .seal_proof
                    .clone()
                    .ok_or("the capsule is not anchored yet")?,
            },
            client.keys.disclosure_keys(&h.capsule.eid),
        );

        // The auditor's whole input: the bundle, the chain's public logs, and
        // public keys. No case key, no index key, no server state.
        let history = chain.anchored_history(&client.keys.cid_c).map_err(e2s)?;
        // eq:auditchk: every anchored checkpoint recomputes from its
        // predecessor, back to the registered reg, and the epoch number grows
        // (M13 A21: the count is per epoch now, so it is `n_e` from the audit
        // package that `d_e` is checked against, not a growing total).
        let links: Vec<(u64, Digest32, u64, Digest32)> = history
            .iter()
            .zip(&client.epochs)
            // `n_e` comes from the client's own record of the epoch, not from
            // the chain: the anchor does not carry it (M13 A21), and the audit
            // package is where it travels.
            .map(|(a, ep)| (ep.e, a.root, ep.leaf_count, a.checkpoint))
            .collect();
        let chain_ok = checkpoint::verify_chain(&client.reg, &links);
        // Every epoch the capsule has a segment in, with the root the chain's
        // own event log carries for it.
        //
        // ⚠️ **Zipped, not indexed by the epoch number** (M13 A21). There is no
        // count on chain to match on any more, so the pairing is positional —
        // `anchored_history` returns this case's events in block order and
        // `client.epochs` is in close order, which is the same order, and the
        // checkpoint chain is what proves it. Indexing `history` by `e` is
        // wrong because the demo's epochs do not start at zero, and it failed
        // the audit step with "epoch root not on chain".
        let roots: Vec<(u64, Digest32)> = client
            .epochs
            .iter()
            .zip(&history)
            .map(|(c, a)| (c.e, a.root))
            .collect();
        if !roots.iter().any(|(e, _)| *e == ep.e) {
            return Err("epoch root not on chain".into());
        }
        let structure = bundle.verify(&roots).map(|()| "verifies").map_err(e2s)?;
        let opened_records = bundle.open().map_err(e2s)?;
        let opened = opened_records.len();
        let defr = sig::verify(
            &pqcl_pipeline::capsule_signed_bytes(&bundle.capsule),
            &bundle.capsule.sig_defr,
            client.custodians[super::DEFR].agent.public_key(),
            &[],
        )
        .is_ok();
        // §1br F2: the court sees `σ_actor` only after opening the bundle.
        let sigs = bundle
            .records()
            .zip(&opened_records)
            .zip(&h.signers)
            .all(|((r, o), s)| {
                sig::verify(
                    &record_signed_bytes(r, &o.body),
                    &o.sigs.actor,
                    client.custodians[*s].agent.public_key(),
                    &[],
                )
                .is_ok()
            });
        let enc = bundle.encode();
        let leaks_other = client
            .held
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != ci)
            .any(|(_, o)| enc.windows(32).any(|w| w == o.capsule.eid));
        Ok(json!({
            "live": "live: verification ran now against roots read from the chain's public event log",
            "client": [
                ["disclosed", format!("{} with its {} records in {} segment(s), one Tier-2 path each (leaf {at}); {opened} bodies opened under the disclosed key", h.file, bundle.record_count(), bundle.segments.len())],
                ["bundle size", format!("{} B", enc.len())],
                ["contains any other capsule's eid", leaks_other.to_string()],
            ],
            "server": [
                ["auditor's input", "the bundle, RootCommitted events, public keys: nothing else"],
                ["roots on chain for this case", history.len().to_string()],
                ["checkpoint chain back to reg (eq:auditchk)", chain_ok.to_string()],
                ["Tier-1 and Tier-2 against the anchored root", structure],
                ["σ_DEFR on the capsule", defr.to_string()],
                ["every σ_actor in the chain", sigs.to_string()],
            ],
        }))
    }

    pub(super) fn tamper(&mut self) -> StepResult {
        self.tamper_capsule(1)
    }

    /// Phase 10 tamper response for capsule `ci`: flip one stored byte and
    /// re-run the keyless check. The custody corner's "tamper" button calls this.
    pub(super) fn tamper_capsule(&mut self, ci: usize) -> StepResult {
        let (client, ais, _) = self.parts()?;
        if ci >= client.held.len() {
            return Err(format!("no capsule {ci}"));
        }
        let eid = client.held[ci].capsule.eid;
        let path = ais.payloads.path(&eid);
        let mut bytes = std::fs::read(&path).map_err(e2s)?;
        // One byte, at a position drawn now.
        let mut r = [0u8; 8];
        rng::fill(&mut r).map_err(e2s)?;
        let offset = usize::try_from(u64::from_le_bytes(r) % bytes.len() as u64).map_err(e2s)?;
        bytes[offset] ^= 0x01;
        std::fs::write(&path, &bytes).map_err(e2s)?;
        drop(bytes);

        let again = chunked::digest_file(&path, Domain::EvidenceDigest).map_err(e2s)?;
        let detected = *again.root() != client.held[ci].capsule.d_ev;
        let bad: Vec<usize> = again
            .chunks()
            .iter()
            .zip(&client.held[ci].chunks)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        client.held[ci].integrity = Some((*again.root(), !detected));
        // Verify-on-access: a reader that decrypts must fail the AES-GCM tag.
        let read = recover(client, ais, ci).err();
        Ok(json!({
            "live": "live: a byte of the stored ciphertext was changed now and the check re-ran over the file",
            "client": [
                ["tampered", format!("{} ciphertext, byte {offset} XOR 0x01", client.held[ci].file)],
                ["recomputed d_ev", hex(again.root())],
                ["anchored d_ev", hex(&client.held[ci].capsule.d_ev)],
                ["detected", detected.to_string()],
                ["localised to chunk", format!("{bad:?} of {} (1 MiB chunks): the other regions stay admissible", again.chunks().len())],
                ["decrypting it now (verify-on-access)", read.map_or_else(|| "NOT refused".to_owned(), |e| format!("refused: {e}"))],
            ],
            "server": [
                ["what changed", "the stored blob; nothing on chain, nothing in the index"],
                ["who can check", "anyone holding the anchored d_ev: the sweep is keyless because d_ev binds ciphertext"],
            ],
        }))
    }

    // ------------------------------------------------------------ D6: Phase 11

    pub(super) fn order(&mut self) -> StepResult {
        let (client, _, chain) = self.parts()?;
        let ci = 0;
        let target = Target::new(&[client.held[ci].capsule.eid]);
        let ts = chain.block_timestamp().map_err(e2s)?;
        let oid = hash_domain(
            Domain::Dispose,
            &[b"order", &client.keys.cid_c, &rng::secret().map_err(e2s)?],
        );
        let order = Order::issue(
            &client.court,
            oid,
            target.root(),
            RedactionScope::Full,
            Mode::Erased,
            ts,
            ts + 86_400,
        )
        .map_err(e2s)?;
        // D4: the order's digest (its 0x05 leaf) goes on chain, never σ_CO.
        let rx = chain
            .order_redaction(&client.keys.cid_c, &order.oid, &order.leaf().digest)
            .map_err(e2s)?;
        let recorded = chain
            .recorded_order(&client.keys.cid_c, &order.oid)
            .map_err(e2s)?
            .is_some();
        // A forged order (signed by the anchoring key, not the court's) fails
        // the AIS's check before anything is deleted.
        let forged = Order::issue(
            &client.committee[0],
            oid,
            target.root(),
            RedactionScope::Full,
            Mode::Erased,
            ts,
            ts + 86_400,
        )
        .map_err(e2s)?;
        let forged_err = forged
            .verify(client.court.public_key(), ts)
            .err()
            .map(|e| e.to_string());
        client.order = Some(order.clone());
        Ok(json!({
            "live": "live: the order was signed now and recorded in a transaction mined now",
            "client": [
                ["court order", format!("erase {} — scope FULL, mode ERASED, expires in 24 h", client.held[ci].file)],
                ["oid", hex(&order.oid)],
                ["target = Merkle root over the targeted eids", hex(&order.tgt)],
                ["σ_CO (ML-DSA-65, court key)", format!("{} B", order.sig_co.len())],
                ["the same order signed with another key", forged_err.unwrap_or_else(|| "NOT refused".into())],
            ],
            "server": [
                ["orderRedaction(oid, digest)", format!("block {}, {} gas: the order's digest, recorded before anything is deleted", rx.block, rx.gas_used)],
                ["recordedOrder(oid) on chain", recorded.to_string()],
                ["nothing deleted yet", "erasure is gated on this record"],
            ],
        }))
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn erase(&mut self) -> StepResult {
        let (client, ais, chain) = self.parts()?;
        let order = client.order.clone().ok_or("no order")?;
        let ci = 0;
        let eid = client.held[ci].capsule.eid;
        let target = Target::new(&[eid]);
        let membership = target.prove(&eid).ok_or("not a target")?;

        // Before: the redacted documents still match.
        let before = client
            .evidence
            .candidates(&ais.evidence, b"ext:jpg")
            .map_err(e2s)?
            .len();

        // The registry is the chain: recordedOrder(cid, oid) read now. It is
        // the **digest** that is read, and erasure requires it to be this
        // order's 0x05 leaf, not merely something under its id (M13 A7).
        let registry = chain_registry(chain, &client.keys.cid_c, &order.oid)?;
        let redactees: Vec<Redactee> = client
            .docs
            .iter()
            .filter(|d| d.capsule == ci)
            .map(|d| Redactee {
                eid,
                doc: d.id,
                membership: membership.clone(),
                keywords: d.index_keywords(),
            })
            .collect();
        let mut openings = Openings::new();
        let outcome = redaction::execute(
            &order,
            client.court.public_key(),
            now(),
            &registry,
            &redactees,
            &ais.payloads,
            &mut openings,
            client.ca_kem.encapsulation_key(),
            &mut client.evidence,
            &mut ais.evidence,
            || PrfKey::new(rng::secret().unwrap_or_else(|_| digest256(b"entropy unavailable"))),
        )
        .map_err(e2s)?;

        // Phase 11 Step 3: DISPOSE, referencing the order, signed by the
        // evidence store (the current custodian). The chain is then closed.
        let lab = &client.custodians[LAB];
        let prev = client.held[ci].chain.last().ok_or("empty chain")?.clone();
        let dispose = lab
            .agent
            .dispose_record(
                &client.keys,
                &client.held[ci].capsule,
                &prev,
                Some(&order.oid),
                &RecordParams::at(client.held[ci].chain.len() as u64, now())
                    .with_params(Params::of(b"court-order", b"1", &order.oid))
                    // Epoch 1: the `DISPOSE` is written after D3 closed epoch 0,
                    // so it opens a **new segment** whose cleartext link says
                    // nothing about the segment it continues (M13 A20).
                    .in_epoch(client.epoch),
            )
            .map_err(e2s)?;
        super::append_record(client, ais, ci, dispose, LAB)?;

        // Phase 11 Step 4: the 0x05 leaf with the updated 0x02 leaf, in a new
        // root, through the same epoch close as D3.
        ais.append(&order.leaf(), 5, client.epoch);
        let close = self.anchor()?;
        let (client, ais, chain) = self.parts()?;

        client.held[ci].erased = Some(order.oid);

        // After: the search no longer returns the capsule.
        let after = client
            .evidence
            .candidates(&ais.evidence, b"ext:jpg")
            .map_err(e2s)?
            .len();

        // The old anchor still verifies: epoch 1's 0x02 proof against epoch 1's
        // root, read from the chain's log; and the 0x01 seal leaf with it.
        let history = chain.anchored_history(&client.keys.cid_c).map_err(e2s)?;
        let first = client.epochs.first().ok_or("no first epoch")?;
        // The first epoch's event is the first one this case emitted; the
        // same positional pairing as the audit step above.
        let old_root = history.first().ok_or("old root missing")?.root;
        let h = &client.held[ci];
        let (_, _, p) = first
            .proofs
            .iter()
            .find(|p| p.0 == ci)
            .ok_or("no old proof")?;
        // ⭐ The old `0x02` covers the **first segment only** (M13 A20), so the
        // check recomputes that segment's root and not a prefix of the chain —
        // and the later `DISPOSE`, which is in a segment of its own, does not
        // disturb it. That is the point being narrated: erasure appends, and
        // the anchor that predates it still verifies.
        let old = h.anchored.first().ok_or("no anchored segment")?;
        let old_leaf = Leaf::new(
            Domain::CustodyRoot,
            &[
                &old.eid_e,
                &pqcl_pipeline::handoff::running_root(&h.chain[old.from..old.to]),
                &((old.to - old.from) as u64).to_le_bytes(),
            ],
        );
        let old_ok = pqcl_forest::tier2::verify(&old_root, &old_leaf, p);

        // Accounting (Phase 10): the missing payload is accounted for by the
        // order and the DISPOSE; the tampered pcap is still present.
        // Each anchored leaf with the epoch whose root holds it, so the audit
        // can require the order's epoch e′ ≥ the capsule's e (M13 A7).
        let leaves: HashMap<Digest32, u64> =
            ais.leaves.iter().map(|l| (l.digest, l.epoch)).collect();
        let registry = chain_registry(chain, &client.keys.cid_c, &order.oid)?;
        let disposals: Vec<(Digest32, redaction::DisposalClaim)> = client
            .held
            .iter()
            .flat_map(|h| {
                // ⭐ **Keyless, and selected by `order_ref` alone.** Since M13
                // A1 the event is inside `C_rec`, so a `DISPOSE` is no longer
                // identifiable without a key — and does not need to be: a
                // court-ordered disposal is exactly one carrying an
                // `order_ref`. The auditor
                // reads the two clear fields and nothing else, which is what
                // keeps this delegable.
                h.chain
                    .iter()
                    .filter(|r| r.order_ref.is_some())
                    .map(|r| (h.capsule.eid, redaction::DisposalClaim::of(r)))
            })
            .collect();
        let anchored: Vec<redaction::AnchoredPayload> = client
            .held
            .iter()
            .map(|h| redaction::AnchoredPayload {
                eid: h.capsule.eid,
                path: ais.payloads.path(&h.capsule.eid),
                epoch: h.seal_epoch,
            })
            .collect();
        let claimed = [ClaimedOrder {
            order: order.clone(),
            covers: vec![(eid, membership)],
        }];
        let unaccounted = redaction::account(
            &anchored,
            &claimed,
            &leaves,
            &registry,
            &disposals,
            client.court.public_key(),
        );

        // The same deletion without an order is caught: account with no claim.
        let without = redaction::account(
            &anchored,
            &[],
            &leaves,
            &registry,
            &[],
            client.court.public_key(),
        );
        let caught = without
            .iter()
            .any(|u| matches!(u, Unaccounted::PayloadDeleted { eid: e } if *e == eid));

        let new_root = close["client"][2][1].clone();
        Ok(json!({
            "live": "live: the payload file was deleted now, tombstones and compaction ran now, and a new root was anchored now",
            "client": [
                ["erasure", format!("1 payload file erased; {} (keyword, document) pairs tombstoned across its {} documents; compaction: {}", outcome.pairs_tombstoned, outcome.payloads_erased, outcome.compacted)],
                ["ext:jpg candidates before → after", format!("{before} → {after}")],
                ["DISPOSE record", "appended by evidence-store-1, referencing the order; the chain is now closed"],
                ["new root R_e'", new_root],
                ["epoch 1's root, from the chain log", hex(&old_root)],
                ["epoch 1's custody leaf still verifies against it", old_ok.to_string()],
            ],
            "server": [
                ["payload file present", ais.payloads.exists(&eid).to_string()],
                ["leaves appended", "0x05 (the order) and 0x02 (the updated custody root)"],
                ["accounting: unaccounted payloads", format!("{} (lawful erasure is accounted for)", unaccounted.len())],
                ["the same deletion with no order", format!("flagged as tampering: {caught}")],
            ],
        }))
    }
}

/// Name a revert by its error selector when the node's message carries it.
fn revert_name(err: &str, signature: &str) -> String {
    let selector = hex(&pqcl_exp::evm::keccak256(signature.as_bytes()))[..8].to_owned();
    if err.contains(&format!("0x{selector}")) {
        format!(
            "{} (the transaction reverts)",
            signature.split('(').next().unwrap_or(signature)
        )
    } else {
        err.to_owned()
    }
}

/// Every value this client holds that may appear on chain, with a name, so
/// the Chain page can say which word of a transaction is which. All of them
/// are public once anchored; naming them is the client's knowledge, not the
/// chain's.
pub(super) fn known_values(client: &Client) -> Vec<Value> {
    let cid = client.keys.cid_c;
    let mut out = vec![
        json!([hex(&cid), "this case's cid (a commitment, registered once)"]),
        json!([
            hex(&client.reg.digest()),
            "this case's registration digest reg (keys and M-of-N policy)"
        ]),
        json!([
            hex(&warrant_namespace(&cid)),
            "the warrant registry's namespace, derived from cid"
        ]),
    ];
    if let Some(rho) = client.rho_w {
        out.push(json!([
            hex(&rho),
            "ρ_W, the root of the court's warrant tree"
        ]));
    }
    if let Some((d_w, a_w)) = client.warrant_anchor {
        out.push(json!([hex(&d_w), "the warrant root's checkpoint"]));
        out.push(json!([
            hex(&a_w),
            "the warrant root's approval digest (2 of 3 custodians)"
        ]));
    }
    if let Some(b) = &client.bundle {
        for w in b["warrants"].as_array().into_iter().flatten() {
            let name = w["name"].as_str().unwrap_or("?");
            if let Some(n) = w["nullifier"].as_str() {
                out.push(json!([
                    n,
                    format!("the {name} warrant's nullifier (spent once)")
                ]));
            }
            if let Some(sc) = w["scope_commit"].as_str() {
                out.push(json!([
                    sc,
                    format!("the {name} warrant's scope commitment")
                ]));
            }
        }
    }
    for ep in &client.epochs {
        out.push(json!([
            hex(&ep.root),
            format!("the client's R_e for epoch {}", ep.e)
        ]));
        out.push(json!([
            hex(&ep.on_chain.checkpoint),
            format!("the client's checkpoint d_e for epoch {}", ep.e)
        ]));
        out.push(json!([
            hex(&ep.on_chain.approval),
            format!("the client's approval digest A_e for epoch {}", ep.e)
        ]));
    }
    out
}

fn warrant_namespace(cid: &Digest32) -> Digest32 {
    hash_domain(Domain::WarrantNode, &[b"warrant-tree root", cid])
}

pub(super) fn unhex(s: &str) -> Result<Digest32, String> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return Err(format!("bad hex digest {s}"));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(e2s)?;
    }
    Ok(out)
}

/// Verify a saved STARK with `warrant-demo verify`, as the AIS, against the
/// values read from the chain. Case (c) when no proof exists, said plainly.
fn verify_proof(
    dir: &std::path::Path,
    name: &str,
    n: &Nullifier,
    sc: &Digest32,
    rho: &Digest32,
    epoch: u64,
    have_bundle: bool,
) -> Value {
    let bin = dir.join("../warrant-host/target/release/warrant-demo");
    if !have_bundle || !dir.join(format!("{name}.proof")).is_file() {
        return json!(
            "not available: the core STARK needs 13.2 GiB to prove (M6) and no saved proof exists, so this demo shows the warrant flow without it (case (c)). No execute run is shown in its place."
        );
    }
    let out = Command::new(bin)
        .arg("verify")
        .arg(dir)
        .arg(name)
        .arg(hex(&n.0))
        .arg(hex(sc))
        .arg(hex(rho))
        .arg(epoch.to_string())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let v: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
            if v["ok"] == true {
                json!(format!(
                    "core STARK ({} B) proved on AWS beforehand, verified here now in {:.0} ms and bound to the chain's N, scope digest, ρ_W and epoch",
                    v["proof_bytes"],
                    v["verify_ms"].as_f64().unwrap_or(0.0)
                ))
            } else {
                json!(format!("REJECTED: {}", v["error"]))
            }
        }
        Ok(o) => json!(format!(
            "verifier failed: {}",
            String::from_utf8_lossy(&o.stderr)
                .lines()
                .last()
                .unwrap_or("")
        )),
        Err(e) => json!(format!(
            "verifier not built ({e}): cargo build --release --bin warrant-demo in zk/warrant-host"
        )),
    }
}

/// The stored AWS result for warrant `name`'s STARK, shown instead of a live
/// verification, with its statement compared
/// **now** against what the chain just registered.
///
/// ⛔ Nothing here claims a verification happened on this machine. The text
/// names the stored files, the AWS timings they record, and says plainly that
/// the proof is not re-verified. The comparison is live: if the code's scope
/// digest or nullifier ever drifts from the one the proof committed to, the
/// panel says `false`.
fn stored_proof(
    dir: &std::path::Path,
    name: &str,
    n: &Nullifier,
    sc: &Digest32,
    rho: &Digest32,
    epoch: u64,
    bundle: Option<&Value>,
) -> Value {
    let Some(b) = bundle else {
        return json!(
            "not available: no saved proof bundle (zk/demo-proof/bundle.json), so this demo shows the warrant flow without a STARK. No execute run is shown in its place."
        );
    };
    if !dir.join(format!("{name}.proof")).is_file() {
        return json!(format!(
            "not available: zk/demo-proof/{name}.proof is missing"
        ));
    }
    // The statement the stored proof commits to: verify.json for the evidence
    // warrant (written by `warrant-demo verify` on AWS), the bundle otherwise.
    let verified: Value = std::fs::read(dir.join("verify.json"))
        .ok()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or(Value::Null);
    let w = b["warrants"]
        .as_array()
        .and_then(|ws| ws.iter().find(|w| w["name"] == name))
        .cloned()
        .unwrap_or(Value::Null);
    let (stored_n, stored_sc, stored_rho, stored_e) =
        if name == "evidence" && verified["ok"] == true {
            (
                verified["statement"]["nullifier"].as_str().unwrap_or(""),
                verified["statement"]["scope_digest"].as_str().unwrap_or(""),
                verified["statement"]["warrant_root"].as_str().unwrap_or(""),
                verified["statement"]["epoch"].as_u64(),
            )
        } else {
            (
                w["nullifier"].as_str().unwrap_or(""),
                w["scope_commit"].as_str().unwrap_or(""),
                b["warrant_root"].as_str().unwrap_or(""),
                b["epoch"].as_u64(),
            )
        };
    let n_ok = stored_n == hex(&n.0);
    let sc_ok = stored_sc == hex(sc);
    let rho_ok = stored_rho == hex(rho);
    let e_ok = stored_e == Some(epoch);
    // What AWS recorded: prove-and-verify time per warrant, and, for the
    // evidence warrant, a verify-only run's time.
    let proved = std::fs::read_to_string(dir.join("prove-time.log"))
        .ok()
        .and_then(|log| {
            log.lines()
                .find(|l| l.starts_with(&format!("{name}:")))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("{name}: no prove-time record"));
    let verify_only = if name == "evidence" && verified["ok"] == true {
        // The verify-only process's peak, read from its own `time -v` log.
        let peak = std::fs::read_to_string(dir.join("verify-rss.log"))
            .ok()
            .and_then(|log| {
                log.lines()
                    .find_map(|l| l.trim().strip_prefix("Maximum resident set size (kbytes):"))
                    .and_then(|kb| kb.trim().parse::<f64>().ok())
            })
            .map_or_else(
                || "peak not recorded".to_owned(),
                |kb| format!("{:.1} GB peak", kb / 1_000_000.0),
            );
        format!(
            "; a verify-only run took {:.1} s there ({peak})",
            verified["verify_ms"].as_f64().unwrap_or(0.0) / 1000.0
        )
    } else {
        String::new()
    };
    // Where and when: the instance type `warrant-demo` wrote into the bundle
    // (if any), `proved-at` (one line written when the bundle was pulled: the
    // UTC time, and the instance type when the bundle lacks it), and the commit.
    let mut place: Vec<String> = Vec::new();
    if let Some(i) = b["instance"]
        .as_str()
        .filter(|s| !s.is_empty() && *s != "unknown")
    {
        place.push(i.to_owned());
    }
    if let Ok(t) = std::fs::read_to_string(dir.join("proved-at")) {
        place.push(t.trim().to_owned());
    }
    if let Some(sha) = b["git_sha"].as_str().filter(|s| !s.is_empty()) {
        place.push(format!("commit {}", sha.get(..7).unwrap_or(sha)));
    }
    let place = if place.is_empty() {
        String::new()
    } else {
        format!(" ({})", place.join(", "))
    };
    json!(format!(
        "PRE-RUN on AWS{place}, not re-verified here: {proved}{verify_only}. Stored statement vs what the chain registered now: N {n_ok}, scope digest {sc_ok}, ρ_W {rho_ok}, epoch {e_ok}"
    ))
}

/// Phase 9 Step 4 for capsule `ci`: unwrap `K_ev` by ML-KEM, decrypt `C_ev`,
/// and check the plaintext against `cm_ev`.
pub(super) fn recover(client: &Client, ais: &super::Ais, ci: usize) -> Result<String, String> {
    let h = &client.held[ci];
    let ss = client.ca_kem.decapsulate(&h.wrap.0).map_err(e2s)?;
    let wrapped = pqcl_primitives::SealedRecord::from_bytes(h.wrap.1.clone());
    let k_ev_bytes = RecordKey::new(*ss.as_bytes())
        .open(&h.capsule.eid, &wrapped)
        .map_err(e2s)?;
    let mut k_ev = [0u8; 32];
    k_ev.copy_from_slice(&k_ev_bytes);
    let ct = pqcl_primitives::SealedRecord::from_bytes(
        std::fs::read(ais.payloads.path(&h.capsule.eid)).map_err(e2s)?,
    );
    let plain = RecordKey::new(k_ev)
        .open(&h.capsule.eid, &ct)
        .map_err(e2s)?;
    Ok(format!(
        "{}: K_ev unwrapped by ML-KEM, {} B decrypted, AES-GCM tag valid; plaintext matches cm_ev: {}",
        h.file,
        plain.len(),
        h.opening.opens(&h.capsule.cm_ev, &plain)
    ))
}

/// What the chain recorded for `oid` in case `cid`, as an
/// [`redaction::OrderRegistry`].
fn chain_registry(
    chain: &super::ChainSession,
    cid: &Digest32,
    oid: &Digest32,
) -> Result<HashMap<Digest32, Digest32>, String> {
    Ok(chain
        .recorded_order(cid, oid)
        .map_err(e2s)?
        .map(|d| (*oid, d))
        .into_iter()
        .collect())
}
