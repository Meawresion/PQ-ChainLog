//! **Experiment 6 on chain** — LEChain's contract against our anchor, on our
//! Besu network, over one custody event stream (M10 H2, `sec:exp-anchor`).
//!
//! # The comparison
//!
//! LEChain (Li et al., FGCS 115, 2021) commits **every custody state
//! transition** as a signed transaction to its contract (§7.1, Table 3). We
//! commit custody records off chain — signed, indexed, hash-chained per capsule
//! into a Tier-1 tree — and anchor **one root per epoch**. Both run here over
//! the same stream (`pqcl_exp::custody_stream`), on the same four-validator
//! QBFT network, through the same client (`pqcl_exp::evm`), and three things
//! are measured for each:
//!
//! 1. gas per custody transition (ours: an anchor's gas over its entries);
//! 2. custody events committed, over the time from first submission to last
//!    commit — raw counts and durations, the rate is left to `mkfigs`;
//! 3. event-to-commit time, per event.
//!
//! # LEChain, faithfully
//!
//! Its published contract (`baselines/lechain/`, pinned by commit and SHA-256)
//! compiled as its pragma and Remix admit. Roles as its Table 4 instantiates
//! them: 10 police investigators, 100 crime-scene analysts, one police
//! department, and its four miners as blockchain nodes. Payload sizes from its
//! §7.3 (`R_ω` 132 B, `{c_sa}` 120 B, `ρ` 20 B, identities 7 B). Every
//! transition carries the `ecrecover`-checked `(msgh, v, r, s)` its contract
//! requires. Its own latency method (§7.3: send, `waitForTransactionReceipt`,
//! 40 uploads) is reproduced as the `sequential` phase; the rest of the stream
//! is submitted pipelined, which is the throughput it can reach.
//!
//! The event mapping is a modelling choice and is recorded in
//! `baselines/UPGRADES.md`. Where our event has no LEChain transition
//! (`TRANSFER`, and `ANALYZE`/`EXPORT` beyond "access"), it maps to `Access`,
//! the cheapest state write — conservative for us.
//!
//! # Running it
//!
//! ```text
//! (cd besu && ./generate.sh && docker compose up -d)
//! bash baselines/lechain/fetch.sh && forge build --root baselines/lechain
//! forge build --root contracts
//! cargo run --release -p pqcl-exp --features chain --bin exp6chain
//! ```
//!
//! `PQCL_RPC` overrides the node URL; `PQCL_ANCHOR_AXIS` the axis and
//! `PQCL_LECHAIN_STEADY_CAPSULES` LEChain's steady-state stream, both for a local smoke run.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use pqcl_bench::RunSpec;
use pqcl_capsule::redaction::{Mode, Order, Scope, Target};
use pqcl_capsule::{Capsule, CustodyRecord, Event};
use pqcl_dsse::core::{Edb, HonestEdb};
use pqcl_exp::appender::from_env;
use pqcl_exp::bdems;
use pqcl_exp::case::CaseBuilder;
use pqcl_exp::cast::Cast;
use pqcl_exp::chain::{
    Chain, DEV_SECRET, GAS_MARGIN_PCT, POLL, WINDOW, Watcher, artifact_bytecode, contract_address,
    gas, network, stuck, submit_pipelined,
};
use pqcl_exp::custody_stream::{CustodyEvent, StreamParams, custody_stream, event_counts};
use pqcl_exp::evm::{
    Abi, Address, Key, LegacyTx, Rpc, Word, abi_encode, address_word, encode_call, from_hex,
    keccak256, quantity, to_hex, uint,
};
use pqcl_exp::{emit_custody, stats::Summary};
use pqcl_pipeline::checkpoint::{
    self, ApprovalSet, ChainView, Committed, Proposal, Registration, Validated, approve,
};
use pqcl_pipeline::{Ais, CUSTODY_KEYWORDS_PER_RECORD, CaseKeys};
use pqcl_primitives::slh::CoSigner;
use pqcl_primitives::xof::{Digest32, Domain, PrfKey, digest256, hash_domain};
use pqcl_primitives::{KeyPair, Signer, SoftwareMlDsa};
use pqcl_sm::Backend;
use sha2::{Digest as _, Sha256};

type Res<T> = Result<T, Box<dyn core::error::Error>>;

/// LEChain §7.3: "a user sent an upload transaction 40 times", each awaited.
const SEQUENTIAL: usize = 40;

/// Epoch sizes for our side, in MMR leaves: §1q.2's denser axis, fixed before
/// campaign 04 (log-spaced, and chosen before seeing which point anyone wins).
const EPOCH_SIZES: &[usize] = &[
    25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 100_000, 1_000_000,
];

/// `tab:exp-anchor`'s axis, in **MMR leaves per epoch** (§1l.2: an entry is
/// every leaf, evidence and custody alike — for us a capsule's `0x01` seal
/// leaf and its `0x02` custody-root leaf, so an epoch of E leaves carries
/// several times E custody records). `PQCL_ANCHOR_AXIS` overrides it for a
/// local smoke run; the campaign runs the full axis.
fn epoch_axis() -> Vec<usize> {
    std::env::var("PQCL_ANCHOR_AXIS").map_or_else(
        |_| EPOCH_SIZES.to_vec(),
        |s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
    )
}

/// Capsules in each axis point's stream: at least E, so every point closes at
/// least two full epochs, and at least this many so a small E closes enough
/// epochs for its rate to be a steady state rather than one co-signature.
const MIN_AXIS_CAPSULES: usize = 1_000;

/// The largest stream LEChain runs on (M13 A4): 10⁴ capsules, about 83 k
/// transitions, one transaction each. Axis points with a larger stream are
/// compared with this run, LEChain's steady state, and their record says so.
const LECHAIN_MAX_CAPSULES: usize = 10_000;

/// One axis point's stream: the base parameters with its own capsule count.
fn axis_params(epoch: usize, params: StreamParams) -> StreamParams {
    StreamParams {
        capsules: u32::try_from(epoch.max(MIN_AXIS_CAPSULES)).unwrap_or(u32::MAX),
        active: 64,
        ..params
    }
}

/// The LEChain stream an axis point's ratio divides by: its own when it has
/// at most [`LECHAIN_MAX_CAPSULES`], otherwise the steady-state run.
fn lechain_capsules_for(epoch: usize, steady: u32) -> u32 {
    let own = axis_params(epoch, StreamParams::default()).capsules;
    if own as usize <= LECHAIN_MAX_CAPSULES {
        own
    } else {
        steady
    }
}

/// The steady-state LEChain stream's size: [`LECHAIN_MAX_CAPSULES`], or
/// `PQCL_LECHAIN_STEADY_CAPSULES` for a local smoke run, which must stay
/// small. `figspec` refuses the caption cells unless it is 10⁴.
fn lechain_steady_capsules() -> u32 {
    std::env::var("PQCL_LECHAIN_STEADY_CAPSULES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(u32::try_from(LECHAIN_MAX_CAPSULES).unwrap_or(u32::MAX))
}

/// §1q.2's co-signer ablation: W at one axis point, 10² entries per epoch,
/// where the co-signature binds. W = 1 and W = cores already run at every
/// point; the sweep adds the values between. ⛔ The table keeps W = vCPUs, the
/// rule set before any result (§1q.2): this sweep is the ablation, not a
/// re-tuning of the table's configuration.
const W_SWEEP: &[usize] = &[1, 2, 4, 8, 16];
const W_SWEEP_AT: usize = 100;

/// LEChain Table 4 role counts, and its four miners as nodes.
const PIS: usize = 10;
const SAS: usize = 100;
const PDS: usize = 1;
const NODES: usize = 4;

/// Deterministic, crypto-looking filler of length `n` — calldata gas depends
/// on zero versus non-zero bytes, and group elements and signatures are not
/// zero-heavy.
fn material(tag: &[u8], i: usize, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut ctr = 0u32;
    while out.len() < n {
        out.extend_from_slice(&keccak256(
            &[tag, &i.to_le_bytes(), &ctr.to_le_bytes()].concat(),
        ));
        ctr += 1;
    }
    out.truncate(n);
    out
}

// ------------------------------------------------------------ LEChain

/// Key-index layout of the role accounts: `[dev, pi…, pd…, sa…, node…]`.
struct Roles;

impl Roles {
    const PI: usize = 1;
    const PD: usize = Self::PI + PIS;
    const SA: usize = Self::PD + PDS;
    const NODE: usize = Self::SA + SAS;
    const END: usize = Self::NODE + NODES;
}

/// One custody transition as LEChain's contract call: `(sender, calldata, label)`.
///
/// `v`, `r`, `s` are `ecrecover`'s own names; `e` and `i` the event and its
/// position.
#[allow(clippy::many_single_char_names)]
fn lechain_call(
    chain: &Chain,
    e: &CustodyEvent,
    i: usize,
    uploads: &mut BTreeMap<u32, (Word, Word)>,
) -> Res<(usize, Vec<u8>, &'static str)> {
    let ts = uint(1_700_000_000 + i as u128);
    let sign = |sender: usize, content: &[Abi]| -> Res<Vec<Abi>> {
        let msgh = keccak256(&abi_encode(content));
        let (v, r, s) = chain.keys[sender].sign_digest(&msgh)?;
        Ok(vec![
            Abi::Word(msgh),
            Abi::Word(uint(u128::from(v))),
            Abi::Word(r),
            Abi::Word(s),
        ])
    };
    Ok(match e.event {
        Event::Collect => {
            let sender = Roles::PI + e.actor as usize % PIS;
            let pi = format!("pi{:05}", sender - Roles::PI).into_bytes();
            let hash_c = keccak256(&material(b"c_omega", i, 132));
            let mut index_pre = pi.clone();
            index_pre.extend_from_slice(&ts);
            uploads.insert(e.capsule, (keccak256(&index_pre), hash_c));
            let content = vec![
                Abi::Bytes(pi),
                Abi::Bytes(material(b"R_omega", i, 132)),
                Abi::Word(hash_c),
                Abi::Word(ts),
                Abi::Bytes(material(b"rho", i, 20)),
            ];
            let mut args = content.clone();
            args.extend(sign(sender, &content)?);
            let sig =
                "orUpload(string,string,bytes32,uint256,string,bytes32,uint8,bytes32,bytes32)";
            (sender, encode_call(sig, &args), "orUpload")
        }
        Event::Seal => {
            let sender = Roles::PD;
            let (index, hash_c) = *uploads.get(&e.capsule).ok_or("SEAL before COLLECT")?;
            let content = vec![
                Abi::Word(index),
                Abi::Word(hash_c),
                Abi::Word(ts),
                Abi::Word(keccak256(&material(b"sig_pd", i, 64))),
            ];
            let mut args = content.clone();
            args.extend(sign(sender, &content)?);
            let sig = "orStore(bytes32,bytes32,uint256,bytes32,bytes32,uint8,bytes32,bytes32)";
            (sender, encode_call(sig, &args), "orStore")
        }
        Event::Dispose => {
            let sender = Roles::NODE + e.capsule as usize % NODES;
            let (index, _) = *uploads.get(&e.capsule).ok_or("DISPOSE before COLLECT")?;
            let content = vec![
                Abi::Word(index),
                Abi::Word(keccak256(&material(b"sig_node", i, 64))),
            ];
            let mut args = content.clone();
            args.extend(sign(sender, &content)?);
            let sig = "orRejectUpload(bytes32,bytes32,bytes32,uint8,bytes32,bytes32)";
            (sender, encode_call(sig, &args), "orRejectUpload")
        }
        Event::Access | Event::Analyze | Event::Export | Event::Transfer => {
            let sender = Roles::SA + e.actor as usize % SAS;
            let content = vec![
                Abi::Bytes(format!("sa{:05}", sender - Roles::SA).into_bytes()),
                Abi::Bytes(material(b"c_sa", i, 120)),
                Abi::Word(ts),
                Abi::Bytes(material(b"rho_sa", i, 20)),
            ];
            let mut args = content.clone();
            args.extend(sign(sender, &content)?);
            let sig = "orAccess(string,string,uint256,string,bytes32,uint8,bytes32,bytes32)";
            (sender, encode_call(sig, &args), "orAccess")
        }
    })
}

fn summarise_by_label(labels: &[&'static str], values: &[u64]) -> serde_json::Value {
    let mut m: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    for (l, v) in labels.iter().zip(values) {
        m.entry(l).or_default().push(*v);
    }
    serde_json::json!(m
        .into_iter()
        .map(|(l, mut v)| {
            v.sort_unstable();
            (l, serde_json::json!({"n": v.len(), "min": v[0], "median": v[v.len() / 2], "max": v[v.len() - 1]}))
        })
        .collect::<BTreeMap<_, _>>())
}

fn latencies(submitted: &[Instant], committed: &[(Instant, u64)]) -> Vec<Duration> {
    submitted
        .iter()
        .zip(committed)
        .map(|(s, (c, _))| c.saturating_duration_since(*s))
        .collect()
}

fn run_lechain(chain: &mut Chain, w: &Watcher, stream: &[CustodyEvent]) -> Res<serde_json::Value> {
    let code = artifact_bytecode("baselines/lechain/out/LEChain.sol/LEChain.json")?;
    let code_len = code.len();
    let deploy = chain.prepare(0, None, code, "deploy")?;
    let deploy_r = chain.send_and_wait(&deploy, w)?;
    let lechain = contract_address(&deploy_r)?;

    let list = |from: usize, n: usize, c: &Chain| {
        Abi::Words(
            (from..from + n)
                .map(|k| address_word(&c.keys[k].address))
                .collect(),
        )
    };
    let set = encode_call(
        "setChars(address[],address[],address[],address[],address[],address[])",
        &[
            list(Roles::PI, PIS, chain),
            list(Roles::NODE, NODES, chain),
            list(Roles::PD, PDS, chain),
            list(Roles::SA, SAS, chain),
            Abi::Words(Vec::new()),
            Abi::Words(Vec::new()),
        ],
    );
    let set = chain.prepare(0, Some(lechain), set, "setChars")?;
    let set_r = chain.send_and_wait(&set, w)?;

    // Client side, timed apart: the officer's `msgh` signature and the
    // transaction signature, per transition.
    let t = Instant::now();
    let mut uploads = BTreeMap::new();
    let mut txs = Vec::with_capacity(stream.len());
    for (i, e) in stream.iter().enumerate() {
        let (sender, data, label) = lechain_call(chain, e, i, &mut uploads)?;
        txs.push(chain.prepare(sender, Some(lechain), data, label)?);
    }
    let prepare = t.elapsed();

    // Phase 1 — LEChain's own method: send, wait for the receipt, repeat.
    let split = SEQUENTIAL.min(txs.len());
    let mut seq_submit = Vec::new();
    let mut seq_commit = Vec::new();
    for p in &txs[..split] {
        seq_submit.push(Instant::now());
        chain.send(p)?;
        seq_commit.extend(w.wait_all(std::slice::from_ref(&p.hash))?);
    }

    // Phase 2 — the rest of the stream, pipelined: the throughput it reaches.
    let rest = &txs[split..];
    let pipe_submit = submit_pipelined(chain, w, rest)?;
    let hashes: Vec<String> = rest.iter().map(|p| p.hash.clone()).collect();
    let pipe_commit = match w.wait_all(&hashes) {
        Ok(c) => c,
        Err(e) => {
            return Err(format!(
                "{e}
{}",
                stuck(chain, w, rest)
            )
            .into());
        }
    };

    let all: Vec<String> = txs.iter().map(|p| p.hash.clone()).collect();
    let receipts = chain.receipts(&all)?;
    let gases = receipts.iter().map(gas).collect::<Res<Vec<u64>>>()?;
    let labels: Vec<&'static str> = txs.iter().map(|p| p.label).collect();
    let span = pipe_commit
        .iter()
        .map(|(c, _)| *c)
        .max()
        .zip(pipe_submit.iter().min())
        .map_or(Duration::ZERO, |(last, first)| {
            last.saturating_duration_since(*first)
        });
    let blocks: std::collections::BTreeSet<u64> = pipe_commit.iter().map(|(_, b)| *b).collect();

    Ok(serde_json::json!({
        "contract_bytes": code_len,
        "deploy_gas": gas(&deploy_r)?,
        "set_chars_gas": gas(&set_r)?,
        "roles": {"pi": PIS, "sa": SAS, "pd": PDS, "node": NODES},
        "client_prepare_total_ns": prepare.as_nanos(),
        "gas_by_transition": summarise_by_label(&labels, &gases),
        "gas_total": gases.iter().sum::<u64>(),
        "transitions": txs.len(),
        "sequential": {
            "events": split,
            "commit_latency_ns": Summary::of(&latencies(&seq_submit, &seq_commit)),
            "method": "LEChain §7.3: send, wait for inclusion, repeat",
        },
        "pipelined": {
            "events": rest.len(),
            "window_per_sender": WINDOW,
            "first_submit_to_last_commit_ns": span.as_nanos(),
            "blocks": blocks.len(),
            "commit_latency_ns": Summary::of(&latencies(&pipe_submit, &pipe_commit)),
        },
    }))
}

// ------------------------------------------------------------- B-DEMS

/// B-DEMS's agencies (its Senders and Receivers, one whitelist): one per
/// stream actor. Its Court is one account, as LEChain's police department.
const AGENCIES: usize = 32;
/// Evidence Providers sign `TxA` and `TxD` for a voluntary submission; they never
/// send a transaction, so their keys are not chain accounts.
const PROVIDERS: usize = 100;

/// Key-index layout after LEChain's: `[…, agency…, court]`.
struct BdemsRoles;

impl BdemsRoles {
    const AGENCY: usize = Roles::END;
    const COURT: usize = Self::AGENCY + AGENCIES;
    const END: usize = Self::COURT + 1;

    fn agency(actor: u32) -> usize {
        Self::AGENCY + actor as usize % AGENCIES
    }
}

/// One item as B-DEMS holds it, with the transactions later steps wait on.
struct BdemsItem {
    eid: Word,
    h_enc: Word,
    sender: usize,
    provider: usize,
    voluntary: bool,
    txa: usize,
    txb: usize,
    /// Agencies whose access a `TxD` has approved, and the registering Sender.
    approved: std::collections::BTreeSet<usize>,
    /// A transfer's `TxC`, waiting for the receipt's `TxD`.
    open_txc: Option<(usize, Word)>,
}

/// Builds B-DEMS's transactions for a stream, event by event
/// (`baselines/UPGRADES.md`, "B-DEMS in Exp. 1"):
///
/// | event | B-DEMS |
/// |---|---|
/// | `COLLECT` | `TxA` (Sender + Provider, or Sender + Court) and `TxB` (Court) |
/// | `SEAL` | `TxA.Completed`, recording `H(E′)` |
/// | `TRANSFER` release / receipt | `TxC` by the receiving agency / `TxD` by the Sender |
/// | `ACCESS`, `ANALYZE`, `EXPORT` | `TxC` + `TxD` the first time an agency needs the item; none after, since its key was released |
/// | `DISPOSE` | `TxE`, then the confirmation hash |
struct BdemsPlan<'a> {
    chain: &'a mut Chain,
    providers: &'a [Key],
    contract: Address,
    items: HashMap<u32, BdemsItem>,
    /// Calls in issue order, signed only when [`BdemsPlan::sign`] runs: a
    /// call's gas is estimated once per shape, and in the warm-up a `TxB`
    /// estimated before its `TxA` is on chain would revert.
    calls: Vec<pqcl_exp::chain::Call>,
    deps: Vec<Vec<usize>>,
    /// Per stream event, the transactions it issued.
    of_event: Vec<Vec<usize>>,
}

/// B-DEMS's `Reason` for a disposal (Fig. 4).
const BDEMS_REASON: &str = "retention period expired";

impl BdemsPlan<'_> {
    fn push(
        &mut self,
        sender: usize,
        data: Vec<u8>,
        label: &'static str,
        deps: Vec<usize>,
    ) -> usize {
        self.calls.push((sender, data, label));
        self.deps.push(deps);
        self.calls.len() - 1
    }

    /// Sign call `i`, taking its sender's next nonce.
    fn sign(&mut self, i: usize) -> Res<pqcl_exp::chain::Prepared> {
        let (sender, data, label) = self.calls[i].clone();
        self.chain.prepare(sender, Some(self.contract), data, label)
    }

    /// `TxC` by `receiver`, then `TxD` by the item's Sender: one approved access.
    fn share(&mut self, capsule: u32, receiver: usize, purpose: Word) -> Res<Vec<usize>> {
        let c = self.txc(capsule, receiver, purpose)?;
        let d = self.txd(capsule)?;
        Ok(vec![c, d])
    }

    fn txc(&mut self, capsule: u32, receiver: usize, purpose: Word) -> Res<usize> {
        let it = self.items.get(&capsule).ok_or("TxC before TxA")?;
        let (eid, txa) = (it.eid, it.txa);
        let reference = bdems::digest(
            "B-DEMS TxC",
            &[
                eid,
                purpose,
                address_word(&self.chain.keys[receiver].address),
            ],
        );
        let i = self.push(
            receiver,
            encode_call(
                "requestShare(bytes32,bytes32)",
                &[Abi::Word(eid), Abi::Word(purpose)],
            ),
            "requestShare",
            vec![txa],
        );
        let it = self.items.get_mut(&capsule).ok_or("item lost")?;
        it.open_txc = Some((i, reference));
        it.approved.insert(receiver);
        Ok(i)
    }

    fn txd(&mut self, capsule: u32) -> Res<usize> {
        let it = self.items.get_mut(&capsule).ok_or("TxD before TxA")?;
        let (txc, reference) = it.open_txc.take().ok_or("TxD with no open TxC")?;
        let (sender, provider, voluntary, txb) = (it.sender, it.provider, it.voluntary, it.txb);
        let d = bdems::digest("B-DEMS TxD", &[reference]);
        let mut sigs = bdems::sig(&self.chain.keys[sender], &d)?;
        if voluntary {
            sigs.extend(bdems::sig(&self.providers[provider], &d)?);
        }
        let label = if voluntary {
            "approveShare (voluntary)"
        } else {
            "approveShare (compulsory)"
        };
        Ok(self.push(
            sender,
            encode_call(
                "approveShare(bytes32,bytes)",
                &[Abi::Word(reference), Abi::Bytes(sigs)],
            ),
            label,
            vec![txc, txb],
        ))
    }

    /// The transactions event `i` issues.
    #[allow(clippy::too_many_lines)]
    fn event(
        &mut self,
        e: &CustodyEvent,
        i: usize,
        receiver_of: &HashMap<(u32, u32), u32>,
    ) -> Res<Vec<usize>> {
        let tag = |t: &[u8]| keccak256(&[t, &e.capsule.to_le_bytes()].concat());
        Ok(match e.event {
            Event::Collect => {
                let sender = BdemsRoles::agency(e.actor);
                let provider = e.capsule as usize % PROVIDERS;
                let voluntary = e.capsule.is_multiple_of(2);
                // H = SHA-256(E) is the identifier; H(E′) of its ciphertext.
                let eid: Word = Sha256::digest(material(b"bdems E", e.capsule as usize, 64)).into();
                let h_enc: Word =
                    Sha256::digest(material(b"bdems E'", e.capsule as usize, 64)).into();
                let meta = tag(b"bdems M");
                let provider_addr = self.providers[provider].address;
                let d = bdems::digest(
                    "B-DEMS TxA",
                    &[
                        eid,
                        meta,
                        address_word(&provider_addr),
                        uint(u128::from(voluntary)),
                        address_word(&self.chain.keys[sender].address),
                    ],
                );
                let second = if voluntary {
                    &self.providers[provider]
                } else {
                    &self.chain.keys[BdemsRoles::COURT]
                };
                let sigs = [
                    bdems::sig(&self.chain.keys[sender], &d)?,
                    bdems::sig(second, &d)?,
                ]
                .concat();
                let label = if voluntary {
                    "registerEvidence (voluntary)"
                } else {
                    "registerEvidence (compulsory)"
                };
                let txa = self.push(
                    sender,
                    encode_call(
                        "registerEvidence(bytes32,bytes32,address,bool,bytes)",
                        &[
                            Abi::Word(eid),
                            Abi::Word(meta),
                            Abi::Word(address_word(&provider_addr)),
                            Abi::Word(uint(u128::from(voluntary))),
                            Abi::Bytes(sigs),
                        ],
                    ),
                    label,
                    Vec::new(),
                );
                let policy = tag(b"bdems policy");
                let sig = bdems::sig(
                    &self.chain.keys[BdemsRoles::COURT],
                    &bdems::digest("B-DEMS TxB", &[eid, policy]),
                )?;
                let txb = self.push(
                    BdemsRoles::COURT,
                    encode_call(
                        "approveRegistration(bytes32,bytes32,bytes)",
                        &[Abi::Word(eid), Abi::Word(policy), Abi::Bytes(sig)],
                    ),
                    "approveRegistration",
                    vec![txa],
                );
                self.items.insert(
                    e.capsule,
                    BdemsItem {
                        eid,
                        h_enc,
                        sender,
                        provider,
                        voluntary,
                        txa,
                        txb,
                        approved: std::iter::once(sender).collect(),
                        open_txc: None,
                    },
                );
                vec![txa, txb]
            }
            Event::Seal => {
                let it = self.items.get(&e.capsule).ok_or("SEAL before COLLECT")?;
                let (sender, eid, h_enc) = (it.sender, it.eid, it.h_enc);
                vec![self.push(
                    sender,
                    encode_call(
                        "completeRegistration(bytes32,bytes32)",
                        &[Abi::Word(eid), Abi::Word(h_enc)],
                    ),
                    "completeRegistration",
                    Vec::new(),
                )]
            }
            Event::Transfer if !e.receipt => {
                let to = *receiver_of
                    .get(&(e.capsule, e.seq + 1))
                    .ok_or("a release with no receipt after it")?;
                vec![self.txc(
                    e.capsule,
                    BdemsRoles::agency(to),
                    tag(&[b"transfer".as_slice(), &i.to_le_bytes()].concat()),
                )?]
            }
            Event::Transfer => vec![self.txd(e.capsule)?],
            Event::Access | Event::Analyze | Event::Export => {
                let a = BdemsRoles::agency(e.actor);
                let it = self.items.get(&e.capsule).ok_or("access before COLLECT")?;
                if it.approved.contains(&a) {
                    Vec::new()
                } else {
                    self.share(
                        e.capsule,
                        a,
                        tag(&[b"access".as_slice(), &i.to_le_bytes()].concat()),
                    )?
                }
            }
            Event::Dispose => {
                let it = self.items.get(&e.capsule).ok_or("DISPOSE before COLLECT")?;
                let (sender, eid, h_enc) = (it.sender, it.eid, it.h_enc);
                let ts = 1_700_000_000 + i as u128;
                let txe_digest = keccak256(&abi_encode(&[
                    Abi::Word(eid),
                    Abi::Word(address_word(&self.chain.keys[sender].address)),
                    Abi::Word(keccak256(BDEMS_REASON.as_bytes())),
                    Abi::Word(uint(ts)),
                ]));
                let conf: Word = Sha256::new()
                    .chain_update(txe_digest)
                    .chain_update(h_enc)
                    .finalize()
                    .into();
                let txe = self.push(
                    sender,
                    encode_call(
                        "requestDestruction(bytes32,string,uint64)",
                        &[
                            Abi::Word(eid),
                            Abi::Bytes(BDEMS_REASON.as_bytes().to_vec()),
                            Abi::Word(uint(ts)),
                        ],
                    ),
                    "requestDestruction",
                    Vec::new(),
                );
                // Algorithm 3: the off-chain copy is destroyed once TxE is on
                // chain, and only then is the confirmation written.
                let confirm = self.push(
                    sender,
                    encode_call(
                        "confirmDestruction(bytes32,bytes32)",
                        &[Abi::Word(eid), Abi::Word(conf)],
                    ),
                    "confirmDestruction",
                    vec![txe],
                );
                vec![txe, confirm]
            }
        })
    }
}

/// The receipt record's actor for every release, keyed by the receipt's
/// position: a release names no receiver, its paired receipt does.
fn receivers(stream: &[CustodyEvent]) -> HashMap<(u32, u32), u32> {
    stream
        .iter()
        .filter(|e| e.event == Event::Transfer && e.receipt)
        .map(|e| ((e.capsule, e.seq), e.actor))
        .collect()
}

/// B-DEMS over the stream: every event's transactions, submitted as fast as
/// the network takes them, each held back only until the other accounts'
/// transactions it builds on are included, and signed only then
/// ([`pqcl_exp::chain::submit_when_ready`]).
#[allow(clippy::too_many_lines)]
fn run_bdems(
    chain: &mut Chain,
    w: &Watcher,
    stream: &[CustodyEvent],
    providers: &[Key],
) -> Res<serde_json::Value> {
    let code = artifact_bytecode("contracts/out/BDems.sol/BDems.json")?;
    let code_len = code.len();
    let deploy = chain.prepare(0, None, code, "deploy")?;
    let deploy_r = chain.send_and_wait(&deploy, w)?;
    let contract = contract_address(&deploy_r)?;
    let mut grants = Vec::new();
    for k in BdemsRoles::AGENCY..BdemsRoles::COURT {
        let a = chain.keys[k].address;
        grants.push(chain.prepare(
            0,
            Some(contract),
            encode_call("grantSender(address)", &[Abi::Word(address_word(&a))]),
            "deploy",
        )?);
    }
    let court = chain.keys[BdemsRoles::COURT].address;
    grants.push(chain.prepare(
        0,
        Some(contract),
        encode_call("grantCourt(address)", &[Abi::Word(address_word(&court))]),
        "deploy",
    )?);
    let grant_hashes: Vec<String> = grants.iter().map(|p| p.hash.clone()).collect();
    pqcl_exp::chain::send_raw(chain, &grants.iter().collect::<Vec<_>>())?;
    w.wait_all(&grant_hashes)?;
    chain.receipts(&grant_hashes)?;

    let receiver_of = receivers(stream);
    let mut plan = BdemsPlan {
        chain,
        providers,
        contract,
        items: HashMap::new(),
        calls: Vec::new(),
        deps: Vec::new(),
        of_event: Vec::new(),
    };
    // Warm-up, not measured: one voluntary and one compulsory item through
    // every step, each included before the next is estimated, so every call
    // shape has its gas limit before the stream is prepared (a TxB estimated
    // before its TxA is on chain would revert in the estimate). Capsule
    // indices past the stream's, so they never collide with it.
    let base = u32::try_from(stream.len())? + 1_000_000;
    for (k, kind) in [(base, 0u32), (base + 1, 1)] {
        let warm = [
            CustodyEvent {
                capsule: k,
                seq: 0,
                event: Event::Collect,
                actor: kind,
                receipt: false,
            },
            CustodyEvent {
                capsule: k,
                seq: 1,
                event: Event::Seal,
                actor: kind,
                receipt: false,
            },
            CustodyEvent {
                capsule: k,
                seq: 2,
                event: Event::Access,
                actor: kind + 1,
                receipt: false,
            },
            CustodyEvent {
                capsule: k,
                seq: 3,
                event: Event::Dispose,
                actor: kind,
                receipt: false,
            },
        ];
        for (j, e) in warm.iter().enumerate() {
            for t in plan.event(e, j, &receiver_of)? {
                let p = plan.sign(t)?;
                plan.chain.send_and_wait(&p, w)?;
            }
        }
    }
    plan.calls.clear();
    plan.deps.clear();

    let t = Instant::now();
    for (i, e) in stream.iter().enumerate() {
        let issued = plan.event(e, i, &receiver_of)?;
        plan.of_event.push(issued);
    }
    let prepare = t.elapsed();
    let BdemsPlan {
        calls,
        deps,
        of_event,
        chain,
        ..
    } = plan;

    let (txs, submitted) = pqcl_exp::chain::submit_when_ready(chain, w, contract, &calls, &deps)?;
    let hashes: Vec<String> = txs.iter().map(|p| p.hash.clone()).collect();
    let committed = match w.wait_all(&hashes) {
        Ok(c) => c,
        Err(e) => return Err(format!("{e}\n{}", stuck(chain, w, &txs)).into()),
    };
    let receipts = chain.receipts(&hashes)?;
    let gases = receipts.iter().map(gas).collect::<Res<Vec<u64>>>()?;
    let labels: Vec<&'static str> = txs.iter().map(|p| p.label).collect();
    let span = committed
        .iter()
        .map(|(c, _)| *c)
        .max()
        .zip(submitted.iter().min())
        .map_or(Duration::ZERO, |(last, first)| {
            last.saturating_duration_since(*first)
        });
    let blocks: std::collections::BTreeSet<u64> = committed.iter().map(|(_, b)| *b).collect();
    // An event's commit: its last transaction included, from its first sent.
    let mut event_latency = Vec::new();
    let mut by_event: BTreeMap<String, (usize, usize, u64)> = BTreeMap::new();
    for (e, issued) in stream.iter().zip(&of_event) {
        let row = by_event.entry(format!("{:?}", e.event)).or_default();
        row.0 += 1;
        row.1 += issued.len();
        row.2 += issued.iter().map(|t| gases[*t]).sum::<u64>();
        if let (Some(first), Some(last)) = (
            issued.iter().map(|t| submitted[*t]).min(),
            issued.iter().map(|t| committed[*t].0).max(),
        ) {
            event_latency.push(last.saturating_duration_since(first));
        }
    }
    let without = of_event.iter().filter(|v| v.is_empty()).count();
    Ok(serde_json::json!({
        "contract_bytes": code_len,
        "deploy_gas": gas(&deploy_r)?,
        "roles": {"agencies": AGENCIES, "courts": 1, "providers": PROVIDERS},
        "collection_method": "voluntary for an even capsule index (TxA and TxD signed by Sender and Provider), compulsory for an odd one (TxA by Sender and Court, TxD by the Sender)",
        "client_prepare_total_ns": prepare.as_nanos(),
        "gas_by_transaction": summarise_by_label(&labels, &gases),
        "by_event": by_event.into_iter().map(|(k, (n, t, g))| (k, serde_json::json!({"events": n, "transactions": t, "gas": g}))).collect::<BTreeMap<_, _>>(),
        "gas_total": gases.iter().sum::<u64>(),
        "transactions": txs.len(),
        "events_without_transaction": without,
        "pipelined": {
            "events": stream.len(),
            "transactions": txs.len(),
            "window_per_sender": WINDOW,
            "first_submit_to_last_commit_ns": span.as_nanos(),
            "blocks": blocks.len(),
            "event_commit_latency_ns": Summary::of(&event_latency),
            "commit_latency_ns": Summary::of(&latencies(&submitted, &committed)),
        },
    }))
}

// ---------------------------------------------------------------- ours

struct Ours {
    cast: Cast,
    keys: CaseKeys,
    /// The Court Authority, a key of its own (design §12.2). It signs one sweep
    /// order per epoch that disposes anything (§1v.4).
    court: SoftwareMlDsa,
}

/// Validity of a harness order. Its `ts` is wall-clock, since the contract
/// checks `exp` against the block timestamp.
const ORDER_TTL_S: u64 = 30 * 24 * 3600;

/// Tier 1 → Tier 2 for this epoch: extend the capsule's chain in the AIS, or
/// hand the AIS the capsule with its first record of the epoch.
fn file_record(
    ais: &mut Ais,
    in_ais: &mut HashMap<u32, usize>,
    capsules: &HashMap<u32, Capsule>,
    capsule: u32,
    record: CustodyRecord,
) -> Res<()> {
    // The AIS files by `eid_e`, so the capsule index is not an argument any
    // more (M13 A20). `in_ais` still tracks which capsules the server holds,
    // which is what decides accept-versus-append.
    match in_ais.entry(capsule) {
        std::collections::hash_map::Entry::Occupied(_) => ais.append(record),
        std::collections::hash_map::Entry::Vacant(slot) => {
            let c = capsules.get(&capsule).cloned().ok_or("capsule lost")?;
            slot.insert(ais.len());
            ais.accept(c, record);
        }
    }
    Ok(())
}

/// Receipt gas of every `orderRedaction` the anchoring worker sent.
fn order_gas(chain: &Chain, w: &Watcher, sent: &[Sent]) -> Res<Vec<u64>> {
    let hashes: Vec<String> = sent.iter().filter_map(|a| a.order_hash.clone()).collect();
    w.wait_all(&hashes)?;
    chain.receipts(&hashes)?.iter().map(gas).collect()
}

/// Phase 11 at epoch close: the court signs one sweep order over the epoch's
/// disposals, and its `0x05` leaf joins this epoch's root. `None` if the epoch
/// disposed nothing.
fn sweep_order(
    o: &Ours,
    order_id: Digest32,
    disposing: &mut Vec<Digest32>,
    ais: &mut Ais,
) -> Res<Option<Order>> {
    if disposing.is_empty() {
        return Ok(None);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let order = Order::issue(
        &o.court,
        order_id,
        Target::new(disposing).root(),
        Scope::Full,
        Mode::Erased,
        now,
        now + ORDER_TTL_S,
    )?;
    ais.record_order(&order);
    disposing.clear();
    Ok(Some(order))
}

/// The epoch's sweep-order id: fixed when the epoch opens, so every `DISPOSE`
/// in it can reference the order the court signs at close.
fn epoch_order_id(cid_c: &Digest32, epoch: usize) -> Digest32 {
    digest256(
        &[
            cid_c.as_slice(),
            b"sweep order",
            &(epoch as u64).to_le_bytes(),
        ]
        .concat(),
    )
}

/// Seal the capsule a `COLLECT` opens, through the builder's appender — so the
/// first responder that signs it is the one whose `COLLECT` opens its chain
/// (M13 A18). Everything after it is [`CaseBuilder`]'s, which names each
/// event's role from draft8's table and routes a `TRANSFER` pair through
/// `handoff` (M13 A2/A14).
fn seal_for(build: &CaseBuilder<'_>, capsule: u32, epoch: u64) -> Res<Capsule> {
    let nonce = digest256(&capsule.to_le_bytes());
    build.seal(
        nonce,
        hash_domain(Domain::PlaintextCommit, &[&nonce]),
        hash_domain(Domain::EvidenceDigest, &[&nonce]),
        b"disk-image",
        b"s3://evidence/capsule",
        epoch,
    )
}

/// File one record's custody tokens, refusing a count other than the 29 draft8
/// Phase 6 Step 4 indexes — an appender that indexed fewer would understate the
/// ingest cost this experiment measures.
fn file_tokens(edb: &mut HonestEdb, tokens: &[pqcl_dsse::core::UpdateToken]) -> Res<()> {
    if tokens.len() != CUSTODY_KEYWORDS_PER_RECORD {
        return Err(format!(
            "a record came back with {} custody tokens, not {CUSTODY_KEYWORDS_PER_RECORD}",
            tokens.len()
        )
        .into());
    }
    for t in tokens {
        edb.insert(t);
    }
    Ok(())
}

/// Close the open epoch and package it for the anchoring worker.
///
/// ⭐ **One server across every epoch, since A20.** The ingest loop used to
/// replace the `Ais` here, which re-appended every touched capsule's `0x01`
/// seal leaf into the next epoch's MMR — a capsule sealed once, anchored
/// repeatedly. `close_epoch` advances the epoch and keeps the capsule store, so
/// a seal leaf is anchored exactly once and an epoch's leaves are the `0x02`s
/// it earns.
fn close_epoch_job(
    o: &Ours,
    order_id: Digest32,
    disposing: &mut Vec<Digest32>,
    ais: &mut Ais,
    records: usize,
) -> Res<Job> {
    let order = sweep_order(o, order_id, disposing, ais)?;
    let root = ais.close_epoch();
    let closed = ais
        .closed_epochs()
        .last()
        .ok_or("the epoch did not close")?;
    let leaves = closed.count;
    let leaf_digests = closed.leaf_digests().to_vec();
    Ok(Job {
        root,
        leaves,
        leaf_digests,
        entries: usize::try_from(leaves).unwrap_or(usize::MAX),
        records,
        closed: Instant::now(),
        order,
    })
}

/// An epoch closed by the ingest thread, handed to the anchoring worker.
struct Job {
    root: [u8; 32],
    /// `n_e` — **this epoch's own** leaf count (M13 A21). It used to be a
    /// running total across the case, which is what made case size public
    /// (`audit/07` D2); it is committed inside `d_e` and is not on chain.
    leaves: u64,
    /// The epoch's Tier-2 leaf digests, which each approving custodian bags
    /// itself before signing (M13 A5, `eq:validcp`).
    leaf_digests: Vec<Digest32>,
    entries: usize,
    records: usize,
    closed: Instant,
    /// The epoch's sweep order, if it disposed anything. Submitted before the
    /// epoch's anchor: Phase 11 records the order before deletion.
    order: Option<Order>,
}

/// An anchor the worker submitted.
struct Sent {
    hash: String,
    tx_bytes: usize,
    closed: Instant,
    submitted: Instant,
    entries: usize,
    records: usize,
    /// The `M` ML-DSA-65 approvals of `d_e`, then the SLH-DSA co-signature:
    /// the mechanism behind the anchoring cadence, recorded rather than
    /// inferred.
    sign: Duration,
    cosign: Duration,
    /// Bytes of the approval set: the audit package's share, never on chain.
    approval_bytes: usize,
    /// The epoch's `orderRedaction` transaction, if any.
    order_hash: Option<String>,
}

/// draft8 Phase 7 Step 3: `M` of `N` registered custodians approve each
/// checkpoint with independent ML-DSA-65 signatures; the co-signer adds
/// SLH-DSA. draft8 fixes no values; 2-of-3 is the smallest committee in which
/// approval is a quorum rather than one key, named here before measuring
/// (rule 21).
const APPROVERS_M: u32 = 2;
const CUSTODIANS_N: usize = 3;

/// ⭐ Anchoring **off the ingest path**, as the AIS does it: its own thread,
/// its own account and nonce, its own signers.
///
/// The first smoke run signed and submitted inline, and every extra epoch cost
/// the ingest thread ~2.6 s — SLH-DSA-SHAKE-192s signing, the `s` variant's
/// deliberate trade of signing time for size. That measured the harness, not
/// the design, so it was fixed before anything was compared. What remains in
/// our commit latency is real: an event waits for its epoch to close, for the
/// co-signature, and for a block.
///
/// ⭐ **M12: `workers` co-signing threads,
/// submission in epoch order.** At 10² entries per epoch campaign 03 closed an
/// epoch faster than one SLH-DSA-SHAKE-192s co-signature (median 2.55 s), so a
/// single worker capped anchoring near 32 records/s and epochs queued. The
/// parameter set is unchanged; signing is simply no longer serial. One AIS
/// identity: every worker signs with the same two keys.
struct Anchorer {
    url: String,
    chain_id: u64,
    anchor: Address,
    cid_c: [u8; 32],
    /// `ρ_c` of the cast that signs the stream's records (§1br F3).
    roster: Digest32,
    workers: usize,
}

/// An epoch approved and co-signed, awaiting in-order submission.
struct Signed {
    job: Job,
    /// `d_{e−1}` and `d_e` (`eq:checkpoint`).
    d_prev: Digest32,
    d_e: Digest32,
    /// `A_e = H(0x13 ‖ ⟪S_e, σ_SLH⟫)`.
    a_e: Digest32,
    approval_bytes: usize,
    sign: Duration,
    cosign: Duration,
}

/// The case's committee: the keys `reg` fixes before the first checkpoint.
struct Committee {
    reg: Registration,
    custodians: Vec<SoftwareMlDsa>,
    cosigner: CoSigner,
}

impl Committee {
    fn new(cid: Digest32, roster: Digest32) -> Result<Self, String> {
        let e = |x: &dyn core::fmt::Display| x.to_string();
        let ca = SoftwareMlDsa::generate().map_err(|x| e(&x))?;
        let kem = KeyPair::generate().map_err(|x| e(&x))?;
        let cosigner = CoSigner::generate().map_err(|x| e(&x))?;
        let custodians = (0..CUSTODIANS_N)
            .map(|_| SoftwareMlDsa::generate().map_err(|x| e(&x)))
            .collect::<Result<Vec<_>, _>>()?;
        let reg = Registration {
            cid,
            pk_sig: ca.public_key().to_vec(),
            pk_kem: kem.encapsulation_key().to_vec(),
            pk_slh: cosigner.public_key().to_vec(),
            custodians: custodians.iter().map(|c| c.public_key().to_vec()).collect(),
            m: APPROVERS_M,
            // Epochs here close by size, not by time: no period to register.
            delta: 0,
            roster,
        };
        Ok(Self {
            reg,
            custodians,
            cosigner,
        })
    }
}

impl Anchorer {
    /// `M` custodians approve `d_e` (ML-DSA-65), the co-signer adds SLH-DSA,
    /// and the set is reduced to `A_e`. Nothing signed goes on chain (D4).
    fn sign_job(
        job: Job,
        d_prev: Digest32,
        d_e: Digest32,
        valid: &[Validated],
        c: &Committee,
    ) -> Result<Signed, String> {
        let t = Instant::now();
        let approvals = (0..APPROVERS_M)
            .zip(valid)
            .map(|(j, v)| approve(&c.custodians[j as usize], j, v).map_err(|x| x.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let sign = t.elapsed();
        let t = Instant::now();
        let set = ApprovalSet::new(approvals, &c.cosigner, &d_e).map_err(|x| x.to_string())?;
        let cosign = t.elapsed();
        Ok(Signed {
            job,
            d_prev,
            d_e,
            a_e: set.digest(),
            approval_bytes: set.wire_bytes(),
            sign,
            cosign,
        })
    }

    fn run(self, jobs: std::sync::mpsc::Receiver<Job>) -> Result<Vec<Sent>, String> {
        let e = |x: &dyn core::fmt::Display| x.to_string();
        let rpc = Rpc::new(&self.url).map_err(|x| e(&x))?;
        let key =
            Key::from_secret(&keccak256(b"exp6chain anchoring authority")).map_err(|x| e(&x))?;
        let committee = Committee::new(self.cid_c, self.roster)?;
        let reg = committee.reg.digest();
        let first_nonce = rpc
            .call(
                "eth_getTransactionCount",
                serde_json::json!([to_hex(&key.address), "pending"]),
            )
            .and_then(|v| quantity(&v))
            .map_err(|x| e(&x))?;
        // Phase 1 Step 3: register the case once, before the first checkpoint.
        let data = encode_call(
            "registerCase(bytes32,bytes32)",
            &[Abi::Word(self.cid_c), Abi::Word(reg)],
        );
        let reg_limit = Self::limit(&rpc, &key, self.anchor, &data, &mut None)?;
        self.send(&rpc, &key, first_nonce, reg_limit, data)?;
        let first_nonce = first_nonce + 1;
        // The work queue: jobs numbered in arrival (= epoch) order, each
        // checkpoint chained to the one before (d_{-1} = reg), and each
        // approving custodian's own view of that chain (M13 A5).
        let views: Vec<ChainView> = (0..APPROVERS_M)
            .map(|_| ChainView::new(self.cid_c, reg))
            .collect();
        let queue = std::sync::Mutex::new((jobs, 0u64, reg, views));
        let cid_c = self.cid_c;
        std::thread::scope(|scope| {
            let (done_tx, done_rx) = std::sync::mpsc::channel::<(u64, Signed)>();
            let handles: Vec<_> = (0..self.workers.max(1))
                .map(|_| {
                    let (queue, committee, done_tx) = (&queue, &committee, done_tx.clone());
                    scope.spawn(move || -> Result<(), String> {
                        loop {
                            // Held across `recv`, so exactly one idle worker
                            // waits for the next epoch and numbering is exact.
                            // d_e is one hash over d_{e-1}, computed here in
                            // epoch order; the signing below stays parallel.
                            //
                            // ⭐ **And each custodian validates here, in order**
                            // (M13 A5): recompute `R_e` and `n_e` from the
                            // leaves, check `d_{e-1}` against what it last
                            // approved, then hand the worker a `Validated` to
                            // sign. Validation must be in epoch order or the
                            // link check means nothing; signing need not be.
                            let next = {
                                let mut q = queue.lock().map_err(|_| "anchoring queue poisoned")?;
                                let k = q.1;
                                let prev = q.2;
                                match q.0.recv() {
                                    Err(_) => None,
                                    Ok(job) => {
                                        let d = checkpoint::checkpoint(
                                            &cid_c, k, &job.root, job.leaves, &prev,
                                        );
                                        let proposal = Proposal {
                                            cid: cid_c,
                                            e: k,
                                            root: job.root,
                                            n_e: job.leaves,
                                            d_prev: prev,
                                            d_e: d,
                                            over: Committed::Epoch(&job.leaf_digests),
                                        };
                                        let valid =
                                            q.3.iter_mut()
                                                .map(|v| {
                                                    v.validate(&proposal).map_err(|x| x.to_string())
                                                })
                                                .collect::<Result<Vec<_>, _>>()?;
                                        q.1 += 1;
                                        q.2 = d;
                                        Some((k, job, prev, d, valid))
                                    }
                                }
                            };
                            let Some((k, job, prev, d, valid)) = next else {
                                return Ok(());
                            };
                            let signed = Self::sign_job(job, prev, d, &valid, committee)?;
                            done_tx
                                .send((k, signed))
                                .map_err(|_| "the submitter stopped")?;
                        }
                    })
                })
                .collect();
            drop(done_tx);
            let out = self.submit_in_order(&rpc, &key, first_nonce, &done_rx);
            for h in handles {
                h.join()
                    .map_err(|_| "a co-signing worker panicked".to_owned())??;
            }
            let out = out?;
            let expected = queue.lock().map_err(|_| "anchoring queue poisoned")?.1;
            if out.len() as u64 != expected {
                return Err(format!(
                    "{expected} epochs closed but {} anchored",
                    out.len()
                ));
            }
            Ok(out)
        })
    }

    /// Submit signed epochs strictly in epoch order, one nonce each, however
    /// the workers finish.
    fn submit_in_order(
        &self,
        rpc: &Rpc,
        key: &Key,
        first_nonce: u64,
        done: &std::sync::mpsc::Receiver<(u64, Signed)>,
    ) -> Result<Vec<Sent>, String> {
        let mut limit = None;
        let mut order_limit = None;
        let mut nonce = first_nonce;
        let mut out = Vec::new();
        let mut pending: std::collections::BTreeMap<u64, Signed> =
            std::collections::BTreeMap::new();
        let mut next = 0u64;
        for (k, signed) in done {
            pending.insert(k, signed);
            while let Some(Signed {
                job,
                d_prev,
                d_e,
                a_e,
                approval_bytes,
                sign,
                cosign,
            }) = pending.remove(&next)
            {
                next += 1;
                let order_hash = match &job.order {
                    Some(o) => {
                        let data = order_call(&self.cid_c, o);
                        let l = Self::limit(rpc, key, self.anchor, &data, &mut order_limit)?;
                        let (hash, _) = self.send(rpc, key, nonce, l, data)?;
                        nonce += 1;
                        Some(hash)
                    }
                    None => None,
                };
                let data = encode_call(
                    "commitRoot(bytes32,bytes32,bytes32,bytes32,bytes32)",
                    &[
                        Abi::Word(self.cid_c),
                        Abi::Word(job.root),
                        Abi::Word(d_prev),
                        Abi::Word(d_e),
                        Abi::Word(a_e),
                    ],
                );
                let gas_limit = Self::limit(rpc, key, self.anchor, &data, &mut limit)?;
                let (hash, tx_bytes) = self.send(rpc, key, nonce, gas_limit, data)?;
                nonce += 1;
                let submitted = Instant::now();
                out.push(Sent {
                    hash,
                    tx_bytes,
                    closed: job.closed,
                    submitted,
                    entries: job.entries,
                    records: job.records,
                    sign,
                    cosign,
                    approval_bytes,
                    order_hash,
                });
            }
        }
        if !pending.is_empty() {
            return Err(format!(
                "{} signed epochs never became submittable",
                pending.len()
            ));
        }
        Ok(out)
    }

    /// A gas limit for `data`, estimated once per call shape and cached.
    fn limit(
        rpc: &Rpc,
        key: &Key,
        to: Address,
        data: &[u8],
        cache: &mut Option<u64>,
    ) -> Result<u64, String> {
        if let Some(l) = *cache {
            return Ok(l);
        }
        let call = serde_json::json!({
            "from": to_hex(&key.address), "to": to_hex(&to), "data": to_hex(data),
        });
        let l = rpc
            .call("eth_estimateGas", serde_json::json!([call]))
            .and_then(|v| quantity(&v))
            .map_err(|x| x.to_string())?
            * GAS_MARGIN_PCT
            / 100;
        *cache = Some(l);
        Ok(l)
    }

    /// Sign and send one transaction to the anchor; its hash and size.
    fn send(
        &self,
        rpc: &Rpc,
        key: &Key,
        nonce: u64,
        gas_limit: u64,
        data: Vec<u8>,
    ) -> Result<(String, usize), String> {
        let raw = LegacyTx {
            nonce,
            gas_price: 0,
            gas_limit,
            to: Some(self.anchor),
            value: 0,
            data,
        }
        .sign(key, self.chain_id)
        .map_err(|x| x.to_string())?;
        let hash = to_hex(&keccak256(&raw));
        rpc.call("eth_sendRawTransaction", serde_json::json!([to_hex(&raw)]))
            .map_err(|x| x.to_string())?;
        Ok((hash, raw.len()))
    }
}

/// Our custody plane over the stream, one anchor per `epoch` **MMR leaves**.
fn run_ours(
    chain: &Chain,
    w: &Watcher,
    anchorer: Anchorer,
    stream: &[CustodyEvent],
    epoch: usize,
    o: &Ours,
) -> Res<(serde_json::Value, Backend)> {
    let (jobs, rx) = std::sync::mpsc::channel::<Job>();
    let workers = anchorer.workers;
    let worker = std::thread::spawn(move || anchorer.run(rx));
    // ⭐ The custody index is the appender's (M13 A18): each record comes back
    // with its 29 tokens, built under `K_S^COC` inside whichever Secure Module
    // built the record, and this loop only files them. It used to keep a
    // client of its own here, which in the enclave case would have meant the
    // index key leaving the boundary.
    let mut edb = HonestEdb::new();
    let mut capsules: HashMap<u32, Capsule> = HashMap::new();
    let appender = from_env(&o.cast, &o.keys)?;
    let backend = appender.backend();
    let mut build = CaseBuilder::new(&*appender, &o.keys);
    let mut ais = Ais::new();
    let mut in_ais: HashMap<u32, usize> = HashMap::new();
    let mut in_epoch = 0usize;
    // Reported in the record, never anchored: the on-chain data carries no
    // count at all since A21.
    let mut total_leaves = 0u64;
    let mut logged = Vec::with_capacity(stream.len());
    let mut epoch_of = Vec::with_capacity(stream.len());
    let mut epochs = 0usize;
    // Capsules disposed in the open epoch: one sweep order covers them all.
    let mut disposing: Vec<Digest32> = Vec::new();
    let start = Instant::now();

    for (i, e) in stream.iter().enumerate() {
        let order_id = epoch_order_id(&o.keys.cid_c, epochs);
        if e.event == Event::Collect {
            let c = seal_for(&build, e.capsule, epochs as u64)?;
            capsules.insert(e.capsule, c.clone());
            build.insert_capsule(e.capsule, c);
        }
        let appended = build.feed(e, 1_700_000_000 + i as u64, epochs as u64, Some(&order_id))?;
        if e.event == Event::Dispose {
            disposing.push(
                capsules
                    .get(&e.capsule)
                    .map(|c| c.eid)
                    .ok_or("capsule lost")?,
            );
        }
        // ⭐ **The custody plane's own index set, all 29 keywords** (M13 A2):
        // `{eid_e, evt, actor:⟪id, role⟫, role} ∪ anc(ts)`, built by
        // `pqcl_sm::tokens_for` inside the appender's call (M13 A18), so the
        // harness cannot drift from draft8's Phase 6 Step 4. It used to emit
        // **two** — the event name and `actor_c` — which both understated the
        // ingest cost and indexed a per-record commitment as if it were a
        // search term.
        file_tokens(&mut edb, &appended.tokens)?;
        file_record(
            &mut ais,
            &mut in_ais,
            &capsules,
            e.capsule,
            appended.signed.record,
        )?;
        logged.push(Instant::now());
        epoch_of.push(epochs);
        in_epoch += 1;

        // Leaves this epoch will hold once closed: the seal leaves already
        // appended plus one custody-root leaf per capsule it touched.
        // ⚠️ `open_segments`, not `len`: the server now keeps its capsules
        // across epochs, and a capsule with no activity this epoch adds no
        // `0x02` leaf (M13 A20).
        let pending = usize::try_from(ais.leaf_count()).unwrap_or(usize::MAX)
            + ais.open_segments()
            + usize::from(!disposing.is_empty());
        if pending >= epoch || i + 1 == stream.len() {
            let job = close_epoch_job(o, order_id, &mut disposing, &mut ais, in_epoch)?;
            total_leaves += job.leaves;
            jobs.send(job).map_err(|_| "the anchoring worker stopped")?;
            epochs += 1;
            in_epoch = 0;
        }
    }
    let ingest = start.elapsed();
    drop(jobs);
    let sent = worker
        .join()
        .map_err(|_| "the anchoring worker panicked")??;

    let hashes: Vec<String> = sent.iter().map(|a| a.hash.clone()).collect();
    let commits = w.wait_all(&hashes)?;
    let receipts = chain.receipts(&hashes)?;
    let gases = receipts.iter().map(gas).collect::<Res<Vec<u64>>>()?;
    let order_gas = order_gas(chain, w, &sent)?;
    let lat: Vec<Duration> = logged
        .iter()
        .zip(&epoch_of)
        .map(|(l, k)| commits[*k].0.saturating_duration_since(*l))
        .collect();
    let last = commits.iter().map(|(c, _)| *c).max().unwrap_or(start);
    let sign: Vec<Duration> = sent
        .iter()
        .map(|a| a.submitted.saturating_duration_since(a.closed))
        .collect();

    Ok((
        ours_record(&OursRun {
            epoch,
            sent: &sent,
            stream,
            gases: &gases,
            order_gas: &order_gas,
            capsules: capsules.len(),
            ingest,
            start,
            last,
            lat: &lat,
            sign: &sign,
            workers,
            total_leaves,
            commits: &commits,
        }),
        backend,
    ))
}

/// Everything one axis run measured, for its record.
struct OursRun<'a> {
    epoch: usize,
    sent: &'a [Sent],
    stream: &'a [CustodyEvent],
    gases: &'a [u64],
    order_gas: &'a [u64],
    capsules: usize,
    ingest: Duration,
    start: Instant,
    last: Instant,
    lat: &'a [Duration],
    sign: &'a [Duration],
    workers: usize,
    commits: &'a [(Instant, u64)],
    /// Leaves over the whole case. A statistic for the record, never anchored.
    total_leaves: u64,
}

fn ours_record(r: &OursRun<'_>) -> serde_json::Value {
    let (epoch, sent, stream, gases, order_gas) = (r.epoch, r.sent, r.stream, r.gases, r.order_gas);
    serde_json::json!({
        "epoch_size": epoch,
        "epochs": sent.len(),
        "entries_per_epoch": sent.iter().map(|a| a.entries).collect::<Vec<_>>(),
        "entries_are": "MMR leaves (0x01 seal + 0x02 custody root), §1l.2",
        "custody_keywords_per_record": CUSTODY_KEYWORDS_PER_RECORD,
        "custody_keywords_are": "{eid_e, evt, actor:⟪id, role⟫, role} ∪ anc(ts): draft8 Phase 6 Step 4, emitted from the library's own constant (M13 A2)",
        "total_leaves": r.total_leaves,
        "total_leaves_is": "the case's leaves summed across epochs, reported here and anchored nowhere: since M13 A21 the chain carries no count, cumulative or otherwise",
        "records_per_epoch": sent.iter().map(|a| a.records).collect::<Vec<_>>(),
        "records": stream.len(),
        "anchor_gas": gases,
        "gas_total": gases.iter().sum::<u64>(),
        "order_gas": order_gas,
        "order_gas_total": order_gas.iter().sum::<u64>(),
        "epochs_with_order": order_gas.len(),
        "disposed_capsules": stream.iter().filter(|e| e.event == Event::Dispose).count(),
        "capsules": r.capsules,
        "orders_are": "one FULL/ERASED sweep order per epoch that disposes anything; its 0x05 digest recorded by orderRedaction before that epoch's anchor (§1v.4, D4)",
        "anchor_is": "commitRoot(cid, R_e, d_prev, d_e, A_e): no signature and no leaf count on chain (D4 + M13 A21); n_e is committed in d_e and the approval set travels off chain",
        "approvers_m": APPROVERS_M,
        "custodians_n": CUSTODIANS_N,
        "approval_set_bytes": sent.first().map_or(0, |a| a.approval_bytes),
        "anchor_tx_bytes": sent.first().map_or(0, |a| a.tx_bytes),
        "ingest_total_ns": r.ingest.as_nanos(),
        "first_event_to_last_commit_ns": r.last.saturating_duration_since(r.start).as_nanos(),
        "commit_latency_ns": Summary::of(r.lat),
        "epoch_close_to_submit_ns": Summary::of(r.sign),
        "anchor_mldsa_sign_ns": Summary::of(&sent.iter().map(|a| a.sign).collect::<Vec<_>>()),
        "anchor_mldsa_sign_is": "the M custodian approvals of d_e, together",
        "anchor_slh_cosign_ns": Summary::of(&sent.iter().map(|a| a.cosign).collect::<Vec<_>>()),
        "anchoring_workers": r.workers,
        "anchor_submit_to_commit_ns": Summary::of(&latencies(
            &sent.iter().map(|a| a.submitted).collect::<Vec<_>>(),
            r.commits,
        )),
    })
}

/// Our side at every point of `tab:exp-anchor`'s axis, each on its own stream.
/// One axis: the cores-worker runs, the single-worker runs, the worker sweep,
/// and the one Secure Module all of them built through.
type AxisRuns = (
    Vec<serde_json::Value>,
    Vec<serde_json::Value>,
    Vec<serde_json::Value>,
    Backend,
);

fn run_axis(
    chain: &Chain,
    w: &Watcher,
    url: &str,
    chain_id: u64,
    anchor: Address,
    params: StreamParams,
) -> Res<AxisRuns> {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    // ⭐ Every run reports the Secure Module it actually built through, and the
    // axis is refused if they differ: one record, one boundary.
    let mut backends: Vec<Backend> = Vec::new();
    let mut ours = Vec::new();
    let mut single = Vec::new();
    let mut sweep = Vec::new();
    let steady = lechain_steady_capsules();
    for (k, epoch) in epoch_axis().into_iter().enumerate() {
        let axis_params = axis_params(epoch, params);
        let axis_stream = custody_stream(&axis_params);
        let lechain_capsules = lechain_capsules_for(epoch, steady);
        // Parallel co-signers (the table's configuration), then one worker,
        // kept beside it (§1o.2). Each run is its own case, which the
        // checkpoint chain requires: `d_e` links back to that case's own `reg`,
        // so two runs cannot share a `cid` without one of them failing to
        // extend the other's head. (Before M13 A21 the reason given here was
        // the anchor's monotonic leaf count; that check is gone, the link
        // remains, and the conclusion is unchanged.)
        let extra: Vec<usize> = if epoch == W_SWEEP_AT {
            W_SWEEP
                .iter()
                .copied()
                .filter(|&w| w > 1 && w < cores)
                .collect()
        } else {
            Vec::new()
        };
        let mut plan: Vec<(usize, String, u8)> =
            vec![(cores, String::new(), 0), (1, "-w1".to_owned(), 1)];
        plan.extend(extra.iter().map(|&w| (w, format!("-w{w}"), 2)));
        for (workers, label, which) in plan {
            let out = match which {
                0 => &mut ours,
                1 => &mut single,
                _ => &mut sweep,
            };
            let o = Ours {
                cast: Cast::generate()?,
                court: SoftwareMlDsa::generate()?,
                keys: CaseKeys::derive(
                    &PrfKey::new(digest256(b"K_mst (exp6chain)")),
                    format!("case-{k}{label}").as_bytes(),
                    &digest256(b"r_case"),
                ),
            };
            eprintln!(
                "ours: {epoch} leaves per epoch, {} records, {workers} co-signing worker(s)",
                axis_stream.len()
            );
            let anchorer = Anchorer {
                url: url.to_owned(),
                chain_id,
                anchor,
                cid_c: o.keys.cid_c,
                roster: o.cast.roster().digest(),
                workers,
            };
            let (mut run, backend) = run_ours(chain, w, anchorer, &axis_stream, epoch, &o)?;
            backends.push(backend);
            run["stream_params"] = serde_json::to_value(axis_params)?;
            // ⭐ The LEChain run this point's ratio divides by, and whether it
            // is this point's own stream (M13 A4). Before A4 every point was
            // divided by one LEChain run on a stream none of them ran, and the
            // record said `"same_stream": true`.
            run["lechain_stream_capsules"] = lechain_capsules.into();
            run["lechain_same_stream"] = (lechain_capsules == axis_params.capsules).into();
            out.push(run);
        }
    }
    let backend = *backends.first().ok_or("the axis ran nothing")?;
    if backends.iter().any(|b| *b != backend) {
        return Err(format!("one axis built through several Secure Modules: {backends:?}").into());
    }
    Ok((ours, single, sweep, backend))
}

/// Sweep sizes for `tab:exp-redaction`'s gas caption (§1v.5): one order over
/// `k` capsules. The order signs a Merkle root over its targets, so the claim
/// is that gas does not grow with `k`; two points test it.
const ORDER_K: &[usize] = &[1, 1_000];

/// Phase 11 Step 1 under D4: the order's **digest** goes on chain (its `0x05`
/// leaf), never `σ_CO`; the AIS and auditors verify the signature. Named under
/// its case, whose anchorer alone may record it (M13 A16).
fn order_call(cid: &Digest32, o: &Order) -> Vec<u8> {
    encode_call(
        "orderRedaction(bytes32,bytes32,bytes32)",
        &[
            Abi::Word(*cid),
            Abi::Word(o.oid),
            Abi::Word(o.leaf().digest),
        ],
    )
}

/// One `orderRedaction` per `k` on the same anchor and network as the axis,
/// each its receipt `gasUsed`.
fn orders_by_k(chain: &mut Chain, w: &Watcher, anchor: Address) -> Res<serde_json::Value> {
    let court = SoftwareMlDsa::generate()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // An order is recorded only by its case's anchorer (M13 A16), so this
    // account registers a case of its own first. The registration is setup,
    // not measured; the orders below then pay the anchorer check, as any real
    // order does.
    let cid = digest256(b"orders-by-k case");
    let reg = chain.prepare(
        0,
        Some(anchor),
        encode_call(
            "registerCase(bytes32,bytes32)",
            &[Abi::Word(cid), Abi::Word(digest256(b"orders-by-k reg"))],
        ),
        "registerCase",
    )?;
    chain.send_and_wait(&reg, w)?;
    let mut out = Vec::new();
    for &k in ORDER_K {
        let members: Vec<Digest32> = (0..k as u64)
            .map(|i| digest256(&[b"order-k capsule".as_slice(), &i.to_le_bytes()].concat()))
            .collect();
        let o = Order::issue(
            &court,
            digest256(&[b"order-k".as_slice(), &(k as u64).to_le_bytes()].concat()),
            Target::new(&members).root(),
            Scope::Full,
            Mode::Erased,
            now,
            now + ORDER_TTL_S,
        )?;
        let p = chain.prepare(0, Some(anchor), order_call(&cid, &o), "orderRedaction")?;
        let r = chain.send_and_wait(&p, w)?;
        out.push(serde_json::json!({"k": k, "gas": gas(&r)?, "tx_bytes": p.raw.len()}));
    }
    Ok(serde_json::json!({
        "orders": out,
        "config": "D4: the order's 0x05 leaf digest recorded on chain; sigma_CO verified by the AIS and auditors",
    }))
}

/// What the record says about the harness rather than the run.
fn static_record() -> serde_json::Value {
    let m = serde_json::json!({
        "lechain_source": {
            "repo": "github.com/SopmmmodII/LEChain",
            "commit": "159b5a7ec01b471409d1ee0799da52cbacc94fbf",
            "sha256": "a9767874785c8e166646f684e8c25b7b4ee209618efa1bd1ec62e9da7d36d4fa",
            "solc": "0.6.12", "evm_version": "istanbul", "optimizer": false,
        },
        "lechain_mapping": {
            "Collect": "orUpload", "Seal": "orStore", "Access": "orAccess",
            "Analyze": "orAccess", "Export": "orAccess", "Transfer": "orAccess (no handoff transition exists)",
            "Dispose": "orRejectUpload (its only deleting transition)",
        },
        "bdems_source": {
            "paper": "Park & Jeong, IP&M 63 (2026) 104654: Alg. 1-3, Figs. 2-4",
            "contract": "contracts/src/BDems.sol (no published code; ported to Solidity for our Besu)",
        },
        "bdems_mapping": {
            "Collect": "TxA (Sender + Provider or Sender + Court, ecrecover-checked) and TxB (Court)",
            "Seal": "TxA.Completed, recording H(E')",
            "Transfer": "release: TxC by the receiving agency; receipt: TxD by the registering Sender",
            "Access": "TxC + TxD the first time an agency needs the item, none after (its key was released)",
            "Analyze": "as Access", "Export": "as Access",
            "Dispose": "TxE, then the destruction confirmation once TxE is included",
            "direction": "events with no transaction favour B-DEMS (fewer transactions than LEChain's one per event); two transactions for COLLECT, a first access and DISPOSE count against it; both are its paper's workflow",
        },
        "method": {
            "gas_limit": "eth_estimateGas x 1.25 per call type, as web3.py (LEChain's client) estimates",
            "same_stream": "per axis point (M13 A4): each ours row names lechain_stream_capsules and lechain_same_stream; a point whose stream exceeds 10^4 capsules is compared with the 10^4-capsule run, LEChain's steady state",
            "same_network_and_client": true,
            "commit_time": format!("first observation of the including block by a watcher polling every {} ms", POLL.as_millis()),
            "ours_event_time": "when the record is signed, indexed and in the epoch tree; our client-side signing is before it, as LEChain's pre-signing is before its submission",
            "ours_anchoring": "an AIS worker thread with its own account signs (ML-DSA-65 + SLH-DSA co-signature) and submits each closed epoch while ingest continues",
            "rates": "not computed here; mkfigs divides events by the recorded span",
        },
    });
    m
}

#[allow(clippy::too_many_lines)]
fn main() -> Res<()> {
    let url = std::env::var("PQCL_RPC").unwrap_or_else(|_| "http://127.0.0.1:8545".to_owned());
    // Every run sets its own capsule count (an axis point's, or LEChain's), so
    // the base contributes only the stream's shape and seed. There is no
    // `PQCL_CUSTODY_CAPSULES` here any more: since M13 A4 nothing would read
    // the stream it used to size.
    let params = StreamParams::default();

    let rpc = Rpc::new(&url)?;
    let chain_id = quantity(&rpc.call("eth_chainId", serde_json::json!([]))?)?;
    let net = network(&rpc)?;
    // Account 0 is the funded dev key; the role keys are fresh and never need
    // funds — the network's minimum gas price is zero.
    let mut keys = vec![Key::from_secret(&from_hex(DEV_SECRET)?)?];
    for k in 1..Roles::END {
        keys.push(Key::from_secret(&keccak256(
            format!("exp6chain role {k}").as_bytes(),
        ))?);
    }
    for k in BdemsRoles::AGENCY..BdemsRoles::END {
        keys.push(Key::from_secret(&keccak256(
            format!("exp6chain B-DEMS account {k}").as_bytes(),
        ))?);
    }
    let providers = (0..PROVIDERS)
        .map(|k| {
            Key::from_secret(&keccak256(
                format!("exp6chain B-DEMS provider {k}").as_bytes(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut nonces = Vec::with_capacity(keys.len());
    for k in &keys {
        nonces.push(quantity(&rpc.call(
            "eth_getTransactionCount",
            serde_json::json!([to_hex(&k.address), "pending"]),
        )?)?);
    }
    let mut chain = Chain {
        rpc,
        id: chain_id,
        nonces,
        keys,
        limits: HashMap::new(),
    };
    let w = Watcher::start(&url)?;

    // ⭐ LEChain on every stream an axis point's ratio divides by (M13 A4):
    // each point's own up to 10⁴ capsules, and the 10⁴ steady state.
    let steady = lechain_steady_capsules();
    let mut lechain_streams: Vec<u32> = epoch_axis()
        .into_iter()
        .map(|e| lechain_capsules_for(e, steady))
        .chain(std::iter::once(steady))
        .collect();
    lechain_streams.sort_unstable();
    lechain_streams.dedup();
    let mut lechain_runs = Vec::new();
    let mut bdems_runs = Vec::new();
    for capsules in lechain_streams {
        let p = StreamParams {
            capsules,
            active: 64,
            ..params
        };
        let s = custody_stream(&p);
        eprintln!("LEChain: {capsules} capsules, {} transitions", s.len());
        let mut run = run_lechain(&mut chain, &w, &s)?;
        run["stream_capsules"] = capsules.into();
        run["stream_params"] = serde_json::to_value(p)?;
        run["events"] = s.len().into();
        run["counts"] = serde_json::to_value(event_counts(&s))?;
        lechain_runs.push(run);
        // ⭐ B-DEMS on the same stream, network and client (§1ci.1): its whole
        // custody workflow, each step the transaction its paper issues.
        eprintln!("B-DEMS: {capsules} capsules, {} events", s.len());
        let mut run = run_bdems(&mut chain, &w, &s, &providers)?;
        run["stream_capsules"] = capsules.into();
        run["stream_params"] = serde_json::to_value(p)?;
        run["events"] = s.len().into();
        run["counts"] = serde_json::to_value(event_counts(&s))?;
        bdems_runs.push(run);
    }

    // D4: the anchor takes no constructor arguments; no verifier, no keys.
    let init = artifact_bytecode("contracts/out/Anchor.sol/Anchor.json")?;
    let dep = chain.prepare(0, None, init, "deploy")?;
    let dep_r = chain.send_and_wait(&dep, &w)?;
    let anchor = contract_address(&dep_r)?;

    let (ours, ours_single_worker, ours_worker_sweep, backend) =
        run_axis(&chain, &w, &url, chain_id, anchor, params)?;
    let order_gas_by_k = orders_by_k(&mut chain, &w, anchor)?;
    let watcher_errors = w.error_count();
    w.finish()?;

    let mut measurements = serde_json::json!({
        "lechain_ceiling_inputs": {
            "gas_limit_margin_pct": GAS_MARGIN_PCT,
            "block_gas_limit": net["block_gas_limit"],
            "observed_block_period_ms": net["observed_block_period_ms"],
        },
        "network": net,
        "watcher_rpc_errors_retried": watcher_errors,
        "sync_retries": pqcl_exp::chain::SYNC_RETRIES.load(std::sync::atomic::Ordering::Relaxed),
        "rebroadcasts": pqcl_exp::chain::REBROADCASTS.load(std::sync::atomic::Ordering::Relaxed),
        "base_stream_params": params,
        "lechain_runs": lechain_runs,
        "bdems_runs": bdems_runs,
        "lechain_steady_state_capsules": steady,
        "ours": ours,
        "ours_single_worker": ours_single_worker,
        "ours_worker_sweep": ours_worker_sweep,
        "worker_sweep_note": "W between 1 and the host's cores at 10^2 entries per epoch (sec:ablation); W = 1 and W = cores at that point are in ours_single_worker and ours",
        "ours_anchor": {"contract": "contracts/src/Anchor.sol", "config": "D4 (digests only)", "deploy_gas": gas(&dep_r)?},
        "order_gas_by_k": order_gas_by_k,
    });
    if let (Some(m), serde_json::Value::Object(extra)) =
        (measurements.as_object_mut(), static_record())
    {
        m.extend(extra);
    }

    emit_custody(
        "exp6chain-custody-commit",
        RunSpec {
            liboqs_version: "ML-DSA-65 via liboqs".to_owned(),
            rng_seeds: vec![params.seed],
            ..RunSpec::default()
        },
        u32::try_from(SEQUENTIAL).unwrap_or(u32::MAX),
        measurements,
        backend,
    )?;
    Ok(())
}
