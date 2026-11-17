//! **SAC Experiment 4 — court-ordered redaction against B-DEMS and PQ-ABL**
//!
//!
//! **Job:** remove evidence on a court's instruction so that a court can later
//! tell lawful destruction from tampering. **Comparators:** B-DEMS (Park &
//! Jeong, IP&M 63, 2026, art. 104654), Algorithm 3 and Fig. 4, as
//! `contracts/src/BDems.sol`; and PQ-ABL (Fugkeaw et al., IEEE TCC 14(2), 2026),
//! whose deletion is our extension of its per-epoch design: remove the
//! ciphertexts, rebuild each epoch that held them, commit it again
//! (`contracts/src/PqablAnchor.sol`). All on the same four-validator Besu
//! network as our anchor, through the same client (`pqcl_exp::chain`).
//!
//! | | ours (SAC Phase 5, `Π_core` only) | B-DEMS | PQ-ABL |
//! |---|---|---|---|
//! | authority | the court's ML-DSA order, recorded by `orderRedaction` before anything is deleted | the Sender's whitelisted role | the logger |
//! | on chain | one `orderRedaction` and one `commitRoot` for the redaction epoch, whatever `k` | one `TxE` and one confirmation per evidence item | one commitment per epoch the deleted objects were in |
//! | erasure | `C_ev`; `Π_core` deletions under `PAYLOAD+INDEX` and `FULL`; `r_ev` by mode | one overwrite with random bytes, then unlink | the epoch rebuilt and re-packed without them |
//! | the court's check | `eq:validredact` (`verify_redaction`) | a `TxE` exists and the destruction hash matches | `Pqabl::judge`: the latest epoch re-validated against the original |
//!
//! # Measured (at least 10 iterations each)
//!
//! * **T1:** `k ∈ {1, 10, 10², 10³}` capsules under one `FULL`/`ERASED` order
//!   (ours) against `k` `TxE`s (B-DEMS) and one deletion of `k` capsules
//!   (PQ-ABL): total gas, and latency from the first step until erasure is
//!   complete and every on-chain record it needs is included.
//! * **F(a):** one capsule at every case size, ours under `PAYLOAD`,
//!   `PAYLOAD+INDEX` and `FULL`, B-DEMS, and PQ-ABL with the records its
//!   rebuild invalidates.
//! * **F(b):** the court's check on that redacted capsule at every case size,
//!   the local check and the chain read it needs, reported apart.
//! * **T2:** the accept/reject matrix, `100` trials per cell, each through the
//!   side's real verifier.
//! * **§1ci.6's labelled series:** the same case with every record in one
//!   sealing epoch, ours `FULL` and PQ-ABL only, F(a) at every size and T1 on
//!   the largest. Past 50,000 logs an epoch is beyond PQ-ABL's evaluated range
//!   (p. 15), and the record says so.
//!
//! # Fixed before measuring (rules 20 and 21)
//!
//! * **The case.** Custody's stream at each size (`PQCL_REDACT_SIZES`, the
//!   campaign passes c09a's), with no disposals, every record through the
//!   appender (the Nitro enclave on the campaign instance), in sealing epochs
//!   of 10⁴ records closed by count in stream order (§1ci.5 item 2), each
//!   anchored as it closes, before anything is timed. PQ-ABL's epochs are the
//!   same epochs.
//! * **Each capsule.** A 4 KiB artefact under a fresh `K_ev` (AES-256-GCM),
//!   chunked `d_ev` over the ciphertext, hiding `cm_ev` under a fresh `r_ev`,
//!   indexed on the evidence plane under 28 keywords: type, device, collector
//!   and the 25 range ancestors of its acquisition hour. B-DEMS stores the same
//!   ciphertext as `E′`, keyed by `SHA-256` of the artefact as its `EID`;
//!   PQ-ABL stores it as a log of the epoch it arrives in.
//! * **Which capsules.** A seeded shuffle; every redaction takes the next unused
//!   ones, so none is redacted twice, and T1's iterations hand every arm the
//!   same capsules.
//! * **Ours.** Each redaction is its own epoch `e′`, closed and anchored at once
//!   with `M = 2` of `N = 3` approvals and the SLH-DSA co-signature. In
//!   deployment the `0x02` and `0x05` leaves wait up to `Δ` for the epoch to
//!   close; that wait is excluded, and the order itself is on chain before the
//!   first deletion either way. The court's signing of the order is before the
//!   clock starts: B-DEMS and PQ-ABL have no counterpart.
//! * **B-DEMS.** One Sender account, all `k` `TxE`s submitted at once, then all
//!   `k` confirmations.
//! * **PQ-ABL.** One deletion per redaction, however many capsules: every
//!   affected epoch rebuilt once (across cores), committed again once.
//! * One warm-up destruction per arm per case is discarded, so gas estimation
//!   is never inside a timed call. T1 and T2 run on the largest case.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use baseline_pqabl as pqabl;
use pqcl_bench::{MIN_ITERATIONS, RunSpec};
use pqcl_capsule::redaction::{Mode, Order, Scope, Target};
use pqcl_capsule::{Capsule, Event};
use pqcl_dsse::core::{Client as CoreClient, DocId, Edb, HonestEdb, Op};
use pqcl_dsse::range::{Attribute, RangeTree};
use pqcl_exp::appender::{Discloser, from_env};
use pqcl_exp::bdems;
use pqcl_exp::case::CaseBuilder;
use pqcl_exp::cast::Cast;
use pqcl_exp::chain::{
    Chain, DEV_SECRET, Prepared, SYNC_RETRIES, Watcher, artifact_bytecode, contract_address, gas,
    network, send_raw, submit_pipelined,
};
use pqcl_exp::custody_stream::{CustodyEvent, StreamParams, custody_stream, event_counts};
use pqcl_exp::evm::{
    Abi, Address, Key, Word, abi_encode, address_word, encode_call, from_hex, keccak256, to_hex,
    uint,
};
use pqcl_exp::{emit_custody, stats::Summary};
use pqcl_pipeline::checkpoint::{
    ApprovalSet, ChainView, Committed, Proposal, Registration, approve, checkpoint,
};
use pqcl_pipeline::redaction::{
    AnchoredPayload, Openings, PayloadStore, Redactee, RedactionClaim, account, execute_core,
    verify_redaction,
};
use pqcl_pipeline::{Ais, CaseKeys, LeafRef, chunked};
use pqcl_primitives::xof::{Digest32, Domain, PrfKey, digest256};
use pqcl_primitives::{CoSigner, KeyPair, RecordKey, Signer, SoftwareMlDsa, rng};
use pqcl_sm::Backend;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{RngCore, SeedableRng};
use sha2::{Digest as _, Sha256};

type Res<T> = Result<T, Box<dyn core::error::Error>>;

/// Case sizes in records for a local run; `PQCL_REDACT_SIZES` overrides.
const DEFAULT_SIZES: &[usize] = &[1_000, 10_000];

/// As `custody`: records per capsule in tenths, to pick a capsule count.
const RECORDS_PER_CAPSULE_X10: usize = 86;

/// T1's sweep; `PQCL_REDACT_K` overrides for a smoke run.
const T1_K: &[usize] = &[1, 10, 100, 1_000];

/// T2's trials per cell; `PQCL_REDACT_TRIALS` overrides for a smoke run.
const TRIALS: usize = 100;

/// Bytes of each artefact.
const ARTEFACT_BYTES: usize = 4_096;

/// B-DEMS's `Reason` for a court-ordered destruction (Fig. 4, §3.4.1).
const REASON: &str = "court-ordered destruction";

/// The `Reason` T2's modified claim presents in place of [`REASON`].
const MODIFIED_REASON: &str = "retention period expired";

/// Validity of an order.
const ORDER_TTL_S: u64 = 30 * 24 * 3600;

/// `M` of `N` custodians approve each checkpoint, as `exp6chain`.
const APPROVERS_M: u32 = 2;
const CUSTODIANS_N: usize = 3;

/// Records per sealing epoch, closed by count in stream order (§1ci.5 item 2):
/// inside PQ-ABL's evaluated range of 1,000 to 50,000 logs per epoch (p. 15),
/// fixed before any measurement. `PQCL_CASE_EPOCH_RECORDS` overrides it for a
/// local smoke run, and the record says which ran.
const EPOCH_RECORDS: usize = 10_000;

/// PQ-ABL's largest evaluated epoch, in logs (p. 15, Fig. 7).
const PQABL_MAX_EVALUATED: usize = 50_000;

fn epoch_records() -> usize {
    std::env::var("PQCL_CASE_EPOCH_RECORDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(EPOCH_RECORDS)
}

/// Accounts that register B-DEMS evidence in setup, so a 10⁶-record case
/// registers in minutes. Destruction uses one Sender.
const REGISTRARS: usize = 16;

/// Chain key indices: the AIS (also deployer and B-DEMS governance), then
/// B-DEMS's Sender, then the registrars.
const AIS: usize = 0;
const SENDER: usize = 1;
/// PQ-ABL's logger, after the registrars.
const LOGGER: usize = SENDER + 1 + REGISTRARS;

/// Every random choice above.
const SEED: u64 = 0x05AC_0004;

/// Record clock origin.
const TS0: u64 = 1_700_000_000;

fn env_list(name: &str, default: &[usize]) -> Vec<usize> {
    std::env::var(name).map_or_else(
        |_| default.to_vec(),
        |s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
    )
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn summary(samples: &[Duration]) -> Res<serde_json::Value> {
    Ok(serde_json::to_value(Summary::of(samples))?)
}

fn median(v: &[u64]) -> u64 {
    let mut v = v.to_vec();
    v.sort_unstable();
    v.get(v.len() / 2).copied().unwrap_or_default()
}

/// The 28 evidence-plane keywords of capsule `c` acquired at `ts`.
fn evidence_keywords(c: u32, ts: u64) -> Res<Vec<Vec<u8>>> {
    let mut out = vec![
        b"type:disk-image".to_vec(),
        format!("dev:{}", c % 32).into_bytes(),
        format!("by:{}", c % 8).into_bytes(),
    ];
    let hour = Attribute::Timestamp
        .of_unix(ts)
        .ok_or("acquisition time outside the range tree's window")?;
    out.extend(RangeTree::profile(Attribute::Timestamp).index_keywords(hour));
    Ok(out)
}

/// Send signed transactions as fast as the node takes them: the operator's
/// path for a batch, no window.
fn send_all(chain: &Chain, txs: &[Prepared]) -> Res<()> {
    send_raw(chain, &txs.iter().collect::<Vec<_>>())
}

fn hashes(txs: &[Prepared]) -> Vec<String> {
    txs.iter().map(|p| p.hash.clone()).collect()
}

fn total_gas(chain: &Chain, txs: &[Prepared]) -> Res<u64> {
    chain.receipts(&hashes(txs))?.iter().map(gas).sum()
}

// ----------------------------------------------------------------- ours

/// The case's committee and its view of the checkpoint chain.
struct Committee {
    cid: Digest32,
    custodians: Vec<SoftwareMlDsa>,
    cosigner: CoSigner,
    views: Vec<ChainView>,
    d_prev: Digest32,
}

/// One epoch anchored.
struct Anchored {
    gas: u64,
    approve: Duration,
    cosign: Duration,
}

impl Committee {
    fn new(cid: Digest32, roster: Digest32) -> Res<(Self, Registration)> {
        let ca = SoftwareMlDsa::generate()?;
        let kem = KeyPair::generate()?;
        let cosigner = CoSigner::generate()?;
        let custodians = (0..CUSTODIANS_N)
            .map(|_| SoftwareMlDsa::generate())
            .collect::<Result<Vec<_>, _>>()?;
        let reg = Registration {
            cid,
            pk_sig: ca.public_key().to_vec(),
            pk_kem: kem.encapsulation_key().to_vec(),
            pk_slh: cosigner.public_key().to_vec(),
            custodians: custodians.iter().map(|c| c.public_key().to_vec()).collect(),
            m: APPROVERS_M,
            // Epochs here close per redaction, not by time.
            delta: 0,
            roster,
        };
        let d = reg.digest();
        Ok((
            Self {
                cid,
                custodians,
                cosigner,
                views: (0..APPROVERS_M).map(|_| ChainView::new(cid, d)).collect(),
                d_prev: d,
            },
            reg,
        ))
    }

    /// Close the AIS's open epoch, have it approved and co-signed, and sign
    /// its `commitRoot`.
    #[allow(clippy::many_single_char_names)]
    fn close_and_sign(
        &mut self,
        ais: &mut Ais,
        chain: &mut Chain,
        anchor: Address,
    ) -> Res<(Prepared, Duration, Duration)> {
        let root = ais.close_epoch();
        let closed = ais.closed_epochs().last().ok_or("no epoch closed")?;
        let d = checkpoint(&self.cid, closed.epoch, &root, closed.count, &self.d_prev);
        let proposal = Proposal {
            cid: self.cid,
            e: closed.epoch,
            root,
            n_e: closed.count,
            d_prev: self.d_prev,
            d_e: d,
            over: Committed::Epoch(closed.leaf_digests()),
        };
        let t = Instant::now();
        let valid = self
            .views
            .iter_mut()
            .map(|v| v.validate(&proposal))
            .collect::<Result<Vec<_>, _>>()?;
        let approvals = (0..APPROVERS_M)
            .zip(&valid)
            .map(|(j, v)| approve(&self.custodians[j as usize], j, v))
            .collect::<Result<Vec<_>, _>>()?;
        let approve_t = t.elapsed();
        let t = Instant::now();
        let set = ApprovalSet::new(approvals, &self.cosigner, &d)?;
        let cosign = t.elapsed();
        let data = encode_call(
            "commitRoot(bytes32,bytes32,bytes32,bytes32,bytes32)",
            &[
                Abi::Word(self.cid),
                Abi::Word(root),
                Abi::Word(self.d_prev),
                Abi::Word(d),
                Abi::Word(set.digest()),
            ],
        );
        let p = chain.prepare(AIS, Some(anchor), data, "commitRoot")?;
        self.d_prev = d;
        Ok((p, approve_t, cosign))
    }

    /// Close the AIS's open epoch and anchor it: the custodians recompute and
    /// approve, the co-signer signs, `commitRoot` is sent and included.
    fn anchor(
        &mut self,
        ais: &mut Ais,
        chain: &mut Chain,
        w: &Watcher,
        anchor: Address,
    ) -> Res<Anchored> {
        let (p, approve, cosign) = self.close_and_sign(ais, chain, anchor)?;
        let r = chain.send_and_wait(&p, w)?;
        Ok(Anchored {
            gas: gas(&r)?,
            approve,
            cosign,
        })
    }

    /// [`Committee::anchor`] for a sealing epoch, in setup: sent, not waited
    /// for. Anchors land in nonce order, so each still extends the last.
    fn anchor_nowait(&mut self, ais: &mut Ais, chain: &mut Chain, anchor: Address) -> Res<String> {
        let (p, ..) = self.close_and_sign(ais, chain, anchor)?;
        chain.send(&p)?;
        Ok(p.hash)
    }
}

/// A recorded order and where its leaf sits.
struct Recorded {
    order: Order,
    target: Target,
    at: LeafRef,
}

/// Our side of one case.
struct Ours<'a> {
    keys: &'a CaseKeys,
    build: CaseBuilder<'a>,
    court_view: Discloser<'a>,
    ais: Ais,
    /// Stream capsule index → the AIS's capsule index.
    slot: HashMap<u32, usize>,
    capsules: Vec<Capsule>,
    payloads: PayloadStore,
    openings: Openings,
    index: CoreClient,
    edb: HonestEdb,
    /// The custody plane's postings for every `DISPOSE`.
    coc: HonestEdb,
    keywords: Vec<Vec<Vec<u8>>>,
    court: SoftwareMlDsa,
    court_kem: KeyPair,
    committee: Committee,
    anchor: Address,
    orders: u64,
    ts: u64,
}

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

/// What the chain recorded under `oid`: the AIS's gate reads it there.
fn recorded_order(chain: &Chain, anchor: &Address, cid: &Digest32, oid: &Digest32) -> Res<Word> {
    let ret = chain.view(
        anchor,
        &encode_call(
            "recordedOrder(bytes32,bytes32)",
            &[Abi::Word(*cid), Abi::Word(*oid)],
        ),
    )?;
    Ok(ret
        .get(..32)
        .ok_or("recordedOrder returned no word")?
        .try_into()?)
}

impl Ours<'_> {
    fn next_oid(&mut self) -> Digest32 {
        self.orders += 1;
        digest256(&[b"sac exp4 order".as_slice(), &self.orders.to_le_bytes()].concat())
    }

    /// An order over `caps`, signed by the court or, for T2's insider, by
    /// `insider`.
    fn issue(
        &mut self,
        insider: Option<&SoftwareMlDsa>,
        caps: &[u32],
        scope: Scope,
    ) -> Res<(Order, Target)> {
        let eids: Vec<Digest32> = caps
            .iter()
            .map(|c| self.capsules[*c as usize].eid)
            .collect();
        let target = Target::new(&eids);
        let oid = self.next_oid();
        let now = now_s();
        let signer = insider.unwrap_or(&self.court);
        let o = Order::issue(
            signer,
            oid,
            target.root(),
            scope,
            Mode::Erased,
            now,
            now + ORDER_TTL_S,
        )?;
        Ok((o, target))
    }

    fn redactees(&self, caps: &[u32], target: &Target) -> Res<Vec<Redactee>> {
        caps.iter()
            .map(|c| {
                let eid = self.capsules[*c as usize].eid;
                Ok(Redactee {
                    eid,
                    doc: DocId::from(*c),
                    membership: target.prove(&eid).ok_or("capsule not in its target")?,
                    keywords: self.keywords[*c as usize].clone(),
                })
            })
            .collect()
    }

    /// Phase 5 Step 3: the `DISPOSE`, built in the Secure Module, indexed on
    /// the custody plane, filed in the open epoch.
    fn dispose(&mut self, c: u32, oid: &Digest32) -> Res<()> {
        let j = self.build.chain(c).ok_or("unknown capsule")?.len();
        let e = CustodyEvent {
            capsule: c,
            seq: u32::try_from(j)?,
            event: Event::Dispose,
            actor: 0,
            receipt: false,
        };
        self.ts += 1;
        let a = self.build.feed(&e, self.ts, self.ais.epoch(), Some(oid))?;
        for t in &a.tokens {
            self.coc.insert(t);
        }
        self.ais.append(a.signed.record);
        Ok(())
    }

    /// One honest redaction of `caps` at `scope`, timed from the
    /// `orderRedaction` submission to the redaction epoch's anchor included.
    fn redact(
        &mut self,
        chain: &mut Chain,
        w: &Watcher,
        caps: &[u32],
        scope: Scope,
    ) -> Res<(Duration, serde_json::Value, Recorded)> {
        let (order, target) = self.issue(None, caps, scope)?;
        let cid = self.keys.cid_c;
        let t0 = Instant::now();
        // Step 1: on chain before anything is deleted.
        let p = chain.prepare(
            AIS,
            Some(self.anchor),
            order_call(&cid, &order),
            "orderRedaction",
        )?;
        chain.send(&p)?;
        w.wait_all(std::slice::from_ref(&p.hash))?;
        let recorded = t0.elapsed();
        // Step 2: the gate reads what the chain recorded.
        let registry = HashMap::from([(
            order.oid,
            recorded_order(chain, &self.anchor, &cid, &order.oid)?,
        )]);
        let redactees = self.redactees(caps, &target)?;
        let out = execute_core(
            &order,
            self.court.public_key(),
            now_s(),
            &registry,
            &redactees,
            &self.payloads,
            &mut self.openings,
            self.court_kem.encapsulation_key(),
            &mut self.index,
            &mut self.edb,
        )?;
        let erased = t0.elapsed();
        for c in caps {
            self.dispose(*c, &order.oid)?;
        }
        let disposed = t0.elapsed();
        let at = self.ais.record_order(&order);
        let a = self
            .committee
            .anchor(&mut self.ais, chain, w, self.anchor)?;
        let total = t0.elapsed();
        let gas_order = total_gas(chain, std::slice::from_ref(&p))?;
        Ok((
            total,
            serde_json::json!({
                "gas_order": gas_order,
                "gas_anchor": a.gas,
                "gas": gas_order + a.gas,
                "order_included_ns": recorded.as_nanos(),
                "erased_ns": erased.as_nanos(),
                "disposed_ns": disposed.as_nanos(),
                "approve_ns": a.approve.as_nanos(),
                "cosign_ns": a.cosign.as_nanos(),
                "pairs_deleted": out.pairs_tombstoned,
                "openings_destroyed": out.openings_destroyed,
            }),
            Recorded { order, target, at },
        ))
    }

    /// The claim a court is handed for capsule `c` under `r`, and the check.
    fn judge(&self, c: u32, r: &Recorded, membership_of: Option<u32>) -> Res<bool> {
        let bundle = self
            .court_view
            .disclose(&self.ais, *self.slot.get(&c).ok_or("capsule not filed")?)?
            .ok_or("no bundle")?;
        let of = membership_of.unwrap_or(c);
        let membership = r
            .target
            .prove(&self.capsules[of as usize].eid)
            .ok_or("no membership proof")?;
        let order_proof = self.ais.prove(&r.at).ok_or("no proof for the order leaf")?;
        let claim = RedactionClaim {
            order: &r.order,
            membership: &membership,
            order_proof: &order_proof,
            capsule: &bundle.capsule,
            seal: &bundle.seal,
            disposal: bundle.segments.last().ok_or("no segment")?,
        };
        Ok(verify_redaction(
            &claim,
            self.court.public_key(),
            &PrfKey::new(bundle.keys.k_eid),
            &self.ais.epoch_roots(),
        )
        .is_ok())
    }
}

// --------------------------------------------------------------- B-DEMS

/// B-DEMS's side of one case.
struct Bdems {
    contract: Address,
    payloads: PayloadStore,
    /// `EID = SHA-256(E)` per capsule.
    eids: Vec<Word>,
    /// `H(E′) = SHA-256(E′)` per capsule.
    h_enc: Vec<Word>,
}

/// A `TxE` as presented to the court.
struct Presented {
    eid: Word,
    sender: Address,
    reason: String,
    ts: u64,
}

/// `keccak256(abi.encode(eid, sender, keccak256(reason), ts))`, as
/// `BDems.txeDigest`.
fn txe_digest(p: &Presented) -> Word {
    keccak256(&abi_encode(&[
        Abi::Word(p.eid),
        Abi::Word(address_word(&p.sender)),
        Abi::Word(keccak256(p.reason.as_bytes())),
        Abi::Word(uint(u128::from(p.ts))),
    ]))
}

/// The destruction confirmation hash: `SHA-256(keccak256(TxE) ‖ H(E′))`.
fn confirmation(p: &Presented, h_enc: &Word) -> Word {
    Sha256::new()
        .chain_update(txe_digest(p))
        .chain_update(h_enc)
        .finalize()
        .into()
}

/// `destructionOf`'s return, decoded.
struct OnChain {
    sender: Address,
    conf: Word,
    destroyed: bool,
    h_enc: Word,
}

fn decode_destruction(ret: &[u8]) -> Res<OnChain> {
    let word = |i: usize| -> Res<Word> {
        Ok(ret
            .get(32 * i..32 * (i + 1))
            .ok_or("short destructionOf return")?
            .try_into()?)
    };
    let s = word(0)?;
    Ok(OnChain {
        sender: s[12..].try_into()?,
        conf: word(3)?,
        destroyed: word(4)?[31] == 1,
        h_enc: word(5)?,
    })
}

/// Algorithm 3 Step 3 and §3.4.2: a `TxE` exists for the `EID`, the item is
/// destroyed, and the destruction hash over the presented `TxE` matches.
fn bdems_judge(on: &OnChain, p: &Presented) -> bool {
    on.sender != [0u8; 20] && on.destroyed && confirmation(p, &on.h_enc) == on.conf
}

fn read_destruction(chain: &Chain, b: &Bdems, eid: &Word) -> Res<Vec<u8>> {
    chain.view(
        &b.contract,
        &encode_call("destructionOf(bytes32)", &[Abi::Word(*eid)]),
    )
}

/// §3.4.1: overwrite with random bytes, flush, unlink.
fn secure_delete(path: &Path) -> Res<()> {
    use std::io::Write as _;
    let len = usize::try_from(std::fs::metadata(path)?.len())?;
    let mut junk = vec![0u8; len];
    StdRng::from_seed(rng::secret()?).fill_bytes(&mut junk);
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(&junk)?;
    f.sync_all()?;
    drop(f);
    std::fs::remove_file(path)?;
    Ok(())
}

impl Bdems {
    fn path(&self, c: u32) -> PathBuf {
        self.payloads.path(&self.eids[c as usize])
    }

    fn txe(&self, chain: &mut Chain, c: u32, reason: &str, ts: u64) -> Res<Prepared> {
        chain.prepare(
            SENDER,
            Some(self.contract),
            encode_call(
                "requestDestruction(bytes32,string,uint64)",
                &[
                    Abi::Word(self.eids[c as usize]),
                    Abi::Bytes(reason.as_bytes().to_vec()),
                    Abi::Word(uint(u128::from(ts))),
                ],
            ),
            "requestDestruction",
        )
    }

    fn presented(&self, chain: &Chain, c: u32, reason: &str, ts: u64) -> Presented {
        Presented {
            eid: self.eids[c as usize],
            sender: chain.keys[SENDER].address,
            reason: reason.to_owned(),
            ts,
        }
    }

    /// Algorithm 3 for `caps`: every `TxE`, every off-chain destruction, every
    /// confirmation. Timed from the first `TxE`'s submission.
    fn destroy(
        &self,
        chain: &mut Chain,
        w: &Watcher,
        caps: &[u32],
        ts: u64,
    ) -> Res<(Duration, serde_json::Value)> {
        let t0 = Instant::now();
        let txes = caps
            .iter()
            .map(|c| self.txe(chain, *c, REASON, ts))
            .collect::<Res<Vec<_>>>()?;
        send_all(chain, &txes)?;
        w.wait_all(&hashes(&txes))?;
        let requested = t0.elapsed();
        let mut confs = Vec::with_capacity(caps.len());
        for c in caps {
            secure_delete(&self.path(*c))?;
            let p = self.presented(chain, *c, REASON, ts);
            confs.push((*c, confirmation(&p, &self.h_enc[*c as usize])));
        }
        let deleted = t0.elapsed();
        let confirms = confs
            .iter()
            .map(|(c, conf)| {
                chain.prepare(
                    SENDER,
                    Some(self.contract),
                    encode_call(
                        "confirmDestruction(bytes32,bytes32)",
                        &[Abi::Word(self.eids[*c as usize]), Abi::Word(*conf)],
                    ),
                    "confirmDestruction",
                )
            })
            .collect::<Res<Vec<_>>>()?;
        send_all(chain, &confirms)?;
        w.wait_all(&hashes(&confirms))?;
        let total = t0.elapsed();
        let gas_txe = total_gas(chain, &txes)?;
        let gas_confirm = total_gas(chain, &confirms)?;
        Ok((
            total,
            serde_json::json!({
                "gas_txe": gas_txe,
                "gas_confirm": gas_confirm,
                "gas": gas_txe + gas_confirm,
                "txe_included_ns": requested.as_nanos(),
                "deleted_ns": deleted.as_nanos(),
                "transactions": txes.len() + confirms.len(),
            }),
        ))
    }
}

// --------------------------------------------------------------- PQ-ABL

/// An object key's low half for a capsule's evidence object; a custody
/// record's is its position in the capsule's chain.
const EVIDENCE: u32 = u32::MAX;

/// `capsule ‖ position`: which stored object this is.
fn obj_key(c: u32, seq: u32) -> u64 {
    (u64::from(c) << 32) | u64::from(seq)
}

fn key_capsule(k: u64) -> u32 {
    u32::try_from(k >> 32).unwrap_or(u32::MAX)
}

/// `SHA-256` of `bytes`: the content address an IPFS CID stands in for.
fn cid(bytes: &[u8]) -> Word {
    Sha256::digest(bytes).into()
}

/// `(R_e, CID_epoch, CID_Proof)`.
type PqState = [Word; 3];

/// One PQ-ABL epoch as the logger holds it.
#[derive(Default)]
struct PqEpoch {
    keys: Vec<u64>,
    cts: Vec<Arc<[u8]>>,
    /// `h_n` per object. Kept, so a rebuild after a deletion hashes no
    /// ciphertext again: that favours PQ-ABL.
    leaves: Vec<pqabl::Digest>,
    /// The epoch's latest state, committed or not.
    state: PqState,
}

/// One epoch rebuilt without some capsules' objects (Phase 4 Steps 2–3).
struct Rebuilt {
    e: usize,
    keys: Vec<u64>,
    cts: Vec<Arc<[u8]>>,
    leaves: Vec<pqabl::Digest>,
    archive: Vec<u8>,
    proof: Vec<u8>,
    state: PqState,
}

/// `MerkleRoot` over `leaves` on `threads` cores: the one-core root.
fn pq_root(leaves: &[pqabl::Digest], threads: usize) -> Word {
    pqabl::root_parallel(leaves.to_vec(), threads).unwrap_or([0u8; 32])
}

/// This host's cores: what PQ-ABL's rebuild and the court's check may use.
fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Rebuild epoch `e` without `gone`'s objects: the tree over the kept leaves,
/// the proof set `P_e`, `Archive_e = tar.gz(…)`, both content addresses; the
/// tree and the gzip on `threads` cores.
fn rebuild(e: usize, ep: &PqEpoch, gone: &HashSet<u32>, threads: usize) -> Result<Rebuilt, String> {
    let mut keys = Vec::with_capacity(ep.keys.len());
    let mut cts = Vec::with_capacity(ep.keys.len());
    let mut leaves = Vec::with_capacity(ep.keys.len());
    for ((k, c), l) in ep.keys.iter().zip(&ep.cts).zip(&ep.leaves) {
        if !gone.contains(&key_capsule(*k)) {
            keys.push(*k);
            cts.push(Arc::clone(c));
            leaves.push(*l);
        }
    }
    let root = pq_root(&leaves, threads);
    let proof = pqabl::proof_set(&leaves);
    let archive = pqabl::archive(&cts, threads).ok_or("an archive thread failed")?;
    let state = [root, cid(&archive), cid(&proof)];
    Ok(Rebuilt {
        e,
        keys,
        cts,
        leaves,
        archive,
        proof,
        state,
    })
}

/// How a deletion ends on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PqEnd {
    /// Every rebuilt epoch committed again: the deletion as PQ-ABL would do it.
    Commit,
    /// Rebuilt and stored, never committed (T2 `NoRecord`).
    NoCommit,
    /// Each rebuilt epoch committed with another epoch's honest state (T2
    /// `Replay`).
    Replay,
}

/// PQ-ABL's side of one case: the logger's epochs, its content-addressed
/// store, and its commitment contract.
struct Pqabl {
    contract: Address,
    epochs: Vec<PqEpoch>,
    /// IPFS's role: every archive and proof set by its content address. A
    /// rebuilt epoch's old archive is removed, since it holds the deleted
    /// ciphertexts; proof sets are digests only and stay.
    store: HashMap<Word, Arc<Vec<u8>>>,
    /// Each capsule's objects as a court last saw them disclosed:
    /// `(epoch, h_n)`.
    disclosed: HashMap<u32, Vec<(usize, pqabl::Digest)>>,
    /// Honest commitments so far, `(e, state)`: T2's replay source.
    committed: Vec<(usize, PqState)>,
}

fn pq_commit_call(e: usize, s: &PqState) -> Vec<u8> {
    encode_call(
        "commit(uint64,bytes32,bytes32,bytes32)",
        &[
            Abi::Word(uint(e as u128)),
            Abi::Word(s[0]),
            Abi::Word(s[1]),
            Abi::Word(s[2]),
        ],
    )
}

/// Three words from a view's return, from word `at`.
fn pq_state_at(ret: &[u8]) -> Res<PqState> {
    let w = |i: usize| -> Res<Word> {
        Ok(ret
            .get(32 * i..32 * (i + 1))
            .ok_or("short anchor return")?
            .try_into()?)
    };
    Ok([w(0)?, w(1)?, w(2)?])
}

impl Pqabl {
    /// Deploy the commitment contract with the logger as its committer.
    fn deploy(chain: &mut Chain, w: &Watcher) -> Res<Self> {
        let mut code = artifact_bytecode("contracts/out/PqablAnchor.sol/PqablAnchor.json")?;
        code.extend(abi_encode(&[Abi::Word(address_word(
            &chain.keys[LOGGER].address,
        ))]));
        let dep = chain.prepare(AIS, None, code, "deploy")?;
        Ok(Self {
            contract: contract_address(&chain.send_and_wait(&dep, w)?)?,
            epochs: Vec::new(),
            store: HashMap::new(),
            disclosed: HashMap::new(),
            committed: Vec::new(),
        })
    }

    /// Phase 4 Step 1: object `key` stored in epoch `e`.
    fn put(&mut self, e: usize, key: u64, ct: &[u8]) {
        if self.epochs.len() <= e {
            self.epochs.resize_with(e + 1, PqEpoch::default);
        }
        let h = pqabl::leaf(ct);
        let ep = &mut self.epochs[e];
        ep.keys.push(key);
        ep.cts.push(Arc::from(ct));
        ep.leaves.push(h);
        self.disclosed
            .entry(key_capsule(key))
            .or_default()
            .push((e, h));
    }

    /// `affected` rebuilt without `gone`, the epochs across cores and each
    /// archive's gzip across what is left of them.
    fn rebuild_all(&self, affected: &[usize], gone: &HashSet<u32>) -> Res<Vec<Rebuilt>> {
        let cores = cores();
        let inner = (cores / affected.len().max(1)).max(1);
        let per = affected.len().div_ceil(cores).max(1);
        let out: Result<Vec<Vec<Rebuilt>>, String> = std::thread::scope(|s| {
            let hs: Vec<_> = affected
                .chunks(per)
                .map(|part| {
                    s.spawn(move || {
                        part.iter()
                            .map(|&e| rebuild(e, &self.epochs[e], gone, inner))
                            .collect::<Result<Vec<_>, String>>()
                    })
                })
                .collect();
            hs.into_iter()
                .map(|h| {
                    h.join()
                        .map_err(|_| "a rebuild thread panicked".to_owned())?
                })
                .collect()
        });
        Ok(out?.into_iter().flatten().collect())
    }

    /// The logger replaces epoch `r.e` with its rebuild.
    fn apply(&mut self, r: Rebuilt) {
        let ep = &mut self.epochs[r.e];
        if ep.state[1] != [0u8; 32] {
            self.store.remove(&ep.state[1]);
        }
        self.store.insert(r.state[1], Arc::new(r.archive));
        self.store.insert(r.state[2], Arc::new(r.proof));
        ep.keys = r.keys;
        ep.cts = r.cts;
        ep.leaves = r.leaves;
        ep.state = r.state;
    }

    /// Phase 4 for every sealing epoch, then each committed: setup, not timed.
    fn seal_all(&mut self, chain: &mut Chain, w: &Watcher) -> Res<()> {
        let all: Vec<usize> = (0..self.epochs.len()).collect();
        for r in self.rebuild_all(&all, &HashSet::new())? {
            self.apply(r);
        }
        let txs = (0..self.epochs.len())
            .map(|e| {
                chain.prepare(
                    LOGGER,
                    Some(self.contract),
                    pq_commit_call(e, &self.epochs[e].state),
                    "pqablCommit",
                )
            })
            .collect::<Res<Vec<_>>>()?;
        submit_pipelined(chain, w, &txs)?;
        w.wait_all(&hashes(&txs))?;
        chain.receipts(&hashes(&txs))?;
        Ok(())
    }

    /// Delete `caps`: remove each capsule's evidence object and custody-record
    /// ciphertexts from every epoch that holds them, rebuild those epochs, and
    /// end as `how` says. Timed from the start of the deletion to the last
    /// commitment included.
    fn delete(
        &mut self,
        chain: &mut Chain,
        w: &Watcher,
        caps: &[u32],
        how: PqEnd,
    ) -> Res<(Duration, serde_json::Value)> {
        let gone: HashSet<u32> = caps.iter().copied().collect();
        let mut affected: Vec<usize> = caps
            .iter()
            .filter_map(|c| self.disclosed.get(c))
            .flatten()
            .map(|(e, _)| *e)
            .collect();
        affected.sort_unstable();
        affected.dedup();
        // T2's replay source, chosen before the rebuild replaces anything: an
        // honest state of an epoch this deletion does not touch, whose archive
        // is still stored, so the court's refusal is the subset check's and
        // not a missing download; failing that, another epoch's; failing
        // that, any earlier commitment.
        let foreign: Vec<(usize, PqState)> = if how == PqEnd::Replay {
            let touched: HashSet<usize> = affected.iter().copied().collect();
            affected
                .iter()
                .map(|&e| {
                    let rev = || self.committed.iter().rev();
                    rev()
                        .find(|(f, s)| !touched.contains(f) && self.store.contains_key(&s[1]))
                        .or_else(|| rev().find(|(f, _)| *f != e))
                        .or_else(|| rev().next())
                        .map(|(_, s)| (e, *s))
                        .ok_or_else(|| "no earlier commitment to replay".into())
                })
                .collect::<Res<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let t0 = Instant::now();
        let rebuilt = self.rebuild_all(&affected, &gone)?;
        let rebuild_t = t0.elapsed();
        let remaining: usize = rebuilt.iter().map(|r| r.keys.len()).sum();
        let remaining_records: usize = rebuilt
            .iter()
            .flat_map(|r| &r.keys)
            .filter(|k| (**k & u64::from(u32::MAX)) != u64::from(EVIDENCE))
            .count();
        for r in rebuilt {
            self.apply(r);
        }
        let commits: Vec<(usize, PqState)> = match how {
            PqEnd::Commit => affected
                .iter()
                .map(|&e| (e, self.epochs[e].state))
                .collect(),
            PqEnd::NoCommit => Vec::new(),
            PqEnd::Replay => foreign,
        };
        let txs = commits
            .iter()
            .map(|(e, s)| {
                chain.prepare(
                    LOGGER,
                    Some(self.contract),
                    pq_commit_call(*e, s),
                    "pqablCommit",
                )
            })
            .collect::<Res<Vec<_>>>()?;
        send_all(chain, &txs)?;
        w.wait_all(&hashes(&txs))?;
        let total = t0.elapsed();
        let gas = total_gas(chain, &txs)?;
        if how == PqEnd::Commit {
            self.committed.extend(commits);
        }
        Ok((
            total,
            serde_json::json!({
                "gas": gas,
                "rebuild_ns": rebuild_t.as_nanos(),
                "epochs_rebuilt": affected.len(),
                "transactions": txs.len(),
                "invalidated_objects": remaining,
                "invalidated_records": remaining_records,
            }),
        ))
    }

    /// T2 `Modified`: after an honest deletion, the stored archive of each of
    /// `caps`' epochs is altered in place, under its anchored address.
    fn tamper(&mut self, caps: &[u32]) -> Res<()> {
        let mut affected: Vec<usize> = caps
            .iter()
            .filter_map(|c| self.disclosed.get(c))
            .flatten()
            .map(|(e, _)| *e)
            .collect();
        affected.sort_unstable();
        affected.dedup();
        for e in affected {
            let at = self.epochs[e].state[1];
            let mut bytes = self
                .store
                .get(&at)
                .ok_or("no archive to alter")?
                .as_ref()
                .clone();
            let mid = bytes.len() / 2;
            bytes[mid] ^= 0x01;
            self.store.insert(at, Arc::new(bytes));
        }
        Ok(())
    }

    /// The court's check that capsule `c` was deleted (our extension of PQ-ABL,
    /// from its own artefacts; `UPGRADES.md`, "PQ-ABL in Exp. 4"). For each
    /// epoch that held it, against the chain:
    ///
    /// 1. the epoch was committed again (`anchorCount ≥ 2`);
    /// 2. the original proof set, fetched by its `CID_Proof`, rebuilds the
    ///    original root and holds the capsule's digests: it was there;
    /// 3. the latest archive, fetched by its `CID_epoch`, matches its address
    ///    and rebuilds the latest root (Phase 5's full-epoch verification);
    /// 4. its objects are a subset of the original's and none is the capsule's:
    ///    the new root is the old epoch less what was deleted.
    ///
    /// Hashing and tree rebuilds run on every core, as Exp. 2's audit of the
    /// same structure does. The same verdict from digests alone (the latest
    /// `P_e` in place of the archive in 3) is timed beside it, so the archive's
    /// share of the check can be told apart.
    fn judge(&self, chain: &Chain, c: u32) -> Res<Judged> {
        let mut by_epoch: BTreeMap<usize, Vec<pqabl::Digest>> = BTreeMap::new();
        for (e, h) in self.disclosed.get(&c).ok_or("capsule never stored")? {
            by_epoch.entry(*e).or_default().push(*h);
        }
        let threads = cores();
        let mut j = Judged {
            ok: true,
            ok_digests: true,
            read: Duration::ZERO,
            local: Duration::ZERO,
            local_digests: Duration::ZERO,
        };
        for (e, hs) in by_epoch {
            let ew = Abi::Word(uint(e as u128));
            let t = Instant::now();
            let n = chain.view(
                &self.contract,
                &encode_call("anchorCount(uint64)", std::slice::from_ref(&ew)),
            )?;
            let n = n.get(24..32).ok_or("short anchorCount")?;
            let n = u64::from_be_bytes(n.try_into()?);
            let (first, latest) = if n >= 2 {
                (
                    pq_state_at(&chain.view(
                        &self.contract,
                        &encode_call(
                            "anchorAt(uint64,uint256)",
                            &[ew.clone(), Abi::Word(uint(0))],
                        ),
                    )?)?,
                    pq_state_at(
                        &chain
                            .view(&self.contract, &encode_call("getAnchorData(uint64)", &[ew]))?,
                    )?,
                )
            } else {
                ([[0u8; 32]; 3], [[0u8; 32]; 3])
            };
            j.read += t.elapsed();
            let t = Instant::now();
            j.ok &= n >= 2 && self.deleted_from(&first, &latest, &hs, threads, false);
            j.local += t.elapsed();
            let t = Instant::now();
            j.ok_digests &= n >= 2 && self.deleted_from(&first, &latest, &hs, threads, true);
            j.local_digests += t.elapsed();
        }
        Ok(j)
    }

    /// Checks 2–4 for one epoch. `digests_only` takes the latest leaf set from
    /// the latest `P_e` (by `CID_Proof`) instead of unpacking and re-hashing
    /// the archive, which then goes unchecked.
    fn deleted_from(
        &self,
        first: &PqState,
        latest: &PqState,
        hs: &[pqabl::Digest],
        threads: usize,
        digests_only: bool,
    ) -> bool {
        let fetch = |at: &Word| self.store.get(at).filter(|b| cid(b) == *at);
        let Some(l0) = fetch(&first[2]).and_then(|p| pqabl::proof_set_leaves(p)) else {
            return false;
        };
        if pq_root(&l0, threads) != first[0] {
            return false;
        }
        let was: HashSet<pqabl::Digest> = l0.into_iter().collect();
        if !hs.iter().all(|h| was.contains(h)) {
            return false;
        }
        let now = if digests_only {
            fetch(&latest[2]).and_then(|p| pqabl::proof_set_leaves(p))
        } else {
            fetch(&latest[1])
                .and_then(|a| pqabl::extract(a))
                .and_then(|cts| pqabl::leaves_parallel(&cts, threads))
        };
        let Some(now) = now else {
            return false;
        };
        if pq_root(&now, threads) != latest[0] {
            return false;
        }
        let is: HashSet<&pqabl::Digest> = now.iter().collect();
        now.iter().all(|l| was.contains(l)) && hs.iter().all(|h| !is.contains(h))
    }
}

/// The court's check on one PQ-ABL deletion: the verdict with the archive
/// re-validated and from digests alone, the chain reads' time, and each local
/// check's.
struct Judged {
    ok: bool,
    ok_digests: bool,
    read: Duration,
    local: Duration,
    local_digests: Duration,
}

/// T2, PQ-ABL: each row's deletion, then each capsule through the court's
/// check. Rows run one after another on one case, each judged as soon as it
/// has run, and `Modified` last, since it alters stored archives.
fn pqabl_matrix(
    p: &mut Pqabl,
    chain: &mut Chain,
    w: &Watcher,
    draw: &mut Draw,
    n: usize,
) -> Res<serde_json::Value> {
    let rows = [
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
    ];
    let [valid, no_record, insider, modified, replay_a, replay_b] = rows;
    let count = |p: &Pqabl, chain: &Chain, caps: &[u32]| -> Res<usize> {
        let mut k = 0;
        for c in caps {
            k += usize::from(p.judge(chain, *c)?.ok);
        }
        Ok(k)
    };
    p.delete(chain, w, &valid, PqEnd::Commit)?;
    let acc_valid = count(p, chain, &valid)?;
    // The logger alone: PQ-ABL has no court, so this is the same sequence.
    p.delete(chain, w, &insider, PqEnd::Commit)?;
    let acc_insider = count(p, chain, &insider)?;
    p.delete(chain, w, &replay_a, PqEnd::Commit)?;
    p.delete(chain, w, &replay_b, PqEnd::Replay)?;
    let acc_replay = count(p, chain, &replay_b)?;
    p.delete(chain, w, &no_record, PqEnd::NoCommit)?;
    let acc_no_record = count(p, chain, &no_record)?;
    p.delete(chain, w, &modified, PqEnd::Commit)?;
    p.tamper(&modified)?;
    let acc_modified = count(p, chain, &modified)?;
    Ok(serde_json::json!({
        "valid": acc_valid,
        "no_record": acc_no_record,
        "insider": acc_insider,
        "modified": acc_modified,
        "replay": acc_replay,
        "verifier": "the court's check from PQ-ABL's own artefacts: a second commitment for each epoch, the original P_e rebuilding the original root and holding the capsule, the latest archive matching its CID and rebuilding the latest root (Phase 5), its objects a subset of the original's without the capsule's",
        "insider_is_by_design": "PQ-ABL has no court and no order: the logger deleting and re-committing on its own is the same sequence as a lawful deletion",
        "rows": "no_record: rebuilt and stored, never committed; replay: each rebuilt epoch committed with another epoch's honest state; modified: an honest deletion whose stored archive is then altered",
    }))
}

// ------------------------------------------------------------- one case

/// One sealed capsule as the case build files it: the capsule, its evidence
/// keywords, B-DEMS's `EID` and `H(E′)`.
type Sealed = (Capsule, Vec<Vec<u8>>, Word, Word);

/// The capsules both systems redact, in the order they take them.
struct Draw {
    order: Vec<u32>,
    next: usize,
}

impl Draw {
    fn take(&mut self, k: usize) -> Res<Vec<u32>> {
        let out = self
            .order
            .get(self.next..self.next + k)
            .ok_or("the case has too few capsules for this run")?
            .to_vec();
        self.next += k;
        Ok(out)
    }
}

/// One timed series: latencies and each iteration's breakdown.
fn series(samples: Vec<(Duration, serde_json::Value)>) -> Res<serde_json::Value> {
    let lat: Vec<Duration> = samples.iter().map(|(d, _)| *d).collect();
    let gases: Vec<u64> = samples
        .iter()
        .filter_map(|(_, v)| v["gas"].as_u64())
        .collect();
    Ok(serde_json::json!({
        "latency_ns": summary(&lat)?,
        "gas_median": median(&gases),
        "iterations": samples.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
    }))
}

/// T2, ours: every row through `verify_redaction`, `NoRecord` through the
/// auditor's `account`, which is where a deletion with no order is caught.
#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
fn ours_matrix(
    o: &mut Ours<'_>,
    chain: &mut Chain,
    w: &Watcher,
    draw: &mut Draw,
    n: usize,
) -> Res<serde_json::Value> {
    // An enrolled custodian's own ML-DSA key: any key but the court's.
    let insider = SoftwareMlDsa::generate()?;
    let rows = [
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
    ];
    let [valid, no_record, insider_caps, modified, replay_a, replay_b] = rows;

    // Every order, genuine or forged, recorded by the AIS in one batch.
    let mut recs: Vec<(u32, Order, Target, bool)> = Vec::new();
    for c in valid.iter().chain(&modified).chain(&replay_a) {
        let (order, target) = o.issue(None, &[*c], Scope::Full)?;
        recs.push((*c, order, target, true));
    }
    for c in &insider_caps {
        let (order, target) = o.issue(Some(&insider), &[*c], Scope::Full)?;
        recs.push((*c, order, target, false));
    }
    let cid = o.keys.cid_c;
    let txs = recs
        .iter()
        .map(|(_, order, _, _)| {
            chain.prepare(
                AIS,
                Some(o.anchor),
                order_call(&cid, order),
                "orderRedaction",
            )
        })
        .collect::<Res<Vec<_>>>()?;
    send_all(chain, &txs)?;
    w.wait_all(&hashes(&txs))?;

    let mut by_cap: HashMap<u32, Recorded> = HashMap::new();
    for (c, order, target, genuine) in recs {
        let registry = HashMap::from([(
            order.oid,
            recorded_order(chain, &o.anchor, &cid, &order.oid)?,
        )]);
        let redactees = o.redactees(&[c], &target)?;
        let ran = execute_core(
            &order,
            o.court.public_key(),
            now_s(),
            &registry,
            &redactees,
            &o.payloads,
            &mut o.openings,
            o.court_kem.encapsulation_key(),
            &mut o.index,
            &mut o.edb,
        );
        // The gate is real: it refuses the insider's order, so the insider
        // deletes around it.
        match (genuine, ran) {
            (true, r) => {
                r?;
            }
            (false, Ok(_)) => return Err("the AIS executed an order the court did not sign".into()),
            (false, Err(_)) => o.payloads.erase(&o.capsules[c as usize].eid)?,
        }
        o.dispose(c, &order.oid)?;
        let at = o.ais.record_order(&order);
        by_cap.insert(c, Recorded { order, target, at });
    }
    // The replayed order's second capsule, and the order-less deletions.
    for (a, b) in replay_a.iter().zip(&replay_b) {
        o.payloads.erase(&o.capsules[*b as usize].eid)?;
        let oid = by_cap.get(a).ok_or("replayed order missing")?.order.oid;
        o.dispose(*b, &oid)?;
    }
    for c in &no_record {
        o.payloads.erase(&o.capsules[*c as usize].eid)?;
    }
    o.committee.anchor(&mut o.ais, chain, w, o.anchor)?;

    let count = |caps: &[u32], f: &dyn Fn(u32) -> Res<bool>| -> Res<usize> {
        let mut n = 0;
        for c in caps {
            n += usize::from(f(*c)?);
        }
        Ok(n)
    };
    let rec = |c: u32| by_cap.get(&c).ok_or("no order for capsule");
    let accepted_valid = count(&valid, &|c| o.judge(c, rec(c)?, None))?;
    let accepted_insider = count(&insider_caps, &|c| o.judge(c, rec(c)?, None))?;
    let accepted_modified = count(&modified, &|c| {
        let r = rec(c)?;
        let mut edited = r.order.clone();
        edited.scope = Scope::Payload;
        o.judge(
            c,
            &Recorded {
                order: edited,
                target: r.target.clone(),
                at: r.at,
            },
            None,
        )
    })?;
    let accepted_replay = count(&replay_b, &|b| {
        let i = replay_b.iter().position(|x| *x == b).ok_or("lost")?;
        let a = replay_a[i];
        o.judge(b, rec(a)?, Some(a))
    })?;
    let accepted_no_record = count(&no_record, &|c| {
        let eid = o.capsules[c as usize].eid;
        let anchored = [AnchoredPayload {
            eid,
            path: o.payloads.path(&eid),
            epoch: o.capsules[c as usize].epoch,
        }];
        let found = account(
            &anchored,
            &[],
            &HashMap::<Digest32, u64>::new(),
            &HashMap::<Digest32, Digest32>::new(),
            &[],
            o.court.public_key(),
        );
        Ok(found.is_empty())
    })?;
    Ok(serde_json::json!({
        "valid": accepted_valid,
        "no_record": accepted_no_record,
        "insider": accepted_insider,
        "modified": accepted_modified,
        "replay": accepted_replay,
        "verifier": "verify_redaction (eq:validredact) for valid, insider, modified and replay; the auditor's account() for no_record",
    }))
}

/// T2, B-DEMS: every row through Algorithm 3's court check over the chain.
fn bdems_matrix(
    b: &Bdems,
    chain: &mut Chain,
    w: &Watcher,
    draw: &mut Draw,
    n: usize,
    ts: u64,
) -> Res<serde_json::Value> {
    let rows = [
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
        draw.take(n)?,
    ];
    let [valid, no_record, insider, modified, replay_a, replay_b] = rows;
    let recorded: Vec<u32> = valid
        .iter()
        .chain(&insider)
        .chain(&modified)
        .chain(&replay_a)
        .copied()
        .collect();
    let txes = recorded
        .iter()
        .map(|c| b.txe(chain, *c, REASON, ts))
        .collect::<Res<Vec<_>>>()?;
    send_all(chain, &txes)?;
    w.wait_all(&hashes(&txes))?;
    for c in recorded.iter().chain(&no_record).chain(&replay_b) {
        secure_delete(&b.path(*c))?;
    }
    let confirms = recorded
        .iter()
        .map(|c| {
            let conf = confirmation(&b.presented(chain, *c, REASON, ts), &b.h_enc[*c as usize]);
            chain.prepare(
                SENDER,
                Some(b.contract),
                encode_call(
                    "confirmDestruction(bytes32,bytes32)",
                    &[Abi::Word(b.eids[*c as usize]), Abi::Word(conf)],
                ),
                "confirmDestruction",
            )
        })
        .collect::<Res<Vec<_>>>()?;
    send_all(chain, &confirms)?;
    w.wait_all(&hashes(&confirms))?;

    let judge = |c: u32, p: &Presented| -> Res<bool> {
        Ok(bdems_judge(
            &decode_destruction(&read_destruction(chain, b, &b.eids[c as usize])?)?,
            p,
        ))
    };
    let mut acc = [0usize; 5];
    for c in &valid {
        acc[0] += usize::from(judge(*c, &b.presented(chain, *c, REASON, ts))?);
    }
    for c in &no_record {
        acc[1] += usize::from(judge(*c, &b.presented(chain, *c, REASON, ts))?);
    }
    for c in &insider {
        acc[2] += usize::from(judge(*c, &b.presented(chain, *c, REASON, ts))?);
    }
    for c in &modified {
        acc[3] += usize::from(judge(*c, &b.presented(chain, *c, MODIFIED_REASON, ts))?);
    }
    for (a, bb) in replay_a.iter().zip(&replay_b) {
        // capsule `bb`'s deletion, presented with capsule `a`'s TxE
        let p = b.presented(chain, *a, REASON, ts);
        let on = decode_destruction(&read_destruction(chain, b, &b.eids[*bb as usize])?)?;
        acc[4] += usize::from(bdems_judge(&on, &p));
    }
    Ok(serde_json::json!({
        "valid": acc[0],
        "no_record": acc[1],
        "insider": acc[2],
        "modified": acc[3],
        "replay": acc[4],
        "verifier": "Algorithm 3 Step 3 / §3.4.2: destructionOf(EID) read from the chain, a TxE exists, status destroyed, and SHA-256(keccak256(TxE as presented) ‖ H(E′)) equals the recorded confirmation",
        "insider_is_by_design": "B-DEMS authorises destruction by the Sender's enrolled role and carries no court signature, so a Sender destroying on its own TxE is indistinguishable from a court-ordered destruction",
    }))
}

/// How a case's records are cut into sealing epochs (§1ci.5 item 2, §1ci.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// The headline: sealing epochs of `epoch_records()` records each.
    Epochs,
    /// §1ci.6's labelled series: the whole case in one sealing epoch, beyond
    /// PQ-ABL's evaluated range once a case exceeds [`PQABL_MAX_EVALUATED`].
    OneEpoch,
}

impl Layout {
    fn per_epoch(self) -> usize {
        match self {
            Self::Epochs => epoch_records(),
            Self::OneEpoch => usize::MAX,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Epochs => "epochs",
            Self::OneEpoch => "one-epoch",
        }
    }
}

/// B-DEMS deployed, its agencies whitelisted, its payload store open.
fn bdems_setup(chain: &mut Chain, w: &Watcher, dir: &Path) -> Res<Bdems> {
    let code = artifact_bytecode("contracts/out/BDems.sol/BDems.json")?;
    let dep = chain.prepare(AIS, None, code, "deploy")?;
    let contract = contract_address(&chain.send_and_wait(&dep, w)?)?;
    let grants = (SENDER..SENDER + 1 + REGISTRARS)
        .map(|k| {
            let a = chain.keys[k].address;
            chain.prepare(
                AIS,
                Some(contract),
                encode_call("grantSender(address)", &[Abi::Word(address_word(&a))]),
                "grantSender",
            )
        })
        .collect::<Res<Vec<_>>>()?;
    send_all(chain, &grants)?;
    w.wait_all(&hashes(&grants))?;
    Ok(Bdems {
        contract,
        payloads: PayloadStore::open(&dir.join("bdems"))?,
        eids: Vec::new(),
        h_enc: Vec::new(),
    })
}

/// B-DEMS registration, as setup: `TxA` as Exp. 1 issues it (Sender and
/// Provider, a voluntary submission), then `TxA.Completed` with `H(E′)`, which
/// destruction reads. `TxB` is left out of this setup: destruction never reads
/// it, and one Court account would take the registration of 10⁵ items to an
/// hour.
fn bdems_register(chain: &mut Chain, w: &Watcher, b: &Bdems) -> Res<usize> {
    let provider = Key::from_secret(&keccak256(b"sac exp4 B-DEMS provider"))?;
    let mut regs = Vec::with_capacity(2 * b.eids.len());
    for c in 0..b.eids.len() {
        let registrar = SENDER + 1 + c % REGISTRARS;
        let meta = keccak256(&c.to_le_bytes());
        let d = bdems::digest(
            "B-DEMS TxA",
            &[
                b.eids[c],
                meta,
                address_word(&provider.address),
                uint(1),
                address_word(&chain.keys[registrar].address),
            ],
        );
        let sigs = [
            bdems::sig(&chain.keys[registrar], &d)?,
            bdems::sig(&provider, &d)?,
        ]
        .concat();
        regs.push(chain.prepare(
            registrar,
            Some(b.contract),
            encode_call(
                "registerEvidence(bytes32,bytes32,address,bool,bytes)",
                &[
                    Abi::Word(b.eids[c]),
                    Abi::Word(meta),
                    Abi::Word(address_word(&provider.address)),
                    Abi::Word(uint(1)),
                    Abi::Bytes(sigs),
                ],
            ),
            "registerEvidence",
        )?);
        // Estimated once its TxA is on chain: the first registrar's first
        // item goes through alone, so the estimate does not revert.
        if c == 0 {
            chain.send_and_wait(&regs[0], w)?;
        }
        regs.push(chain.prepare(
            registrar,
            Some(b.contract),
            encode_call(
                "completeRegistration(bytes32,bytes32)",
                &[Abi::Word(b.eids[c]), Abi::Word(b.h_enc[c])],
            ),
            "completeRegistration",
        )?);
    }
    submit_pipelined(chain, w, &regs[1..])?;
    w.wait_all(&hashes(&regs))?;
    Ok(b.eids.len())
}

/// F(b), ours: the court's check on each redacted capsule, the chain read and
/// the check timed apart, and the check alone over prebuilt claims.
fn ours_fb(
    o: &Ours<'_>,
    chain: &Chain,
    anchor: Address,
    redactions: &[(u32, Recorded)],
) -> Res<serde_json::Value> {
    let (mut local, mut read) = (Vec::new(), Vec::new());
    for (c, r) in redactions {
        let t = Instant::now();
        let logs = chain.rpc.call(
            "eth_getLogs",
            serde_json::json!([{
                "address": to_hex(&anchor),
                "fromBlock": "0x0",
                "toBlock": "latest",
                "topics": [to_hex(&keccak256(b"RootCommitted(bytes32,bytes32,uint64,bytes32,bytes32)")), to_hex(&o.keys.cid_c)],
            }]),
        )?;
        read.push(t.elapsed());
        if logs.as_array().is_none_or(Vec::is_empty) {
            return Err("the court found no anchored roots on chain".into());
        }
        // The bundle is the court's input; only the check is timed.
        let t = Instant::now();
        let ok = o.judge(*c, r, None)?;
        local.push(t.elapsed());
        if !ok {
            return Err(format!("an honest redaction of capsule {c} was refused").into());
        }
    }
    // `judge` above includes building the disclosure; time the check alone
    // over prebuilt claims as well, so the two can be told apart.
    let mut alone = Vec::new();
    for (c, r) in redactions {
        let bundle = o
            .court_view
            .disclose(&o.ais, o.slot[c])?
            .ok_or("no bundle")?;
        let membership = r
            .target
            .prove(&o.capsules[*c as usize].eid)
            .ok_or("no proof")?;
        let order_proof = o.ais.prove(&r.at).ok_or("no proof")?;
        let roots = o.ais.epoch_roots();
        let k_eid = PrfKey::new(bundle.keys.k_eid);
        let claim = RedactionClaim {
            order: &r.order,
            membership: &membership,
            order_proof: &order_proof,
            capsule: &bundle.capsule,
            seal: &bundle.seal,
            disposal: bundle.segments.last().ok_or("no segment")?,
        };
        let t = Instant::now();
        let ok = verify_redaction(&claim, o.court.public_key(), &k_eid, &roots).is_ok();
        alone.push(t.elapsed());
        if !ok {
            return Err("an honest claim was refused".into());
        }
    }
    Ok(serde_json::json!({
        "verify_ns": summary(&alone)?,
        "verify_with_disclosure_ns": summary(&local)?,
        "chain_read_ns": summary(&read)?,
        "chain_read": "eth_getLogs for the case's RootCommitted events (every R_e and R_e')",
    }))
}

/// One case at one layout: built, every arm set up, then F(a) and F(b) at
/// every size, and T1 and T2 on the largest.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
fn one_size(
    target_records: usize,
    largest: bool,
    layout: Layout,
    chain: &mut Chain,
    w: &Watcher,
    anchor: Address,
) -> Res<(serde_json::Value, Backend)> {
    let capsules = u32::try_from(
        (target_records * 10)
            .div_ceil(RECORDS_PER_CAPSULE_X10)
            .max(1),
    )?;
    let params = StreamParams {
        capsules,
        active: 64,
        dispose_pct: 0,
        ..StreamParams::default()
    };
    let stream = custody_stream(&params);
    let cast = Cast::generate()?;
    let keys = CaseKeys::derive(
        &PrfKey::new(digest256(b"K_mst (sac redaction)")),
        format!("case {target_records} {}", layout.label()).as_bytes(),
        &digest256(b"r_case"),
    );
    let appender = from_env(&cast, &keys)?;
    let backend = appender.backend();
    let dir = std::env::temp_dir().join(format!(
        "pqcl-sac-redaction-{target_records}-{}",
        layout.label()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let (committee, reg) = Committee::new(keys.cid_c, cast.roster().digest())?;
    let mut o = Ours {
        keys: &keys,
        build: CaseBuilder::new(&*appender, &keys),
        court_view: Discloser::new(&*appender, keys.cid_c)?,
        ais: Ais::new(),
        slot: HashMap::new(),
        capsules: Vec::new(),
        payloads: PayloadStore::open(&dir.join("ours"))?,
        openings: Openings::new(),
        index: CoreClient::new(keys.evidence_index_key()),
        edb: HonestEdb::new(),
        coc: HonestEdb::new(),
        keywords: Vec::new(),
        court: SoftwareMlDsa::generate()?,
        court_kem: KeyPair::generate()?,
        committee,
        anchor,
        orders: 0,
        ts: TS0,
    };
    // The case is registered first: sealing epochs are anchored as they close.
    let reg_tx = chain.prepare(
        AIS,
        Some(anchor),
        encode_call(
            "registerCase(bytes32,bytes32)",
            &[Abi::Word(keys.cid_c), Abi::Word(reg.digest())],
        ),
        "registerCase",
    )?;
    chain.send_and_wait(&reg_tx, w)?;
    // B-DEMS has no epochs, so it runs in the headline layout only.
    let mut b = match layout {
        Layout::Epochs => Some(bdems_setup(chain, w, &dir)?),
        Layout::OneEpoch => None,
    };
    let mut p = Pqabl::deploy(chain, w)?;

    // The case: every capsule sealed through the appender, every record of the
    // stream signed there, in sealing epochs of `per_epoch` records closed by
    // count in stream order; each anchored as it closes.
    let per_epoch = layout.per_epoch();
    let start = Instant::now();
    let mut slots: Vec<Option<Sealed>> = Vec::new();
    let mut sealing_anchors = Vec::new();
    for (i, e) in stream.iter().enumerate() {
        let ts = TS0 + i as u64;
        let epoch = (i / per_epoch) as u64;
        while o.ais.epoch() < epoch {
            sealing_anchors.push(o.committee.anchor_nowait(&mut o.ais, chain, anchor)?);
        }
        let pe = usize::try_from(epoch)?;
        if e.event == Event::Collect {
            let c = e.capsule;
            let nonce = digest256(
                &[
                    &target_records.to_le_bytes()[..],
                    layout.label().as_bytes(),
                    &c.to_le_bytes(),
                ]
                .concat(),
            );
            let mut artefact = vec![0u8; ARTEFACT_BYTES];
            StdRng::seed_from_u64(SEED ^ u64::from(c) ^ ((target_records as u64) << 32))
                .fill_bytes(&mut artefact);
            let ct = RecordKey::new(rng::secret()?).seal(&nonce, &artefact)?;
            let d_ev = *chunked::digest_bytes(ct.as_bytes(), Domain::EvidenceDigest).root();
            let r_ev = rng::secret()?;
            let cm_ev = *chunked::commit_bytes(&artefact, &r_ev).root();
            let capsule = o.build.seal(
                nonce,
                cm_ev,
                d_ev,
                b"disk-image",
                b"s3://evidence/capsule",
                epoch,
            )?;
            o.payloads.put(&capsule.eid, ct.as_bytes())?;
            o.openings.insert(capsule.eid, r_ev);
            let kws = evidence_keywords(c, ts)?;
            for w in &kws {
                o.edb.insert(&o.index.update(Op::Add, w, DocId::from(c))?);
            }
            let eid_b: Word = Sha256::digest(&artefact).into();
            let h_enc: Word = Sha256::digest(ct.as_bytes()).into();
            if let Some(b) = &b {
                b.payloads.put(&eid_b, ct.as_bytes())?;
            }
            // PQ-ABL stores the same evidence ciphertext as a log of the
            // epoch it arrives in, before its first custody record.
            p.put(pe, obj_key(c, EVIDENCE), ct.as_bytes());
            o.build.insert_capsule(c, capsule.clone());
            let s = c as usize;
            if slots.len() <= s {
                slots.resize(s + 1, None);
            }
            if slots[s].replace((capsule, kws, eid_b, h_enc)).is_some() {
                return Err(format!("capsule {s} collected twice").into());
            }
        }
        let a = o.build.feed(e, ts, epoch, None)?;
        p.put(pe, obj_key(e.capsule, e.seq), &a.signed.record.encode());
        if o.slot.contains_key(&e.capsule) {
            o.ais.append(a.signed.record);
        } else {
            let (capsule, ..) = slots[e.capsule as usize]
                .as_ref()
                .ok_or("record before COLLECT")?;
            o.slot.insert(e.capsule, o.ais.len());
            o.ais.accept(capsule.clone(), a.signed.record);
        }
    }
    sealing_anchors.push(o.committee.anchor_nowait(&mut o.ais, chain, anchor)?);
    o.ts = TS0 + stream.len() as u64;
    for s in slots {
        let (capsule, kws, eid_b, h_enc) = s.ok_or("a capsule index was never collected")?;
        o.capsules.push(capsule);
        o.keywords.push(kws);
        if let Some(b) = &mut b {
            b.eids.push(eid_b);
            b.h_enc.push(h_enc);
        }
    }
    let build = start.elapsed();
    w.wait_all(&sealing_anchors)?;
    chain.receipts(&sealing_anchors)?;
    let sealing_epochs = o.ais.epoch();
    p.seal_all(chain, w)?;
    let registered = match &b {
        Some(b) => bdems_register(chain, w, b)?,
        None => 0,
    };
    eprintln!(
        "  {} records, {} capsules, {sealing_epochs} sealing epoch(s); built in {:.1} s; B-DEMS registered {registered}",
        stream.len(),
        o.capsules.len(),
        build.as_secs_f64(),
    );

    // Every arm takes capsules from one seeded shuffle, the next unused ones,
    // so T1's iterations hand all three the same capsules.
    let mut order: Vec<u32> = (0..u32::try_from(o.capsules.len())?).collect();
    order.shuffle(&mut StdRng::seed_from_u64(SEED ^ target_records as u64));
    let mut ours_draw = Draw {
        order: order.clone(),
        next: 0,
    };
    let mut b_draw = Draw {
        order: order.clone(),
        next: 0,
    };
    let mut p_draw = Draw { order, next: 0 };
    let ts = now_s();

    // One warm-up each, discarded: gas limits are estimated here, not timed.
    o.redact(chain, w, &ours_draw.take(1)?, Scope::Full)?;
    if let Some(b) = &b {
        b.destroy(chain, w, &b_draw.take(1)?, ts)?;
    }
    p.delete(chain, w, &p_draw.take(1)?, PqEnd::Commit)?;

    // F(a): one capsule per redaction.
    let scopes: &[(&str, Scope)] = match layout {
        Layout::Epochs => &[
            ("payload", Scope::Payload),
            ("payload_index", Scope::PayloadIndex),
            ("full", Scope::Full),
        ],
        Layout::OneEpoch => &[("full", Scope::Full)],
    };
    let mut fa = serde_json::Map::new();
    let mut full_redactions = Vec::new();
    for (name, scope) in scopes {
        let mut runs = Vec::new();
        for _ in 0..MIN_ITERATIONS {
            let caps = ours_draw.take(1)?;
            let (d, v, r) = o.redact(chain, w, &caps, *scope)?;
            runs.push((d, v));
            if *scope == Scope::Full {
                full_redactions.push((caps[0], r));
            }
        }
        fa.insert((*name).to_owned(), series(runs)?);
    }
    let mut b_runs = Vec::new();
    let mut b_destroyed = Vec::new();
    if let Some(b) = &b {
        for _ in 0..MIN_ITERATIONS {
            let caps = b_draw.take(1)?;
            b_runs.push(b.destroy(chain, w, &caps, ts)?);
            b_destroyed.push(caps[0]);
        }
    }
    let mut p_runs = Vec::new();
    let mut p_deleted = Vec::new();
    for _ in 0..MIN_ITERATIONS {
        let caps = p_draw.take(1)?;
        p_runs.push(p.delete(chain, w, &caps, PqEnd::Commit)?);
        p_deleted.push(caps[0]);
    }
    let invalidated: Vec<u64> = p_runs
        .iter()
        .filter_map(|(_, v)| v["invalidated_records"].as_u64())
        .collect();
    let invalidated_objects: Vec<u64> = p_runs
        .iter()
        .filter_map(|(_, v)| v["invalidated_objects"].as_u64())
        .collect();

    let mut out = serde_json::json!({
        "layout": layout.label(),
        "records": stream.len(),
        "capsules": o.capsules.len(),
        "epoch_records": per_epoch.min(stream.len()),
        "sealing_epochs": sealing_epochs,
        "stream": {"params": params, "counts": event_counts(&stream)},
        "record_build_total_ns": build.as_nanos(),
        "evidence_keywords_per_capsule": o.keywords.first().map_or(0, Vec::len),
        "artefact_bytes": ARTEFACT_BYTES,
        "fa": {"ours": fa, "pqabl": series(p_runs)?},
        "pqabl_invalidated": {
            "records_median": median(&invalidated),
            "objects_median": median(&invalidated_objects),
            "per_iteration_records": invalidated,
            "is": "other custody records (and, in objects, evidence objects too) whose membership paths a one-capsule deletion invalidates: every log left in a rebuilt epoch, since its root changed",
        },
        "ours_invalidated": "none, by construction: a redaction anchors a new epoch and never changes an anchored root, so every earlier proof still verifies",
        "beyond_pqabl_evaluated_range": per_epoch.min(stream.len()) > PQABL_MAX_EVALUATED,
    });
    if b.is_some() {
        out["fa"]["bdems"] = series(b_runs)?;
    }

    // F(b), the headline layout: the court's check on each redacted capsule.
    if layout == Layout::Epochs {
        let ours = ours_fb(&o, chain, anchor, &full_redactions)?;
        let mut fb = serde_json::json!({"ours": ours});
        if let Some(b) = &b {
            let (mut b_local, mut b_read) = (Vec::new(), Vec::new());
            for c in &b_destroyed {
                let t = Instant::now();
                let ret = read_destruction(chain, b, &b.eids[*c as usize])?;
                b_read.push(t.elapsed());
                let pr = b.presented(chain, *c, REASON, ts);
                let t = Instant::now();
                let ok = bdems_judge(&decode_destruction(&ret)?, &pr);
                b_local.push(t.elapsed());
                if !ok {
                    return Err(format!("B-DEMS refused its own honest destruction of {c}").into());
                }
            }
            fb["bdems"] = serde_json::json!({
                "verify_ns": summary(&b_local)?,
                "chain_read_ns": summary(&b_read)?,
                "chain_read": "eth_call destructionOf(EID)",
            });
        }
        let (mut p_local, mut p_digests, mut p_read) = (Vec::new(), Vec::new(), Vec::new());
        for c in &p_deleted {
            let j = p.judge(chain, *c)?;
            if !(j.ok && j.ok_digests) {
                return Err(format!("PQ-ABL's court check refused its own deletion of {c}").into());
            }
            p_read.push(j.read);
            p_local.push(j.local);
            p_digests.push(j.local_digests);
        }
        fb["pqabl"] = serde_json::json!({
            "verify_ns": summary(&p_local)?,
            "verify_digests_only_ns": summary(&p_digests)?,
            "chain_read_ns": summary(&p_read)?,
            "chain_read": "eth_call anchorCount, anchorAt(e, 0) and getAnchorData per epoch that held the capsule",
            "check": "per such epoch: the original P_e (by CID_Proof) rebuilds the original root and holds the capsule; the latest archive (by CID_epoch) is unpacked, re-hashed and rebuilt against the latest root (Phase 5); its objects are a subset of the original's without the capsule's; hashing and rebuilds on every core",
            "digests_only": "the same verdict with the latest P_e (by CID_Proof) in place of the archive: the deletion's record without re-validating the stored archive; T2 uses the full check",
            "threads": cores(),
        });
        out["fb"] = fb;
    }

    if largest {
        let mut t1_ours = Vec::new();
        let mut t1_b = Vec::new();
        let mut t1_p = Vec::new();
        for k in env_list("PQCL_REDACT_K", T1_K) {
            eprintln!("  T1 k = {k} ({})", layout.label());
            let (mut ro, mut rb, mut rp) = (Vec::new(), Vec::new(), Vec::new());
            for _ in 0..MIN_ITERATIONS {
                let caps = ours_draw.take(k)?;
                let (d, v, _) = o.redact(chain, w, &caps, Scope::Full)?;
                ro.push((d, v));
                if let Some(b) = &b {
                    let caps = b_draw.take(k)?;
                    rb.push(b.destroy(chain, w, &caps, ts)?);
                }
                let caps = p_draw.take(k)?;
                rp.push(p.delete(chain, w, &caps, PqEnd::Commit)?);
            }
            for (into, runs) in [(&mut t1_ours, ro), (&mut t1_b, rb), (&mut t1_p, rp)] {
                if !runs.is_empty() {
                    let mut s = series(runs)?;
                    s["k"] = k.into();
                    into.push(s);
                }
            }
        }
        out["t1"] =
            serde_json::json!({"ours": t1_ours, "pqabl": t1_p, "scope": "FULL", "mode": "ERASED"});
        if b.is_some() {
            out["t1"]["bdems"] = t1_b.into();
        }
        if layout == Layout::Epochs {
            let trials = std::env::var("PQCL_REDACT_TRIALS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(TRIALS);
            eprintln!("  T2, {trials} trials per cell");
            let mut t2 = serde_json::json!({
                "trials": trials,
                "ours": ours_matrix(&mut o, chain, w, &mut ours_draw, trials)?,
                "pqabl": pqabl_matrix(&mut p, chain, w, &mut p_draw, trials)?,
            });
            if let Some(b) = &b {
                t2["bdems"] = bdems_matrix(b, chain, w, &mut b_draw, trials, ts)?;
            }
            out["t2"] = t2;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok((out, backend))
}

fn main() -> Res<()> {
    let url = std::env::var("PQCL_RPC").unwrap_or_else(|_| "http://127.0.0.1:8545".to_owned());
    let sizes = env_list("PQCL_REDACT_SIZES", DEFAULT_SIZES);
    let largest = sizes.iter().copied().max().ok_or("no case sizes")?;
    let mut keys = vec![
        Key::from_secret(&from_hex(DEV_SECRET)?)?,
        Key::from_secret(&keccak256(b"sac exp4 B-DEMS sender"))?,
    ];
    for k in 0..REGISTRARS {
        keys.push(Key::from_secret(&keccak256(
            format!("sac exp4 registrar {k}").as_bytes(),
        ))?);
    }
    keys.push(Key::from_secret(&keccak256(b"sac exp4 PQ-ABL logger"))?);
    let mut chain = Chain::connect(&url, keys)?;
    let net = network(&chain.rpc)?;
    let w = Watcher::start(&url)?;
    let init = artifact_bytecode("contracts/out/Anchor.sol/Anchor.json")?;
    let dep = chain.prepare(AIS, None, init, "deploy")?;
    let anchor = contract_address(&chain.send_and_wait(&dep, &w)?)?;

    let mut cases = Vec::new();
    let mut one_epoch = Vec::new();
    let mut backends = Vec::new();
    // The headline layout at every size, then §1ci.6's one-epoch series.
    for layout in [Layout::Epochs, Layout::OneEpoch] {
        for n in &sizes {
            eprintln!("case of ~{n} records ({})", layout.label());
            let (case, backend) = one_size(*n, *n == largest, layout, &mut chain, &w, anchor)?;
            // A checkpoint per case, outside `results/`: evidence for a run
            // that fails later, never an input to a number (campaign 09,
            // c09b).
            if let Some(home) = std::env::var_os("HOME") {
                let p = std::path::Path::new(&home).join("pqcl-logs/sac-redaction-cases.jsonl");
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                {
                    use std::io::Write as _;
                    let _ = writeln!(f, "{case}");
                }
            }
            backends.push(backend);
            match layout {
                Layout::Epochs => cases.push(case),
                Layout::OneEpoch => one_epoch.push(case),
            }
        }
    }
    // ⭐ One Secure Module for the whole record, as `custody` refuses otherwise.
    let backend = *backends.first().ok_or("no case ran")?;
    if backends.iter().any(|b| *b != backend) {
        return Err("one run built through several Secure Modules".into());
    }
    let watcher_errors = w.error_count();
    w.finish()?;
    let measurements = serde_json::json!({
        "cases": cases,
        "one_epoch_cases": one_epoch,
        "one_epoch_note": "the design record: the same case sizes with every record in one sealing epoch, ours FULL and PQ-ABL only; a case past 50,000 logs is beyond PQ-ABL's evaluated range (p. 15), as each case's beyond_pqabl_evaluated_range says",
        "epoch_records": epoch_records(),
        "network": net,
        "watcher_errors": watcher_errors,
        "sync_retries": SYNC_RETRIES.load(std::sync::atomic::Ordering::Relaxed),
        "method": {
            "ours": "SAC Phase 5 over Pi_core: orderRedaction included, the gate reading the recorded digest, execute_core, one DISPOSE per capsule from the Secure Module, the order leaf and the DISPOSE segments anchored in their own epoch with M = 2 of N = 3 ML-DSA approvals and the SLH-DSA co-signature",
            "bdems": "Algorithm 3 per evidence item: TxE, overwrite-and-unlink, confirmation hash SHA-256(keccak256(TxE) || H(E')) by the TxE's Sender; one Sender, every transaction of a batch submitted at once",
            "pqabl": "deletion as our extension of PQ-ABL's per-epoch design: the capsule's evidence object and custody-record ciphertexts removed from every epoch holding them, each such epoch rebuilt once per deletion (tree over the kept leaf digests, P_e, tar.gz in parallel gzip members, SHA-256 content addresses for the IPFS CIDs) and committed again by the logger with an appended, superseding commit(e, R_e, CID_epoch, CID_Proof)",
            "latency": "first transaction submitted to the last one included, erasure done in between; ours excludes the epoch wait (up to Delta) and the court's signing of the order",
            "gas": "receipt gasUsed: ours orderRedaction + commitRoot of the redaction epoch; B-DEMS every TxE and confirmation; PQ-ABL every re-commitment",
            "warm_up": "one redaction per system per case size, discarded",
            "t1_t2_case": "the largest case",
            "evidence_keywords": "type, device, collector, and the 25 range ancestors of the acquisition hour",
        },
    });
    emit_custody(
        "sac-redaction",
        RunSpec {
            liboqs_version: "ML-DSA-65 via liboqs".to_owned(),
            rng_seeds: vec![SEED, StreamParams::default().seed],
            ..RunSpec::default()
        },
        MIN_ITERATIONS,
        measurements,
        backend,
    )?;
    Ok(())
}
