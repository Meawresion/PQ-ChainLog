//! The chain client every on-chain experiment submits through: a block
//! watcher, nonce-tracked signing, pipelined submission and receipts.
//!
//! Moved out of `exp6chain` unchanged so SAC Exp. 4 (`redaction`) submits
//! B-DEMS's transactions and our anchor's through the same code that measured
//! LEChain's. Behind the `chain` feature, as
//! [`crate::evm`] is.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::evm::{Address, Key, LegacyTx, Rpc, from_hex, keccak256, quantity, to_hex};

type Res<T> = Result<T, Box<dyn core::error::Error>>;

/// Besu's documented development account, funded by `besu/qbft-config.json`.
/// Public by design; the chain is disposable.
pub const DEV_SECRET: &str = "8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";

/// Gas limit = `eth_estimateGas` × this, in percent — what web3.py, LEChain's
/// client, does by default. A fixed generous cap would waste the tail of every
/// block (Besu stops packing when the next limit no longer fits) and so lower
/// LEChain's throughput for a reason that is not its design.
pub const GAS_MARGIN_PCT: u64 = 125;

/// In-flight transactions per sender in the pipelined phase.
pub const WINDOW: usize = 64;

/// Block-watcher poll interval: the resolution of every commit time.
pub const POLL: Duration = Duration::from_millis(20);

/// Give up after this long **without any inclusion**: 15 min, or
/// `PQCL_INCLUSION_TIMEOUT_S`. Every waiting loop restarts its deadline when a
/// transaction lands, so a long submission that keeps progressing never times
/// out: a fixed deadline over the whole of one stopped c10b at 10^6 records,
/// whose 232,560 B-DEMS registrations take about as long as the deadline.
pub fn timeout() -> Duration {
    std::env::var("PQCL_INCLUSION_TIMEOUT_S")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(Duration::from_mins(15), Duration::from_secs)
}

// ------------------------------------------------------------- watcher

/// Records, for every transaction in every new block, when the block was
/// first observed. Runs on its own thread so a commit is timed even while the
/// main thread is busy ingesting.
///
/// ⚠️ **A transient RPC error is retried, never fatal, and never skips a
/// block.** The first version returned on any error; under load one failed
/// call ended the thread silently, and the run then reported hundreds of
/// transactions "not included" that the chain's own nonces showed were. `next`
/// advances only on a successful fetch, every error is counted into the
/// record, and [`Watcher::wait_all`] fails at once, naming the cause, if the
/// thread has stopped.
pub struct Watcher {
    seen: Arc<Mutex<HashMap<String, (Instant, u64)>>>,
    errors: Arc<Mutex<(u64, Option<String>)>>,
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<Result<(), String>>,
}

/// Consecutive failed polls before the watcher gives up: the node is gone.
const WATCHER_MAX_CONSECUTIVE_ERRORS: u32 = 500;

impl Watcher {
    /// Start watching from the block after the current head.
    ///
    /// # Errors
    ///
    /// The node is unreachable.
    pub fn start(url: &str) -> Res<Self> {
        let rpc = Rpc::new(url)?;
        let mut next = quantity(&rpc.call("eth_blockNumber", serde_json::json!([]))?)? + 1;
        let seen = Arc::new(Mutex::new(HashMap::new()));
        let errors = Arc::new(Mutex::new((0u64, None)));
        let stop = Arc::new(AtomicBool::new(false));
        let (s, er, st) = (Arc::clone(&seen), Arc::clone(&errors), Arc::clone(&stop));
        let handle = std::thread::spawn(move || -> Result<(), String> {
            let mut consecutive = 0u32;
            while !st.load(Ordering::Relaxed) {
                match Self::poll(&rpc, &s, &mut next) {
                    Ok(()) => consecutive = 0,
                    Err(e) => {
                        consecutive += 1;
                        let mut g = er.lock().map_err(|_| "watcher lock poisoned")?;
                        g.0 += 1;
                        if g.0 <= 5 {
                            eprintln!("  watcher: poll failed, retrying: {e}");
                        }
                        g.1 = Some(e.clone());
                        if consecutive >= WATCHER_MAX_CONSECUTIVE_ERRORS {
                            return Err(format!(
                                "{consecutive} consecutive failed polls, last: {e}"
                            ));
                        }
                    }
                }
                std::thread::sleep(POLL); // xtask-allow: sleep — polling a real node for block inclusion is real waiting, not simulated work
            }
            Ok(())
        });
        Ok(Self {
            seen,
            errors,
            stop,
            handle,
        })
    }

    /// Fetch every block up to the head; `next` advances only past blocks
    /// actually read.
    fn poll(
        rpc: &Rpc,
        seen: &Mutex<HashMap<String, (Instant, u64)>>,
        next: &mut u64,
    ) -> Result<(), String> {
        let head = rpc
            .call("eth_blockNumber", serde_json::json!([]))
            .and_then(|v| quantity(&v))
            .map_err(|e| e.to_string())?;
        while *next <= head {
            let b = rpc
                .call(
                    "eth_getBlockByNumber",
                    serde_json::json!([format!("0x{:x}", *next), false]),
                )
                .map_err(|e| e.to_string())?;
            let now = Instant::now();
            let txs = b["transactions"]
                .as_array()
                .ok_or_else(|| format!("block {} has no transaction list: {b}", *next))?;
            let mut m = seen.lock().map_err(|_| "watcher lock poisoned")?;
            for h in txs.iter().filter_map(serde_json::Value::as_str) {
                m.insert(h.to_ascii_lowercase(), (now, *next));
            }
            *next += 1;
        }
        Ok(())
    }

    /// Polls that failed and were retried — recorded beside the timings they
    /// could have delayed.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        self.errors.lock().map_or(0, |g| g.0)
    }

    /// When and in which block `hash` was first seen, if it has been.
    #[must_use]
    pub fn included(&self, hash: &str) -> Option<(Instant, u64)> {
        self.seen.lock().ok()?.get(hash).copied()
    }

    /// Wait until every one of `hashes` is in a block.
    ///
    /// # Errors
    ///
    /// [`timeout`] passes first, or the watcher thread has stopped.
    pub fn wait_all(&self, hashes: &[String]) -> Res<Vec<(Instant, u64)>> {
        let mut deadline = Instant::now() + timeout();
        let mut landed = 0;
        loop {
            let got: Vec<Option<(Instant, u64)>> =
                hashes.iter().map(|h| self.included(h)).collect();
            if got.iter().all(Option::is_some) {
                return Ok(got.into_iter().flatten().collect());
            }
            let now = got.iter().filter(|g| g.is_some()).count();
            if now > landed {
                landed = now;
                deadline = Instant::now() + timeout();
            }
            if self.handle.is_finished() {
                let last = self.errors.lock().ok().and_then(|g| g.1.clone());
                return Err(format!("the block watcher stopped; last error: {last:?}").into());
            }
            if Instant::now() > deadline {
                let missing = got.iter().filter(|g| g.is_none()).count();
                return Err(format!(
                    "{missing} transactions not included; none landed for {:?}",
                    timeout()
                )
                .into());
            }
            std::thread::sleep(POLL); // xtask-allow: sleep — polling a real node for block inclusion is real waiting, not simulated work
        }
    }

    /// Stop the watcher thread.
    ///
    /// # Errors
    ///
    /// The thread had already failed.
    pub fn finish(self) -> Res<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .join()
            .map_err(|_| "watcher thread panicked")?
            .map_err(Into::into)
    }
}

// ---------------------------------------------------------- tx plumbing

/// A signed transaction, ready to submit.
pub struct Prepared {
    /// Index of the signing key in [`Chain::keys`].
    pub sender: usize,
    /// Its nonce.
    pub nonce: u64,
    /// The signed RLP.
    pub raw: Vec<u8>,
    /// `keccak256(raw)`, lower-case hex.
    pub hash: String,
    /// What the call is, for gas grouping.
    pub label: &'static str,
}

/// Signing keys with their nonces, over one node.
pub struct Chain {
    /// The node.
    pub rpc: Rpc,
    /// `eth_chainId`.
    pub id: u64,
    /// Next nonce per key.
    pub nonces: Vec<u64>,
    /// The signing keys; index 0 is the funded dev account.
    pub keys: Vec<Key>,
    /// Estimated gas limit per call type, estimated once on its first call.
    pub limits: HashMap<&'static str, u64>,
}

impl Chain {
    /// `eth_estimateGas` × [`GAS_MARGIN_PCT`], estimated once per `label`.
    ///
    /// # Errors
    ///
    /// The node refuses the estimate, usually because the call reverts.
    pub fn gas_limit(
        &mut self,
        sender: usize,
        to: Option<Address>,
        data: &[u8],
        label: &'static str,
    ) -> Res<u64> {
        if let Some(l) = self.limits.get(label) {
            return Ok(*l);
        }
        let mut call =
            serde_json::json!({"from": to_hex(&self.keys[sender].address), "data": to_hex(data)});
        if let Some(a) = to {
            call["to"] = serde_json::json!(to_hex(&a));
        }
        let est = quantity(
            &self
                .rpc
                .call("eth_estimateGas", serde_json::json!([call]))?,
        )?;
        let limit = est * GAS_MARGIN_PCT / 100;
        // Deployments and one-off setup differ per call; only transitions share.
        if !matches!(label, "deploy" | "setChars") {
            self.limits.insert(label, limit);
        }
        Ok(limit)
    }

    /// Sign a call from key `sender`, advancing its nonce.
    ///
    /// # Errors
    ///
    /// Gas estimation or signing fails.
    pub fn prepare(
        &mut self,
        sender: usize,
        to: Option<Address>,
        data: Vec<u8>,
        label: &'static str,
    ) -> Res<Prepared> {
        let gas_limit = self.gas_limit(sender, to, &data, label)?;
        let nonce = self.nonces[sender];
        let tx = LegacyTx {
            nonce,
            gas_price: 0,
            gas_limit,
            to,
            value: 0,
            data,
        };
        self.nonces[sender] += 1;
        let raw = tx.sign(&self.keys[sender], self.id)?;
        let hash = to_hex(&keccak256(&raw));
        Ok(Prepared {
            sender,
            nonce,
            raw,
            hash,
            label,
        })
    }

    /// Submit one signed transaction.
    ///
    /// # Errors
    ///
    /// The node refuses it or names a different hash.
    pub fn send(&self, p: &Prepared) -> Res<()> {
        send_raw(self, &[p])
    }

    /// Connect over `url` with `keys`, reading the chain id and each key's
    /// pending nonce.
    ///
    /// # Errors
    ///
    /// The node is unreachable.
    pub fn connect(url: &str, keys: Vec<Key>) -> Res<Self> {
        let rpc = Rpc::new(url)?;
        let id = quantity(&rpc.call("eth_chainId", serde_json::json!([]))?)?;
        let mut nonces = Vec::with_capacity(keys.len());
        for k in &keys {
            nonces.push(quantity(&rpc.call(
                "eth_getTransactionCount",
                serde_json::json!([to_hex(&k.address), "pending"]),
            )?)?);
        }
        Ok(Self {
            rpc,
            id,
            nonces,
            keys,
            limits: HashMap::new(),
        })
    }

    /// `eth_call` at the latest block: a view's return data.
    ///
    /// # Errors
    ///
    /// The node refuses the call or returns something that is not hex.
    pub fn view(&self, to: &Address, data: &[u8]) -> Res<Vec<u8>> {
        let r = self.rpc.call(
            "eth_call",
            serde_json::json!([{"to": to_hex(to), "data": to_hex(data)}, "latest"]),
        )?;
        Ok(from_hex(r.as_str().ok_or("eth_call returned no data")?)?)
    }

    /// Receipts for `hashes`, refusing any that reverted: a reverted custody
    /// transition is a harness bug, and its gas would be a wrong number.
    pub fn receipts(&self, hashes: &[String]) -> Res<Vec<serde_json::Value>> {
        let mut out = Vec::with_capacity(hashes.len());
        for chunk in hashes.chunks(crate::evm::MAX_BATCH) {
            let params: Vec<serde_json::Value> =
                chunk.iter().map(|h| serde_json::json!([h])).collect();
            for (h, r) in chunk
                .iter()
                .zip(self.rpc.batch("eth_getTransactionReceipt", &params)?)
            {
                let r = r?;
                if r["status"].as_str() != Some("0x1") {
                    return Err(format!("transaction {h} reverted: {r}").into());
                }
                out.push(r);
            }
        }
        Ok(out)
    }

    /// Send one transaction and wait for it — deployments and setup.
    pub fn send_and_wait(&self, p: &Prepared, w: &Watcher) -> Res<serde_json::Value> {
        self.send(p)?;
        w.wait_all(std::slice::from_ref(&p.hash))?;
        Ok(self.receipts(std::slice::from_ref(&p.hash))?.remove(0))
    }
}

/// `gasUsed` of a receipt.
pub fn gas(r: &serde_json::Value) -> Res<u64> {
    Ok(quantity(&r["gasUsed"])?)
}

/// A Foundry artefact's creation bytecode.
pub fn artifact_bytecode(path: &str) -> Res<Vec<u8>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{path}: {e} -- build it first (see this binary's docs)"))?;
    let j: serde_json::Value = serde_json::from_str(&text)?;
    let hex = j["bytecode"]["object"]
        .as_str()
        .ok_or_else(|| format!("{path}: no bytecode.object"))?;
    Ok(from_hex(hex)?)
}

/// The address a deployment receipt created.
pub fn contract_address(receipt: &serde_json::Value) -> Res<Address> {
    let a = from_hex(
        receipt["contractAddress"]
            .as_str()
            .ok_or("deployment receipt has no contractAddress")?,
    )?;
    Ok(a.try_into()
        .map_err(|_| "contractAddress is not 20 bytes")?)
}

/// Submit `txs` keeping at most `WINDOW` in flight per sender. Returns the
/// submission instants, in `txs` order.
pub fn submit_pipelined(chain: &Chain, w: &Watcher, txs: &[Prepared]) -> Res<Vec<Instant>> {
    let mut per_sender: BTreeMap<usize, std::collections::VecDeque<usize>> = BTreeMap::new();
    for (i, t) in txs.iter().enumerate() {
        per_sender.entry(t.sender).or_default().push_back(i);
    }
    let mut in_flight: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut submitted = vec![None; txs.len()];
    let mut deadline = Instant::now() + timeout();
    while per_sender.values().any(|q| !q.is_empty()) {
        let mut batch = Vec::new();
        for (s, q) in &mut per_sender {
            let live = in_flight.entry(*s).or_default();
            let before = live.len();
            live.retain(|i| w.included(&txs[*i].hash).is_none());
            if live.len() < before {
                deadline = Instant::now() + timeout();
            }
            while live.len() < WINDOW
                && let Some(i) = q.pop_front()
            {
                live.push(i);
                batch.push(i);
            }
        }
        if !batch.is_empty() {
            let now = Instant::now();
            send_raw(chain, &batch.iter().map(|i| &txs[*i]).collect::<Vec<_>>())?;
            for i in &batch {
                submitted[*i] = Some(now);
            }
        }
        if Instant::now() > deadline {
            return Err(format!("pipelined submission: none landed for {:?}", timeout()).into());
        }
        std::thread::sleep(POLL); // xtask-allow: sleep — waiting for a real node to include what is in flight
    }
    Ok(submitted.into_iter().flatten().collect())
}

/// One unsigned call: `(sender, calldata, label)`, all to one contract.
pub type Call = (usize, Vec<u8>, &'static str);

/// Transactions [`submit_when_ready`] sent again because the node no longer
/// held them: an account's lowest one in flight, sent at least
/// [`REBROADCAST_AFTER`] earlier, still at the account's confirmed nonce. A
/// local anvil node dropped such a transaction whose dependencies were both
/// included (§1ci smoke); a wallet rebroadcasts. Counted into the record.
pub static REBROADCASTS: AtomicU64 = AtomicU64::new(0);

/// How long an account's lowest transaction in flight may wait for inclusion
/// before its account's transactions in flight are sent again.
const REBROADCAST_AFTER: Duration = Duration::from_secs(10);

/// How far into an account's pending calls [`submit_when_ready`] looks for
/// ones that are ready: a client works through its own backlog roughly in
/// order, and the bound keeps each poll cheap.
const READY_SCAN: usize = 512;

/// [`submit_pipelined`] for a workflow whose steps come from different
/// accounts: call `i` is sent once every `deps[i]` is included, since nonces
/// order one account's transactions and nothing orders two accounts'.
/// B-DEMS's `TxB` is the Court's over the Sender's `TxA`, and its `TxD` the
/// Sender's over a Receiver's `TxC`; sent together, a block may carry the
/// second first, and it reverts.
///
/// ⭐ **Each call is signed when it is sent, taking its account's next nonce
/// then.** Signing every call up front, in issue order, gives each account one
/// queue that a single waiting call blocks: a `TxD` waiting a block for its
/// `TxC` held back every later, independent call from the same agency. A real
/// client signs what is ready, so its later calls do not wait (a local smoke
/// measured B-DEMS at 30 records/s the first way). The envelope signing is
/// inside the measured span; the participants' signatures the calls carry
/// were made before it.
///
/// Every dependency must be an earlier call. Returns the signed transactions
/// and their submission instants, both in call order.
///
/// # Errors
///
/// A dependency is not earlier than its call, signing fails, the node refuses
/// a transaction, or [`timeout`].
pub fn submit_when_ready(
    chain: &mut Chain,
    w: &Watcher,
    to: Address,
    calls: &[Call],
    deps: &[Vec<usize>],
) -> Res<(Vec<Prepared>, Vec<Instant>)> {
    if deps.len() != calls.len() {
        return Err("one dependency list per call".into());
    }
    if deps
        .iter()
        .enumerate()
        .any(|(i, d)| d.iter().any(|j| *j >= i))
    {
        return Err("a call depends on one at or after it".into());
    }
    let mut pending: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, (s, ..)) in calls.iter().enumerate() {
        pending.entry(*s).or_default().push(i);
    }
    let mut signed: Vec<Option<Prepared>> = (0..calls.len()).map(|_| None).collect();
    let mut submitted = vec![None; calls.len()];
    let mut in_flight: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut deadline = Instant::now() + timeout();
    let mut checked = Instant::now();
    while pending.values().any(|q| !q.is_empty()) {
        if checked.elapsed() >= REBROADCAST_AFTER {
            checked = Instant::now();
            rebroadcast(chain, &in_flight, &signed, &submitted)?;
        }
        let mut batch = Vec::new();
        for (s, q) in &mut pending {
            let live = in_flight.entry(*s).or_default();
            let before = live.len();
            live.retain(|i| {
                signed[*i]
                    .as_ref()
                    .is_some_and(|p| w.included(&p.hash).is_none())
            });
            if live.len() < before {
                deadline = Instant::now() + timeout();
            }
            let mut k = 0;
            while live.len() < WINDOW && k < q.len().min(READY_SCAN) {
                let i = q[k];
                let ready = deps[i].iter().all(|j| {
                    signed[*j]
                        .as_ref()
                        .is_some_and(|p| w.included(&p.hash).is_some())
                });
                if ready {
                    q.remove(k);
                    let (sender, data, label) = &calls[i];
                    signed[i] = Some(chain.prepare(*sender, Some(to), data.clone(), label)?);
                    live.push(i);
                    batch.push(i);
                } else {
                    k += 1;
                }
            }
        }
        if !batch.is_empty() {
            let now = Instant::now();
            let txs: Vec<&Prepared> = batch.iter().filter_map(|i| signed[*i].as_ref()).collect();
            send_raw(chain, &txs)?;
            for i in &batch {
                submitted[*i] = Some(now);
            }
        }
        if Instant::now() > deadline {
            return Err(ready_timeout(chain, w, calls, deps, &pending, &in_flight, &signed).into());
        }
        std::thread::sleep(POLL); // xtask-allow: sleep — waiting for a real node to include what is in flight
    }
    let signed = signed
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or("a call was never signed")?;
    let submitted = submitted
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or("a call was never submitted")?;
    Ok((signed, submitted))
}

/// Send again every transaction in flight of an account whose lowest one is
/// [`REBROADCAST_AFTER`] old and still at the account's confirmed nonce: the
/// node has dropped it, and everything after it waits behind the gap.
fn rebroadcast(
    chain: &Chain,
    in_flight: &BTreeMap<usize, Vec<usize>>,
    signed: &[Option<Prepared>],
    submitted: &[Option<Instant>],
) -> Res<()> {
    for (s, live) in in_flight {
        let Some(&low) = live
            .iter()
            .min_by_key(|i| signed[**i].as_ref().map_or(u64::MAX, |p| p.nonce))
        else {
            continue;
        };
        let (Some(p), Some(at)) = (signed[low].as_ref(), submitted[low]) else {
            continue;
        };
        if at.elapsed() < REBROADCAST_AFTER {
            continue;
        }
        let confirmed = quantity(&chain.rpc.call(
            "eth_getTransactionCount",
            serde_json::json!([to_hex(&chain.keys[*s].address), "latest"]),
        )?)?;
        if confirmed == p.nonce {
            let again: Vec<&Prepared> = live.iter().filter_map(|i| signed[*i].as_ref()).collect();
            REBROADCASTS.fetch_add(again.len() as u64, Ordering::Relaxed);
            send_raw(chain, &again)?;
        }
    }
    Ok(())
}

/// What each account of [`submit_when_ready`] is waiting on when it times
/// out: a timeout that does not say is not a diagnosis.
fn ready_timeout(
    chain: &Chain,
    w: &Watcher,
    calls: &[Call],
    deps: &[Vec<usize>],
    pending: &BTreeMap<usize, Vec<usize>>,
    in_flight: &BTreeMap<usize, Vec<usize>>,
    signed: &[Option<Prepared>],
) -> String {
    use core::fmt::Write as _;
    let mut why = String::from(
        "dependent submission timed out
",
    );
    for (s, q) in pending.iter().filter(|(_, q)| !q.is_empty()).take(12) {
        let head = q[0];
        let state = |j: &usize| match signed[*j].as_ref() {
            None => "unsigned",
            Some(p) if w.included(&p.hash).is_some() => "included",
            Some(_) => "in flight",
        };
        let count = |tag: &str| {
            chain
                .rpc
                .call(
                    "eth_getTransactionCount",
                    serde_json::json!([to_hex(&chain.keys[*s].address), tag]),
                )
                .and_then(|v| quantity(&v))
                .map_or_else(|e| format!("? ({e})"), |n| n.to_string())
        };
        let lowest_call = in_flight.get(s).and_then(|v| {
            v.iter()
                .copied()
                .filter(|i| signed[*i].is_some())
                .min_by_key(|i| signed[*i].as_ref().map_or(u64::MAX, |p| p.nonce))
        });
        let lowest = lowest_call.and_then(|i| signed[i].as_ref());
        if let Some(i) = lowest_call {
            let _ = writeln!(
                why,
                "  lowest in flight of account {s} is call {i} ({}), deps {:?}",
                calls[i].2,
                deps[i]
                    .iter()
                    .map(|j| (*j, calls[*j].0, calls[*j].2, state(j)))
                    .collect::<Vec<_>>()
            );
        }
        let known = lowest.map(|p| {
            chain
                .rpc
                .call("eth_getTransactionByHash", serde_json::json!([p.hash]))
                .map_or_else(
                    |e| format!("? ({e})"),
                    |v| {
                        if v.is_null() {
                            "unknown to the node".to_owned()
                        } else {
                            "known to the node".to_owned()
                        }
                    },
                )
        });
        let _ = writeln!(
            why,
            "  account {s}: chain nonce {}, pending {}, lowest in flight {:?} ({known:?}); {} queued, {} in flight; first is call {head} ({}), waiting on {:?}",
            count("latest"),
            count("pending"),
            lowest.map(|p| p.nonce),
            q.len(),
            in_flight.get(s).map_or(0, Vec::len),
            calls[head].2,
            deps[head]
                .iter()
                .map(|j| (*j, calls[*j].2, state(j)))
                .collect::<Vec<_>>(),
        );
    }
    why
}

/// Why transactions are not being included: per sender with any stuck, the
/// chain's nonce, the pool's pending nonce, and the first nonce we sent that
/// never landed — a gap there means the pool dropped one and everything after
/// it is waiting. A timeout that does not say this is not a diagnosis.
#[must_use]
pub fn stuck(chain: &Chain, w: &Watcher, txs: &[Prepared]) -> String {
    use core::fmt::Write as _;
    let mut by_sender: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
    for p in txs.iter().filter(|p| w.included(&p.hash).is_none()) {
        by_sender.entry(p.sender).or_default().push(p.nonce);
    }
    let count = |a: &Address, tag: &str| {
        chain
            .rpc
            .call(
                "eth_getTransactionCount",
                serde_json::json!([to_hex(a), tag]),
            )
            .and_then(|v| quantity(&v))
            .map_or_else(|e| format!("? ({e})"), |n| n.to_string())
    };
    let mut out = format!(
        "{} senders have stuck transactions; pool: {}
",
        by_sender.len(),
        chain
            .rpc
            .call("txpool_besuStatistics", serde_json::json!([]))
            .map_or_else(|e| e.to_string(), |v| v.to_string())
    );
    for (s, nonces) in by_sender.iter().take(12) {
        let a = &chain.keys[*s].address;
        let _ = writeln!(
            out,
            "  sender {s}: chain nonce {}, pending {}, stuck {} from nonce {}",
            count(a, "latest"),
            count(a, "pending"),
            nonces.len(),
            nonces.iter().min().copied().unwrap_or_default()
        );
    }
    out
}

/// What the record says about the network a run measured on: client, block
/// gas limit, observed block period, validator count.
///
/// # Errors
///
/// The node is unreachable.
pub fn network(rpc: &Rpc) -> Res<serde_json::Value> {
    let head = quantity(&rpc.call("eth_blockNumber", serde_json::json!([]))?)?;
    let b = |n: u64| {
        rpc.call(
            "eth_getBlockByNumber",
            serde_json::json!([format!("0x{n:x}"), false]),
        )
    };
    let latest = b(head)?;
    // ⚠️ Never reach back to genesis: its timestamp is 0 on a freshly generated
    // network, which made the first smoke run report a 94-million-second block.
    let span = 20.min(head.saturating_sub(1));
    let first = quantity(&b(head - span)?["timestamp"])?;
    let period_ms = ((quantity(&latest["timestamp"])? - first) * 1000).checked_div(span);
    let validators = rpc
        .call(
            "qbft_getValidatorsByBlockNumber",
            serde_json::json!(["latest"]),
        )
        .map_or(0, |v| v.as_array().map_or(0, Vec::len));
    Ok(serde_json::json!({
        "client": rpc.call("web3_clientVersion", serde_json::json!([]))?,
        "block_gas_limit": quantity(&latest["gasLimit"])?,
        "observed_block_period_ms": period_ms,
        "validators": validators,
    }))
}

/// Transactions a node turned away for a transient reason and were
/// resubmitted: it believed itself behind its peers (`-32008`, "Initial sync
/// is still in progress"), or the nonce was further ahead of the sender's
/// confirmed one than its pool admits, which clears as earlier ones land.
pub static SYNC_RETRIES: AtomicU64 = AtomicU64::new(0);

/// How long to wait before resubmitting to a node that reports itself syncing.
const SYNC_BACKOFF: Duration = Duration::from_secs(2);

/// Submit signed transactions in JSON-RPC batches, resubmitting any the node
/// refuses because it believes it is still syncing.
///
/// ⭐ **A transient refusal is retried, never fatal** (campaign 09, c09b's first
/// attempt). Under load one Besu validator briefly reported `-32008` "Initial
/// sync is still in progress" and turned a registration away; the harness
/// treated that as a harness bug and the whole run, six case sizes measured,
/// was lost. The node accepts the same transaction moments later, so it is
/// resubmitted until [`timeout`]; each resubmission is counted in
/// [`SYNC_RETRIES`] for the record. A transaction the node already holds
/// ("already known") is accepted, since a resubmission after a lost reply
/// would otherwise fail on its own success. Any other refusal is an error.
///
/// # Errors
///
/// A refusal that is not transient, a hash the node disputes, or [`timeout`].
pub fn send_raw(chain: &Chain, txs: &[&Prepared]) -> Res<()> {
    let deadline = Instant::now() + timeout();
    let mut pending: Vec<&Prepared> = txs.to_vec();
    while !pending.is_empty() {
        let mut again = Vec::new();
        for part in pending.chunks(crate::evm::MAX_BATCH) {
            let params: Vec<serde_json::Value> = part
                .iter()
                .map(|p| serde_json::json!([to_hex(&p.raw)]))
                .collect();
            for (p, r) in part
                .iter()
                .zip(chain.rpc.batch("eth_sendRawTransaction", &params)?)
            {
                match r {
                    Ok(got) => {
                        if got.as_str().map(str::to_ascii_lowercase).as_deref()
                            != Some(p.hash.as_str())
                        {
                            return Err(
                                format!("node returned hash {got}, expected {}", p.hash).into()
                            );
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("-32008")
                            || msg.contains("Initial sync")
                            || msg.contains("nonce is too distant")
                        {
                            again.push(*p);
                        } else if !(msg.contains("already known")
                            || msg.contains("Known transaction")
                            || msg.contains("already imported"))
                        {
                            return Err(format!("submitting {}: {msg}", p.hash).into());
                        }
                    }
                }
            }
        }
        if !again.is_empty() {
            if Instant::now() > deadline {
                return Err(format!(
                    "{} transactions still refused as syncing after {:?}",
                    again.len(),
                    timeout()
                )
                .into());
            }
            SYNC_RETRIES.fetch_add(again.len() as u64, Ordering::Relaxed);
            std::thread::sleep(SYNC_BACKOFF); // xtask-allow: sleep — waiting for a real node that reported itself behind its peers
        }
        pending = again;
    }
    Ok(())
}
