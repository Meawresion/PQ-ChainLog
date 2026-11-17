//! A read-only block explorer over the demo chain, for the dashboard's Chain
//! page.
//!
//! One thread follows the node block by block over JSON-RPC: every block's
//! header, every transaction with its receipt, and every log. Calls and events
//! are decoded against the ABI of the artefact the demo **deploys**
//! (`contracts/out/Anchor.sol/Anchor.json`), so a name on the page is the
//! contract's own and an argument is what the chain stored, word for word.
//!
//! ⭐ It reads only what any node operator or auditor can read. It holds no
//! key and asks the demo's case for nothing; the page is where the client's
//! own values (its `R_e`, its checkpoints) are set beside the chain's.
//!
//! Its RPC traffic is tooling, not protocol, so it is **not** counted in the
//! Performance page's chain counters.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pqcl_exp::evm::{Rpc, keccak256, quantity};
use serde_json::{Value, json};

/// How often the explorer asks the node for new blocks.
const POLL: Duration = Duration::from_secs(1);
/// Blocks kept for the block list (transactions are all kept).
const KEEP_BLOCKS: usize = 240;
/// Most blocks fetched in one tick, so a long catch-up stays responsive.
const PER_TICK: u64 = 256;

/// A function, event or error from the ABI: name and inputs (name, type,
/// indexed).
#[derive(Debug, Clone)]
struct Entry {
    name: String,
    inputs: Vec<(String, String, bool)>,
}

impl Entry {
    fn signature(&self) -> String {
        let types: Vec<&str> = self.inputs.iter().map(|i| i.1.as_str()).collect();
        format!("{}({})", self.name, types.join(","))
    }
}

#[derive(Debug, Default)]
struct Abi {
    /// 4-byte selector (hex, no 0x) → function.
    functions: HashMap<String, Entry>,
    /// topic0 (hex, no 0x) → event.
    events: HashMap<String, Entry>,
}

impl Abi {
    fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let v: Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut abi = Self::default();
        for item in v["abi"].as_array().into_iter().flatten() {
            let entry = Entry {
                name: item["name"].as_str().unwrap_or("").to_owned(),
                inputs: item["inputs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|i| {
                        (
                            i["name"].as_str().unwrap_or("").to_owned(),
                            i["type"].as_str().unwrap_or("").to_owned(),
                            i["indexed"].as_bool().unwrap_or(false),
                        )
                    })
                    .collect(),
            };
            let hash = keccak256(entry.signature().as_bytes());
            match item["type"].as_str() {
                Some("function") => {
                    abi.functions.insert(hex(&hash[..4]), entry);
                }
                Some("event") => {
                    abi.events.insert(hex(&hash), entry);
                }
                _ => {}
            }
        }
        Ok(abi)
    }
}

fn hex(b: &[u8]) -> String {
    use core::fmt::Write;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// One ABI word as the page shows it. Static types only; the contract has no
/// dynamic argument, and one would be named rather than guessed at.
fn word_value(ty: &str, w: &[u8]) -> String {
    if w.len() < 32 {
        return "(short)".to_owned();
    }
    match ty {
        "address" => format!("0x{}", hex(&w[12..32])),
        "bool" => (w[31] != 0).to_string(),
        t if t.starts_with("uint") => {
            let mut v: u128 = 0;
            for b in &w[16..32] {
                v = (v << 8) | u128::from(*b);
            }
            if w[..16].iter().any(|b| *b != 0) {
                format!("0x{}", hex(w))
            } else {
                v.to_string()
            }
        }
        t if t.starts_with("bytes") && t != "bytes" => hex(w),
        other => format!("({other}: dynamic, not decoded)"),
    }
}

fn decode_call(abi: &Abi, input: &[u8]) -> (String, Vec<Value>) {
    if input.len() < 4 {
        return ("(no calldata)".to_owned(), Vec::new());
    }
    let Some(f) = abi.functions.get(&hex(&input[..4])) else {
        return ("(contract creation or unknown call)".to_owned(), Vec::new());
    };
    let args = f
        .inputs
        .iter()
        .enumerate()
        .map(|(i, (name, ty, _))| {
            let at = 4 + 32 * i;
            let w = input.get(at..at + 32).unwrap_or(&[]);
            json!([name, ty, word_value(ty, w)])
        })
        .collect();
    (f.signature(), args)
}

fn decode_log(abi: &Abi, log: &Value) -> Value {
    let topics: Vec<Vec<u8>> = log["topics"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(unhex)
        .collect();
    let data = unhex(log["data"].as_str().unwrap_or("0x"));
    let address = log["address"].as_str().unwrap_or("").to_owned();
    let Some(ev) = topics.first().and_then(|t| abi.events.get(&hex(t))) else {
        return json!({"event": "(unknown event)", "address": address, "args": []});
    };
    let mut topic_i = 1;
    let mut data_i = 0;
    let args: Vec<Value> = ev
        .inputs
        .iter()
        .map(|(name, ty, indexed)| {
            let w = if *indexed {
                topic_i += 1;
                topics.get(topic_i - 1).cloned().unwrap_or_default()
            } else {
                data_i += 1;
                data.get(32 * (data_i - 1)..32 * data_i)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default()
            };
            json!([name, ty, word_value(ty, &w), indexed])
        })
        .collect();
    json!({"event": ev.name, "signature": ev.signature(), "address": address, "args": args})
}

#[derive(Debug, Default)]
struct Explorer {
    rpc: String,
    abi_path: String,
    abi_error: Option<String>,
    error: Option<String>,
    chain_id: Option<u64>,
    validators: Vec<String>,
    height: Option<u64>,
    scanned: Option<u64>,
    blocks: VecDeque<Value>,
    txs: Vec<Value>,
    contracts: Vec<String>,
}

static EXPLORER: Mutex<Option<Explorer>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Start the explorer thread against `rpc`, decoding with the artefact at
/// `abi_path`.
///
/// # Errors
///
/// The thread cannot be spawned.
pub fn start(rpc: &str, abi_path: PathBuf) -> std::io::Result<()> {
    *lock(&EXPLORER) = Some(Explorer {
        rpc: rpc.to_owned(),
        abi_path: abi_path.display().to_string(),
        ..Explorer::default()
    });
    let url = rpc.to_owned();
    std::thread::Builder::new()
        .name("chain-explorer".to_owned())
        .spawn(move || follow(&url, &abi_path))?;
    Ok(())
}

fn set<F: FnOnce(&mut Explorer)>(f: F) {
    if let Some(e) = lock(&EXPLORER).as_mut() {
        f(e);
    }
}

fn follow(url: &str, abi_path: &Path) {
    let mut abi: Option<Abi> = None;
    loop {
        if abi.is_none() {
            // The artefact may be rebuilt before the demo starts; retry.
            match Abi::load(abi_path) {
                Ok(a) => {
                    abi = Some(a);
                    set(|e| e.abi_error = None);
                }
                Err(err) => set(|e| e.abi_error = Some(err)),
            }
        }
        let result = Rpc::new(url)
            .map_err(|e| e.0)
            .and_then(|rpc| tick(&rpc, abi.as_ref().unwrap_or(&Abi::default())));
        set(|e| e.error = result.err());
        std::thread::sleep(POLL); // xtask-allow: sleep — the explorer's real polling cadence against a live node
    }
}

// One pass over the new blocks, kept whole so the order of the RPC calls reads.
#[allow(clippy::too_many_lines)]
fn tick(rpc: &Rpc, abi: &Abi) -> Result<(), String> {
    let q = |v: &Value| quantity(v).map_err(|e| e.0);
    let height = q(&rpc.call("eth_blockNumber", json!([])).map_err(|e| e.0)?)?;
    let (scanned, need_meta) = lock(&EXPLORER)
        .as_ref()
        .map_or((None, true), |e| (e.scanned, e.chain_id.is_none()));
    // A lower height than we have scanned is a fresh chain: start again.
    let scanned = match scanned {
        Some(s) if s > height => {
            set(|e| {
                e.blocks.clear();
                e.txs.clear();
                e.contracts.clear();
                e.scanned = None;
                e.chain_id = None;
            });
            None
        }
        s => s,
    };
    if need_meta || scanned.is_none() {
        let chain_id = q(&rpc.call("eth_chainId", json!([])).map_err(|e| e.0)?)?;
        let validators: Vec<String> = rpc
            .call("qbft_getValidatorsByBlockNumber", json!(["latest"]))
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        set(|e| {
            e.chain_id = Some(chain_id);
            e.validators = validators;
        });
    }
    let from = scanned.map_or(0, |s| s + 1);
    let to = height.min(from + PER_TICK - 1);
    set(|e| e.height = Some(height));
    if from > to {
        return Ok(());
    }
    let params: Vec<Value> = (from..=to)
        .map(|n| json!([format!("0x{n:x}"), true]))
        .collect();
    let blocks = rpc
        .batch("eth_getBlockByNumber", &params)
        .map_err(|e| e.0)?;
    let mut new_blocks = Vec::new();
    let mut new_txs = Vec::new();
    let mut new_contracts = Vec::new();
    for b in blocks {
        let b = b.map_err(|e| e.0)?;
        let number = q(&b["number"])?;
        let ts = q(&b["timestamp"])?;
        let txs = b["transactions"].as_array().cloned().unwrap_or_default();
        let hashes: Vec<Value> = txs.iter().map(|t| json!([t["hash"]])).collect();
        let receipts = rpc
            .batch("eth_getTransactionReceipt", &hashes)
            .map_err(|e| e.0)?;
        for (t, r) in txs.iter().zip(receipts) {
            let r = r.map_err(|e| e.0)?;
            let input = unhex(t["input"].as_str().unwrap_or("0x"));
            let created = r["contractAddress"].as_str().map(str::to_owned);
            let (method, args) = if created.is_some() {
                ("deploy Anchor.sol".to_owned(), Vec::new())
            } else {
                decode_call(abi, &input)
            };
            if let Some(c) = &created {
                new_contracts.push(c.clone());
            }
            let words: Vec<String> = input
                .get(4..)
                .unwrap_or(&[])
                .chunks(32)
                .take(16)
                .map(hex)
                .collect();
            new_txs.push(json!({
                "hash": t["hash"], "block": number, "ts": ts,
                "from": t["from"], "to": t["to"], "nonce": q(&t["nonce"]).unwrap_or(0),
                "method": method, "args": args,
                "selector": input.get(..4).map(hex),
                "input_bytes": input.len(), "words": words,
                "gas_used": q(&r["gasUsed"]).unwrap_or(0),
                "status": r["status"].as_str() == Some("0x1"),
                "created": created,
                "logs": r["logs"].as_array().into_iter().flatten().map(|l| decode_log(abi, l)).collect::<Vec<_>>(),
            }));
        }
        new_blocks.push(json!({
            "number": number, "hash": b["hash"], "parent": b["parentHash"], "ts": ts,
            "txs": txs.len(), "gas_used": q(&b["gasUsed"]).unwrap_or(0),
            "size": q(&b["size"]).unwrap_or(0), "miner": b["miner"],
        }));
    }
    set(|e| {
        for b in new_blocks {
            e.blocks.push_back(b);
        }
        while e.blocks.len() > KEEP_BLOCKS {
            e.blocks.pop_front();
        }
        e.txs.extend(new_txs);
        e.contracts.extend(new_contracts);
        e.scanned = Some(to);
    });
    Ok(())
}

/// What the Chain page draws.
#[must_use]
pub fn snapshot() -> Value {
    let guard = lock(&EXPLORER);
    let Some(e) = guard.as_ref() else {
        return json!({"running": false});
    };
    let blocks: Vec<&Value> = e.blocks.iter().rev().collect();
    let txs: Vec<&Value> = e.txs.iter().rev().collect();
    json!({
        "running": true, "rpc": e.rpc, "abi": e.abi_path, "abi_error": e.abi_error,
        "error": e.error, "chain_id": e.chain_id, "validators": e.validators,
        "height": e.height, "scanned": e.scanned, "blocks": blocks, "txs": txs,
        "contracts": e.contracts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_decode_by_type() {
        let mut w = [0u8; 32];
        w[31] = 7;
        assert_eq!(word_value("uint64", &w), "7");
        assert_eq!(word_value("bool", &w), "true");
        assert_eq!(word_value("bytes32", &w), format!("{}07", "00".repeat(31)));
        w[12] = 0xab;
        assert!(word_value("address", &w).starts_with("0xab"));
    }

    #[test]
    fn a_call_decodes_against_its_selector() {
        let mut abi = Abi::default();
        let f = Entry {
            name: "authoriseSearch".into(),
            inputs: vec![
                ("nullifier".into(), "bytes32".into(), false),
                ("scopeCommit".into(), "bytes32".into(), false),
            ],
        };
        let sel = keccak256(f.signature().as_bytes());
        abi.functions.insert(hex(&sel[..4]), f);
        let mut input = sel[..4].to_vec();
        input.extend([1u8; 32]);
        input.extend([2u8; 32]);
        let (name, args) = decode_call(&abi, &input);
        assert_eq!(name, "authoriseSearch(bytes32,bytes32)");
        assert_eq!(args[1][2], hex(&[2u8; 32]));
    }
}
