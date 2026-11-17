//! The live chain, as the demo talks to it: deploy `Anchor.sol`, commit epoch
//! roots, record redaction orders, register search nullifiers, and read the
//! anchored state back.
//!
//! Every call is a real transaction or `eth_call` against the Besu node, through
//! `pqcl-exp`'s client — the one Exp. 6 measured with — so the demo and the
//! experiment cannot disagree about encodings.

use std::path::Path;
use std::time::{Duration, Instant};

use pqcl_exp::evm::{
    Abi, Address, Key, LegacyTx, Rpc, Word, encode_call, from_hex, quantity, to_hex,
};
use pqcl_primitives::xof::Digest32;

/// The Besu dev account the demo genesis funds (`besu/demo/qbft-demo-config.json`).
/// Gas is free (`zeroBaseFee`, `--min-gas-price=0`); the balance only exists so
/// the account is valid.
const DEV_SECRET: &str = "8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";

/// How long to wait for a transaction to be included.
const INCLUSION_TIMEOUT: Duration = Duration::from_mins(1);
const POLL: Duration = Duration::from_millis(250);

/// A chain error, named.
#[derive(Debug)]
pub struct ChainError(pub String);

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for ChainError {}

impl From<pqcl_exp::evm::EvmError> for ChainError {
    fn from(e: pqcl_exp::evm::EvmError) -> Self {
        Self(e.0)
    }
}

type Res<T> = Result<T, ChainError>;

/// What a mined transaction produced.
#[derive(Debug, Clone)]
pub struct Receipt {
    /// Transaction hash.
    pub tx_hash: String,
    /// Block it was included in.
    pub block: u64,
    /// `gasUsed`.
    pub gas_used: u64,
    /// The transaction's own byte length on the wire.
    pub tx_bytes: usize,
}

/// The anchored epoch `latestEpoch(cid)` returns.
///
/// ⚠️ **No leaf count** (M13 A21): the chain does not carry one. `n_e` is
/// committed inside `checkpoint` and travels in the off-chain audit package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchored {
    /// `R_e` as stored on chain.
    pub root: Digest32,
    /// The block that anchored it.
    pub block: u64,
    /// `d_e`, the checkpoint.
    pub checkpoint: Digest32,
    /// `A_e`, the approval-set digest.
    pub approval: Digest32,
}

/// One JSON-RPC exchange, counted for the Performance page and charged to the
/// chain side of the worker's clock (`perf`). The bytes counted are the
/// method, the params and the result as JSON, not the HTTP envelope.
fn jsonrpc(rpc: &Rpc, method: &str, params: serde_json::Value) -> Res<serde_json::Value> {
    let _side = crate::perf::on(crate::perf::Side::Chain);
    let up = method.len() + params.to_string().len();
    let v = rpc.call(method, params)?;
    crate::perf::rpc(up, v.to_string().len());
    Ok(v)
}

fn word(w: &[u8]) -> Digest32 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&w[..32]);
    out
}

fn anchored(data: &[u8]) -> Res<Anchored> {
    if data.len() < 128 {
        return Err(ChainError("an anchored epoch needs four words".into()));
    }
    Ok(Anchored {
        root: word(&data[..32]),
        block: word_u64(&data[32..64]),
        checkpoint: word(&data[64..96]),
        approval: word(&data[96..128]),
    })
}

/// One connection to the node, with one funded sender.
pub struct ChainSession {
    rpc: Rpc,
    url: String,
    chain_id: u64,
    key: Key,
    nonce: u64,
    /// `Anchor.sol`'s address once deployed.
    pub anchor: Option<Address>,
}

impl core::fmt::Debug for ChainSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChainSession")
            .field("url", &self.url)
            .field("chain_id", &self.chain_id)
            .field("anchor", &self.anchor.map(|a| to_hex(&a)))
            .finish_non_exhaustive()
    }
}

impl ChainSession {
    /// Connect and read the chain id and the sender's nonce.
    ///
    /// # Errors
    ///
    /// The node is unreachable or answers malformed JSON.
    pub fn connect(url: &str) -> Res<Self> {
        let rpc = Rpc::new(url)?;
        let chain_id = quantity(&jsonrpc(&rpc, "eth_chainId", serde_json::json!([]))?)?;
        let key = Key::from_secret(&from_hex(DEV_SECRET)?)?;
        let nonce = quantity(&jsonrpc(
            &rpc,
            "eth_getTransactionCount",
            serde_json::json!([to_hex(&key.address), "pending"]),
        )?)?;
        Ok(Self {
            rpc,
            url: url.to_owned(),
            chain_id,
            key,
            nonce,
            anchor: None,
        })
    }

    /// The node's URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// `eth_chainId`.
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The current block height.
    ///
    /// # Errors
    ///
    /// RPC failure.
    pub fn block_number(&self) -> Res<u64> {
        Ok(quantity(
            &self.jsonrpc("eth_blockNumber", serde_json::json!([]))?,
        )?)
    }

    /// How many validators the node reports (`qbft_getValidatorsByBlockNumber`).
    ///
    /// # Errors
    ///
    /// RPC failure.
    pub fn validators(&self) -> Res<usize> {
        let v = self.jsonrpc(
            "qbft_getValidatorsByBlockNumber",
            serde_json::json!(["latest"]),
        )?;
        Ok(v.as_array().map_or(0, Vec::len))
    }

    /// Deploy `Anchor.sol` (draft8, D4): a registry that verifies no
    /// signature, so it takes no keys.
    ///
    /// # Errors
    ///
    /// A missing build artefact, or the deployment failed.
    pub fn deploy_anchor(&mut self, artefact: &Path) -> Res<Receipt> {
        let init = artifact_bytecode(artefact)?;
        let (receipt, raw) = self.send(None, init)?;
        let addr = raw["contractAddress"]
            .as_str()
            .ok_or_else(|| ChainError("deployment receipt has no contractAddress".into()))?;
        let bytes = from_hex(addr)?;
        let mut a = [0u8; 20];
        a.copy_from_slice(&bytes);
        self.anchor = Some(a);
        Ok(receipt)
    }

    fn anchor(&self) -> Res<Address> {
        self.anchor
            .ok_or_else(|| ChainError("Anchor.sol is not deployed yet".into()))
    }

    /// `registerCase(cid, reg)` — draft8 Phase 1 Step 3, once per case.
    ///
    /// # Errors
    ///
    /// Already registered, or not included.
    pub fn register_case(&mut self, cid: &Digest32, reg: &Digest32) -> Res<Receipt> {
        let data = encode_call(
            "registerCase(bytes32,bytes32)",
            &[Abi::Word(*cid), Abi::Word(*reg)],
        );
        let to = self.anchor()?;
        Ok(self.send(Some(to), data)?.0)
    }

    /// `commitRoot(cid, R_e, d_{e−1}, d_e, A_e)` — draft8 `eq:anchortx`. No
    /// signature and, since M13 A21, no leaf count goes on chain.
    ///
    /// # Errors
    ///
    /// The checkpoint does not extend the last one, or the transaction was not
    /// included.
    pub fn commit_root(
        &mut self,
        cid: &Digest32,
        root: &Digest32,
        d_prev: &Digest32,
        d_e: &Digest32,
        a_e: &Digest32,
    ) -> Res<Receipt> {
        let data = encode_call(
            "commitRoot(bytes32,bytes32,bytes32,bytes32,bytes32)",
            &[
                Abi::Word(*cid),
                Abi::Word(*root),
                Abi::Word(*d_prev),
                Abi::Word(*d_e),
                Abi::Word(*a_e),
            ],
        );
        let to = self.anchor()?;
        Ok(self.send(Some(to), data)?.0)
    }

    /// `latestEpoch(cid)`, read back from chain state.
    ///
    /// # Errors
    ///
    /// The case has never anchored (`UnknownEpoch`), or RPC failure.
    pub fn latest_epoch(&self, cid: &Digest32) -> Res<Anchored> {
        let data = encode_call("latestEpoch(bytes32)", &[Abi::Word(*cid)]);
        let out = self.call(self.anchor()?, &data)?;
        anchored(&out)
    }

    /// Every root ever anchored for `cid`, oldest first, from the
    /// `RootCommitted` events: public data, which is all an auditor has.
    /// `latestEpoch` alone would hide every superseded root, and Phase 10
    /// checks a sealing epoch's leaf against *that* epoch's root.
    ///
    /// # Errors
    ///
    /// RPC failure or a malformed log.
    pub fn anchored_history(&self, cid: &Digest32) -> Res<Vec<Anchored>> {
        let topic0 =
            pqcl_exp::evm::keccak256(b"RootCommitted(bytes32,bytes32,uint64,bytes32,bytes32)");
        let logs = self.jsonrpc(
            "eth_getLogs",
            serde_json::json!([{
                "fromBlock": "0x0", "toBlock": "latest",
                "address": to_hex(&self.anchor()?),
                "topics": [to_hex(&topic0), to_hex(cid)],
            }]),
        )?;
        let mut out = Vec::new();
        for l in logs.as_array().into_iter().flatten() {
            out.push(anchored(&from_hex(l["data"].as_str().unwrap_or("0x"))?)?);
        }
        Ok(out)
    }

    /// `orderRedaction(cid, oid, digest)` — Phase 11 Step 1 under D4: the
    /// order's digest goes on chain before anything is deleted; `σ_CO` is
    /// verified by the AIS and auditors. Only the case's anchorer — the account
    /// that registered it — may record one (M13 A16).
    ///
    /// # Errors
    ///
    /// Already recorded, not this case's anchorer, or not included.
    pub fn order_redaction(
        &mut self,
        cid: &Digest32,
        oid: &Digest32,
        digest: &Digest32,
    ) -> Res<Receipt> {
        let data = encode_call(
            "orderRedaction(bytes32,bytes32,bytes32)",
            &[Abi::Word(*cid), Abi::Word(*oid), Abi::Word(*digest)],
        );
        let to = self.anchor()?;
        Ok(self.send(Some(to), data)?.0)
    }

    /// `authoriseSearch(N, scopeCommit)` — Phase 8 Step 2's registration.
    ///
    /// # Errors
    ///
    /// The nullifier was already spent, or the transaction was not included.
    pub fn authorise_search(
        &mut self,
        nullifier: &Digest32,
        scope_commit: &Digest32,
    ) -> Res<Receipt> {
        let data = encode_call(
            "authoriseSearch(bytes32,bytes32)",
            &[Abi::Word(*nullifier), Abi::Word(*scope_commit)],
        );
        let to = self.anchor()?;
        Ok(self.send(Some(to), data)?.0)
    }

    /// `nullifierSpent(N)`.
    ///
    /// # Errors
    ///
    /// RPC failure.
    pub fn nullifier_spent(&self, nullifier: &Digest32) -> Res<bool> {
        let data = encode_call("nullifierSpent(bytes32)", &[Abi::Word(*nullifier)]);
        let out = self.call(self.anchor()?, &data)?;
        Ok(out.get(31).copied() == Some(1))
    }

    /// `recordedOrder(cid, oid)`: non-zero once the order is on chain in that
    /// case (M13 A16 keys orders by case).
    ///
    /// # Errors
    ///
    /// RPC failure.
    pub fn recorded_order(&self, cid: &Digest32, oid: &Digest32) -> Res<Option<Word>> {
        let data = encode_call(
            "recordedOrder(bytes32,bytes32)",
            &[Abi::Word(*cid), Abi::Word(*oid)],
        );
        let out = self.call(self.anchor()?, &data)?;
        let mut w = [0u8; 32];
        w.copy_from_slice(out.get(..32).unwrap_or(&[0; 32]));
        Ok((w != [0; 32]).then_some(w))
    }

    /// The latest block's timestamp, which `orderRedaction` compares `exp` to.
    ///
    /// # Errors
    ///
    /// RPC failure.
    pub fn block_timestamp(&self) -> Res<u64> {
        let b = self.jsonrpc("eth_getBlockByNumber", serde_json::json!(["latest", false]))?;
        Ok(quantity(&b["timestamp"])?)
    }

    fn jsonrpc(&self, method: &str, params: serde_json::Value) -> Res<serde_json::Value> {
        jsonrpc(&self.rpc, method, params)
    }

    fn call(&self, to: Address, data: &[u8]) -> Res<Vec<u8>> {
        let v = self.jsonrpc(
            "eth_call",
            serde_json::json!([{"to": to_hex(&to), "data": to_hex(data)}, "latest"]),
        )?;
        let s = v
            .as_str()
            .ok_or_else(|| ChainError("eth_call returned no data".into()))?;
        Ok(from_hex(s)?)
    }

    /// Sign, send, and wait for inclusion. A reverted transaction is an error
    /// carrying the node's revert reason, never a receipt.
    fn send(&mut self, to: Option<Address>, data: Vec<u8>) -> Res<(Receipt, serde_json::Value)> {
        let _span = crate::perf::span(
            crate::perf::Side::Chain,
            "chain: sign, send, wait for inclusion",
        );
        let mut call =
            serde_json::json!({"from": to_hex(&self.key.address), "data": to_hex(&data)});
        if let Some(a) = to {
            call["to"] = serde_json::json!(to_hex(&a));
        }
        // `eth_estimateGas` runs the call first, so a revert surfaces here with
        // its reason, before anything is sent.
        let est = quantity(&self.jsonrpc("eth_estimateGas", serde_json::json!([call]))?)?;
        let tx = LegacyTx {
            nonce: self.nonce,
            gas_price: 0,
            gas_limit: est * 13 / 10,
            to,
            value: 0,
            data,
        };
        let raw = tx.sign(&self.key, self.chain_id)?;
        let hash = self.jsonrpc("eth_sendRawTransaction", serde_json::json!([to_hex(&raw)]))?;
        let hash = hash
            .as_str()
            .ok_or_else(|| ChainError("eth_sendRawTransaction returned no hash".into()))?
            .to_owned();
        self.nonce += 1;

        let start = Instant::now();
        loop {
            let r = self.jsonrpc("eth_getTransactionReceipt", serde_json::json!([hash]))?;
            if !r.is_null() {
                if r["status"].as_str() != Some("0x1") {
                    return Err(ChainError(format!("transaction {hash} reverted")));
                }
                let receipt = Receipt {
                    tx_hash: hash,
                    block: quantity(&r["blockNumber"])?,
                    gas_used: quantity(&r["gasUsed"])?,
                    tx_bytes: raw.len(),
                };
                crate::perf::tx(receipt.gas_used, receipt.tx_bytes);
                return Ok((receipt, r));
            }
            if start.elapsed() > INCLUSION_TIMEOUT {
                return Err(ChainError(format!(
                    "transaction {hash} not included within {INCLUSION_TIMEOUT:?}"
                )));
            }
            std::thread::sleep(POLL); // xtask-allow: sleep — polling a real node for block inclusion is real waiting, not simulated work
        }
    }
}

fn word_u64(w: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&w[24..32]);
    u64::from_be_bytes(b)
}

/// The deployable bytecode from a Foundry artefact (`forge build` output).
fn artifact_bytecode(path: &Path) -> Res<Vec<u8>> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        ChainError(format!(
            "{}: {e}. Run `forge build --root contracts` first.",
            path.display()
        ))
    })?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| ChainError(format!("{}: {e}", path.display())))?;
    let code = v["bytecode"]["object"]
        .as_str()
        .ok_or_else(|| ChainError(format!("{}: no bytecode.object", path.display())))?;
    Ok(from_hex(code)?)
}
