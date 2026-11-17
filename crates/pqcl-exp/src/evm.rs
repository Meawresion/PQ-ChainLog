//! A minimal EVM client for the chain experiments (M10 H2).
//!
//! Exp. 6 compares LEChain's per-transition transactions with our per-epoch
//! anchor **on the same Besu network, through the same client**, so neither
//! side's latency carries a different submission path. Nothing else in the
//! workspace sends transactions — `forge create` deploys in the acceptance
//! script, and `exp6` reads its gas out of Foundry — so this is that client,
//! kept to what the experiment needs:
//!
//! * Keccak-256, RLP, EIP-155 legacy transactions, the secp256k1 signature an
//!   Ethereum transaction envelope carries;
//! * Solidity ABI encoding for static words, `bytes`/`string` and word arrays;
//! * JSON-RPC over plain HTTP/1.1 to a local node — `std::net` only.
//!
//! ⛔ **KATs before use** (house rule 17). The transaction encoder is checked
//! against EIP-155's own worked example, the ABI encoder against the Solidity
//! ABI specification's `sam` example, and key-to-address against the Besu dev
//! account this repository's genesis funds. A primitive that has not passed
//! vectors in our build is a guess.
//!
//! ⚠️ secp256k1 signs **transaction envelopes** here and nothing else — never
//! evidence, never a custody record. `xtask no-stubs` confines `k256` to this
//! crate.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

/// A 20-byte account address.
pub type Address = [u8; 20];

/// A 32-byte ABI word.
pub type Word = [u8; 32];

/// Anything that went wrong talking to the chain, named.
#[derive(Debug)]
pub struct EvmError(pub String);

impl core::fmt::Display for EvmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for EvmError {}

fn err(msg: impl Into<String>) -> EvmError {
    EvmError(msg.into())
}

/// Keccak-256 — Ethereum's pre-standardisation SHA-3, **not** SHA3-256.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Lower-case hex with a `0x` prefix.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(2 + 2 * bytes.len());
    s.push_str("0x");
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse hex, with or without `0x`.
///
/// # Errors
///
/// Odd length or a non-hex digit.
pub fn from_hex(s: &str) -> Result<Vec<u8>, EvmError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(err(format!("odd-length hex: {s}")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| err(format!("hex {s}: {e}"))))
        .collect()
}

/// A hex quantity (`0x1a`) as an integer.
///
/// # Errors
///
/// Not a hex quantity.
pub fn quantity(v: &serde_json::Value) -> Result<u64, EvmError> {
    let s = v
        .as_str()
        .ok_or_else(|| err(format!("expected a hex quantity, got {v}")))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|e| err(format!("quantity {s}: {e}")))
}

// ------------------------------------------------------------------ RLP

fn minimal_be(x: u128) -> Vec<u8> {
    x.to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect()
}

fn strip_zeros(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|x| **x == 0).count();
    &b[n..]
}

fn rlp_len(len: usize, offset: u8) -> Vec<u8> {
    match u8::try_from(len) {
        Ok(l) if l < 56 => vec![offset + l],
        _ => {
            let be = minimal_be(len as u128);
            // `be` is at most 16 bytes, so this cannot truncate.
            let mut v = vec![offset + 55 + u8::try_from(be.len()).unwrap_or(16)];
            v.extend(be);
            v
        }
    }
}

/// RLP of a byte string.
#[must_use]
pub fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if let [x] = b
        && *x < 0x80
    {
        return vec![*x];
    }
    let mut out = rlp_len(b.len(), 0x80);
    out.extend_from_slice(b);
    out
}

/// RLP of an unsigned integer (minimal big-endian, zero as the empty string).
#[must_use]
pub fn rlp_uint(x: u128) -> Vec<u8> {
    rlp_bytes(&minimal_be(x))
}

/// RLP of a list of already-encoded items.
#[must_use]
pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload = items.concat();
    let mut out = rlp_len(payload.len(), 0xc0);
    out.extend(payload);
    out
}

// ----------------------------------------------------------- keys, txs

/// A secp256k1 account key.
pub struct Key {
    sk: SigningKey,
    /// Its address.
    pub address: Address,
}

impl Key {
    /// From a 32-byte secret.
    ///
    /// # Errors
    ///
    /// The scalar is zero or out of range.
    pub fn from_secret(secret: &[u8]) -> Result<Self, EvmError> {
        let sk = SigningKey::from_slice(secret).map_err(|e| err(format!("secret key: {e}")))?;
        let point = sk.verifying_key().to_encoded_point(false);
        let h = keccak256(&point.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&h[12..]);
        Ok(Self { sk, address })
    }

    /// Sign a 32-byte digest as `ecrecover` expects: `(v = 27 + recid, r, s)`.
    ///
    /// # Errors
    ///
    /// The signer refused the digest.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<(u8, Word, Word), EvmError> {
        let (sig, recid) = self
            .sk
            .sign_prehash_recoverable(digest)
            .map_err(|e| err(format!("sign: {e}")))?;
        let (r, s) = sig.split_bytes();
        Ok((27 + recid.to_byte(), r.into(), s.into()))
    }
}

/// A pre-EIP-2718 ("legacy") transaction, signed under EIP-155.
///
/// Legacy rather than typed because the network runs `zeroBaseFee` with a
/// zero minimum gas price: no fee market exists for a type-2 transaction to
/// express, and the legacy envelope is what LEChain's own client (web3.py in
/// 2020) submitted.
#[derive(Debug, Clone)]
pub struct LegacyTx {
    /// Sender nonce.
    pub nonce: u64,
    /// Gas price in wei.
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient, or `None` for a contract creation.
    pub to: Option<Address>,
    /// Value in wei.
    pub value: u128,
    /// Calldata or init code.
    pub data: Vec<u8>,
}

impl LegacyTx {
    fn fields(&self) -> Vec<Vec<u8>> {
        vec![
            rlp_uint(u128::from(self.nonce)),
            rlp_uint(self.gas_price),
            rlp_uint(u128::from(self.gas_limit)),
            rlp_bytes(self.to.as_ref().map_or(&[][..], |a| &a[..])),
            rlp_uint(self.value),
            rlp_bytes(&self.data),
        ]
    }

    /// The EIP-155 signing payload, `rlp([…, chainId, 0, 0])`.
    #[must_use]
    pub fn signing_data(&self, chain_id: u64) -> Vec<u8> {
        let mut f = self.fields();
        f.extend([rlp_uint(u128::from(chain_id)), rlp_uint(0), rlp_uint(0)]);
        rlp_list(&f)
    }

    /// Sign and encode, ready for `eth_sendRawTransaction`.
    ///
    /// # Errors
    ///
    /// The signer refused the digest.
    pub fn sign(&self, key: &Key, chain_id: u64) -> Result<Vec<u8>, EvmError> {
        let digest = keccak256(&self.signing_data(chain_id));
        let (sig, recid) = key
            .sk
            .sign_prehash_recoverable(&digest)
            .map_err(|e| err(format!("sign: {e}")))?;
        let (r, s) = sig.split_bytes();
        let v = u128::from(recid.to_byte()) + 35 + 2 * u128::from(chain_id);
        let mut f = self.fields();
        f.extend([
            rlp_uint(v),
            rlp_bytes(strip_zeros(&r)),
            rlp_bytes(strip_zeros(&s)),
        ]);
        Ok(rlp_list(&f))
    }
}

// ------------------------------------------------------------------ ABI

/// One ABI argument.
#[derive(Debug, Clone)]
pub enum Abi {
    /// A static 32-byte word: `uintN`, `bool`, `address`, `bytes32`.
    Word(Word),
    /// Dynamic `bytes` or `string` — identical encodings.
    Bytes(Vec<u8>),
    /// A dynamic array of static words, e.g. `address[]`, `uint256[]`.
    Words(Vec<Word>),
}

/// `uint256` word.
#[must_use]
pub fn uint(x: u128) -> Word {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&x.to_be_bytes());
    w
}

/// `address` word, left-padded.
#[must_use]
pub fn address_word(a: &Address) -> Word {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// The 4-byte selector of a canonical signature, e.g. `"f(uint256)"`.
#[must_use]
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn padded(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    v.resize(b.len().div_ceil(32) * 32, 0);
    v
}

/// Head/tail encoding of an argument tuple.
#[must_use]
pub fn abi_encode(args: &[Abi]) -> Vec<u8> {
    let head_len = 32 * args.len();
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();
    for a in args {
        match a {
            Abi::Word(w) => head.extend_from_slice(w),
            Abi::Bytes(b) => {
                head.extend_from_slice(&uint((head_len + tail.len()) as u128));
                tail.extend_from_slice(&uint(b.len() as u128));
                tail.extend(padded(b));
            }
            Abi::Words(ws) => {
                head.extend_from_slice(&uint((head_len + tail.len()) as u128));
                tail.extend_from_slice(&uint(ws.len() as u128));
                for w in ws {
                    tail.extend_from_slice(w);
                }
            }
        }
    }
    head.extend(tail);
    head
}

/// Selector plus encoded arguments.
#[must_use]
pub fn encode_call(signature: &str, args: &[Abi]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    out.extend(abi_encode(args));
    out
}

// ------------------------------------------------------------- JSON-RPC

/// Requests per JSON-RPC batch. Besu refuses a batch above
/// `--rpc-http-max-batch-size` (default 1024) outright, so a larger call is
/// split rather than tuned into the node's configuration.
pub const MAX_BATCH: usize = 256;

/// JSON-RPC over HTTP/1.1 to a local node, one connection per request.
///
/// `std::net` only: the node is on loopback, there is no TLS to speak, and a
/// full HTTP stack would be a dependency measured by nothing.
pub struct Rpc {
    addr: String,
    path: String,
    timeout: Duration,
}

impl Rpc {
    /// From `http://host:port[/path]`.
    ///
    /// # Errors
    ///
    /// Not a plain `http://` URL.
    pub fn new(url: &str) -> Result<Self, EvmError> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| err(format!("only http:// is supported: {url}")))?;
        let (addr, path) = rest
            .find('/')
            .map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
        Ok(Self {
            addr: addr.to_owned(),
            path: path.to_owned(),
            timeout: Duration::from_secs(30),
        })
    }

    fn post(&self, body: &[u8]) -> Result<Vec<u8>, EvmError> {
        let mut s = TcpStream::connect(&self.addr)
            .map_err(|e| err(format!("connect {}: {e}", self.addr)))?;
        s.set_read_timeout(Some(self.timeout))
            .and_then(|()| s.set_write_timeout(Some(self.timeout)))
            .map_err(|e| err(format!("socket: {e}")))?;
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.addr,
            body.len()
        );
        s.write_all(req.as_bytes())
            .and_then(|()| s.write_all(body))
            .map_err(|e| err(format!("write: {e}")))?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp)
            .map_err(|e| err(format!("read: {e}")))?;
        split_http(&resp)
    }

    /// One call; the `result`, or the node's error.
    ///
    /// # Errors
    ///
    /// Transport failure, or a JSON-RPC `error` object.
    pub fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, EvmError> {
        let mut body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method});
        body["params"] = params;
        let raw = self.post(body.to_string().as_bytes())?;
        let v: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| err(format!("{method}: bad JSON: {e}")))?;
        one_result(method, &v)
    }

    /// Many calls as JSON-RPC batches of at most [`MAX_BATCH`]; results in
    /// request order.
    ///
    /// # Errors
    ///
    /// Transport failure or a malformed batch reply. Per-call errors come back
    /// as `Err` entries, not as a failure of the batch.
    pub fn batch(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<Vec<Result<serde_json::Value, EvmError>>, EvmError> {
        let mut out = Vec::with_capacity(params.len());
        for chunk in params.chunks(MAX_BATCH) {
            out.extend(self.one_batch(method, chunk)?);
        }
        Ok(out)
    }

    fn one_batch(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<Vec<Result<serde_json::Value, EvmError>>, EvmError> {
        if params.is_empty() {
            return Ok(Vec::new());
        }
        let body: Vec<serde_json::Value> = params
            .iter()
            .enumerate()
            .map(|(i, p)| serde_json::json!({"jsonrpc": "2.0", "id": i, "method": method, "params": p}))
            .collect();
        let raw = self.post(serde_json::Value::Array(body).to_string().as_bytes())?;
        let v: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| err(format!("{method} batch: bad JSON: {e}")))?;
        let arr = v
            .as_array()
            .ok_or_else(|| err(format!("{method} batch: reply is not an array: {v}")))?;
        let mut out: Vec<Option<Result<serde_json::Value, EvmError>>> =
            (0..params.len()).map(|_| None).collect();
        for item in arr {
            let id = item
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .and_then(|i| usize::try_from(i).ok())
                .filter(|i| *i < params.len())
                .ok_or_else(|| err(format!("{method} batch: reply without a valid id: {item}")))?;
            out[id] = Some(one_result(method, item));
        }
        out.into_iter()
            .enumerate()
            .map(|(i, r)| r.ok_or_else(|| err(format!("{method} batch: no reply for request {i}"))))
            .collect()
    }
}

fn one_result(method: &str, v: &serde_json::Value) -> Result<serde_json::Value, EvmError> {
    if let Some(e) = v.get("error") {
        return Err(err(format!("{method}: {e}")));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| err(format!("{method}: reply has neither result nor error: {v}")))
}

/// Split an HTTP/1.1 response into its body, decoding chunked transfer.
fn split_http(resp: &[u8]) -> Result<Vec<u8>, EvmError> {
    let end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| err("HTTP response has no header terminator"))?;
    let head = String::from_utf8_lossy(&resp[..end]).to_ascii_lowercase();
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200") {
        return Err(err(format!("HTTP status: {status}")));
    }
    let body = &resp[end + 4..];
    if !head.contains("transfer-encoding: chunked") {
        return Ok(body.to_vec());
    }
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let nl = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| err("chunked body: missing size line"))?;
        let size_str = String::from_utf8_lossy(&rest[..nl]);
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|e| err(format!("chunk size {size_str}: {e}")))?;
        rest = &rest[nl + 2..];
        if size == 0 {
            return Ok(out);
        }
        let chunk = rest
            .get(..size)
            .ok_or_else(|| err("chunked body: truncated chunk"))?;
        out.extend_from_slice(chunk);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        from_hex(s).unwrap()
    }

    /// RLP specification examples.
    #[test]
    fn rlp_matches_the_specification() {
        assert_eq!(rlp_bytes(b"dog"), hex("83646f67"));
        assert_eq!(
            rlp_list(&[rlp_bytes(b"cat"), rlp_bytes(b"dog")]),
            hex("c88363617483646f67")
        );
        assert_eq!(rlp_bytes(b""), hex("80"));
        assert_eq!(rlp_list(&[]), hex("c0"));
        assert_eq!(rlp_uint(0), hex("80"));
        assert_eq!(rlp_uint(15), hex("0f"));
        assert_eq!(rlp_uint(1024), hex("820400"));
        let lorem = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit";
        let mut want = hex("b838");
        want.extend_from_slice(lorem);
        assert_eq!(rlp_bytes(lorem), want);
    }

    /// ⭐ EIP-155's own worked example, verbatim from EIPS/eip-155.md.
    #[test]
    fn eip155_worked_example() {
        let tx = LegacyTx {
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some([0x35; 20]),
            value: 1_000_000_000_000_000_000,
            data: Vec::new(),
        };
        assert_eq!(
            tx.signing_data(1),
            hex(
                "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
            )
        );
        assert_eq!(
            keccak256(&tx.signing_data(1)).to_vec(),
            hex("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
        );
        let key = Key::from_secret(&[0x46; 32]).unwrap();
        assert_eq!(
            tx.sign(&key, 1).unwrap(),
            hex(
                "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
            )
        );
    }

    /// The Besu dev account this repository's genesis funds
    /// (`besu/qbft-config.json`, `besu/acceptance.sh`).
    #[test]
    fn besu_dev_key_derives_the_funded_address() {
        let key = Key::from_secret(&hex(
            "8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63",
        ))
        .unwrap();
        assert_eq!(
            key.address.to_vec(),
            hex("fe3b557e8fb62b89f4916b721be55ceb828dbd73")
        );
    }

    /// ⭐ The Solidity ABI specification's `sam("dave", true, [1,2,3])`.
    #[test]
    fn abi_matches_the_specification() {
        let got = encode_call(
            "sam(bytes,bool,uint256[])",
            &[
                Abi::Bytes(b"dave".to_vec()),
                Abi::Word(uint(1)),
                Abi::Words(vec![uint(1), uint(2), uint(3)]),
            ],
        );
        assert_eq!(
            got,
            hex(
                "a5643bf20000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000464617665000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003"
            )
        );
    }

    /// A digest signature must recover to the signer — what LEChain's
    /// `ecrecover(msgh, v, r, s) == msg.sender` checks on chain.
    #[test]
    fn a_digest_signature_recovers_to_the_signer() {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        let key = Key::from_secret(&[0x11; 32]).unwrap();
        let digest = keccak256(b"custody transition");
        let (v, r, s) = key.sign_digest(&digest).unwrap();
        let sig = Signature::from_scalars(r, s).unwrap();
        let vk = VerifyingKey::recover_from_prehash(
            &digest,
            &sig,
            RecoveryId::from_byte(v - 27).unwrap(),
        )
        .unwrap();
        let h = keccak256(&vk.to_encoded_point(false).as_bytes()[1..]);
        assert_eq!(h[12..], key.address);
    }

    #[test]
    fn http_bodies_are_split_and_dechunked() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(split_http(plain).unwrap(), b"{}");
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n4\r\n\":1}\r\n0\r\n\r\n";
        assert_eq!(split_http(chunked).unwrap(), b"{\"a\":1}");
        assert!(split_http(b"HTTP/1.1 500 Oops\r\n\r\n").is_err());
    }
}
