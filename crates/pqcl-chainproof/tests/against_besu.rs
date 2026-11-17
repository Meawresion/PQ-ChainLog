//! Verify a `SearchAuthorised` event against the **real Besu chain**.
//!
//! ⭐ **This is the test that matters.** Everything in the unit tests builds a
//! trie with this crate's own code and then verifies it with this crate's own
//! code — which catches internal inconsistency but would happily pass if our
//! whole notion of an Ethereum receipt trie were wrong. This test takes a
//! header and receipts that **Hyperledger Besu** produced, reconstructs the
//! receipt trie, and checks that our root matches the `receiptsRoot` Besu
//! independently computed. If our RLP, our hex-prefix encoding, our inlining
//! rule or our receipt encoding were wrong in any way, those two roots would
//! differ.
//!
//! ⛔ **It does not skip.** A missing chain fails loudly and says how to start
//! one, the same discipline as the PKCS#11 tests. A test that quietly passes
//! when its subject is absent reports green forever.
//!
//! Run it with a chain up:
//!
//! ```sh
//! cd besu && docker compose up -d && cd ..
//! PQCL_BESU_RPC=http://localhost:8545 cargo test -p pqcl-chainproof --test against_besu
//! ```

// The workspace's test lint allowances, matching the other integration suites:
// a panic in a test is a failure report, which is what it is for.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use std::sync::OnceLock;

use pqcl_chainproof::{
    BlockHeader, Consensus, ExpectedEvent, InclusionProof, mpt, rlp, search_authorised_topic,
    verify_search_authorised,
};

/// The fixture a run produces: everything needed to rebuild and verify.
struct Fixture {
    header_rlp: Vec<u8>,
    block_hash: [u8; 32],
    receipts_root: [u8; 32],
    /// `(tx_index, raw receipt bytes as stored in the trie)`.
    receipts: Vec<(u64, Vec<u8>)>,
    tx_index: u64,
    contract: [u8; 20],
    nullifier: [u8; 32],
    scope_commit: [u8; 32],
}

fn rpc_url() -> String {
    std::env::var("PQCL_BESU_RPC").unwrap_or_else(|_| "http://localhost:8545".to_owned())
}

/// Drive the chain through `besu/searchauth-fixture.sh`, which deploys the
/// contract, calls `authoriseSearch`, and prints the header and receipts.
///
/// Shelling out to `cast` rather than writing a JSON-RPC client in Rust is
/// deliberate: Foundry is already a pinned dependency of this repo, and a
/// hand-rolled client would be a second thing to get wrong for no gain — this
/// crate's job is verification, not transport.
/// ⚠️ **Generated once for the whole binary.** Cargo runs tests in parallel,
/// and each fixture run deploys a contract and sends a transaction from the
/// *same* development account — five concurrent runs collide on the account
/// nonce and most of them fail, which reads as "the chain is down" rather than
/// "the harness raced itself". Sharing one fixture also makes the suite a
/// single deployment instead of five.
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(generate)
}

fn generate() -> Fixture {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../besu/searchauth-fixture.sh"
    );

    let out = Command::new("bash")
        .arg(script)
        .env("PQCL_BESU_RPC", rpc_url())
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "could not run {script}: {e}\n\
                 This test needs a live Besu chain and Foundry:\n  \
                 cd besu && ./generate.sh && docker compose up -d"
            )
        });

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "the fixture script failed.\n\
         Is a Besu chain up?  cd besu && docker compose up -d\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    parse_fixture(&stdout)
}

fn field<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("the fixture script printed no `{key}=` line:\n{text}"))
        .trim()
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("bad hex {s}: {e}"))
        })
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected 32 bytes, got {}", v.len()))
}

fn parse_fixture(text: &str) -> Fixture {
    let mut receipts = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("receipt=") {
            let (idx, raw) = rest
                .split_once(':')
                .unwrap_or_else(|| panic!("malformed receipt line: {line}"));
            receipts.push((
                idx.parse::<u64>()
                    .unwrap_or_else(|e| panic!("bad index {idx}: {e}")),
                unhex(raw),
            ));
        }
    }
    assert!(
        !receipts.is_empty(),
        "the fixture printed no receipts:\n{text}"
    );

    Fixture {
        header_rlp: unhex(field(text, "header")),
        block_hash: unhex32(field(text, "blockhash")),
        receipts_root: unhex32(field(text, "receiptsroot")),
        receipts,
        tx_index: field(text, "txindex")
            .parse()
            .unwrap_or_else(|e| panic!("bad txindex: {e}")),
        contract: unhex(field(text, "contract"))
            .try_into()
            .unwrap_or_else(|v: Vec<u8>| panic!("expected a 20-byte address, got {}", v.len())),
        nullifier: unhex32(field(text, "nullifier")),
        scope_commit: unhex32(field(text, "scopecommit")),
    }
}

fn build_trie(fx: &Fixture) -> mpt::Trie {
    let mut t = mpt::Trie::new();
    for (idx, raw) in &fx.receipts {
        t.insert(rlp::encode_u64(*idx), raw.clone());
    }
    t
}

/// ⭐ The cross-check: our trie must reproduce Besu's `receiptsRoot`.
///
/// This is the single assertion that validates the whole encoding stack against
/// an independent implementation.
#[test]
fn our_receipt_trie_reproduces_besus_root() {
    let fx = fixture();
    let ours = build_trie(fx).root();

    assert_eq!(
        ours,
        fx.receipts_root,
        "our receipt trie root disagrees with Besu's.\n\
         ours  = {}\n\
         besu  = {}\n\
         Something in the RLP, hex-prefix, inlining or receipt encoding is wrong.",
        hex(&ours),
        hex(&fx.receipts_root)
    );
}

/// The header must hash to the block hash Besu reports, and its `receiptsRoot`
/// field must be the one we just matched. Together these bind the proof to a
/// specific block.
///
/// ⭐ **QBFT does not hash a header the way mainnet does**, and this test is
/// what established that. Plain `keccak256(rlp(header))` produces an unrelated
/// value; the commit seals must be emptied first. Both directions are asserted
/// so a future "simplification" back to the mainnet rule fails here rather than
/// silently rejecting every real authorisation.
#[test]
fn the_header_hashes_and_parses_as_besu_reports_it() {
    let fx = fixture();
    let header = BlockHeader::new(fx.header_rlp.clone());

    assert_eq!(
        header.hash(Consensus::Qbft).expect("header parses"),
        fx.block_hash,
        "the QBFT hash (commit seals emptied) is not the block hash Besu reports"
    );
    assert_ne!(
        header.hash(Consensus::Ethereum).expect("header parses"),
        fx.block_hash,
        "mainnet's rule matched, so this chain is not behaving as QBFT —          re-run examples/qbft_probe.rs before changing anything"
    );
    assert_eq!(
        header.receipts_root().expect("header parses"),
        fx.receipts_root,
        "field 5 of the header is not the receiptsRoot"
    );
}

/// The end-to-end property design §7b′ asks for: the SM is handed a proof and
/// concludes, from that alone, that the authorisation was published on chain.
#[test]
fn a_real_search_authorised_event_verifies_end_to_end() {
    let fx = fixture();
    let trie = build_trie(fx);

    let proof = InclusionProof {
        header: BlockHeader::new(fx.header_rlp.clone()),
        consensus: Consensus::Qbft,
        tx_index: fx.tx_index,
        nodes: trie.proof(&rlp::encode_u64(fx.tx_index)),
    };
    let expected = ExpectedEvent {
        contract: fx.contract,
        nullifier: fx.nullifier,
        scope_commit: fx.scope_commit,
        block_hash: fx.block_hash,
    };

    verify_search_authorised(&proof, &expected)
        .expect("a real on-chain SearchAuthorised must verify");
}

/// A gate that cannot fail is not a gate. Each of these is a distinct lie a
/// caller might be told, and each must be caught.
#[test]
fn the_verifier_refuses_every_tampered_variant() {
    let fx = fixture();
    let trie = build_trie(fx);
    let nodes = trie.proof(&rlp::encode_u64(fx.tx_index));

    let good_proof = || InclusionProof {
        header: BlockHeader::new(fx.header_rlp.clone()),
        consensus: Consensus::Qbft,
        tx_index: fx.tx_index,
        nodes: nodes.clone(),
    };
    let good_expect = ExpectedEvent {
        contract: fx.contract,
        nullifier: fx.nullifier,
        scope_commit: fx.scope_commit,
        block_hash: fx.block_hash,
    };

    // Wrong nullifier: someone else's authorisation replayed as yours.
    let mut e = good_expect;
    e.nullifier[0] ^= 0x01;
    assert!(
        verify_search_authorised(&good_proof(), &e).is_err(),
        "a different nullifier must not verify"
    );

    // Wrong scope: registered narrow, claimed wide.
    let mut e = good_expect;
    e.scope_commit[0] ^= 0x01;
    assert!(
        verify_search_authorised(&good_proof(), &e).is_err(),
        "a different scope commitment must not verify"
    );

    // Wrong contract: an event of the same shape from somewhere else.
    let mut e = good_expect;
    e.contract[0] ^= 0x01;
    assert!(
        verify_search_authorised(&good_proof(), &e).is_err(),
        "an event from another contract must not verify"
    );

    // Wrong block: a genuine old authorisation presented as a current one.
    let mut e = good_expect;
    e.block_hash[0] ^= 0x01;
    assert!(
        verify_search_authorised(&good_proof(), &e).is_err(),
        "a proof against a different block hash must not verify"
    );

    // Tampered header: same claimed hash, different bytes.
    let mut bad_header = fx.header_rlp.clone();
    let n = bad_header.len();
    bad_header[n - 1] ^= 0x01;
    let p = InclusionProof {
        header: BlockHeader::new(bad_header),
        consensus: Consensus::Qbft,
        tx_index: fx.tx_index,
        nodes: nodes.clone(),
    };
    assert!(
        verify_search_authorised(&p, &good_expect).is_err(),
        "a modified header must not still hash to the expected block hash"
    );

    // Tampered proof node: breaks the hash chain to receiptsRoot.
    let mut bad_nodes = nodes.clone();
    let last = bad_nodes.len() - 1;
    let m = bad_nodes[last].len();
    bad_nodes[last][m - 1] ^= 0x01;
    let p = InclusionProof {
        header: BlockHeader::new(fx.header_rlp.clone()),
        consensus: Consensus::Qbft,
        tx_index: fx.tx_index,
        nodes: bad_nodes,
    };

    // Wrong consensus rule: a real proof, read with mainnet's hashing.
    let p_eth = InclusionProof {
        header: BlockHeader::new(fx.header_rlp.clone()),
        consensus: Consensus::Ethereum,
        tx_index: fx.tx_index,
        nodes: nodes.clone(),
    };
    assert!(
        verify_search_authorised(&p_eth, &good_expect).is_err(),
        "the mainnet hashing rule must not accept a QBFT header"
    );
    assert!(
        verify_search_authorised(&p, &good_expect).is_err(),
        "a tampered receipt must not verify against the anchored root"
    );
}

/// The event topic we compute must equal the one Besu actually emitted. A
/// mismatch would mean the verifier silently matches nothing and reports
/// `EventNotFound` for every real event.
#[test]
fn our_topic_matches_the_one_the_chain_emitted() {
    let fx = fixture();
    let raw = fx
        .receipts
        .iter()
        .find(|(i, _)| *i == fx.tx_index)
        .map(|(_, r)| r.clone())
        .expect("the fixture's own receipt is present");

    let receipt = pqcl_chainproof::Receipt::decode(&raw).expect("decodes");
    assert!(receipt.success, "the authorisation transaction reverted");

    let topic = search_authorised_topic();
    assert!(
        receipt
            .logs
            .iter()
            .any(|l| l.topics.first() == Some(&topic)),
        "no log carries keccak(\"SearchAuthorised(bytes32,bytes32)\"); \
         the computed topic disagrees with the deployed event signature"
    );
}

fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}
