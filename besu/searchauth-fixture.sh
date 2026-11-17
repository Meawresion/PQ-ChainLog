#!/usr/bin/env bash
# Emit a real `SearchAuthorised` inclusion-proof fixture from the live chain.
#
# Deploys `Anchor.sol`, calls `authoriseSearch`, then prints the block header,
# every receipt in that block, and the values the event should carry. The Rust
# test in `crates/pqcl-chainproof/tests/against_besu.rs` rebuilds the receipt
# trie from this and checks its root against the `receiptsRoot` **Besu**
# computed — which is what validates our encoding against an independent
# implementation rather than against itself.
#
# ⭐ **Every receipt in the block, not just ours.** A receipt trie commits to
# all of them, so a fixture carrying only the interesting one could not
# reproduce the root. On a quiet QBFT chain that is usually a block of one, but
# the script does not assume it.
#
# Output is `key=value` lines, plus one `receipt=<index>:<hex>` per receipt.
#
# Usage:  PQCL_BESU_RPC=http://localhost:8545 besu/searchauth-fixture.sh

set -euo pipefail
cd "$(dirname "$0")"

RPC="${PQCL_BESU_RPC:-http://localhost:8545}"
# Besu's documented development account. Public by design; this chain is
# disposable and holds nothing.
DEV_KEY="0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63"

export PATH="$HOME/.foundry/bin:$PATH"

command -v cast >/dev/null 2>&1 || {
    echo "cast not found; install Foundry (foundryup)" >&2
    exit 1
}

curl -s --max-time 10 -o /dev/null "$RPC" || {
    echo "no JSON-RPC at $RPC" >&2
    echo "start one:  cd besu && docker compose up -d" >&2
    exit 1
}

# draft8 D4: the anchor is a registry with no keys; the event path is unchanged.
out=$(forge create --rpc-url "$RPC" --private-key "$DEV_KEY" --broadcast \
    --root ../contracts ../contracts/src/Anchor.sol:Anchor 2>&1)
addr=$(echo "$out" | sed -n 's/.*Deployed to: \(0x[0-9a-fA-F]*\).*/\1/p')
[ -n "$addr" ] || { echo "$out" >&2; echo "deployment produced no address" >&2; exit 1; }

# Distinct, recognisable values so a mix-up is visible in a hex dump.
NULLIFIER="0x$(printf '%064x' 305419896)"
SCOPE="0x$(printf '%064x' 2596069104)"

txh=$(cast send --rpc-url "$RPC" --private-key "$DEV_KEY" --json "$addr" \
    'authoriseSearch(bytes32,bytes32)' "$NULLIFIER" "$SCOPE" |
    sed -n 's/.*"transactionHash":"\(0x[0-9a-f]*\)".*/\1/p')
[ -n "$txh" ] || { echo "authoriseSearch produced no transaction hash" >&2; exit 1; }

receipt_json=$(cast receipt --rpc-url "$RPC" --json "$txh")
block_hash=$(echo "$receipt_json" | sed -n 's/.*"blockHash":"\(0x[0-9a-f]*\)".*/\1/p')
tx_index_hex=$(echo "$receipt_json" | sed -n 's/.*"transactionIndex":"\(0x[0-9a-f]*\)".*/\1/p')
tx_index=$((tx_index_hex))

# `cast block --raw` gives the RLP-encoded header — exactly the bytes whose
# keccak is the block hash. Reconstructing it from parsed fields would risk
# producing different bytes and therefore a different hash.
header=$(cast block --rpc-url "$RPC" --raw "$block_hash")
receipts_root=$(cast block --rpc-url "$RPC" --json "$block_hash" |
    sed -n 's/.*"receiptsRoot":"\(0x[0-9a-f]*\)".*/\1/p')

echo "contract=$addr"
echo "nullifier=$NULLIFIER"
echo "scopecommit=$SCOPE"
echo "blockhash=$block_hash"
echo "receiptsroot=$receipts_root"
echo "header=$header"
echo "txindex=$tx_index"

# Every transaction in the block, in index order. `cast receipt` has no
# `--raw`, so the trie-encoded bytes are reassembled from the JSON fields by
# `receipt-rlp.py` — see that script for the EIP-2718 rules it follows.
python3 receipt-rlp.py "$RPC" "$block_hash"
