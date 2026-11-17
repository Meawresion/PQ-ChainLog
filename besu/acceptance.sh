#!/usr/bin/env bash
# M7's chain-level acceptance criteria, on a live four-validator QBFT network.
#
# The build plan (M7):
#   * a multi-validator QBFT network produces blocks
#   * the contract deploys within a realistic block
#   * anchors survive a validator restart
#
# The contract-level criteria (monotonicity, authority split, nullifier replay)
# are Foundry tests in `contracts/test/Anchor.t.sol`; they need no chain.
#
# ⚠️ **The gas limit is not a dial.** Plan §9 fixes ~36 M and forbids raising it
# to make anything fit. Whether a deployment fits in a realistic block *is* the
# result, either way — this script reports it and fails if it does not.
#
# Usage:  ./generate.sh && docker compose up -d && ./acceptance.sh

set -euo pipefail
cd "$(dirname "$0")"

RPC="http://localhost:8545"
# Besu's documented development account. Public by design; this chain is
# disposable and holds nothing.
DEV_KEY="0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63"
GAS_LIMIT=36000000

export PATH="$HOME/.foundry/bin:$PATH"

rpc() {
    curl -s -X POST -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}" "$RPC" |
        sed 's/.*"result":"\?\([^,"}]*\)"\?.*/\1/'
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "== 1. the network produces blocks =="
first=$(rpc eth_blockNumber '[]')
sleep 6
second=$(rpc eth_blockNumber '[]')
echo "   block $((first)) -> $((second))"
[ "$((second))" -gt "$((first))" ] || fail "no new block in 6 s; consensus is stalled, not slow"

validators=$(curl -s -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"qbft_getValidatorsByBlockNumber","params":["latest"],"id":1}' "$RPC" |
    grep -o '0x[0-9a-f]\{40\}' | wc -l)
echo "   validators: $validators"
# Four is the point: QBFT needs 2f+1 of 3f+1, so tolerating one fault requires
# four. Fewer would make step 3 below prove nothing.
[ "$validators" -ge 4 ] || fail "expected >= 4 validators, found $validators"

echo "== 2. the contract deploys within a realistic block =="
# draft8 D4: a registry that verifies no signature, so it takes no keys.
out=$(forge create --rpc-url "$RPC" --private-key "$DEV_KEY" --broadcast \
    --root ../contracts ../contracts/src/Anchor.sol:Anchor 2>&1)
addr=$(echo "$out" | sed -n 's/.*Deployed to: \(0x[0-9a-fA-F]*\).*/\1/p')
txh=$(echo "$out" | sed -n 's/.*Transaction hash: \(0x[0-9a-fA-F]*\).*/\1/p')
[ -n "$addr" ] || { echo "$out" >&2; fail "deployment produced no address"; }

gas_used=$(curl -s -X POST -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$txh\"],\"id\":1}" "$RPC" |
    sed 's/.*"gasUsed":"\([^"]*\)".*/\1/')
echo "   Anchor deployed at $addr"
echo "   deploy gas $((gas_used)) of $GAS_LIMIT ($(( (gas_used) * 100 / GAS_LIMIT ))% of a block)"
[ "$((gas_used))" -lt "$GAS_LIMIT" ] || fail "deployment does not fit in a realistic block"

echo "== 3. anchors survive a validator restart =="
cid="0x$(printf '%064x' 1)"
root="0x$(printf '%064x' 3735928559)"
reg="0x$(printf '%064x' 2)"
d1="0x$(printf '%064x' 4)"
a1="0x$(printf '%064x' 5)"
cast send --rpc-url "$RPC" --private-key "$DEV_KEY" "$addr" \
    'registerCase(bytes32,bytes32)' "$cid" "$reg" >/dev/null
cast send --rpc-url "$RPC" --private-key "$DEV_KEY" "$addr" \
    'commitRoot(bytes32,bytes32,bytes32,bytes32,bytes32)' "$cid" "$root" "$reg" "$d1" "$a1" >/dev/null
before=$(cast call --rpc-url "$RPC" "$addr" 'latestEpoch(bytes32)((bytes32,uint64,bytes32,bytes32))' "$cid" | head -1)
echo "   anchored root $before"

# Stop one validator. Three of four remain, which is still 2f+1, so the chain
# must keep producing — that is what makes this a restart test rather than a
# shutdown test.
docker compose stop node4 >/dev/null 2>&1
mid=$(rpc eth_blockNumber '[]')

# Poll rather than sleep a fixed amount.
#
# Losing a validator costs a round change, and with `requesttimeoutseconds=4`
# that can take several seconds — longer still if the stopped node was the
# proposer for the current round. A short fixed window would report "BFT is
# broken" for what is really "consensus is recovering", which is a false
# finding of the worst kind: alarming and wrong.
deadline=$((SECONDS + 90))
after_stop=$mid
while [ "$SECONDS" -lt "$deadline" ]; do
    sleep 3
    after_stop=$(rpc eth_blockNumber '[]')
    if [ "$((after_stop))" -gt "$((mid))" ]; then break; fi
done
[ "$((after_stop))" -gt "$((mid))" ] ||
    fail "no block in 90 s with 3/4 validators. QBFT needs ceil(2N/3) = 3 of 4, so this is a real stall, not a slow round change"
echo "   chain kept producing with 3/4 validators: $((mid)) -> $((after_stop))"

docker compose start node4 >/dev/null 2>&1
sleep 15
after=$(cast call --rpc-url "$RPC" "$addr" 'latestEpoch(bytes32)((bytes32,uint64,bytes32,bytes32))' "$cid" | head -1)
echo "   anchor after restart $after"
[ "$before" = "$after" ] || fail "the anchor changed across a restart: $before -> $after"

# Read it from the node that was restarted, not just the one that never went
# down. Querying node1 only would prove the anchor survived in a process that
# never stopped, which is not the claim.
after4=$(cast call --rpc-url http://localhost:8548 "$addr" 'latestEpoch(bytes32)((bytes32,uint64,bytes32,bytes32))' "$cid" | head -1)
[ "$before" = "$after4" ] || fail "the restarted node disagrees about the anchor: $before vs $after4"
echo "   the restarted node agrees"

echo
echo "all M7 chain-level acceptance criteria passed"
