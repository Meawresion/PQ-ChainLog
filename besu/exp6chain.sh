#!/usr/bin/env bash
# Experiment 6 on chain (M10 H2): LEChain's contract against our anchor, and
# since the design record B-DEMS's whole workflow on the same streams.
#
# Owns the network's whole life: a fresh four-validator QBFT network is
# generated, used for exactly this run, and taken down on every exit path —
# a network left running between campaigns is state nobody measured.
#
# Needs `contracts/out/Anchor.sol/Anchor.json`, which `cargo xtask contracts`
# (forge test) builds; the campaign runs that step first. Builds LEChain itself.
#
# Usage (from the repository root):  bash besu/exp6chain.sh

set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.foundry/bin:$PATH"

bash baselines/lechain/fetch.sh
forge build --root baselines/lechain > /dev/null
[ -f contracts/out/Anchor.sol/Anchor.json ] && [ -f contracts/out/BDems.sol/BDems.json ] ||
    forge build --root contracts > /dev/null

(cd besu && docker compose down > /dev/null 2>&1 || true)
# The nodes' own logs are kept before the network goes, as besu/redaction.sh
# does since c09b's first attempt.
keep_logs() {
    mkdir -p "$HOME/pqcl-logs"
    (cd besu && docker compose logs --no-color --tail 2000 > "$HOME/pqcl-logs/besu-exp6chain.log" 2>&1) || true
    (cd besu && docker compose down > /dev/null 2>&1) || true
}
trap keep_logs EXIT
(cd besu && ./generate.sh > /dev/null && docker compose up -d)

RPC="http://127.0.0.1:8545"
for _ in $(seq 1 60); do
    # `|| true`: a node still starting refuses or resets the connection, and
    # under `set -euo pipefail` that first probe would end the script. Found by
    # the M10 rehearsal (curl exit 56); the smoke run had no `set -e`.
    n=$( (curl -s -X POST -H 'Content-Type: application/json' \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' "$RPC" || true) |
        sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p')
    if [ -n "$n" ] && [ "$((n))" -gt 2 ]; then
        echo "network producing blocks (block $((n)))"
        break
    fi
    sleep 2
done
[ -n "${n:-}" ] && [ "$((n))" -gt 2 ] || { echo "network did not produce blocks" >&2; exit 1; }

# PQCL_EXP_FEATURES adds Cargo features: the campaign's enclave run passes
# "chain enclave" with PQCL_SECURE_MODULE=nitro:<cid> (M13 A18). Default is the
# in-process build, whose records say host-software and do not publish.
PQCL_RPC="$RPC" cargo run --release -q -p pqcl-exp --features "${PQCL_EXP_FEATURES:-chain}" --bin exp6chain
