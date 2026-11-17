#!/usr/bin/env bash
# SAC Experiment 4: our court-ordered redaction against
# B-DEMS's destruction protocol, both on one fresh four-validator QBFT network.
#
# Owns the network's whole life, as besu/exp6chain.sh does: generated for this
# run, used for exactly this run, and taken down on every exit path.
#
# Needs contracts/out/{Anchor,BDems}.sol, which `cargo xtask contracts` (forge
# test) builds; the campaign runs that step first.
#
# Usage (from the repository root):  bash besu/redaction.sh

set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.foundry/bin:$PATH"

[ -f contracts/out/Anchor.sol/Anchor.json ] && [ -f contracts/out/BDems.sol/BDems.json ] ||
    forge build --root contracts > /dev/null

(cd besu && docker compose down > /dev/null 2>&1 || true)
# The nodes' own logs are kept before the network goes: c09b's first attempt
# lost a validator to "Initial sync is still in progress" with nothing to say why.
keep_logs() {
    mkdir -p "$HOME/pqcl-logs"
    (cd besu && docker compose logs --no-color --tail 2000 > "$HOME/pqcl-logs/besu-redaction.log" 2>&1) || true
    (cd besu && docker compose down > /dev/null 2>&1) || true
}
trap keep_logs EXIT
# B-DEMS submits every TxE of a batch at once from one Sender; Besu's default
# per-sender window (200 nonces) would refuse T1's k = 1,000. Fabric has no
# nonce, so the window is raised for this network only (UPGRADES.md, B-DEMS).
export PQCL_BESU_MAX_FUTURE_BY_SENDER=4096
(cd besu && ./generate.sh > /dev/null && docker compose up -d)

RPC="http://127.0.0.1:8545"
for _ in $(seq 1 60); do
    # `|| true`: a node still starting resets the connection (see exp6chain.sh).
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

# PQCL_EXP_FEATURES: the campaign passes "chain enclave" with
# PQCL_SECURE_MODULE=nitro:<cid>; the in-process default does not publish.
PQCL_RPC="$RPC" cargo run --release -q -p pqcl-exp --features "${PQCL_EXP_FEATURES:-chain}" --bin redaction
