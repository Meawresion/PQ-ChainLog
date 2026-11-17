#!/usr/bin/env bash
# The demo chain: one QBFT validator (see docker-compose.yml for why one).
#
# Usage:
#   besu/demo/chain.sh up      generate a fresh genesis and key, start, wait for blocks
#   besu/demo/chain.sh down    stop and remove the container and its data
#
# `up` always starts from a fresh genesis: a demo walks Phases 1-11 from an
# empty chain, so yesterday's anchors must not be on it.
#
# ⛔ `data/` holds the validator's private key. It is gitignored
# (`besu/**/data/`) and disposable.

set -euo pipefail
cd "$(dirname "$0")"

IMAGE="hyperledger/besu@sha256:6f3f21ce533383fcc8db3bce02252b59d5a9e776b72b5a1c8ecd2db011600042"
RPC="http://127.0.0.1:8555"

wipe() {
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
    if [ -d data ]; then
        # The container may have written root-owned files; remove through it.
        docker run --rm -v "$PWD":/w -w /w --entrypoint sh "$IMAGE" -c 'rm -rf /w/data'
    fi
}

up() {
    wipe
    # Besu creates the output directory but not its parent.
    mkdir -p data
    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/w -w /w "$IMAGE" \
        operator generate-blockchain-config \
        --config-file=qbft-demo-config.json \
        --to=data/networkFiles \
        --private-key-file-name=key >/dev/null
    keydir=$(find data/networkFiles/keys -mindepth 1 -maxdepth 1 -type d | head -1)
    mkdir -p data/node
    cp "$keydir/key" "$keydir/key.pub" data/node/
    docker compose up -d >/dev/null

    # Wait until the validator has sealed a block: RPC up is not chain up.
    for _ in $(seq 1 90); do
        n=$(curl -s -X POST -H 'Content-Type: application/json' \
            --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
            "$RPC" 2>/dev/null | sed -n 's/.*"result":"0x\([0-9a-f]*\)".*/\1/p' || true)
        if [ -n "${n:-}" ] && [ "$((16#$n))" -gt 0 ]; then
            echo "demo chain up: one QBFT validator, block $((16#$n)), $RPC"
            return 0
        fi
        # xtask-allow: sleep — polling a real node for its first block is real waiting, not fake work
        sleep 1
    done
    echo "demo chain did not produce a block within 90 s" >&2
    docker compose logs --tail 40 >&2
    exit 1
}

case "${1:-}" in
    up) up ;;
    down) wipe; echo "demo chain removed" ;;
    *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
