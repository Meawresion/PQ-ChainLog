#!/usr/bin/env bash
# Generate the QBFT genesis and validator keys, then lay them out for compose.
#
# ⚠️ Never hand-write QBFT `extraData`. It is an RLP encoding of the validator
# set, and `besu operator generate-blockchain-config` is what produces it
# correctly (plan §9). A wrong one fails as a silent consensus stall rather than
# an error, which is a bad afternoon.
#
# ⛔ `networkFiles/` and `nodes/` hold real validator **private keys** and are
# gitignored. The tracked artefact is `qbft-config.json` — that is what makes
# this reproducible; the keys are disposable and per-machine.
#
# Usage:  ./generate.sh   (idempotent — wipes and regenerates)

set -euo pipefail

cd "$(dirname "$0")"

# Pinned by digest, not by tag. `latest` moves, and a chain that silently
# changed client version between two measurement runs would make them
# incomparable — the same reasoning that pins the Rust toolchain and the
# ETHDILITHIUM commit.
BESU_IMAGE="hyperledger/besu@sha256:6f3f21ce533383fcc8db3bce02252b59d5a9e776b72b5a1c8ecd2db011600042"
VALIDATORS=4

# The container previously ran as root and wrote root-owned files, after which
# the next run could not even remove its own output. Clean up through the
# container for exactly that reason, then generate as the invoking user.
if [ -d networkFiles ] || [ -d nodes ]; then
    docker run --rm -v "$PWD":/w -w /w --entrypoint sh "$BESU_IMAGE" \
        -c 'rm -rf /w/networkFiles /w/nodes'
fi

docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/w -w /w "$BESU_IMAGE" \
    operator generate-blockchain-config \
    --config-file=qbft-config.json \
    --to=networkFiles \
    --private-key-file-name=key

# Keys are emitted under directories named by validator address. Compose wants
# stable node names, so map them in **sorted** order: the same config then
# always yields the same node1..node4 assignment, and a regeneration cannot
# silently permute validator identities between runs.
i=1
for keydir in $(find networkFiles/keys -mindepth 1 -maxdepth 1 -type d | sort); do
    mkdir -p "nodes/node${i}/data"
    cp "$keydir/key" "nodes/node${i}/data/key"
    cp "$keydir/key.pub" "nodes/node${i}/data/key.pub"
    i=$((i + 1))
done

actual=$((i - 1))
if [ "$actual" -ne "$VALIDATORS" ]; then
    echo "expected $VALIDATORS validators, laid out $actual" >&2
    exit 1
fi

# Static peering, because discovery is off.
#
# Discovery is disabled deliberately: it is UDP-based, and on a fixed four-node
# compose network where every peer is known at generation time it only adds a
# nondeterministic join delay to a measurement harness. Static peers make the
# topology exactly what the config says it is.
#
# An enode is `enode://<pubkey without 0x>@<ip>:<port>`.
#
# ⚠️ **IP, not hostname.** Besu rejects a DNS name in a static enode and dies at
# startup with "Illegal static enode supplied", which reads like a malformed key
# rather than a name-resolution rule. The addresses are fixed in
# docker-compose.yml's `ipam` block; these two files must agree.
#
# Each node's list **excludes itself** — a node does not dial itself.
IP_PREFIX="172.28.0.1"

for n in $(seq 1 "$VALIDATORS"); do
    enodes=""
    for m in $(seq 1 "$VALIDATORS"); do
        if [ "$m" = "$n" ]; then continue; fi
        pub=$(sed 's/^0x//' "nodes/node${m}/data/key.pub")
        if [ -n "$enodes" ]; then enodes="${enodes},"; fi
        enodes="${enodes}\"enode://${pub}@${IP_PREFIX}${m}:30303\""
    done
    printf '[%s]\n' "$enodes" >"nodes/node${n}/data/static-nodes.json"
done

# ≥4 validators so Byzantine fault tolerance is real rather than nominal: QBFT
# needs 2f+1 of 3f+1, so tolerating one faulty validator requires four. A one-
# or three-validator chain measures nothing about consensus (plan §9), and the
# restart-survival check is meaningless without a quorum that survives the stop.
echo "genesis + $actual validator keys ready"
echo "next: docker compose up -d   then   ./wait-ready.sh"
