#!/usr/bin/env bash
# The midterm demo, one command (plan M8b, extended 2026-10-01, constraint 6).
#
#   scripts/demo.sh            start the chain, build, serve the three-corner
#                              dashboard on http://127.0.0.1:8080/ until Ctrl-C,
#                              then stop the chain. Course mode (no D6) and the
#                              labelled warm-up are on.
#   scripts/demo.sh --walk     the scripted walkthrough: every step in order,
#                              then the corners' scripted walk, against a fresh
#                              live chain; exits non-zero on the first failure
#
# On a laptop the whole demo fits in 8 GB of RAM: build with
# `CARGO_BUILD_JOBS=2`, and leave `--live-stark` off (the saved STARK's verify
# alone peaks at 7.1 GB).
#
# Needs: Docker (Besu, and the pinned forensic container), the real artefacts
# (`sh datasets/fetch-artefacts.sh`) and `forge build --root contracts`.
#
# ⛔ Nothing this prints is a paper number: one validator, host-software Secure
# Module, a laptop.

set -euo pipefail
cd "$(dirname "$0")/.."

for f in datasets/artefacts/nps-2009-canon2-gen6.E01 datasets/artefacts/multifile_25_21.pcap \
         contracts/out/Anchor.sol/Anchor.json; do
    [ -f "$f" ] || { echo "missing $f (see the header of this script)" >&2; exit 1; }
done

cargo build -q --release -p pqcl-investigator
# Port 8555, not 8545: the four-validator measurement chain owns 8545, and
# `cargo xtask ci` runs both.
export PQCL_RPC="${PQCL_RPC:-http://127.0.0.1:8555}"
besu/demo/chain.sh up
trap 'besu/demo/chain.sh down >/dev/null' EXIT

if [ "${1:-}" = "--walk" ]; then
    /usr/bin/time -v target/release/pqcl-dashboard --walk 2> >(grep -E "Maximum resident|Elapsed" >&2)
    /usr/bin/time -v target/release/pqcl-dashboard --course --walk-corners 2> >(grep -E "Maximum resident|Elapsed" >&2)
    docker stats --no-stream --format "chain container: {{.MemUsage}}" pqcl-demo-besu
else
    target/release/pqcl-dashboard --course --port "${PQCL_DEMO_PORT:-8080}"
fi
