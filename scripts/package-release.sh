#!/usr/bin/env bash
# Build the release bundle: the demo dashboard as a prebuilt Linux binary plus
# the few repository files it reads at run time, so the demo can run on a
# machine with Docker and no Rust or Foundry toolchain.
#
#   scripts/package-release.sh
#
# Writes target/dist/pq-chainlog-demo-<version>-linux-<arch>.tar.gz and its
# .sha256. Needs everything a source build of the demo needs: the pinned Rust
# toolchain, and `forge build --root contracts` already run (the bundle ships
# the compiled anchor contract, contracts/out/Anchor.sol/Anchor.json).
#
# The artefacts are not bundled (they are third-party data, ~85 MB for the two
# the demo reads); the bundle carries the fetch script and its pinned hashes.

set -euo pipefail
cd "$(dirname "$0")/.."

ABI=contracts/out/Anchor.sol/Anchor.json
[ -f "$ABI" ] || { echo "missing $ABI: run  forge build --root contracts  first" >&2; exit 1; }

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
ARCH=$(uname -m)
NAME="pq-chainlog-demo-${VERSION}-linux-${ARCH}"
OUT="target/dist/$NAME"

cargo build --release --locked -p pqcl-investigator

rm -rf "$OUT" "target/dist/$NAME.tar.gz" "target/dist/$NAME.tar.gz.sha256"
mkdir -p "$OUT/bin" "$OUT/besu/demo" "$OUT/forensics/out" "$OUT/forensics/symbols" \
         "$OUT/contracts/out/Anchor.sol" "$OUT/zk" "$OUT/datasets"

install -m 755 target/release/pqcl-dashboard "$OUT/bin/"
install -m 755 besu/demo/chain.sh "$OUT/besu/demo/"
install -m 644 besu/demo/docker-compose.yml besu/demo/qbft-demo-config.json "$OUT/besu/demo/"
install -m 755 forensics/run.sh "$OUT/forensics/"
install -m 644 forensics/Dockerfile "$OUT/forensics/"
install -m 644 "$ABI" "$OUT/$ABI"
cp -r zk/demo-proof "$OUT/zk/"
install -m 755 datasets/fetch-artefacts.sh "$OUT/datasets/"
install -m 644 datasets/artefacts.sha256 "$OUT/datasets/"

cat > "$OUT/run-demo.sh" <<'EOF'
#!/usr/bin/env bash
# Start the one-validator demo chain, then the dashboard on
# http://127.0.0.1:8080/ until Ctrl-C; the chain is removed on exit.
#
#   ./run-demo.sh           serve the dashboard
#   ./run-demo.sh --walk    run the scripted walkthrough end to end and exit
#                           (non-zero on the first failed step)
set -euo pipefail
cd "$(dirname "$0")"
for f in datasets/artefacts/nps-2009-canon2-gen6.E01 datasets/artefacts/multifile_25_21.pcap; do
    [ -f "$f" ] || { echo "missing $f: run  sh datasets/fetch-artefacts.sh  first" >&2; exit 1; }
done
export PQCL_RPC="${PQCL_RPC:-http://127.0.0.1:8555}"
besu/demo/chain.sh up
trap 'besu/demo/chain.sh down >/dev/null' EXIT
if [ "${1:-}" = "--walk" ]; then
    bin/pqcl-dashboard --walk
    bin/pqcl-dashboard --course --walk-corners
else
    bin/pqcl-dashboard --course --port "${PQCL_DEMO_PORT:-8080}"
fi
EOF
chmod 755 "$OUT/run-demo.sh"

cat > "$OUT/README.txt" <<EOF
PQ-ChainLog demo ${VERSION} (Linux ${ARCH}, prebuilt)

The investigator's dashboard: evidence ingestion through the real pipeline, a
live chain of custody anchored on a local Hyperledger Besu node, and keyword and
custody search under access control. Source and full instructions:
the repository's README.md.

Requirements
  - Linux x86_64 with glibc 2.39 or newer (built on Ubuntu 24.04)
  - Docker Engine with the compose plugin; your user can run docker
  - curl and sha256sum (for the artefact download)
  - about 1 GB of free RAM, and ~800 MB of disk for the artefacts

Run
  1. sh datasets/fetch-artefacts.sh     (~680 MB from Digital Corpora, hash-checked)
  2. ./run-demo.sh                      then open http://127.0.0.1:8080/
     ./run-demo.sh --walk               scripted end-to-end check, exits 0 on success

The first run builds the forensic tool container (forensics/Dockerfile) and
pulls the pinned Besu image, which takes a few minutes. The dashboard binds to
127.0.0.1 only. Set PQCL_DEMO_PORT to use another port.

Nothing the demo prints is a measured result: it runs on one validator with a
software Secure Module.
EOF

tar -C target/dist -czf "target/dist/$NAME.tar.gz" "$NAME"
(cd target/dist && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "wrote target/dist/$NAME.tar.gz"
cat "target/dist/$NAME.tar.gz.sha256"
