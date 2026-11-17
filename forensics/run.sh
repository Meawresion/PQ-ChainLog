#!/usr/bin/env bash
# Run one real forensic tool against one real artefact, in the pinned container.
#
# This is the only way M8 invokes forensic tooling. Everything the pipeline
# records about a tool run — the name, the version, the exact arguments — comes
# from here, because `params_c = H(0x23 ‖ ⟪tool, ver, args, just, r_p⟫)` puts
# those inside a signed custody record. A version read from anywhere other than
# the binary that actually ran would make that commitment a statement about
# nothing.
#
# ⛔ **The artefact is mounted read-only.** A forensic tool that modifies its
# evidence has destroyed the chain of custody it was invoked to document, and
# `d_ev` would stop matching. `:ro` makes that a mount error rather than a
# silent corruption discovered at verification time.
#
# Usage:
#   forensics/run.sh --versions
#   forensics/run.sh --build
#   forensics/run.sh --fetch-symbols <artefact-dir> <tool> [args...]
#   forensics/run.sh <artefact-dir> <tool> [args...]
#
# Examples:
#   forensics/run.sh datasets/artefacts fls -r -p nps-2009-canon2-gen6.E01
#   forensics/run.sh datasets/artefacts vol -f charlie-2009-12-03.mddramimage windows.pslist
#   forensics/run.sh datasets/artefacts tshark -r multifile_25_21.pcap -q -z io,phs

set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="pqcl-forensics:1"

build() {
    docker build -q -t "$IMAGE" forensics/ >/dev/null
}

# Build on demand rather than requiring a separate step. The layer cache makes
# the no-op case fast, and a missing image is otherwise a confusing failure
# several calls deep inside the pipeline.
ensure_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        echo "building $IMAGE (first run only) ..." >&2
        build
    fi
}

case "${1:-}" in
    --build)
        build
        echo "built $IMAGE"
        exit 0
        ;;
    --versions)
        ensure_image
        docker run --rm "$IMAGE" cat /etc/pqcl-tool-versions
        exit 0
        ;;
    --digest)
        # The image's own content digest, for the results record.
        ensure_image
        docker image inspect --format '{{.Id}}' "$IMAGE"
        exit 0
        ;;
    --fetch-symbols)
        # ⭐ **Reference-data acquisition, deliberately a separate verb.**
        #
        # Volatility cannot analyse a Windows dump without the matching kernel
        # symbols, and it obtains them from Microsoft's symbol server. That is a
        # network fetch — but of *reference data*, not of evidence, and the two
        # deserve different rules. Making it its own command keeps the ordinary
        # examination path offline (see `--network none` below) instead of
        # quietly granting every run a network it does not need.
        #
        # Symbols land in `forensics/symbols/`, which persists, so this is run
        # once per kernel build and never again.
        NETWORK="bridge"
        shift
        ;;
    "")
        echo "usage: forensics/run.sh <artefact-dir> <tool> [args...]" >&2
        echo "       forensics/run.sh --fetch-symbols <artefact-dir> <tool> [args...]" >&2
        echo "       forensics/run.sh --build | --versions | --digest" >&2
        exit 2
        ;;
esac

NETWORK="${NETWORK:-none}"

ARTEFACT_DIR="$1"
shift

mkdir -p forensics/symbols forensics/out

if [ ! -d "$ARTEFACT_DIR" ]; then
    echo "no such artefact directory: $ARTEFACT_DIR" >&2
    echo "run:  sh datasets/fetch-artefacts.sh" >&2
    exit 1
fi

ensure_image

# `--user` so output files are not root-owned — the same trap `besu/generate.sh`
# already records, where a root-owned artefact left the next run unable to clean
# up after itself.
#
# `--network` is `none` for examination: a forensic tool has no business
# reaching the network while looking at evidence, and closing it makes an
# unexpected outbound connection an error rather than something nobody noticed.
# Only `--fetch-symbols` sets it to `bridge`, and only to acquire reference data.
#
# ⚠️ `HOME` must point somewhere writable. Running as the invoking uid leaves
# `HOME` unset inside the container, so Volatility 3 resolves its cache to
# `/.cache` and dies with `PermissionError: [Errno 13]` — which reads like a
# broken image rather than a missing environment variable. `/out` is the one
# writable mount, so it doubles as the tool cache.
#
# ⚠️ The symbols mount lands **on Volatility's own package path**, not on a
# directory of our choosing. `-s` and `VOLATILITY3_SYMBOL_DIRS` only say where
# to *read*; downloaded symbols are written package-relative, so a mount
# anywhere else is silently ignored and the tool emits a permissions warning
# that reads like a broken image.
exec docker run --rm \
    --user "$(id -u):$(id -g)" \
    --network "$NETWORK" \
    --env HOME=/out \
    --env XDG_CACHE_HOME=/out/.cache \
    --volume "$(cd "$ARTEFACT_DIR" && pwd):/work:ro" \
    --volume "$(pwd)/forensics/out:/out" \
    --volume "$(pwd)/forensics/symbols:/usr/local/lib/python3.11/dist-packages/volatility3/symbols/windows" \
    "$IMAGE" "$@"
