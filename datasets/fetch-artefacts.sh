#!/bin/sh
# Fetch the three real forensic artefacts M8 ingests.
#
# The build plan: **no synthetic corpora.** M8's acceptance is
# "ingest real disk images / memory dumps / PCAPs; run real forensic tooling",
# and a generated image would fail that on both halves — there would be nothing
# for The Sleuth Kit or Volatility to find, so the custody records derived from
# those runs would describe work that never happened.
#
# One artefact of each type, chosen as the smallest *real* item of its kind so
# the pipeline can be exercised on a developer box. Nothing here is a sample,
# a trimmed copy, or a reconstruction: these are the corpora's own files.
#
# | Artefact | Source | Why this one |
# |---|---|---|
# | `nps-2009-canon2-gen6.E01` | NPS drive corpus | A real EnCase image of a real camera card, ~31 MB. Has a genuine FAT filesystem with deleted files, which is what makes `fls`/`icat` meaningful |
# | `charlie-2009-12-03.mddramimage` | M57-Patents scenario | A real Windows RAM capture taken with mdd during the scenario, ~598 MB compressed. Volatility 3 finds real processes in it |
# | `multifile_25_21.pcap` | 2013 HTTP-transfer capture | A real packet capture, ~53 MB, with real HTTP transfers for tshark to dissect |
#
# ⚠️ **~680 MB of downloads.** Not in git (§3: "datasets/ — fetch + prepare
# scripts. No data in git.").
#
# On AWS prefer the in-region S3 copy: `s3://digitalcorpora/` is an AWS Open
# Data bucket, so these reads are free from us-east-1, which is a large part of
# why the AWS run is the real run. This script is the portable HTTPS fallback.
#
# Usage:
#   sh datasets/fetch-artefacts.sh [target-dir]   # default: datasets/artefacts

set -eu

TARGET="${1:-$(dirname "$0")/artefacts}"
BASE="https://digitalcorpora.s3.amazonaws.com/corpora"
MANIFEST="$(dirname "$0")/artefacts.sha256"

DISK_KEY="drives/nps-2009-canon2/nps-2009-canon2-gen6.E01"
RAM_KEY="scenarios/2009-m57-patents/ram/charlie-2009-12-03.mddramimage.zip"
PCAP_KEY="packets/2013-httpxfer/multifile_25_21.pcap"

mkdir -p "$TARGET"

# ⚠️ **Resume, and abandon a stalled connection rather than riding it down.**
#
# Measured 2026-09-12: a fresh connection to this bucket sustains ~2 MB/s, but a
# long-lived one degraded to ~27 KiB/s and stayed there — which turns a
# ten-minute download into a five-hour one. `--speed-limit`/`--speed-time` give
# up on a transfer that drops below 100 KiB/s for a minute, and `-C -` resumes
# from the bytes already on disk, so a retry costs only the stalled seconds.
#
# The retry loop is bounded. An unbounded one would hide a genuinely dead
# mirror as an unending "download" that nobody notices.
fetch() {
    key="$1"
    out="$TARGET/$(basename "$key")"
    if [ -f "$out" ]; then
        echo "already present: $out"
        return 0
    fi
    echo "fetching $(basename "$key") ..."

    attempt=1
    while [ "$attempt" -le 20 ]; do
        # `--fail` so an S3 error page is not silently written out as if it were
        # the artefact; a "NoSuchKey" XML body would otherwise sail through and
        # fail much later as an unreadable image.
        if curl --fail --location --progress-bar \
                --continue-at - \
                --speed-limit 102400 --speed-time 60 \
                --output "$out.part" "$BASE/$key"; then
            mv "$out.part" "$out"
            return 0
        fi
        echo "  stalled or failed; resuming (attempt $attempt)" >&2
        attempt=$((attempt + 1))
    done

    echo "giving up on $key after $((attempt - 1)) attempts" >&2
    return 1
}

fetch "$DISK_KEY"
fetch "$RAM_KEY"
fetch "$PCAP_KEY"

# The RAM image ships zipped; Volatility needs it raw.
RAM_ZIP="$TARGET/$(basename "$RAM_KEY")"
RAM_RAW="$TARGET/charlie-2009-12-03.mddramimage"
if [ ! -f "$RAM_RAW" ]; then
    echo "expanding the RAM image ..."
    # `unzip` is not installed on every box and `apt-get` here needs an
    # interactive password. Python's `zipfile` is stdlib and always present,
    # so it is the fallback rather than a new system dependency.
    if command -v unzip >/dev/null 2>&1; then
        unzip -o -j "$RAM_ZIP" -d "$TARGET" >/dev/null
    else
        python3 -m zipfile -e "$RAM_ZIP" "$TARGET"
    fi
fi

echo
if [ -f "$MANIFEST" ]; then
    echo "verifying against $MANIFEST"
    # ⚠️ The manifest lives beside this script, the files in $TARGET. The old
    # form ran `sha256sum -c` from $TARGET against a manifest that is not there,
    # then fell back to the manifest's directory where the files are not — so
    # it could never pass. Campaign 02 never noticed because its run *wrote*
    # the manifest; campaign 03 was the first to reach this branch.
    MANIFEST_ABS="$(cd "$(dirname "$MANIFEST")" && pwd)/$(basename "$MANIFEST")"
    ( cd "$TARGET" && sha256sum -c "$MANIFEST_ABS" )
else
    # ⚠️ First run on a new machine writes the manifest rather than checking it.
    # A checksum nobody has ever verified is indistinguishable from a wrong one,
    # so this records what was actually downloaded instead of shipping a
    # constant taken on trust — the same lesson `fetch-enron.sh` carries.
    echo "no manifest yet; recording one from this download"
    ( cd "$TARGET" && sha256sum \
        "$(basename "$DISK_KEY")" \
        "$(basename "$RAM_RAW")" \
        "$(basename "$PCAP_KEY")" ) > "$MANIFEST"
    cat "$MANIFEST"
fi

echo
echo "artefacts ready in $TARGET"
