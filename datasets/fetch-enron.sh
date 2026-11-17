#!/bin/sh
# Fetch the Enron email corpus — the shared point of contact with every SSE
# baseline, and what M2's acceptance criterion is stated against.
#
# The build plan: no synthetic corpora. Enron is the standard SSE
# benchmark and is what `CDSecLab/Doris` uses, so it is the dataset that makes
# our numbers comparable to theirs at all.
#
# The corpus is NOT in git (§3: "datasets/ — fetch + prepare scripts. No data in
# git."). ~423 MB compressed, ~1.7 GB expanded, ~517k messages.
#
# Usage:
#   sh datasets/fetch-enron.sh [target-dir]      # default: datasets/enron
#
# On AWS, prefer the in-region S3 copy if one is available in us-east-1 —
# The design record pins runs there precisely so corpus reads are
# free. This script is the portable fallback.

set -eu

TARGET="${1:-$(dirname "$0")/enron}"
URL="https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
ARCHIVE="$TARGET/enron_mail_20150507.tar.gz"

# Pinned checksum. Recorded 2026-09-09 from an actual download, not from
# recollection — the manifest in datasets/enron.sha256 is the authority and this
# constant is the fallback when it is absent.
#
# History worth keeping: an earlier draft of this script carried this exact
# value as an unverified constant, and it was removed for being unverifiable.
# The download later produced the same digest. That does not retroactively make
# shipping it correct: a value nobody has checked is indistinguishable from a
# wrong one, and the failure mode -- a checksum that rejects a good download --
# teaches the next person to delete the check.
SHA256="b3da1b3fe0369ec3140bb4fbce94702c33b7da810ec15d718b3fadf5cd748ca7"
MANIFEST="$(dirname "$0")/enron.sha256"

mkdir -p "$TARGET"

if [ -d "$TARGET/maildir" ]; then
    echo "already present: $TARGET/maildir"
    exit 0
fi

if [ ! -f "$ARCHIVE" ]; then
    echo "fetching $URL"
    echo "  ~423 MB; this takes a while"
    curl -fSL --retry 3 -o "$ARCHIVE.part" "$URL"
    mv "$ARCHIVE.part" "$ARCHIVE"
fi

command -v sha256sum >/dev/null 2>&1 || {
    echo "sha256sum unavailable; refusing to continue unverified." >&2
    exit 1
}

# Prefer a previously recorded manifest over the in-script constant, so the
# pin survives without anyone editing this file.
if [ -z "$SHA256" ] && [ -f "$MANIFEST" ]; then
    SHA256=$(cut -d' ' -f1 "$MANIFEST")
fi

ACTUAL=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)

if [ -z "$SHA256" ]; then
    printf '%s  %s\n' "$ACTUAL" "enron_mail_20150507.tar.gz" > "$MANIFEST"
    echo
    echo "NO PINNED CHECKSUM EXISTED. Recorded this download as the reference:"
    echo "  $ACTUAL"
    echo "  -> $MANIFEST   (commit this)"
    echo
    echo "⚠️  This pins what we downloaded; it does not prove it is what the"
    echo "    maintainers published. Check it against the corpus homepage"
    echo "    before any measurement is published from it, and say in the paper"
    echo "    which corpus snapshot was used."
elif [ "$ACTUAL" != "$SHA256" ]; then
    echo
    echo "CHECKSUM MISMATCH. Refusing to use this file."
    echo "  expected $SHA256"
    echo "  got      $ACTUAL"
    echo
    echo "Either the download is truncated, or upstream changed the corpus."
    echo "Do not 'fix' this by editing the pin: a changed corpus changes every"
    echo "keyword distribution in the paper, and that must be a deliberate,"
    echo "recorded decision."
    exit 1
else
    echo "checksum ok: $ACTUAL"
fi

echo "expanding into $TARGET"
tar -xzf "$ARCHIVE" -C "$TARGET"

echo
echo "done: $TARGET/maildir"
echo "run the M2 corpus acceptance with:"
echo "  PQCL_ENRON=$TARGET/maildir cargo test --release -p pqcl-dsse --test corpus -- --ignored --nocapture"
