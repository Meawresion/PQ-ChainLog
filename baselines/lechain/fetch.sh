#!/usr/bin/env bash
# Fetch LEChain's published contract at the pinned commit and verify its bytes.
#
# LEChain (Li et al., FGCS 115, 2021) cites github.com/SopmmmodII/LEChain in
# footnote 5 as its source code. The repository carries **no licence**, so the
# source is not vendored into ours: this script fetches it into `upstream/`
# (gitignored), pinned by commit and by SHA-256, the way `ref-papers/*.pdf` is
# pinned rather than committed.
#
# ⛔ A hash mismatch is a refusal, not a warning. A different contract is a
# different baseline, and nothing measured against it may carry this name.
#
# Usage: bash baselines/lechain/fetch.sh    (from anywhere)

set -euo pipefail
cd "$(dirname "$0")"

REPO="https://github.com/SopmmmodII/LEChain"
COMMIT="159b5a7ec01b471409d1ee0799da52cbacc94fbf" # master, 2020-08-18 "Add files via upload" — the head, and the only one carrying the contract
SHA256="a9767874785c8e166646f684e8c25b7b4ee209618efa1bd1ec62e9da7d36d4fa"

if [ ! -d upstream/.git ]; then
    git clone -q "$REPO" upstream
fi
git -C upstream fetch -q origin "$COMMIT"
git -C upstream -c advice.detachedHead=false checkout -q "$COMMIT"

got="$(sha256sum upstream/LEChain.sol | cut -d' ' -f1)"
if [ "$got" != "$SHA256" ]; then
    echo "REFUSED: upstream/LEChain.sol is $got, pinned $SHA256" >&2
    exit 1
fi
echo "LEChain.sol at $COMMIT verified ($SHA256)"
