#!/usr/bin/env bash
# Push the repo to the measurement instance.
#
# ⚠️ **`.git` must go across, and this is not optional.**
# `RunMetadata::collect` calls `detect_commit`, which shells out to
# `git rev-parse HEAD` and `git status --porcelain`. Without a `.git` directory
# that call returns `ProvenanceError::Git`, which is deliberately *not*
# recoverable — a measurement with no commit behind it cannot be traced to the
# code that produced it, so the harness refuses to write a record at all.
#
# The practical consequence: an instance seeded with a plain `scp -r` of the
# source files produces **no results whatsoever**, and it fails at the end of
# the first experiment rather than at setup. `.git` is 88 MB; send it.
#
# ⛔ **Exclude untracked bulk only — never a whole directory that holds tracked
# files.** The first version of this script excluded `ref-papers/` and
# `forensics/out/` wholesale. Both contain tracked files (`cite.bib`,
# `MANIFEST.sha256`, `.gitignore` stubs), so `--delete` removed them on the
# instance and `git status` there reported six deletions — meaning every record
# the campaign produced would have been stamped `git_dirty = true` and refused.
#
# The source clone is clean by the check above, so it holds no untracked bulk
# beyond these two. Anything else tracked is small and travels.
#
# What is left behind:
#   target/          ~8 GB of build artefacts, rebuilt on the instance anyway
#   ref-papers/*.pdf 114 MB of third-party PDFs, untracked, not needed to measure
#   datasets/enron/  3 GB, 517k files — the instance fetches it itself with
#                    datasets/fetch-enron.sh (423 MB, SHA-256 pinned), which is
#                    faster in-region than any home uplink. Gitignored, so its
#                    absence leaves the tree clean; excluded paths are also
#                    never deleted on the receiver by --delete.
#   datasets/artefacts/ 2.7 GB of M8 test inputs; not a campaign input.
#
# Usage:
#   aws/sync-to-instance.sh ec2-user@<public-dns> [ssh-key]

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <user@host> [ssh-key]" >&2
    exit 2
fi

TARGET="$1"
KEY="${2:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

SSH_OPTS="-o StrictHostKeyChecking=accept-new"
[ -n "$KEY" ] && SSH_OPTS="$SSH_OPTS -i $KEY"

# ⛔ Refuse to seed an instance from a dirty tree. Otherwise the SHA that gets
# stamped on every number does not describe the code that ran, which is the
# thing the whole results pipeline exists to guarantee — and it would not be
# discovered until `mkfigs.py` refused the output, after the instance had been
# paid for.
cd "$REPO_ROOT"
if [ -n "$(git status --porcelain)" ]; then
    echo "refusing to sync: the tree is dirty, so the SHA would not describe what ran" >&2
    git status --short >&2
    exit 1
fi

echo "syncing $(git rev-parse --short HEAD) to $TARGET"

# ⛔ `results/`'s CONTENTS are excluded — but its tracked
# `.gitignore` is included first. Excluding the whole directory (the previous
# version) left that file missing on the instance, so `git status` there showed
# ` D results/.gitignore` and every record would have been
# stamped dirty and refused: the exact shape the warning above describes, in
# the one exclude it did not check. Found on campaign 02's instance before any
# measurement.
#
# The exclusion itself is about `--delete`, not
# about bandwidth. Measurements are written on the instance; without this
# exclude a second sync — to ship a fix mid-campaign, which is exactly when one
# happens — **deletes every result taken so far**. It already destroyed the
# provenance rehearsal record once.
#
# ⛔ `nitro/out/` likewise: gitignored, and it holds what the
# instance built — the EIF, its measurements, the KMS-wrapped `K_mst`. A
# mid-campaign sync with `--delete` used to remove them, so the enclave could
# not be booted again without rebuilding the image and re-applying the key
# policy. `m5b-acceptance.sh` rebuilds the image itself when the code changes.
#
# Excluding it also means results never travel host→instance, which is the right
# direction of travel anyway: they flow back through `pull-results.sh` and
# nowhere else.
rsync -az --delete \
    --exclude 'target/' \
    --exclude '**/target/' \
    --exclude 'ref-papers/*.pdf' \
    --exclude '/local-work/' \
    --exclude 'aws/audit/' \
    --include 'results/.gitignore' \
    --exclude 'results/*' \
    --exclude 'datasets/enron/' \
    --exclude 'datasets/artefacts/' \
    --exclude 'nitro/out/' \
    -e "ssh $SSH_OPTS" \
    "$REPO_ROOT/" "$TARGET:~/pq-chainlog/"

# ⛔ **Tracked records are restored from `.git`, and the tree is then checked
# here rather than left to the reader.** Campaign 07's records are committed
# under `results/`, so the exclude above left them missing on the instance and
# `git status` there showed five-plus deletions: every record campaign 08 wrote
# would have been stamped dirty. Found on campaign 08's instance before any
# measurement, after the script had printed "synced" and an instruction to
# check by hand. `git checkout` restores exactly the tracked files and touches
# nothing the instance wrote itself.
# shellcheck disable=SC2029
ssh $SSH_OPTS "$TARGET" 'cd ~/pq-chainlog && git checkout -- results'
# shellcheck disable=SC2029
DIRTY="$(ssh $SSH_OPTS "$TARGET" 'cd ~/pq-chainlog && git status --porcelain')"
if [ -n "$DIRTY" ]; then
    echo "synced, but the instance tree is dirty; every record would be refused:" >&2
    echo "$DIRTY" >&2
    exit 1
fi
echo "synced $(git rev-parse --short HEAD); the instance tree is clean"
