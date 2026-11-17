#!/usr/bin/env bash
# Pull measurements back from the instance. Results only.
#
# ⭐ **Only JSON comes back, and that is a design property rather than a
# convenience.** The build plan fixes one path from a run to a
# printed number:
#
#     run -> results/<exp>/*.json -> tools/mkfigs.py -> paper/generated/*.tex
#
# `mkfigs.py` runs *here*, on the pulled JSON. Nothing rendered, plotted or
# formatted is produced on the instance, so nothing rendered can be smuggled
# into the paper without a record behind it. Pulling a CSV or a figure would
# quietly create a second path to a published number, which is the one thing
# this pipeline exists to prevent.
#
# The logs come back too, under a separate directory. They are evidence, not
# input: nothing reads them to make a number.
#
# Usage:
#   aws/pull-results.sh ec2-user@<public-dns> [ssh-key]

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

mkdir -p "$REPO_ROOT/results" "$REPO_ROOT/aws/run-logs"

echo "pulling results/ from $TARGET"
rsync -az -e "ssh $SSH_OPTS" \
    "$TARGET:~/pq-chainlog/results/" \
    "$REPO_ROOT/results/"

# ⭐ Failures below are recorded rather than raised, and the script exits on the
# worst of them at the very end. Two things have to be true at once: a failing
# check must not be silently discarded, and the terminate reminder must print
# whatever happens — an instance left running because a check failed is the
# expensive failure, not the cheap one. `set -e` alone gives the second at the
# cost of the first; `|| true` gave the first at the cost of the second.
FAILED=""

echo "pulling run logs (evidence, never an input to a number)"
if ! rsync -az -e "ssh $SSH_OPTS" --ignore-missing-args \
        "$TARGET:~/pqcl-logs/" \
        "$REPO_ROOT/aws/run-logs/"; then
    FAILED="$FAILED log-pull"
fi

echo
echo "checking what was pulled against the publication rules:"
cd "$REPO_ROOT"
# ⛔ The exit status of this is the whole point of running it. It decides
# whether the pulled JSON may become a number in the paper, and discarding it
# turns the one publication gate into decoration.
if ! python3 tools/mkfigs.py --check results/; then
    FAILED="$FAILED publication-check"
fi

echo
echo "⛔ NEXT STEP IS NOT OPTIONAL — terminate the instance:"
echo "     aws ec2 terminate-instances --instance-ids <id>"
echo "   then confirm with aws ec2 describe-instances that nothing you launched is still running."

if [ -n "$FAILED" ]; then
    echo
    echo "⛔ FAILED:$FAILED" >&2
    echo "   The results are on disk, but the run above did not pass clean." >&2
    echo "   Terminate the instance first, then fix this — do not publish from" >&2
    echo "   a pull whose publication check did not pass." >&2
    exit 1
fi
