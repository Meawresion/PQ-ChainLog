#!/bin/bash
# What a harness executes, measured: build it with LLVM coverage at a record's
# SHA, run it at smoke scale, and export per-function execution counts.
#
#   tools/stale_coverage.sh <sha> <outdir> <bin>...
#
# Writes <outdir>/<bin>.json (`llvm-cov export`) for each harness. The input to
# `tools/stale_guard.py`, which decides whether a record is stale
#
#
# ⚠️ Coverage is of the **whole smoke process**, a superset of the timed
# region (setup and record emission are counted too). The guard is therefore
# conservative: it may flag a change the timed region never reaches, never the
# reverse.
#
# Local-RAM rule: every invocation below is a smoke size; peak RSS is printed.
set -uo pipefail
SHA=$1; OUT=$2; shift 2
source ~/.cargo/env
CLONE=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
WT=/tmp/pqcl-stale-$SHA
TARGET=$CLONE/local-work/cov-target
LLVM=$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin
ENRON=${PQCL_ENRON:-$CLONE/datasets/enron/maildir}
mkdir -p "$OUT"; OUT=$(readlink -f "$OUT")

[ -d "$WT" ] || git -C "$CLONE" worktree add -q --detach "$WT" "$SHA" || exit 1
# A worktree has no submodules; the harnesses read data (not code) from one.
SUB=baselines/doris/upstream
if [ -z "$(ls -A "$WT/$SUB" 2>/dev/null)" ]; then
  rmdir "$WT/$SUB" 2>/dev/null; ln -sfn "$CLONE/$SUB" "$WT/$SUB"
fi
cd "$WT" || exit 1
export RUSTFLAGS="-C instrument-coverage" CARGO_TARGET_DIR=$TARGET CARGO_BUILD_JOBS=4

# Smoke invocations: <bin> <features> <env...>. Sizes are the smallest each
# harness accepts; the code paths are the campaign's.
smoke() {
  case "$1" in
    # The axis must include the declared operating point (y = 4096), or the
    # harness refuses to run (§1q.2).
    exp1)    echo "classical-baseline|PQCL_COLLECTION_N=64,4096" ;;
    exp7)    echo "|PQCL_COLLECTION_N=64,4096" ;;
    exp2)    echo "|PQCL_EXP2_TIERS=500" ;;
    size)    echo "|PQCL_SIZE_TIERS=0" ;;   # a tier index: the smallest
    exp345|exp6|exp8910) echo "|" ;;
    *) echo "unknown harness $1" >&2; return 1 ;;
  esac
}

for bin in "$@"; do
  spec=$(smoke "$bin") || exit 1
  feat=${spec%%|*}; envs=${spec#*|}
  rm -f "$OUT/$bin"-*.profraw
  cargo build --release -q -p pqcl-exp --bin "$bin" ${feat:+--features $feat} || exit 1
  exe=$TARGET/release/$bin
  echo "== $bin ($envs) at $SHA" >&2
  env $envs PQCL_ENRON="$ENRON" LLVM_PROFILE_FILE="$OUT/$bin-%p.profraw" \
      /usr/bin/time -f "   peak RSS %M KB, exit %x" "$exe" > /dev/null 2> "$OUT/$bin.err"
  tail -1 "$OUT/$bin.err" >&2
  # ⛔ A harness that did not finish covered only part of what it executes,
  # and a guard reading that would under-flag. Refuse (rule 18).
  if ! tail -1 "$OUT/$bin.err" | grep -q "exit 0$"; then
    echo "REFUSED: $bin did not exit 0 at $SHA; its coverage would be partial" >&2
    rm -f "$OUT/$bin"-*.profraw "$OUT/$bin.json"
    exit 1
  fi
  "$LLVM/llvm-profdata" merge -sparse "$OUT/$bin"-*.profraw -o "$OUT/$bin.profdata" || exit 1
  "$LLVM/llvm-cov" export -format=text -skip-expansions -instr-profile="$OUT/$bin.profdata" \
      "$exe" > "$OUT/$bin.json" || exit 1
  rm -f "$OUT/$bin"-*.profraw
  echo "$WT" > "$OUT/root.txt"
done
