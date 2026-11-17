#!/usr/bin/env bash
# Run the upstream `CDSecLab/Doris` experiments in their pinned container.
#
# ⛔ **No wall-clock number produced here may reach the paper.** Plan §5: our
# system is Rust, this is Python, and comparing their latency to ours is
# meaningless. The upstream log line is
# `protocol,pair_num,setup_time(s),tset_size(B),xset_size(B)` — we take the two
# **byte counts** and discard `setup_time`. `extract.py` enforces that by
# dropping the column rather than trusting a reader to ignore it.
#
# Usage:
#   baselines/doris/run.sh --build
#   baselines/doris/run.sh --versions
#   baselines/doris/run.sh setup          # storage: tset/xset bytes per tier
#   baselines/doris/run.sh shell          # poke around

set -euo pipefail
cd "$(dirname "$0")"

IMAGE="pqcl-doris:1"
UPSTREAM="$PWD/upstream"

build() {
    docker build -q -t "$IMAGE" . >/dev/null
}

ensure_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        echo "building $IMAGE (first run: PBC is compiled from source) ..." >&2
        build
    fi
}

if [ ! -d "$UPSTREAM/Utils" ]; then
    echo "the upstream submodule is not checked out" >&2
    echo "run:  git submodule update --init baselines/doris/upstream" >&2
    exit 1
fi

case "${1:---help}" in
    --build)   build; echo "built $IMAGE"; exit 0 ;;
    --versions) ensure_image; docker run --rm "$IMAGE" cat /etc/pqcl-doris-versions; exit 0 ;;
    --help)
        echo "usage: baselines/doris/run.sh <metrics|publish|setup|shell|--build|--versions>" >&2
        echo "  metrics [--tiers 0,1,2,3] [--datasets enron,enwiki]   structural metrics -> results/*.json" >&2
        echo "  publish [--out PATH] [same args]                      run twice, prove determinism, emit the record" >&2
        echo "     the 10^6 tier needs its own job: publish --tiers 4 --datasets enron --out results/doris-structural-tier4.json" >&2
        echo "  setup                                                 upstream's own driver; logs a wall-clock we discard" >&2
        exit 2
        ;;
esac

MODE="$1"; shift

ensure_image

# `--user` so the log/ and results/ files are not root-owned; the same trap
# `besu/generate.sh` already records.
#
# The upstream tree is mounted **read-write** because the experiment drivers
# write into `./log/`. It is a pinned submodule, so any change is visible as a
# dirty submodule rather than lost.
run() {
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --volume "$UPSTREAM:/work" \
        --volume "$PWD/results:/results" \
        --volume "$PWD:/harness:ro" \
        --workdir /work \
        "$IMAGE" "$@"
}

mkdir -p results "$UPSTREAM/log"

case "$MODE" in
    setup)
        # Their driver defaults to `cnt = 4`, i.e. tiers 100..10^5. The plan caps
        # us at their 10^6 tier, which is index 4, so all five are wanted and
        # `cnt` has to be 5. Patched into a copy at run time rather than edited
        # in the submodule, so the pin stays clean and the change is visible
        # here instead of hidden in a dirty checkout.
        #
        # The assert matters: if upstream ever stops saying `cnt = 4`, this must
        # fail loudly rather than silently run whichever tiers it now defaults
        # to and report them as "up to 10^6".
        # The patched copy goes to /results, so the pinned submodule stays
        # byte-identical to its commit. `PYTHONPATH=/work` is what lets a script
        # outside the tree still import `OXT`, `Utils`, and the rest.
        run bash -c "set -e; python3 /harness/patch_tiers.py && PYTHONPATH=/work python3 /results/setup_exp_all_tiers.py"
        ;;
    metrics)
        # Our own driver: their code and their size formulas, plus a retry for
        # the probabilistic TSet failure, JSON output, and no timing at all.
        # Tiers default to 0..3; tier 4 is the 10^6 cap and is slow enough in
        # Python to be worth asking for explicitly.
        # Resolve the pin on the host: inside the container the submodule's
        # `.git` file points outside the mount and cannot be followed.
        REV="$(git -C "$UPSTREAM" rev-parse HEAD)"
        run bash -c "PYTHONPATH=/work python3 /harness/metrics.py --upstream-commit $REV $*"
        ;;
    publish)
        # Condition 4 of the AWS-only carve-out: the exception rests on this
        # output being host-independent, so run the container twice and compare
        # rather than asserting it. `publish.py` refuses on any disagreement.
        #
        # ⛔ The record this emits is the *only* form of these metrics that
        # `tools/mkfigs.py` will accept. A single `metrics` run produces a file
        # with no exemption marker and no determinism evidence, which the
        # pipeline refuses -- deliberately, so the short path is the unusable
        # one.
        REV="$(git -C "$UPSTREAM" rev-parse HEAD)"

        # ⭐ `--out` is a publish-level option, pulled out of the argument
        # list before the rest is handed to metrics.py.
        #
        # ⚠️ **It exists because the 10^6 tier does not fit alongside the rest.**
        # Running every tier and both corpora in one job was killed by the OOM
        # reaper part-way through Doris at tier 4 — its XOR-filter peeling holds
        # several large arrays at once, and by then the process had already been
        # through 10^5. Splitting the job bounds the peak without touching
        # upstream's structures, which we may not do. The 10^6 tier already had
        # its own file before this (`doris-structural-tier4.json`), so this
        # follows a precedent rather than inventing one.
        OUT="results/doris-structural.json"
        ARGS=""
        while [ $# -gt 0 ]; do
            case "$1" in
                --out) OUT="$2"; shift 2 ;;
                *) ARGS="$ARGS $1"; shift ;;
            esac
        done
        set -- $ARGS

        # Host-side, because the container has no view of our repo. A dirty
        # tree is still a refusal under the carve-out: waiving the AWS rule
        # does not make an untraceable number acceptable.
        SHA="$(git rev-parse HEAD)"
        if [ -n "$(git status --porcelain)" ]; then DIRTY=true; else DIRTY=false; fi

        # ⛔ **The intermediates are named after the record, not fixed.**
        # They used to be `.determinism-1/2.json` for every publish, so two
        # jobs -- a tiers-0-3 run and a tier-4 run, say -- silently shared
        # scratch files and the second destroyed the first's evidence. That
        # became reachable the moment `--out` let two records exist, and it
        # nearly cost the only surviving copy of a completed 32-row run --
        # recoverable *only* because these files are gitignored while the
        # record itself is tracked.
        STEM="$(basename "$OUT" .json)"
        for n in 1 2; do
            echo "== determinism run $n of 2 ==" >&2
            run bash -c "PYTHONPATH=/work python3 /harness/metrics.py \
                --upstream-commit $REV --out /results/.$STEM-run$n.json $*"
        done

        mkdir -p "$(dirname "$OUT")"
        python3 publish.py \
            --first  "results/.$STEM-run1.json" \
            --second "results/.$STEM-run2.json" \
            --out    "$OUT" \
            --git-sha "$SHA" --git-dirty "$DIRTY"

        # --- put the record where the pipeline actually looks -----------------
        #
        # ⛔ **Without this the carve-out record is unreachable, and that was
        # true for its whole existence.** `tools/mkfigs.py` discovers records by
        # `rglob("*.json")` under the root it is handed, and every caller hands
        # it `results/` -- `aws/pull-results.sh` included. This
        # record lived only under `baselines/doris/results/`, which that glob
        # never reaches. So the AWS-only carve-out, its whitelist, its
        # determinism requirement and its sixteen self-tests were all enforced
        # against a file the pipeline could not see. Checked directly: copied
        # into a directory mkfigs was pointed at, the record reports
        # "1 publishable, 0 refused" -- it always conformed, it was simply never
        # presented.
        #
        # ⭐ Two copies, written by one command, so they cannot drift. The
        # tracked one under `baselines/doris/results/` is the archive, and being
        # tracked is what made it recoverable when a stray `metrics` run
        # overwrote it. The one under `results/` is the
        # pipeline's input and is gitignored like every other live record, for
        # the reason that directory's .gitignore spells out: a tracked record
        # dirties the tree and poisons the *next* run's provenance.
        #
        # ⚠️ During a campaign `--out` points INTO the pipeline directory, so
        # the tracked archive is not written mid-run — writing it dirties the
        # tree, and every later publish on the box is then stamped dirty and
        # refused. The archive is refreshed from the pulled records and
        # committed afterwards. In that case there is no second copy to make.
        # ⛔ Relative to $PWD, NOT `$(dirname "$0")`: line 18 has already cd'd
        # into this script's directory, so a relative $0 (the campaign's
        # `bash baselines/doris/run.sh`) resolved to a path that does not exist
        # from here, and `set -e` failed the step AFTER the record was written.
        # Seen on campaign 02; the record itself was intact.
        PIPELINE_DIR="$(cd ../.. && pwd)/results/doris-structural"
        mkdir -p "$PIPELINE_DIR"
        if [ "$(realpath "$OUT")" != "$(realpath "$PIPELINE_DIR/$(basename "$OUT")")" ]; then
            cp "$OUT" "$PIPELINE_DIR/$(basename "$OUT")"
            echo "also wrote $PIPELINE_DIR/$(basename "$OUT") (the pipeline reads this one)" >&2
        fi
        ;;
    shell)
        # Pass arguments through, so `run.sh shell -c "..."` works. Dropping
        # them made a smoke test silently produce nothing, which reads as a
        # broken container rather than a broken wrapper.
        run bash "$@"
        ;;
    *)
        echo "unknown mode: $MODE" >&2
        exit 2
        ;;
esac
