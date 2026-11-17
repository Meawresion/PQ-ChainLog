# `CDSecLab/Doris` — OXT, HXT, ConjFilter and Doris

The four baselines PQ-ChainLog **reuses** rather than reimplements. The authors published working
code for all four, so reimplementing them would add risk and no fidelity.

Everything about how this differs from upstream — and the findings that came out of running it —
is in [`../UPGRADES.md`](../UPGRADES.md). Read that before trusting a number from here.

## ⛔ The one rule that governs this directory

**No wall-clock number from this baseline may reach the paper.** Our system is Rust; this is
Python. The build plan:

> Comparing their wall-clock is meaningless and a reviewer will say so immediately.

What we take: **index size, round count, leakage profile**. `metrics.py` never calls `time()`, so
there is no timing here for anyone to later restore.

⚠️ **Communication volume is not taken from upstream either**, and that is deliberate rather than
an oversight — their `cal_comm_cost` is `len(pickle.dumps(...))`, which measures Python
serialization overhead, not wire bytes. See `../UPGRADES.md`.

## Layout

| Path | What |
|---|---|
| `upstream/` | The authors' repository, a submodule pinned to `61907c60910e159830009051c32fef077274c6e1`. **Never edited** — changes go in this directory instead |
| `Dockerfile` | Their exact stack: Ubuntu 20.04, Python 3.8, PBC 0.5.14, `pypbc` pinned by commit |
| `requirements-upstream.txt` | A copy of their `requirements.txt`, so the image builds without mounting the submodule |
| `run.sh` | The only entry point |
| `metrics.py` | Our driver: their code and their size formulas, plus a retry for upstream's probabilistic `TSet` failure, JSON output, and no timing |
| `results/` | Output. Gitignored |

## Running it from scratch

```sh
git submodule update --init baselines/doris/upstream

./baselines/doris/run.sh --build       # first run compiles PBC from source, several minutes
./baselines/doris/run.sh --versions    # what actually got installed

# Smoke test: does the harness still work? 100 pairs, seconds, throwaway output.
./baselines/doris/run.sh metrics --tiers 0 --datasets enron \
    --out /results/doris-structural-singlerun.json
```

## ⛔ Run the small tier here. Run the real ones on AWS.

**This machine cannot produce the full table, and each attempt costs an hour.**
The 10^6 tier was OOM-killed twice on a 16.9 GB host whose WSL gets ~10.7 GiB --
once at Doris, once at ConjFilter. A *different* scheme each time is the tell:
no single scheme is too big, the cost is cumulative. Every scheme’s structures
are freed when its function returns, but CPython does not hand freed arenas back
to the OS, so four schemes at 10^6 fragment past the cap.

Neither obvious lever is available. Raising the WSL cap would starve Windows at
16 GB, and shrinking upstream’s structures is forbidden -- this baseline is
reused rather than modernized precisely so its numbers stay the authors’.

| Where | What | Why |
|---|---|---|
| **here** | tier 0 only, as a smoke test | proves the container, the pins and the §1.7 tripwire still work, in seconds |
| **AWS** | every tier, both corpora, all four schemes | the only box with the memory, and the campaign is provisioned for it |

⭐ `--schemes` exists for the AWS run, not for this one: one scheme per process
bounds the peak, and `mkfigs.py` evaluates each record independently, so
per-scheme records with their own determinism evidence are as publishable as one
combined record.

```sh
# On the campaign instance, the real thing:
./baselines/doris/run.sh publish --tiers 0,1,2,3 --datasets enron,enwiki
failed=""
for S in OXT HXT ConjFilter Doris; do
  if ! ./baselines/doris/run.sh publish --tiers 4 --datasets enron,enwiki --schemes "$S" \
          --out "results/doris-structural-tier4-$S.json"; then
    failed="$failed $S"
  fi
done
[ -n "$failed" ] && echo "FAILED SCHEMES:$failed" >&2
```

⛔ **Collect the failures; do not trust a loop that keeps going.** A scheme that OOMs leaves the
loop running and the next one succeeds, so the tail of the log looks healthy. Worse, `$?` after a
`| tail` is **`tail`’s** status, so a wrapper that pipes the output reports success for a run that
died — that is how a Doris tier-4 failure was read as `exit=0` here, the third time that trap has
bitten this project. The missing record is the real signal: check the files, not the exit line.

⚠️ `publish`, not `metrics`. A single `metrics` run carries no determinism
evidence and no exemption marker, and the pipeline refuses it by design.

Other modes:

```sh
./baselines/doris/run.sh setup                 # upstream's own driver, logs a wall-clock we discard
./baselines/doris/run.sh shell -c "python3 -c 'import OXT'"
```

## Tiers

The tier index selects one of the pre-built inverted-index CSVs that ship in `upstream/data/`. The
labels are `(keyword, id)` pair counts, and the files really do contain exactly that many —
verified, not assumed:

| Tier | Pairs | Enron keywords | Enwiki keywords |
|---|---|---|---|
| 0 | 100 | 86 | 100 |
| 1 | 1 000 | 620 | 942 |
| 2 | 10 000 | 2 756 | 7 268 |
| 3 | 100 000 | 10 997 | 48 555 |
| 4 | 1 000 000 | 44 681 | 330 489 |

Upstream's own driver stops at tier 3 (`cnt = 4`). Plan §7 caps us at their 10⁶ tier, so tier 4 is
in scope.

## What the output means

Each row of `doris-structural.json` carries:

- `tset_bytes`, `xset_bytes`, `index_bytes` — **measured**, using upstream's own per-scheme
  formulas. These count occupied entries, not allocated slots; `../UPGRADES.md` explains why that
  distinction matters when comparing against our index size.
- `setup_attempts` — how many times upstream's `TSet` setup had to be retried. Usually 1. It is
  reported rather than hidden because a value above 1 is real fragility in the reused code.
- `search_rounds`, `storage_order`, `kprp_hidden`, `ip_hidden` — **paper-derived**, from Table 1 of
  `ref-papers/DORIS_CCS2024.pdf`, and labelled `protocol_fields_source` so they are never mistaken
  for something this harness observed. Note **HXT is two rounds**; the other three are one.
- `comm_bytes` — always `null`, with `comm_note` saying why.
