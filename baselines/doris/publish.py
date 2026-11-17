#!/usr/bin/env python3
"""Turn two container runs into one publication record, or refuse.

Condition 4 of the AWS-only carve-out: the
exception rests on the container's output being host-independent, and the way
to evidence that is to run it twice and compare — not to argue it.

⭐ **This converts "host-independent by argument" into "deterministic by
measurement"**, which is the form a reviewer can check. It kills the plausible
failure — a hidden RNG, clock, or hash-order dependence — instead of reasoning
it away.

⚠️ **The comparison is over the structural projection, not the whole file.**
``setup_attempts`` counts how many times upstream's probabilistic ``TSet`` setup
had to be retried with a fresh seed, which is a property of the *run* and varies
legitimately between runs. Including it would make the check fail for a reason
that has nothing to do with the metrics, and the natural next step would be to
weaken the check. It is recorded per run and excluded from the comparison, and
that exclusion is stated in the record itself rather than buried here.

Usage::

    publish.py --first a.json --second b.json --out record.json \\
               --git-sha <sha> --git-dirty <true|false>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

#: Must match ``AWS_EXEMPT_MARKER`` in ``tools/mkfigs.py``. Asserted there too:
#: a record carrying anything else is refused.
AWS_EXEMPT_MARKER = "reused-baseline-structural"

#: Identifies which row is which. Not compared — used to pair rows up.
ROW_KEY = ("scheme", "dataset", "tier")

#: Excluded from the determinism comparison, with the reason recorded in the
#: emitted record. Everything not listed here IS compared.
#:
#: ⚠️ Keep this list short and argued. Each entry is a field whose variation is
#: tolerated, so an unjustified addition is how a determinism check quietly
#: becomes a tolerance — the thing §1.7 rejected option B for.
#:
#: * ``setup_attempts`` — retries of upstream's probabilistic ``TSet`` setup.
#:   A property of the run, not of the index.
#: * ``zr_short_encodings`` / ``canonical_bytes_added`` — how many field
#:   elements happened to land below ``2^152`` this run. ⭐ These are the
#:   *absorbed* variation: they vary precisely so that ``tset_bytes`` no longer
#:   does. Comparing them would re-introduce the nondeterminism the
#:   canonicalisation removes. ``zr_elements`` is **not** excluded — the number
#:   of elements serialised is deterministic and must agree.
RUN_VARIANT_KEYS = frozenset(
    {"setup_attempts", "zr_short_encodings", "canonical_bytes_added"}
)


def projection(doc: dict) -> dict[tuple, dict]:
    """The part of a run that must be identical across runs."""
    out = {}
    for row in doc.get("rows", []):
        key = tuple(row.get(k) for k in ROW_KEY)
        out[key] = {k: v for k, v in sorted(row.items()) if k not in RUN_VARIANT_KEYS}
    return out


def compare(first: dict, second: dict) -> list[str]:
    """Every way the two runs disagree. Empty means identical."""
    a, b = projection(first), projection(second)
    problems = []

    for key in sorted(set(a) - set(b), key=repr):
        problems.append(f"{key}: present in run 1, absent in run 2")
    for key in sorted(set(b) - set(a), key=repr):
        problems.append(f"{key}: absent in run 1, present in run 2")

    for key in sorted(set(a) & set(b), key=repr):
        for field in sorted(set(a[key]) | set(b[key])):
            x, y = a[key].get(field, "<missing>"), b[key].get(field, "<missing>")
            if x != y:
                problems.append(f"{key} field {field!r}: run 1 {x!r} != run 2 {y!r}")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--first", required=True, type=Path)
    ap.add_argument("--second", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--git-sha", required=True)
    ap.add_argument("--git-dirty", required=True, choices=("true", "false"))
    args = ap.parse_args()

    first = json.loads(args.first.read_text(encoding="utf-8"))
    second = json.loads(args.second.read_text(encoding="utf-8"))

    if not first.get("rows"):
        raise SystemExit("run 1 produced no rows; there is nothing to publish")

    problems = compare(first, second)

    if problems:
        print(
            "REFUSING to publish: the two runs disagree, so the output is not "
            "deterministic and the carve-out's premise does not hold.\n",
            file=sys.stderr,
        )
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(
            "\nThis is a finding, not a flaky box. Do not retry until it "
            "passes -- find the source of the variation first.",
            file=sys.stderr,
        )
        return 1

    # Errors recorded by metrics.py are rows too, and they compare equal when
    # both runs failed the same way. That must not read as a clean result.
    failed = [r for r in first["rows"] if "error" in r]
    if failed:
        print(
            f"warning: {len(failed)} row(s) recorded an error. They are "
            f"deterministic, but they are not measurements.",
            file=sys.stderr,
        )

    record = {
        "experiment": "doris-structural",
        "aws_exempt": AWS_EXEMPT_MARKER,
        "aws_exempt_rule": (
            "the design record standing rule, 'the one AWS-only "
            "carve-out'. Scope: the reused CDSecLab/Doris container, "
            "structural quantities only. Our own Rust structural metrics are "
            "not covered and run on AWS."
        ),
        "git_sha": args.git_sha,
        "git_dirty": args.git_dirty == "true",
        "provenance": first["provenance"],
        "determinism": {
            "runs": 2,
            "identical": True,
            "compared": "every row field except " + ", ".join(sorted(RUN_VARIANT_KEYS)),
            "excluded_reason": (
                "setup_attempts counts retries of upstream's probabilistic "
                "TSet setup and is a property of the run, not of the index. "
                "It is recorded per run below."
            ),
            "setup_attempts_run1": {
                "/".join(str(r.get(k)) for k in ROW_KEY): r.get("setup_attempts")
                for r in first["rows"]
                if "setup_attempts" in r
            },
            "setup_attempts_run2": {
                "/".join(str(r.get(k)) for k in ROW_KEY): r.get("setup_attempts")
                for r in second["rows"]
                if "setup_attempts" in r
            },
        },
        "rows": first["rows"],
    }

    args.out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"wrote {args.out} ({len(record['rows'])} rows, 2 runs identical)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
