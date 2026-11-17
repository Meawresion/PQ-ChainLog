#!/usr/bin/env python3
"""Turn committed results JSON into LaTeX the paper ``\\input{}``s.

The build plan fixes one path from a run to a printed number::

    run -> results/<exp>/<utc>-<git-sha>-<instance>.json
        -> tools/mkfigs.py
        -> paper/generated/*.tex
        -> draft7.tex \\input{}s them

Nobody hand-types a measurement. This script is the only thing that writes
``paper/generated/``, and it **refuses** rather than warns:

* ``environment`` must be ``aws``. A local number may decide whether something
  is worth running on AWS, and nothing else (§0.3).
* ``git_dirty`` must be false. Otherwise the SHA does not describe the code
  that ran, and the record is not traceable.
* ``profile`` must be ``release``. A debug build measured AES-256-GCM at
  8 MiB/s where release gives 1524 MiB/s, because generic code compiles at the
  caller's opt-level. A debug timing can be two orders of magnitude wrong.
* ``iterations`` must be >= 10, since §12 reports median and IQR rather than a
  single run (and never a mean without spread).

The same rules live in ``crates/pqcl-bench/src/lib.rs`` as
``RunMetadata::publication_refusals``. They are stated twice on purpose — the
Rust side stops a bad run being written, this side stops one being printed —
and ``test_rules_match_rust`` checks the two lists have not drifted apart.

There is **one** exception to the AWS rule, and it is enforced here rather than
remembered. See ``exempt_refusals``.

Usage::

    python3 tools/mkfigs.py --check results/            # refuse-only, no output
    python3 tools/mkfigs.py results/ --out ../paper/generated/
    python3 tools/mkfigs.py --selftest                  # run the built-in tests
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from pathlib import Path

MIN_ITERATIONS = 10

# Kept in step with RefusalReason in crates/pqcl-bench/src/lib.rs **by a test
# on that side** (`refusal_kinds_match_the_python_guard`), which parses this
# exact line. ⚠️ Keep it on one line, starting `REFUSAL_KINDS = (`.
REFUSAL_KINDS = ("not_aws", "dirty_tree", "debug_build", "too_few_iterations", "secure_module_not_enclave")

# The one Secure Module whose records may be published. Mirrors
# `pqcl_bench::PUBLISHABLE_SECURE_MODULE` (M13 A18); the project rules locks AWS
# Nitro Enclaves for every paper number.
PUBLISHABLE_SECURE_MODULE = "nitro-enclave"

# Refusals that exist only on this side, because the carve-out below is a
# property of a Python container's output and the Rust harness can never
# produce one. Deliberately not mirrored in Rust: `RunSpec` has no field that
# could set the marker, and that is the point.
EXEMPTION_REFUSAL_KINDS = (
    "bad_exemption",
    "not_reused_upstream",
    "unwhitelisted_metric",
    "not_deterministic",
)

# --------------------------------------------------------------------------
# The one AWS-only carve-out (the design record standing rule).
#
# ⛔ This is a named exception to ground rule #3, not a softening of it. Scope:
# the reused CDSecLab/Doris container, structural quantities only. Our own Rust
# structural metrics are NOT covered and run on AWS like everything else.
#
# Condition 3 of that rule is why this code exists: a carve-out policed by
# memory is the permanent hole the original ruling was avoiding. The
# `RunMetadata` finding is the argument — a type defined, serialised,
# unit-tested and constructed nowhere let a complete guard run while enforcing
# nothing. A rule everyone knows is not a control.
# --------------------------------------------------------------------------

#: The only accepted value of the ``aws_exempt`` marker. A free-form string
#: would let a future record invent its own justification.
AWS_EXEMPT_MARKER = "reused-baseline-structural"

#: Metric names the carve-out may carry. **Closed and exhaustive**: adding a
#: name here is a decision to be argued, not a convenience. Every one is a byte
#: count or a paper-derived protocol property — nothing that could vary with
#: the host, and nothing that is a measurement of *speed*.
STRUCTURAL_METRICS = frozenset(
    {
        "tset_bytes",
        "xset_bytes",
        "index_bytes",
        "comm_bytes",
        "search_rounds",
        "storage_order",
        "kprp_hidden",
        "ip_hidden",
        # §1.7: the canonical-field-element correction, exposed so a reader can
        # recover upstream's raw figure from ours. Counts, not measurements.
        "zr_elements",
        "zr_short_encodings",
        "canonical_bytes_added",
    }
)

#: Keys that describe *which* measurement a row is, rather than being one.
ROW_DESCRIPTOR_KEYS = frozenset(
    {
        "scheme",
        "dataset",
        "tier",
        "pairs",
        "setup_attempts",
        "error",
        "comm_note",
        "protocol_fields_source",
    }
)

#: Substrings that may never appear in an exempt record's keys, whatever the
#: whitelist says. Belt and braces: the whitelist is the control, and this
#: catches a well-meaning addition to it that is plainly a timing.
FORBIDDEN_SUBSTRINGS = (
    "latency",
    "throughput",
    "gas",
    "seconds",
    "millis",
    "micros",
    "nanos",
    "_ms",
    "_us",
    "_ns",
    "elapsed",
    "duration",
    "time",
    "ops_per",
    "rate",
    "speed",
)


def _row_keys(record: dict) -> set[str]:
    """Every key appearing in any measurement row.

    Walks ``rows`` rather than trusting a declared schema, because the thing
    being checked is what the record actually contains.
    """
    keys: set[str] = set()
    for row in record.get("rows") or []:
        if isinstance(row, dict):
            keys |= set(row)
    return keys


def exempt_refusals(record: dict) -> list[str]:
    """Rules for a record claiming the one AWS-only carve-out.

    The carve-out **swaps two rules, it does not drop four**:

    * ``not_aws`` — waived. That is the whole exception.
    * ``debug_build`` — waived. The reused baseline is Python; there is no
      release/debug distinction to assert.
    * ``too_few_iterations`` — *replaced* by the determinism requirement.
      Ten repetitions of a deterministic byte count says nothing; two runs
      agreeing bit for bit says the thing we actually need (condition 4).
    * ``dirty_tree`` — **still enforced, unchanged.** Waiving the AWS rule does
      not make an untraceable number acceptable.

    Two further gates keep the exception from widening:

    * the record must come from a *reused upstream*, identified by its own
      provenance. Our code has no upstream commit, so our metrics cannot claim
      this route even if someone set the marker.
    * every measurement key must be in :data:`STRUCTURAL_METRICS`. A latency,
      throughput or gas field is refused however the record is labelled.
    """
    out: list[str] = []

    marker = record.get("aws_exempt")
    if marker != AWS_EXEMPT_MARKER:
        out.append(
            f"bad_exemption: aws_exempt is {marker!r}; the only accepted value "
            f"is {AWS_EXEMPT_MARKER!r}"
        )

    prov = record.get("provenance")
    prov = prov if isinstance(prov, dict) else {}
    if not prov.get("upstream") or not prov.get("upstream_commit"):
        out.append(
            "not_reused_upstream: the carve-out covers reused third-party code "
            "only, and this record names no upstream and commit. Our own "
            "structural metrics run on AWS like everything else"
        )
    elif prov.get("upstream_commit") == "unknown":
        out.append("not_reused_upstream: upstream_commit is 'unknown', so the record is untraceable")

    # dirty_tree survives the exemption verbatim.
    if record.get("git_dirty", True):
        sha = record.get("git_sha", "<missing>")
        out.append(f"dirty_tree: tree was dirty at {sha}, so the SHA does not describe it")

    # And so does the Secure Module rule: the carve-out waives *where* a
    # number was measured, never *what built it*. A reused Python baseline
    # never sets the field, so this costs the carve-out nothing.
    out.extend(secure_module_refusals(record))

    det = record.get("determinism")
    det = det if isinstance(det, dict) else {}
    runs = det.get("runs", 0)
    if not isinstance(runs, int) or runs < 2 or det.get("identical") is not True:
        out.append(
            f"not_deterministic: the carve-out rests on the output being "
            f"host-independent, which is evidenced by running the container "
            f"twice and comparing bytes. Got runs={runs!r}, "
            f"identical={det.get('identical')!r}"
        )

    allowed = STRUCTURAL_METRICS | ROW_DESCRIPTOR_KEYS
    for key in sorted(_row_keys(record)):
        lowered = key.lower()
        bad = next((s for s in FORBIDDEN_SUBSTRINGS if s in lowered), None)
        if bad is not None:
            out.append(
                f"unwhitelisted_metric: {key!r} looks like a timing ({bad!r}); "
                f"the carve-out covers structural quantities only"
            )
        elif key not in allowed:
            out.append(
                f"unwhitelisted_metric: {key!r} is not in the structural "
                f"whitelist. Adding it is a decision, not a convenience"
            )

    return out


def secure_module_refusals(record: dict) -> list[str]:
    """The Secure Module rule, shared by both paths below.

    A record that names no ``secure_module`` makes no claim about one and is
    not refused for it: most experiments build nothing through a module.
    A record that names one must name the enclave. ``pqcl_exp::emit_custody``
    is the only writer that sets the field, and a source test there makes every
    harness that builds custody records write through it, so the absence of
    the field is not something a custody harness can achieve by forgetting.
    """
    if "secure_module" not in record:
        return []
    backend = record.get("secure_module")
    if backend != PUBLISHABLE_SECURE_MODULE:
        return [
            f"secure_module_not_enclave: records were built through the "
            f"{backend!r} Secure Module, not {PUBLISHABLE_SECURE_MODULE!r}: "
            f"paper numbers come from the enclave"
        ]
    return []


def refusals(record: dict) -> list[str]:
    """Every reason this record may not be published. Empty means publishable.

    Returns all reasons rather than the first, so a run is not fixed one
    complaint at a time.
    """
    # A record that claims the carve-out is judged *only* by the carve-out's
    # rules. Falling through to the standard ones as well would refuse it for
    # `not_aws` — the very thing the exception grants — and the operator would
    # then be tempted to "fix" that by lying about `environment`.
    if "aws_exempt" in record:
        return exempt_refusals(record)

    out: list[str] = []

    env = record.get("environment")
    if env != "aws":
        out.append(f"not_aws: environment is {env!r}, not 'aws'")

    if record.get("git_dirty", True):
        sha = record.get("git_sha", "<missing>")
        out.append(f"dirty_tree: tree was dirty at {sha}, so the SHA does not describe it")

    profile = record.get("profile")
    if profile != "release":
        out.append(f"debug_build: profile is {profile!r}, not 'release'")

    iters = record.get("iterations", 0)
    if not isinstance(iters, int) or iters < MIN_ITERATIONS:
        out.append(f"too_few_iterations: {iters}, need at least {MIN_ITERATIONS}")

    out.extend(secure_module_refusals(record))

    return out


try:
    import figspec
except ImportError:  # pragma: no cover - only when run from another directory
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import figspec


def load_records(root: Path) -> list[tuple[Path, dict]]:
    out = []
    for path in sorted(root.rglob("*.json")):
        try:
            out.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except json.JSONDecodeError as e:
            raise SystemExit(f"{path}: not valid JSON: {e}") from e
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results", nargs="?", type=Path, help="results/ directory")
    ap.add_argument("--out", type=Path, help="paper/generated/ directory")
    ap.add_argument(
        "--check",
        action="store_true",
        help="report which records are publishable and write nothing",
    )
    ap.add_argument("--selftest", action="store_true", help="run the built-in tests")
    ap.add_argument(
        "--target", choices=sorted(figures_targets()), default="ieee",
        help="paper class whose text and column widths the figures are drawn at",
    )
    ap.add_argument(
        "--paper", type=Path,
        help="emit only the figures this .tex places with \\genfig/\\genfigw, and "
        "refuse a placement whose width disagrees with the figure's",
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.results is None:
        ap.error("results directory is required unless --selftest is given")

    records = load_records(args.results)
    if not records:
        print(
            f"no results found under {args.results}. Nothing has been measured "
            f"yet, which is the expected state until M9.",
            file=sys.stderr,
        )
        return 0

    publishable, refused = [], []
    for path, rec in records:
        rs = refusals(rec)
        (refused if rs else publishable).append((path, rec, rs))
    publishable_records = [(p, r) for p, r, _ in publishable]

    for path, _, rs in refused:
        print(f"REFUSED {path}", file=sys.stderr)
        for r in rs:
            print(f"        {r}", file=sys.stderr)

    print(f"\n{len(publishable)} publishable, {len(refused)} refused", file=sys.stderr)

    if args.check:
        return 1 if refused else 0

    if not publishable:
        raise SystemExit(
            "refusing to emit: no record passed. Every published number must "
            "come from a clean-tree release build on AWS with >= "
            f"{MIN_ITERATIONS} iterations."
        )

    if args.out is None:
        ap.error("--out is required when not using --check")
    # ⛔ Render BEFORE creating the directory. Creating it first left an empty
    # `paper/generated/` behind on a refusal, which reads as "generation ran and
    # produced nothing" rather than "generation refused".
    rendered = figspec.render(publishable_records)
    placed = placements(args.paper) if args.paper else None
    args.out.mkdir(parents=True, exist_ok=True)
    # ⭐ Only the records that passed the gate reach the emitter. A refused
    # record is not "missing data to work around"; it is a number that may not
    # be printed, and `render` never sees it.
    out_file = args.out / "values.tex"
    out_file.write_text(rendered, encoding="utf-8")
    print(f"wrote {out_file}", file=sys.stderr)
    emit_figures(publishable_records, args.out, args.target, placed)
    return 0


def figures_targets() -> list:
    import figures

    return list(figures.TARGETS)


def placements(tex: Path) -> dict:
    """`{figure name: (wide?, width fraction)}` for every `\\genfig`/`\\genfigw`
    in `tex`, parsed from the file rather than listed by hand (rule 14), with
    the optional `[0.88]` fraction (default 1): the figure is drawn at that
    fraction so it prints 1:1. Comment lines are skipped, so a commented-out
    figure is not emitted."""
    import re

    live = "\n".join(ln.split("%", 1)[0] for ln in tex.read_text(encoding="utf-8").splitlines())
    found = {}
    for wide, frac, name in re.findall(r"\\genfig(w?)(?:\[([0-9.]+)\])?\{([^}]+)\}", live):
        here = (wide == "w", float(frac) if frac else 1.0)
        if name in found and found[name][0] != here[0]:
            raise SystemExit(f"{tex} places {name} both wide and narrow")
        if name in found and found[name] != here:
            raise SystemExit(f"{tex} places {name} at two widths")
        found[name] = here
    return found


def emit_figures(records: list, out: Path, target: str = "ieee", placed: dict | None = None) -> None:
    """§1q.3: one PDF per `\\genfig` name, from the same publishable records.

    A figure its record cannot build is a named gap, and any stale PDF of that
    name is **removed**: the paper then shows its placeholder rather than a
    figure drawn from older records than the numbers beside it.

    With `placed` (from `--paper`), only the figures that paper places are
    drawn; a PDF of any other figure in `out` is removed as not belonging to
    it. A placement of unknown name, or one whose width (`\\genfigw` = text
    width) disagrees with the figure's panel count, refuses: the figure would
    print scaled, which §1al exists to prevent.
    """
    import figures

    if placed is not None:
        unknown = sorted(set(placed) - set(figures.FIGURES))
        if unknown:
            raise SystemExit(f"the paper places figures no record builds: {', '.join(unknown)}")
    for name, (prefix, build) in figures.FIGURES.items():
        target_pdf = out / f"{name}.pdf"
        if placed is not None and name not in placed:
            if target_pdf.exists():
                target_pdf.unlink()
            continue
        override = figures.FIGURES_BY_TARGET.get(name, {}).get(target)
        if isinstance(override, tuple):
            prefix, build = override
        elif override is not None:
            build = override
        if build is None:
            # §1cm: a figure for another paper class only. Never drawn here,
            # and a stale copy is removed rather than left looking emitted.
            if placed is not None and name in placed:
                raise SystemExit(f"the paper places {name}, which --target {target} does not draw")
            if target_pdf.exists():
                target_pdf.unlink()
            continue
        rec = figspec._latest(records, prefix)
        try:
            if rec is None:
                raise KeyError(f"no publishable {prefix} record")
            fig = build(rec)
            wide, frac = placed[name] if placed is not None else (fig.wide, 1.0)
            if wide != fig.wide:
                raise SystemExit(
                    f"{name} is drawn {'wide' if fig.wide else 'in one column'} but the paper "
                    f"places it {'wide' if wide else 'in one column'}"
                )
            path = figures.render(fig, out, target, frac)
        except KeyError as e:
            if target_pdf.exists():
                target_pdf.unlink()
            print(f"figure {name}: NOT DRAWN ({e}); placeholder stays", file=sys.stderr)
            continue
        print(f"wrote {path}", file=sys.stderr)


def _unreachable() -> None:
    raise SystemExit(
        "no experiments have been implemented yet, so there is nothing to "
        "generate. The refusal rules above are live and tested; the emitters "
        "arrive with M9. This is deliberately an error rather than an empty "
        "file, so an absent table is never mistaken for a measured one."
    )


# --------------------------------------------------------------------- tests


def selftest() -> int:
    """Built-in tests. Kept in this file so the rules and their tests cannot
    drift apart, and so `python3 mkfigs.py --selftest` needs no test runner."""

    def good() -> dict:
        return {
            "git_sha": "0123456789abcdef",
            "git_dirty": False,
            "environment": "aws",
            "profile": "release",
            "iterations": 10,
        }

    failures = []

    def _raises(fn) -> bool:
        """True if `fn` refuses. Used where refusing IS the behaviour under test."""
        try:
            fn()
        except BaseException:  # noqa: BLE001 - SystemExit is the expected one
            return True
        return False

    def check(name: str, cond: bool) -> None:
        if cond:
            print(f"  ok   {name}")
        else:
            print(f"  FAIL {name}")
            failures.append(name)

    check("a clean aws release run is publishable", refusals(good()) == [])

    r = good() | {"environment": "local"}
    check("refuses a local run", any(x.startswith("not_aws") for x in refusals(r)))

    r = good() | {"git_dirty": True}
    check("refuses a dirty tree", any(x.startswith("dirty_tree") for x in refusals(r)))

    r = good() | {"profile": "debug"}
    check("refuses a debug build", any(x.startswith("debug_build") for x in refusals(r)))

    r = good() | {"iterations": 3}
    check(
        "refuses too few iterations",
        any(x.startswith("too_few_iterations") for x in refusals(r)),
    )

    r = good() | {"secure_module": "host-software"}
    check(
        "refuses records built through a non-enclave Secure Module",
        any(x.startswith("secure_module_not_enclave") for x in refusals(r)),
    )

    r = good() | {"secure_module": PUBLISHABLE_SECURE_MODULE}
    check("publishes records built through the enclave", refusals(r) == [])

    check(
        "a record naming no Secure Module makes no claim about one",
        "secure_module" not in good() and refusals(good()) == [],
    )

    r = good() | {"secure_module": None}
    check(
        "a record naming the field without a value is refused, not waved through",
        any(x.startswith("secure_module_not_enclave") for x in refusals(r)),
    )

    r = {
        "environment": "local",
        "git_dirty": True,
        "profile": "debug",
        "iterations": 1,
        "secure_module": "pkcs11-softhsm",
    }
    check("reports every reason at once", len(refusals(r)) == 5)

    # A record missing its provenance fields must be refused, not accepted by
    # default. This is the failure mode that would quietly publish an
    # unattributed number.
    check("refuses an empty record", len(refusals({})) == 4)

    # ⭐ Derived, not transcribed. The previous form compared REFUSAL_KINDS
    # with a literal of the same four names, which could never fail. This
    # compares the declared kinds with the kinds `refusals` actually *emits*
    # over a record that breaks every rule — and the Rust side reads this
    # file's REFUSAL_KINDS line and compares it with its own enum.
    emitted = {x.split(":", 1)[0] for x in refusals(r)}
    check(
        "the declared kinds are exactly the kinds refusals() emits",
        emitted == set(REFUSAL_KINDS),
    )

    # ------------------------------------------------------------------
    # The one AWS-only carve-out. Condition 3 of the standing rule: enforced
    # here, not remembered. Each test below is a way the exception could widen.
    # ------------------------------------------------------------------

    def exempt() -> dict:
        return {
            "aws_exempt": AWS_EXEMPT_MARKER,
            "git_sha": "0123456789abcdef",
            "git_dirty": False,
            "provenance": {
                "upstream": "github.com/CDSecLab/Doris",
                "upstream_commit": "61907c60910e159830009051c32fef077274c6e1",
            },
            "determinism": {"runs": 2, "identical": True},
            "rows": [
                {
                    "scheme": "OXT",
                    "dataset": "enron",
                    "tier": 0,
                    "pairs": 100,
                    "tset_bytes": 6659,
                    "xset_bytes": 128,
                    "index_bytes": 6787,
                    "search_rounds": 1,
                }
            ],
        }

    check("a conforming carve-out record is publishable", refusals(exempt()) == [])

    r = exempt() | {"environment": "local"}
    check(
        "the carve-out waives not_aws, which is the whole point",
        refusals(r) == [],
    )

    r = exempt() | {"aws_exempt": "because I said so"}
    check(
        "refuses a free-form exemption marker",
        any(x.startswith("bad_exemption") for x in refusals(r)),
    )

    r = exempt() | {"git_dirty": True}
    check(
        "the carve-out does NOT waive dirty_tree",
        any(x.startswith("dirty_tree") for x in refusals(r)),
    )

    r = exempt()
    del r["provenance"]
    check(
        "refuses an exemption claimed by code with no upstream",
        any(x.startswith("not_reused_upstream") for x in refusals(r)),
    )

    r = exempt()
    r["provenance"] = dict(r["provenance"], upstream_commit="unknown")
    check(
        "refuses an upstream commit of 'unknown'",
        any(x.startswith("not_reused_upstream") for x in refusals(r)),
    )

    r = exempt() | {"determinism": {"runs": 1, "identical": True}}
    check(
        "refuses a single run: determinism is the evidence, not the claim",
        any(x.startswith("not_deterministic") for x in refusals(r)),
    )

    r = exempt() | {"determinism": {"runs": 2, "identical": False}}
    check(
        "refuses two runs that disagreed",
        any(x.startswith("not_deterministic") for x in refusals(r)),
    )

    r = exempt()
    del r["determinism"]
    check(
        "refuses a record with no determinism evidence at all",
        any(x.startswith("not_deterministic") for x in refusals(r)),
    )

    # ⭐ The tests that matter most: a timing must not ride in under a
    # structural label. Each of these is the carve-out being abused.
    for field in ("search_latency_ms", "throughput_ops", "verify_gas", "elapsed_us"):
        r = exempt()
        r["rows"][0][field] = 1
        check(
            f"refuses {field!r} under the carve-out",
            any(x.startswith("unwhitelisted_metric") for x in refusals(r)),
        )

    r = exempt()
    r["rows"][0]["some_new_count"] = 5
    check(
        "refuses an unrecognised key rather than assuming it is structural",
        any(x.startswith("unwhitelisted_metric") for x in refusals(r)),
    )

    check(
        "no whitelisted metric name trips the forbidden-substring scan",
        not [
            m
            for m in STRUCTURAL_METRICS | ROW_DESCRIPTOR_KEYS
            if any(s in m.lower() for s in FORBIDDEN_SUBSTRINGS)
        ],
    )

    # An ordinary record must be unaffected by any of the above.
    check("the carve-out does not leak into ordinary records", refusals(good()) == [])
    r = good() | {"environment": "local"}
    check(
        "an ordinary local record is still refused",
        any(x.startswith("not_aws") for x in refusals(r)),
    )

    # --- the emitter ------------------------------------------------------
    #
    # ⭐ Exercised with synthetic records rather than real ones, because the
    # real ones are local and the gate rightly refuses them. These are fixtures,
    # not measurements: they check the SHAPE of the mapping, which is the half
    # that silently rots when a harness changes a field name.

    def exp1_record(**over):
        # The committed profile: depths 24/20/32/32, so 20 keywords + 112
        # prefixes = 132 per event with range on, and 20 + 4 = 24 for an
        # ordered plaintext index.
        m = {
            "events": 1000,
            "numeric_attributes": 4,
            "plaintext_total_ns": {"median_ns": 1_000_000},
            "plaintext_indexed_tokens": 20_000,
            "plaintext_ordered_total_ns": {"median_ns": 1_250_000},
            "plaintext_ordered_indexed_entries": 24_000,
            "plaintext_with_range_total_ns": {"median_ns": 11_000_000},
            "plaintext_with_range_indexed_tokens": 132_000,
            "index_growth": {"ratio_pct": 550, "depths": [24, 20, 32, 32],
                             "indexed_entries_per_event": 132},
            "query_class": {
                "plaintext_total_ns": "keyword",
                "plaintext_ordered_total_ns": "keyword+range",
                "plaintext_with_range_total_ns":
                    "keyword+range (prefix-expanded, diagnostic)",
                "pqc_total_ns": "keyword",
                "classical_total_ns": "keyword",
                "pqc_with_range_total_ns": "keyword+range",
            },
            "rows": [
                {"signing_batch_size": 1, "pqc_total_ns": {"median_ns": 2_000_000},
                 "indexed_tokens": 20_000,
                 "pqc_with_range_total_ns": {"median_ns": 12_500_000},
                 "with_range_indexed_tokens": 132_000},
                {"signing_batch_size": 64, "pqc_total_ns": {"median_ns": 1_100_000},
                 "indexed_tokens": 20_000,
                 "pqc_with_range_total_ns": {"median_ns": 11_000_000},
                 "with_range_indexed_tokens": 132_000},
            ],
        }
        m.update(over)
        return (Path("exp1.json"), {"experiment": "exp1-ingestion-throughput",
                                    "started_utc": "2026-01-01T00:00:00Z",
                                    "measurements": m})

    vals = {}
    for macro, (prefix, fn, _d) in figspec.SPEC.items():
        if prefix != "exp1":
            continue
        m = figspec._latest([exp1_record()], "exp1")
        try:
            vals[macro] = fn(m)
        except Exception as exc:  # noqa: BLE001
            vals[macro] = f"RAISED {exc}"

    check(
        "exp1 throughput is events per second, not per nanosecond",
        # 1000 events in 2 ms is 500 000 per second, printed with a thin space.
        vals["pqclExpOneThroughputBOne"].replace(chr(92) + ",", "") == "500000",
    )
    check(
        "exp1 ratio compares PQ against plaintext",
        # The macro retired with tab:exp1; the guarded function stays tested.
        figspec.exp1_ratio(figspec._latest([exp1_record()], "exp1"), 1).startswith("2.00"),
    )
    # ⛔ The third Exp. 1 drift: the plaintext baseline kept its range trees
    # (20 keyword tokens + 112 prefix tokens per event) after the rows divided
    # by it dropped theirs. Every ratio still looked plausible, which is why the
    # refusal has to be on the work done rather than on the ratio's size.
    drifted = figspec._latest(
        [exp1_record(plaintext_indexed_tokens=132_000)], "exp1"
    )
    check(
        "exp1 refuses a ratio between passes that indexed different work",
        _raises(lambda: figspec.exp1_ratio(drifted, 1))
        and _raises(lambda: figspec.exp1_plaintext(drifted)),
    )
    predates = figspec._latest([exp1_record()], "exp1")
    del predates["plaintext_indexed_tokens"]
    check(
        "exp1 refuses a record that predates per-pass token counts",
        _raises(lambda: figspec.exp1_ratio(predates, 1)),
    )
    classical = figspec._latest([exp1_record()], "exp1")
    classical["rows"][0] |= {"classical_total_ns": {"median_ns": 2_000_000},
                             "classical_indexed_tokens": 132_000}
    check(
        "exp1 refuses PQ/ECDSA when the ECDSA pass did different work",
        _raises(lambda: figspec.exp1_pq_over_classical(classical, 1))
        and _raises(lambda: figspec.exp1_classical_ratio(classical, 1)),
    )
    # --- §1g: the range row's denominator, and the class-aware guard --------
    good = figspec._latest([exp1_record()], "exp1")
    check(
        "exp1 range row divides by the ORDERED plaintext: 12.5 ms / 1.25 ms",
        figspec.exp1_with_range_ratio(good, 1).startswith("10.00"),
    )

    def with_range_over(m, den_field, den_count):
        row = m["rows"][0]
        return figspec._same_query(
            m, "selftest",
            ("pqc_with_range_total_ns", row["with_range_indexed_tokens"]),
            (den_field, den_count),
        )

    # ⛔ The pairing §1g ruled out: with-range over the prefix-expanding
    # plaintext, 132/132. Refused by class as recorded...
    check(
        "exp1 refuses with-range over the prefix-expanding plaintext (by class)",
        _raises(lambda: with_range_over(
            good, "plaintext_with_range_total_ns", 132_000)),
    )
    # ...and still refused if someone relabels the diagnostic as the range
    # class, because the derived denominator is keywords + one per attribute.
    relabelled = figspec._latest([exp1_record()], "exp1")
    relabelled["query_class"]["plaintext_with_range_total_ns"] = "keyword+range"
    check(
        "exp1 refuses 132/132 even when mislabelled, from derived counts",
        _raises(lambda: with_range_over(
            relabelled, "plaintext_with_range_total_ns", 132_000)),
    )
    check(
        "exp1 refuses a range pair whose numerator is not keywords + sum(depth+1)",
        _raises(lambda: figspec.exp1_with_range_ratio(
            figspec._latest([exp1_record(rows=[
                {"signing_batch_size": 1, "pqc_with_range_total_ns": {"median_ns": 1},
                 "with_range_indexed_tokens": 128_000}])], "exp1"), 1)),
    )
    check(
        "exp1 refuses a keyword row divided by a range-class baseline",
        _raises(lambda: figspec._same_query(
            good, "selftest", ("pqc_total_ns", 20_000),
            ("plaintext_ordered_total_ns", 24_000))),
    )
    unclassed = figspec._latest([exp1_record()], "exp1")
    del unclassed["query_class"]
    check(
        "exp1 refuses a record that declares no query_class",
        _raises(lambda: figspec.exp1_ratio(unclassed, 1)),
    )

    # --- M10 H1: the head-to-head pairs, guarded like the plaintext ones ------
    def h2h(**over):
        # 1000 events, depths 24/20/32/32: 20 000 keyword pairs, 112 000 nodes.
        rows = [
            {"scheme": "Plaintext", "query_class": "keyword+range-ordered",
             "total_ns": {"median_ns": 1_000_000}, "entries": 24_000},
            {"scheme": "ODXT", "query_class": "keyword",
             "total_ns": {"median_ns": 4_000_000}, "entries": 20_000},
            {"scheme": "Zuo22", "query_class": "range",
             "total_ns": {"median_ns": 30_000_000}, "entries": 112_000},
            {"scheme": "ODXT+Zuo22", "query_class": "keyword+range",
             "total_ns": {"median_ns": 34_000_000}, "entries": 132_000},
            {"scheme": "PQ-ChainLog", "query_class": "keyword",
             "total_ns": {"median_ns": 2_000_000}, "entries": 20_000},
            {"scheme": "PQ-ChainLog", "query_class": "range",
             "total_ns": {"median_ns": 10_000_000}, "entries": 112_000},
            {"scheme": "PQ-ChainLog", "query_class": "keyword+range",
             "total_ns": {"median_ns": 12_000_000}, "entries": 132_000},
        ]
        h = {"events": 1000, "keyword_pairs": 20_000, "numeric_attributes": 4,
             "range_depths": [24, 20, 32, 32], "rows": rows}
        h.update(over)
        return figspec._latest([exp1_record(head_to_head=h)], "exp1")

    check(
        "exp1 head-to-head: ours over ODXT, keyword class, 2 ms / 4 ms",
        figspec.exp1_h2h_time_ratio(h2h(), "ODXT", "keyword").startswith("0.50"),
    )
    check(
        "exp1 head-to-head: composed over the full class",
        figspec.exp1_h2h_time_ratio(h2h(), "ODXT+Zuo22", "keyword+range")
        .startswith("0.35"),
    )
    shallow = h2h(range_depths=[16, 16, 16, 16])
    check(
        "exp1 head-to-head refuses Zuo'22 at depths other than ours",
        _raises(lambda: figspec.exp1_h2h_time_ratio(shallow, "Zuo22", "range")),
    )
    short = h2h()
    next(r for r in short["head_to_head"]["rows"] if r["scheme"] == "Zuo22")["entries"] = 104_000
    check(
        "exp1 head-to-head refuses a baseline that indexed different work",
        _raises(lambda: figspec.exp1_h2h_time_ratio(short, "Zuo22", "range")),
    )
    check(
        "exp1 head-to-head refuses a class no row answers, and a stale record",
        _raises(lambda: figspec.exp1_h2h_time_ratio(h2h(), "ODXT", "range"))
        and _raises(lambda: figspec.exp1_h2h_throughput(good, "ODXT", "keyword")),
    )
    check(
        "exp1 head-to-head refuses range entries that do not derive from its event count",
        _raises(lambda: figspec.exp1_h2h_throughput(h2h(events=999), "Zuo22", "range")),
    )

    # --- M10 H2: exp6chain, both sides must have committed the same stream --
    # M13 A4: one LEChain run per stream, and each of our rows names its own.
    def lechain_run(capsules, events=100, secs=3):
        return {"stream_capsules": capsules, "events": events, "transitions": events,
                "gas_total": 80_000 * events,
                "sequential": {"events": 40, "commit_latency_ns": {"median_ns": 2_000_000_000}},
                "pipelined": {"events": events - 40,
                              "first_submit_to_last_commit_ns": secs * 1_000_000_000}}

    def ours_row(size, capsules=1000, records=100, ns=5_000_000_000):
        return {"epoch_size": size, "entries_per_epoch": [30, 20], "records": records,
                "records_per_epoch": [64, records - 64], "gas_total": 7_000 * records,
                "first_event_to_last_commit_ns": ns,
                "commit_latency_ns": {"median_ns": 4_000_000_000},
                "stream_params": {"capsules": capsules},
                "lechain_stream_capsules": capsules, "lechain_same_stream": True}

    def chain_rec(**over):
        m = {
            "lechain_runs": [lechain_run(1000), lechain_run(10_000)],
            "lechain_steady_state_capsules": 10_000,
            "ours": [ours_row(64)],
        }
        m.update(over)
        return m

    check(
        "exp6chain gas ratio: LEChain 80 000/event over ours 7 000/event",
        figspec.exp6c_gas_ratio(chain_rec(), 64).startswith("11.43"),
    )
    check(
        "exp6chain rates are derived: 60 events in 3 s, 100 events in 5 s",
        figspec.exp6c_events_per_s(chain_rec(), "LEChain", 64) == figspec.fmt_int(20)
        and figspec.exp6c_events_per_s(chain_rec(), "ours", 64) == figspec.fmt_int(20),
    )
    check(
        "exp6chain latency cells carry their unit",
        figspec.exp6c_commit_s(chain_rec(), "LEChain", 64).endswith("\\,s"),
    )
    short = chain_rec()
    short["ours"][0]["records_per_epoch"] = [64, 30]
    check(
        "exp6chain refuses when our epochs did not anchor the whole stream",
        _raises(lambda: figspec.exp6c_gas_ratio(short, 64)),
    )
    # §1as.3.2: LEChain runs 60 events in 3 s = 20/s; ours crosses it once.
    def run(size, recs_per_s):
        return dict(ours_row(size, records=recs_per_s, ns=1_000_000_000),
                    records_per_epoch=[recs_per_s])

    crossing = chain_rec(ours=[run(25, 5), run(50, 15), run(100, 40), run(250, 90)])
    check(
        "anchor crossover is the two measured sizes either side of the per-event rate",
        figspec.exp6c_cross(crossing, "ours", "low") == figspec.fmt_int(50)
        and figspec.exp6c_cross(crossing, "ours", "high") == figspec.fmt_int(100),
    )
    wobble = chain_rec(ours=[run(25, 5), run(50, 30), run(100, 10), run(250, 90)])
    check(
        "anchor crossover refuses a curve that crosses more than once, or never",
        _raises(lambda: figspec.exp6c_cross(wobble, "ours", "low"))
        and _raises(lambda: figspec.exp6c_cross(chain_rec(ours=[run(25, 30), run(50, 40)]), "ours", "low"))
        and _raises(lambda: figspec.exp6c_cross(crossing, "ours_single_worker", "low")),
    )
    # §1ck.2: B-DEMS commits 100 events in 2 s = 50/s, so its bracket differs from LEChain's.
    def bdems_run(capsules, events=100, secs=2):
        return {"stream_capsules": capsules, "events": events, "transactions": 150,
                "gas_total": 90_000 * events,
                "by_event": {"seal": {"events": events, "transactions": 150}},
                "pipelined": {"events": events, "first_submit_to_last_commit_ns": secs * 1_000_000_000}}

    vs_bdems = dict(crossing, bdems_runs=[bdems_run(1000), bdems_run(10_000)])
    check(
        "anchor §1ck.2: the B-DEMS crossing and floor ratio read B-DEMS's rate, not LEChain's; "
        "refused without a B-DEMS arm",
        figspec.exp6c_cross(vs_bdems, "ours", "low", "bdems") == figspec.fmt_int(100)
        and figspec.exp6c_cross(vs_bdems, "ours", "high", "bdems") == figspec.fmt_int(250)
        and figspec.exp6c_bdems_floor_ratio(vs_bdems).startswith("0.10")
        and _raises(lambda: figspec.exp6c_cross(crossing, "ours", "low", "bdems")),
    )
    partial = chain_rec()
    partial["lechain_runs"][0]["transitions"] = 90
    check(
        "exp6chain refuses when LEChain did not commit the whole stream",
        _raises(lambda: figspec.exp6c_gas_per_event(partial, "LEChain", 64))
        and _raises(lambda: figspec.exp6c_gas_ratio(chain_rec(), 256)),
    )
    # ⭐ M13 A4: each point divides by the LEChain run on its own stream.
    two = chain_rec(lechain_runs=[lechain_run(1000, secs=3), lechain_run(2500, secs=6),
                                  lechain_run(10_000, secs=12)],
                    ours=[ours_row(64), ours_row(2500, capsules=2500)])
    check(
        "exp6chain: each axis point's ratio divides by its own stream's LEChain run",
        figspec.exp6c_speed_ratio(two, 64).startswith("1.00")
        and figspec.exp6c_speed_ratio(two, 2500).startswith("2.00"),
    )
    old = chain_rec()
    del old["lechain_runs"]
    old["lechain"] = lechain_run(1000)
    check(
        "exp6chain refuses a record from before A4, and a row naming no LEChain stream",
        _raises(lambda: figspec.exp6c_speed_ratio(old, 64))
        and _raises(lambda: figspec.exp6c_speed_ratio(
            chain_rec(ours=[{k: v for k, v in ours_row(64).items() if k != "lechain_stream_capsules"}]), 64)),
    )
    ceil = chain_rec(lechain_ceiling_inputs={"gas_limit_margin_pct": 125, "block_gas_limit": 10_000_000,
                                              "observed_block_period_ms": 2000})
    check(
        "A19: the per-event ceiling is a projection from measured gas, limit and period",
        # 80 000 gas x 1.25 = 100 000 per tx -> 100 per block -> 50 per second
        figspec.exp6c_lechain_ceiling(ceil) == figspec.fmt_int(50)
        and _raises(lambda: figspec.exp6c_lechain_ceiling(chain_rec())),
    )
    check(
        "A19: each point's LEChain rate is its own stream's",
        figspec.exp6c_lechain_point_rate(two, 64) == figspec.fmt_int(20)
        and figspec.exp6c_lechain_point_rate(two, 2500) == figspec.fmt_int(10),
    )
    check(
        "exp6chain caption cells read the 10^4 steady state, and refuse a smoke's",
        figspec.exp6c_lechain_rate(chain_rec()) == figspec.fmt_int(20)
        and _raises(lambda: figspec.exp6c_lechain_rate(chain_rec(lechain_steady_state_capsules=1000))),
    )

    # --- §1l: the head-to-head's own stream, and the caption cells -----------
    check(
        "exp1 ceiling reads the head-to-head's plaintext row: 1000 events in 1 ms",
        figspec.exp1_plain_ceiling(h2h()).replace(chr(92) + ",", "") == "1000000"
        and figspec.exp1_ours_over_ceiling(h2h()).startswith("0.08"),
    )
    across = {"operating_y": 1000, "largest_y_measured": 4096, "rows": [
        {"y": 4096, "zuo22": {"total_ns": {"median_ns": 9_000_000}, "entries": 458_752},
         "ours_range": {"total_ns": {"median_ns": 3_000_000}, "entries": 458_752}},
        {"y": 65536, "skipped": True}]}
    ym = h2h()
    ym["range_ingest_across_y"] = across
    check(
        "exp1 caption: operating y is the head-to-head's stream, ratio at the largest y",
        figspec.ingest_y(ym, "operating") == figspec.fmt_int(1000)
        and figspec.ingest_y(ym, "largest") == figspec.fmt_int(4096)
        and figspec.ingest_range_ratio_at_largest(ym).startswith("3.00"),
    )
    uneven = h2h()
    uneven["range_ingest_across_y"] = dict(across, rows=[dict(across["rows"][0], zuo22={
        "total_ns": {"median_ns": 9_000_000}, "entries": 1})])
    check(
        "exp1 caption refuses a ratio over passes that indexed different work",
        _raises(lambda: figspec.ingest_range_ratio_at_largest(uneven)),
    )
    lost = chain_rec()
    lost["ours"][0]["records_per_epoch"] = [64, 30]
    check(
        "exp6chain refuses a run whose epochs did not anchor its whole stream",
        _raises(lambda: figspec.exp6c_speed_ratio(lost, 64))
        and figspec.exp6c_speed_ratio(chain_rec(), 64).startswith("1.00"),
    )

    # --- M10 H7: custody disclosure, same target, whole case to replay -------
    def custody_rec():
        def row(n, v):
            return {"disclosed_records": n, "disclosed_bytes": 1000 * n,
                    "verify_ns": {"median_ns": v}, "full_replay_ns": {"median_ns": 10 * v}}
        return {"cases": [
            {"records": 1030, "ours": row(9, 137_000), "flat_mmr": row(9, 133_000),
             "hash_chain_replay": row(1030, 7_700_000)},
            {"records": 96333, "ours": row(8, 146_000), "flat_mmr": row(8, 176_000),
             "hash_chain_replay": row(96333, 746_000_000)},
        ]}

    check(
        "custody picks the smallest case at or above the size asked for",
        figspec.custody_bytes(custody_rec(), "hash_chain_replay", 50_000)
        == figspec.fmt_int(96_333_000),
    )
    check(
        "custody verify cells carry their unit, us or ms by magnitude",
        figspec.custody_verify(custody_rec(), "ours", 1000).endswith("$\\mu$s")
        and figspec.custody_verify(custody_rec(), "hash_chain_replay", 50_000).endswith("ms"),
    )
    diff = custody_rec()
    diff["cases"][0]["flat_mmr"]["disclosed_records"] = 7
    part = custody_rec()
    part["cases"][1]["hash_chain_replay"]["disclosed_records"] = 50_000
    check(
        "custody refuses different target histories, a partial replay, a missing size",
        _raises(lambda: figspec.custody_bytes(diff, "ours", 1000))
        and _raises(lambda: figspec.custody_verify(part, "ours", 50_000))
        and _raises(lambda: figspec.custody_bytes(custody_rec(), "ours", 10**6)),
    )
    # §1cd: SAC's 2023+ arms. A record with them must disclose the same history
    # through each; the SAC figure draws them and refuses a record without them,
    # while draft8's figure keeps its own arms.
    sac = custody_rec()
    for c in sac["cases"]:
        n = c["ours"]["disclosed_records"]
        for arm in ("pq_abl", "glassdb"):
            c[arm] = {"disclosed_records": n, "disclosed_bytes": 1100 * n,
                      "verify_ns": {"median_ns": 150_000, "p25_ns": 140_000, "p75_ns": 160_000},
                      "full_replay_ns": {"median_ns": 1_500_000}}
        c["ours"]["verify_ns"].update(p25_ns=1, p75_ns=2)
    lied = custody_rec()
    for c in lied["cases"]:
        c["glassdb"] = dict(sac["cases"][0]["glassdb"], disclosed_records=3)
    import figures as figs_sac

    sac_fig = figs_sac.FIGURES_BY_TARGET["exp-custody"]["acm"]
    check(
        "custody: the SAC arms refuse a different history; the SAC figure draws ours, PQ-ABL, "
        "GlassDB and refuses a record without them",
        figspec.custody_bytes(sac, "pq_abl", 1000) == figspec.fmt_int(9900)
        and _raises(lambda: figspec.custody_bytes(lied, "ours", 1000))
        and [s.label.split()[0] for s in sac_fig(sac).panels[0].series] == ["ours", "PQ-ABL", "GlassDB"]
        and _raises(lambda: sac_fig(custody_rec())),
    )

    # --- SAC Exp. 4 (§1cf, §1ci): redaction against B-DEMS and PQ-ABL ---------
    def redaction_rec(trials=100, ks=(1, 10, 100, 1000), epoch_records=10_000, one_epoch=True,
                      arms=("ours", "bdems", "pqabl")):
        def lat(ms):
            return {"median_ns": ms * 1_000_000, "p25_ns": ms * 900_000, "p75_ns": ms * 1_100_000}

        def verify(ns):
            return {"verify_ns": {"median_ns": ns, "p25_ns": 1, "p75_ns": 2}}

        def t1(arm_gas):
            return {arm: [{"k": k, "gas_median": g * k if arm == "bdems" else g,
                           "latency_ns": lat(5000 + k)} for k in ks]
                    for arm, g in arm_gas if arm in arms}

        def case(records, top):
            c = {"records": records, "epoch_records": epoch_records,
                 "sealing_epochs": records // epoch_records + 1,
                 "fa": {"ours": {s: {"latency_ns": lat(6000)} for s in ("payload", "payload_index", "full")},
                        "bdems": {"latency_ns": lat(4000)}, "pqabl": {"latency_ns": lat(2000)}},
                 "fb": {"ours": verify(120_000), "bdems": verify(3_000), "pqabl": verify(25_000_000)},
                 "ours_invalidated": "none: a redaction never changes an anchored root",
                 "pqabl_invalidated": {"records_median": epoch_records - 42}}
            if top:
                c["t1"] = t1((("ours", 150_000), ("bdems", 120_000), ("pqabl", 110_000)))
                c["t2"] = {"trials": trials,
                           "ours": {"valid": trials, "no_record": 0, "insider": 0, "modified": 0, "replay": 0},
                           "bdems": {"valid": trials, "no_record": 0, "insider": trials, "modified": 0,
                                     "replay": 0},
                           "pqabl": {"valid": trials, "no_record": 0, "insider": trials, "modified": 0,
                                     "replay": 0}}
            return c

        def one(records):
            return {"records": records, "epoch_records": records, "sealing_epochs": 1,
                    "beyond_pqabl_evaluated_range": records > 50_000,
                    "fa": {"pqabl": {"latency_ns": lat(9000)}},
                    "t1": t1((("ours", 150_000), ("pqabl", 130_000))),
                    "ours_invalidated": "none: a redaction never changes an anchored root",
                    "pqabl_invalidated": {"records_median": records - 42}}

        m = {"cases": [case(1000, False), case(1_000_000, True)]}
        if one_epoch:
            m["one_epoch_cases"] = [one(1000), one(1_000_000)]
        return m

    red = redaction_rec()
    import figures as figs_red

    red_fig = figs_red.FIGURES_BY_TARGET["exp-redaction"]["acm"]
    check(
        "redaction: T1 gas and latency by arm and k, the matrix out of 100, the check at the "
        "largest case; a reduced sweep, a short matrix, a missing arm or another epoch size is refused",
        figspec.redact_gas(red, "bdems", 1000) == figspec.fmt_int(120_000_000)
        and figspec.redact_gas(red, "ours", 1000) == figspec.fmt_int(150_000)
        and figspec.redact_gas(red, "pqabl", 10) == figspec.fmt_int(110_000)
        and figspec.redact_matrix(red, "bdems", "insider") == "100"
        and figspec.redact_matrix(red, "pqabl", "insider") == "100"
        and figspec.redact_matrix(red, "ours", "insider") == "0"
        and figspec.redact_verify_us(red, "ours") == "120.00"
        and figspec.redact_case_size(red) == figspec.fmt_int(1_000_000)
        and _raises(lambda: figspec.redact_gas(redaction_rec(ks=(1, 3)), "ours", 1))
        and _raises(lambda: figspec.redact_matrix(redaction_rec(trials=3), "ours", "valid"))
        and _raises(lambda: figspec.redact_gas(redaction_rec(arms=("ours", "bdems")), "ours", 1))
        and _raises(lambda: figspec.redact_gas(redaction_rec(epoch_records=1000), "ours", 1)),
    )
    check(
        "redaction §1ci.6: the one-epoch PQ-ABL series and the invalidated proofs are cells; "
        "a record without the series is refused, not filled from the epoch layout",
        figspec.redact_one_epoch(red, "gas", 100) == figspec.fmt_int(130_000)
        and figspec.redact_invalidated(red, False) == figspec.fmt_int(9_958)
        and figspec.redact_invalidated(red, True) == figspec.fmt_int(999_958)
        and _raises(lambda: figspec.redact_one_epoch(redaction_rec(one_epoch=False), "gas", 1))
        and _raises(lambda: figspec.redact_invalidated(redaction_rec(one_epoch=False), True)),
    )
    no_ours = redaction_rec()
    for c in no_ours["one_epoch_cases"]:
        c["t1"].pop("ours")
    check(
        "redaction §1ck.2: ours' latency on the one-epoch layout is a cell, refused when ours "
        "did not run there",
        figspec.redact_one_epoch(red, "lat", 1, "ours") == figspec.fmt_ms(5_001_000_000)
        and _raises(lambda: figspec.redact_one_epoch(no_ours, "lat", 1, "ours")),
    )

    # §1ck.2: GlassDB's range over one record, refused unless above ours everywhere
    glass = copy.deepcopy(sac)
    for c in glass["cases"]:
        c["ours"]["redacted"] = {"disclosed_bytes": 50, "verify_ns": {"median_ns": 100_000}}
        c["glassdb"]["redacted"] = {"disclosed_bytes": 70_000, "verify_ns": {"median_ns": 300_000}}
    below = copy.deepcopy(glass)
    below["cases"][1]["glassdb"]["redacted"]["disclosed_bytes"] = 10
    check(
        "custody §1ck.2: GlassDB's range spans every case live and redacted; refused when one "
        "cell is not above ours, or a case has no redacted block",
        figspec.custody_glass_range(glass, "bytes", "min") == figspec.fmt_int(8800)
        and figspec.custody_glass_range(glass, "bytes", "max") == figspec.fmt_int(70_000)
        and figspec.custody_glass_range(glass, "verify", "min") == "150.00"
        and figspec.custody_glass_range(glass, "verify", "max") == "300.00"
        and _raises(lambda: figspec.custody_glass_range(below, "bytes", "max"))
        and _raises(lambda: figspec.custody_glass_range(sac, "bytes", "max")),
    )

    check(
        "custody §1ci.5: the epoch size is one cell, refused when cases disagree",
        figspec.case_epoch_records({"cases": [{"epoch_records": 10_000}] * 2}) == figspec.fmt_int(10_000)
        and _raises(lambda: figspec.case_epoch_records(
            {"cases": [{"epoch_records": 10_000}, {"epoch_records": 1_000}]})),
    )
    red_panels = red_fig[1](red).panels
    check(
        "redaction: SAC draws Exp. 4 from sac-redaction, five latency series plus the labelled "
        "one-epoch PQ-ABL series, three checks; draft8 keeps exp9redact's figure",
        red_fig[0] == "sac-redaction"
        and [len(p.series) for p in red_panels] == [6, 3]
        and any("beyond PQ-ABL" in n for n in red_panels[0].notes)
        and [len(p.series) for p in red_fig[1](redaction_rec(one_epoch=False)).panels] == [5, 3]
        and figs_red.FIGURES["exp-redaction"][0] == "exp9redact",
    )

    # --- §1cm: SAC's two bar figures, narrow, from the records already read ---
    rk = figs_red.FIGURES_BY_TARGET["exp-redaction-k"]["acm"](red)
    top_t1 = figspec._redact_largest(red)["t1"]
    check(
        "bars §1cm.1: exp-redaction-k is two panels in one column; each bar is the record's "
        "gas median or latency median with its IQR, per arm and k",
        not rk.wide and rk.narrow and len(rk.panels) == 2
        and [s.label for s in rk.panels[0].series] == ["ours", "B-DEMS", "PQ-ABL"]
        and rk.panels[0].series[1].y == [int(r["gas_median"]) for r in top_t1["bdems"]]
        and rk.panels[1].series[0].y == [r["latency_ns"]["median_ns"] / 1e9 for r in top_t1["ours"]]
        and rk.panels[1].series[0].lo == [r["latency_ns"]["p25_ns"] / 1e9 for r in top_t1["ours"]]
        and rk.panels[0].categories == ["1", "10", "$10^2$", "$10^3$"]
        and figs_red.FIGURES["exp-redaction-k"][1] is None,
    )

    def dist(v):
        return {"median_ns": v, "p25_ns": v - 1, "p75_ns": v + 1}

    bars_rec = copy.deepcopy(glass)
    for c in bars_rec["cases"]:
        for i, arm in enumerate(("ours", "pq_abl", "glassdb")):
            c[arm].update(verify_ns=dist(100_000 + i), full_replay_ns=dist(9_000_000_000 + i),
                          full_replay_parallel_ns=dist(800_000_000 + i))
            c[arm]["redacted"] = {"disclosed_bytes": 10 ** 6 if arm == "glassdb" else 50,
                                  "verify_ns": dist(140_000 + i)}
    cb = figs_red.FIGURES_BY_TARGET["exp-custody-bars"]["acm"](bars_rec)
    no_par = copy.deepcopy(bars_rec)
    del no_par["cases"][1]["pq_abl"]["full_replay_parallel_ns"]
    check(
        "bars §1cm.2: exp-custody-bars reads the largest case, live/redacted verify and "
        "one-core/all-core audit per arm; GlassDB alone hatched; refused without an all-core audit",
        not cb.wide and [p.categories for p in cb.panels] == [["ours", "PQ-ABL", "GlassDB"]] * 2
        and [s.label for p in cb.panels for s in p.series] == ["live", "redacted", "one core", "all cores"]
        and cb.panels[0].series[1].y == [(140_000 + i) / 1e3 for i in range(3)]
        and cb.panels[1].series[1].y == [(800_000_000 + i) / 1e9 for i in range(3)]
        and [bool(h) for h in cb.panels[0].series[0].hatches] == [False, False, True]
        and any("one draw" in e[0] for e in cb.legend)
        and _raises(lambda: figs_red.exp_custody_bars(no_par)),
    )
    import tempfile as _tf
    with _tf.TemporaryDirectory() as tmp:
        lay = {}
        for fig in (rk, cb):
            figs_red.render(fig, Path(tmp), "acm")
            lay[fig.name] = figs_red.LAYOUT[fig.name]
        long = figs_red.Figure("overflow", [figs_red.Panel("(b) " + "a very long panel title " * 3, "", "",
                                                           xscale="linear", yscale="linear",
                                                           categories=["x"])], narrow=True)
        long.panels[0].series.append(figs_red.Series("s", figs_red.OURS, ["x"], [1.0]))
        figs_red.render(long, Path(tmp), "acm")
        check(
            "bars §1cm: both drawn at acmart's column width with no text past the page and no "
            "legend inside a panel; the overflow check fires on a title that runs off the page",
            all(abs(v["width_in"] * 72.27 - 241.15) < 0.01 and not v["text_outside"]
                and not v["legend_inside"] for v in lay.values())
            and figs_red.LAYOUT["overflow"]["text_outside"],
        )
        emit_figures([], Path(tmp), "ieee", {})
        # §1cq overturned this test's first form, which refused `exp-redaction-k`
        # at `ieee`: draft9 places a one-panel version of it. A figure that is
        # really SAC-only must still be refused, and draft9's must not reach SAC.
        check(
            "bars §1cm, §1cq: ieee never draws the SAC-only exp-custody-bars and refuses a placement of "
            "it; acm refuses a placement of draft9's exp-anchor-all",
            not (Path(tmp) / "exp-custody-bars.pdf").exists()
            and _raises(lambda: emit_figures([], Path(tmp), "ieee", {"exp-custody-bars": (False, 1.0)}))
            and _raises(lambda: emit_figures([], Path(tmp), "acm", {"exp-anchor-all": (False, 1.0)})),
        )
        by_target = figs_red.FIGURES_BY_TARGET
        rk9 = by_target["exp-redaction-k"]["ieee"](red)
        check(
            "§1cq: draft9's exp-redaction-k is one column and one panel, time to erasure with no gas, "
            "and draws the same medians and IQRs as SAC's panel (b)",
            not rk9.wide and len(rk9.panels) == 1
            and rk9.panels[0].ylabel == "time to erasure (s)"
            and [s.y for s in rk9.panels[0].series] == [s.y for s in rk.panels[1].series]
            and [s.lo for s in rk9.panels[0].series] == [s.lo for s in rk.panels[1].series],
        )
        cu9 = by_target["exp-custody-all"]["ieee"](glass)
        cu_sac = by_target["exp-custody"]["acm"](glass)
        rc9 = by_target["exp-redaction-custody"]["ieee"](red)
        rc_sac = by_target["exp-redaction"]["acm"][1](red)
        check(
            "§1cq: draft9's custody and redaction figures are wide, named for draft9, at the full plot "
            "height, and carry exactly SAC's arms and values",
            cu9.name == "exp-custody-all" and rc9.name == "exp-redaction-custody"
            and cu9.wide and rc9.wide and cu9.plot_in is None and rc9.plot_in is None
            and [(s.label, s.y) for s in cu9.panels[0].series] == [(s.label, s.y) for s in cu_sac.panels[0].series]
            and [(s.label, s.y) for s in rc9.panels[0].series] == [(s.label, s.y) for s in rc_sac.panels[0].series],
        )

    # --- M14: the 2023+ arms, read from the record shapes the harnesses write ---
    def m14_dist(v):
        return {"median_ns": v, "p25_ns": v, "p75_ns": v}

    m14_arm = {"first_search_ns": m14_dist(9000), "repeat_search_ns": m14_dist(6000),
               "oracle_shortfall_bloom_false_positives": 2,
               "term_updates_per_query": [[3, 40, 7], [5, 90]]}
    m14_exp2 = {"rows": [
        {"documents": 1000, "conjunction_width": 2, "pi_xt": {"search_ns": m14_dist(1000)},
         "sdsse_cq": m14_arm, "sdsse_cq_s": m14_arm},
        {"documents": 250000, "conjunction_width": 2, "pi_xt": {"search_ns": m14_dist(3000)},
         "sdsse_cq": m14_arm, "sdsse_cq_s": m14_arm},
    ]}
    check(
        "M14 Exp. 2: above 1 favours us, first and repeat stay apart, the top tier is read from "
        "the record, a shortfall sums over cells, and only x-terms count towards the fetch",
        figspec.exp2_sdsse_ratio(m14_exp2, 1000, 2, "sdsse_cq", "first").startswith("9.00")
        and figspec.exp2_sdsse_ratio(m14_exp2, 1000, 2, "sdsse_cq", "repeat").startswith("6.00")
        and figspec.exp2_sdsse_ratio(m14_exp2, None, 2, "sdsse_cq", "first").startswith("3.00")
        and figspec.exp2_shortfall(m14_exp2, "sdsse_cq") == "4"
        and figspec.exp2_max_x_updates(m14_exp2, "sdsse_cq") == "90"
        and _raises(lambda: figspec.exp2_sdsse_ratio(m14_exp2, 7, 2, "sdsse_cq", "first")),
    )

    def m14_y(y, theirs, ours, entries=10, skip=False):
        skq = ({"skipped": True} if skip else
               {"range": {"total_ns": m14_dist(theirs), "entries": entries},
                "keyword_range": {"total_ns": m14_dist(theirs), "entries": entries},
                "range_index_bytes": y * 1_000_000})
        return {"y": y, "dsse_skq": skq, "ours_range": {"total_ns": m14_dist(ours), "entries": 10},
                "ours_keyword_range": {"total_ns": m14_dist(ours), "entries": 10},
                "index_bytes": {"ours_range": {"total": 2_000_000}}}

    m14_exp1 = {"range_ingest_across_y": {"rows": [m14_y(256, 50, 100), m14_y(1024, 200, 100),
                                                   m14_y(4096, 800, 100), m14_y(65536, 0, 0, skip=True)]}}
    check(
        "M14 Exp. 1: the crossover is the two measured y around it, the largest y skips a point "
        "over the memory budget, and a ratio over different work or several crossings refuses",
        figspec.skq_crossover(m14_exp1, "range", "low") == "256"
        and figspec.skq_crossover(m14_exp1, "range", "high") == "1\\,024"
        and figspec.skq_largest_y(m14_exp1) == "4\\,096"
        and figspec.skq_ratio_at_largest(m14_exp1, "range").startswith("8.00")
        and figspec.skq_index_mb_at_largest_y(m14_exp1, "skq") == "4\\,096.0"
        and figspec.fmt_dec1(60364.44) == "60\\,364.4" and figspec.fmt_dec1(653.3) == "653.3"
        and _raises(lambda: figspec.skq_ratio_at_largest(
            {"range_ingest_across_y": {"rows": [m14_y(4096, 800, 100, entries=11)]}}, "range"))
        and _raises(lambda: figspec.skq_crossover(
            {"range_ingest_across_y": {"rows": [m14_y(1, 50, 100), m14_y(2, 200, 100), m14_y(3, 50, 100)]}},
            "range", "low")),
    )
    def m14_n(n, width, cold, warm, ours):
        return {"records": n, "range_width_pct": width,
                "dsse_skq": {"cold_search_ns": cold, "warm_search_ns": m14_dist(warm)},
                "pi_range": {"search_ns": m14_dist(ours)}}

    m14_exp7 = {"median_configuration": {"records": 1024, "range_width_pct": 10, "depth": 10},
                "n_axis_rows": [m14_n(256, 10, 50, 40, 100), m14_n(1024, 10, 150, 80, 100),
                                m14_n(4096, 10, 900, 300, 100),
                                m14_n(256, 50, 500, 500, 100), m14_n(1024, 50, 50, 50, 100)]}
    m14_twice = {"median_configuration": m14_exp7["median_configuration"],
                 "n_axis_rows": [m14_n(256, 10, 50, 50, 100), m14_n(1024, 10, 150, 150, 100),
                                 m14_n(4096, 10, 50, 50, 100)]}
    check(
        "M14 Exp. 4: each DSSE_SKQ crossing is the two measured N around it, at the median "
        "width only, and a curve that crosses twice refuses",
        figspec.exp7_skq_crossover(m14_exp7, "cold", "low") == "256"
        and figspec.exp7_skq_crossover(m14_exp7, "cold", "high") == "1\\,024"
        and figspec.exp7_skq_crossover(m14_exp7, "warm", "low") == "1\\,024"
        and figspec.exp7_skq_crossover(m14_exp7, "warm", "high") == "4\\,096"
        and _raises(lambda: figspec.exp7_skq_crossover(m14_twice, "cold", "low")),
    )
    m14_leak = {"rows": [{"queries": 50, "associations": {
        "sdsse_cq": {"associations": 20, "reuse_trials": 4, "reuse_hits": 5},
        "sdsse_cq_s": {"associations": 20, "reuse_trials": 4, "reuse_hits": 0}}}]}
    m14_size = {"rows": [{"dataset": "enron", "pairs": 10**6, "doris_fu": {
        "tset_bytes": 41 * 10**6, "xset_bytes": 9 * 10**6, "xset_tags": 7},
        "sdsse_cq": {"tset_bytes": 5 * 10**8, "xset_bytes": 3 * 10**8}}]}
    check(
        "M14 Exps. 3 and 5: bytes per pair add both structures; each arm's reuse is read as measured",
        figspec.size_arm_bpp(m14_size, "doris_fu") == "50.0"
        and figspec.size_arm_bpp(m14_size, "sdsse_cq") == "800.0"
        and figspec.leak_sdsse(m14_leak, 50, "sdsse_cq", "reuse_hits") == "5"
        and figspec.leak_sdsse(m14_leak, 50, "sdsse_cq_s", "reuse_hits") == "0"
        and _raises(lambda: figspec.leak_sdsse(m14_leak, 10, "sdsse_cq", "reuse_hits")),
    )
    # --- M15 / c15: the second baselines, read from the shapes exp2/exp7/exp345 write ---
    def m15_row(docs, width, ours, dfu=None, pairs=1000):
        r = {"documents": docs, "conjunction_width": width, "pairs": pairs,
             "pi_xt": {"search_ns": m14_dist(ours)},
             "vcfb": {"first_search_ns": m14_dist(50 * ours), "repeat_search_ns": m14_dist(5 * ours)}}
        if dfu is not None:
            r["doris_fu"] = ({"search_ns": m14_dist(dfu), "stored_bytes": 10_000 * pairs,
                              "admission": {"stop_documents": 50000}} if dfu else
                             {"skipped": True, "reason": "stop size", "stop_documents": 50000})
        return r

    m15_exp2 = {"rows": [m15_row(1000, 2, 100, dfu=60), m15_row(50000, 2, 200, dfu=300, pairs=7000),
                         m15_row(250000, 2, 1000, dfu=0)]}
    check(
        "M15 Exp. 2: VCFB's first and repeat stay apart; the Doris follow-up is read at its own "
        "largest tier, a skipped tier is never read, and the stop size comes from the record",
        figspec.exp2_sdsse_ratio(m15_exp2, None, 2, "vcfb", "first").startswith("50.0")
        and figspec.exp2_sdsse_ratio(m15_exp2, None, 2, "vcfb", "repeat").startswith("5.00")
        and figspec.exp2_dfu_ratio(m15_exp2, 1000, 2).startswith("0.60")
        and figspec.exp2_dfu_ratio(m15_exp2, None, 2).startswith("1.50")
        and figspec.exp2_dfu_largest_documents(m15_exp2) == "50\\,000"
        and figspec.exp2_dfu_stop_documents(m15_exp2) == "50\\,000"
        and figspec.exp2_dfu_kb_per_pair(m15_exp2) == "10.0"
        and _raises(lambda: figspec.exp2_dfu_ratio(m15_exp2, 250000, 2)),
    )

    # §1db.8 fix A: pass 2's per-tier records merge into pass 1's rows, and refuse
    # another commit, instance type or query set, a missing row, or a mismatch.
    m15_q = {"2": [["a", "b"]]}

    def m15_main(sha="abc", typ="r7i.8xlarge"):
        rows = [{k: v for k, v in r.items() if k != "doris_fu"} for r in m15_exp2["rows"]]
        return {"experiment": "exp2-conjunctive-latency", "started_utc": "2026-11-10T00:00:00Z",
                "git_sha": sha, "instance_type": typ,
                "measurements": {"rows": rows, "workload": {"queries_by_width": m15_q}}}

    def m15_dfu(docs, cell, sha="abc", typ="r7i.8xlarge", q=None, mismatch=None, when="01"):
        return {"experiment": "m15-doris-fu-search", "started_utc": f"2026-11-10T01:{when}:00Z",
                "git_sha": sha, "instance_type": typ,
                "measurements": {"rows": [{"documents": docs, "conjunction_width": 2, "doris_fu": cell}],
                                 "oracle_mismatch": mismatch or [],
                                 "workload": {"queries_by_width": q or m15_q}}}

    def m15_recs(*extra):
        return [(Path("x"), r) for r in (m15_main(), *extra)]

    m15_ok = m15_recs(m15_dfu(1000, m15_exp2["rows"][0]["doris_fu"]),
                      m15_dfu(50000, m15_exp2["rows"][1]["doris_fu"], when="02"),
                      m15_dfu(250000, m15_exp2["rows"][2]["doris_fu"], when="03"))
    m15_merged = figspec._latest(m15_ok, figspec.EXP2_WITH_DORIS)
    check(
        "M15 §1db.8: pass 2's per-tier records merge into pass 1's rows; another commit, "
        "instance type or query set, a row pass 1 lacks, or an oracle mismatch refuses",
        figspec.exp2_dfu_ratio(m15_merged, None, 2).startswith("1.50")
        and figspec.exp2_dfu_largest_documents(m15_merged) == "50\\,000"
        and "doris_fu" not in figspec._latest(m15_ok, "exp2")["rows"][0]
        and all("doris_fu" not in r for r in figspec._latest(m15_recs(), figspec.EXP2_WITH_DORIS)["rows"])
        and _raises(lambda: figspec._latest(m15_recs(m15_dfu(1000, {}, sha="other")), figspec.EXP2_WITH_DORIS))
        and _raises(lambda: figspec._latest(m15_recs(m15_dfu(1000, {}, typ="m7i.8xlarge")),
                                            figspec.EXP2_WITH_DORIS))
        and _raises(lambda: figspec._latest(m15_recs(m15_dfu(1000, {}, q={"2": [["z"]]})),
                                            figspec.EXP2_WITH_DORIS))
        and _raises(lambda: figspec._latest(m15_recs(m15_dfu(7, {})), figspec.EXP2_WITH_DORIS))
        and _raises(lambda: figspec._latest(m15_recs(m15_dfu(1000, {}, mismatch=["q1"])),
                                            figspec.EXP2_WITH_DORIS)),
    )

    def m15_n(n, width, ours, md):
        return {"records": n, "range_width_pct": width, "pi_range": {"search_ns": m14_dist(ours)},
                "mdrsse": {"search_ns": m14_dist(md), "leaves_in_cover": 3}}

    m15_exp7 = {"median_configuration": {"records": 4096, "range_width_pct": 10, "depth": 10,
                                         "boolean_forms_measured_at": 4096},
                "n_axis_rows": [m15_n(4096, 1, 10, 50), m15_n(4096, 10, 100, 30), m15_n(4096, 50, 900, 90),
                                m15_n(256, 10, 1, 1)],
                "boolean_forms": [{"form": "w1 AND w2", "total_ns": m14_dist(1000)}],
                "boolean_forms_sdsse": [
                    {"arm": "sdsse_cq", "hits": 682, "want": 683,
                     "first_total_ns": m14_dist(9000), "repeat_total_ns": m14_dist(8000)},
                    {"arm": "sdsse_cq_s", "hits": 683, "want": 683,
                     "first_total_ns": m14_dist(27000), "repeat_total_ns": m14_dist(26000)}]}
    check(
        "M15 Exp. 4: MDRSSE is read at the median N per width (below 1 is our loss, reported); "
        "the SDSSE row emits hits beside want, so a Bloom loss shows",
        figspec.exp7_mdrsse_ratio(m15_exp7, None).startswith("0.30")
        and figspec.exp7_mdrsse_ratio(m15_exp7, 1).startswith("5.00")
        and figspec.exp7_mdrsse_ratio(m15_exp7, 50).startswith("0.10")
        and figspec.exp7_mdrsse_leaves(m15_exp7) == "3"
        and figspec.exp7_sdsse_conj_ratio(m15_exp7, "sdsse_cq", "first").startswith("9.00")
        and figspec.exp7_sdsse_conj_count(m15_exp7, "sdsse_cq", "hits") == "682"
        and figspec.exp7_sdsse_conj_count(m15_exp7, "sdsse_cq", "want") == "683"
        and _raises(lambda: figspec.exp7_sdsse_conj_ms(m15_exp7, "vcfb", "first")),
    )
    m15_leak = {"rows": [{"queries": 50, "hit_link_in_two_or_more_queries": 7, "associations": {
        "vcfb": {"associations": 30, "reuse_trials": 4, "reuse_hits": 6},
        "doris_fu": {"associations": 12, "inferred_by_elimination": 2,
                     "unattributable_links_distinct": 9, "unattributable_links_in_two_or_more_queries": 1}}}]}
    check(
        "M15 Exp. 5: the new arms are read under associations, the inferred count apart from Attr",
        figspec.leak_sdsse(m15_leak, 50, "vcfb", "reuse_hits") == "6"
        and figspec.leak_sdsse(m15_leak, 50, "doris_fu", "associations") == "12"
        and figspec.leak_sdsse(m15_leak, 50, "doris_fu", "inferred_by_elimination") == "2"
        and figspec.leak_row(m15_leak, 50, "hit_link_in_two_or_more_queries") == "7"
        and _raises(lambda: figspec.leak_row(m15_leak, 10, "hit_link_in_two_or_more_queries")),
    )
    m15_figs = __import__("figures")
    m15_arm = {"first_search_ns": m14_dist(9000), "repeat_search_ns": m14_dist(6000)}
    m15_conj = m15_figs.exp_conj({"rows": [
        {"documents": d, "conjunction_width": 2, "pi_xt": {"search_ns": m14_dist(1)},
         "pi_cd": {"search_ns": m14_dist(1)}, "sdsse_cq": m15_arm, "sdsse_cq_s": m15_arm,
         "vcfb": {"first_search_ns": m14_dist(50_000), "repeat_search_ns": m14_dist(5000)},
         **({"doris_fu": {"search_ns": m14_dist(700)}} if d <= 50_000 else
            {"doris_fu": {"skipped": True, "reason": "stop size"}})}
        for d in (1000, 50_000, 250_000)]})
    m15_series = {s.label: s for s in m15_conj.panels[0].series}
    check(
        "M15 figures (1db.8 ruling 2): exp-conj draws VCFB at its repeat search and the Doris "
        "follow-up only where measured, so its line stops at its last tier (no point is invented)",
        m15_series["VCFB (repeat)"].y == [5000 / 1e6] * 3
        and m15_series["Doris follow-up"].y == [700 / 1e6, 700 / 1e6, None]
        and m15_series["Doris follow-up"].measured_x == [1000, 50_000]
        and m15_figs.FIGURES["exp-conj"][0] == figspec.EXP2_WITH_DORIS,
    )
    m14_figs = __import__("figures")
    m14_conj = m14_figs.exp_conj({"rows": [
        {"documents": 1000, "conjunction_width": 2, "pi_xt": {"search_ns": m14_dist(1)},
         "pi_cd": {"search_ns": m14_dist(1)}, "sdsse_cq": m14_arm, "sdsse_cq_s": m14_arm}]})
    check(
        "M14 figures: a record with the new arms draws them, at the first search, and not ODXT",
        [s.label for s in m14_conj.panels[0].series] == ["Π_XT", "Π_CD", "SDSSE-CQ", "SDSSE-CQ-S"]
        and m14_conj.panels[0].series[2].y == [9000 / 1e6],
    )

    # --- M10 H8: tamper times carry their own unit, and "never" is a value ---
    check(
        "exp8 durations pick their unit across six orders of magnitude",
        figspec.fmt_duration(3_400_000) == "3.4\\,ms"
        and figspec.fmt_duration(42_000_000_000) == "42.0\\,s"
        and figspec.fmt_duration(7_200 * 10**9) == "2.0\\,h"
        and figspec.fmt_duration(3 * 86_400 * 10**9) == "3.0\\,d"
        and figspec.fmt_duration(None) == "never",
    )

    def tamper_rec(trials=20):
        return {
            "read_budget_bytes_per_s": 50_000_000,
            "payload_at_rest": {
                "trials": trials,
                "ours_sampled_sweep": {"detect_ns": {"median_ns": 41_000_000_000}},
                "full_rehash_same_budget": {"detect_ns": {"median_ns": 66_000_000_000}},
                "verify_on_access": {"detect_ns": None},
            },
        }

    check(
        "exp8 reads a sweep time, and verify-on-access as never",
        figspec.tamper_detect(tamper_rec(), "payload_at_rest", "ours_sampled_sweep") == "41.0\\,s"
        and figspec.tamper_detect(tamper_rec(), "payload_at_rest", "verify_on_access") == "never",
    )
    check(
        "exp8 refuses fewer than 20 trials, an unknown arm, and a record with no budget",
        _raises(lambda: figspec.tamper_detect(tamper_rec(3), "payload_at_rest", "ours_sampled_sweep"))
        and _raises(lambda: figspec.tamper_detect(tamper_rec(), "payload_at_rest", "flat_verify_on_access"))
        and _raises(lambda: figspec.tamper_detect(
            {k: v for k, v in tamper_rec().items() if k != "read_budget_bytes_per_s"},
            "payload_at_rest", "ours_sampled_sweep")),
    )

    # --- §1g: k is observed, and must equal the derived value -------------
    check("exp1 k reads the observed count: 132", figspec.exp1_k(good) == "132")
    diverged = figspec._latest([exp1_record()], "exp1")
    diverged["rows"] = [dict(r, with_range_indexed_tokens=131_000) for r in diverged["rows"]]
    check(
        "exp1 k refuses when observed and derived disagree",
        _raises(lambda: figspec.exp1_k(diverged)),
    )
    check(
        "a renamed field becomes a NAMED gap, never a zero",
        any(
            st == "FIELD MISSING"
            for _m, st, _d in figspec.coverage([exp1_record(rows=[])])
        ),
    )
    check(
        "exp1 cells do not read exp10's record",
        figspec._latest(
            [(Path("x"), {"experiment": "exp10-integrity-audit",
                          "started_utc": "2030-01-01T00:00:00Z",
                          "measurements": {"sentinel": True}})],
            "exp1",
        )
        is None,
    )
    check(
        "render refuses rather than emitting a partial macro file",
        _raises(lambda: figspec.render([])),
    )
    check(
        "every unsourced cell carries a reason a reader can act on",
        all(len(v) > 40 for v in figspec.UNSOURCED.values()),
    )
    # Campaign 08 (§1ca): a withdrawn cell is a named SPEC cell with a reason,
    # and the instance cells read the newest record, not every record kept.
    check(
        "every withdrawn cell is a SPEC cell with a reason a reader can act on",
        all(m in figspec.SPEC and len(v) > 40 for m, v in figspec.WITHDRAWN.items()),
    )

    def _inst(exp, when, typ):
        return {"experiment": exp, "started_utc": when, "instance_type": typ,
                "environment": "aws", "git_dirty": False, "profile": "release", "iterations": 10}

    _runs = [_inst("custody-disclosure", "2030-01-01T00:00:00Z", "r7i.8xlarge"),
             _inst("custody-disclosure", "2030-01-02T00:00:00Z", "m7i.8xlarge")]
    check("an instance cell names the newest record's instance, not a superseded one",
          figspec.setup_instance(_runs, "custody") == "m7i.8xlarge")
    _saved = dict(figspec.WITHDRAWN)
    try:
        figspec.WITHDRAWN.clear()
        figspec.WITHDRAWN["pqclNoSuchCell"] = "x" * 50
        # The message, not only the refusal: render([]) refuses anyway, for
        # every missing cell, so a bare _raises could not fail (rule 15).
        try:
            figspec.render([])
            _why = ""
        except SystemExit as exc:
            _why = str(exc)
        check("render refuses a withdrawn cell SPEC does not hold, by name",
              "WITHDRAWN" in _why and "pqclNoSuchCell" in _why)
    finally:
        figspec.WITHDRAWN.clear()
        figspec.WITHDRAWN.update(_saved)
    # Campaign 03's two formatting defects: a real ratio printed as zero, and an
    # exponent LaTeX sets literally.
    check("a small ratio keeps its magnitude", figspec.fmt_ratio(0.0143).startswith("0.014"))
    check("an ordinary ratio is unchanged", figspec.fmt_ratio(2.7).startswith("2.70"))
    # §1aa.3: large values group as thin-spaced integers.
    check("a large ratio is a grouped integer",
          figspec.fmt_ratio(19128.65) == "19" + figspec.BS + ",129" + figspec.BS + "times"
          and figspec.fmt_ratio(99.5).startswith("99.50"))
    check("a large microsecond value is a grouped integer",
          figspec.fmt_us(8_652_489_220) == "8" + figspec.BS + ",652" + figspec.BS + ",489"
          and figspec.fmt_us(84_460) == "84.46")
    check("a large millisecond value is a grouped integer",
          figspec.fmt_ms(2_793_866_000) == "2" + figspec.BS + ",794"
          and figspec.fmt_ms(53_005_000) == "53.005")
    # §1ag: the anchor ratio is per record, over full epochs only.
    run = {"epoch_size": 100, "records_per_epoch": [90, 70, 80, 5], "entries_per_epoch": [101, 100, 102, 7]}
    check("records per epoch counts full epochs only, partial one dropped",
          figspec._full_epoch_records(run) == 80)
    check("leaves per record is a range over the axis",
          figspec.exp6c_leaves_per_record({"ours": [
              {"entries_per_epoch": [26, 26], "records": 26},
              {"entries_per_epoch": [100], "records": 400}]}) == "0.25--2.00")
    check(
        "three figures from 1000 up is an integer, not an exponent",
        figspec.fmt_sig3(3477.3).replace(chr(92) + ",", "") == "3480",
    )
    # Rule 21: a crossover is the two measured points that bracket it, and a
    # curve that crosses twice (or never) is refused, not summarised.
    def across(pairs):
        return {"range_ingest_across_y": {"rows": [
            {"y": y, "zuo22": {"total_ns": {"median_ns": z}}, "ours_range": {"total_ns": {"median_ns": o}}}
            for y, z, o in pairs]}}
    once = across([(256, 40, 120), (4096, 1500, 1800), (16384, 16000, 7600)])
    check("the crossover bracket is two measured y",
          (figspec.range_crossover_bracket(once, "low"), figspec.range_crossover_bracket(once, "high"))
          == ("4" + chr(92) + ",096", "16" + chr(92) + ",384"))
    check("a curve that never crosses 1 has no bracket",
          _raises(lambda: figspec.range_crossover_bracket(across([(256, 40, 120), (4096, 100, 1800)]), "low")))
    check("a curve that crosses twice is refused, not summarised",
          _raises(lambda: figspec.range_crossover_bracket(
              across([(256, 40, 120), (4096, 2000, 1800), (16384, 1000, 7600)]), "low")))
    # ⭐ §1q.3 / rule 21: figures plot only what was observed.
    import figures as figmod
    fig_src = Path(figmod.__file__).read_text(encoding="utf-8")
    # A CALL, not a word: the module's docstring rightly says "no fitting or
    # interpolation", and a substring match flagged the rule itself.
    import re as _re
    fit_call = _re.compile(r"\b(polyfit|curve_fit|interp1d|interp|UnivariateSpline|"
                           r"make_interp_spline|CubicSpline|lowess|linregress|fit)\s*\(")
    check("the figure code calls no fitting or interpolation routine", not fit_call.search(fig_src))
    check("the fitting-call guard fires on a fitting call",
          bool(fit_call.search("y = np.polyfit(x, y, 1)")) and bool(fit_call.search("m.fit(x)")))
    ingest = {"range_ingest_across_y": {"rows": [
        {"y": y, "zuo22": {"total_ns": {"median_ns": z, "p25_ns": z, "p75_ns": z}},
         "odxt_zuo22": {"total_ns": {"median_ns": 2 * z, "p25_ns": 2 * z, "p75_ns": 2 * z}},
         "ours_range": {"total_ns": {"median_ns": o, "p25_ns": o, "p75_ns": o}},
         "ours_keyword_range": {"total_ns": {"median_ns": o, "p25_ns": o, "p75_ns": o}},
         "index_bytes": {"ours_range": {"total": 10 * y}, "zuo22": 20 * y}}
        for y, z, o in ((256, 40, 120), (1024, 200, 450), (4096, 1500, 1800))]
        + [{"y": 65536, "skipped": True, "reason": "memory"}]}}
    fig = figmod.exp_ingest_y(ingest)
    xs_measured = {256, 1024, 4096, 65536}
    plotted = {x for p in fig.panels for s in p.series for x, y in zip(s.x, s.y) if y is not None}
    check("every plotted x is a measured x in the record", plotted <= xs_measured)
    check("a skipped point is a gap, never a plotted value",
          all(y is None for p in fig.panels for s in p.series for x, y in zip(s.x, s.y) if x == 65536))
    check("a skipped point is named on the panel",
          any("65,536" in n for p in fig.panels for n in p.notes))
    # §1al: emitted at print size, readable. Rendered for real (to a temp dir).
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        figmod.render(fig, Path(tmp))
        lay = figmod.LAYOUT[fig.name]
        check("a multi-panel figure is emitted at the text width, 7.16 in",
              abs(lay["width_in"] - figmod.TEXT_WIDTH_IN) < 1e-6)
        check("every plotting area is at least 1.9 in tall", lay["min_plot_in"] >= figmod.MIN_PLOT_IN)
        check("at most five labelled major ticks per axis", lay["max_major_ticks"] <= 5)
        check("no legend sits inside a plotting area", not lay["legend_inside"])
        # §1as.3.1: the SAC paper's acmart widths, 506.30 pt and 241.15 pt.
        figmod.render(fig, Path(tmp), "acm")
        check("--target acm draws a multi-panel figure at acmart's text width, 506.30 pt",
              abs(figmod.LAYOUT[fig.name]["width_in"] * 72.27 - 506.30) < 0.01)
        tex = Path(tmp) / "p.tex"
        tex.write_text("\\genfig{exp-anchor}{a}\n% \\genfigw{exp-conj}{gone}\n\\genfigw{exp-custody}{b}\n",
                       encoding="utf-8")
        check("--paper reads each live placement and its width, skipping comments",
              placements(tex) == {"exp-anchor": (False, 1.0), "exp-custody": (True, 1.0)})
        tex.write_text("\\genfig[0.88]{exp-anchor}{a}\n\\genfigw[0.85]{exp-custody}{b}\n", encoding="utf-8")
        check("--paper reads the optional width fraction of a placement",
              placements(tex) == {"exp-anchor": (False, 0.88), "exp-custody": (True, 0.85)})
        tex.write_text("\\genfig[0.88]{exp-anchor}{a}\n\\genfig{exp-anchor}{b}\n", encoding="utf-8")
        check("--paper refuses a figure placed at two widths", _raises(lambda: placements(tex)))
        figmod.render(fig, Path(tmp), "acm", 0.85)
        check("a placement fraction draws the figure at that fraction of the width, so it prints 1:1",
              abs(figmod.LAYOUT[fig.name]["width_in"] * 72.27 - 0.85 * 506.30) < 0.01
              and _raises(lambda: figmod.render(fig, Path(tmp), "acm", 0.3)))
        tex.write_text("\\genfig{exp-custody}{a}\n\\genfigw{exp-custody}{b}\n", encoding="utf-8")
        check("--paper refuses a figure placed both wide and narrow", _raises(lambda: placements(tex)))
    check("log ticks are decades only when the span has two",
          figmod.log_ticks(0.3, 2000) == [1.0, 10.0, 100.0, 1000.0])
    check("log ticks thin to at most five",
          len(figmod.log_ticks(1, 1e9)) <= 5)
    check("one tick style per axis: powers of ten once an axis reaches 10^4",
          figmod.tick_labels([1e3, 1e4, 1e5]) == ["$10^{3}$", "$10^{4}$", "$10^{5}$"]
          and figmod.tick_labels([1.0, 10.0, 100.0]) == ["1", "10", "100"])
    runs = list(figmod._runs([1, 2, 3, 4], [5, None, 7, 8]))
    check("a gap splits a series into separate runs, never bridged", runs == [[(1, 5)], [(3, 7), (4, 8)]])
    leak = {"rows": [{"queries": q, "associations": {"odxt": {"associations": 10 * q}, "pi_xt": 0},
                      "hit_link_distinct_pairs": 3 * q} for q in (1, 10, 50)]}
    lf = figmod.exp_leak(leak)
    check("an all-zero series is stated in a note, not drawn on a log axis",
          any("= 0 at every" in n for n in lf.panels[0].notes)
          and all(s.label != "Π_XT attributable" for s in lf.panels[0].series))
    check(
        "three figures below 1000 is unchanged",
        [figspec.fmt_sig3(v) for v in (347.73, 34.773, 0.34773)] == ["348", "34.8", "0.348"],
    )


    # --- M13 A19: tamper mean/p95, the tail row, observed admissibility -------
    def tamper_rec(trials=20):
        det = {"median_ns": 2_000_000_000, "mean_ns": 3_000_000_000, "p95_ns": 9_000_000_000}
        return {
            "read_budget_bytes_per_s": 50_000_000,
            "payload_at_rest": {"trials": trials,
                                "ours_sampled_sweep": {"detect_ns": det, "admissible_observed": [
                                    {"object": "a", "chunks": 4, "verified": 3},
                                    {"object": "a", "chunks": 4, "verified": 3},
                                    {"object": "b", "chunks": 100, "verified": 99}]},
                                "full_rehash_same_budget": {"detect_ns": det}},
            "agent_epoch_omitted": {"trials": trials, "tail_omitted": {
                "trials": trials,
                "ours_heartbeat": {"detect_ns": {"median_ns": 7_000_000_000}, "heartbeat_period_ns": 5_000_000_000},
                "ours_epoch_la_id_contiguity": {"detected_trials": 0}}},
        }
    check(
        "A19: tamper mean and p95 read their own fields, with units",
        figspec.tamper_stat(tamper_rec(), "payload_at_rest", "ours_sampled_sweep", "mean") == figspec.fmt_duration(3_000_000_000)
        and figspec.tamper_stat(tamper_rec(), "payload_at_rest", "full_rehash_same_budget", "p95") == figspec.fmt_duration(9_000_000_000),
    )
    old_t = tamper_rec()
    del old_t["payload_at_rest"]["ours_sampled_sweep"]["detect_ns"]["p95_ns"]
    check(
        "A19: a record from before A11 has no p95, and says so",
        _raises(lambda: figspec.tamper_stat(old_t, "payload_at_rest", "ours_sampled_sweep", "p95")),
    )
    check(
        "A19: the tail row's detect, T and contiguity count",
        figspec.tamper_tail(tamper_rec(), "detect") == figspec.fmt_duration(7_000_000_000)
        and figspec.tamper_tail(tamper_rec(), "heartbeat") == figspec.fmt_duration(5_000_000_000)
        and figspec.tamper_tail(tamper_rec(), "contiguity") == "0"
        and _raises(lambda: figspec.tamper_tail(tamper_rec(trials=5), "detect")),
    )
    check(
        "A19: admissibility is per artefact and observed: 75% and 99%",
        figspec.tamper_admissible_range(tamper_rec()) == "75.00--99.00\\,\\%",
    )

    # §1v.3: the stale-record guard's own self-test, so CI reaches it (rule 13).
    import stale_guard
    check("stale_guard: must-flag and must-not-flag cases all hold", stale_guard.selftest() == 0)

    print(f"\n{'all self-tests passed' if not failures else str(len(failures)) + ' FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
