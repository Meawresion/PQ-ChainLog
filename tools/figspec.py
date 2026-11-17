r"""The map from measured records to the numbers `draft7.tex` prints (draft6 is
frozen since the design record).

⭐ **Written before the campaign, on purpose.** The alternative is to run the
experiments, come back with JSON, and only then discover which fields a table
actually needed — and a missing field means another paid instance. Every cell of
every performance table is named here, **including the ones nothing currently
measures**, so [`coverage`] can say what a campaign will and will not be able
to fill, and `render` can name every macro it refuses to emit.

⛔ This module computes and formats. It decides nothing about publishability:
`mkfigs.refusals` remains the only gate, and `render` is never reached for a
record that gate rejects.

# How a cell is named

One LaTeX macro per number, letters only (TeX forbids digits in a control word),
so the paper reads `\pqclExpOneThroughputBOne` where it used to read `\TODO{}`.
Three reasons for macros rather than generated table bodies: the caption and
label stay in the author's file, a missing number becomes a **loud** LaTeX error
instead of a silently empty cell, and every value keeps a name a reviewer can
trace back to the record that produced it.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

#: Cells no experiment currently produces. Each carries its reason, because
#: "no source" and "not measured yet" need different answers: the first is a
#: paper edit, the second is harness work.
UNSOURCED: dict[str, str] = {
    # ⭐ Emptied 2026-09-24 (§1d ruled). Kept as a named, empty table rather than
    # deleted, because the next gap wants somewhere obvious to go and a reader
    # should be able to see that "nothing is unsourced" was asserted rather than
    # merely absent.
    #
    # How the original six were closed:
    #   * ECDSA-P256 (2 cells)  -- built: exp1 `classical_total_ns`, bench-only
    #                              behind the default-off `classical-baseline`
    #                              feature, `p256` banned outside crates/pqcl-exp/
    #                              by `cargo xtask no-stubs`
    #   * B = 1024              -- built: added to exp1's BATCH_SIZES
    #   * Boolean forms (2)     -- built: exp7 `boolean_forms`, with
    #                              `client_eval_ns` beside the totals so a null
    #                              result is readable as a result
    #   * Trinity latency       -- ⛔ NOT built and never will be: no public code.
    #                              Resolved in the PAPER instead -- the row keeps
    #                              `Rounds = 1` (documented) and empties only the
    #                              two unmeasurable cells with a dagger. It is
    #                              therefore not a macro at all
}

#: Cells the records can no longer answer **as the paper words them**. Each is
#: emitted as a red marker carrying its reason, so the sentence around it shows
#: in the PDF as due a rewrite while every other cell refreshes. Every gap not
#: named here still refuses the whole file. ⛔ A withdrawn cell that yields a
#: value again is refused too: the withdrawal is lifted on purpose, never left
#: to mask a number.
WITHDRAWN: dict[str, str] = {
    **{"pqclAnchorCrossParallel" + side: (
        "no crossing: with parallel co-signers ours is at or above the per-event "
        "rate at every measured epoch size; see pqclAnchorParallelFloorEpoch and "
        "pqclAnchorParallelFloorRatio")
       for side in ("Low", "High")},
    "pqclSetupInstanceOther": (
        "the experiments ran on more than one instance type; name each with "
        "pqclSetupInstanceAnchor, Custody, Tamper or Rest"),
}

#: Cells draft9 stopped reading when Exps. 1-5 moved to the 2023+ comparators
#: (campaign 14 item 1): ODXT, Zuo'22, the
#: composed baseline, the OXT family's size rows and Exp. 9's ODXT arms. Their
#: records stay in `results/`. Removed from SPEC after it is built, and a name
#: SPEC does not hold is refused, so this list cannot quietly outlive its cells.
#: Checked against every tracked .tex (comments stripped) before retiring.
#: The 32nd, `pqclExpSevenIndexSkq` (withdrawn in §1cx.4 item 3), lost its SPEC
#: entry and its extractor outright, so it is not listed.
RETIRED: tuple = (
    "pqclExpSevenIndexRange", "pqclExpSevenIndexZuo",
    "pqclExpSevenZuoColdMs", "pqclExpSevenZuoWarmMs",
    "pqclExpTwoSpeedupLarge", "pqclExpTwoSpeedupSmall",
    "pqclIngestComposed", "pqclIngestCrossHighY", "pqclIngestCrossLowY",
    "pqclIngestLargestY", "pqclIngestOdxt", "pqclIngestOursOverComposed",
    "pqclIngestOursOverOdxt", "pqclIngestOursOverZuo", "pqclIngestRangeRatioAtLargestY",
    "pqclIngestZuo",
    "pqclLeakOdxtAttrFifty", "pqclLeakOdxtAttrOne", "pqclLeakOdxtAttrTen",
    "pqclRangeIndexMbOurs", "pqclRangeIndexMbZuo",
    "pqclRedactOdxtDelEraseMs", "pqclRedactOdxtDelResidual", "pqclRedactOdxtDelSearchMs",
    "pqclRedactOdxtRebuildEraseMs", "pqclRedactOdxtRebuildResidual",
    "pqclRedactOdxtRebuildSearchMs",
    "pqclSizeConjFilter", "pqclSizeHxt", "pqclSizeOdxt", "pqclSizeOxt",
)


BS = chr(92)  # written this way so no literal backslash travels through tooling


def _median_ns(summary: dict) -> int:
    return int(summary["median_ns"])


def _per_second(count: int, total_ns: int) -> float:
    if total_ns <= 0:
        raise ValueError("a duration of zero cannot produce a rate")
    return count * 1e9 / total_ns


def fmt_int(value: float) -> str:
    """Thousands-separated with a thin space, which is TeX-safe inside a table."""
    return f"{round(value):,}".replace(",", BS + ",")


def fmt_dec1(value: float) -> str:
    """One decimal, thousands thin-spaced like `fmt_int` (§1cy.2 item 3:
    `pqclRangeIndexMbSkq` printed `60364.4`)."""
    return f"{value:,.1f}".replace(",", BS + ",")


def fmt_ratio(value: float) -> str:
    """Two decimals, except below 0.095 where two significant figures.

    ⚠️ Campaign 03 emitted `pqclIngestOursOverCeiling` as `0.00\times` -- the
    true ratio was 0.0143, and fixed-point rounding printed a real measurement
    as zero. A small ratio keeps its magnitude; nothing else changes.
    """
    if 0 < abs(value) < 0.095:
        return f"{value:.2g}" + BS + "times"
    # §1aa.3: from 100 up, a thin-spaced integer: two decimals on a five-digit
    # ratio are noise, and ungrouped digits misread.
    if abs(value) >= 100:
        return fmt_int(value) + BS + "times"
    return f"{value:.2f}" + BS + "times"


def fmt_sig3(value: float) -> str:
    """Three significant figures, never in exponent form.

    `f"{v:.3g}"` prints 3480 as `3.48e+03`, which LaTeX sets literally.
    Campaign 03 emitted exactly that into `tab:exp-anchor`. From 1000 up the
    value is rounded to three figures and printed as a thin-spaced integer.
    """
    if abs(value) >= 1000:
        return fmt_int(float(f"{value:.3g}"))
    return f"{value:.3g}"


def fmt_us(ns: float) -> str:
    """Microseconds, two decimals; from 1000 up a thin-spaced integer
    (§1aa.3: replay's verify printed `8652489.22` in a µs column)."""
    us = ns / 1000.0
    return fmt_int(us) if abs(us) >= 1000 else f"{us:.2f}"


def fmt_ms(ns: float) -> str:
    """⚠️ `tab:exp7`'s column is **Latency (ms)**, not microseconds.

    The first version of these macros emitted microseconds into it, which would
    have printed every latency a thousand times too large — a wrong number that
    renders perfectly and reads as plausible. Caught by reading the column
    header rather than by anything failing.
    """
    ms = ns / 1_000_000.0
    # §1aa.3: from 1000 ms up, a thin-spaced integer (ODXT rebuild: 2 794).
    return fmt_int(ms) if abs(ms) >= 1000 else f"{ms:.3f}"


# --- extractors -------------------------------------------------------------
#
# Each takes the `measurements` object of one record and returns a formatted
# string, or raises if the field it needs is absent. ⭐ Raising is the point:
# `render` and [`coverage`] turn an absent field into a named gap, never a zero.


def _exp1_row(m: dict, batch: int) -> dict:
    for row in m["rows"]:
        if row["signing_batch_size"] == batch:
            return row
    raise KeyError(f"exp1 has no row for signing_batch_size={batch}")


def _same_query(m: dict, what: str, num: tuple, den: tuple) -> None:
    """Refuse a ratio unless both sides answer the same query class, with the
    entry counts that class allows. `num`/`den` are `(field, observed_count)`.

    ⛔ Exp. 1's comparisons drifted apart **three times**, each time because
    two call sites that had to agree were written separately — and the third
    time nothing moved by a factor, so no ratio looked wrong: the plaintext
    baseline kept its range trees after the rows divided by it dropped theirs.
    The counts are what each pass *observed*, so checking them checks the work.

    ⭐ Generalised per §1g rather than dropped. Equal counts is right for the
    **keyword** class and wrong for **keyword+range**: a plaintext system
    answers ranges with one ordered-map entry per attribute, while `Π_RANGE`
    pays `depth + 1` prefixes each — a cost encryption imposes, which the ratio
    must carry. So a range pair may differ **only** by that expansion, and both
    sides are checked against counts derived from the record, never a constant.
    """
    classes = m.get("query_class")
    if not isinstance(classes, dict):
        raise KeyError(
            f"exp1 {what}: the record declares no query_class; it predates the "
            "ordered-index denominator, and its range row divided by a baseline "
            "doing prefix expansion no plaintext system does"
        )
    (num_field, num_count), (den_field, den_count) = num, den
    for side, field, got in (("numerator", num_field, num_count),
                             ("denominator", den_field, den_count)):
        if got is None:
            raise KeyError(
                f"exp1 {what}: the {side} ({field}) carries no entry count; the "
                "run predates per-pass counts"
            )
    num_class, den_class = classes.get(num_field), classes.get(den_field)
    if num_class is None or num_class != den_class:
        raise ValueError(
            f"exp1 {what}: {num_field} answers {num_class!r} but {den_field} "
            f"answers {den_class!r} -- different query classes, so their ratio "
            "is not a cost"
        )

    if num_class == "keyword":
        if num_count != den_count:
            raise ValueError(
                f"exp1 {what}: numerator indexed {num_count} entries, denominator "
                f"{den_count} -- the two passes did different work, so their "
                "ratio is not a cost"
            )
    elif num_class == "keyword+range":
        # Derived: keyword entries observed by the keyword-only pass, plus the
        # per-event numeric cost of each side, from the record's own profile.
        events = int(m["events"])
        keywords = int(m["plaintext_indexed_tokens"])
        depths = [int(d) for d in m["index_growth"]["depths"]]
        n_attrs = int(m["numeric_attributes"])
        if len(depths) != n_attrs:
            raise ValueError(
                f"exp1 {what}: {len(depths)} range-tree depths for {n_attrs} "
                "numeric attributes; the profile does not describe the workload"
            )
        want_num = keywords + events * sum(d + 1 for d in depths)
        want_den = keywords + events * n_attrs
        if (num_count, den_count) != (want_num, want_den):
            raise ValueError(
                f"exp1 {what}: range class wants numerator {want_num} entries "
                f"(keywords + sum(depth+1) prefixes) and denominator {want_den} "
                f"(keywords + one ordered entry per attribute); observed "
                f"{num_count} and {den_count}"
            )
    else:
        raise ValueError(
            f"exp1 {what}: {num_class!r} is not a class any paper cell divides by"
        )


def exp1_throughput(m: dict, batch: int) -> str:
    row = _exp1_row(m, batch)
    return fmt_int(_per_second(m["events"], _median_ns(row["pqc_total_ns"])))


def exp1_plaintext(m: dict) -> str:
    """The Plain row sits above `+ range indexing`, so it must match the rows
    beside it: every swept row must have indexed what the plaintext pass did."""
    for row in m["rows"]:
        _same_query(
            m, f"plaintext vs B={row['signing_batch_size']}",
            ("pqc_total_ns", row.get("indexed_tokens")),
            ("plaintext_total_ns", m.get("plaintext_indexed_tokens")),
        )
    return fmt_int(_per_second(m["events"], _median_ns(m["plaintext_total_ns"])))


def exp1_ratio(m: dict, batch: int) -> str:
    row = _exp1_row(m, batch)
    _same_query(
        m, f"B={batch} over plaintext",
        ("pqc_total_ns", row.get("indexed_tokens")),
        ("plaintext_total_ns", m.get("plaintext_indexed_tokens")),
    )
    return fmt_ratio(
        _median_ns(row["pqc_total_ns"]) / _median_ns(m["plaintext_total_ns"])
    )


def exp1_with_range(m: dict, batch: int) -> str:
    """`tab:exp1`'s `+ range indexing` row: throughput with the expansion on.

    ⚠️ The rows above it are measured **without** range indexing, so this row is
    incremental as the `+` promises. That was not true until 2026-09-25: every
    row was measured with the expansion on, and the table said otherwise.
    """
    row = _exp1_row(m, batch)
    got = row.get("pqc_with_range_total_ns")
    if got is None:
        raise KeyError(
            "exp1 carries no pqc_with_range_total_ns; the run predates the "
            "without-range split and its `+ range indexing` row would repeat "
            "the row above it"
        )
    return fmt_int(_per_second(m["events"], _median_ns(got)))


def exp1_with_range_ratio(m: dict, batch: int) -> str:
    """`tab:exp1`'s `+ range indexing` **Overhead**: the with-range pipeline over
    a plaintext pipeline answering the same query class (§1g).

    ⛔ Not over the prefix-expanding plaintext pass. That pass does 132 inserts
    per event where a plaintext system does 24, so dividing by it cancels the
    very cost range indexing under encryption imposes. The guard refuses that
    pairing by query class and by derived entry counts.

    📌 Index growth (5.5x) used to sit in this cell. It is an entry ratio in a
    column of time ratios, and `tab:exp7`'s `Index (x)` column already owns it
    (`pqclExpSevenIndexRange`), so it left `tab:exp1` entirely.
    """
    row = _exp1_row(m, batch)
    _same_query(
        m, f"B={batch} with range over ordered plaintext",
        ("pqc_with_range_total_ns", row.get("with_range_indexed_tokens")),
        ("plaintext_ordered_total_ns", m.get("plaintext_ordered_indexed_entries")),
    )
    return fmt_ratio(
        _median_ns(row["pqc_with_range_total_ns"])
        / _median_ns(m["plaintext_ordered_total_ns"])
    )


def exp1_k(m: dict) -> str:
    """`k`, indexed tokens per event with range indexing on —
    `tab:accesscontrol`'s projection input (§1g, option (a)).

    ⭐ Sourced from the **observed** count, and refused unless it agrees with
    the value derived from the tree profile. If they diverge — an event with
    fewer keywords, a retuned depth — that is a finding, and printing either one
    would hide it.
    """
    observed = {row["with_range_indexed_tokens"] for row in m["rows"]}
    if len(observed) != 1:
        raise ValueError(f"exp1 k: with-range passes disagree on tokens: {sorted(observed)}")
    total = observed.pop()
    events = int(m["events"])
    if total % events:
        raise ValueError(
            f"exp1 k: {total} tokens over {events} events is not a whole number "
            "per event, so events differ and no single k describes them"
        )
    k = total // events
    derived = int(m["index_growth"]["indexed_entries_per_event"])
    if k != derived:
        raise ValueError(
            f"exp1 k: observed {k} tokens per event, derived {derived} from the "
            "tree profile -- they must agree before either is printed"
        )
    return str(k)


def _exp1_classical(m: dict, batch: int) -> int:
    row = _exp1_row(m, batch)
    got = row.get("classical_total_ns")
    if got is None:
        raise KeyError(
            "exp1 carries no classical_total_ns; the run was built without "
            "--features classical-baseline, so the ECDSA comparison point is "
            "missing and the PQC-overhead claim cannot be stated"
        )
    return _median_ns(got)


def exp1_classical(m: dict, batch: int) -> str:
    return fmt_int(_per_second(m["events"], _exp1_classical(m, batch)))


def exp1_classical_ratio(m: dict, batch: int) -> str:
    row = _exp1_row(m, batch)
    _same_query(
        m, f"ECDSA B={batch} over plaintext",
        ("classical_total_ns", row.get("classical_indexed_tokens")),
        ("plaintext_total_ns", m.get("plaintext_indexed_tokens")),
    )
    return fmt_ratio(_exp1_classical(m, batch) / _median_ns(m["plaintext_total_ns"]))


def exp1_pq_over_classical(m: dict, batch: int) -> str:
    """⭐ The number that can falsify the paper's systems argument.

    Against the plaintext pipeline alone we can only say what *signatures* cost.
    This says what **post-quantum** signatures cost against classical ones. If it
    lands near 1, the cost is signing rather than post-quantum signing, and the
    argument that PQC ingestion forces a symmetric-only data path needs
    rewriting rather than supporting.
    """
    row = _exp1_row(m, batch)
    denominator = _exp1_classical(m, batch)
    _same_query(
        m, f"ML-DSA over ECDSA at B={batch}",
        ("pqc_total_ns", row.get("indexed_tokens")),
        ("classical_total_ns", row.get("classical_indexed_tokens")),
    )
    return fmt_ratio(_median_ns(row["pqc_total_ns"]) / denominator)


H2H_CLASSES = ("keyword", "range", "keyword+range")


def _h2h_row(m: dict, scheme: str, qclass: str) -> dict:
    """One row of exp1's `head_to_head`, with its entry count checked.

    ⭐ The same guard as `_same_query`, applied to the head-to-head pairs, and
    exact rather than class-relative: ODXT's pairs equal our keyword tokens,
    and Zuo'22 updates `depth + 1` nodes per value, which equals our prefix
    keywords **only if both trees have the same depths** -- so the depths are
    checked too. Every row must carry the entries its class derives to, from
    **the head-to-head stream's own** keyword count and profile (§1l.3: it runs
    at the operating collection, not over exp1's 2 000-event B sweep).
    """
    h = m.get("head_to_head")
    if not isinstance(h, dict):
        raise KeyError("exp1 carries no head_to_head; the run predates M10 H1")
    if "keyword_pairs" not in h:
        raise KeyError("exp1 head_to_head predates §1l.3 (no keyword_pairs of its own stream)")
    classes = H2H_CLASSES + ("keyword+range-ordered",)
    if qclass not in classes:
        raise ValueError(f"exp1 head-to-head: {qclass!r} is not a head-to-head class")
    events = int(h["events"])
    depths = [int(d) for d in m["index_growth"]["depths"]]
    if [int(d) for d in h["range_depths"]] != depths:
        raise ValueError(
            f"exp1 head-to-head: Zuo'22 at depths {h['range_depths']}, ours at "
            f"{depths} -- the brief requires the same tree depths"
        )
    keywords = int(h["keyword_pairs"])
    ranges = events * sum(d + 1 for d in depths)
    want = {
        "keyword": keywords,
        "range": ranges,
        "keyword+range": keywords + ranges,
        # A plaintext system answers ranges with one ordered entry per attribute.
        "keyword+range-ordered": keywords + events * int(h["numeric_attributes"]),
    }[qclass]
    rows = [r for r in h["rows"] if r["scheme"] == scheme and r["query_class"] == qclass]
    if len(rows) != 1:
        raise KeyError(f"exp1 head-to-head has {len(rows)} rows for {scheme} / {qclass}")
    row = rows[0]
    if int(row["entries"]) != want:
        raise ValueError(
            f"exp1 head-to-head: {scheme} / {qclass} indexed {row['entries']} "
            f"entries, the class derives {want} -- the passes did different work"
        )
    return row


def exp1_h2h_throughput(m: dict, scheme: str, qclass: str) -> str:
    """Events per second for one head-to-head row, single-threaded."""
    row = _h2h_row(m, scheme, qclass)
    return fmt_int(_per_second(int(m["head_to_head"]["events"]), _median_ns(row["total_ns"])))


def exp1_h2h_time_ratio(m: dict, scheme: str, qclass: str) -> str:
    """Ours over `scheme`, same class, same stream: **below 1 means we ingest
    faster.** The direction is fixed so a cell can never silently invert."""
    ours = _h2h_row(m, "PQ-ChainLog", qclass)
    theirs = _h2h_row(m, scheme, qclass)
    return fmt_ratio(_median_ns(ours["total_ns"]) / _median_ns(theirs["total_ns"]))


#: LEChain's steady-state stream, in capsules (M13 A4). The caption cells
#: and every axis point above it divide by this run, so a record whose steady
#: run is any other size (a local smoke) cannot reach the paper.
LECHAIN_STEADY_CAPSULES = 10_000


def _lechain_run(m: dict, capsules: int) -> dict:
    """`exp6chain`: LEChain's run on the `capsules`-capsule stream, checked
    complete: its transitions are its own stream's events and its two phases
    cover them.

    ⛔ A record from before M13 A4 is refused. It ran LEChain once, on a stream
    no axis point ran, and divided every point by it."""
    if "lechain_runs" not in m:
        raise KeyError("exp6chain record predates M13 A4: LEChain ran on a different stream from ours")
    runs = [r for r in m["lechain_runs"] if int(r["stream_capsules"]) == capsules]
    if len(runs) != 1:
        raise KeyError(f"exp6chain has {len(runs)} LEChain runs on {capsules} capsules")
    run = runs[0]
    events = int(run["events"])
    if int(run["transitions"]) != events:
        raise ValueError(
            f"exp6chain: LEChain committed {run['transitions']} transitions "
            f"for a {events}-event stream"
        )
    if int(run["sequential"]["events"]) + int(run["pipelined"]["events"]) != events:
        raise ValueError("exp6chain: LEChain's two phases do not cover the stream")
    return run


def _lechain_steady(m: dict) -> dict:
    """LEChain's steady-state run, which must be the 10⁴-capsule stream."""
    steady = int(m.get("lechain_steady_state_capsules", -1))
    if steady != LECHAIN_STEADY_CAPSULES:
        raise ValueError(
            f"exp6chain: LEChain's steady state ran on {steady} capsules, "
            f"not {LECHAIN_STEADY_CAPSULES}: a smoke run, not a paper record"
        )
    return _lechain_run(m, steady)


def _custody_commit(m: dict, epoch: int) -> tuple:
    """`exp6chain`: our run at one axis point and the LEChain run its ratio
    divides by, after checking both are complete.

    ⛔ Every per-record figure divides by a count, so the counts are what to
    check: LEChain's must be its own stream's events (`_lechain_run`), and our
    epochs must have anchored every record of the run's own stream (§1l.2
    gives each axis point its own). Since M13 A4 the LEChain run is the one
    the row names: its own stream up to 10⁴ capsules, the steady state above.

    Returns `(LEChain's events, LEChain's run, our run)`.
    """
    rows = [o for o in m["ours"] if int(o["epoch_size"]) == epoch]
    if len(rows) != 1:
        raise KeyError(f"exp6chain has {len(rows)} runs at epoch size {epoch}")
    ours = rows[0]
    if "lechain_stream_capsules" not in ours:
        raise KeyError("exp6chain run predates M13 A4: it names no LEChain stream")
    capsules = int(ours["lechain_stream_capsules"])
    lechain = _lechain_run(m, capsules)
    if capsules != int(ours["stream_params"]["capsules"]) and capsules != LECHAIN_STEADY_CAPSULES:
        raise ValueError(
            f"exp6chain: the point at {epoch} divides by a {capsules}-capsule LEChain run, "
            "which is neither its own stream nor the steady state"
        )
    held = int(ours["records"])
    anchored = sum(int(n) for n in ours.get("records_per_epoch", ours["entries_per_epoch"]))
    if anchored != held:
        raise ValueError(
            f"exp6chain: our epochs anchored {anchored} records of a {held}-record stream"
        )
    return int(lechain["events"]), lechain, ours


def exp6c_gas_per_event(m: dict, side: str, epoch: int) -> str:
    """Gas per custody event: LEChain's mean transition, or our anchors over
    the entries they commit."""
    events, lechain, ours = _custody_commit(m, epoch)
    if side == "LEChain":
        return fmt_int(int(lechain["gas_total"]) / events)
    return fmt_int(int(ours["gas_total"]) / int(ours["records"]))


def exp6c_gas_ratio(m: dict, epoch: int) -> str:
    """LEChain's gas per event over ours: **above 1 means we spend less.**

    Per record on both sides, so the ratio holds whether or not the two
    streams are the same size (M13 A4)."""
    events, lechain, ours = _custody_commit(m, epoch)
    return fmt_ratio((int(lechain["gas_total"]) / events) / (int(ours["gas_total"]) / int(ours["records"])))


def exp6c_events_per_s(m: dict, side: str, epoch: int) -> str:
    """Committed custody records per second. LEChain: its pipelined phase over
    first submission to last commit. Ours: the run's whole stream over first
    event to last anchor commit. The rate is derived here, never recorded."""
    _, lechain, ours = _custody_commit(m, epoch)
    if side == "LEChain":
        p = lechain["pipelined"]
        return fmt_int(_per_second(int(p["events"]), int(p["first_submit_to_last_commit_ns"])))
    return fmt_int(_per_second(int(ours["records"]), int(ours["first_event_to_last_commit_ns"])))


def exp6c_commit_s(m: dict, side: str, epoch: int) -> str:
    """Median event-to-commit time, in seconds with its unit — LEChain's from
    its own sequential method (§7.3)."""
    _, lechain, ours = _custody_commit(m, epoch)
    s = lechain["sequential"] if side == "LEChain" else ours
    return f"{_median_ns(s['commit_latency_ns']) / 1e9:.2f}\\,s"


CUSTODY_SCHEMES = ("ours", "flat_mmr", "hash_chain_replay")
#: Macro stem and record key of every arm with custody cells. Flat and Replay
#: are draft8's Exp. 7; Pqabl and Glass are SAC Exp. 2's 2023+ arms (§1cd).
CUSTODY_CELL_ARMS = (("Ours", "ours"), ("Flat", "flat_mmr"), ("Replay", "hash_chain_replay"),
                     ("Pqabl", "pq_abl"), ("Glass", "glassdb"))


def _custody_case(m: dict, records_at_least: int) -> dict:
    """The `custody-disclosure` case whose realised size is the smallest at or
    above `records_at_least` (M10 H7), after checking all three schemes
    disclosed from the same records.

    ⛔ Ours and the flat MMR must disclose the **same** target history, and
    replay must have been handed the **whole** case: otherwise the rows measure
    different requests.
    """
    cases = sorted(
        (c for c in m["cases"] if int(c["records"]) >= records_at_least),
        key=lambda c: int(c["records"]),
    )
    if not cases:
        raise KeyError(f"custody-disclosure has no case of >= {records_at_least} records")
    c = cases[0]
    if int(c["ours"]["disclosed_records"]) != int(c["flat_mmr"]["disclosed_records"]):
        raise ValueError(
            "custody-disclosure: ours and the flat MMR disclosed different histories "
            f"({c['ours']['disclosed_records']} vs {c['flat_mmr']['disclosed_records']} records)"
        )
    # §1v.4: since redaction, replay's chain carries the sweep order as one
    # entry beside the records, so the whole case is records + 1 when the case
    # records an order. Anything else is still refused.
    whole = int(c["records"]) + (1 if "order" in c else 0)
    if int(c["hash_chain_replay"]["disclosed_records"]) != whole:
        raise ValueError("custody-disclosure: replay was not handed the whole case")
    # §1cd: SAC's 2023+ arms disclose the same history too, when the record has them.
    for arm in ("pq_abl", "glassdb"):
        if arm in c and int(c[arm]["disclosed_records"]) != int(c["ours"]["disclosed_records"]):
            raise ValueError(
                f"custody-disclosure: ours and {arm} disclosed different histories "
                f"({c['ours']['disclosed_records']} vs {c[arm]['disclosed_records']} records)"
            )
    return c


def custody_bytes(m: dict, scheme: str, records: int) -> str:
    c = _custody_case(m, records)
    return fmt_int(int(c[scheme]["disclosed_bytes"]))


def custody_verify(m: dict, scheme: str, records: int, full: bool = False) -> str:
    """Median verification time with its unit — it spans µs to seconds."""
    c = _custody_case(m, records)
    ns = _median_ns(c[scheme]["full_replay_ns" if full else "verify_ns"])
    return fmt_us(ns) + "\\,$\\mu$s" if ns < 1_000_000 else fmt_ms(ns) + "\\,ms"


def fmt_duration(ns) -> str:
    """A time with **its own unit** (M10 H8): detection latency spans six
    orders of magnitude, so a column with one unit would print `0.00` or
    `86400000` somewhere. `None` is an alert that never came — "never", not a
    large number standing in for infinity."""
    if ns is None:
        return "never"
    s = ns / 1e9
    for limit, div, unit in ((1.0, 1e-3, "ms"), (3600.0, 1.0, "s"), (86400.0, 3600.0, "h")):
        if s < limit:
            return f"{s / div:.1f}\\,{unit}"
    return f"{s / 86400.0:.1f}\\,d"


TAMPER_CLASSES = {
    "payload_at_rest": ("ours_sampled_sweep", "full_rehash_same_budget", "verify_on_access"),
    "payload_then_read": ("ours_q2_chunk_on_read", "flat_verify_on_access"),
    "custody_record_edited": ("ours_epoch_auditor", "verify_on_access"),
    "agent_epoch_omitted": ("ours_epoch_la_id_contiguity", "verify_on_access"),
    "payload_deleted": ("ours_0x05_accounting", "full_rehash_same_budget", "verify_on_access"),
}


def tamper_detect(m: dict, klass: str, arm: str) -> str:
    """Median injection-to-alert time for one class and arm, with its unit.

    ⛔ Refuses a class or arm the harness does not define, a record without the
    budget every class is read against, and a non-null time from fewer than 20
    trials (the M4b acceptance's floor)."""
    if klass not in TAMPER_CLASSES or arm not in TAMPER_CLASSES[klass]:
        raise KeyError(f"exp8: no arm {arm!r} in class {klass!r}")
    if "read_budget_bytes_per_s" not in m:
        raise KeyError("exp8 record carries no read budget; its times cannot be read")
    c = m[klass]
    a = c[arm]
    if not isinstance(a, dict):
        raise ValueError(f"exp8: {klass}/{arm} is structural ({a!r}), not a time")
    d = a.get("detect_ns")
    if d is None:
        return fmt_duration(None)
    if int(c["trials"]) < 20:
        raise ValueError(f"exp8: {klass} has {c['trials']} trials; the acceptance needs >= 20")
    return fmt_duration(_median_ns(d))


def tamper_stat(m: dict, klass: str, arm: str, stat: str) -> str:
    """Mean or p95 injection-to-alert time for one class and arm (M13 A11, A19).

    The median alone hid the sweep's tail: a pass without replacement bounds
    the worst case, and that bound is what p95 shows. Same refusals as
    `tamper_detect`, and a record from before A11 carries no mean or p95."""
    key = {"mean": "mean_ns", "p95": "p95_ns"}[stat]
    tamper_detect(m, klass, arm)
    d = m[klass][arm]["detect_ns"]
    if d is None:
        return fmt_duration(None)
    if key not in d:
        raise KeyError(f"exp8 {klass}/{arm} has no {key}: the record predates M13 A11")
    return fmt_duration(int(d[key]))


def _tamper_tail(m: dict) -> dict:
    t = m["agent_epoch_omitted"].get("tail_omitted")
    if not isinstance(t, dict):
        raise KeyError("exp8 has no tail-omission row: the record predates M13 A6")
    return t


def tamper_tail(m: dict, which: str) -> str:
    """Class 4's tail row (M13 A6): `detect` is the median drop-to-alert time
    through the heartbeat, `heartbeat` its period `T`, `contiguity` how many
    trials contiguity alone caught (it should be zero, and is measured)."""
    t = _tamper_tail(m)
    if which == "heartbeat":
        return fmt_duration(int(t["ours_heartbeat"]["heartbeat_period_ns"]))
    if which == "contiguity":
        return str(int(t["ours_epoch_la_id_contiguity"]["detected_trials"]))
    if int(t["trials"]) < 20:
        raise ValueError(f"exp8 tail row has {t['trials']} trials; the acceptance needs >= 20")
    return fmt_duration(_median_ns(t["ours_heartbeat"]["detect_ns"]))


def tamper_admissible_range(m: dict) -> str:
    """Per artefact, the observed share of chunks still verifying after one
    damaged chunk (M13 A9): each artefact's median over its trials, then the
    range across artefacts. Observed, not `(chunks − 1)/chunks`."""
    obs = m["payload_at_rest"]["ours_sampled_sweep"].get("admissible_observed")
    if not obs:
        raise KeyError("exp8 has no observed admissibility: the record predates M13 A9")
    by_obj: dict = {}
    for o in obs:
        by_obj.setdefault(o["object"], []).append(int(o["verified"]) / int(o["chunks"]))
    meds = sorted(sorted(v)[len(v) // 2] * 100 for v in by_obj.values())
    lo, hi = f"{meds[0]:.2f}", f"{meds[-1]:.2f}"
    return (lo if lo == hi else f"{lo}--{hi}") + "\\,\\%"


def _anchor_gas(m: dict) -> int:
    got = m.get("anchor_gas")
    if not isinstance(got, dict) or "anchor_commit_gas" not in got:
        raise KeyError(
            "exp6 carries no anchor_gas; run `cargo xtask contracts` first so "
            "GasProfile.t.sol writes contracts/out/anchor-gas.json. A missing "
            "figure is not a free anchor"
        )
    return int(got["anchor_commit_gas"])


def exp6_anchor_gas(m: dict) -> str:
    """The caption's constant: what one anchor costs, whatever the epoch holds."""
    return fmt_int(_anchor_gas(m))


def exp6_gas_per_entry(m: dict, entries: int) -> str:
    """⭐ A division, not a second measurement.

    `tab:exp6` is one measured quantity and four divisions, which is exactly why
    it is axed on entry count: the anchor commits a single root with fixed-size
    arguments, so its cost does not depend on how many entries the epoch holds.
    Three significant figures, because the ratio's precision is the constant's
    and printing more would invent some.
    """
    per = _anchor_gas(m) / entries
    return fmt_sig3(per)


def exp7_boolean_us(m: dict, form: str) -> str:
    for row in m.get("boolean_forms") or []:
        if row["form"] == form:
            return fmt_ms(_median_ns(row["total_ns"]))
    raise KeyError(f"exp7 has no boolean_forms row for {form!r}")


def exp7_index_ratio(m: dict) -> str:
    rows = m.get("index_sizes") or []
    if not rows:
        raise KeyError("exp7 carries no index_sizes; re-run it")
    return fmt_ratio(rows[-1]["index_ratio_milli"] / 1000.0)


def exp7_index_zuo(m: dict) -> str:
    rows = m.get("index_sizes") or []
    if not rows:
        raise KeyError("exp7 carries no index_sizes; re-run it")
    return fmt_ratio(rows[-1]["zuo_index_ratio_milli"] / 1000.0)


def exp7_conj_range_ms(m: dict) -> str:
    for row in m.get("boolean_forms") or []:
        if row["form"] == "w1 AND range":
            return fmt_ms(_median_ns(row["total_ns"]))
    raise KeyError("exp7 has no boolean_forms row for 'w1 AND range'")


def exp2_speedup(m: dict, documents: int, width: int) -> str:
    for row in m["rows"]:
        if row["documents"] == documents and row["conjunction_width"] == width:
            ours = _median_ns(row["pi_xt"]["search_ns"])
            theirs = _median_ns(row["odxt"]["search_ns"])
            return fmt_ratio(theirs / ours)
    raise KeyError(f"exp2 has no row for documents={documents}, width={width}")


def exp5_dropped(m: dict, epsilon: float, epochs: int) -> str:
    for row in m["rows"]:
        if row["epsilon"] == epsilon and row["closed_epochs"] == epochs:
            return str(int(row["answer_dropped"]))
    raise KeyError(f"exp5 has no row for epsilon={epsilon}, E={epochs}")


def exp6_sign_us(m: dict) -> str:
    return fmt_us(_median_ns(m["epochs"][0]["anchor_sign_ns"]))


def exp6_proof_bytes(m: dict) -> str:
    return fmt_int(m["epochs"][0]["inclusion_proof_bytes"])


def exp7_range_ms(m: dict) -> str:
    return fmt_ms(_median_ns(m["rows"][0]["pi_range"]["search_ns"]))


def exp7_zuo_cold_ms(m: dict) -> str:
    """Zuo'22 first search over a range.

    ⚠️ Cold and warm are **separate numbers** for this baseline and must
    stay separate. Its search is destructive and compacting (`UPGRADES.md`), so
    a second search over the same range does less work -- quoting one figure
    would flatter or penalise it depending which one, and the asymmetry with
    our non-mutating search is a property worth showing rather than averaging
    away. Cold is the like-for-like comparison against ours.
    """
    # ⭐ A scalar, not a summary, and that is correct rather than an
    # omission: a destructive search can only be cold **once**, so there is no
    # distribution to take a median of. Taking one would mean re-warming the
    # index, which is a different measurement wearing the same name.
    return fmt_ms(m["rows"][0]["zuo22"]["cold_search_ns"])


def exp7_zuo_warm_ms(m: dict) -> str:
    return fmt_ms(_median_ns(m["rows"][0]["zuo22"]["warm_search_ns"]))


# --- M10 Phase C: the semantic tables ----------------------------------------

def exp1_plain_ceiling(m: dict) -> str:
    """`tab:exp-ingest`'s ceiling: the ORDERED plaintext pass on the
    head-to-head's own stream, entries checked against what its class derives."""
    return exp1_h2h_throughput(m, "Plaintext", "keyword+range-ordered")


def exp1_h2h_speed_ratio(m: dict, scheme: str, qclass: str) -> str:
    """Ours / it in events/s — **above 1 favours us** (the table's convention)."""
    ours = _h2h_row(m, "PQ-ChainLog", qclass)
    theirs = _h2h_row(m, scheme, qclass)
    return fmt_ratio(_median_ns(theirs["total_ns"]) / _median_ns(ours["total_ns"]))


def exp1_ours_over_ceiling(m: dict) -> str:
    """Our keyword AND range events/s over the plaintext ceiling's."""
    plain = _h2h_row(m, "Plaintext", "keyword+range-ordered")
    ours = _h2h_row(m, "PQ-ChainLog", "keyword+range")
    return fmt_ratio(_median_ns(plain["total_ns"]) / _median_ns(ours["total_ns"]))


def exp1_vs_ecdsa(m: dict, batch: int) -> str:
    """`tab:abl-sign`'s vs. ECDSA: per-event time at `batch` over ECDSA at B=1
    (above 1 is slower), over passes that indexed the same tokens."""
    row = _exp1_row(m, batch)
    base = _exp1_row(m, 1)
    if row.get("indexed_tokens") != base.get("classical_indexed_tokens"):
        raise ValueError(f"exp1 B={batch} and ECDSA B=1 indexed different tokens")
    return fmt_ratio(_median_ns(row["pqc_total_ns"]) / _exp1_classical(m, 1))


def _steady_anchor_gas(m: dict) -> int:
    """Our anchor's gas **as a transaction on the network**: receipt gasUsed,
    steady state (every commit after a case's first, which pays a cold
    SSTORE). ⛔ Not exp6's Foundry figure: that commits with empty signatures
    and counts execution only, ~10x below what the chain charges an anchor
    carrying its ML-DSA and SLH-DSA signatures. LEChain's per-event figure is a
    receipt gasUsed too, so the two sides are the same quantity."""
    steady = sorted(g for o in m["ours"] for g in o["anchor_gas"][1:])
    if not steady:
        raise KeyError("exp6chain has no steady-state anchor (every run anchored once)")
    return steady[len(steady) // 2]


def exp6c_anchor_gas(m: dict) -> str:
    return fmt_int(_steady_anchor_gas(m))


def _order_gas_per_epoch(ours: dict) -> float:
    """§1v.4: the axis point's measured `orderRedaction` gas, per epoch.

    ⛔ Refuses a run without `order_gas`: it predates redaction orders, and its
    per-entry figure would silently omit a cost every disposing epoch pays."""
    if "order_gas" not in ours:
        raise KeyError("exp6chain run carries no order_gas; it predates §1v.4 (redaction orders)")
    return sum(int(g) for g in ours["order_gas"]) / max(1, len(ours["anchor_gas"]))


def _ours_gas_per_entry(m: dict, entries: int) -> float:
    """The caption's rule: the steady anchor, plus the point's redaction
    orders per epoch, over the epoch's entries."""
    _, _, ours = _custody_commit(m, entries)
    return (_steady_anchor_gas(m) + _order_gas_per_epoch(ours)) / entries


def exp6c_gas_per_entry(m: dict, entries: int) -> str:
    return fmt_sig3(_ours_gas_per_entry(m, entries))


def _full_epoch_records(ours: dict) -> float:
    """Median records per **full** epoch (one that reached `epoch_size`
    leaves); the run's last, partial epoch is left out. With two full epochs
    the median is their mean."""
    size = int(ours["epoch_size"])
    full = [int(r) for r, e in zip(ours["records_per_epoch"], ours["entries_per_epoch"]) if int(e) >= size]
    if not full:
        raise KeyError(f"exp6chain run at epoch size {size} has no full epoch")
    return statistics.median(full)


def _ours_gas_per_record(m: dict, entries: int) -> float:
    """§1ag: the steady anchor plus the point's orders per epoch, over the
    median records of a full epoch -- the same unit as LEChain's per event."""
    _, _, ours = _custody_commit(m, entries)
    return (_steady_anchor_gas(m) + _order_gas_per_epoch(ours)) / _full_epoch_records(ours)


def exp6c_per_event_over_ours(m: dict, entries: int) -> str:
    """Gas per custody record: LEChain's (`gas_total / events`, each event one
    record) over ours -- above 1 favours us.

    ⛔ Per record on both sides (§1ag, overturning §1l.2's per-leaf unit): a
    leaf is not a record. A small epoch holds more leaves than records, a large
    one folds about four records into each custody-root leaf."""
    events, lechain, _ = _custody_commit(m, entries)
    return fmt_ratio((int(lechain["gas_total"]) / events) / _ours_gas_per_record(m, entries))


def custody_append_us(m: dict) -> str:
    """One custody record built, sealed, signed and indexed (29 tokens) through
    the run's Secure Module, median: the unilateral arm of the transfer timer."""
    return fmt_us(_median_ns(m["bilateral_transfer"]["unilateral_ns"]))


def custody_record_verify_us(m: dict) -> str:
    """One record's ML-DSA-65 check, median. Every scheme of Exp. 2 pays it once
    per disclosed record, so the verify cells leave it out."""
    return fmt_us(_median_ns(m["record_signature_verify_ns"]))


def exp6c_custody_keywords(m: dict) -> str:
    """The custody plane's index set per record, from the library's own
    constant as the harness recorded it (M13 A2).

    Every run must agree: the constant is compiled in, so a disagreement means
    two runs of different code were merged into one record set, which is worse
    than a wrong number.
    """
    vals = {int(o["custody_keywords_per_record"]) for o in m["ours"]}
    if len(vals) != 1:
        raise ValueError(f"runs disagree on the custody index set: {sorted(vals)}")
    return str(vals.pop())


def exp6c_leaves_per_record(m: dict) -> str:
    """`tab:exp-anchor`'s caption: Tier-2 leaves per custody record, over each
    axis run's whole stream, as the measured range smallest to largest."""
    vals = []
    for o in m["ours"]:
        vals.append(sum(int(e) for e in o["entries_per_epoch"]) / int(o["records"]))
    lo, hi = f"{min(vals):.2f}", f"{max(vals):.2f}"
    return lo if lo == hi else f"{lo}--{hi}"


def _pct(v: float) -> str:
    return f"{v:.1f}" if v < 10 else f"{v:.0f}"


def exp6c_dispose_pct(m: dict) -> str:
    """`tab:exp-anchor`'s caption: the share of capsules disposed, realised
    over every axis run's stream (not the stream parameter)."""
    runs = m["ours"]
    if any("disposed_capsules" not in o for o in runs):
        raise KeyError("exp6chain run carries no disposed_capsules; it predates §1v.4")
    d = sum(int(o["disposed_capsules"]) for o in runs)
    c = sum(int(o["capsules"]) for o in runs)
    return _pct(100 * d / c) + "\\,\\%"


def exp6c_order_epoch_pct(m: dict) -> str:
    """`tab:exp-anchor`'s caption: the share of epochs that carry an order.

    ⚠️ It depends on the axis point (a large epoch always disposes something,
    a small one rarely), so the cell is the measured range across the axis,
    smallest to largest, never one blended share."""
    pcts = []
    for o in m["ours"]:
        if "epochs_with_order" not in o:
            raise KeyError("exp6chain run carries no epochs_with_order; it predates §1v.4")
        pcts.append(100 * int(o["epochs_with_order"]) / int(o["epochs"]))
    lo, hi = min(pcts), max(pcts)
    if _pct(lo) == _pct(hi):
        return _pct(lo) + "\\,\\%"
    return f"{_pct(lo)}--{_pct(hi)}\\,\\%"


def exp6c_speed_ratio(m: dict, epoch: int) -> str:
    """Records/s: ours at this axis point over LEChain's -- above 1 favours us."""
    _, lechain, ours = _custody_commit(m, epoch)
    p = lechain["pipelined"]
    theirs = int(p["events"]) / int(p["first_submit_to_last_commit_ns"])
    mine = int(ours["records"]) / int(ours["first_event_to_last_commit_ns"])
    return fmt_ratio(mine / theirs)


def exp6c_floor_epoch(m: dict) -> str:
    """The smallest epoch size the parallel series measured (rule 21: the
    point a "wins everywhere" statement is bounded by)."""
    return fmt_int(min(int(o["epoch_size"]) for o in m["ours"]))


def exp6c_floor_ratio(m: dict) -> str:
    """Ours over LEChain's records/s at that smallest measured epoch size."""
    return exp6c_speed_ratio(m, min(int(o["epoch_size"]) for o in m["ours"]))


def exp6c_ingest_us_per_record(m: dict) -> str:
    """Parallel series: ingest time per record, range over `ANCHOR_AXIS`.

    Ingest is building, sealing, signing and indexing each record (29 Π_core
    tokens since M13 A2) through the run's Secure Module, the enclave on a
    campaign run since M13 A18. It is the term that sets the plateau of the
    rate ratio, so the caption can name it."""
    us = []
    for _, n in ANCHOR_AXIS:
        _, _, ours = _custody_commit(m, n)
        us.append(int(ours["ingest_total_ns"]) / 1000 / int(ours["records"]))
    lo, hi = fmt_int(min(us)), fmt_int(max(us))
    return lo if lo == hi else f"{lo}--{hi}"


def exp6c_lechain_rate(m: dict) -> str:
    """`tab:exp-anchor`'s caption: the per-event commitment's records/s, on
    LEChain's 10⁴-capsule steady-state stream (M13 A4)."""
    p = _lechain_steady(m)["pipelined"]
    return fmt_int(_per_second(int(p["events"]), int(p["first_submit_to_last_commit_ns"])))


def exp6c_cross(m: dict, key: str, which: str, against: str = "lechain") -> str:
    """Rule 21's bracket (§1as.3.2): the two adjacent measured epoch sizes
    between which `key`'s records/s crosses the per-event rate of `against`
    ("lechain", or "bdems" since §1ck.2), read off the same points
    `figures.exp_anchor` plots. `which` is "low" or "high".

    ⚠️ One run per point, so the curve could wobble across the line more than
    once. A bracket is then not one place, and the cell refuses rather than
    name the first crossing it meets."""
    if key not in m:
        raise KeyError(f"exp6chain run carries no {key!r} series")
    if against not in ("lechain", "bdems"):
        raise ValueError(f"exp6chain: no per-event arm {against!r}")

    def beats(o):
        # Each point against the run on the stream its own ratio divides by (M13 A4).
        point = {**m, "ours": [o]}
        if against == "bdems":
            theirs = _bdems_rate(_bdems_at(point, int(o["epoch_size"]))[0])
        else:
            p = _custody_commit(point, int(o["epoch_size"]))[1]["pipelined"]
            theirs = _per_second(int(p["events"]), int(p["first_submit_to_last_commit_ns"]))
        return _per_second(int(o["records"]), int(o["first_event_to_last_commit_ns"])) > theirs

    pts = sorted((int(o["epoch_size"]), beats(o)) for o in m[key])
    flips = [(a, b) for (a, wa), (b, wb) in zip(pts, pts[1:]) if wa != wb]
    if len(flips) != 1:
        raise ValueError(f"exp6chain {key}: {len(flips)} crossings of {against}'s per-event rate, need exactly 1")
    lo, hi = flips[0]
    return fmt_int(lo if which == "low" else hi)


def exp6c_lechain_ceiling(m: dict) -> str:
    """**A projection** (rule 12), from three measured inputs (M13 A4, A19):
    the most per-event transactions this network can commit per second.

    Besu packs a block by each transaction's gas *limit*, which LEChain's
    client sets to the estimate times the recorded margin, so a block holds
    `floor(block gas limit / (gas per transition x margin))` of them, one block
    per observed period. Gas per transition is the 10^4 steady state's. It
    turns on our measured quantities, so a cheap transition gives a high
    ceiling rather than a convenient one."""
    steady = _lechain_steady(m)
    ci = m.get("lechain_ceiling_inputs")
    if not isinstance(ci, dict):
        raise KeyError("exp6chain carries no lechain_ceiling_inputs: it predates M13 A4")
    gas = int(steady["gas_total"]) / int(steady["transitions"])
    per_block = int(int(ci["block_gas_limit"]) // (gas * int(ci["gas_limit_margin_pct"]) / 100))
    period_ms = ci["observed_block_period_ms"]
    if not period_ms:
        raise ValueError("exp6chain: no observed block period, so no ceiling")
    return fmt_int(per_block * 1000 / int(period_ms))


def exp6c_lechain_point_rate(m: dict, epoch: int) -> str:
    """LEChain's records/s on the stream this axis point divides by (M13 A4)."""
    p = _custody_commit(m, epoch)[1]["pipelined"]
    return fmt_int(_per_second(int(p["events"]), int(p["first_submit_to_last_commit_ns"])))


def exp6c_lechain_gas(m: dict) -> str:
    """`tab:exp-anchor`'s caption: gas per custody event, per-event style,
    on the steady-state stream (M13 A4)."""
    lechain = _lechain_steady(m)
    return fmt_int(int(lechain["gas_total"]) / int(lechain["transitions"]))


def _bdems_run(m: dict, capsules: int) -> dict:
    """`exp6chain`: B-DEMS's run on the `capsules`-capsule stream (§1ci.1),
    checked complete: one pipelined phase over every event of its own stream,
    and the same stream LEChain ran at that size."""
    if "bdems_runs" not in m:
        raise KeyError("exp6chain record predates §1ci.1: it carries no B-DEMS arm")
    runs = [r for r in m["bdems_runs"] if int(r["stream_capsules"]) == capsules]
    if len(runs) != 1:
        raise KeyError(f"exp6chain has {len(runs)} B-DEMS runs on {capsules} capsules")
    run = runs[0]
    events = int(run["events"])
    if int(run["pipelined"]["events"]) != events:
        raise ValueError("exp6chain: B-DEMS's pipelined phase does not cover its stream")
    if events != int(_lechain_run(m, capsules)["events"]):
        raise ValueError(f"exp6chain: B-DEMS and LEChain ran different {capsules}-capsule streams")
    issued = sum(int(v["transactions"]) for v in run["by_event"].values())
    if issued != int(run["transactions"]) or sum(int(v["events"]) for v in run["by_event"].values()) != events:
        raise ValueError("exp6chain: B-DEMS's per-event accounting does not add up to its run")
    return run


def _bdems_gas_per_record(run: dict) -> float:
    """Every transaction's gas over every custody record of the stream; a
    record B-DEMS issues no transaction for counts, at zero gas."""
    return int(run["gas_total"]) / int(run["events"])


def _bdems_rate(run: dict) -> float:
    p = run["pipelined"]
    return _per_second(int(p["events"]), int(p["first_submit_to_last_commit_ns"]))


def exp6c_bdems_gas(m: dict) -> str:
    """`\\pqclAnchorBdemsGas`: B-DEMS's gas per custody record on the 10⁴-capsule
    steady-state stream, LEChain's."""
    return fmt_int(_bdems_gas_per_record(_bdems_run(m, int(_lechain_steady(m)["stream_capsules"]))))


def exp6c_bdems_rate(m: dict) -> str:
    """`\\pqclAnchorBdemsRate`: B-DEMS's custody records per second, on the
    steady-state stream: every event over first submission to last commit."""
    return fmt_int(_bdems_rate(_bdems_run(m, int(_lechain_steady(m)["stream_capsules"]))))


def _bdems_at(m: dict, epoch: int) -> tuple:
    """B-DEMS's run on the stream this axis point divides by, and our run."""
    _, lechain, ours = _custody_commit(m, epoch)
    return _bdems_run(m, int(lechain["stream_capsules"])), ours


def exp6c_bdems_over_ours(m: dict, entries: int) -> str:
    """Gas per custody record, B-DEMS's over ours (the same unit as
    `exp6c_per_event_over_ours`): above 1 favours us."""
    run, _ = _bdems_at(m, entries)
    return fmt_ratio(_bdems_gas_per_record(run) / _ours_gas_per_record(m, entries))


def exp6c_bdems_rate_ratio(m: dict, epoch: int) -> str:
    """Records/s, ours at this axis point over B-DEMS's on the stream it
    divides by: above 1 favours us, the direction of `exp6c_speed_ratio`."""
    run, ours = _bdems_at(m, epoch)
    mine = _per_second(int(ours["records"]), int(ours["first_event_to_last_commit_ns"]))
    return fmt_ratio(mine / _bdems_rate(run))


def exp6c_bdems_floor_ratio(m: dict) -> str:
    """`\\pqclAnchorBdemsFloorRatio` (§1ck.2): ours (parallel) over B-DEMS's
    records/s at the smallest measured epoch size, the point B-DEMS wins."""
    return exp6c_bdems_rate_ratio(m, min(int(o["epoch_size"]) for o in m["ours"]))


def _across_y(m: dict) -> dict:
    a = m.get("range_ingest_across_y")
    if not isinstance(a, dict):
        raise KeyError("exp1 carries no range_ingest_across_y; the run predates §1l.3")
    return a


def ingest_y(m: dict, which: str) -> str:
    """`tab:exp-ingest`'s caption: the operating y, or the largest y measured."""
    a = _across_y(m)
    if which == "operating":
        y = int(a["operating_y"])
        if int(m["head_to_head"]["events"]) != y:
            raise ValueError("exp1 head-to-head did not run at the operating y")
        return fmt_int(y)
    return fmt_int(int(a["largest_y_measured"]))


def ingest_range_ratio_at_largest(m: dict) -> str:
    """Our range events/s over Zuo'22's at the largest y measured -- above 1
    favours us -- over passes that indexed the same nodes."""
    a = _across_y(m)
    y = int(a["largest_y_measured"])
    rows = [r for r in a["rows"] if int(r["y"]) == y and not r.get("skipped")]
    if len(rows) != 1:
        raise KeyError(f"exp1 has no measured across-y row at y = {y}")
    r = rows[0]
    if int(r["zuo22"]["entries"]) != int(r["ours_range"]["entries"]):
        raise ValueError(f"exp1 across-y at y = {y}: Zuo'22 and ours indexed different work")
    return fmt_ratio(_median_ns(r["zuo22"]["total_ns"]) / _median_ns(r["ours_range"]["total_ns"]))


def leak_count(m: dict, queries: int, what: str) -> str:
    """`tab:exp-leak`: ODXT/Pi_XT attributable associations, Pi_XT's
    unattributable repeated hits, Pi_CD's per-conjunct volumes."""
    rows = [r for r in m["rows"] if int(r["queries"]) == queries]
    if len(rows) != 1:
        raise KeyError(f"exp3 has no row at {queries} queries")
    r = rows[0]
    v = {
        "odxt_attr": lambda: r["associations"]["odxt"]["associations"],
        "xt_attr": lambda: r["associations"]["pi_xt"],
        "xt_link": lambda: r["hit_link_distinct_pairs"],
        "cd_vol": lambda: r["pi_cd_conjunct_volumes_total"],
    }[what]()
    return fmt_int(int(v))


def custody_case_size(m: dict) -> str:
    return fmt_int(max(int(c["records"]) for c in m["cases"]))


def custody_audit_s(m: dict, scheme: str) -> str:
    """`tab:exp-custody`'s Audit (s): the whole case, at the largest case."""
    top = max(int(c["records"]) for c in m["cases"])
    c = _custody_case(m, top)
    return f"{_median_ns(c[scheme]['full_replay_ns']) / 1e9:.2f}"


def custody_audit_all_s(m: dict, scheme: str) -> str:
    """`tab:exp-custody`'s Audit (s), all cores (§1o.3 F2), at the largest case.

    Chain replay is inherently sequential, so its all-cores cell is its
    one-core audit, but **only** when the record says so
    (`parallel_note`). A record without the parallel field predates F2 and
    is a named gap, never a copied number.
    """
    top = max(int(c["records"]) for c in m["cases"])
    s = _custody_case(m, top)[scheme]
    par = s.get("full_replay_parallel_ns")
    if par is None:
        if "parallel_note" in s:
            return f"{_median_ns(s['full_replay_ns']) / 1e9:.2f}"
        raise KeyError(f"custody record has no all-cores audit for {scheme} (predates M12 F2)")
    return f"{_median_ns(par) / 1e9:.2f}"


def range_crossover_bracket(m: dict, which: str) -> str:
    """`tab:exp-ingest` caption (0,3)/(0,4): the two MEASURED y that bracket
    where our range ratio against Zuo'22 crosses 1 (the project rules rule 21).

    Never an interpolated crossover. Refuses when the measured ratio does not
    cross 1, or crosses more than once: a single bracket in the caption would
    then misdescribe the curve.
    """
    rows = sorted(
        (r for r in m["range_ingest_across_y"]["rows"] if not r.get("skipped")),
        key=lambda r: int(r["y"]),
    )
    ratios = [
        (int(r["y"]), int(r["zuo22"]["total_ns"]["median_ns"]) / int(r["ours_range"]["total_ns"]["median_ns"]))
        for r in rows
    ]
    brackets = [(a[0], b[0]) for a, b in zip(ratios, ratios[1:]) if (a[1] < 1) != (b[1] < 1)]
    if len(brackets) != 1:
        raise KeyError(f"our range ratio crosses 1 {len(brackets)} times across the measured y; "
                       "the caption's single bracket needs exactly one")
    lo, hi = brackets[0]
    return fmt_int(lo if which == "low" else hi)


def ingest_index_mb_at_largest_y(m: dict, whose: str) -> str:
    """`tab:exp-range` row 9 (§1o.4): index MB at the largest y, **measured**
    (exp1's across-y `index_bytes`), never the skip reason's estimate."""
    rows = [r for r in m["range_ingest_across_y"]["rows"] if not r.get("skipped") and "index_bytes" in r]
    if not rows:
        raise KeyError("exp1 has no measured index bytes across y (predates M12 §1o.4)")
    top = max(rows, key=lambda r: int(r["y"]))["index_bytes"]
    b = int(top["zuo22"]) if whose == "zuo" else int(top["ours_range"]["total"])
    return f"{b / 1e6:.1f}"


def tamper_param(m: dict, which: str) -> str:
    """`tab:exp-tamper`'s caption parameters, from the record (§1l.5)."""
    if which == "budget":
        return f"{int(m['read_budget_bytes_per_s']) / 1e6:.0f}\\,MB/s"
    if which == "period":
        return fmt_duration(int(m["audit_period_ns"]))
    ppm = sorted(int(x) for x in m["payload_at_rest"]["ours_sampled_sweep"]["admissible_ppm_of_object"])
    if not ppm:
        raise KeyError("exp8 has no localisation figures")
    return f"{ppm[len(ppm) // 2] / 1e4:.2f}\\,\\%"


#: `tab:exp-size`'s Bloom operating point, ruled in the design record:
#: delta = 1e-3 at (n_max - 1)E = 5 x 24 = 120 -- the heaviest point the
#: deployment admits (tab:params: E <= 24, n_max = 6), not the heaviest one a
#: sweep happened to measure.
SIZE_BLOOM = (1e-3, 5, 24)


def _size_row(m: dict) -> dict:
    rows = [r for r in m["rows"] if r["dataset"] == "enron" and int(r["pairs"]) == 10**6]
    if len(rows) != 1:
        raise KeyError("index-size has no single enron row at 10^6 pairs")
    return rows[0]


def size_bpp(m: dict, which: str) -> str:
    r = _size_row(m)
    n = int(r["pairs"])
    o, d = r["ours"], r["odxt"]
    if which == "ours_exact":
        return f"{(o['edb_bytes'] + o['xset_exact_bytes']) / n:.1f}"
    if which == "ours_bloom":
        delta, x, e = SIZE_BLOOM
        b = [v for v in o["xset_bloom"] if v["target_loss"] == delta and v["x_terms"] == x and v["closed_epochs"] == e]
        if len(b) != 1:
            raise KeyError(f"index-size has no ours Bloom row at {SIZE_BLOOM}")
        return f"{(o['edb_bytes'] + b[0]['xset_bytes']) / n:.1f}"
    if which == "odxt":
        b = [v for v in d["xset_bloom"] if v["target_loss"] == SIZE_BLOOM[0]]
        if len(b) != 1:
            raise KeyError("index-size has no ODXT Bloom row at the table's delta")
        return f"{(d['tset_bytes'] + b[0]['xset_bytes']) / n:.1f}"
    raise KeyError(which)


def doris_bpp(records: list, scheme: str) -> str:
    """OXT/HXT/ConjFilter/Doris at 10^6 Enron pairs, from the carve-out
    records (their rows are top-level, not under `measurements`)."""
    rows = [row for r in records for row in r.get("rows", [])
            if row.get("scheme") == scheme and row.get("dataset") == "enron"
            and int(row.get("pairs", 0)) == 10**6 and "index_bytes" in row]
    if not rows:
        raise KeyError(f"no doris-structural row for {scheme}, enron, 10^6 pairs")
    vals = {int(r["index_bytes"]) for r in rows}
    if len(vals) != 1:
        raise ValueError(f"doris-structural records disagree on {scheme}: {sorted(vals)}")
    return f"{vals.pop() / 10**6:.1f}"


def leak_associations(m: dict, queries: int, scheme: str) -> str:
    rows = [r for r in m["rows"] if int(r["queries"]) == queries]
    if len(rows) != 1:
        raise KeyError(f"exp3 has no row at {queries} queries")
    a = rows[0]["associations"]
    v = a["odxt"]["associations"] if scheme == "odxt" else a[scheme]
    return fmt_int(int(v))


def custody_largest(m: dict, scheme: str, what: str) -> str:
    """`tab:exp-custody` at the largest case measured (10^6 on AWS)."""
    top = max(int(c["records"]) for c in m["cases"])
    c = _custody_case(m, top)
    if what == "bytes":
        return fmt_int(int(c[scheme]["disclosed_bytes"]))
    return fmt_us(_median_ns(c[scheme]["verify_ns"]))


# --- SAC Exp. 4: court-ordered redaction against B-DEMS (§1cf) -------------

REDACT_ARMS = (("Ours", "ours"), ("Bdems", "bdems"), ("Pqabl", "pqabl"))
REDACT_K = (("One", 1), ("Ten", 10), ("Hundred", 100), ("Thousand", 1000))
REDACT_ROWS = (("Valid", "valid"), ("NoRecord", "no_record"), ("Insider", "insider"),
               ("Modified", "modified"), ("Replay", "replay"))
#: T2's trials per cell, fixed in §1cf.2 before measuring.
REDACT_TRIALS = 100


def _redact_largest(m: dict) -> dict:
    """The largest case, the only one carrying T1 and T2 (`redaction`'s
    "t1_t2_case"). ⛔ Refuses a record whose largest case lacks either: a
    smoke run with a reduced sweep must not reach the paper."""
    top = max(m["cases"], key=lambda c: int(c["records"]))
    if "t1" not in top or "t2" not in top:
        raise ValueError("the largest redaction case carries no T1/T2")
    want = [k for _, k in REDACT_K]
    for _, arm in REDACT_ARMS:
        ks = sorted(int(r["k"]) for r in top["t1"].get(arm, []))
        if ks != want:
            raise ValueError(f"T1 swept k = {ks} for {arm}, not 1, 10, 100, 1000")
    if int(top.get("epoch_records", 0)) != CASE_EPOCH_RECORDS:
        raise ValueError(f"the redaction case ran {top.get('epoch_records')}-record epochs, not {CASE_EPOCH_RECORDS}")
    if int(top["t2"]["trials"]) != REDACT_TRIALS:
        raise ValueError(f"T2 ran {top['t2']['trials']} trials per cell, not {REDACT_TRIALS}")
    return top


#: Records per sealing epoch in Exp. 2 and Exp. 4, fixed in §1ci.5 item 2
#: before measuring.
CASE_EPOCH_RECORDS = 10_000


def _redact_one_epoch(m: dict) -> dict:
    """§1ci.6's labelled series: the largest one-epoch case, which carries T1
    for ours and PQ-ABL, checked to hold the whole case in one epoch."""
    cases = m.get("one_epoch_cases")
    if not cases:
        raise KeyError("sac-redaction record predates §1ci.6: no one-epoch series")
    top = max(cases, key=lambda c: int(c["records"]))
    if int(top["sealing_epochs"]) != 1:
        raise ValueError(f"the one-epoch case has {top['sealing_epochs']} sealing epochs")
    ks = sorted(int(r["k"]) for r in top.get("t1", {}).get("pqabl", []))
    if ks != [k for _, k in REDACT_K]:
        raise ValueError(f"one-epoch T1 swept k = {ks}, not 1, 10, 100, 1000")
    return top


def redact_one_epoch(m: dict, what: str, k: int, arm: str = "pqabl") -> str:
    """`pqclRedact{LatMs,Gas}PqablOneEpoch*`: PQ-ABL's T1 with the whole case
    in one epoch, beyond its evaluated range past 50,000 logs (§1ci.6); and
    `pqclRedactLatMsOursOneEpochOne` (§1ck.2), ours on the same layout."""
    rows = _redact_one_epoch(m)["t1"].get(arm, [])
    if sorted(int(r["k"]) for r in rows) != [kk for _, kk in REDACT_K]:
        raise ValueError(f"one-epoch T1 did not sweep k = 1, 10, 100, 1000 for {arm}")
    row = [r for r in rows if int(r["k"]) == k]
    if len(row) != 1:
        raise ValueError(f"one-epoch T1 has {len(row)} {arm} rows at k = {k}")
    if what == "gas":
        return fmt_int(int(row[0]["gas_median"]))
    return fmt_ms(_median_ns(row[0]["latency_ns"]))


def redact_invalidated(m: dict, one_epoch: bool) -> str:
    """`pqclRedactInvalidatedPqabl[OneEpoch]`: other custody records whose
    proofs a one-capsule PQ-ABL deletion invalidates at the largest case,
    median over F(a)'s iterations. Ours is none by construction; the record
    says so rather than carrying a constant."""
    top = _redact_one_epoch(m) if one_epoch else _redact_largest(m)
    if "never changes an anchored root" not in top.get("ours_invalidated", ""):
        raise KeyError("the redaction record does not state ours invalidates nothing")
    return fmt_int(int(top["pqabl_invalidated"]["records_median"]))


def redact_case_size(m: dict) -> str:
    """`pqclRedactCaseSize`: Exp. 4's largest case, in records (§1ch.1)."""
    return fmt_int(int(_redact_largest(m)["records"]))


def case_epoch_records(m: dict) -> str:
    """`pqclCaseEpochRecords`: records per sealing epoch, the same in every
    custody case (§1ci.5 item 2)."""
    vals = {int(c.get("epoch_records", 0)) for c in m["cases"]}
    if vals != {CASE_EPOCH_RECORDS}:
        raise ValueError(f"custody cases ran epochs of {sorted(vals)} records, not {CASE_EPOCH_RECORDS}")
    return fmt_int(CASE_EPOCH_RECORDS)


def _redact_t1(m: dict, arm: str, k: int) -> dict:
    row = [r for r in _redact_largest(m)["t1"][arm] if int(r["k"]) == k]
    if len(row) != 1:
        raise ValueError(f"T1 has {len(row)} rows for {arm} at k = {k}")
    return row[0]


def redact_gas(m: dict, arm: str, k: int) -> str:
    """`tab:exp-redaction` total gas: ours `orderRedaction` + the redaction
    epoch's `commitRoot`; B-DEMS every `TxE` and confirmation. Median over
    iterations, as gas varies only with storage warmth."""
    return fmt_int(int(_redact_t1(m, arm, k)["gas_median"]))


def redact_lat_ms(m: dict, arm: str, k: int) -> str:
    """`tab:exp-redaction` latency: first transaction submitted to the last
    record included, erasure done in between."""
    return fmt_ms(_median_ns(_redact_t1(m, arm, k)["latency_ns"]))


def redact_verify_us(m: dict, arm: str) -> str:
    """`pqclRedactVerifyUs`: the court's local check on a redacted capsule at
    the largest case, which is `pqclCustodyCaseSize`'s."""
    top = max(m["cases"], key=lambda c: int(c["records"]))
    return fmt_us(_median_ns(top["fb"][arm]["verify_ns"]))


def redact_matrix(m: dict, arm: str, row: str) -> str:
    """`tab:exp-redact-matrix`: accepted out of `REDACT_TRIALS`."""
    n = int(_redact_largest(m)["t2"][arm][row])
    if not 0 <= n <= REDACT_TRIALS:
        raise ValueError(f"{arm} {row} accepted {n} of {REDACT_TRIALS}")
    return str(n)


def custody_redacted(m: dict, scheme: str, what: str) -> str:
    """`tab:exp-custody`'s lower block: a redacted capsule, at the largest case."""
    top = max(int(c["records"]) for c in m["cases"])
    c = _custody_case(m, top)
    r = c[scheme].get("redacted")
    if r is None:
        raise KeyError("custody record carries no redacted block; it predates §1v.4")
    if what == "bytes":
        return fmt_int(int(r["disclosed_bytes"]))
    return fmt_us(_median_ns(r["verify_ns"]))


def custody_glass_range(m: dict, what: str, end: str) -> str:
    """`pqclCustodyGlass{Bytes,VerifyUs}{Min,Max}` (§1ck.2): GlassDB's
    disclosed bytes or verify µs, min or max over every case of this one
    record × {live, redacted}. GlassDB's content-defined node boundaries make
    each cell one draw (§1cj.5), so the paper prints the range.

    ⛔ The paper says the range lies "above ours at every size", so this
    refuses unless every GlassDB cell is above ours' cell of the same case and
    state: the sentence stays true or the file does not emit."""
    vals = []
    for case in m["cases"]:
        c = _custody_case(m, int(case["records"]))
        if "glassdb" not in c:
            raise KeyError(f"custody case of {c['records']} records carries no GlassDB arm")
        for state in ("live", "redacted"):
            g = c["glassdb"] if state == "live" else c["glassdb"].get("redacted")
            o = c["ours"] if state == "live" else c["ours"].get("redacted")
            if g is None or o is None:
                raise KeyError(f"custody case of {c['records']} records has no redacted block")
            pair = ((int(g["disclosed_bytes"]), int(o["disclosed_bytes"])) if what == "bytes"
                    else (_median_ns(g["verify_ns"]), _median_ns(o["verify_ns"])))
            if pair[0] <= pair[1]:
                raise ValueError(f"GlassDB's {state} {what} at {c['records']} records is not above ours")
            vals.append(pair[0])
    v = min(vals) if end == "min" else max(vals)
    return fmt_int(v) if what == "bytes" else fmt_us(v)


EXP9_ROWS = (("OdxtDel", "odxt_del"), ("OdxtRebuild", "odxt_rebuild"), ("OursPayload", "ours_payload"),
             ("OursPayloadIndex", "ours_payload_index"), ("OursFull", "ours_full"))


def _exp9_operating(m: dict) -> dict:
    """Exp. 9's operating case (10^5 pairs), refusing a record without it."""
    tier = int(m["operating_tier"])
    cases = [c for c in m["cases"] if int(c["tier"]) == tier]
    if len(cases) != 1:
        raise KeyError(f"exp9redact has {len(cases)} cases at its operating tier {tier}")
    return cases[0]


def exp9_cell(m: dict, row: str, col: str) -> str:
    """`tab:exp-redaction`, operating point: Erase (ms), Residual, Search after (ms)."""
    r = _exp9_operating(m)["rows"][row]
    if col == "erase":
        return fmt_ms(_median_ns(r["erase_ns"]))
    if col == "search":
        return fmt_ms(_median_ns(r["search_after_ns"]))
    vals = {int(v) for v in r["residual"]}
    if len(vals) != 1:
        raise ValueError(f"exp9 {row}: the residual differs across iterations ({sorted(vals)})")
    return fmt_int(vals.pop())


def exp9_sweep(m: dict, k: int) -> str:
    """`tab:exp-redaction`'s sweep block: ours FULL erase time at `k`."""
    rows = [s for s in _exp9_operating(m)["sweep"] if int(s["k"]) == k]
    if len(rows) != 1:
        raise KeyError(f"exp9redact has no sweep at k = {k}")
    return fmt_ms(_median_ns(rows[0]["ours_full"]["erase_ns"]))


def exp9_order_gas(m: dict, k: int) -> str:
    """`tab:exp-redaction`'s caption: receipt gas of one order over `k` capsules
    (`exp6chain`'s `order_gas_by_k`, same network and contract as the anchors)."""
    rows = [o for o in m["order_gas_by_k"]["orders"] if int(o["k"]) == k]
    if len(rows) != 1:
        raise KeyError(f"exp6chain has no order at k = {k}")
    return fmt_int(int(rows[0]["gas"]))


def exp9_detect(m: dict, server: str, arm: str) -> str:
    """`tab:exp-redact-detect`: missed unauthorised / false alarms on lawful."""
    d = m["detection"][server][arm]
    return f"{int(d['missed_unauthorised'])} / {int(d['false_alarms_on_lawful'])}"


# ---- §1aa.5: the setup paragraph, from the records and the manifests -----

def _aws(records: list) -> list:
    """The AWS records the paper's cells actually read: the newest per
    experiment, as `_latest` picks them (superseded campaigns are not the setup
    being described). The Doris carve-out is local by design and states no
    instance."""
    newest: dict = {}
    for r in records:
        if str(r.get("environment", "")).lower() != "aws":
            continue
        e = str(r.get("experiment", ""))
        if e not in newest or str(r.get("started_utc", "")) > str(newest[e].get("started_utc", "")):
            newest[e] = r
    return list(newest.values())


def _one(values: set, what: str) -> str:
    """The single value every record agrees on, or a refusal naming them."""
    if len(values) != 1:
        raise ValueError(f"records disagree on {what}: {sorted(values)}")
    return values.pop()


def _tex(s: str) -> str:
    return s.replace("_", BS + "_").replace("(R)", "")


#: The experiments `sec:setup` names an instance for, by the prefix their
#: cells read. `rest` is every other prefix SPEC reads.
SETUP_INSTANCE_OF = {
    "ingest": "exp1",
    # Exp. 2 moved to an r7i.8xlarge in c15 (§1db.6; the Doris follow-up's
    # memory), while Exps. 3-5 and 7 stayed on the m7i.8xlarge (c15a).
    "conj": "exp2",
    "anchor": "exp6chain",
    "custody": "custody-disclosure",
    "tamper": "exp8-tamper-response",
    # SAC Exp. 4 (§1cf) ran on its own instance (c09b), with an enclave and
    # Besu; it is not one of the "rest".
    "redaction": "sac-redaction",
    # draft9's redaction-scope ablation (Exp. 9's sweep) was last measured in
    # c08 on an m7i.4xlarge; campaign 14 re-ran Exps. 2-5 on an m7i.8xlarge and
    # not it, so it is named on its own rather than mixed into "rest".
    "scope": "exp9redact",
}


def _newest_record(records: list, prefix: str):
    """The whole record `_latest` reads its cells from, or None."""
    hits = [r for r in records
            if str(r.get("experiment", "")) == prefix
            or str(r.get("experiment", "")).startswith(prefix + "-")]
    return sorted(hits, key=lambda r: str(r.get("started_utc", "")))[-1] if hits else None


def setup_instance(records: list, which: str) -> str:
    """The instance type of the record each cell actually reads.

    `ingest`, `anchor`, `custody`, `tamper`, `redaction`: that experiment's
    newest record.
    `rest`: every other experiment SPEC reads, which must agree. `other` is
    the pre-campaign-08 meaning, everything but Exp. 1; it is withdrawn.

    ⚠️ Until 2026-10-13 this read **every** AWS record ever kept, superseded
    ones included, so a re-run on a new instance type disagreed with its own
    predecessor. A cell describes the record its neighbours were read from.
    """
    rs = _aws(records)
    if which in SETUP_INSTANCE_OF:
        r = _newest_record(rs, SETUP_INSTANCE_OF[which])
        if r is None:
            raise KeyError(f"no AWS {SETUP_INSTANCE_OF[which]} record")
        return str(r["instance_type"])
    named = set(SETUP_INSTANCE_OF.values())
    if which == "other":
        named = {"exp1"}
    elif which != "rest":
        raise ValueError(f"no instance class {which!r}")
    prefixes = {p for p, _, _ in SPEC.values() if p != "*" and not p.endswith("*")} - named
    types = {str(r["instance_type"]) for p in prefixes
             if (r := _newest_record(rs, p)) is not None}
    return _one(types, f"{which} instance type")


def setup_host(records: list, what: str) -> str:
    """CPU model or kernel, the same on every AWS record."""
    return _tex(" ".join(_one({str(r[what]) for r in _aws(records)}, what).split()))


def setup_iterations_min(records: list) -> str:
    """The fewest iterations any AWS record's points were taken over."""
    return fmt_int(min(int(r["iterations"]) for r in _aws(records)))


def setup_manifest(name: str, what: str) -> str:
    """From `datasets/<name>.sha256`: the file it pins, or its SHA-256 prefix."""
    path = Path(__file__).resolve().parents[1] / "datasets" / f"{name}.sha256"
    rows = [ln.split() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if what == "files":
        return ", ".join(BS + "texttt{" + _tex(f) + "}" for _, f in rows)
    return ", ".join(BS + "texttt{" + h[:16] + "}" for h, _ in rows)


def _exp7_median(m: dict) -> tuple:
    med = m["median_configuration"]
    rows = [r for r in m["n_axis_rows"] if int(r["records"]) == int(med["records"])
            and int(r["range_width_pct"]) == int(med["range_width_pct"])]
    if len(rows) != 1:
        raise KeyError("exp7 has no n-axis row at its median configuration")
    return med, rows[0]


def exp7_median_ms(m: dict, arm: str) -> str:
    _, r = _exp7_median(m)
    if arm == "ours":
        return fmt_ms(_median_ns(r["pi_range"]["search_ns"]))
    if arm == "cold":
        return fmt_ms(r["zuo22"]["cold_search_ns"])
    return fmt_ms(_median_ns(r["zuo22"]["warm_search_ns"]))


def exp7_median_boolean(m: dict, form: str) -> str:
    med, _ = _exp7_median(m)
    if int(med["boolean_forms_measured_at"]) != int(med["records"]):
        raise ValueError("exp7 Boolean forms were not measured at the median configuration")
    return exp7_boolean_us(m, form)


def exp7_median_index(m: dict, whose: str) -> str:
    med, _ = _exp7_median(m)
    rows = [r for r in m["index_sizes"] if int(r["depth"]) == int(med["depth"])]
    if len(rows) != 1:
        raise KeyError("exp7 has no index_sizes row at the median depth")
    key = "index_ratio_milli" if whose == "ours" else "zuo_index_ratio_milli"
    return fmt_ratio(rows[0][key] / 1000.0)



#: `tab:exp-anchor`'s axis, entries (MMR leaves) per epoch, and the macro
#: suffix for each point.
ANCHOR_AXIS = (("Hundred", 10**2), ("Kilo", 10**3), ("TenKilo", 10**4),
               ("HundredKilo", 10**5), ("Mega", 10**6))


#: macro name -> (experiment prefix, extractor, one-line description).
#: A prefix ending in `*` hands the extractor every matching record whole
#: (the Doris carve-out records carry their rows at top level).
SPEC: dict = {
    # tab:exp-ingest
    "pqclExpOneThroughputPlain": (
        "exp1", exp1_plain_ceiling, "ingest: plaintext ceiling (ordered index), events/s"),
    "pqclIngestOursOverCeiling": (
        "exp1", exp1_ours_over_ceiling, "ingest: ours kw AND range over the ceiling"),
    "pqclIngestOdxt": (
        "exp1", lambda m: exp1_h2h_throughput(m, "ODXT", "keyword"), "ingest: ODXT events/s"),
    "pqclIngestOursOverOdxt": (
        "exp1", lambda m: exp1_h2h_speed_ratio(m, "ODXT", "keyword"), "ingest: ours over ODXT"),
    "pqclIngestOursKeyword": (
        "exp1", lambda m: exp1_h2h_throughput(m, "PQ-ChainLog", "keyword"), "ingest: ours keyword events/s"),
    "pqclIngestZuo": (
        "exp1", lambda m: exp1_h2h_throughput(m, "Zuo22", "range"), "ingest: Zuo'22 events/s"),
    "pqclIngestOursOverZuo": (
        "exp1", lambda m: exp1_h2h_speed_ratio(m, "Zuo22", "range"), "ingest: ours over Zuo'22"),
    "pqclIngestOursRange": (
        "exp1", lambda m: exp1_h2h_throughput(m, "PQ-ChainLog", "range"), "ingest: ours range events/s"),
    "pqclIngestComposed": (
        "exp1", lambda m: exp1_h2h_throughput(m, "ODXT+Zuo22", "keyword+range"), "ingest: ODXT+Zuo'22 events/s"),
    "pqclIngestOursOverComposed": (
        "exp1", lambda m: exp1_h2h_speed_ratio(m, "ODXT+Zuo22", "keyword+range"), "ingest: ours over ODXT+Zuo'22"),
    "pqclIngestOursBoth": (
        "exp1", lambda m: exp1_h2h_throughput(m, "PQ-ChainLog", "keyword+range"), "ingest: ours kw AND range events/s"),
    "pqclIngestOperatingY": ("exp1", lambda m: ingest_y(m, "operating"), "ingest caption: operating y"),
    "pqclIngestLargestY": ("exp1", lambda m: ingest_y(m, "largest"), "ingest caption: largest y measured"),
    "pqclIngestRangeRatioAtLargestY": (
        "exp1", ingest_range_ratio_at_largest, "ingest caption: our range ratio at the largest y"),
    # tab:abl-sign
    "pqclExpOneThroughputClassical": (
        "exp1", lambda m: exp1_classical(m, 1), "abl-sign: ECDSA-P256 B=1 events/s"),
    "pqclExpOneThroughputBOne": (
        "exp1", lambda m: exp1_throughput(m, 1), "abl-sign: ML-DSA B=1 events/s"),
    "pqclExpOneThroughputBSixtyFour": (
        "exp1", lambda m: exp1_throughput(m, 64), "abl-sign: ML-DSA B=64 events/s"),
    "pqclExpOneThroughputBKilo": (
        "exp1", lambda m: exp1_throughput(m, 1024), "abl-sign: ML-DSA B=1024 events/s"),
    "pqclExpOneRatioPqOverClassical": (
        "exp1", lambda m: exp1_pq_over_classical(m, 1), "abl-sign: ML-DSA over ECDSA at B=1, time"),
    "pqclExpOneRatioBSixtyFour": (
        "exp1", lambda m: exp1_vs_ecdsa(m, 64), "abl-sign: B=64 time over ECDSA B=1"),
    "pqclExpOneRatioBKilo": (
        "exp1", lambda m: exp1_vs_ecdsa(m, 1024), "abl-sign: B=1024 time over ECDSA B=1"),
    "pqclAccessControlK": (
        "exp1", exp1_k, "k, indexed tokens per event with range indexing (observed = derived)"),
    # prose figures (no table cell)
    "pqclExpTwoSpeedupSmall": (
        "exp2", lambda m: exp2_speedup(m, 1000, 2), "Exp.2 Pi_XT over ODXT, 1e3 docs, width 2"),
    "pqclExpTwoSpeedupLarge": (
        "exp2", lambda m: exp2_speedup(m, 20000, 6), "Exp.2 Pi_XT over ODXT, 2e4 docs, width 6"),
    "pqclExpFiveDroppedLoose": (
        "exp5", lambda m: exp5_dropped(m, 1e-1, 16), "Exp.5 true matches dropped at eps=1e-1, E=16"),
    "pqclExpFiveDroppedDefault": (
        "exp5", lambda m: exp5_dropped(m, 1e-3, 16), "Exp.5 true matches dropped at eps=1e-3, E=16"),
    "pqclExpSixAnchorSignUs": (
        "exp6", exp6_sign_us, "Exp.6 ML-DSA anchor signing, microseconds"),
    "pqclExpSixProofBytes": (
        "exp6", exp6_proof_bytes, "Exp.6 MMR inclusion proof, bytes"),
    # tab:exp-anchor -- on-chain receipt gas, both sides; axis in MMR leaves
    "pqclExpSixGasPerAnchor": (
        "exp6chain", exp6c_anchor_gas, "anchor: gas per anchor, on-chain steady state"),
    "pqclAnchorPerEventGas": ("exp6chain", exp6c_lechain_gas, "anchor: per-event commitment gas per record"),
    "pqclAnchorPerEventRate": ("exp6chain", exp6c_lechain_rate, "anchor: per-event commitment records/s"),
    "pqclAnchorPerEventCeiling": (
        "exp6chain", exp6c_lechain_ceiling,
        "anchor: per-event commitment ceiling, records/s -- a projection from block gas limit, gas per transition and block period"),
    # §1as.3.2: rule 21's crossover bracket, two measured axis points each
    **{f"pqclAnchorCross{name}{side.title()}": (
        "exp6chain", (lambda k, s: lambda m: exp6c_cross(m, k, s))(key, side),
        f"anchor: {side} measured epoch size of the {name.lower()}-co-signer crossing of the per-event rate")
       for name, key in (("Parallel", "ours"), ("Single", "ours_single_worker"))
       for side in ("low", "high")},
    **{f"pqclExpSixGasPerEntry{k}": ("exp6chain", (lambda nn: lambda m: exp6c_gas_per_entry(m, nn))(n),
                                     f"anchor: gas/entry at {n}")
       for k, n in ANCHOR_AXIS},
    **{f"pqclAnchorPerEventOverOurs{k}": ("exp6chain", (lambda nn: lambda m: exp6c_per_event_over_ours(m, nn))(n),
                                          f"anchor: per-event gas over ours at {n}")
       for k, n in ANCHOR_AXIS},
    **{f"pqclAnchorRateRatio{k}": ("exp6chain", (lambda nn: lambda m: exp6c_speed_ratio(m, nn))(n),
                                   f"anchor: ours over per-event records/s at {n}")
       for k, n in ANCHOR_AXIS},
    **{f"pqclAnchorPerEventRate{k}": ("exp6chain", (lambda nn: lambda m: exp6c_lechain_point_rate(m, nn))(n),
                                      f"anchor: per-event records/s on the stream the {n} point divides by")
       for k, n in ANCHOR_AXIS},
    # SAC Exp. 1's second arm (§1ci.1): B-DEMS's per-transaction workflow
    "pqclAnchorBdemsGas": ("exp6chain", exp6c_bdems_gas, "anchor: B-DEMS gas per custody record, steady state"),
    "pqclAnchorBdemsRate": ("exp6chain", exp6c_bdems_rate, "anchor: B-DEMS custody records/s, steady state"),
    **{f"pqclAnchorBdemsOverOurs{k}": ("exp6chain", (lambda nn: lambda m: exp6c_bdems_over_ours(m, nn))(n),
                                       f"anchor: B-DEMS gas per record over ours at {n}")
       for k, n in ANCHOR_AXIS},
    **{f"pqclAnchorBdemsRateRatio{k}": ("exp6chain", (lambda nn: lambda m: exp6c_bdems_rate_ratio(m, nn))(n),
                                        f"anchor: ours over B-DEMS records/s at {n}")
       for k, n in ANCHOR_AXIS},
    # §1ck.2: B-DEMS wins below the bracket, so the floor and the crossings are cells
    "pqclAnchorBdemsFloorRatio": ("exp6chain", exp6c_bdems_floor_ratio,
                                  "anchor: ours (parallel) over B-DEMS records/s at the smallest measured epoch size"),
    **{f"pqclAnchorBdemsCross{name}{side.title()}": (
        "exp6chain", (lambda k, s: lambda m: exp6c_cross(m, k, s, "bdems"))(key, side),
        f"anchor: {side} measured epoch size of the {name.lower()}-co-signer crossing of B-DEMS's rate")
       for name, key in (("Parallel", "ours"), ("Single", "ours_single_worker"))
       for side in ("low", "high")},
    # tab:exp-size
    "pqclSizeOxt": ("doris-structural*", lambda rs: doris_bpp(rs, "OXT"), "size: OXT B/pair, 1e6 Enron"),
    "pqclSizeHxt": ("doris-structural*", lambda rs: doris_bpp(rs, "HXT"), "size: HXT B/pair, 1e6 Enron"),
    "pqclSizeConjFilter": ("doris-structural*", lambda rs: doris_bpp(rs, "ConjFilter"), "size: ConjFilter B/pair"),
    "pqclSizeDoris": ("doris-structural*", lambda rs: doris_bpp(rs, "Doris"), "size: Doris B/pair, 1e6 Enron"),
    "pqclSizeOdxt": ("index-size", lambda m: size_bpp(m, "odxt"), "size: ODXT B/pair (Bloom at delta=1e-3)"),
    "pqclSizeOursExact": ("index-size", lambda m: size_bpp(m, "ours_exact"), "size: ours exact XSet B/pair"),
    "pqclSizeOursBloom": ("index-size", lambda m: size_bpp(m, "ours_bloom"), "size: ours Bloom XSet B/pair"),
    # tab:exp-range -- the median configuration of fig:exp-range
    "pqclExpSevenLatencyConjunction": (
        "exp7", lambda m: exp7_median_boolean(m, "w1 AND w2"), "range: w1 AND w2, ms"),
    "pqclExpSevenLatencyDisjunction": (
        "exp7", lambda m: exp7_median_boolean(m, "w1 AND (w2 OR w3)"), "range: w1 AND (w2 OR w3), ms"),
    "pqclExpSevenLatencyNegation": (
        "exp7", lambda m: exp7_median_boolean(m, "w1 AND NOT w2"), "range: w1 AND NOT w2, ms"),
    "pqclExpSevenRangeMs": ("exp7", lambda m: exp7_median_ms(m, "ours"), "range: Pi_RANGE, ms"),
    "pqclExpSevenZuoColdMs": ("exp7", lambda m: exp7_median_ms(m, "cold"), "range: Zuo'22 cold, ms"),
    "pqclExpSevenZuoWarmMs": ("exp7", lambda m: exp7_median_ms(m, "warm"), "range: Zuo'22 warm, ms"),
    "pqclExpSevenLatencyConjRange": (
        "exp7", lambda m: exp7_median_boolean(m, "w1 AND range"), "range: w1 AND range, ms"),
    "pqclExpSevenIndexRange": ("exp7", lambda m: exp7_median_index(m, "ours"), "range: index growth, ours"),
    "pqclExpSevenIndexZuo": ("exp7", lambda m: exp7_median_index(m, "zuo"), "range: index growth, Zuo'22"),
    # tab:exp-leak -- ODXT Attr. | Pi_XT Attr. | Pi_XT Link | Pi_CD Vol.
    **{f"pqclLeak{s}{q}": ("exp3", (lambda qq, ss: lambda m: leak_count(m, qq, ss))(qn, sk),
                            f"leak: {sk} at {qn} queries")
       for q, qn in (("One", 1), ("Ten", 10), ("Fifty", 50))
       for s, sk in (("OdxtAttr", "odxt_attr"), ("XtAttr", "xt_attr"), ("XtLink", "xt_link"), ("CdVol", "cd_vol"))},
    # tab:exp-custody -- caption case size; Proof (B) | Verify (us) | Audit (s)
    "pqclCustodyCaseSize": ("custody-disclosure", custody_case_size, "custody caption: case size, records"),
    **{f"pqclCustody{s}{w}": ("custody-disclosure", (lambda ss, ww: lambda m: custody_largest(m, ss, ww))(sk, wk),
                               f"custody: {sk} {wk}")
       for s, sk in CUSTODY_CELL_ARMS
       for w, wk in (("Bytes", "bytes"), ("VerifyUs", "verify"))},
    **{f"pqclCustody{s}AuditS": ("custody-disclosure", (lambda ss: lambda m: custody_audit_s(m, ss))(sk),
                                  f"custody: {sk} full-case audit, s")
       for s, sk in CUSTODY_CELL_ARMS},
    **{f"pqclCustody{s}AuditAllS": ("custody-disclosure", (lambda ss: lambda m: custody_audit_all_s(m, ss))(sk),
                                     f"custody: {sk} full-case audit, all cores, s")
       for s, sk in CUSTODY_CELL_ARMS},
    # SAC tab:exp-redaction / tab:exp-redact-matrix (§1cf.2): T1 gas and latency,
    # the court's check at \pqclCustodyCaseSize, the T2 accept counts
    **{f"pqclRedactGas{a}{k}": ("sac-redaction", (lambda aa, kk: lambda m: redact_gas(m, aa, kk))(ak, kn),
                                 f"redaction: {ak} total gas at k = {kn}")
       for a, ak in REDACT_ARMS for k, kn in REDACT_K},
    **{f"pqclRedactLatMs{a}{k}": ("sac-redaction", (lambda aa, kk: lambda m: redact_lat_ms(m, aa, kk))(ak, kn),
                                   f"redaction: {ak} latency at k = {kn}, ms")
       for a, ak in REDACT_ARMS for k, kn in REDACT_K},
    **{f"pqclRedactVerifyUs{a}": ("sac-redaction", (lambda aa: lambda m: redact_verify_us(m, aa))(ak),
                                   f"redaction: {ak} post-redaction check at the largest case, us")
       for a, ak in REDACT_ARMS},
    **{f"pqclRedactMatrix{a}{r}": ("sac-redaction", (lambda aa, rr: lambda m: redact_matrix(m, aa, rr))(ak, rk),
                                    f"redaction: {ak} {rk}, accepted of 100")
       for a, ak in REDACT_ARMS for r, rk in REDACT_ROWS},
    # §1ci.2/§1ci.6: PQ-ABL's invalidated proofs, its one-epoch series, the case
    "pqclRedactInvalidatedPqabl": ("sac-redaction", lambda m: redact_invalidated(m, False),
                                   "redaction: records whose proofs a one-capsule PQ-ABL deletion invalidates, largest case"),
    "pqclRedactInvalidatedPqablOneEpoch": ("sac-redaction", lambda m: redact_invalidated(m, True),
                                           "redaction: the same, whole case in one epoch (beyond PQ-ABL's evaluated range)"),
    **{f"pqclRedactLatMsPqablOneEpoch{k}": ("sac-redaction", (lambda kk: lambda m: redact_one_epoch(m, "lat", kk))(kn),
                                            f"redaction: PQ-ABL latency at k = {kn}, one epoch, ms")
       for k, kn in REDACT_K},
    **{f"pqclRedactGasPqablOneEpoch{k}": ("sac-redaction", (lambda kk: lambda m: redact_one_epoch(m, "gas", kk))(kn),
                                          f"redaction: PQ-ABL total gas at k = {kn}, one epoch")
       for k, kn in REDACT_K},
    "pqclRedactLatMsOursOneEpochOne": ("sac-redaction", lambda m: redact_one_epoch(m, "lat", 1, "ours"),
                                       "redaction: ours latency at k = 1, the same one-epoch layout, ms (§1ck.2)"),
    # §1ck.2: GlassDB's range over this record's cases, live and redacted
    **{f"pqclCustodyGlass{w}{e.title()}": ("custody-disclosure", (lambda ww, ee: lambda m: custody_glass_range(m, ww, ee))(wk, e),
                                           f"custody: GlassDB {wk} {e} over every case, live and redacted (one draw each)")
       for w, wk in (("Bytes", "bytes"), ("VerifyUs", "verify"))
       for e in ("min", "max")},
    "pqclRedactCaseSize": ("sac-redaction", redact_case_size, "redaction: the largest case, records"),
    "pqclCaseEpochRecords": ("custody-disclosure", case_epoch_records, "records per sealing epoch, Exp. 2 and Exp. 4"),
    # tab:exp-ingest caption (0,3)/(0,4): the measured y bracketing the crossover
    "pqclIngestCrossLowY": ("exp1", lambda m: range_crossover_bracket(m, "low"),
                            "ingest caption: measured y just below the range crossover"),
    "pqclIngestCrossHighY": ("exp1", lambda m: range_crossover_bracket(m, "high"),
                             "ingest caption: measured y just above the range crossover"),
    # tab:exp-range row 9 -- index MB at the largest y (§1o.4)
    "pqclRangeIndexMbOurs": ("exp1", lambda m: ingest_index_mb_at_largest_y(m, "ours"),
                             "range: our index MB at the largest y, measured"),
    "pqclRangeIndexMbZuo": ("exp1", lambda m: ingest_index_mb_at_largest_y(m, "zuo"),
                            "range: Zuo'22 index MB at the largest y, measured"),
    # tab:exp-tamper -- each cell carries its own unit
    "pqclTamperRestOurs": ("exp8-tamper-response", lambda m: tamper_detect(m, "payload_at_rest", "ours_sampled_sweep"), "tamper: at rest, sweep"),
    "pqclTamperRehash": ("exp8-tamper-response", lambda m: tamper_detect(m, "payload_at_rest", "full_rehash_same_budget"), "tamper: full re-hash at the same budget"),
    "pqclTamperReadOurs": ("exp8-tamper-response", lambda m: tamper_detect(m, "payload_then_read", "ours_q2_chunk_on_read"), "tamper: then read, chunk on read"),
    "pqclTamperReadAccess": ("exp8-tamper-response", lambda m: tamper_detect(m, "payload_then_read", "flat_verify_on_access"), "tamper: then read, flat verify-on-access"),
    "pqclTamperEditOurs": ("exp8-tamper-response", lambda m: tamper_detect(m, "custody_record_edited", "ours_epoch_auditor"), "tamper: record edited, auditor"),
    "pqclTamperEditAccess": ("exp8-tamper-response", lambda m: tamper_detect(m, "custody_record_edited", "verify_on_access"), "tamper: record edited, on access"),
    "pqclTamperBudget": ("exp8-tamper-response", lambda m: tamper_param(m, "budget"), "tamper caption: read budget"),
    "pqclTamperPeriod": ("exp8-tamper-response", lambda m: tamper_param(m, "period"), "tamper caption: audit period"),
    "pqclTamperAdmissible": ("exp8-tamper-response", lambda m: tamper_param(m, "admissible"), "tamper caption: share admissible after one chunk"),
    "pqclTamperOmitOurs": ("exp8-tamper-response", lambda m: tamper_detect(m, "agent_epoch_omitted", "ours_epoch_la_id_contiguity"), "tamper: epoch omitted, contiguity"),
    # M13 A6/A9/A11/A19
    "pqclTamperTailOurs": ("exp8-tamper-response", lambda m: tamper_tail(m, "detect"), "tamper: last epoch dropped, heartbeat"),
    "pqclTamperTailContiguity": ("exp8-tamper-response", lambda m: tamper_tail(m, "contiguity"), "tamper: last epoch dropped, trials contiguity caught"),
    "pqclTamperHeartbeat": ("exp8-tamper-response", lambda m: tamper_tail(m, "heartbeat"), "tamper caption: heartbeat period T"),
    "pqclTamperAdmissibleRange": ("exp8-tamper-response", tamper_admissible_range, "tamper caption: per-artefact share admissible after one chunk, observed"),
    **{f"pqclTamper{cell}{stat.title().replace('P95', 'PNinetyFive')}": (
        "exp8-tamper-response", (lambda k, a, s: lambda m: tamper_stat(m, k, a, s))(klass, arm, stat),
        f"tamper: {klass}/{arm} {stat}")
       for cell, klass, arm in (("RestOurs", "payload_at_rest", "ours_sampled_sweep"),
                                ("Rehash", "payload_at_rest", "full_rehash_same_budget"))
       for stat in ("mean", "p95")},
    # §1v.4 -- Exp. 8 "Payload deleted"; Exp. 6 caption; Exp. 7 redacted block
    "pqclTamperDeletedOurs": ("exp8-tamper-response", lambda m: tamper_detect(m, "payload_deleted", "ours_0x05_accounting"), "tamper: payload deleted, 0x05 accounting"),
    "pqclTamperDeletedRehash": ("exp8-tamper-response", lambda m: tamper_detect(m, "payload_deleted", "full_rehash_same_budget"), "tamper: payload deleted, re-hash with the deletion list"),
    "pqclAnchorDisposePct": ("exp6chain", exp6c_dispose_pct, "anchor caption: capsules disposed, realised"),
    "pqclAnchorOrderEpochPct": ("exp6chain", exp6c_order_epoch_pct, "anchor caption: epochs carrying an order, range across the axis"),
    "pqclAnchorLeavesPerRecord": ("exp6chain", exp6c_leaves_per_record, "anchor caption: Tier-2 leaves per custody record, range across the axis"),
    "pqclCustodyKeywordsPerRecord": ("exp6chain", exp6c_custody_keywords, "custody plane: Pi_core updates per record, the index set of draft8 Phase 6 Step 4"),
    "pqclAnchorParallelFloorEpoch": ("exp6chain", exp6c_floor_epoch, "anchor: smallest measured epoch size of the parallel series"),
    "pqclAnchorParallelFloorRatio": ("exp6chain", exp6c_floor_ratio, "anchor: ours over per-event records/s at that smallest size, parallel co-signers"),
    "pqclAnchorIngestUsPerRecord": ("exp6chain", exp6c_ingest_us_per_record, "anchor: ingest us per record through the Secure Module, parallel series, range over the axis"),
    "pqclCustodyAppendUs": ("custody-disclosure", custody_append_us, "custody: one record appended through the Secure Module (build, seal, sign, 29 tokens), us"),
    "pqclCustodyRecordVerifyUs": ("custody-disclosure", custody_record_verify_us, "custody: one record's ML-DSA-65 verify, us, paid by every scheme per disclosed record"),
    **{f"pqclCustody{s}Redacted{w}": ("custody-disclosure", (lambda ss, ww: lambda m: custody_redacted(m, ss, ww))(sk, wk),
                                      f"custody: {sk} redacted capsule {wk}")
       for s, sk in CUSTODY_CELL_ARMS
       for w, wk in (("Bytes", "bytes"), ("VerifyUs", "verify"))},
    # §1aa.5 -- sec:setup prose, from every AWS record (prefix "*") and the
    # dataset manifests. No warm-up count: no harness runs warm-ups.
    "pqclSetupInstanceIngest": ("*", lambda rs: setup_instance(rs, "ingest"), "setup: Exp. 1 instance type"),
    "pqclSetupInstanceOther": ("*", lambda rs: setup_instance(rs, "other"), "setup: every other experiment's instance type"),
    **{f"pqclSetupInstance{w.title()}": ("*", (lambda ww: lambda rs: setup_instance(rs, ww))(w),
                                         f"setup: {w} instance type, from the record its cells read")
       for w in ("conj", "anchor", "custody", "tamper", "redaction", "scope", "rest")},
    "pqclSetupCpu": ("*", lambda rs: setup_host(rs, "cpu_model"), "setup: CPU model, every AWS record"),
    "pqclSetupKernel": ("*", lambda rs: setup_host(rs, "kernel"), "setup: kernel, every AWS record"),
    "pqclSetupIterationsMin": ("*", setup_iterations_min, "setup: fewest iterations behind any point"),
    "pqclSetupEnronFile": ("*", lambda _rs: setup_manifest("enron", "files"), "setup: Enron release"),
    "pqclSetupEnronSha": ("*", lambda _rs: setup_manifest("enron", "sha"), "setup: Enron SHA-256 prefix"),
    "pqclSetupArtefactFiles": ("*", lambda _rs: setup_manifest("artefacts", "files"), "setup: Digital Corpora artefacts"),
    "pqclSetupArtefactSha": ("*", lambda _rs: setup_manifest("artefacts", "sha"), "setup: artefact SHA-256 prefixes"),
    # §1v.5 -- Exp. 9, tab:exp-redaction and tab:exp-redact-detect
    **{f"pqclRedact{r}{c}": ("exp9redact", (lambda rr, cc: lambda m: exp9_cell(m, rr, cc))(rk, ck),
                             f"redaction: {rk} {ck} at 10^5 pairs")
       for r, rk in EXP9_ROWS
       for c, ck in (("EraseMs", "erase"), ("Residual", "residual"), ("SearchMs", "search"))},
    **{f"pqclRedactSweep{s}": ("exp9redact", (lambda kk: lambda m: exp9_sweep(m, kk))(k),
                               f"redaction: ours FULL erase at k = {k}")
       for s, k in (("Ten", 10), ("Hundred", 100), ("Thousand", 1000))},
    **{f"pqclRedactOrderGas{s}": ("exp6chain", (lambda kk: lambda m: exp9_order_gas(m, kk))(k),
                                  f"redaction caption: order gas at k = {k}")
       for s, k in (("One", 1), ("Thousand", 1000))},
    "pqclRedactDetectN": ("exp9redact", lambda m: fmt_int(int(m["detection"]["n"])), "redact-detect caption: deletions per cell"),
    **{f"pqclRedactDetect{s}{a}": ("exp9redact", (lambda ss, aa: lambda m: exp9_detect(m, ss, aa))(sk, ak),
                                   f"redact-detect: {sk} {ak}")
       for s, sk in (("Benign", "benign_ais"), ("Compromised", "compromised_ais"))
       for a, ak in (("Ours", "ours_0x05"), ("Rehash", "rehash_with_list"))},
}


#: The SPEC prefix for Exp. 2 cells that need the Doris follow-up: pass 1's
#: `exp2-conjunctive-latency` with pass 2's per-tier `m15-doris-fu-search` records
#: merged into its rows (fix A).
EXP2_WITH_DORIS = "exp2+doris-fu"
DORIS_FU_EXPERIMENT = "m15-doris-fu-search"


def exp2_with_doris(records: list):
    """Pass 1's newest record, with each pass-2 cell placed in its (documents, width)
    row. ⛔ Refuses loudly (SystemExit, which `render`'s `except Exception` does not
    swallow) when a pass-2 record comes from another commit or instance type, drew
    another query set, names a row pass 1 lacks, or carries an oracle mismatch."""
    mains = [r for _, r in records if r.get("experiment") == "exp2-conjunctive-latency"]
    dorises = [r for _, r in records if r.get("experiment") == DORIS_FU_EXPERIMENT]
    if not mains:
        return None
    main = sorted(mains, key=lambda r: str(r.get("started_utc", "")))[-1]
    merged = json.loads(json.dumps(main.get("measurements", {})))
    if not dorises:
        # Pass 1 alone: its rows, with no Doris cell (exp-conj still draws; the Doris
        # macros then have nothing to read and refuse as pending).
        return merged
    want_q = merged.get("workload", {}).get("queries_by_width")
    cells: dict = {}
    for d in sorted(dorises, key=lambda r: str(r.get("started_utc", ""))):
        for key in ("git_sha", "instance_type"):
            if d.get(key) != main.get(key):
                raise SystemExit(f"refusing to merge {DORIS_FU_EXPERIMENT}: its {key} {d.get(key)!r} "
                                 f"differs from exp2's {main.get(key)!r} (pass 2 must run on pass 1's host and commit)")
        m = d.get("measurements", {})
        if m.get("oracle_mismatch"):
            raise SystemExit(f"refusing to merge {DORIS_FU_EXPERIMENT}: the Doris follow-up disagreed "
                             f"with the oracle: {m['oracle_mismatch']}")
        if m.get("workload", {}).get("queries_by_width") != want_q:
            raise SystemExit(f"refusing to merge {DORIS_FU_EXPERIMENT}: its query set differs from exp2's")
        for row in m.get("rows", []):
            cells[(int(row["documents"]), int(row["conjunction_width"]))] = row["doris_fu"]  # newest wins
    rows = {(int(r["documents"]), int(r["conjunction_width"])): r for r in merged.get("rows", [])}
    for key, cell in cells.items():
        if key not in rows:
            raise SystemExit(f"refusing to merge {DORIS_FU_EXPERIMENT}: exp2 has no row at {key}")
        rows[key]["doris_fu"] = cell
    return merged


def _latest(records: list, prefix: str):
    """The most recent record whose experiment name starts with `prefix`."""
    # ⛔ `startswith` alone is wrong: "exp10-integrity-audit" starts with
    # "exp1", so every Exp.1 cell silently read Exp.10's record and reported a
    # missing field. Caught by the (since removed, §1an.3) coverage report on
    # its first run. Require the prefix to end at a separator.
    # ⚠️ M10: `exp8-verified-mode` and `exp8-tamper-response` share the
    # prefix `exp8`, the same collision as exp10/exp1 -- so the tamper cells
    # name their experiment in full, and an exact name always wins here.
    if prefix == EXP2_WITH_DORIS:
        return exp2_with_doris(records)
    if prefix.endswith("*"):
        # Whole records, every match: the Doris carve-out records carry their
        # rows at top level, and its tier-4 schemes are separate records.
        base = prefix[:-1]
        whole = [r for _, r in records if str(r.get("experiment", "")).startswith(base)]
        return whole or None
    hits = [
        r
        for _, r in records
        if str(r.get("experiment", "")) == prefix
        or str(r.get("experiment", "")).startswith(prefix + "-")
    ]
    if not hits:
        return None
    newest = sorted(hits, key=lambda r: str(r.get("started_utc", "")))[-1]
    return newest.get("measurements", {})


def coverage(records: list) -> list:
    """`(macro, status, detail)` for every cell, sourced or not.

    ⚠️ Deliberately runs on **any** record, publishable or not. It reports
    whether a field *exists*, never what it holds, so pointing it at local runs
    is safe — and is exactly the pre-campaign check it exists for.
    """
    out = []
    for macro, why in sorted(UNSOURCED.items()):
        out.append((macro, "NO SOURCE", why))
    for macro, (prefix, fn, desc) in sorted(SPEC.items()):
        m = _latest(records, prefix)
        if m is None:
            out.append((macro, "NO RECORD", desc + f" — no {prefix} record found"))
            continue
        try:
            fn(m)
        except Exception as exc:  # noqa: BLE001
            out.append(
                (macro, "FIELD MISSING", f"{desc} — {type(exc).__name__}: {exc}")
            )
        else:
            out.append((macro, "ok", desc))
    return out


# --- M14: draft9's 2023+ comparators ----------------
#: The record key of each SDSSE arm, and its macro stem.
SDSSE_ARMS = (("Cq", "sdsse_cq"), ("CqS", "sdsse_cq_s"))
#: `Exp. 2`'s points, the same as ODXT's macros plus the top tier.
EXP2_POINTS = (("Small", 1000, 2), ("Large", 20000, 6))


def _exp2_row(m: dict, documents: int | None, width: int) -> dict:
    rows = [r for r in m["rows"] if int(r["conjunction_width"]) == width]
    top = documents if documents is not None else max(int(r["documents"]) for r in rows)
    for r in rows:
        if int(r["documents"]) == top:
            return r
    raise KeyError(f"exp2 has no row for documents={top}, width={width}")


def exp2_sdsse_ratio(m: dict, documents: int | None, width: int, arm: str, mode: str) -> str:
    """Their search time over ours, Pi_XT: above 1 favours us. `mode` is `first` or
    `repeat`, kept apart because Aura's second search reads a cache (§1cu.2)."""
    r = _exp2_row(m, documents, width)
    theirs = _median_ns(r[arm][f"{mode}_search_ns"])
    return fmt_ratio(theirs / _median_ns(r["pi_xt"]["search_ns"]))


def exp2_sdsse_ms(m: dict, documents: int | None, width: int, arm: str, mode: str) -> str:
    return fmt_ms(_median_ns(_exp2_row(m, documents, width)[arm][f"{mode}_search_ns"]))


def exp2_top_documents(m: dict) -> str:
    return fmt_int(max(int(r["documents"]) for r in m["rows"]))


def exp2_ours_ms_top(m: dict, width: int) -> str:
    return fmt_ms(_median_ns(_exp2_row(m, None, width)["pi_xt"]["search_ns"]))


def exp2_shortfall(m: dict, arm: str) -> str:
    """Results a Bloom false positive lost, over every cell: the scheme allows them
    at rate `p`, and they are reported, not hidden."""
    return fmt_int(sum(int(r[arm]["oracle_shortfall_bloom_false_positives"]) for r in m["rows"]))


def exp2_max_x_updates(m: dict, arm: str) -> str:
    """The most updates of any x-term at the top tier: what SDSSE's search fetches,
    and so what its cost follows (its Fig. 3; §1cs.4 item 2)."""
    top = max(int(r["documents"]) for r in m["rows"])
    vols = [v for r in m["rows"] if int(r["documents"]) == top
            for q in r[arm]["term_updates_per_query"] for v in q[1:]]
    return fmt_int(max(int(v) for v in vols))


def size_arm_bpp(m: dict, arm: str) -> str:
    """Bytes per pair at 10^6 Enron pairs, counted from the real structure."""
    r = _size_row(m)
    a = r[arm]
    return f"{(int(a['tset_bytes']) + int(a['xset_bytes'])) / int(r['pairs']):.1f}"


def size_doris_fu_tags(m: dict) -> str:
    return fmt_int(int(_size_row(m)["doris_fu"]["xset_tags"]))


def exp7_skq_ms(m: dict, mode: str) -> str:
    _, r = _exp7_median(m)
    if mode == "cold":
        return fmt_ms(r["dsse_skq"]["cold_search_ns"])
    return fmt_ms(_median_ns(r["dsse_skq"]["warm_search_ns"]))


def exp7_skq_form_ms(m: dict, form: str, mode: str) -> str:
    med, _ = _exp7_median(m)
    if int(med["boolean_forms_measured_at"]) != int(med["records"]):
        raise ValueError("exp7 Boolean forms were not measured at the median configuration")
    for row in m["boolean_forms_dsse_skq"]:
        if row["form"] == form:
            if mode == "cold":
                return fmt_ms(row["cold_total_ns"])
            return fmt_ms(_median_ns(row["warm_total_ns"]))
    raise KeyError(f"exp7 has no DSSE_SKQ row for {form!r}")


def exp7_skq_crossover(m: dict, mode: str, which: str) -> str:
    """`sec:exp-range`: the two MEASURED collection sizes that bracket where
    DSSE_SKQ's `mode` (cold or warm) range latency crosses ours, at the median
    range width (rule 21). Refuses unless it crosses exactly once."""
    med, _ = _exp7_median(m)
    width = int(med["range_width_pct"])
    rows = sorted((r for r in m["n_axis_rows"] if int(r["range_width_pct"]) == width),
                  key=lambda r: int(r["records"]))
    if len({int(r["records"]) for r in rows}) != len(rows) or len(rows) < 2:
        raise KeyError(f"exp7 has no single N axis at {width} %")

    def theirs(r: dict) -> int:
        s = r["dsse_skq"]
        return int(s["cold_search_ns"]) if mode == "cold" else _median_ns(s["warm_search_ns"])

    ratios = [(int(r["records"]), theirs(r) / _median_ns(r["pi_range"]["search_ns"])) for r in rows]
    brackets = [(a[0], b[0]) for a, b in zip(ratios, ratios[1:]) if (a[1] < 1) != (b[1] < 1)]
    if len(brackets) != 1:
        raise KeyError(f"DSSE_SKQ {mode} crosses ours {len(brackets)} times at {width} %")
    return fmt_int(brackets[0][0] if which == "low" else brackets[0][1])


def _skq_rows(m: dict) -> list:
    return sorted((r for r in m["range_ingest_across_y"]["rows"]
                   if not r.get("skipped") and "total_ns" in r.get("dsse_skq", {}).get("range", {})),
                  key=lambda r: int(r["y"]))


def skq_largest_y(m: dict) -> str:
    return fmt_int(int(_skq_rows(m)[-1]["y"]))


def skq_ratio_at_largest(m: dict, qclass: str) -> str:
    """Ours over DSSE_SKQ at the largest y it was measured at: above 1 favours us,
    over passes that indexed the same labels."""
    r = _skq_rows(m)[-1]
    theirs, ours = {"range": ("range", "ours_range"),
                    "both": ("keyword_range", "ours_keyword_range")}[qclass]
    t, o = r["dsse_skq"][theirs], r[ours]
    if int(t["entries"]) != int(o["entries"]):
        raise ValueError(f"exp1 across-y at y = {r['y']}: DSSE_SKQ and ours indexed different work")
    return fmt_ratio(_median_ns(t["total_ns"]) / _median_ns(o["total_ns"]))


def skq_crossover(m: dict, qclass: str, which: str) -> str:
    """The two MEASURED y that bracket where our ratio crosses 1 (rule 21). Refuses
    unless it crosses exactly once: one bracket would misdescribe anything else."""
    theirs, ours = {"range": ("range", "ours_range"),
                    "both": ("keyword_range", "ours_keyword_range")}[qclass]
    ratios = [(int(r["y"]), _median_ns(r["dsse_skq"][theirs]["total_ns"]) / _median_ns(r[ours]["total_ns"]))
              for r in _skq_rows(m)]
    brackets = [(a[0], b[0]) for a, b in zip(ratios, ratios[1:]) if (a[1] < 1) != (b[1] < 1)]
    if len(brackets) != 1:
        raise KeyError(f"ours over DSSE_SKQ crosses 1 {len(brackets)} times across y")
    return fmt_int(brackets[0][0] if which == "low" else brackets[0][1])


def skq_index_mb_at_largest_y(m: dict, whose: str) -> str:
    """Both at the largest y DSSE_SKQ was measured at, so one row compares them."""
    r = _skq_rows(m)[-1]
    b = int(r["dsse_skq"]["range_index_bytes"]) if whose == "skq" else int(r["index_bytes"]["ours_range"]["total"])
    return fmt_dec1(b / 1e6)


def leak_sdsse(m: dict, queries: int, arm: str, what: str) -> str:
    """the design record: associations and reuse, from each arm's own
    server loop."""
    rows = [r for r in m["rows"] if int(r["queries"]) == queries]
    if len(rows) != 1:
        raise KeyError(f"exp3 has no row at {queries} queries")
    return fmt_int(int(rows[0]["associations"][arm][what]))


SPEC.update({
    # tab:exp-ingest
    **{f"pqclIngest{s}": ("exp1", (lambda n, c: lambda m: exp1_h2h_throughput(m, n, c))(name, cls),
                           f"ingest: {name} {cls} events/s")
       for s, name, cls in (("Cq", "SDSSE-CQ", "keyword"), ("CqS", "SDSSE-CQ-S", "keyword"),
                            ("SkqKeyword", "DSSE_SKQ", "keyword"), ("SkqRange", "DSSE_SKQ", "range"),
                            ("SkqBoth", "DSSE_SKQ", "keyword+range"))},
    **{f"pqclIngestOursOver{s}": ("exp1", (lambda n, c: lambda m: exp1_h2h_speed_ratio(m, n, c))(name, cls),
                                   f"ingest: ours over {name} {cls}")
       for s, name, cls in (("Cq", "SDSSE-CQ", "keyword"), ("CqS", "SDSSE-CQ-S", "keyword"),
                            ("SkqKeyword", "DSSE_SKQ", "keyword"), ("SkqRange", "DSSE_SKQ", "range"),
                            ("SkqBoth", "DSSE_SKQ", "keyword+range"))},
    "pqclIngestSkqLargestY": ("exp1", skq_largest_y, "ingest: the largest y DSSE_SKQ was measured at"),
    "pqclIngestSkqRangeRatioAtLargestY": (
        "exp1", lambda m: skq_ratio_at_largest(m, "range"), "ingest: ours over DSSE_SKQ, range, largest y"),
    "pqclIngestSkqBothRatioAtLargestY": (
        "exp1", lambda m: skq_ratio_at_largest(m, "both"), "ingest: ours over DSSE_SKQ, kw AND range, largest y"),
    **{f"pqclIngestSkq{c}Cross{w}Y": ("exp1", (lambda cc, ww: lambda m: skq_crossover(m, cc, ww))(ck, wk),
                                       f"ingest: measured y {wk} the {ck} crossover against DSSE_SKQ")
       for c, ck in (("Range", "range"), ("Both", "both")) for w, wk in (("Low", "low"), ("High", "high"))},
    # Exp. 2
    "pqclExpTwoTopDocuments": ("exp2", exp2_top_documents, "conj: documents at the top tier"),
    "pqclExpTwoOursTopMsTwo": ("exp2", lambda m: exp2_ours_ms_top(m, 2), "conj: Pi_XT ms, top tier, n=2"),
    **{f"pqclExpTwoOver{a}{p}{'Repeat' if mode == 'repeat' else ''}": (
        "exp2", (lambda d, w, k, mm: lambda m: exp2_sdsse_ratio(m, d, w, k, mm))(docs, width, key, mode),
        f"conj: {key} {mode} over Pi_XT, {'the top tier' if docs is None else f'{docs} docs'}, n={width}")
       for a, key in SDSSE_ARMS for p, docs, width in EXP2_POINTS + (("Top", None, 2),)
       for mode in ("first", "repeat")},
    **{f"pqclExpTwo{a}Top{'Repeat' if mode == 'repeat' else 'First'}Ms": (
        "exp2", (lambda k, mm: lambda m: exp2_sdsse_ms(m, None, 2, k, mm))(key, mode),
        f"conj: {key} {mode} ms, top tier, n=2")
       for a, key in SDSSE_ARMS for mode in ("first", "repeat")},
    **{f"pqclExpTwo{a}Shortfall": ("exp2", (lambda k: lambda m: exp2_shortfall(m, k))(key),
                                    f"conj: {key} results lost to Bloom false positives, all cells")
       for a, key in SDSSE_ARMS},
    **{f"pqclExpTwo{a}MaxXUpdates": ("exp2", (lambda k: lambda m: exp2_max_x_updates(m, k))(key),
                                      f"conj: {key} largest x-term updates, top tier")
       for a, key in SDSSE_ARMS},
    # tab:exp-size
    "pqclSizeCq": ("index-size", lambda m: size_arm_bpp(m, "sdsse_cq"), "size: SDSSE-CQ B/pair"),
    "pqclSizeCqS": ("index-size", lambda m: size_arm_bpp(m, "sdsse_cq_s"), "size: SDSSE-CQ-S B/pair"),
    "pqclSizeDorisFu": ("index-size", lambda m: size_arm_bpp(m, "doris_fu"), "size: the Doris follow-up, B/pair"),
    "pqclSizeDorisFuTags": ("index-size", size_doris_fu_tags, "size: the Doris follow-up, tags at 10^6 pairs"),
    # tab:exp-range
    "pqclExpSevenSkqColdMs": ("exp7", lambda m: exp7_skq_ms(m, "cold"), "range: DSSE_SKQ cold, ms"),
    "pqclExpSevenSkqWarmMs": ("exp7", lambda m: exp7_skq_ms(m, "warm"), "range: DSSE_SKQ warm, ms"),
    **{f"pqclExpSevenSkq{s}{mode.capitalize()}Ms": (
        "exp7", (lambda f, mm: lambda m: exp7_skq_form_ms(m, f, mm))(form, mode),
        f"range: DSSE_SKQ {form}, {mode}, ms")
       for s, form in (("Conjunction", "w1 AND w2"), ("Disjunction", "w1 AND (w2 OR w3)"),
                       ("Negation", "w1 AND NOT w2"), ("ConjRange", "w1 AND range"))
       for mode in ("cold", "warm")},
    **{f"pqclExpSevenSkq{mode.capitalize()}Cross{w}N": (
        "exp7", (lambda mm, ww: lambda m: exp7_skq_crossover(m, mm, ww))(mode, wk),
        f"range: measured N {wk} the DSSE_SKQ {mode} crossover, median width")
       for mode in ("cold", "warm") for w, wk in (("Low", "low"), ("High", "high"))},
    "pqclRangeIndexMbSkq": ("exp1", lambda m: skq_index_mb_at_largest_y(m, "skq"),
                            "range: DSSE_SKQ index MB at its largest y"),
    "pqclRangeIndexMbOursAtSkqY": ("exp1", lambda m: skq_index_mb_at_largest_y(m, "ours"),
                                   "range: ours index MB at DSSE_SKQ's largest y"),
    # tab:exp-leak
    **{f"pqclLeak{a}{s}{q}": ("exp3", (lambda qq, k, w: lambda m: leak_sdsse(m, qq, k, w))(qn, key, what),
                               f"leak: {key} {what} at {qn} queries")
       for a, key in SDSSE_ARMS
       for q, qn in (("One", 1), ("Ten", 10), ("Fifty", 50))
       for s, what in (("Attr", "associations"), ("ReuseTrials", "reuse_trials"), ("ReuseHits", "reuse_hits"))},
})

# --- M15 / c15: the second baselines ----------------
# New macros only: no entry above changes. Exp. 2 reads VCFB through the SDSSE
# readers (the same `first_search_ns` / `repeat_search_ns` keys) and the Doris
# follow-up where it ran; Exp. 4 reads MDRSSE and the SDSSE conjunction row; Exp. 5
# reads both new arms under `associations`, as SDSSE's are read.

def _dfu_rows(m: dict, width: int) -> list:
    """Exp. 2 rows where the Doris follow-up was measured (it stops where its memory
    does, and a skipped tier records why)."""
    return sorted((r for r in m["rows"] if int(r["conjunction_width"]) == width
                   and "search_ns" in r.get("doris_fu", {})), key=lambda r: int(r["documents"]))


def exp2_dfu_ratio(m: dict, documents: int | None, width: int) -> str:
    """Its search time over ours, Pi_XT: above 1 favours us. `None` is its largest
    measured tier, not Exp. 2's top tier."""
    rows = _dfu_rows(m, width)
    if documents is None:
        if not rows:
            raise KeyError(f"exp2 has no Doris follow-up row at width {width}")
        r = rows[-1]
    else:
        r = next((x for x in rows if int(x["documents"]) == documents), None)
        if r is None:
            raise KeyError(f"exp2 has no Doris follow-up row at {documents} docs, width {width}")
    return fmt_ratio(_median_ns(r["doris_fu"]["search_ns"]) / _median_ns(r["pi_xt"]["search_ns"]))


def exp2_dfu_largest_documents(m: dict) -> str:
    rows = _dfu_rows(m, 2)
    if not rows:
        raise KeyError("exp2 has no Doris follow-up row")
    return fmt_int(int(rows[-1]["documents"]))


def exp2_dfu_stop_documents(m: dict) -> str:
    """The stop size the harness was built with, read from the record."""
    stops = {int(r["doris_fu"].get("admission", r["doris_fu"]).get("stop_documents"))
             for r in m["rows"] if "doris_fu" in r}
    if len(stops) != 1:
        raise ValueError(f"exp2 rows disagree on the Doris follow-up's stop size: {sorted(stops)}")
    return fmt_int(stops.pop())


def exp2_dfu_kb_per_pair(m: dict) -> str:
    """Stored kB per pair at its largest measured tier: why its curve stops."""
    r = _dfu_rows(m, 2)[-1]
    return fmt_dec1(int(r["doris_fu"]["stored_bytes"]) / int(r["pairs"]) / 1e3)


def _exp7_median_any(m: dict, width_pct: int) -> dict:
    med = m["median_configuration"]
    rows = [r for r in m["n_axis_rows"] if int(r["records"]) == int(med["records"])
            and int(r["range_width_pct"]) == width_pct]
    if len(rows) != 1:
        raise KeyError(f"exp7 has no n-axis row at the median N and {width_pct} %")
    return rows[0]


def exp7_mdrsse_ms(m: dict) -> str:
    _, r = _exp7_median(m)
    return fmt_ms(_median_ns(r["mdrsse"]["search_ns"]))


def exp7_mdrsse_ratio(m: dict, width_pct: int | None) -> str:
    """MDRSSE's time over ours at the median N: above 1 favours us. `None` is the
    median width."""
    r = _exp7_median(m)[1] if width_pct is None else _exp7_median_any(m, width_pct)
    return fmt_ratio(_median_ns(r["mdrsse"]["search_ns"]) / _median_ns(r["pi_range"]["search_ns"]))


def exp7_mdrsse_leaves(m: dict) -> str:
    _, r = _exp7_median(m)
    return fmt_int(int(r["mdrsse"]["leaves_in_cover"]))


def _exp7_sdsse_conj(m: dict, arm: str) -> dict:
    med, _ = _exp7_median(m)
    if int(med["boolean_forms_measured_at"]) != int(med["records"]):
        raise ValueError("exp7 Boolean forms were not measured at the median configuration")
    rows = [r for r in m["boolean_forms_sdsse"] if r["arm"] == arm]
    if len(rows) != 1:
        raise KeyError(f"exp7 has no SDSSE conjunction row for {arm}")
    return rows[0]


def exp7_sdsse_conj_ms(m: dict, arm: str, mode: str) -> str:
    return fmt_ms(_median_ns(_exp7_sdsse_conj(m, arm)[f"{mode}_total_ns"]))


def exp7_sdsse_conj_ratio(m: dict, arm: str, mode: str) -> str:
    """Their time over ours on the same three terms: above 1 favours us."""
    ours = next(r for r in m["boolean_forms"] if r["form"] == "w1 AND w2")
    return fmt_ratio(_median_ns(_exp7_sdsse_conj(m, arm)[f"{mode}_total_ns"]) / _median_ns(ours["total_ns"]))


def exp7_sdsse_conj_count(m: dict, arm: str, what: str) -> str:
    """`hits` (what the arm returned) or `want` (the fixture's answer), emitted side by
    side so a Bloom loss is visible (§1db.6 (a))."""
    return fmt_int(int(_exp7_sdsse_conj(m, arm)[what]))


def leak_row(m: dict, queries: int, key: str) -> str:
    rows = [r for r in m["rows"] if int(r["queries"]) == queries]
    if len(rows) != 1:
        raise KeyError(f"exp3 has no row at {queries} queries")
    return fmt_int(int(rows[0][key]))


M15_LEAK_Q = (("One", 1), ("Ten", 10), ("Fifty", 50))

SPEC.update({
    # Exp. 2: VCFB, first and repeat apart (§1db.6 (b))
    **{f"pqclExpTwoOverVcfb{p}{'Repeat' if mode == 'repeat' else ''}": (
        "exp2", (lambda d, w, mm: lambda m: exp2_sdsse_ratio(m, d, w, "vcfb", mm))(docs, width, mode),
        f"conj: VCFB {mode} over Pi_XT, {'the top tier' if docs is None else f'{docs} docs'}, n={width}")
       for p, docs, width in EXP2_POINTS + (("Top", None, 2),) for mode in ("first", "repeat")},
    **{f"pqclExpTwoVcfbTop{'Repeat' if mode == 'repeat' else 'First'}Ms": (
        "exp2", (lambda mm: lambda m: exp2_sdsse_ms(m, None, 2, "vcfb", mm))(mode),
        f"conj: VCFB {mode} ms, top tier, n=2")
       for mode in ("first", "repeat")},
    # Exp. 2: the Doris follow-up, where its memory allows
    **{f"pqclExpTwoOverDorisFu{p}": (
        EXP2_WITH_DORIS, (lambda d, w: lambda m: exp2_dfu_ratio(m, d, w))(docs, width),
        f"conj: the Doris follow-up over Pi_XT, {'its largest tier' if docs is None else f'{docs} docs'}, n={width}")
       for p, docs, width in EXP2_POINTS + (("Largest", None, 2),)},
    "pqclExpTwoDorisFuLargestDocuments": (EXP2_WITH_DORIS, exp2_dfu_largest_documents,
                                          "conj: the Doris follow-up's largest measured tier, documents"),
    "pqclExpTwoDorisFuStopDocuments": (EXP2_WITH_DORIS, exp2_dfu_stop_documents,
                                       "conj: the Doris follow-up's stop size, documents (decided before c15)"),
    "pqclExpTwoDorisFuKbPerPair": (EXP2_WITH_DORIS, exp2_dfu_kb_per_pair,
                                   "conj: the Doris follow-up's stored kB per pair at its largest tier"),
    # Exp. 4: MDRSSE at the median N; SDSSE on the three-keyword row
    "pqclExpSevenMdrsseMs": ("exp7", exp7_mdrsse_ms, "range: MDRSSE ms, median configuration"),
    "pqclExpSevenMdrsseLeaves": ("exp7", exp7_mdrsse_leaves, "range: MDRSSE leaves in the cover, median configuration"),
    **{f"pqclExpSevenOverMdrsse{s}": ("exp7", (lambda w: lambda m: exp7_mdrsse_ratio(m, w))(width),
                                       f"range: MDRSSE over Pi_RANGE at the median N, {label}")
       for s, width, label in (("", None, "median width"), ("Narrow", 1, "1 %"), ("Wide", 50, "50 %"))},
    **{f"pqclExpSeven{a}Conjunction{mode.capitalize()}Ms": (
        "exp7", (lambda k, mm: lambda m: exp7_sdsse_conj_ms(m, k, mm))(key, mode),
        f"range: {key} w1 AND w2 AND w3, {mode}, ms")
       for a, key in SDSSE_ARMS for mode in ("first", "repeat")},
    **{f"pqclExpSevenOver{a}Conjunction{'Repeat' if mode == 'repeat' else ''}": (
        "exp7", (lambda k, mm: lambda m: exp7_sdsse_conj_ratio(m, k, mm))(key, mode),
        f"range: {key} over Pi_BOOL on w1 AND w2 AND w3, {mode}")
       for a, key in SDSSE_ARMS for mode in ("first", "repeat")},
    **{f"pqclExpSeven{a}Conjunction{w.capitalize()}": (
        "exp7", (lambda k, ww: lambda m: exp7_sdsse_conj_count(m, k, ww))(key, w),
        f"range: {key} w1 AND w2 AND w3, {w}")
       for a, key in SDSSE_ARMS for w in ("hits", "want")},
    # Exp. 5: both new arms under §1db.1's rules, and ours' reading (b)
    **{f"pqclLeakVcfb{s}{q}": ("exp3", (lambda qq, w: lambda m: leak_sdsse(m, qq, "vcfb", w))(qn, what),
                                f"leak: VCFB {what} at {qn} queries")
       for q, qn in M15_LEAK_Q
       for s, what in (("Attr", "associations"), ("ReuseTrials", "reuse_trials"), ("ReuseHits", "reuse_hits"))},
    **{f"pqclLeakDorisFu{s}{q}": ("exp3", (lambda qq, w: lambda m: leak_sdsse(m, qq, "doris_fu", w))(qn, what),
                                   f"leak: the Doris follow-up {what} at {qn} queries")
       for q, qn in M15_LEAK_Q
       for s, what in (("Attr", "associations"), ("Inferred", "inferred_by_elimination"),
                       ("Link", "unattributable_links_distinct"),
                       ("LinkTwo", "unattributable_links_in_two_or_more_queries"))},
    **{f"pqclLeakXtLinkTwo{q}": ("exp3", (lambda qq: lambda m: leak_row(m, qq, "hit_link_in_two_or_more_queries"))(qn),
                                 f"leak: Pi_XT tags seen in two or more queries at {qn} queries")
       for q, qn in M15_LEAK_Q},
})

_unknown = [m for m in RETIRED if m not in SPEC]
if _unknown or len(set(RETIRED)) != len(RETIRED):
    raise SystemExit("RETIRED names cells SPEC does not hold, or repeats one: " + ", ".join(_unknown))
for _m in RETIRED:
    del SPEC[_m]


def render(records: list) -> str:
    """The LaTeX macro file. The caller must have checked publishability first."""
    lines = [
        "% Generated by tools/mkfigs.py. Do not edit.",
        "%",
        "% Every value here came from a record that passed the publication gate.",
        "% Regenerate rather than edit: an edited number has no provenance.",
        "",
        BS + "providecommand{" + BS + "pqclWithdrawn}[1]{" + BS + "textcolor{red}{[withdrawn: #1]}}",
        "",
    ]
    missing = []
    revived = [m for m in WITHDRAWN if m not in SPEC]
    for macro, (prefix, fn, desc) in sorted(SPEC.items()):
        m = _latest(records, prefix)
        try:
            value = fn(m) if m is not None else None
        except Exception:  # noqa: BLE001
            value = None
        if macro in WITHDRAWN:
            if value is not None:
                revived.append(macro)
                continue
            lines.append("% " + desc)
            lines.append("% WITHDRAWN -- " + WITHDRAWN[macro])
            lines.append(BS + "newcommand{" + BS + macro + "}{" + BS + "pqclWithdrawn{"
                         + BS + "texttt{" + macro + "}}}")
            continue
        if value is None:
            missing.append(macro)
            continue
        lines.append("% " + desc)
        lines.append(BS + "newcommand{" + BS + macro + "}{" + value + "}")
    if revived:
        raise SystemExit(
            "refusing to emit: these WITHDRAWN cells are not in SPEC or yield a value "
            "again; lift the withdrawal deliberately:\n  " + "\n  ".join(sorted(revived))
        )
    if missing:
        # Name each gap and its reason here: the separate coverage report was
        # removed.
        why = {m: f"{st}: {d}" for m, st, d in coverage(records) if st != "ok"}
        raise SystemExit(
            "refusing to emit an incomplete macro file; no value for:\n  "
            + "\n  ".join(f"{m} ({why.get(m, 'no value')})" for m in missing)
        )
    return "\n".join(lines) + "\n"
