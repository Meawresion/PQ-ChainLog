"""The paper's figures, from publishable records only — the design record.

Same contract as ``values.tex``: ``mkfigs.py --out paper/generated`` writes
``<name>.pdf`` for each name the paper's ``\\genfig`` includes, **only** from
publishable records, never during a run.

⭐ **Plot only what was observed** (the project rules rule 21), enforced here rather
than left to the reader's goodwill:

* every point is a measured one: a median, with IQR bars where the record holds
  a distribution;
* segments join **adjacent measured points only**; a skipped point is a gap,
  never bridged;
* no fitted curve, no line past the last point, and no fitting or
  interpolation call anywhere in this file (a self-test greps for them);
* axis limits sit at the measured range;
* a value a log axis cannot show (a zero count) is stated in a note on the
  panel, never dropped silently or nudged to a small positive number.

Builders are pure (record -> spec) so the self-tests can check that every
plotted x is in the record's measured set. ``render`` is the only function that
touches matplotlib, imported lazily so ``--check`` never needs
it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path

# Fixed categorical order (dataviz reference palette, validated: CVD dE >= 9.1).
# Ours is always the first hue; identity is also carried by marker and legend.
OURS, BASE1, BASE2, BASE3 = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
#: SAC Exp. 4's third arm (§1ci.2) and its labelled one-epoch series (§1ci.6).
BASE4, BASE4_ONE_EPOCH = "#8e5bd1", "#c4a3f0"
#: M15 / c15: a fifth arm (the Doris follow-up), a neutral dark grey. Identity is
#: carried by its own marker and dash as well, never by hue alone.
BASE5 = "#4d4d4d"
MARKERS = {OURS: "o", BASE1: "s", BASE2: "^", BASE3: "D"}
INK, MUTED, GRID = "#0b0b0b", "#898781", "#e1e0d9"


@dataclass
class Series:
    label: str
    color: str
    x: list          # measured x, in axis order; None y marks a skipped point
    y: list          # medians (None = skipped: a gap, never bridged)
    lo: list | None = None   # lower whisker values (absolute), or None
    hi: list | None = None
    measured_x: list = field(default_factory=list)  # every x the record holds
    # §1cm, bar panels only: per-bar colour and hatch (default: `color`, none),
    # and an open bar (white face, coloured edge) for a second state.
    colors: list | None = None
    hatches: list | None = None
    filled: bool = True


@dataclass
class Panel:
    title: str
    xlabel: str
    ylabel: str
    xscale: str = "log"
    yscale: str = "log"
    xbase: int = 10
    series: list = field(default_factory=list)
    refs: list = field(default_factory=list)    # (y, label): axis-independent measured values
    notes: list = field(default_factory=list)
    #: §1cm: non-empty makes this a grouped-bar panel, one group per category
    #: (each series' `y` has one value per category), drawn in series order.
    categories: list = field(default_factory=list)


@dataclass
class Figure:
    name: str
    panels: list
    #: §1cm: two panels side by side in one column, placed with `\genfig`.
    narrow: bool = False
    #: Plotting-area height in inches; None is `MIN_PLOT_IN` (§1al.2).
    plot_in: float | None = None
    #: One shared legend of proxy patches `(label, face, edge, hatch)`, for a
    #: figure whose bar colours name the groups rather than the series.
    legend: list = field(default_factory=list)

    @property
    def wide(self) -> bool:
        """Placed at the text width (`\\genfigw`)?"""
        return len(self.panels) > 1 and not self.narrow


def _med(s: dict) -> float:
    return float(s["median_ns"])


def _iqr(s: dict) -> tuple:
    return float(s["p25_ns"]), float(s["p75_ns"])


# --------------------------------------------------------------- builders

def exp_ingest_y(m: dict) -> Figure:
    """(a) our range and keyword+range ratios over y, with parity; (b) index MB."""
    rows = sorted(m["range_ingest_across_y"]["rows"], key=lambda r: int(r["y"]))
    xs = [int(r["y"]) for r in rows]

    def ratio(r, get_base, ours):
        if r.get("skipped") or get_base(r) is None:
            return None, None, None
        b, o = get_base(r)["total_ns"], r[ours]["total_ns"]
        (bl, bh), (ol, oh) = _iqr(b), _iqr(o)
        # Our events/s over theirs = their time over ours; the bars combine the
        # two IQRs conservatively (their p25 / our p75 .. their p75 / our p25).
        return _med(b) / _med(o), bl / oh, bh / ol

    a = Panel("(a) ingest rate, ours over baseline (>1 favours ours)", "y (bitmap width = events)",
              "rate ratio", yscale="log", xbase=2)
    # M14: DSSE_SKQ replaces both comparators once a record carries it.
    skq = any("dsse_skq" in r for r in rows)
    arms = (
        ("range vs DSSE_SKQ", lambda r: r["dsse_skq"].get("range"), "ours_range", OURS),
        ("keyword+range vs DSSE_SKQ", lambda r: r["dsse_skq"].get("keyword_range"), "ours_keyword_range", BASE1),
    ) if skq else (
        ("range vs Zuo'22", lambda r: r["zuo22"], "ours_range", OURS),
        ("keyword+range vs ODXT+Zuo'22", lambda r: r["odxt_zuo22"], "ours_keyword_range", BASE1),
    )
    for label, base, ours, color in arms:
        vals = [ratio(r, base, ours) for r in rows]
        a.series.append(Series(label, color, xs, [v[0] for v in vals],
                               [v[1] for v in vals], [v[2] for v in vals], measured_x=xs))
    a.refs.append((1.0, "parity"))

    b = Panel("(b) index size", "y (bitmap width = events)", "index (MB)", xbase=2)
    theirs = ("DSSE_SKQ", "skq") if skq else ("Zuo'22", "zuo22")
    for label, key, color in (("ours (range)", "ours", OURS), (theirs[0], theirs[1], BASE1)):
        ys = []
        for r in rows:
            ib = r.get("index_bytes")
            if r.get("skipped") or not ib:
                ys.append(None)
            elif key == "skq":
                v = r["dsse_skq"].get("range_index_bytes")
                ys.append(None if v is None else int(v) / 1e6)
            else:
                v = ib["ours_range"]["total"] if key == "ours" else ib["zuo22"]
                ys.append(int(v) / 1e6)
        b.series.append(Series(label, color, xs, ys, measured_x=xs))
    skipped = [int(r["y"]) for r in rows if r.get("skipped")]
    if skipped:
        b.notes.append("not measured (memory): y = " + ", ".join(f"{y:,}" for y in skipped))
    return Figure("exp-ingest-y", [a, b])


def exp_conj(m: dict) -> Figure:
    panels = []
    for width in sorted({int(r["conjunction_width"]) for r in m["rows"]}):
        rows = sorted((r for r in m["rows"] if int(r["conjunction_width"]) == width),
                      key=lambda r: int(r["documents"]))
        xs = [int(r["documents"]) for r in rows]
        p = Panel(f"n = {width}", "documents", "latency (ms)")
        # M14: the SDSSE arms replace ODXT once a record carries them, each at its
        # first search; its repeat is in the macros.
        new = all("sdsse_cq" in r for r in rows)
        arms = (("Π_XT", "pi_xt", OURS, "search_ns"), ("Π_CD", "pi_cd", BASE2, "search_ns"),
                ("SDSSE-CQ", "sdsse_cq", BASE1, "first_search_ns"),
                ("SDSSE-CQ-S", "sdsse_cq_s", BASE3, "first_search_ns")) if new else (
                ("Π_XT", "pi_xt", OURS, "search_ns"), ("Π_CD", "pi_cd", BASE2, "search_ns"),
                ("ODXT", "odxt", BASE1, "search_ns"))
        # M15 / c15 (the design record ruling 2): VCFB at its repeat search
        # (its first search is in the table and macros, not a line); the Doris
        # follow-up only where it was measured, so its line stops at its last tier.
        if new and all("vcfb" in r for r in rows):
            arms = (*arms, ("VCFB (repeat)", "vcfb", BASE4, "repeat_search_ns"))
        for label, key, color, field_name in arms:
            if not all(key in r for r in rows):
                p.notes.append(f"{label}: not in this record")
                continue
            ss = [r[key][field_name] for r in rows]
            p.series.append(Series(label, color, xs, [_med(s) / 1e6 for s in ss],
                                   [_iqr(s)[0] / 1e6 for s in ss], [_iqr(s)[1] / 1e6 for s in ss],
                                   measured_x=xs))
        dfu = [r.get("doris_fu", {}).get("search_ns") for r in rows]
        if any(d is not None for d in dfu):
            p.series.append(Series("Doris follow-up", BASE5, xs,
                                   [None if d is None else _med(d) / 1e6 for d in dfu],
                                   [None if d is None else _iqr(d)[0] / 1e6 for d in dfu],
                                   [None if d is None else _iqr(d)[1] / 1e6 for d in dfu],
                                   measured_x=[x for x, d in zip(xs, dfu) if d is not None]))
        panels.append(p)
    return Figure("exp-conj", panels)


def exp_range(m: dict) -> Figure:
    panels = []
    for pct in sorted({int(r["range_width_pct"]) for r in m["n_axis_rows"]}):
        rows = sorted((r for r in m["n_axis_rows"] if int(r["range_width_pct"]) == pct),
                      key=lambda r: int(r["records"]))
        xs = [int(r["records"]) for r in rows]
        p = Panel(f"range width {pct} %", "collection size N", "latency (ms)", xbase=2)
        # M14: DSSE_SKQ replaces Zuo'22 once a record carries it.
        key, name = ("dsse_skq", "DSSE_SKQ") if all("dsse_skq" in r for r in rows) else ("zuo22", "Zuo'22")
        for label, get, color in (
            ("Π_RANGE", lambda r: r["pi_range"]["search_ns"], OURS),
            (f"{name} warm", lambda r: r[key]["warm_search_ns"], BASE2),
        ):
            ss = [get(r) for r in rows]
            p.series.append(Series(label, color, xs, [_med(s) / 1e6 for s in ss],
                                   [_iqr(s)[0] / 1e6 for s in ss], [_iqr(s)[1] / 1e6 for s in ss],
                                   measured_x=xs))
        # Its search is destructive: each build yields ONE cold search, so the
        # record holds a single observation, drawn without a bar.
        p.series.append(Series(f"{name} cold", BASE1, xs,
                               [int(r[key]["cold_search_ns"]) / 1e6 for r in rows], measured_x=xs))
        p.notes.append(f"{name} cold: one search per build (destructive), no IQR")
        if all("mdrsse" in r for r in rows):
            ss = [r["mdrsse"]["search_ns"] for r in rows]
            p.series.append(Series("MDRSSE (static, γ = 500)", BASE3, xs, [_med(s) / 1e6 for s in ss],
                                   [_iqr(s)[0] / 1e6 for s in ss], [_iqr(s)[1] / 1e6 for s in ss],
                                   measured_x=xs))
        panels.append(p)
    return Figure("exp-range", panels)


def exp_anchor(m: dict) -> Figure:
    p = Panel("", "entries (MMR leaves) per epoch", "records/s")

    def curve(runs):
        runs = sorted(runs, key=lambda o: int(o["epoch_size"]))
        xs = [int(o["epoch_size"]) for o in runs]
        ys = [int(o["records"]) * 1e9 / int(o["first_event_to_last_commit_ns"]) for o in runs]
        return xs, ys

    for label, key, color in (("ours, parallel co-signers", "ours", OURS),
                              ("ours, one co-signer", "ours_single_worker", BASE2)):
        if key in m:
            xs, ys = curve(m[key])
            p.series.append(Series(label, color, xs, ys, measured_x=xs))
    # ⭐ LEChain at each point on the stream that point's ratio divides by
    # (M13 A4): its own up to 10^4 capsules, the 10^4 steady state above. The
    # rate is LEChain's, not a function of the epoch; drawn per point because
    # the streams differ.
    by_cap = {int(r["stream_capsules"]): r for r in m["lechain_runs"]}
    runs = sorted(m["ours"], key=lambda o: int(o["epoch_size"]))
    xs = [int(o["epoch_size"]) for o in runs]
    ys = []
    for o in runs:
        lp = by_cap[int(o["lechain_stream_capsules"])]["pipelined"]
        ys.append(int(lp["events"]) * 1e9 / int(lp["first_submit_to_last_commit_ns"]))
    p.series.append(Series("LEChain (one tx per event)", BASE1, xs, ys, measured_x=xs))
    if any(not o["lechain_same_stream"] for o in runs):
        p.notes.append("LEChain above 10^4 capsules: its 10^4-capsule steady state")
    p.notes.append("one run per point: no IQR")
    return Figure("exp-anchor", [p])


def exp_anchor_sac(m: dict) -> Figure:
    """SAC Exp. 1 (§1ci.1): draft8's figure plus B-DEMS's per-transaction
    workflow, each point on the stream that point's LEChain ratio divides by."""
    f = exp_anchor(m)
    p = f.panels[0]
    by_cap = {int(r["stream_capsules"]): r for r in m["bdems_runs"]}
    runs = sorted(m["ours"], key=lambda o: int(o["epoch_size"]))
    xs = [int(o["epoch_size"]) for o in runs]
    ys = []
    for o in runs:
        bp = by_cap[int(o["lechain_stream_capsules"])]["pipelined"]
        ys.append(int(bp["events"]) * 1e9 / int(bp["first_submit_to_last_commit_ns"]))
    p.series.append(Series("B-DEMS (TxA-TxE per step)", BASE3, xs, ys, measured_x=xs))
    f.plot_in = PLOT_IN_SAC
    return f


def _custody(m: dict, schemes: tuple) -> Figure:
    cases = sorted(m["cases"], key=lambda c: int(c["records"]))
    xs = [int(c["records"]) for c in cases]
    a = Panel("(a) verify one capsule's history", "records in the case", "verify (µs)")
    b = Panel("(b) bytes handed to the court", "records in the case", "proof (bytes)")
    for label, key, color in schemes:
        if any(key not in c for c in cases):
            raise KeyError(f"custody record has no {key} arm")
        ss = [c[key]["verify_ns"] for c in cases]
        a.series.append(Series(label, color, xs, [_med(s) / 1e3 for s in ss],
                               [_iqr(s)[0] / 1e3 for s in ss], [_iqr(s)[1] / 1e3 for s in ss],
                               measured_x=xs))
        b.series.append(Series(label, color, xs, [int(c[key]["disclosed_bytes"]) for c in cases],
                               measured_x=xs))
    return Figure("exp-custody", [a, b])


def exp_custody(m: dict) -> Figure:
    """draft8's Exp. 7: ours against the flat case MMR and chain replay."""
    return _custody(m, (("ours (three-tier)", "ours", OURS), ("flat case MMR", "flat_mmr", BASE1),
                        ("chain replay", "hash_chain_replay", BASE2)))


def exp_custody_sac(m: dict) -> Figure:
    """SAC Exp. 2 (§1cd): ours against its 2023+ arms, PQ-ABL and GlassDB."""
    f = _custody(m, (("ours (three-tier)", "ours", OURS), ("PQ-ABL (per-epoch trees)", "pq_abl", BASE1),
                     ("GlassDB (POS-tree ledger)", "glassdb", BASE2)))
    f.plot_in = PLOT_IN_SAC
    return f


def exp_leak(m: dict) -> Figure:
    rows = sorted(m["rows"], key=lambda r: int(r["queries"]))
    xs = [int(r["queries"]) for r in rows]
    p = Panel("", "queries issued", "count")
    new = all("sdsse_cq" in r["associations"] for r in rows)
    theirs = ((("SDSSE-CQ attributable", lambda r: r["associations"]["sdsse_cq"]["associations"], BASE1),
               ("SDSSE-CQ-S attributable", lambda r: r["associations"]["sdsse_cq_s"]["associations"], BASE3))
              if new else
              (("ODXT attributable", lambda r: r["associations"]["odxt"]["associations"], BASE1),))
    if new and all("vcfb" in r["associations"] and "doris_fu" in r["associations"] for r in rows):
        theirs = (*theirs,
                  ("VCFB attributable", lambda r: r["associations"]["vcfb"]["associations"], BASE4),
                  ("Doris follow-up attributable", lambda r: r["associations"]["doris_fu"]["associations"], BASE5))
    for label, get, color in (
        *theirs,
        ("Π_XT attributable", lambda r: r["associations"]["pi_xt"], OURS),
        ("Π_XT linkable hits", lambda r: r["hit_link_distinct_pairs"], BASE2),
    ):
        vals = [int(get(r)) for r in rows]
        zeros = [x for x, v in zip(xs, vals) if v == 0]
        if len(zeros) == len(vals):
            p.notes.append(f"{label} = 0 at every measured query count")
            continue
        if zeros:
            p.notes.append(f"{label} = 0 at {', '.join(map(str, zeros))} queries (not drawable on a log axis)")
        p.series.append(Series(label, color, xs, [v if v > 0 else None for v in vals], measured_x=xs))
    return Figure("exp-leak", [p])


#: name -> (record prefix, builder). The names are the paper's \genfig names.
def exp_redaction(m: dict) -> Figure:
    """`fig:exp-redaction` (§1v.5): time from a recorded order to erasure
    complete vs case size, one capsule. ODXT's deletion completes no erasure,
    so it is tabulated, never drawn."""
    cases = sorted(m["cases"], key=lambda c: int(c["pairs"]))
    xs = [int(c["pairs"]) for c in cases]
    p = Panel("", "(w, id) pairs in the case", "erasure time (ms)")
    for label, key, color in (("ours, FULL (compaction complete)", "ours_full", OURS),
                              ("ours, PAYLOAD+INDEX (tombstones landed)", "ours_payload_index", BASE2),
                              ("ODXT, full rebuild", "odxt_rebuild", BASE1)):
        ss = [c["rows"][key]["erase_ns"] for c in cases]
        p.series.append(Series(label, color, xs, [_med(s) / 1e6 for s in ss],
                               [_iqr(s)[0] / 1e6 for s in ss], [_iqr(s)[1] / 1e6 for s in ss],
                               measured_x=xs))
    p.notes.append("ODXT deletion completes no erasure: tabulated only")
    return Figure("exp-redaction", [p])


def exp_redaction_sac(m: dict) -> Figure:
    """SAC Exp. 4 (§1cf.2) against B-DEMS, one capsule per redaction: (a) the
    time from the first transaction to erasure complete and every record on
    chain, (b) the court's local check on the redacted capsule."""
    cases = sorted(m["cases"], key=lambda c: int(c["records"]))
    xs = [int(c["records"]) for c in cases]
    a = Panel("(a) redaction, order to record final", "records in the case", "latency (s)")
    b = Panel("(b) the court's check after redaction", "records in the case", "verify (µs)")
    for label, get, color in (
        ("ours, FULL", lambda c: c["fa"]["ours"]["full"], OURS),
        ("ours, PAYLOAD+INDEX", lambda c: c["fa"]["ours"]["payload_index"], BASE2),
        ("ours, PAYLOAD", lambda c: c["fa"]["ours"]["payload"], BASE3),
        ("B-DEMS (TxE + confirmation)", lambda c: c["fa"]["bdems"], BASE1),
        ("PQ-ABL (rebuild, re-commit)", lambda c: c["fa"]["pqabl"], BASE4),
    ):
        ss = [get(c)["latency_ns"] for c in cases]
        a.series.append(Series(label, color, xs, [_med(x) / 1e9 for x in ss],
                               [_iqr(x)[0] / 1e9 for x in ss], [_iqr(x)[1] / 1e9 for x in ss],
                               measured_x=xs))
    # §1ci.6: PQ-ABL with the whole case in one epoch, labelled as beyond its
    # evaluated range (50,000 logs per epoch) where it is.
    one = sorted(m.get("one_epoch_cases", []), key=lambda c: int(c["records"]))
    if one:
        ox = [int(c["records"]) for c in one]
        ss = [c["fa"]["pqabl"]["latency_ns"] for c in one]
        a.series.append(Series("PQ-ABL, whole case in one epoch", BASE4_ONE_EPOCH, ox,
                               [_med(x) / 1e9 for x in ss],
                               [_iqr(x)[0] / 1e9 for x in ss], [_iqr(x)[1] / 1e9 for x in ss],
                               measured_x=ox))
        beyond = [int(c["records"]) for c in one if c.get("beyond_pqabl_evaluated_range")]
        if beyond:
            a.notes.append(f"one epoch past 50,000 logs (from {min(beyond):,} records): beyond PQ-ABL's evaluated range")
    for label, key, color in (("ours (court's check)", "ours", OURS), ("B-DEMS (Alg. 3)", "bdems", BASE1),
                              ("PQ-ABL (epoch re-validated)", "pqabl", BASE4)):
        ss = [c["fb"][key]["verify_ns"] for c in cases]
        b.series.append(Series(label, color, xs, [_med(x) / 1e3 for x in ss],
                               [_iqr(x)[0] / 1e3 for x in ss], [_iqr(x)[1] / 1e3 for x in ss],
                               measured_x=xs))
    b.notes.append("local check only; the chain read is reported beside it")
    return Figure("exp-redaction", [a, b], plot_in=PLOT_IN_SAC)


#: §1cm: the k axis as group labels, and SAC Exp. 4's arm colours.
REDACT_K_LABELS = ("1", "10", "$10^2$", "$10^3$")
REDACT_K_ARMS = (("ours", "ours", OURS), ("B-DEMS", "bdems", BASE1), ("PQ-ABL", "pqabl", BASE4))


def exp_redaction_k(m: dict) -> Figure:
    """§1cm.1, replacing SAC's `tab:exp-redaction`: T1 at the largest case,
    one group per k, a bar per arm. (a) total gas, a single median per cell
    (gas varies only with storage warmth, so the record keeps no spread);
    (b) time to erasure, median with its IQR."""
    import figspec

    top = figspec._redact_largest(m)
    ks = [k for _, k in figspec.REDACT_K]
    if len(ks) != len(REDACT_K_LABELS):
        raise ValueError("the k labels do not match the swept k")
    a = Panel("(a) gas", "capsules redacted, k", "", xscale="linear", yscale="log",
              categories=list(REDACT_K_LABELS))
    b = Panel("(b) time to erasure (s)", "capsules redacted, k", "", xscale="linear", yscale="linear",
              categories=list(REDACT_K_LABELS))
    for label, key, color in REDACT_K_ARMS:
        rows = {int(r["k"]): r for r in top["t1"][key]}
        a.series.append(Series(label, color, ks, [int(rows[k]["gas_median"]) for k in ks], measured_x=ks))
        lat = [rows[k]["latency_ns"] for k in ks]
        b.series.append(Series(label, color, ks, [_med(s) / 1e9 for s in lat],
                               [_iqr(s)[0] / 1e9 for s in lat], [_iqr(s)[1] / 1e9 for s in lat],
                               measured_x=ks))
    return Figure("exp-redaction-k", [a, b], narrow=True, plot_in=PLOT_IN_COMPACT)


#: §1cm.2: SAC Exp. 2's arms, in `exp_custody_sac`'s colours; GlassDB hatched.
CUSTODY_BAR_ARMS = (("ours", "ours", OURS, ""), ("PQ-ABL", "pq_abl", BASE1, ""),
                    ("GlassDB", "glassdb", BASE2, "////"))


def exp_custody_bars(m: dict) -> Figure:
    """§1cm.2, replacing SAC's `tab:exp-custody`: the largest case, one group
    per scheme. (a) verify one capsule, live (filled) and redacted (open);
    (b) audit the whole case, one core (filled) and all cores (open). Every bar
    a median with its IQR. GlassDB is hatched: its proof shape is one draw per
    run (§1cj.5), and no min-max whisker is drawn, since that range spans case
    sizes and these bars are the largest case."""
    import figspec

    top = max(int(c["records"]) for c in m["cases"])
    c = figspec._custody_case(m, top)
    cats = [label for label, _, _, _ in CUSTODY_BAR_ARMS]
    colors = [color for _, _, color, _ in CUSTODY_BAR_ARMS]
    hatches = [hatch for _, _, _, hatch in CUSTODY_BAR_ARMS]
    a = Panel("(a) verify (µs)", "", "", xscale="linear", yscale="linear", categories=cats)
    b = Panel("(b) full audit (s)", "", "", xscale="linear", yscale="log", categories=cats)

    def arm(key):
        if key not in c:
            raise KeyError(f"custody record has no {key} arm")
        return c[key]

    for label, get, scale, panel, filled in (
        ("live", lambda k: arm(k)["verify_ns"], 1e3, a, True),
        ("redacted", lambda k: arm(k)["redacted"]["verify_ns"], 1e3, a, False),
        ("one core", lambda k: arm(k)["full_replay_ns"], 1e9, b, True),
        ("all cores", lambda k: arm(k)["full_replay_parallel_ns"], 1e9, b, False),
    ):
        ss = [get(key) for _, key, _, _ in CUSTODY_BAR_ARMS]
        panel.series.append(Series(label, OURS, cats, [_med(s) / scale for s in ss],
                                   [_iqr(s)[0] / scale for s in ss], [_iqr(s)[1] / scale for s in ss],
                                   measured_x=cats, colors=colors, hatches=hatches, filled=filled))
    legend = [("live / one core", MUTED, MUTED, ""),
              ("redacted / all cores", "white", MUTED, ""),
              ("GlassDB: one draw", "white", BASE2, "////")]
    return Figure("exp-custody-bars", [a, b], narrow=True, plot_in=PLOT_IN_COMPACT, legend=legend)


def _at_full_height(f: Figure, name: str) -> Figure:
    """§1cq: SAC's figure under draft9's name, at the standard plotting height.
    SAC's shorter plot (`PLOT_IN_SAC`) served its page limit; draft9 has none."""
    f.name = name
    f.plot_in = None
    return f


def exp_anchor_all(m: dict) -> Figure:
    """draft9 `fig:exp-anchor`: the same arms and record as SAC's."""
    return _at_full_height(exp_anchor_sac(m), "exp-anchor-all")


def exp_custody_all(m: dict) -> Figure:
    """draft9 `fig:exp-custody`: the three 2023+ arms, as SAC's (§1cr)."""
    return _at_full_height(exp_custody_sac(m), "exp-custody-all")


def exp_redaction_custody(m: dict) -> Figure:
    """draft9 `fig:exp-redaction-coc`: the same panels and record as SAC's."""
    return _at_full_height(exp_redaction_sac(m), "exp-redaction-custody")


def exp_redaction_k_time(m: dict) -> Figure:
    """draft9 `fig:exp-redaction-k`: time to erasure only, no gas panel (the
    professor's ruling). The `ieee` twin of `sacpaper/make_fig6.py`. The quantity
    goes on the y axis, as there."""
    _, lat = exp_redaction_k(m).panels
    lat.title = ""
    lat.ylabel = "time to erasure (s)"
    return Figure("exp-redaction-k", [lat], plot_in=PLOT_IN_SAC)


FIGURES = {
    "exp-ingest-y": ("exp1", exp_ingest_y),
    # §1db.8: pass 1's record with pass 2's Doris cells merged in (figspec).
    "exp-conj": ("exp2+doris-fu", exp_conj),
    "exp-range": ("exp7", exp_range),
    "exp-anchor": ("exp6chain", exp_anchor),
    "exp-custody": ("custody-disclosure", exp_custody),
    "exp-leak": ("exp3", exp_leak),
    "exp-redaction": ("exp9redact", exp_redaction),
    # A builder only for the targets `FIGURES_BY_TARGET` names. `exp-custody-bars`
    # is SAC only (§1cm); `exp-redaction-k` is drawn for both, differently (§1cq).
    "exp-redaction-k": ("sac-redaction", None),
    "exp-custody-bars": ("custody-disclosure", None),
    # §1cq: draft9 only.
    "exp-anchor-all": ("exp6chain", None),
    "exp-custody-all": ("custody-disclosure", None),
    "exp-redaction-custody": ("sac-redaction", None),
}

#: A figure drawn differently for one paper class: name -> {target: builder},
#: or {target: (record prefix, builder)} when that paper's figure comes from
#: another record. SAC (`acm`) compares custody disclosure against 2023+
#: systems only (§1cd), from the same record; its redaction figure is Exp. 4
#: against B-DEMS (§1cf), from `sac-redaction`, where draft8 (`ieee`) keeps
#: `exp9redact`'s.
FIGURES_BY_TARGET = {
    "exp-anchor": {"acm": exp_anchor_sac},
    "exp-custody": {"acm": exp_custody_sac},
    "exp-redaction": {"acm": ("sac-redaction", exp_redaction_sac)},
    "exp-redaction-k": {"acm": exp_redaction_k, "ieee": exp_redaction_k_time},
    "exp-custody-bars": {"acm": exp_custody_bars},
    "exp-anchor-all": {"ieee": exp_anchor_all},
    "exp-custody-all": {"ieee": exp_custody_all},
    "exp-redaction-custody": {"ieee": exp_redaction_custody},
}


# --------------------------------------------------------------- rendering

def _runs(xs: list, ys: list):
    """Split into runs of consecutive measured points: a None is a gap."""
    run = []
    for x, y in zip(xs, ys):
        if y is None:
            if run:
                yield run
            run = []
        else:
            run.append((x, y))
    if run:
        yield run


#: §1al print sizes (IEEEtran): what is emitted is what prints, unscaled.
TEXT_WIDTH_IN, COLUMN_WIDTH_IN = 7.16, 3.5
#: (text width, column width) in inches per paper class. ACM SIGCONF's were
#: measured from `acmart` (§1as.3.1): 506.30 pt and 241.15 pt, TeX points.
TARGETS = {
    "ieee": (TEXT_WIDTH_IN, COLUMN_WIDTH_IN),
    "acm": (506.30 / 72.27, 241.15 / 72.27),
}
#: Smallest plotting-area height, in inches, for every panel (§1al.2).
MIN_PLOT_IN = 1.9
#: §1cm: the compact bar figures, two panels in one column, asked for at about
#: 3.6 cm tall in all. The plotting area is what is left after the legend,
#: titles and k labels.
PLOT_IN_COMPACT = 0.8
#: The user (2026-10-15): SAC's line figures (Figs. 2, 3 and 5) smaller. A
#: shorter plotting area, and the width comes from the paper's placement
#: fraction (`render`'s `frac`), so the text keeps its 8/9 pt in print.
PLOT_IN_SAC = 1.3
#: Per-series identity beyond colour (§1al.6): marker, line style, filled.
#: Colour, marker and dash all differ between any two series, so two series
#: lying on top of each other stay distinguishable without moving a point.
STYLE = {
    OURS: ("o", "-", True),
    BASE1: ("s", (0, (4.5, 2.0)), False),
    BASE2: ("^", (0, (6.0, 1.8, 1.2, 1.8)), True),
    BASE3: ("D", (0, (1.2, 1.6)), False),
    BASE4: ("v", (0, (3.0, 1.2, 1.0, 1.2, 1.0, 1.2)), True),
    BASE4_ONE_EPOCH: ("v", (0, (7.0, 3.0)), False),
    BASE5: ("P", (0, (2.0, 2.0)), True),
}
#: Layout of the last render of each figure, read by the self-tests.
LAYOUT: dict = {}


def log_ticks(lo: float, hi: float, limit: int = 5) -> list:
    """Labelled ticks for a log axis over [lo, hi]: decades only (§1al.5),
    thinned to at most `limit`. A span inside one decade has no two decades to
    label, so it falls back to 1-2-5 values, still at most `limit`."""
    e_lo = math.ceil(math.log10(lo) - 1e-9)
    e_hi = math.floor(math.log10(hi) + 1e-9)
    ticks = [10.0 ** e for e in range(e_lo, e_hi + 1)]
    if len(ticks) < 2:
        ticks = [m * 10.0 ** e for e in range(e_lo - 1, e_hi + 1) for m in (1, 2, 5)
                 if lo <= m * 10.0 ** e <= hi]
    step = max(1, math.ceil(len(ticks) / limit))
    return ticks[::step]


def tick_labels(ticks: list) -> list:
    """One style per axis: every tick as a power of ten when the axis reaches
    10^4 (and all ticks are decades), plain numbers otherwise. Mixing
    "1,000" with "10^5" on one axis reads as two scales."""
    decades = all(abs(math.log10(t) - round(math.log10(t))) < 1e-9 for t in ticks)
    if decades and ticks and max(ticks) >= 1e4:
        return [f"$10^{{{round(math.log10(t))}}}$" for t in ticks]
    return [f"{t:,.0f}" if t >= 10 else f"{t:g}" for t in ticks]


def _legend_cols(labels: list, width_in: float, handle_in: float = 0.75) -> int:
    """Columns that fit `width_in` at 8 pt: ~0.062 in per character plus the
    handle and spacing (a bar legend's short patch is `handle_in` = 0.45)."""
    item = handle_in + 0.062 * max(len(lbl) for lbl in labels)
    return max(1, min(len(labels), int(width_in // item)))


def _title_x(p: Panel) -> float:
    """Where a panel title starts, in axes fraction. A bar panel in one column
    is narrow, so its title starts over the tick labels (§1cm): at the axis
    edge, "(b) time to erasure (s)" ran past the page."""
    return -0.12 if p.categories else 0.0


def _bars(ax, p: Panel) -> None:
    """§1cm: grouped bars, one group per category and one bar per series, in
    series order. Each bar is a measured median; its IQR is a whisker where the
    series has one. A filled bar takes its colour; an open bar is white with a
    coloured edge; a hatch is drawn in white on a filled bar and in colour on an
    open one. A log panel's bars start at the axis floor, which sits below the
    smallest measured value or whisker, as on the line panels."""
    from matplotlib.ticker import NullFormatter

    cats = p.categories
    group, n = 0.8, len(p.series)
    bw = group / n
    vals = [v for s in p.series for v in s.y if v is not None]
    vals += [v for s in p.series for v in (s.lo or []) + (s.hi or []) if v is not None]
    if not vals:
        return
    lo, hi = min(vals), max(vals)
    if p.yscale == "log":
        if lo <= 0:
            raise ValueError(f"panel {p.title!r}: a log bar panel holds a value <= 0")
        ax.set_yscale("log")
        floor = lo / 1.3
    else:
        floor = 0.0
    for i, s in enumerate(p.series):
        if len(s.y) != len(cats):
            raise ValueError(f"series {s.label!r} has {len(s.y)} values for {len(cats)} groups")
        for j, y in enumerate(s.y):
            if y is None:
                continue
            x = j - group / 2 + bw * (i + 0.5)
            col = s.colors[j] if s.colors else s.color
            hatch = s.hatches[j] if s.hatches else ""
            ax.bar(x, y - floor, bottom=floor, width=bw * 0.9, color=col if s.filled else "white",
                   edgecolor=("white" if s.filled else col) if hatch else col, hatch=hatch or None,
                   linewidth=0 if s.filled else 0.8, label=s.label, zorder=2.5)
            if hatch and s.filled:
                ax.bar(x, y - floor, bottom=floor, width=bw * 0.9, fill=False, edgecolor=col,
                       linewidth=0.8, zorder=2.6)
            if s.lo is not None and s.hi is not None and s.lo[j] is not None and s.hi[j] is not None:
                ax.errorbar([x], [y], yerr=[[max(y - s.lo[j], 0)], [max(s.hi[j] - y, 0)]],
                            color=INK, capsize=1.5, elinewidth=0.7, fmt="none", zorder=3.0)
    ax.set_xticks(range(len(cats)), cats)
    ax.set_xlim(-0.5, len(cats) - 0.5)
    ax.tick_params(axis="x", length=0, labelsize=7)
    if p.xlabel:
        ax.set_xlabel(p.xlabel)
    if p.ylabel:
        ax.set_ylabel(p.ylabel)
    ax.grid(True, axis="y", which="major", color=GRID, linewidth=0.5, zorder=0)
    ax.set_axisbelow(True)
    if p.yscale == "log":
        ax.set_ylim(floor, hi * 1.3)
        ticks = log_ticks(floor, hi * 1.3)
        ax.set_yticks(ticks, tick_labels(ticks))
        ax.yaxis.set_minor_formatter(NullFormatter())
    else:
        ax.set_ylim(0, hi * 1.08)
        from matplotlib.ticker import MaxNLocator

        ax.yaxis.set_major_locator(MaxNLocator(4))


def render(fig: Figure, out: Path, target: str = "ieee", frac: float = 1.0) -> Path:
    """Draw `fig` at its print size: the column or text width of `target`,
    times `frac`, the fraction the paper places it at (`\\genfig[0.88]`), so
    `\\includegraphics` prints it 1:1 and no text is scaled below 7 pt."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator, NullFormatter

    # §1al.3: ticks and legends 8 pt, axis labels and titles 9 pt, nothing < 7.
    plt.rcParams.update({
        "pdf.fonttype": 42, "ps.fonttype": 42, "font.size": 8, "axes.labelsize": 9,
        "axes.titlesize": 9, "legend.fontsize": 8, "legend.title_fontsize": 9,
        "xtick.labelsize": 8, "ytick.labelsize": 8,
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK,
        "axes.spines.top": False, "axes.spines.right": False, "lines.linewidth": 1.4,
        "lines.markersize": 5, "legend.frameon": False,
    })

    n = len(fig.panels)
    text_w, column_w = TARGETS[target]
    if not 0.5 <= frac <= 1.0:
        raise ValueError(f"{fig.name}: placement fraction {frac} is outside 0.5-1")
    width = (text_w if fig.wide else column_w) * frac
    plot_in = fig.plot_in or MIN_PLOT_IN
    f = plt.figure(figsize=(width, plot_in + 1.2), layout="constrained")
    f.get_layout_engine().set(w_pad=0.04, h_pad=0.03, wspace=0.06, hspace=0.0)
    axes = f.subplots(1, n, squeeze=False)[0]

    for ax, p in zip(axes, fig.panels):
        if p.categories:
            _bars(ax, p)  # titles follow with the legend, below
            continue
        xs_all, ys_all = [], []
        for s in p.series:
            marker, dash, filled = STYLE.get(s.color, ("o", "-", True))
            for run in _runs(s.x, s.y):
                rx, ry = [q[0] for q in run], [q[1] for q in run]
                ax.plot(rx, ry, color=s.color, marker=marker, linestyle=dash,
                        markerfacecolor=s.color if filled else "white", markeredgewidth=1.1,
                        label=s.label, zorder=3.0 if s.color == OURS else 2.5)
                xs_all += rx
                ys_all += ry
            if s.lo is not None and s.hi is not None:
                for x, y, lo, hi in zip(s.x, s.y, s.lo, s.hi):
                    if y is not None and lo is not None and hi is not None:
                        ax.errorbar([x], [y], yerr=[[max(y - lo, 0)], [max(hi - y, 0)]],
                                    color=s.color, capsize=2, elinewidth=0.8, fmt="none", zorder=2.0)
                        ys_all += [lo, hi]
        for y, ref in p.refs:
            ax.axhline(y, color=MUTED, linestyle=(0, (1.0, 1.0)), linewidth=1.0, label=ref)
            ys_all.append(y)
        ax.set_xscale(p.xscale, **({"base": p.xbase} if p.xscale == "log" else {}))
        ax.set_yscale(p.yscale)
        ax.set_xlabel(p.xlabel)
        ax.set_ylabel(p.ylabel)
        ax.grid(True, which="major", color=GRID, linewidth=0.5)
        if xs_all:
            # Axis limits at the measured range (a small margin so markers show).
            lo, hi = min(xs_all), max(xs_all)
            if p.xscale == "log":
                ax.set_xlim(lo / 1.15, hi * 1.15)
                if p.xbase == 2:
                    # Powers of two anchored at the smallest measured one, at
                    # most five labels.
                    e_lo = int(math.floor(math.log2(lo)))
                    e_hi = int(math.ceil(math.log2(hi)))
                    step = max(1, math.ceil((e_hi - e_lo + 1) / 5))
                    ticks = [2 ** e for e in range(e_lo, e_hi + 1, step)]
                    ax.set_xticks(ticks, [f"$2^{{{int(math.log2(t))}}}$" for t in ticks])
                else:
                    ticks = log_ticks(lo / 1.15, hi * 1.15)
                    ax.set_xticks(ticks, tick_labels(ticks))
                ax.xaxis.set_minor_formatter(NullFormatter())
            else:
                ax.set_xlim(lo, hi)
                ax.xaxis.set_major_locator(MaxNLocator(5))
        if ys_all:
            lo, hi = min(ys_all), max(ys_all)
            if p.yscale == "log" and lo > 0:
                ax.set_ylim(lo / 1.3, hi * 1.3)
                ticks = log_ticks(lo / 1.3, hi * 1.3)
                ax.set_yticks(ticks, tick_labels(ticks))
                ax.yaxis.set_minor_formatter(NullFormatter())
            elif p.yscale != "log":
                ax.yaxis.set_major_locator(MaxNLocator(5))

    # §1al.4: legends ABOVE the plotting areas, never inside one. One shared
    # row when every panel plots the same series; otherwise (panels plotting
    # different quantities, where one legend would give a colour two meanings)
    # each panel carries its own legend above it, titled with the panel title.
    # Notes are not drawn: they live in the paper's text (§1ad.2).
    per_panel = []
    for ax in axes:
        d = {}
        for h, lbl in zip(*ax.get_legend_handles_labels()):
            d.setdefault(lbl, h)
        per_panel.append(d)
    shared = all(list(d) == list(per_panel[0]) for d in per_panel)
    if fig.legend:
        # Proxy patches: the bar colours name the groups, so the legend names
        # what fill and hatch mean instead (§1cm.2).
        from matplotlib.patches import Patch

        for ax, p in zip(axes, fig.panels):
            if p.title:
                ax.set_title(p.title, loc="left", pad=3, x=_title_x(p))
        handles = [Patch(facecolor=face, edgecolor=edge, hatch=hatch, linewidth=0.8)
                   for _, face, edge, hatch in fig.legend]
        labels = [lbl for lbl, _, _, _ in fig.legend]
        f.legend(handles, labels, loc="outside upper center",
                 ncol=_legend_cols(labels, width - 0.2, 0.45), columnspacing=1.0, handlelength=1.2,
                 borderaxespad=0.1)
    elif shared and per_panel[0]:
        for ax, p in zip(axes, fig.panels):
            if p.title:
                ax.set_title(p.title, loc="left", pad=3, x=_title_x(p))
        labels = list(per_panel[0])
        bars = any(p.categories for p in fig.panels)
        f.legend(list(per_panel[0].values()), labels, loc="outside upper center",
                 ncol=_legend_cols(labels, width - 0.2, 0.45 if bars else 0.75),
                 columnspacing=1.0 if bars else 1.4, handlelength=1.2 if bars else 2.6,
                 borderaxespad=0.1)
    else:
        for ax, p, g in zip(axes, fig.panels, per_panel):
            if not g:
                if p.title:
                    ax.set_title(p.title, loc="left", pad=3, x=_title_x(p))
                continue
            labels = list(g)
            ax.legend(list(g.values()), labels, loc="lower left", bbox_to_anchor=(0.0, 1.01),
                      ncol=_legend_cols(labels, width / n - 0.3), title=p.title or None,
                      alignment="left", columnspacing=1.2, handlelength=2.6, borderaxespad=0.0)

    # §1al.2: grow or shrink the page until the smallest plotting area is
    # MIN_PLOT_IN tall, with the width fixed at the print width.
    height = plot_in + 1.2
    target = plot_in + 0.02
    for _ in range(8):
        f.set_size_inches(width, height)
        f.canvas.draw()
        plot_h = min(ax.get_position().height for ax in axes) * height
        if abs(plot_h - target) < 0.005:
            break
        height += target - plot_h
    f.canvas.draw()

    def labelled(axis_ticks, lim):
        return sum(1 for t in axis_ticks if lim[0] <= t <= lim[1])

    LAYOUT[fig.name] = {
        "width_in": float(f.get_size_inches()[0]),
        "height_in": float(f.get_size_inches()[1]),
        "min_plot_in": min(ax.get_position().height for ax in axes) * float(f.get_size_inches()[1]),
        "max_major_ticks": max(max(labelled(a.get_xticks(), a.get_xlim()),
                                   labelled(a.get_yticks(), a.get_ylim())) for a in axes),
        "text_outside": any(
            not (txt.get_window_extent().x0 >= -0.5 and txt.get_window_extent().x1 <= f.bbox.x1 + 0.5)
            for txt in f.findobj(matplotlib.text.Text) if txt.get_visible() and txt.get_text()),
        "legend_inside": any(a.get_legend() is not None
                             and a.get_legend().get_window_extent().overlaps(a.get_window_extent())
                             and a.get_legend().get_window_extent().y0 < a.get_window_extent().y1 - 1
                             for a in axes),
    }

    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{fig.name}.pdf"
    # No tight bounding box: the page is the print size (§1al.1). Constrained
    # layout keeps every label and legend inside it. No CreationDate: the same
    # records must emit byte-identical PDFs (§1af.5).
    f.savefig(path, metadata={"CreationDate": None})
    plt.close(f)
    return path
