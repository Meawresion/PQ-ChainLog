#!/usr/bin/env python3
"""Export every publishable result record to CSV, and chart it as PNG.

    python tools/export_results.py [results/] [--out results/export]

Writes ``<out>/csv/<experiment>*.csv`` (one flat row per measured row — the
table view of every chart) and ``<out>/png/<experiment>*.png``.

⛔ **Working charts, not paper figures.** Paper numbers flow only through
``mkfigs.py`` into ``values.tex``. This reads the same records so the charts
cannot disagree with the paper, but nothing here is an input to the paper.

⚠️ **Publishable records only.** A record is used only if it is from AWS with a
clean tree (or a Doris carve-out record with a clean tree). A local record is
skipped and named, so a chart can never silently mix a laptop timing into an
AWS figure. For each experiment the newest publishable record is used.

Style follows the dataviz reference palette: categorical hues in fixed order,
a one-hue sequential ramp for ordered quantities, one y-axis per panel (two
measures -> two panels, never a dual axis), medians with IQR whiskers.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# --- palette (dataviz reference instance; validated, see docstring) ---------
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # fixed order, never cycled
SEQUENTIAL = ["#86b6ef", "#3987e5", "#1c5cab", "#0d366b"]  # one hue, light -> dark
SURFACE, INK, INK2, MUTED = "#fcfcfb", "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"
MARKERS = ["o", "s", "^", "D"]  # secondary encoding: identity is never colour alone

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": AXIS, "axes.labelcolor": INK2, "axes.titlecolor": INK,
    "axes.titlesize": 11, "axes.titleweight": "bold", "axes.labelsize": 9,
    "xtick.color": MUTED, "ytick.color": MUTED, "xtick.labelsize": 8, "ytick.labelsize": 8,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False,
    "lines.linewidth": 2, "lines.markersize": 7,
    "legend.frameon": False, "legend.fontsize": 8, "font.size": 9,
})


# --- records ----------------------------------------------------------------

def publishable(rec: dict) -> bool:
    if rec.get("git_dirty") is not False:
        return False
    if rec.get("experiment") == "doris-structural":
        return True  # the carve-out: structural, deterministic, AWS-exempt
    return rec.get("environment") == "aws"


def load(results: Path) -> tuple[dict[str, list[tuple[Path, dict]]], list[str]]:
    by_exp: dict[str, list[tuple[Path, dict]]] = {}
    skipped: list[str] = []
    for f in sorted(results.rglob("*.json")):
        if "export" in f.parts:
            continue
        rec = json.loads(f.read_text(encoding="utf-8"))
        if not publishable(rec):
            skipped.append(str(f))
            continue
        by_exp.setdefault(rec.get("experiment", f.parent.name), []).append((f, rec))
    return by_exp, skipped


def newest(recs: list[tuple[Path, dict]]) -> tuple[Path, dict]:
    return sorted(recs, key=lambda pr: str(pr[1].get("started_utc", pr[0].name)))[-1]


def stamp(path: Path) -> str:
    """'<utc>-<sha12>-<instance>.json' -> 'AWS m7i.4xlarge · 4cb4e1e'."""
    parts = path.stem.split("-")
    if len(parts) >= 3:
        return f"AWS {parts[-1]} · commit {parts[-2][:7]}"
    return f"AWS · {path.name}"


# --- helpers ----------------------------------------------------------------

def flatten(obj, key: str = "") -> dict:
    """Nested dicts -> dotted columns (`pi_xt.search_ns.median_ns`); a list of
    scalars -> one `;`-joined cell; a list of dicts -> indexed columns."""
    if isinstance(obj, dict):
        out: dict = {}
        for k, v in obj.items():
            out.update(flatten(v, f"{key}.{k}" if key else k))
        return out
    if isinstance(obj, list):
        if all(not isinstance(x, (dict, list)) for x in obj):
            return {key: ";".join(str(x) for x in obj)}
        out = {}
        for i, x in enumerate(obj):
            out.update(flatten(x, f"{key}.{i}"))
        return out
    return {key: obj}


def write_csv(path: Path, rows: list[dict]) -> Path:
    flat = [flatten(r) for r in rows]
    # Prose notes are provenance, not data; they stay in the JSON record.
    cols: list[str] = []
    for r in flat:
        for k in r:
            if k not in cols and not k.endswith(("note", "reason")):
                cols.append(k)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(flat)
    return path


def med(s: dict, scale: float = 1.0) -> tuple[float, float, float]:
    """(median, lower whisker, upper whisker) in `scale` units, from a Summary."""
    m = s["median_ns"] / scale
    return m, m - s["p25_ns"] / scale, s["p75_ns"] / scale - m


def line(ax, xs, summaries, label, i, scale, seq=False):
    ys = [med(s, scale) for s in summaries]
    colour = (SEQUENTIAL if seq else SERIES)[i]
    ax.errorbar(xs, [y[0] for y in ys], yerr=[[y[1] for y in ys], [y[2] for y in ys]],
                label=label, color=colour, marker=MARKERS[i % 4], capsize=3, elinewidth=1)


def plain(ax, xs, ys, label, i, **kw):
    """An un-whiskered series drawn through `errorbar` too, so every series is
    the same artist type and the legend keeps plotting order."""
    ax.errorbar(xs, ys, label=label, color=kw.pop("color", SERIES[i]),
                marker=kw.pop("marker", MARKERS[i % 4]), **kw)


def categories(ax, axis: str, positions, labels, **kw):
    """Set category tick labels and mark the axis so `tidy()` leaves it alone."""
    (ax.set_yticks if axis == "y" else ax.set_xticks)(list(positions), labels, **kw)
    ax._pqcl_categorical = getattr(ax, "_pqcl_categorical", set()) | {axis}


def _thousands(v, _pos):
    return f"{v:,.0f}" if abs(v) >= 1000 else f"{v:g}"


def tidy(fig):
    """Readable linear axes: thousands separators, no hidden `1e7` offset, and
    ticks at the actual values when x is a short integer sweep."""
    from matplotlib.ticker import FuncFormatter
    for ax in fig.axes:
        # ⚠️ Never touch an axis carrying category labels: reformatting turns
        # names into numbers. Marked explicitly by `categories()` — checking the
        # formatter's type did not work (matplotlib 3.10 labels bars without a
        # FixedFormatter), and the first render showed 0..7 instead of names.
        cat = getattr(ax, "_pqcl_categorical", set())
        if ax.get_yscale() == "linear" and "y" not in cat:
            ax.yaxis.set_major_formatter(FuncFormatter(_thousands))
        if ax.get_xscale() == "linear" and "x" not in cat:
            xs = sorted({float(x) for ln in ax.get_lines() for x in ln.get_xdata()})
            if 1 < len(xs) <= 8 and all(x == int(x) for x in xs):
                ax.set_xticks(xs)
                ax.xaxis.set_major_formatter(FuncFormatter(_thousands))


def finish(fig, title: str, src: Path, out: Path) -> Path:
    tidy(fig)
    fig.suptitle(title, x=0.01, ha="left", fontsize=12, fontweight="bold", color=INK)
    fig.text(0.01, 0.005, f"{stamp(src)} · median, whiskers = IQR where shown",
             fontsize=7, color=MUTED, ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.03, 1, 0.95))
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def legend(ax):
    if len(ax.get_legend_handles_labels()[0]) >= 2:  # one series: the title names it
        ax.legend()


# --- per-experiment exporters ---------------------------------------------
# Each returns the list of files it wrote.

def exp1(src, m, out):
    rows = [
        {"config": "plaintext (keyword)", "signing_batch_size": None,
         "query_class": "keyword", **_s(m["plaintext_total_ns"], m["events"])},
        {"config": "plaintext (ordered range index)", "signing_batch_size": None,
         "query_class": "keyword+range", **_s(m["plaintext_ordered_total_ns"], m["events"])},
    ]
    for r in m["rows"]:
        b = r["signing_batch_size"]
        rows.append({"config": f"ML-DSA-65, B={b}", "signing_batch_size": b,
                     "query_class": "keyword", **_s(r["pqc_total_ns"], m["events"])})
        if r.get("classical_total_ns"):
            rows.append({"config": f"ECDSA-P256, B={b}", "signing_batch_size": b,
                         "query_class": "keyword", **_s(r["classical_total_ns"], m["events"])})
        rows.append({"config": f"ML-DSA-65 + range, B={b}", "signing_batch_size": b,
                     "query_class": "keyword+range", **_s(r["pqc_with_range_total_ns"], m["events"])})
    files = [write_csv(out / "csv" / "exp1-ingestion.csv", rows)]

    fig, ax = plt.subplots(figsize=(8, 5.2))
    shown = [r for r in rows if r["signing_batch_size"] in (None, 1, 1024)]
    ys = range(len(shown))
    ax.barh(list(ys), [r["events_per_s"] for r in shown], color=SERIES[0], height=0.6)
    categories(ax, "y", ys, [r["config"] for r in shown])
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlabel("events per second (log scale)")
    for y, r in zip(ys, shown):
        ax.text(r["events_per_s"] * 1.08, y, f"{r['events_per_s']:,.0f}", va="center", fontsize=7, color=INK2)
    ax.grid(axis="y", visible=False)
    files.append(finish(fig, "Exp. 1 — ingestion throughput", src, out / "png" / "exp1-throughput.png"))

    fig, ax = plt.subplots(figsize=(7, 4.2))
    bs = [r["signing_batch_size"] for r in m["rows"]]
    line(ax, bs, [r["pqc_total_ns"] for r in m["rows"]], "ML-DSA-65", 0, 1e6)
    if all(r.get("classical_total_ns") for r in m["rows"]):
        line(ax, bs, [r["classical_total_ns"] for r in m["rows"]], "ECDSA-P256 (same pipeline)", 1, 1e6)
    ax.set_xscale("log", base=2)
    ax.set_xticks(bs, [str(b) for b in bs])
    ax.minorticks_off()
    ax.set_xlabel("signing batch size B")
    ax.set_ylabel(f"ms to ingest {m['events']:,} events")
    ax.set_ylim(bottom=0)
    legend(ax)
    files.append(finish(fig, "Exp. 1 — post-quantum vs classical signing, same pipeline", src,
                        out / "png" / "exp1-pq-vs-classical.png"))
    if "head_to_head" in m:
        files += exp1_head_to_head(src, m["head_to_head"], out)
    if "range_ingest_across_y" in m:
        files += exp1_across_y(src, m["range_ingest_across_y"], out)
    return files


def exp1_head_to_head(src, h, out):
    rows = [{"scheme": r["scheme"], "query_class": r["query_class"], "entries": r["entries"],
             **_s(r["total_ns"], h["events"])} for r in h["rows"]]
    files = [write_csv(out / "csv" / "exp1-head-to-head.csv", rows)]
    fig, ax = plt.subplots(figsize=(8, 4.6))
    ys = range(len(rows))
    colours = [SERIES[0] if r["scheme"] == "PQ-ChainLog" else (MUTED if r["scheme"] == "Plaintext" else SERIES[1])
               for r in rows]
    ax.barh(list(ys), [r["events_per_s"] for r in rows], color=colours, height=0.6)
    categories(ax, "y", ys, [f"{r['scheme']} — {r['query_class']}" for r in rows])
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlabel(f"events per second (log scale), {h['events']:,} events")
    for y, r in zip(ys, rows):
        ax.text(r["events_per_s"] * 1.08, y, f"{r['events_per_s']:,.0f}", va="center", fontsize=7, color=INK2)
    ax.grid(axis="y", visible=False)
    files.append(finish(fig, "Exp. 1 — ingestion head-to-head (blue: ours, orange: baselines, grey: plaintext)",
                        src, out / "png" / "exp1-head-to-head.png"))
    return files


def exp1_across_y(src, y, out):
    # Ours first: SERIES[0] is "ours" blue in every other chart.
    series = [("ours_range", "ours (range)"), ("zuo22", "Zuo'22 (range)"),
              ("ours_keyword_range", "ours (keyword + range)"), ("odxt_zuo22", "ODXT + Zuo'22 (keyword + range)")]
    rows = []
    for r in y["rows"]:
        row = {"y": r["y"], "events": r.get("events"), "skipped": bool(r.get("skipped")),
               "skip_reason": r.get("reason", "")}
        for key, _ in series:
            if isinstance(r.get(key), dict):
                row[f"{key}_events_per_s"] = r["events"] * 1e9 / r[key]["total_ns"]["median_ns"]
        rows.append(row)
    files = [write_csv(out / "csv" / "exp1-range-across-y.csv", rows)]
    done = [r for r in y["rows"] if not r.get("skipped")]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for i, (key, label) in enumerate(series):
        xs = [r["y"] for r in done]
        plain(ax, xs, [r["events"] * 1e9 / r[key]["total_ns"]["median_ns"] for r in done], label, i)
    ax.set_xscale("log", base=2)
    ax.set_xticks([r["y"] for r in done], [f"{r['y']:,}" for r in done])
    ax.minorticks_off()
    ax.set_yscale("log")
    ax.set_xlabel("y: range-domain bitmap width, and events (one per value)")
    ax.set_ylabel("events per second (log)")
    legend(ax)
    skipped = [f"y = {r['y']:,} skipped: {r.get('reason', '')}" for r in y["rows"] if r.get("skipped")]
    if skipped:
        ax.text(0.01, 0.02, "\n".join(skipped), transform=ax.transAxes, fontsize=6.5, color=MUTED)
    files.append(finish(fig, "Exp. 1 — range ingest across y", src, out / "png" / "exp1-range-across-y.png"))
    return files


def _s(summary, events):
    return {"median_ns": summary["median_ns"], "p25_ns": summary["p25_ns"],
            "p75_ns": summary["p75_ns"], "n": summary["n"],
            "events_per_s": events * 1e9 / summary["median_ns"]}


def exp2(src, m, out):
    rows = m["rows"]
    files = [write_csv(out / "csv" / "exp2-conjunctive-latency.csv", rows)]
    widths = sorted({r["conjunction_width"] for r in rows})
    fig, axes = plt.subplots(1, len(widths), figsize=(4 * len(widths), 3.8), sharey=True, squeeze=False)
    for ax, w in zip(axes[0], widths):
        rs = sorted((r for r in rows if r["conjunction_width"] == w), key=lambda r: r["documents"])
        docs = [r["documents"] for r in rs]
        line(ax, docs, [r["pi_xt"]["search_ns"] for r in rs], "Π_XT (2 rounds)", 0, 1e3)
        line(ax, docs, [r["odxt"]["search_ns"] for r in rs], "ODXT (1 round)", 1, 1e3)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_title(f"conjunction width {w}")
        ax.set_xlabel("documents")
    legend(axes[0][0])  # colours are shared across panels: one legend
    axes[0][0].set_ylabel("search latency, µs (log)")
    files.append(finish(fig, "Exp. 2 — conjunctive search latency, Π_XT vs ODXT", src,
                        out / "png" / "exp2-latency.png"))
    return files


def _panels(src, out, rows, x, xlabel, panels, title, name, logx=False):
    """One single-series panel per measure: never a dual axis."""
    # Floor of 6.5 in: a single panel at 3.6 in cropped its own title and footer.
    fig, axes = plt.subplots(1, len(panels), figsize=(max(6.5, 3.6 * len(panels)), 3.6), squeeze=False)
    xs = [r[x] for r in rows]
    for ax, (key, label, get) in zip(axes[0], panels):
        vals = [get(r) for r in rows]
        if isinstance(vals[0], dict):
            line(ax, xs, vals, label, 0, 1e3)
            ax.set_ylabel(f"{label}, µs")
        else:
            ax.plot(xs, vals, color=SERIES[0], marker=MARKERS[0])
            ax.set_ylabel(label)
        ax.set_title(label)
        ax.set_xlabel(xlabel)
        ax.set_ylim(bottom=0)
        if logx:
            ax.set_xscale("log")
    return finish(fig, title, src, out / "png" / name)


def exp3(src, m, out):
    rows = sorted(m["rows"], key=lambda r: r["queries"])
    files = [write_csv(out / "csv" / "exp3-leakage.csv", rows)]
    files.append(_panels(src, out, rows, "queries", "queries issued", [
        ("probe_count_total", "probes sent", lambda r: r["probe_count_total"]),
        ("hit_link_distinct_pairs", "distinct HitLink pairs", lambda r: r["hit_link_distinct_pairs"]),
        ("eq_pat_distinct_s_terms", "distinct s-terms (EqPat)", lambda r: r["eq_pat_distinct_s_terms"]),
        ("wire_bytes_up_total", "bytes up", lambda r: r["wire_bytes_up_total"]),
    ], f"Exp. 3 — leakage counters vs query volume (width {m.get('conjunction_width')})", "exp3-leakage.png"))
    return files


def exp4(src, m, out):
    rows = sorted(m["rows"], key=lambda r: r["closed_epochs"])
    files = [write_csv(out / "csv" / "exp4-epoch-compaction.csv", rows)]
    files.append(_panels(src, out, rows, "closed_epochs", "closed epochs E", [
        ("search", "search latency", lambda r: r["search_ns"]),
        ("probes", "probes per query (median)", lambda r: r["probe_count_median"]),
        ("wire", "bytes up per query (median)", lambda r: r["wire_bytes_up_median"]),
    ], "Exp. 4 — epoch count vs search cost", "exp4-epochs.png"))
    fig, ax = plt.subplots(figsize=(6, 3.8))
    es = [r["closed_epochs"] for r in rows]
    ax.plot(es, [r["compaction"]["xtags_before"] for r in rows], color=SERIES[0], marker=MARKERS[0], label="before compaction")
    ax.plot(es, [r["compaction"]["xtags_after"] for r in rows], color=SERIES[1], marker=MARKERS[1], label="after compaction")
    ax.set_xlabel("closed epochs E")
    ax.set_ylabel("cross-tags in XSet")
    ax.set_ylim(bottom=0)
    legend(ax)
    files.append(finish(fig, "Exp. 4 — compaction reclaims deleted pairs", src, out / "png" / "exp4-compaction.png"))
    return files


def exp5(src, m, out):
    rows = m["rows"]
    files = [write_csv(out / "csv" / "exp5-bloom-xset.csv", rows)]
    eps = sorted({r["epsilon"] for r in rows}, reverse=True)  # loosest first = lightest
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), squeeze=False)
    ax = axes[0][0]
    for i, e in enumerate(eps):
        rs = sorted((r for r in rows if r["epsilon"] == e), key=lambda r: r["closed_epochs"])
        ax.plot([r["closed_epochs"] for r in rs], [r["answer_loss_ppm"] for r in rs],
                color=SEQUENTIAL[i], marker=MARKERS[i], label=f"ε = {e:g}")
    ax.set_yscale("symlog", linthresh=1)
    ax.set_xlabel("closed epochs E")
    ax.set_ylabel("true matches dropped, ppm (symlog)")
    ax.set_title("answer loss")
    legend(ax)
    ax = axes[0][1]
    for i, e in enumerate(eps):
        rs = sorted((r for r in rows if r["epsilon"] == e), key=lambda r: r["closed_epochs"])
        ax.plot([r["closed_epochs"] for r in rs], [r["bits_per_tag_milli"] / 1000 for r in rs],
                color=SEQUENTIAL[i], marker=MARKERS[i], label=f"ε = {e:g}")
    ax.set_xlabel("closed epochs E")
    ax.set_ylabel("filter bits per cross-tag")
    ax.set_title("space")
    ax.set_ylim(bottom=0)
    legend(ax)
    files.append(finish(fig, "Exp. 5 — Bloom XSet: loss and space vs ε and E", src, out / "png" / "exp5-bloom.png"))
    return files


def exp6(src, m, out):
    rows = sorted(m["epochs"], key=lambda r: r["leaves"])
    gas = m.get("anchor_gas", {}).get("anchor_commit_gas")
    files = [write_csv(out / "csv" / "exp6-anchoring.csv",
                       [{**r, "anchor_commit_gas": gas} for r in rows])]
    files.append(_panels(src, out, rows, "leaves", "leaves per epoch", [
        ("sign", "anchor signing (ML-DSA-65)", lambda r: r["anchor_sign_ns"]),
        ("build", "MMR build + root", lambda r: r["mmr_build_and_root_ns"]),
        ("verify", "auditor inclusion verify", lambda r: r["auditor_verify_inclusion_ns"]),
        ("proof", "inclusion proof, bytes", lambda r: r["inclusion_proof_bytes"]),
    ], "Exp. 6 — per-epoch anchoring costs", "exp6-anchoring.png", logx=True))
    if gas:
        ns = [10**k for k in range(3, 7)]
        write_csv(out / "csv" / "exp6-gas-per-entry.csv",
                  [{"entries_per_epoch": n, "anchor_commit_gas": gas, "gas_per_entry": gas / n} for n in ns])
        files.append(out / "csv" / "exp6-gas-per-entry.csv")
        fig, ax = plt.subplots(figsize=(6, 3.8))
        ax.plot(ns, [gas / n for n in ns], color=SERIES[0], marker=MARKERS[0])
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("entries per epoch (N)")
        ax.set_ylabel("gas per entry (log)")
        for n in ns:
            # Three significant figures: `.1f` printed 0.037 as "0.0".
            ax.annotate(f"{gas / n:.3g}", (n, gas / n), textcoords="offset points", xytext=(5, 5), fontsize=7, color=INK2)
        files.append(finish(fig, f"Exp. 6 — anchor gas amortised: {gas:,} gas / N", src,
                            out / "png" / "exp6-gas-per-entry.png"))
    return files


def exp7(src, m, out):
    rows = m["rows"]
    files = [write_csv(out / "csv" / "exp7-range.csv", rows),
             write_csv(out / "csv" / "exp7-boolean.csv", m["boolean_forms"]),
             write_csv(out / "csv" / "exp7-index-size.csv", m["index_sizes"])]
    depths = sorted({r["depth"] for r in rows})
    fig, axes = plt.subplots(1, len(depths), figsize=(4 * len(depths), 3.8), sharey=True, squeeze=False)
    for ax, d in zip(axes[0], depths):
        rs = sorted((r for r in rows if r["depth"] == d), key=lambda r: r["range_width_pct"])
        xs = [r["range_width_pct"] for r in rs]
        line(ax, xs, [r["pi_range"]["search_ns"] for r in rs], "Π_RANGE", 0, 1e3)
        plain(ax, xs, [r["zuo22"]["cold_search_ns"] / 1e3 for r in rs],
              "Zuo'22, cold (single observation)", 1)
        warm = [r["zuo22"].get("warm_search_ns") for r in rs]
        if all(isinstance(w, dict) for w in warm):
            line(ax, xs, warm, "Zuo'22, warm", 2, 1e3)
        ax.set_yscale("log")
        ax.set_title(f"domain $2^{{{d}}}$")
        ax.set_xlabel("range width, % of domain")
    legend(axes[0][0])  # shared colours: one legend, in plotting order
    axes[0][0].set_ylabel("search latency, µs (log)")
    files.append(finish(fig, "Exp. 7 — range search, Π_RANGE vs Zuo'22", src, out / "png" / "exp7-range.png"))

    forms = m["boolean_forms"]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), squeeze=False)
    names = [f["form"] for f in forms]
    for ax, key, scale, unit, title in ((axes[0][0], "total_ns", 1e6, "ms", "end-to-end query"),
                                        (axes[0][1], "client_eval_ns", 1e3, "µs", "client-side formula evaluation")):
        ms = [med(f[key], scale) for f in forms]
        ax.bar(range(len(forms)), [x[0] for x in ms], yerr=[[x[1] for x in ms], [x[2] for x in ms]],
               color=SERIES[0], width=0.6, capsize=3, ecolor=INK2)
        categories(ax, "x", range(len(forms)), names, rotation=15, ha="right")
        ax.set_ylabel(unit)
        ax.set_title(title)
        ax.grid(axis="x", visible=False)
    files.append(finish(fig, "Exp. 7 — Boolean forms: same server work, formula evaluated client-side", src,
                        out / "png" / "exp7-boolean.png"))

    idx = sorted(m["index_sizes"], key=lambda r: r["depth"])
    fig, ax = plt.subplots(figsize=(6, 3.8))
    ds = [r["depth"] for r in idx]
    ours = [r["index_ratio_milli"] / 1000 for r in idx]
    zuo = [r["zuo_index_ratio_milli"] / 1000 for r in idx]
    # The two series coincide exactly, so Zuo'22 is dashed and Π_RANGE drawn on
    # top as large hollow circles — both stay visible, and the title says so.
    plain(ax, ds, zuo, "Zuo'22", 1, linestyle="--")
    plain(ax, ds, ours, "Π_RANGE", 0, markersize=12, markerfacecolor="none", markeredgewidth=2)
    ax.set_xlabel("range-tree depth (log₂ domain)")
    ax.set_ylabel("index size vs keyword-only (×)")
    ax.set_ylim(bottom=0)
    legend(ax)
    if ours == zuo:  # in the panel title: appended to the figure title it was cropped
        ax.set_title("Π_RANGE and Zuo'22 coincide at every depth", fontsize=9, fontweight="normal", color=INK2)
    files.append(finish(fig, "Exp. 7 — index expansion from range indexing", src,
                        out / "png" / "exp7-index-size.png"))
    return files


def exp8(src, m, out):
    rows = sorted(m["rows"], key=lambda r: r["postings"])
    return [write_csv(out / "csv" / "exp8-verified-mode.csv", rows),
            _panels(src, out, rows, "postings", "postings verified", [
                ("v", "verified search", lambda r: r["verified_search_ns"]),
            ], "Exp. 8 — verified search cost vs result size", "exp8-verified.png", logx=True)]


def exp9(src, m, out):
    rows = sorted(m["rows"], key=lambda r: r["chain_length"])
    return [write_csv(out / "csv" / "exp9-custody-chain.csv", rows),
            _panels(src, out, rows, "chain_length", "custody records in the chain", [
                ("b", "Tier-1 tree build", lambda r: r["tree_build_ns"]),
                ("v", "court-side verify", lambda r: r["court_verify_ns"]),
                ("p", "disclosure proof, bytes", lambda r: r["proof_bytes"]),
            ], "Exp. 9 — per-capsule custody disclosure", "exp9-custody.png", logx=True)]


def exp10(src, m, out):
    rows = sorted(m["rows"], key=lambda r: r["artefact_mib"])
    bound = m["detection_bound"]
    files = [write_csv(out / "csv" / "exp10-integrity-audit.csv", rows),
             write_csv(out / "csv" / "exp10-detection-bound.csv", bound)]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), squeeze=False)
    ax = axes[0][0]
    xs = [r["artefact_mib"] for r in rows]
    line(ax, xs, [r["full_rehash_ns"] for r in rows], "full re-hash", 0, 1e6)
    line(ax, xs, [r["sampled_sweep_ns"] for r in rows], "sampled sweep", 1, 1e6)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("artefact size, MiB")
    ax.set_ylabel("ms (log)")
    ax.set_title("audit cost")
    legend(ax)
    ax = axes[0][1]
    samples = [8, 32, 128]
    for i, b in enumerate(sorted(bound, key=lambda b: b["corrupted_fraction_pct"])):
        ax.plot(samples, [v / 1e4 for v in b["undetected_ppm_after_8_32_128_samples"]],
                color=SEQUENTIAL[i + 1], marker=MARKERS[i], label=f"{b['corrupted_fraction_pct']}% corrupted")
    ax.set_xscale("log", base=2)
    ax.set_yscale("symlog", linthresh=0.1)
    ax.set_ylim(bottom=0)  # a probability: symlog autoscale dipped below zero
    ax.set_xticks(samples, [str(s) for s in samples])
    ax.minorticks_off()
    ax.set_xlabel("chunks sampled per sweep")
    ax.set_ylabel("P(corruption undetected), % (symlog)")
    ax.set_title("detection bound (1−c)^k")
    legend(ax)
    files.append(finish(fig, "Exp. 10 — integrity auditing", src, out / "png" / "exp10-integrity.png"))
    return files


def doris(recs, out):
    rows, src = [], None
    for f, rec in recs:
        rows.extend(rec["rows"])
        src = f
    key = {(r["scheme"], r["dataset"], r["tier"]): r for r in rows}  # tier-4 files add, never duplicate
    rows = sorted(key.values(), key=lambda r: (r["dataset"], r["scheme"], r["pairs"]))
    files = [write_csv(out / "csv" / "doris-structural.csv", rows)]
    schemes = ["OXT", "HXT", "ConjFilter", "Doris"]  # fixed order -> fixed colours
    datasets = sorted({r["dataset"] for r in rows})
    fig, axes = plt.subplots(1, len(datasets), figsize=(5 * len(datasets), 4), sharey=True, squeeze=False)
    for ax, ds in zip(axes[0], datasets):
        for i, s in enumerate(schemes):
            rs = sorted((r for r in rows if r["dataset"] == ds and r["scheme"] == s), key=lambda r: r["pairs"])
            if rs:
                ax.plot([r["pairs"] for r in rs], [r["index_bytes"] for r in rs],
                        color=SERIES[i], marker=MARKERS[i], label=s)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_title(ds)
        ax.set_xlabel("keyword–document pairs")
        legend(ax)
    axes[0][0].set_ylabel("index bytes (TSet + XSet), log")
    fig.suptitle("")
    fig.text(0.01, 0.005, "Doris baseline (reused upstream, Python) · structural sizes, deterministic over 2 runs",
             fontsize=7, color=MUTED)
    fig.suptitle("Baselines — index size vs corpus size", x=0.01, ha="left", fontsize=12, fontweight="bold")
    fig.tight_layout(rect=(0, 0.03, 1, 0.95))
    p = out / "png" / "doris-index-size.png"
    p.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(p, dpi=150)
    plt.close(fig)
    files.append(p)
    return files


def _median(summary):
    return summary["median_ns"] if isinstance(summary, dict) and "median_ns" in summary else None


def exp6chain(src, m, out):
    # M13 A4: one LEChain run per stream; the steady state is the 10^4 one.
    steady = next(r for r in m["lechain_runs"]
                  if r["stream_capsules"] == m["lechain_steady_state_capsules"])
    lec_rows = []
    for lec in sorted(m["lechain_runs"], key=lambda r: r["stream_capsules"]):
        lec_rows.append({
            "scheme": f"LEChain (per-event transactions, pipelined), {lec['stream_capsules']} capsules",
            "entries_per_epoch": None, "records": lec["pipelined"]["events"],
            "records_per_s": lec["pipelined"]["events"] * 1e9 / lec["pipelined"]["first_submit_to_last_commit_ns"],
            "gas_per_record": lec["gas_total"] / lec["transitions"],
        })
    lec_rate = steady["pipelined"]["events"] * 1e9 / steady["pipelined"]["first_submit_to_last_commit_ns"]
    lec_gas = steady["gas_total"] / steady["transitions"]
    rows = [{"scheme": "LEChain steady state (10^4 capsules)", "entries_per_epoch": None,
             "records": steady["pipelined"]["events"], "records_per_s": lec_rate, "gas_per_record": lec_gas}]
    for o in sorted(m["ours"], key=lambda o: o["epoch_size"]):
        rows.append({
            "scheme": "PQ-ChainLog (epoch anchor)", "entries_per_epoch": o["epoch_size"],
            "epochs": o["epochs"], "records": o["records"],
            "records_per_s": o["records"] * 1e9 / o["first_event_to_last_commit_ns"],
            "gas_per_record": o["gas_total"] / o["records"],
            "slh_cosign_median_s": _median(o["anchor_slh_cosign_ns"]) / 1e9,
            "mldsa_sign_median_us": _median(o["anchor_mldsa_sign_ns"]) / 1e3,
            "record_commit_latency_median_s": _median(o["commit_latency_ns"]) / 1e9,
            "anchoring_workers": o["anchoring_workers"],
            "lechain_stream_capsules": o["lechain_stream_capsules"],
            "lechain_same_stream": o["lechain_same_stream"],
        })
    files = [write_csv(out / "csv" / "exp6chain-anchor.csv", rows + lec_rows)]
    ours = rows[1:]
    xs = [r["entries_per_epoch"] for r in ours]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, key, label in ((axes[0], "records_per_s", "records per second (log)"),
                           (axes[1], "gas_per_record", "gas per record (log)")):
        plain(ax, xs, [r[key] for r in ours], "ours: one anchor per epoch", 0)
        ax.axhline(rows[0][key], color=SERIES[1], linestyle="--", label="LEChain: one transaction per event")
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("entries (MMR leaves) per epoch")
        ax.set_ylabel(label)
        legend(ax)
    files.append(finish(fig, "Anchoring — ours vs LEChain on the same live Besu QBFT network",
                        src, out / "png" / "exp6chain-anchor.png"))
    return files


def custody(src, m, out):
    schemes = [("ours", "ours (Tier-1 bundle)"), ("flat_mmr", "flat per-case MMR"),
               ("hash_chain_replay", "hash-chain replay")]
    rows = []
    for c in m["cases"]:
        for key, label in schemes:
            sc = c[key]
            rows.append({"case_records": c["records"], "capsules": c["capsules"], "scheme": label,
                         "disclosed_records": sc["disclosed_records"], "disclosed_bytes": sc["disclosed_bytes"],
                         "verify_median_us": _median(sc["verify_ns"]) / 1e3,
                         "full_audit_median_s": _median(sc["full_replay_ns"]) / 1e9,
                         "full_audit_bytes": sc["full_replay_bytes"], "exposed": sc["exposed"]})
    files = [write_csv(out / "csv" / "custody-disclosure.csv", rows)]
    bt = m["bilateral_transfer"]
    signing = [{"what": "bilateral transfer (2 records, 3 signatures)",
                "median_us": _median(bt["bilateral_ns"]) / 1e3, "bytes": bt["bilateral_bytes"]},
               {"what": "unilateral transfer", "median_us": _median(bt["unilateral_ns"]) / 1e3}]
    for c in m["committee"]:
        signing.append({"what": f"committee endorsement, M = {c['members']}",
                        "median_us": _median(c["sign_ns"]) / 1e3, "verify_median_us": _median(c["verify_ns"]) / 1e3,
                        "bytes": c["signature_bytes"]})
    files.append(write_csv(out / "csv" / "custody-signing.csv", signing))
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    for ax, key, label in ((axes[0], "verify_median_us", "verify one capsule's history, µs"),
                           (axes[1], "disclosed_bytes", "bytes handed to the court"),
                           (axes[2], "full_audit_median_s", "audit the whole case, s")):
        for i, (_, name) in enumerate(schemes):
            rs = sorted((r for r in rows if r["scheme"] == name), key=lambda r: r["case_records"])
            plain(ax, [r["case_records"] for r in rs], [r[key] for r in rs], name, i)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("records in the case")
        ax.set_title(label, fontsize=9)
    legend(axes[0])
    files.append(finish(fig, "Custody disclosure — one capsule to a court, and a full audit",
                        src, out / "png" / "custody-disclosure.png"))
    return files


#: Scenario sub-keys that are parameters, not approaches.
_TAMPER_PARAMS = {"trials", "agents", "epochs_per_agent", "record_bytes", "records_per_epoch", "capsules"}


def tamper(src, m, out):
    def row(scenario, approach, part):
        if not isinstance(part, dict):
            return {"scenario": scenario, "approach": approach, "outcome": str(part)}
        det = part.get("detect_ns")
        if not (isinstance(det, dict) and "median_ns" in det):
            return {"scenario": scenario, "approach": approach, "outcome": part.get("reason", "never")}
        br = part.get("bytes_read")
        return {"scenario": scenario, "approach": approach, "outcome": "detected",
                "detect_median_s": det["median_ns"] / 1e9, "detect_p25_s": det["p25_ns"] / 1e9,
                "detect_p75_s": det["p75_ns"] / 1e9, "trials": det["n"],
                "mean_bytes_read": sum(br) / len(br) if isinstance(br, list) and br else None}
    plan = [("payload at rest", "payload_at_rest"), ("payload, then read", "payload_then_read"),
            ("custody record edited", "custody_record_edited"), ("agent epoch omitted", "agent_epoch_omitted")]
    rows = [row(label, approach, part)
            for label, key in plan for approach, part in m[key].items() if approach not in _TAMPER_PARAMS]
    files = [write_csv(out / "csv" / "exp8-tamper-response.csv", rows)]
    fig, ax = plt.subplots(figsize=(9, 5))
    ys = range(len(rows))
    vals = [r.get("detect_median_s") for r in rows]
    floor = min(v for v in vals if v) / 3
    ax.barh(list(ys), [v or 0 for v in vals], height=0.6,
            color=[SERIES[0] if r["approach"].startswith("ours") else SERIES[1] for r in rows])
    categories(ax, "y", ys, [f"{r['scenario']} — {r['approach']}" for r in rows], fontsize=7)
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlim(left=floor)
    for y, r, v in zip(ys, rows, vals):
        if v:
            txt = f"{v:.3g} s"
        elif "not applicable" in r["outcome"]:
            txt = "n/a"
        else:
            txt = "never detected"
        ax.text((v or floor) * 1.1, y, txt, va="center", fontsize=7, color=INK2)
    ax.set_xlabel(f"median time to detection, s (log); read budget {m['read_budget_bytes_per_s'] / 1e6:.0f} MB/s")
    ax.grid(axis="y", visible=False)
    files.append(finish(fig, "Exp. 8 — tamper response (blue: ours)", src, out / "png" / "exp8-tamper-response.png"))
    return files


def index_size(src, m, out):
    rows = []
    for r in m["rows"]:
        ours, odxt = r["ours"], r["odxt"]
        rows.append({"dataset": r["dataset"], "tier": r["tier"], "pairs": r["pairs"],
                     "ours_exact_bytes": ours["edb_bytes"] + ours["xset_exact_bytes"],
                     "odxt_exact_bytes": odxt["tset_bytes"] + odxt["xset_exact_bytes"],
                     "ours_edb_bytes": ours["edb_bytes"], "ours_xset_exact_bytes": ours["xset_exact_bytes"],
                     "odxt_tset_bytes": odxt["tset_bytes"], "odxt_xset_exact_bytes": odxt["xset_exact_bytes"]})
    files = [write_csv(out / "csv" / "index-size.csv", rows)]
    datasets = sorted({r["dataset"] for r in rows})
    fig, axes = plt.subplots(1, len(datasets), figsize=(5 * len(datasets), 4), sharey=True, squeeze=False)
    for ax, ds in zip(axes[0], datasets):
        rs = sorted((r for r in rows if r["dataset"] == ds), key=lambda r: r["pairs"])
        plain(ax, [r["pairs"] for r in rs], [r["ours_exact_bytes"] for r in rs], "ours (EDB + exact XSet)", 0)
        plain(ax, [r["pairs"] for r in rs], [r["odxt_exact_bytes"] for r in rs], "ODXT (TSet + exact XSet)", 1)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_title(ds)
        ax.set_xlabel("keyword–document pairs")
        legend(ax)
    axes[0][0].set_ylabel("index bytes (log)")
    files.append(finish(fig, "Index size — ours vs ODXT, Doris's size convention", src, out / "png" / "index-size.png"))
    return files


EXPORTERS = {
    "exp1-ingestion-throughput": exp1, "exp2-conjunctive-latency": exp2,
    "exp3-leakage": exp3, "exp4-epoch-compaction": exp4, "exp5-bloom-xset": exp5,
    "exp6-anchoring-cost": exp6, "exp7-range-latency": exp7, "exp8-verified-mode": exp8,
    "exp9-custody-chain": exp9, "exp10-integrity-audit": exp10,
    "exp6chain-custody-commit": exp6chain, "custody-disclosure": custody,
    "exp8-tamper-response": tamper, "index-size": index_size,
}

#: Publishable experiments deliberately not charted here, each with the reason.
#: ⚠️ Campaign 03 found four M10 experiments charted by nothing while the export
#: reported success. An experiment absent from both maps now fails the export.
NOT_CHARTED = {
    "pipeline-rehearsal": "the AWS gate's own no-measurement record",
    "doris-structural": "charted by doris(), which takes every record",
    "m15-doris-fu-search": "exp2's pass 2 (one record per tier); figspec merges it into exp2's rows",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results", nargs="?", type=Path, default=Path("results"))
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args()
    out = a.out or a.results / "export"

    by_exp, skipped = load(a.results)
    for s in skipped:
        print(f"skipped (not publishable): {s}")
    written: list[Path] = []
    for exp, fn in EXPORTERS.items():
        if exp not in by_exp:
            print(f"no publishable record: {exp}")
            continue
        src, rec = newest(by_exp[exp])
        written += fn(src, rec["measurements"], out)
    if "doris-structural" in by_exp:
        written += doris(by_exp["doris-structural"], out)
    for w in written:
        print(f"wrote {w}")
    print(f"{sum(p.suffix == '.csv' for p in written)} CSV, {sum(p.suffix == '.png' for p in written)} PNG")
    uncharted = sorted(set(by_exp) - set(EXPORTERS) - set(NOT_CHARTED))
    for exp in uncharted:
        print(f"NO EXPORTER for publishable experiment: {exp}", file=sys.stderr)
    return 1 if uncharted else 0


if __name__ == "__main__":
    sys.exit(main())
