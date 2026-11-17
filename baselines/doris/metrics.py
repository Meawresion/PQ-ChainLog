"""Extract the language-independent metrics from `CDSecLab/Doris`.

⛔ **No wall-clock number is produced here, deliberately.** The build plan
§5: our system is Rust, this is Python, and comparing their latency to ours is
meaningless — a reviewer will say so immediately. The upstream driver logs
`protocol,pair_num,setup_time(s),tset_size(B),xset_size(B)`; this takes the two
**byte counts** and never calls `time()` at all. That is stronger than dropping
a column, because there is no timing here for anyone to later "restore".

⭐ **Their code, their size formulas.** Each scheme's `tset_size`/`xset_size`
expression below is copied from the matching function in `setup_exp.py`, because
the schemes count differently — OXT's XSet is a Bloom bit array (bits→bytes),
the other three count 32-byte elements. Recomputing these our own way would
measure something the authors never reported.

⚠️ **Why this exists instead of running `setup_exp.py`.** Two reasons:

1. Their driver hardcodes `cnt = 4`, so it stops at the 10^5 tier. Plan §7 caps
   us at their 10^6 tier, which is index 4.
2. Their `TSet.setup` fails **probabilistically** — see `retry` below.

Usage (inside the container, with the upstream tree as the working directory):
    PYTHONPATH=/work python3 /results/metrics.py --tiers 0,1,2,3 --out /results/x.json
"""

import argparse
import json
import math
import os
import platform
import sys
import traceback

import ConjFilter_alter
import Doris_XF
import HXT
import OXT
import Utils.cfg
import Utils.pbcUtils
from Utils.TSet import cal_size

# ---------------------------------------------------------------------------
# ⭐ Canonical field-element width — the design record, ruled A.
#
# Upstream serialises a Zr element with `long_to_bytes`, which is
# **minimal-length**: an element below `2^152` encodes one byte shorter than
# one above it. Two consequences, and the second is the one that matters.
#
# 1. The index byte total is **not reproducible**. Measured across container
#    runs, `tset_bytes` at tier 1 spanned 62 987–62 995.
# 2. ⭐ It **understates their index**, and measures `Crypto.Util.number`
#    rather than the scheme. Any C or Rust implementation writes a canonical
#    fixed-width element; a Python minimal encoding is a host-language artifact.
#
# Fixing it at the one point where a field element is serialised is deliberate.
# The alternative — reconstructing each entry's composition and summing
# canonical widths — would need a model of `struct.pack("H", len(y)) + y + e`
# that we could get wrong, silently, in our own favour. Padding `Zr2Bytes`
# needs no model: every other component already has a deterministic length, so
# canonicalising the only variable one makes the total exact by construction.
#
# ⚠️ Safe for the schemes. `bytes2Zr` is `bytes_to_long`, which ignores leading
# zeros, and `element` carries an explicit length prefix whose own width does
# not change. `TSet._xor` truncates against a 108-byte `K`, and an entry stays
# far below that.
#
# 📌 Only OXT and HXT are affected — they are the pairing-based pair and the
# only callers of `Zr2Bytes`. ConjFilter and Doris should already be
# reproducible, and condition 4 will say so. If a non-pairing scheme also
# varies there is a second cause, and §1.7 does not cover it.
# ---------------------------------------------------------------------------


def _zr_width() -> int:
    """`ceil(log2(r) / 8)` for the pinned curve, read from upstream's own params.

    Derived rather than hardcoded as 20: if the curve in `Utils/cfg.py` ever
    changes, a constant would silently become the wrong canonical width, which
    is exactly the class of error this whole section exists to remove.
    """
    for line in Utils.cfg.pbc_params.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "r":
            return (int(parts[1]).bit_length() + 7) // 8
    raise SystemExit("could not read the group order r from Utils/cfg.py")


ZR_BYTES = _zr_width()


class Canonicaliser:
    """Pads `Zr2Bytes` to `ZR_BYTES`, and counts what it had to add.

    The counts are the tripwire. A correction of the wrong *shape* — a broken
    composition model, a changed curve, a second source of variation — shows up
    as an excess far larger than the binomial predicts, and is asserted against
    rather than reported.
    """

    def __init__(self, width: int):
        self.width = width
        self.elements = 0
        self.padded = 0
        self.bytes_added = 0
        self._original = Utils.pbcUtils.pbcUtil.Zr2Bytes

    def install(self):
        original, state = self._original, self

        def canonical(self_, ele):
            raw = original(self_, ele)
            state.elements += 1
            if len(raw) > state.width:
                # Cannot happen for a well-formed Zr element; if it does, the
                # width is wrong and every figure below it would be too.
                raise SystemExit(
                    f"a Zr element serialised to {len(raw)} bytes, over the "
                    f"canonical width {state.width}. The curve or the "
                    f"derivation is wrong; stop rather than report."
                )
            if len(raw) < state.width:
                state.padded += 1
                state.bytes_added += state.width - len(raw)
            return raw.rjust(state.width, b"\x00")

        Utils.pbcUtils.pbcUtil.Zr2Bytes = canonical
        return self

    def snapshot_and_reset(self) -> dict:
        out = {
            "zr_elements": self.elements,
            "zr_short_encodings": self.padded,
            "canonical_bytes_added": self.bytes_added,
        }
        self.elements = self.padded = self.bytes_added = 0
        return out


CANON = Canonicaliser(ZR_BYTES).install()

# The tier labels are the (w, id) pair counts, and the data files really do
# contain exactly this many — verified, not assumed.
TIER_PAIRS = [100, 1000, 10000, 100000, 1000000]

# Upstream's own parameters, unchanged. ⚠️ **Their provenance differs, and an
# earlier version of this comment conflated the two:**
#
# * `BF_FPR = 10^-6` is in **both** `setup_exp.py:98` and the paper (p. 12,
#   "a fixed false positive rate 10^-6", restated p. 13).
# * `TSET_K = 2` is **upstream's code only** — `setup_exp.py:99, 123, 146, 174`.
#   The paper never states it. Faithful to the artefact, not attributable to
#   the text, and the distinction matters when a reviewer asks where a
#   parameter came from.
BF_FPR = pow(10, -6)
TSET_K = 2

# ⚠️ **Upstream's `TSet.setup` fails probabilistically, and this is a real
# finding rather than a flaky environment.**
#
# `TSet.__init__` sizes a B×S grid with B = S = ceil(sqrt(n·k)). `_free_b`
# raises `Exception("insufficient space")` when the bucket a pair hashes to is
# already full. Bucket assignment depends on `kt`, which `setup` draws freshly
# at random on every call, so whether a given run survives is a coin flip
# weighted by how close the maximum bucket load sits to S.
#
# Measured at k = 2 (12 trials per tier, Enron): **1/12 failures at n = 100**,
# 0/12 at 1000 and 10000. At k = 4 and k = 6, 0/12 everywhere.
#
# Retrying with a fresh `TSet` is the faithful fix, and it is preferred over
# raising `k`: `k` is an upstream parameter that shapes the structure, whereas
# `kt` is *already* random per run, so re-drawing it changes nothing about the
# scheme. The retry count is reported, so a reader can see the fragility rather
# than have it silently smoothed away.
MAX_ATTEMPTS = 12


def retry(build):
    """Run `build()`, re-rolling upstream's random `kt` on `insufficient space`.

    Returns `(result, attempts)`. Re-raises anything that is not the known
    capacity failure — a different exception is a different problem and must not
    be retried into silence.
    """
    last = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        # ⚠️ The §1.7 counters must describe the build that survived, not every
        # build tried. Campaign 03 caught this: OXT/enwiki/tier0 needed a second
        # attempt in one determinism run and reported zr_elements 200 against
        # 100 in the other -- the discarded attempt's serialisations, counted.
        CANON.snapshot_and_reset()
        try:
            return build(), attempt
        except Exception as exc:  # noqa: BLE001 - upstream raises bare Exception
            if "insufficient space" not in str(exc):
                raise
            last = exc
    raise RuntimeError(
        f"upstream TSet setup failed {MAX_ATTEMPTS} times running: {last}"
    )


def oxt(n, wid, _idw):
    def build():
        keys = OXT.PARAMS()
        edb = OXT.EDB(n, BF_FPR, TSET_K)
        edb.EDBSetup(wid, keys)
        return edb

    edb, attempts = retry(build)
    # setup_exp.py::oxt_test — the XSet is a Bloom bit array, so bits → bytes.
    return cal_size(edb.tset), len(edb.xset) // 8, attempts


def hxt(n, wid, _idw):
    def build():
        keys = HXT.PARAMS()
        edb = HXT.EDB(n, BF_FPR, TSET_K)
        edb.EDBSetup(wid, keys)
        return edb

    edb, attempts = retry(build)
    # setup_exp.py::hxt_test
    return cal_size(edb.tset), len(edb.xset) * 32, attempts


def conjfilter(n, wid, idw):
    def build():
        keys = ConjFilter_alter.PARAMS()
        edb = ConjFilter_alter.EDB(n, TSET_K)
        edb.setup(wid, idw, keys)
        return edb

    edb, attempts = retry(build)
    # setup_exp.py::conjFilter_alter_test — note `EMM`, not `tset`.
    return cal_size(edb.EMM), len(edb.X) * 32, attempts


def doris(n, wid, idw):
    def build():
        keys = Doris_XF.PARAMS()
        edb = Doris_XF.EDB(n, TSET_K)
        edb.setup(wid, idw, keys)
        return edb

    edb, attempts = retry(build)
    # setup_exp.py::Doris_xf_test
    return cal_size(edb.tset), len(edb.ct) * 32, attempts


SCHEMES = {
    "OXT": oxt,
    "HXT": hxt,
    "ConjFilter": conjfilter,
    "Doris": doris,
}

# ⭐ **Protocol properties, taken from the Doris paper's Table 1 — not measured
# here, and labelled as such in the output so nobody mistakes them for
# observations.**
#
# Table 1 (CCS 2024, p. 3) compares the four schemes on a conjunctive query
# `l1 AND l2 AND ... AND lq`, with `n = sum_l |MM[l]|` and
# `N = sum_{li,lj} |MM[li] INTERSECT MM[lj]|`:
#
# | Scheme     | Storage | Rounds | KPRP hidden | IP hidden |
# |------------|---------|--------|-------------|-----------|
# | OXT        | O(n)    | 1      | no          | no        |
# | HXT        | O(n)    | 2      | yes         | no        |
# | ConjFilter | O(N)    | 1      | no          | yes       |
# | Doris      | O(N)    | 1      | yes         | yes       |
#
# ⚠️ **HXT is two rounds.** An earlier version of this file asserted one round
# for all four schemes — wrong, and wrong in the direction that would have
# flattered HXT in a round-count comparison. Table 1 is explicit, and the paper's
# body explains why: hiding KPRP "still requires an additional round of
# interaction", because the client cannot generate tokens for the designated
# label/value pairs without first hearing from the server. Doris's contribution
# is removing exactly that round while keeping both properties hidden.
#
# KPRP = keyword-pair result pattern. IP = intersection pattern.
PROTOCOL = {
    "OXT": {"search_rounds": 1, "storage_order": "O(n)", "kprp_hidden": False, "ip_hidden": False},
    "HXT": {"search_rounds": 2, "storage_order": "O(n)", "kprp_hidden": True, "ip_hidden": False},
    "ConjFilter": {"search_rounds": 1, "storage_order": "O(N)", "kprp_hidden": False, "ip_hidden": True},
    "Doris": {"search_rounds": 1, "storage_order": "O(N)", "kprp_hidden": True, "ip_hidden": True},
}

# ⛔ **Communication volume is deliberately NOT taken from upstream.**
#
# `two_keywords_exp.py::cal_comm_cost` is `len(pickle.dumps(object))`, with a
# fallback of `n * m * 64` for objects pickle cannot handle. A pickle length is
# Python's serialization framing plus object headers — **language-dependent**,
# and therefore exactly the kind of number plan §5 forbids comparing against a
# Rust wire format. Their storage figures are honest byte counts of real byte
# strings; their communication figures are not the same kind of thing, and the
# difference is easy to miss because both are reported in bytes.
#
# Recorded here rather than silently omitted, so the gap is visible and a later
# reader does not "helpfully" wire the pickle number in.
COMM_NOTE = (
    "not measured: upstream's cal_comm_cost is len(pickle.dumps(...)), which is "
    "Python serialization overhead rather than a wire-format byte count, so it "
    "is not comparable across languages (plan section 5)"
)


def provenance(upstream_rev):
    with open("/etc/pqcl-doris-versions", encoding="utf-8") as fh:
        versions = dict(
            line.strip().split("=", 1) if "=" in line else (line.strip(), "")
            for line in fh
            if line.strip()
        )
    return {
        "upstream": "github.com/CDSecLab/Doris",
        "upstream_commit": upstream_rev,
        "stack": versions,
        "python": platform.python_version(),
        "bloom_fpr": BF_FPR,
        "tset_expansion_k": TSET_K,
        "note": (
            "Structural metrics only. No wall-clock figure is produced or "
            "permitted from this baseline: plan §5 restricts a Python "
            "implementation to language-independent axes."
        ),
    }


#: Probability a uniform Zr element encodes at least one byte short, i.e.
#: `P(y < 2^(8*(ZR_BYTES-1))) = 2^152 / r` for the pinned curve. Derived, not
#: assumed, for the same reason `ZR_BYTES` is.
def _short_encoding_probability() -> float:
    for line in Utils.cfg.pbc_params.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "r":
            return pow(2, 8 * (ZR_BYTES - 1)) / int(parts[1])
    raise SystemExit("could not read the group order r from Utils/cfg.py")


P_SHORT = _short_encoding_probability()


def check_canonicalisation(scheme, dataset, tier, canon):
    """⭐ The §1.7 tripwire: is the correction the right *size*?

    A canonical figure we derived wrongly would be an error of **ours**, not
    theirs, and it would move a published number in our favour — so it gets a
    check rather than trust.

    Two properties, both cheap:

    * ``canonical_bytes_added >= 0`` by construction — padding only ever adds —
      and a scheme that serialises no field element must add exactly zero.
      ConjFilter and Doris are not pairing-based, so a non-zero count there
      means a second source of variation that §1.7 does not cover.
    * the excess must match the binomial the diagnosis predicts. With
      ``p = 2^152/r`` and one element per pair, the mean is ``n*p`` — order ten
      bytes per thousand entries. **Hundreds would mean the composition model
      is wrong, and the run stops.**
    """
    added = canon["canonical_bytes_added"]
    elements = canon["zr_elements"]

    if added < 0:
        raise SystemExit(f"{scheme}/{dataset}/tier{tier}: negative correction {added}")

    if elements == 0:
        if added != 0:
            raise SystemExit(
                f"{scheme}/{dataset}/tier{tier}: {added} bytes added with no Zr "
                f"element serialised. The canonicaliser is counting something else."
            )
        return

    mean = elements * P_SHORT
    sigma = math.sqrt(elements * P_SHORT * (1 - P_SHORT))
    # Six sigma plus a constant: loose enough never to fire on chance, tight
    # enough that a wrong model — which would be off by a factor, not a few
    # bytes — cannot slip through.
    bound = mean + 6 * sigma + 16

    if added > bound:
        raise SystemExit(
            f"{scheme}/{dataset}/tier{tier}: canonicalisation added {added} bytes "
            f"across {elements} field elements, against a predicted "
            f"{mean:.1f} ± {sigma:.1f} (bound {bound:.0f}).\n"
            f"The correction is the wrong size, so the composition model is "
            f"wrong. Do not publish this: raise it."
        )


def selftest_canonicalisation():
    """⭐ Watch the §1.7 tripwire fire, before trusting it not to.

    The design record: *"a tripwire nobody has watched fire is
    instance 3 wearing different clothes."* `check_canonicalisation` was
    exercised on every run and **falsified by none** — it had never been shown
    to reject anything, so "it did not fire" carried no information.

    ⛔ **This runs unconditionally at the start of `main`, not behind a flag.**
    A negative test somebody has to remember to run is the same shape as the
    problem it fixes. It costs microseconds and needs no upstream state.

    The case that matters is a **wrong canonical width**. If `ZR_BYTES` were 24
    rather than 20, every element would be over-padded by four bytes and the
    correction would scale with the element count instead of with the rare
    short encoding — an error of ours, in our favour, in a published number.
    """
    def fires(label, canon):
        try:
            check_canonicalisation("selftest", "synthetic", 0, canon)
        except SystemExit:
            return True
        raise SystemExit(
            f"§1.7 tripwire selftest FAILED: it accepted {label}. The check is "
            f"not protecting the canonicalisation figures; fix it before "
            f"running a measurement that depends on it."
        )

    def passes(label, canon):
        try:
            check_canonicalisation("selftest", "synthetic", 0, canon)
        except SystemExit as exc:
            raise SystemExit(
                f"§1.7 tripwire selftest FAILED: it rejected {label}, which is "
                f"legitimate. A check that fires on correct input will be "
                f"switched off.\n  {exc}"
            )

    n = 1000
    # 1. The wrong-width case: four extra bytes on every element.
    fires("a width wrong by 4 bytes per element", {
        "zr_elements": n, "zr_short_encodings": n, "canonical_bytes_added": 4 * n,
    })
    # 2. Off by a factor rather than a constant — the shape §1.7 warns about.
    fires("a correction 100x the binomial mean", {
        "zr_elements": n, "zr_short_encodings": n,
        "canonical_bytes_added": int(100 * n * P_SHORT) + 1000,
    })
    # 3. Padding can only add.
    fires("a negative correction", {
        "zr_elements": n, "zr_short_encodings": 0, "canonical_bytes_added": -1,
    })
    # 4. A non-pairing scheme serialises no Zr element, so it must add nothing.
    fires("bytes added with no field element serialised", {
        "zr_elements": 0, "zr_short_encodings": 0, "canonical_bytes_added": 7,
    })

    # And the two shapes that must be accepted, or the check is useless.
    passes("a correction at the binomial mean", {
        "zr_elements": n, "zr_short_encodings": int(n * P_SHORT),
        "canonical_bytes_added": int(n * P_SHORT),
    })
    passes("ConjFilter/Doris, which serialise no Zr element", {
        "zr_elements": 0, "zr_short_encodings": 0, "canonical_bytes_added": 0,
    })

    # A retried build must leave only the surviving attempt in the counters.
    CANON.snapshot_and_reset()
    tries = []

    def flaky():
        tries.append(1)
        for _ in range(5):
            CANON.elements += 1
        if len(tries) == 1:
            raise Exception("insufficient space")
        return "built"

    _, attempts = retry(flaky)
    counted = CANON.snapshot_and_reset()["zr_elements"]
    if attempts != 2 or counted != 5:
        raise SystemExit(
            f"§1.7 tripwire self-test FAILED: a build retried once counted "
            f"{counted} elements over {attempts} attempts, expected 5 over 2. "
            f"The counters are describing discarded attempts."
        )

    print(f"§1.7 tripwire: 7 selftests pass (width {ZR_BYTES} B, "
          f"P_short {P_SHORT:.3g})", flush=True)


def refuse_to_clobber_published(out_path):
    """⛔ Never overwrite a published carve-out record with a single run.

    A carve-out record carries `aws_exempt` and is written only by
    `publish.py`, after two independent runs agree. This driver produces one
    run, which `tools/mkfigs.py` refuses by design — so replacing the published
    file with its output can only ever destroy something.

    ⚠️ **Checked before any work, not at write time.** The first version of this
    guard refused after computing, which on the 10^6 tier means an hour of
    Python spent to earn an error message.
    """
    if not os.path.exists(out_path):
        return
    try:
        with open(out_path, encoding="utf-8") as fh:
            existing = json.load(fh)
    except (ValueError, OSError):
        return
    if isinstance(existing, dict) and "aws_exempt" in existing:
        raise SystemExit(
            f"refusing to overwrite {out_path}: it is a published carve-out "
            f"record (it carries `aws_exempt`), and this driver produces a "
            f"single run, which the pipeline refuses. Use `run.sh publish` to "
            f"regenerate it, or pass --out with a different path."
        )


def main():
    # ⛔ Before anything is measured. See `selftest_canonicalisation`.
    selftest_canonicalisation()

    ap = argparse.ArgumentParser()
    ap.add_argument("--tiers", default="0,1,2,3")
    ap.add_argument("--datasets", default="enron,enwiki")
    # ⭐ **One scheme per process is how the 10^6 tier fits at all.**
    # Every scheme's structures are freed when its function returns -- the loop
    # keeps only byte counts -- but CPython does not hand freed arenas back to
    # the OS, so four schemes at 10^6 fragment past this machine's 10.7 GiB and
    # the OOM reaper takes the run. It did, twice: once at Doris and once at
    # ConjFilter, which is the give-away that the limit is cumulative rather
    # than any one scheme being too big.
    #
    # Splitting by scheme bounds the peak without touching upstream's
    # structures, which the reuse rule forbids. No merge step is needed either:
    # `mkfigs.py` evaluates each record independently, so four per-scheme
    # records with four sets of determinism evidence are as publishable as one
    # combined record -- arguably better, since each scheme's reproducibility is
    # then proven on its own.
    ap.add_argument(
        "--schemes",
        default=",".join(SCHEMES),
        help="comma-separated subset of " + ",".join(SCHEMES),
    )
    # ⛔ **Not `doris-structural.json`.** That is the *published* record, written
    # only by `publish.py` after two runs agree. This driver produces one run,
    # which the pipeline refuses by design — so defaulting to that name meant a
    # casual `run.sh metrics` silently replaced a conforming carve-out record
    # with an unpublishable one. It did, on 2026-09-24; the file was tracked, so
    # `git checkout` got it back, and this name plus the guard below means the
    # next person does not need that luck.
    ap.add_argument("--out", default="/results/doris-structural-singlerun.json")
    # ⚠️ Passed in from the host rather than resolved here. The submodule's
    # `.git` is a *file* pointing outside the mount, so `git rev-parse` inside
    # the container silently reports "unknown" — which quietly destroys the one
    # field that makes a metric traceable to the code that produced it.
    ap.add_argument("--upstream-commit", default="unknown")
    args = ap.parse_args()

    refuse_to_clobber_published(args.out)

    tiers = [int(t) for t in args.tiers.split(",") if t != ""]
    datasets = [d for d in args.datasets.split(",") if d]

    selected = [x for x in args.schemes.split(",") if x]
    unknown = [x for x in selected if x not in SCHEMES]
    if unknown:
        # ⛔ A typo must not silently measure fewer schemes than asked for:
        # the missing rows would read as "not run" rather than "never named".
        raise SystemExit(
            f"unknown scheme(s) {unknown}; known: {list(SCHEMES)}"
        )
    schemes = {k: v for k, v in SCHEMES.items() if k in selected}

    rev = args.upstream_commit
    if rev == "unknown":
        raise SystemExit(
            "refusing to write results without the upstream commit: pass "
            "--upstream-commit. An untraceable metric is not a usable one."
        )

    rows = []
    for ds in datasets:
        for tier in tiers:
            wid = f"data/{ds}_inverted{tier}.csv"
            idw = f"data/{ds}_index{tier}.csv"
            n = TIER_PAIRS[tier]
            for name, fn in schemes.items():
                CANON.snapshot_and_reset()
                try:
                    tset_b, xset_b, attempts = fn(n, wid, idw)
                except Exception:  # noqa: BLE001
                    # Record the failure rather than dropping the row. A missing
                    # row reads as "not run"; this reads as "run, and it broke".
                    print(f"FAILED {name} {ds} tier{tier}", file=sys.stderr)
                    traceback.print_exc()
                    rows.append(
                        {
                            "scheme": name,
                            "dataset": ds,
                            "tier": tier,
                            "pairs": n,
                            "error": traceback.format_exc(limit=1).strip(),
                        }
                    )
                    continue

                canon = CANON.snapshot_and_reset()
                check_canonicalisation(name, ds, tier, canon)

                row = {
                    "scheme": name,
                    "dataset": ds,
                    "tier": tier,
                    "pairs": n,
                    "tset_bytes": tset_b,
                    "xset_bytes": xset_b,
                    "index_bytes": tset_b + xset_b,
                    "setup_attempts": attempts,
                    "comm_bytes": None,
                    "comm_note": COMM_NOTE,
                    # ⭐ The §1.7 correction, exposed rather than folded in
                    # silently. `canonical_bytes_added` is how much the
                    # reported figure exceeds what upstream's minimal-length
                    # encoding would have produced, so a reader can recover
                    # their raw number and check ours.
                    **canon,
                    **PROTOCOL[name],
                    "protocol_fields_source": "DORIS_CCS2024.pdf Table 1 (paper-derived, not measured)",
                }
                rows.append(row)
                print(
                    f"{name:<11} {ds:<7} tier{tier} pairs={n:<8} "
                    f"tset={tset_b:<10} xset={xset_b:<10} "
                    f"total={tset_b + xset_b:<11} attempts={attempts} "
                    f"canon+{canon['canonical_bytes_added']}",
                    flush=True,
                )

    doc = {"provenance": provenance(rev), "rows": rows}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    print(f"\nwrote {args.out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
