#!/usr/bin/env python3
"""Fetch NIST ACVP vectors and extract only the parameter sets PQ-ChainLog uses.

Why extraction rather than vendoring whole files or fetching at test time:

  * The upstream ``internalProjection.json`` files total 90+ MB because they
    cover every parameter set --- ``SLH-DSA-sigGen-FIPS205`` alone is 38 MB.
    We use exactly three parameter sets.
  * Fetching at test time would make ``cargo test`` need the network, and an
    artifact evaluator wants a repository that verifies offline.

So we commit the extracted subset plus this script plus ``UPSTREAM.txt``. The
provenance stays pinned: the manifest records the SHA-256 of each *upstream*
file as well as each extracted one, so anyone can re-run this and confirm we
did not tamper with the vectors we kept.

Usage::

    python3 extract.py            # fetch, extract, write MANIFEST.sha256
    python3 extract.py --verify   # re-fetch and check nothing drifted

``internalProjection.json`` is the file that carries expected outputs.
``prompt.json`` alone does not, and a harness built on it would silently test
nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

# Pinned upstream commit on usnistgov/ACVP-Server. Bumping this is a deliberate
# act: re-run without --verify, inspect the manifest diff, and say so in the
# commit message.
UPSTREAM_COMMIT = "a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324"

RAW = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{sha}/gen-val/json-files/{d}/internalProjection.json"

# Parameter sets fixed by implementation-plan.md and Require-Consultant.md §1.
KEEP = {
    "ML-KEM": {"ML-KEM-768"},
    "ML-DSA": {"ML-DSA-65"},
    "SLH-DSA": {"SLH-DSA-SHAKE-192s"},
}

# (directory, note). None in KEEP means "keep every group" --- used where the
# whole file is already small and parameter selection happens in the harness.
SOURCES = [
    ("ML-KEM-keyGen-FIPS203", "FIPS 203 key generation"),
    ("ML-KEM-encapDecap-FIPS203", "FIPS 203 encapsulation / decapsulation"),
    ("ML-DSA-keyGen-FIPS204", "FIPS 204 key generation"),
    ("ML-DSA-sigGen-FIPS204", "FIPS 204 signature generation"),
    ("ML-DSA-sigVer-FIPS204", "FIPS 204 signature verification"),
    ("SLH-DSA-keyGen-FIPS205", "FIPS 205 key generation"),
    ("SLH-DSA-sigGen-FIPS205", "FIPS 205 signature generation"),
    ("SLH-DSA-sigVer-FIPS205", "FIPS 205 signature verification"),
    ("SHAKE-256-FIPS202", "FIPS 202 XOF --- kept whole, all groups"),
    ("ACVP-AES-ECB-1.0", "AES-256 block cipher, encrypt AFT --- the GGM step G (M12 R3)"),
]

# Algorithms whose groups are not selected by ``parameterSet``.
#
# M12 R3: the GGM step is ``G(s) = AES-256_s(<0>) || ... || AES-256_s(<3>)``, so
# the only AES behaviour we use is **AES-256 encryption of a block**. Keep
# exactly that: keyLen 256, encrypt, the AFT groups. MCT is left out because G
# never feeds a cipher output back into its next input; AES-128/192 and decrypt
# would be vectors for code we do not run.
GROUP_FILTER = {
    "ACVP-AES-ECB": lambda g: g.get("keyLen") == 256
    and g.get("direction") == "encrypt"
    and g.get("testType") == "AFT",
}

# Extractions that do **not** belong to pqcl-primitives' vector set.
#
# ⭐ ML-DSA-44 is not a parameter set this system uses, and it must never reach
# the Rust KAT harness --- `kat.rs` asserts every group is ML-DSA-65, and it
# should keep doing so. It is extracted here purely as the **control** for the
# ETHDILITHIUM port (`Require-Consultant.md` row 15, condition 2): the upstream
# verifier is level II, so proving it conformant *before* we touch it is what
# makes a later failure bisectable --- "I broke it" versus "it was already
# non-conformant at the pinned commit".
#
# Written outside this directory on purpose, so the two vector sets cannot be
# confused, while provenance stays single-sourced through UPSTREAM_COMMIT.
EXTRA = [
    (
        "ML-DSA-sigVer-FIPS204",
        {"ML-DSA-44"},
        "../../../../contracts/test/vectors/ML-DSA-44-sigVer-FIPS204.json",
        "control for the unported ETHDILITHIUM verifier (level II)",
    ),
]

# AES-256-GCM comes from CAVP, not ACVP.
#
# The ACVP ``ACVP-AES-GCM-1.0`` sample file is a demonstration set: four groups,
# **all AES-128**, none with a 96-bit all-zero IV. It cannot discharge
# "AES-256-GCM passes KATs" no matter how it is filtered, so using it would have
# been a KAT that looked green while testing a cipher we do not ship.
#
# CAVP's long-standing GCM vectors do have AES-256 at IVlen=96 / Taglen=128,
# which is exactly our configuration.
CAVP_GCM_URL = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip"
CAVP_GCM_MEMBERS = ("gcmEncryptExtIV256.rsp", "gcmDecrypt256.rsp")

# Our AEAD is AES-256, 96-bit nonce, 128-bit tag. Anything else exercises a mode
# the public API deliberately does not expose.
CAVP_KEEP = {"Keylen": 256, "IVlen": 96, "Taglen": 128}

HERE = Path(__file__).resolve().parent


def fetch_url(url: str) -> bytes:
    # csrc.nist.gov returns 403 to urllib's default User-Agent. Both URLs here
    # are pinned constants, not user input.
    req = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": "pq-chainlog-kat-fetch/1.0"}
    )
    with urllib.request.urlopen(req) as r:  # noqa: S310
        return r.read()


def fetch(directory: str) -> bytes:
    return fetch_url(RAW.format(sha=UPSTREAM_COMMIT, d=directory))


def extract(raw: bytes, override: set[str] | None = None) -> tuple[bytes, int, int]:
    """Filter testGroups to the parameter sets we use.

    Returns (json bytes, groups kept, groups seen).
    """
    doc = json.loads(raw)
    groups = doc.get("testGroups", [])
    wanted = override if override is not None else KEEP.get(doc.get("algorithm", ""))
    pred = None if override is not None else GROUP_FILTER.get(doc.get("algorithm", ""))

    if pred is not None:
        kept = [g for g in groups if pred(g)]
        if not kept:
            raise SystemExit(
                "no test groups matched the filter for algorithm %r --- upstream "
                "may have renamed keyLen/direction/testType" % doc.get("algorithm")
            )
    elif wanted is None:
        kept = groups
    else:
        kept = [g for g in groups if g.get("parameterSet") in wanted]
        if not kept:
            raise SystemExit(
                "no test groups matched %s for algorithm %r --- the upstream "
                "parameterSet naming may have changed, which is exactly the "
                "kind of drift this script must not paper over"
                % (sorted(wanted), doc.get("algorithm"))
            )

    doc["testGroups"] = kept
    # Deterministic serialisation so the committed file is stable across runs.
    out = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False)
    return out.encode("utf-8") + b"\n", len(kept), len(groups)


def parse_rsp(text: str) -> list[dict[str, str]]:
    """Parse a CAVP ``.rsp`` file into flat records.

    Sections are headed by ``[Key = Value]`` lines; each ``Count =`` starts a
    case. A bare ``FAIL`` line marks a decrypt case that must not authenticate.
    """
    section: dict[str, int] = {}
    cases: list[dict[str, str]] = []
    cur: dict[str, str] | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            k, _, v = line[1:-1].partition("=")
            section[k.strip()] = int(v.strip())
            continue
        if line == "FAIL":
            if cur is not None:
                cur["FAIL"] = "1"
            continue
        k, sep, v = line.partition("=")
        if not sep:
            continue
        k, v = k.strip(), v.strip()
        if k == "Count":
            cur = {"_section": dict(section)}  # type: ignore[dict-item]
            cases.append(cur)
        if cur is not None:
            cur[k] = v
    return cases


def extract_cavp_gcm(zip_bytes: bytes) -> tuple[bytes, int, int]:
    """Keep only AES-256 / 96-bit IV / 128-bit tag cases."""
    import io
    import zipfile

    z = zipfile.ZipFile(io.BytesIO(zip_bytes))
    out: dict[str, list[dict[str, str]]] = {}
    kept = seen = 0

    for member in CAVP_GCM_MEMBERS:
        text = z.read(member).decode("ascii", "replace")
        rows = []
        for c in parse_rsp(text):
            seen += 1
            sec = c.pop("_section")
            if any(sec.get(k) != v for k, v in CAVP_KEEP.items()):
                continue
            row = {k: c.get(k, "") for k in ("Key", "IV", "PT", "AAD", "CT", "Tag")}
            row["fail"] = c.get("FAIL", "")
            rows.append(row)
            kept += 1
        out[member] = rows

    if not kept:
        raise SystemExit(
            "no CAVP GCM cases matched %r --- the .rsp section headers may have "
            "changed" % (CAVP_KEEP,)
        )

    doc = {
        "source": CAVP_GCM_URL,
        "filter": CAVP_KEEP,
        "note": (
            "AES-256-GCM, 96-bit IV, 128-bit tag. The ACVP sample file for GCM "
            "is AES-128 only, so it cannot test the cipher we ship."
        ),
        "files": out,
    }
    body = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False)
    return body.encode("utf-8") + b"\n", kept, seen


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--verify",
        action="store_true",
        help="re-fetch and compare against the committed manifest; write nothing",
    )
    args = ap.parse_args()

    lines = [
        "# ACVP known-answer vectors --- provenance manifest",
        "#",
        "# Upstream: https://github.com/usnistgov/ACVP-Server",
        "# Commit:   %s" % UPSTREAM_COMMIT,
        "#",
        "# Each row is  <sha256>  <bytes>  <name>.  'upstream/' rows are the",
        "# digests of the full internalProjection.json as published; the plain",
        "# rows are what we committed after extracting our parameter sets.",
        "# Regenerate or check with extract.py [--verify].",
        "#",
    ]

    failures = []
    for directory, note in SOURCES:
        raw = fetch(directory)
        subset, kept, seen = extract(raw)

        name = "%s.json" % directory
        target = HERE / name

        up_digest = hashlib.sha256(raw).hexdigest()
        ex_digest = hashlib.sha256(subset).hexdigest()

        if args.verify:
            if not target.exists():
                failures.append("%s: missing" % name)
            elif hashlib.sha256(target.read_bytes()).hexdigest() != ex_digest:
                failures.append("%s: content differs from a fresh extraction" % name)
        else:
            target.write_bytes(subset)

        print(
            "%-32s %2d/%2d groups  %7.1f KB -> %6.1f KB   %s"
            % (directory, kept, seen, len(raw) / 1024, len(subset) / 1024, note),
            file=sys.stderr,
        )

        lines.append("%s  %9d  upstream/%s" % (up_digest, len(raw), name))
        lines.append("%s  %9d  %s" % (ex_digest, len(subset), name))

    for directory, wanted, relpath, note in EXTRA:
        raw = fetch(directory)
        subset, kept, seen = extract(raw, override=wanted)

        target = (HERE / relpath).resolve()
        ex_digest = hashlib.sha256(subset).hexdigest()
        shown = target.name

        if args.verify:
            if not target.exists():
                failures.append("%s: missing" % shown)
            elif hashlib.sha256(target.read_bytes()).hexdigest() != ex_digest:
                failures.append("%s: content differs from a fresh extraction" % shown)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(subset)

        print(
            "%-32s %2d/%2d groups  %7.1f KB -> %6.1f KB   %s"
            % (shown, kept, seen, len(raw) / 1024, len(subset) / 1024, note),
            file=sys.stderr,
        )

        lines.append("%s  %9d  extra/%s" % (ex_digest, len(subset), shown))

    # ---- CAVP AES-256-GCM ------------------------------------------------
    zip_bytes = fetch_url(CAVP_GCM_URL)
    subset, kept, seen = extract_cavp_gcm(zip_bytes)
    name = "CAVP-AES-256-GCM.json"
    target = HERE / name
    up_digest = hashlib.sha256(zip_bytes).hexdigest()
    ex_digest = hashlib.sha256(subset).hexdigest()

    if args.verify:
        if not target.exists():
            failures.append("%s: missing" % name)
        elif hashlib.sha256(target.read_bytes()).hexdigest() != ex_digest:
            failures.append("%s: content differs from a fresh extraction" % name)
    else:
        target.write_bytes(subset)

    print(
        "%-32s %4d/%4d cases %7.1f KB -> %6.1f KB   AES-256-GCM, 96-bit IV, 128-bit tag"
        % ("CAVP gcmtestvectors", kept, seen, len(zip_bytes) / 1024, len(subset) / 1024),
        file=sys.stderr,
    )
    lines.append("%s  %9d  upstream/gcmtestvectors.zip" % (up_digest, len(zip_bytes)))
    lines.append("%s  %9d  %s" % (ex_digest, len(subset), name))

    if args.verify:
        if failures:
            print("\nVERIFY FAILED:", file=sys.stderr)
            for f in failures:
                print("  " + f, file=sys.stderr)
            return 1
        print("\nverify: all extracted vectors match a fresh fetch", file=sys.stderr)
        return 0

    (HERE / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\nwrote MANIFEST.sha256", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
