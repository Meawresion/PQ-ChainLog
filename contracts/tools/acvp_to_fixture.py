#!/usr/bin/env python3
"""Turn NIST ACVP ML-DSA sigVer vectors into fixtures the Solidity verifier can eat.

The design record, condition 2: run ACVP against the **unported**
ETHDILITHIUM verifier first, as a control. If the ML-DSA-65 port later fails
vectors, that control is what separates *"I broke it"* from *"it was already
non-conformant at the pinned commit"*. Without it the failure is unbisectable.

It also substantiates the upstream repo's own "KATs pass" claim independently.
Their KAT is a single vector from their own `generate_test_vectors.py`; this is
NIST's, including **negative** cases, which their KAT has none of.

# Why a generator rather than feeding `pk` straight in

The verifier does not take a FIPS-204 public key. It takes a pre-expanded blob:
the matrix `A` already in the NTT domain, `tr`, and `t1` scaled and transformed,
ABI-encoded and stored once via `SSTORE2`. `ExpandA` happens off-chain. So an
ACVP `pk` has to be put through the reference implementation first, and that is
all this script does — it computes no cryptography of its own, it drives
`dilithium_py` exactly as upstream's `prepare_pk_for_deployment.py` does.

⚠️ **This script must never decide whether a case passes.** It copies ACVP's
`testPassed` through untouched. The moment a generator starts forming opinions
about expected results, the test is measuring the generator.

Usage::

    python3 acvp_to_fixture.py            # regenerate the fixture
    python3 acvp_to_fixture.py --check    # regenerate and diff, write nothing
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACTS = HERE.parent
REF = CONTRACTS / "lib" / "ETHDILITHIUM" / "pythonref"
VECTORS = CONTRACTS / "test" / "vectors"

# Two levels, two purposes. 44 is the control against the *unported* upstream;
# 65 is the binding gate on the port. Same generator, so a discrepancy between
# them cannot come from the harness.
LEVELS = {
    "44": {
        "source": VECTORS / "ML-DSA-44-sigVer-FIPS204.json",
        "out": VECTORS / "mldsa44-control.json",
        "param": "Dilithium2",
        "sig_bytes": 2420,
    },
    "65": {
        # The 65 vectors already live with pqcl-primitives; there is no reason
        # to hold a second copy, and two copies is how they drift.
        "source": CONTRACTS.parent
        / "crates"
        / "pqcl-primitives"
        / "tests"
        / "vectors"
        / "ML-DSA-sigVer-FIPS204.json",
        "out": VECTORS / "mldsa65-acvp.json",
        "param": "Dilithium3",
        "sig_bytes": 3309,
    },
}

# The verifier implements the FIPS-204 **external** interface with a context
# string: it builds `0x00 || len(ctx) || ctx || m` itself. So only the group
# that matches is usable; the internal-interface and preHash groups are a
# different function and would fail for reasons that say nothing about
# conformance.
WANT = {"signatureInterface": "external", "preHash": "pure", "externalMu": False}

def load_reference(param: str):
    """Import upstream's reference implementation, from its own directory."""
    sys.path.insert(0, str(REF))
    try:
        import dilithium_py.dilithium.default_parameters as dp
        from dilithium_py.shake.shake_wrapper import shake128, shake256

        D = getattr(dp, param)
    except ImportError as exc:  # pragma: no cover - environment problem, not logic
        raise SystemExit(
            f"cannot import dilithium_py from {REF}: {exc}\n"
            "Create the venv first:\n"
            "  python3 -m venv ~/.pqcl-venv-ethd\n"
            "  ~/.pqcl-venv-ethd/bin/pip install eth_abi pycryptodome numpy \\\n"
            "      'git+https://github.com/ZKNoxHQ/NTT.git@main#subdirectory=assets/pythonref/'"
        ) from exc
    return D, shake128, shake256


def deployment_blob(D, shake128, shake256, pk: bytes) -> str:
    """`pk` → the ABI-encoded (A_hat, tr, t1) blob the contract stores.

    Mirrors upstream `prepare_pk_for_deployment.py` step for step, differing
    only in taking `pk` as given instead of deriving it from a seed. Any
    divergence here would be a bug in *our* harness masquerading as a
    conformance failure in theirs.
    """
    from eth_abi import encode

    rho, t1 = D._unpack_pk(pk)
    a_hat = D._expand_matrix_from_seed(rho, _xof=shake128)
    tr = D._h(pk, 64, _xof=shake256)

    t1 = t1.scale(1 << D.d).to_ntt()

    a_hat_compact = [[[int(v) for v in col] for col in row] for row in a_hat.compact_256(32)]
    t1_compact = [[int(v) for v in row[0]] for row in t1.compact_256(32)]

    blob = encode(
        ["bytes", "bytes", "bytes"],
        [
            encode(["uint256[][][]"], [a_hat_compact]),
            tr,
            encode(["uint256[][]"], [t1_compact]),
        ],
    )
    return "0x" + blob.hex()


def build(cfg: dict) -> dict:
    D, shake128, shake256 = load_reference(cfg["param"])
    doc = json.loads(cfg["source"].read_text(encoding="utf-8"))

    groups = [g for g in doc["testGroups"] if all(g.get(k) == v for k, v in WANT.items())]
    if not groups:
        raise SystemExit(
            "no external/pure group in the ACVP file. Either the extraction "
            "changed or ACVP renamed its group fields — do not paper over it."
        )

    cases = []
    skipped = []
    for g in groups:
        for c in g["tests"]:
            sig = bytes.fromhex(c["signature"])
            pk = bytes.fromhex(c["pk"])

            # A wrong-length signature is rejected by a `require` before the
            # verifier looks at anything, so the contract reverts rather than
            # returning false. The fixture records which, so the Solidity test
            # asserts the right thing instead of accepting either.
            reverts = len(sig) != cfg["sig_bytes"]

            try:
                blob = deployment_blob(D, shake128, shake256, pk)
            except Exception as exc:
                # A malformed pk that the reference itself cannot unpack is not
                # something the on-chain verifier is ever handed — the key is
                # deployed once, off-line, and a broken one fails there. Record
                # it rather than inventing a blob.
                skipped.append({"tcId": c["tcId"], "why": f"pk unusable: {exc}"})
                continue

            cases.append(
                {
                    "tcId": c["tcId"],
                    "pk": blob,
                    "message": "0x" + c["message"],
                    "context": "0x" + c.get("context", ""),
                    "signature": "0x" + c["signature"],
                    "expected": bool(c["testPassed"]),
                    "reverts": reverts,
                    "reason": c.get("reason", ""),
                }
            )

    return {
        "_source": cfg["source"].name,
        "_group": WANT,
        "_note": (
            "ACVP testPassed copied through untouched. Generated by "
            "tools/acvp_to_fixture.py; do not hand-edit."
        ),
        "skipped": skipped,
        "cases": cases,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--level", choices=sorted(LEVELS), default="44")
    ap.add_argument("--check", action="store_true", help="regenerate and diff; write nothing")
    args = ap.parse_args()

    cfg = LEVELS[args.level]
    fixture = build(cfg)
    text = json.dumps(fixture, indent=1, sort_keys=True) + "\n"

    passes = sum(1 for c in fixture["cases"] if c["expected"])
    fails = sum(1 for c in fixture["cases"] if not c["expected"])
    reverts = sum(1 for c in fixture["cases"] if c["reverts"])

    print(
        f"{len(fixture['cases'])} cases  ({passes} expect-valid, {fails} expect-invalid, "
        f"{reverts} expect-revert), {len(fixture['skipped'])} skipped",
        file=sys.stderr,
    )
    if fails == 0:
        raise SystemExit(
            "no expect-invalid cases survived. A conformance control made only "
            "of valid signatures cannot distinguish a working verifier from one "
            "that returns true unconditionally."
        )

    out = cfg["out"]
    if args.check:
        if not out.exists():
            print(f"{out.name}: missing", file=sys.stderr)
            return 1
        if out.read_text(encoding="utf-8") != text:
            print(f"{out.name}: differs from a fresh generation", file=sys.stderr)
            return 1
        print("fixture matches", file=sys.stderr)
        return 0

    out.write_text(text, encoding="utf-8")
    print(f"wrote {out.relative_to(CONTRACTS)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
