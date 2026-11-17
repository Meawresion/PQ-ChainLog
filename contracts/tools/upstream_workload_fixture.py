#!/usr/bin/env python3
"""Generate an ML-DSA-44 fixture at upstream ETHDILITHIUM's benchmark workload.

# Why

Our first ML-DSA-44 measurement was 12 502 346 gas against upstream's published
8.1 M, and an unexplained 54% gap over a vendored verifier is the kind of thing
that quietly invalidates a paper's cost analysis.

It is not a porting defect and not a compiler-settings difference — those match
theirs exactly. Their benchmark signs a **32-byte** message with an **empty**
context; the first valid ACVP case carries a 2473-byte message and a 31-byte
context. The NIST variant computes `mu` by absorbing `tr || M'` through a
Solidity SHAKE256, so verification cost is linear in message length
(~1.7 k gas/byte at level II, measured in `test/GasProfile.t.sol`).

This script removes the last inference from that argument. Rather than
extrapolating our fit down to 32 bytes, it produces a real level-II signature at
exactly their workload so the comparison is measured on both sides.

# Determinism

Unlike the liboqs fixture, this one **is** reproducible: `dilithium_py` exposes
a seedable DRBG and deterministic signing, so re-running yields byte-identical
output. The seed is fixed below and the fixture is committed; a regeneration
that differs is a real change, not noise.

⚠️ This key is a test artefact with a hardcoded seed. It exists to be verified,
never to protect anything.

Usage:

    ~/.pqcl-venv-ethd/bin/python3 contracts/tools/upstream_workload_fixture.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acvp_to_fixture import VECTORS, deployment_blob, load_reference  # noqa: E402

OUT = VECTORS / "mldsa44-upstream-workload.json"

# Upstream's `test/benchmarks.t.sol` signs these 32 bytes with an empty context.
MESSAGE = bytes.fromhex("1111222233334444111122223333444411112222333344441111222233334444")

# Any fixed value works; this one is recognisable in a hex dump as deliberate.
SEED = bytes.fromhex("5eed" * 24)


def main() -> int:
    D, shake128, shake256 = load_reference("Dilithium2")

    # Seeded so the fixture is reproducible. Without this, `keygen` draws from
    # os.urandom and the committed file could never be regenerated exactly.
    D.set_drbg_seed(SEED)
    pk, sk = D.keygen()

    sig = D.sign(sk, MESSAGE, ctx=b"", deterministic=True)

    # Verify with the reference before emitting. If the reference rejects its
    # own signature the fixture is worthless, and the Solidity failure would be
    # misread as a defect in the contract.
    if not D.verify(pk, MESSAGE, sig, ctx=b""):
        raise SystemExit("the reference implementation rejected its own signature")

    if len(sig) != 2420:
        raise SystemExit(f"ML-DSA-44 signature must be 2420 bytes, got {len(sig)}")

    out = {
        "source": "dilithium_py (ETHDILITHIUM's own reference), deterministic",
        "note": (
            "ML-DSA-44 at upstream's published benchmark workload: 32-byte message, "
            "empty context. Exists so our level-II figure is comparable to their 8.1 M "
            "rather than merely adjacent to it. Reproducible from the seed in "
            "tools/upstream_workload_fixture.py."
        ),
        "cases": [
            {
                "tcId": 1,
                "expected": True,
                "reverts": False,
                "reason": "",
                "context": "0x",
                "message": "0x" + MESSAGE.hex(),
                "signature": "0x" + sig.hex(),
                "pk": deployment_blob(D, shake128, shake256, pk),
            }
        ],
    }

    OUT.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(MESSAGE)}-byte message, empty context, {len(sig)}-byte signature)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
