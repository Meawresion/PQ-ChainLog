#!/usr/bin/env python3
"""Turn our Rust signer's output into the fixture the Solidity gate reads.

The Rust binary (`crates/pqcl-interop`) emits a raw FIPS-204 public key. The
verifier does not take one — it takes the pre-expanded `(A_hat, tr, t1)` blob,
stored once via SSTORE2, with `ExpandA` done off-chain. This script performs
exactly that expansion, reusing `acvp_to_fixture.deployment_blob` so the ACVP
gate and the interop gate cannot drift apart in how a key is prepared.

⚠️ **Reuse, not reimplementation, is the point.** A second copy of the blob
encoding would be a place for the two gates to disagree, and a disagreement
there shows up as a conformance failure in the contract rather than as a bug in
the harness — the most expensive possible way to find it.

Usage (normally via `cargo xtask interop-fixture`):

    cargo run -q -p pqcl-interop | python3 contracts/tools/rust_interop_fixture.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acvp_to_fixture import VECTORS, deployment_blob, load_reference  # noqa: E402

OUT = VECTORS / "rust-interop-mldsa65.json"


def main() -> int:
    doc = json.load(sys.stdin)

    if doc.get("parameterSet") != "ML-DSA-65":
        raise SystemExit(f"expected ML-DSA-65, got {doc.get('parameterSet')!r}")

    # The gate only means something for the interface the contract implements.
    # A preHash or internal-interface signature is a different function and
    # would fail for reasons that say nothing about interoperability.
    if doc.get("signatureInterface") != "external" or doc.get("preHash") != "pure":
        raise SystemExit("fixture is not the external/pure interface the verifier implements")

    pk = bytes.fromhex(doc["pk"][2:])
    if len(pk) != 1952:
        raise SystemExit(f"ML-DSA-65 public key must be 1952 bytes, got {len(pk)}")

    sig = bytes.fromhex(doc["signature"][2:])
    if len(sig) != 3309:
        raise SystemExit(f"ML-DSA-65 signature must be 3309 bytes, got {len(sig)}")

    D, shake128, shake256 = load_reference("Dilithium3")

    out = {
        "source": "PQ-ChainLog liboqs ML-DSA-65 signer",
        "backend": doc.get("backend", "unknown"),
        "note": (
            "Interop gate, Rust -> Solidity. The key and signature were produced by our "
            "own signer, not taken from NIST, which is what this fixture proves that the "
            "ACVP gate cannot. Regenerating yields a different but equally valid file: "
            "liboqs exposes no seeded keygen and its signing is hedged."
        ),
        "cases": [
            {
                "tcId": 1,
                "expected": True,
                "reverts": False,
                "reason": "",
                "context": doc["context"],
                "message": doc["message"],
                "signature": doc["signature"],
                "pk": deployment_blob(D, shake128, shake256, pk),
            }
        ],
    }

    OUT.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    msg_len = (len(doc["message"]) - 2) // 2
    print(f"wrote {OUT} ({msg_len}-byte message, empty context)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
