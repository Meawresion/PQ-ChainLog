#!/usr/bin/env python3
"""Turn a court order signed by our Rust signer into the Solidity fixture.

The key is expanded exactly as the interop gate expands it
(`acvp_to_fixture.deployment_blob`), so the two gates cannot disagree on how a
key is prepared. The fields are kept separately *and* as the signed message, so
the Solidity test can re-encode the fields with `abi.encodePacked` and compare:
that comparison is what pins `pqcl_capsule::redaction::Order::message` to the
contract's encoding.

Usage:

    cargo run -q -p pqcl-interop --bin redaction-order \\
      | python3 contracts/tools/redaction_order_fixture.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acvp_to_fixture import VECTORS, deployment_blob, load_reference  # noqa: E402

OUT = VECTORS / "redaction-order-mldsa65.json"


def main() -> int:
    doc = json.load(sys.stdin)
    if doc.get("parameterSet") != "ML-DSA-65":
        raise SystemExit(f"expected ML-DSA-65, got {doc.get('parameterSet')!r}")
    if doc.get("signatureInterface") != "external" or doc.get("preHash") != "pure":
        raise SystemExit("fixture is not the external/pure interface the verifier implements")

    pk = bytes.fromhex(doc["pk"][2:])
    sig = bytes.fromhex(doc["signature"][2:])
    msg = bytes.fromhex(doc["message"][2:])
    if len(pk) != 1952 or len(sig) != 3309:
        raise SystemExit(f"bad ML-DSA-65 sizes: pk {len(pk)}, sig {len(sig)}")
    if len(msg) != 82:
        raise SystemExit(f"eq:order message must be 82 bytes, got {len(msg)}")

    D, shake128, shake256 = load_reference("Dilithium3")
    out = {
        "source": "PQ-ChainLog liboqs ML-DSA-65 signer, court authority",
        "backend": doc.get("backend", "unknown"),
        "note": "A genuine redaction order (draft7 eq:order). Regenerating yields a "
                "different but equally valid file.",
        "orderId": doc["orderId"],
        "target": doc["target"],
        "scope": doc["scope"],
        "mode": doc["mode"],
        "ts": doc["ts"],
        "exp": doc["exp"],
        "message": doc["message"],
        "signature": doc["signature"],
        "pk": deployment_blob(D, shake128, shake256, pk),
    }
    OUT.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
