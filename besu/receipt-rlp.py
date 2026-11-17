#!/usr/bin/env python3
"""Re-encode a block's receipts into the exact bytes the receipt trie stores.

`cast receipt` has no `--raw`, so the trie value has to be reassembled from the
JSON fields. The encoding is EIP-2718:

    legacy  :  rlp([status, cumulativeGasUsed, logsBloom, logs])
    typed   :  type_byte ‖ rlp([status, cumulativeGasUsed, logsBloom, logs])

with the type byte **raw**, not RLP-wrapped. Each log is
`[address, [topic, ...], data]`.

⚠️ This script reconstructs; it does not measure. If the reconstruction is
wrong, the trie root built from its output will not match the `receiptsRoot`
Besu computed, and `tests/against_besu.rs` fails. That comparison is what makes
this safe to rely on — the encoding is checked against an independent
implementation rather than trusted.

Usage:  receipt-rlp.py <rpc-url> <block-hash>
Prints: one `receipt=<index>:<hex>` line per transaction, in index order.
"""

import json
import sys
import urllib.request


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    req = urllib.request.Request(
        url, data=body.encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as fh:
        out = json.loads(fh.read())
    if "error" in out:
        raise SystemExit(f"{method} failed: {out['error']}")
    return out["result"]


def rlp_bytes(data: bytes) -> bytes:
    if len(data) == 1 and data[0] < 0x80:
        return data
    if len(data) <= 55:
        return bytes([0x80 + len(data)]) + data
    length = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(length)]) + length + data


def rlp_list(items) -> bytes:
    payload = b"".join(items)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length)]) + length + payload


def unhex(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def rlp_int(value: int) -> bytes:
    """Minimal big-endian. Zero is the empty string, not a zero byte."""
    if value == 0:
        return rlp_bytes(b"")
    return rlp_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def encode_receipt(r) -> bytes:
    logs = rlp_list(
        [
            rlp_list(
                [
                    rlp_bytes(unhex(log["address"])),
                    rlp_list([rlp_bytes(unhex(t)) for t in log["topics"]]),
                    rlp_bytes(unhex(log["data"])),
                ]
            )
            for log in r["logs"]
        ]
    )

    # Post-Byzantium receipts carry a status flag. `1` is success; failure is
    # the *empty* string, which is how RLP encodes zero.
    status = int(r["status"], 16)
    body = rlp_list(
        [
            rlp_bytes(b"\x01") if status == 1 else rlp_bytes(b""),
            rlp_int(int(r["cumulativeGasUsed"], 16)),
            rlp_bytes(unhex(r["logsBloom"])),
            logs,
        ]
    )

    # `type` is absent on a legacy receipt and 0x0 on a legacy-shaped typed one;
    # only a non-zero type is prefixed.
    tx_type = int(r.get("type", "0x0"), 16)
    return body if tx_type == 0 else bytes([tx_type]) + body


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: receipt-rlp.py <rpc-url> <block-hash>")
    url, block_hash = sys.argv[1], sys.argv[2]

    block = rpc(url, "eth_getBlockByHash", [block_hash, False])
    tx_hashes = block["transactions"]

    for i, txh in enumerate(tx_hashes):
        r = rpc(url, "eth_getTransactionReceipt", [txh])
        idx = int(r["transactionIndex"], 16)
        if idx != i:
            raise SystemExit(f"receipt {txh} reports index {idx}, expected {i}")
        print(f"receipt={idx}:0x{encode_receipt(r).hex()}")


if __name__ == "__main__":
    main()
