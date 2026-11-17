#!/usr/bin/env python3
"""GGM-over-AES vectors from an implementation that is not ours.

M12 R3 (`Require-Consultant.md` §1o.1) moved the GGM step to

    G(s) = AES-256_s(<0>) || AES-256_s(<1>) || AES-256_s(<2>) || AES-256_s(<3>)

with <i> the 128-bit big-endian encoding of i; the first 32 bytes are the left
child, the last 32 the right. A GGM leaf at index x is reached from the root by
64 steps, taking the right child where bit (63 - depth) of x is set.

This script computes both with Python's `cryptography` (OpenSSL underneath),
written from those two sentences, and `tests/independent_vectors.rs` requires
our Rust build to reproduce every line byte for byte. Regenerate with:

    python3 ggm_aes.py > ggm_aes.txt
"""
import hashlib
import sys

import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def G(seed: bytes) -> bytes:
    enc = Cipher(algorithms.AES(seed), modes.ECB()).encryptor()
    blocks = b"".join(i.to_bytes(16, "big") for i in range(4))
    return enc.update(blocks) + enc.finalize()


def leaf(root: bytes, index: int) -> bytes:
    key = root
    for depth in range(64):
        out = G(key)
        key = out[32:] if (index >> (63 - depth)) & 1 else out[:32]
    return key


SEEDS = [bytes(32), b"\xff" * 32, bytes(range(32))] + [
    hashlib.sha256(b"ggm-aes seed %d" % i).digest() for i in range(5)
]
ROOTS = [bytes(range(32)), hashlib.sha256(b"ggm-aes root").digest()]
INDICES = [0, 1, 2, 3, 255, 256, 2**32, 2**63, 2**64 - 1, 1234567890123456789]

print("# GGM over AES-256, independent vectors (Python cryptography %s)" % cryptography.__version__)
print("# step <seed> <G(seed)>   |   eval <root> <index> <leaf>")
for s in SEEDS:
    print("step", s.hex(), G(s).hex())
for r in ROOTS:
    for x in INDICES:
        print("eval", r.hex(), x, leaf(r, x).hex())
sys.stdout.flush()
