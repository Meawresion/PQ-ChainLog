#!/usr/bin/env python3
"""Derive an ML-DSA-65 verifier from the pinned ML-DSA-44 upstream.

Mechanical and reviewable on purpose (condition 3):
every edit is an explicit (old, new) pair below, so the diff is auditable and
re-derivable if upstream is ever bumped.
"""
import pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
UP = ROOT / "lib" / "ETHDILITHIUM" / "src"
OUT = ROOT / "src" / "mldsa65"
OUT.mkdir(parents=True, exist_ok=True)

BANNER = """// SPDX-License-Identifier: MIT
// -----------------------------------------------------------------------------
// DERIVED WORK -- not upstream code.
//
// Source : ZKNoxHQ/ETHDILITHIUM, {src}
// Commit : c8b6a60d563fbdc76dbe468f960b0ca882a585f8  (pinned submodule)
// Change : ML-DSA-44 (level II) -> ML-DSA-65 (level III)
//
// Upstream is NOT modified. This is a copy with the parameter set changed, so
// the submodule stays a clean pinned checkout and the diff stays reviewable.
// Every edit is listed in ../../../PORTING-mldsa65.md with its rationale.
//
// ⚠️ No gas number from this file may be reported until it passes the vendored
// ACVP ML-DSA-65 vectors. That gate is binding, not advisory.
// -----------------------------------------------------------------------------

"""

def strip_spdx(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if "SPDX-License-Identifier" not in l) + "\n"


EDITS = {
    "ZKNOX_dilithium_utils.sol": [
        # --- parameter constants, FIPS 204 Table 1 -------------------------
        ("uint256 constant OMEGA = 80;", "uint256 constant OMEGA = 55;"),
        ("uint256 constant GAMMA_1 = 131072;", "uint256 constant GAMMA_1 = 524288; // 2^19"),
        # beta = tau * eta = 49 * 4 = 196; 524288 - 196
        ("uint256 constant GAMMA_1_MINUS_BETA = 130994;",
         "uint256 constant GAMMA_1_MINUS_BETA = 524092; // GAMMA_1 - beta, beta = tau*eta = 49*4"),
        ("uint256 constant TAU = 39;", "uint256 constant TAU = 49;"),
        ("uint256 constant k = 4;", "uint256 constant k = 6;"),
        ("uint256 constant l = 4;", "uint256 constant l = 5;"),
        # --- shapes: A is k x l = 6 x 5, t1 is k = 6 -----------------------
        (""" * @notice Expands a compressed 4×4×32 matrix into 4×4×256 form""",
         """ * @notice Expands a compressed k×l×32 matrix into k×l×256 form (6×5 at level III)"""),
        ("""    b = new uint256[][][](4);
    for (uint256 i = 0; i < 4; i++) {
        b[i] = new uint256[][](4);
        for (uint256 j = 0; j < 4; j++) {
            b[i][j] = expand(table[i][j]);
        }
    }
    return b;""",
         """    b = new uint256[][][](k);
    for (uint256 i = 0; i < k; i++) {
        b[i] = new uint256[][](l);
        for (uint256 j = 0; j < l; j++) {
            b[i][j] = expand(table[i][j]);
        }
    }
    return b;"""),
        ("""    b = new uint256[][](4);
    for (uint256 i = 0; i < 4; i++) {
        b[i] = expand(table[i]);
    }
    return b;""",
         """    b = new uint256[][](k);
    for (uint256 i = 0; i < k; i++) {
        b[i] = expand(table[i]);
    }
    return b;"""),
        ("uint256 constant ROW_COUNT = 4;\nuint256 constant COL_COUNT = 4;",
         "uint256 constant ROW_COUNT = 6; // k\nuint256 constant COL_COUNT = 5; // l"),
        (""" * @dev Specialized implementation for 4×4 matrices with assembly inner loops""",
         """ * @dev Specialized implementation for k×l matrices with assembly inner loops"""),
    ],
    "ZKNOX_hint.sol": [
        # gamma2 = (q-1)/32 at level III, against (q-1)/88 at level II.
        # Missed by a grep for k/l/TAU/OMEGA/GAMMA_1 -- it is spelled GAMMA_2
        # and lives in a file that names none of the others.
        ("int256 constant _2_GAMMA_2_INVERSE = 44; // (8380417 - 1) / _2_GAMMA_2",
         "int256 constant _2_GAMMA_2_INVERSE = 16; // (8380417 - 1) / _2_GAMMA_2"),
        ('import {q} from "./ZKNOX_dilithium_utils.sol";', 'import {q} from "./MLDSA65_utils.sol";'),
        # ⚠️ The assembly bodies inline 2*GAMMA_2 and GAMMA_2 as literals,
        # because Yul cannot see a Solidity constant. Editing only the named
        # constants above would leave decompose() running at level II while the
        # file read as fully ported. Applied to every occurrence.
        ("190464", "523776"),
        ("95232", "261888"),
        # --- shape and stride: k rows, 256 coeffs x 4 bits / 8 = 128 B ------
        ("for { let i := 0 } lt(i, 4) { i := add(i, 1) } {",
         "for { let i := 0 } lt(i, 6) { i := add(i, 1) } { // k = 6"),
        ("let writePtr := add(hintData, mul(i, 192))",
         "let writePtr := add(hintData, mul(i, 128))"),
        # --- w1 lives in [0, 15] at level III, so the rotation is mod 16 -----
        ("case 1 { r1 := mod(add(r1, 1), 44) } // (r1 + 1) mod m",
         "case 1 { r1 := mod(add(r1, 1), 16) } // (r1 + 1) mod m, m = (q-1)/(2*GAMMA_2)"),
        ("default { r1 := mod(add(r1, 43), 44) } // (r1 + m - 1) mod m",
         "default { r1 := mod(add(r1, 15), 16) } // (r1 + m - 1) mod m"),
        # --- 4 bits per coefficient, so four of them make two bytes ----------
        ("""                    // Pack r1 (6-bit value) into the 24-bit accumulator
                    // s=0 -> bits [0:5], s=1 -> bits [6:11], s=2 -> bits [12:17], s=3 -> bits [18:23]
                    packed := or(packed, shl(mul(s, 6), r1))""",
         """                    // Pack r1 (4-bit value) into a 16-bit accumulator.
                    // Level III w1 is in [0,15], against [0,43] at level II, so
                    // this is 4 bits per coefficient rather than 6 -- a change
                    // to the packing itself, not to a bound.
                    packed := or(packed, shl(mul(s, 4), r1))"""),
        ("""                // Write 3 bytes from the 24-bit packed value
                // Byte layout matches original packing:
                //   byte 0 = (coeff1[1:0] << 6) | coeff0[5:0]     = packed[7:0]
                //   byte 1 = (coeff2[3:0] << 4) | coeff1[5:2]     = packed[15:8]
                //   byte 2 = (coeff3[5:0] << 2) | coeff2[5:4]     = packed[23:16]
                mstore8(writePtr, packed) // mstore8 writes lowest byte of value
                mstore8(add(writePtr, 1), shr(8, packed))
                mstore8(add(writePtr, 2), shr(16, packed))
                writePtr := add(writePtr, 3)""",
         """                // Write 2 bytes from the 16-bit packed value (FIPS 204
                // SimpleBitPack, little-endian bit order):
                //   byte 0 = (coeff1 << 4) | coeff0
                //   byte 1 = (coeff3 << 4) | coeff2
                mstore8(writePtr, packed) // mstore8 writes lowest byte of value
                mstore8(add(writePtr, 1), shr(8, packed))
                writePtr := add(writePtr, 2)"""),
        (" *        4. Pack 4 results (6-bit each) into 3 bytes: 4 x 6 = 24 = 3 x 8",
         " *        4. Pack 4 results (4-bit each) into 2 bytes: 4 x 4 = 16 = 2 x 8"),
        (" *      Output: 768 bytes = 4 rows x 192 bytes (256 coefficients x 6 bits / 8)",
         " *      Output: 768 bytes = 6 rows x 128 bytes (256 coefficients x 4 bits / 8)"),
        (" *        3. If h == 1: adjust r1 -> (r1 + 1) % 44 if r0 > 0, else (r1 + 43) % 44",
         " *        3. If h == 1: adjust r1 -> (r1 + 1) % 16 if r0 > 0, else (r1 + 15) % 16"),
        (" * @param h Hint matrix (4 x 256 binary values)", " * @param h Hint matrix (6 x 256 binary values)"),
        (" * @param r Coefficient matrix (4 x 256 values mod q)",
         " * @param r Coefficient matrix (6 x 256 values mod q)"),
    ],
    "ZKNOX_dilithium_core.sol": [
        ('import {nttFw, nttInv} from "./ZKNOX_NTT_dilithium.sol";',
         'import {nttFw, nttInv} from "../../lib/ETHDILITHIUM/src/ZKNOX_NTT_dilithium.sol";'),
        ('import {PubKey, Signature} from "./ZKNOX_dilithium_utils.sol";',
         'import {PubKey, Signature} from "./MLDSA65_utils.sol";'),
        ('} from "./ZKNOX_dilithium_utils.sol";', '} from "./MLDSA65_utils.sol";'),
        ('import {useHintDilithium} from "./ZKNOX_hint.sol";',
         'import {useHintDilithium} from "./MLDSA65_hint.sol";'),
        # --- loop bounds hardcoded as 4. Which constant each one is depends
        # --- on what it walks: h and A*z are k-dimensional, z is l.
        ("""    normH = 0;
    // Assembly: walk the h arrays directly in memory
    assembly {
        for { let i := 0 } lt(i, 4) { i := add(i, 1) } {""",
         """    normH = 0;
    // `k`, not a literal: h has one polynomial per row of A. Assembly cannot
    // read a Solidity constant, so it is copied to a local first.
    uint256 _k = k;
    // Assembly: walk the h arrays directly in memory
    assembly {
        for { let i := 0 } lt(i, _k) { i := add(i, 1) } {"""),
        ("""    // NTT(z)
    for (uint256 i = 0; i < 4; i++) {
        z[i] = nttFw(z[i]);
    }""",
         """    // NTT(z) -- z is l-dimensional, one polynomial per column of A.
    for (uint256 i = 0; i < l; i++) {
        z[i] = nttFw(z[i]);
    }"""),
        ("""    for (uint256 i = 0; i < 4; i++) {
        z[i] = nttInv(vecSubMulMod(z[i], t1New[i], cNtt));
    }""",
         """    // After the matrix-vector product `z` holds A*z, which is
    // k-dimensional -- not l. Getting this one wrong reads plausibly.
    for (uint256 i = 0; i < k; i++) {
        z[i] = nttInv(vecSubMulMod(z[i], t1New[i], cNtt));
    }"""),
    ],
    "ZKNOX_dilithium.sol": [
        ('import {nttFw} from "./ZKNOX_NTT_dilithium.sol";',
         'import {nttFw} from "../../lib/ETHDILITHIUM/src/ZKNOX_NTT_dilithium.sol";'),
        ('import {dilithiumCore1, dilithiumCore2} from "./ZKNOX_dilithium_core.sol";',
         'import {dilithiumCore1, dilithiumCore2} from "./MLDSA65_core.sol";'),
        ('import {sampleInBallNist} from "./ZKNOX_SampleInBall.sol";',
         '// SampleInBall takes tau and c_tilde as arguments, so it is already\n'
         '// parameter-generic and is used unmodified from upstream.\n'
         'import {sampleInBallNist} from "../../lib/ETHDILITHIUM/src/ZKNOX_SampleInBall.sol";'),
        ('import {CtxShake, shakeUpdate, shakeDigest} from "./ZKNOX_shake.sol";',
         'import {CtxShake, shakeUpdate, shakeDigest} from "../../lib/ETHDILITHIUM/src/ZKNOX_shake.sol";'),
        ('import {q, expandVec, OMEGA, GAMMA_1_MINUS_BETA, TAU, d, PubKey, Signature, slice} from "./ZKNOX_dilithium_utils.sol";',
         'import {\n'
         '    q,\n'
         '    expandVec,\n'
         '    OMEGA,\n'
         '    GAMMA_1_MINUS_BETA,\n'
         '    TAU,\n'
         '    d,\n'
         '    l,\n'
         '    PubKey,\n'
         '    Signature,\n'
         '    slice\n'
         '} from "./MLDSA65_utils.sol";'),
        ("contract ZKNOX_dilithium is ISigVerifier {", "contract MLDSA65Verifier is ISigVerifier {"),
        # --- signature layout: c_tilde 48 | z 3200 | h 61 = 3309 ------------
        ('require(signature.length == 2420, "invalid signature length");',
         'require(signature.length == 3309, "invalid signature length");'),
        ("if (signature.length != 2420) {", "if (signature.length != 3309) {"),
        ("Signature({cTilde: slice(signature, 0, 32), z: slice(signature, 32, 2304), h: slice(signature, 2336, 84)});",
         "Signature({cTilde: slice(signature, 0, 48), z: slice(signature, 48, 3200), h: slice(signature, 3248, 61)});"),
        # --- z-norm loop runs over l polynomials, hardcoded at level II -----
        ("""            uint256 _q = q;
            uint256 _bound = GAMMA_1_MINUS_BETA;""",
         """            uint256 _q = q;
            uint256 _bound = GAMMA_1_MINUS_BETA;
            // `l`, not a literal: z has one polynomial per column of A, and at
            // level III that is 5 rather than 4. Assembly cannot read a
            // Solidity constant, so it is copied to a local first.
            uint256 _l = l;"""),
        ("for { let i := 0 } lt(i, 4) { i := add(i, 1) } {",
         "for { let i := 0 } lt(i, _l) { i := add(i, 1) } {"),
        # --- c_tilde is 48 bytes at level III (lambda/4, lambda = 192).
        # --- Squeezing 32 and comparing as bytes32 would check only two thirds
        # --- of the challenge hash -- it would still *pass* valid signatures,
        # --- which is exactly what makes it dangerous rather than obvious.
        ("""        bytes32 finalHash = bytes32(shakeDigest(sctx2, 32));

        return finalHash == bytes32(signature.cTilde);""",
         """        bytes memory finalHash = shakeDigest(sctx2, 48);

        // keccak, not a bytes32 cast: c_tilde is 48 bytes here, and casting
        // would silently compare only the first 32.
        return keccak256(finalHash) == keccak256(signature.cTilde);"""),
    ],
}

RENAME = {
    "ZKNOX_dilithium_utils.sol": "MLDSA65_utils.sol",
    "ZKNOX_hint.sol": "MLDSA65_hint.sol",
    "ZKNOX_dilithium_core.sol": "MLDSA65_core.sol",
    "ZKNOX_dilithium.sol": "MLDSA65.sol",
}

total = 0
for src, edits in EDITS.items():
    text = (UP / src).read_text(encoding="utf-8")
    for old, new in edits:
        if old not in text:
            sys.exit(f"ANCHOR MISSING in {src}:\n  {old[:110]}")
        n = text.count(old)
        text = text.replace(old, new)
        total += n
    (OUT / RENAME[src]).write_text(BANNER.format(src=src) + strip_spdx(text), encoding="utf-8")
    print(f"{src:34s} -> {RENAME[src]:22s} {len(edits)} edits")

print(f"\n{total} edits applied across {len(EDITS)} files")
