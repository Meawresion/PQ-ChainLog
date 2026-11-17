// SPDX-License-Identifier: MIT
// -----------------------------------------------------------------------------
// DERIVED WORK -- not upstream code.
//
// Source : ZKNoxHQ/ETHDILITHIUM, ZKNOX_hint.sol
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

// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_hint.sol
// Description: Hint computation for Dilithium verification (UseHint / Decompose)
pragma solidity ^0.8.25;

int256 constant GAMMA_2 = 261888;
int256 constant _2_GAMMA_2 = 523776;
int256 constant _2_GAMMA_2_INVERSE = 16; // (8380417 - 1) / _2_GAMMA_2
import {q} from "./MLDSA65_utils.sol";

// Function to reduce r0 within the range of -(a << 1) < r0 <= (a << 1)
function reduceModPm(int256 r0) pure returns (int256 res) {
    res = r0 % _2_GAMMA_2;
    if (res > GAMMA_2) {
        res = res - _2_GAMMA_2;
    }
}

// Decompose function equivalent to the Python version
function decompose(uint256 r) pure returns (int256 r1, int256 r0) {
    // casting to 'int256' is safe because q is 23-bit long
    // forge-lint: disable-next-line(unsafe-typecast)
    int256 rp = int256(r % q);
    r0 = reduceModPm(rp);
    r1 = rp - r0;

    if (rp - r0 == 8380416) {
        r1 = 0;
        r0 = r0 - 1;
    } else {
        r1 = r1 / _2_GAMMA_2;
    }
    return (r1, r0);
}

// Main function, use_hint
function useHint(uint256 h, uint256 r) pure returns (uint256) {
    int256 m = _2_GAMMA_2_INVERSE;
    (int256 r1, int256 r0) = decompose(r);

    if (h == 1) {
        if (r0 > 0) {
            // casting to 'int256' is safe because q is 23-bit long
            // forge-lint: disable-next-line(unsafe-typecast)
            return uint256((r1 + 1) % m);
        }
        // (r1-1)%m
        // casting to 'uint256' is safe because q is 23-bit long
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint256((r1 + m - 1) % m);
    }
    // casting to 'uint256' is safe because r1 is small enough as output by decompose
    // forge-lint: disable-next-line(unsafe-typecast)
    return uint256(r1);
}

/**
 * @notice Assembly-optimized UseHint + Decompose with 6-bit packing for Dilithium
 * @dev Replaces 1024 Solidity-level function calls (useHint -> decompose -> reduceModPm)
 *      with a single assembly pass over the h[][] and r[][] arrays.
 *
 *      Gas savings come from:
 *        - Eliminating 1024 internal function call overhead (~20 gas each = ~20k)
 *        - Eliminating 4 intermediate hintI allocations (4 x 192 bytes)
 *        - Replacing int256 casting/division with unsigned assembly arithmetic
 *        - Direct pointer walking instead of nested array dereferencing (h[i][j])
 *        - Direct mstore8 writes instead of bytes1(uint8(...)) packing
 *
 *      Math inlined per coefficient (all unsigned):
 *        1. r0_raw = r_val % 523776          (unsigned mod by 2*GAMMA_2)
 *        2. Three cases determine r1 and sign of r0:
 *           a) r0_raw == 0  -> r0 not positive; r1 = r_val/523776 (or 0 if r_val == q-1)
 *           b) 0 < r0_raw <= 261888 -> r0 positive; r1 = (r_val - r0_raw) / 523776
 *           c) r0_raw > 261888 -> r0 negative; r1 = (r_val - r0_raw + 523776) / 523776
 *              (edge case: if that premul equals q-1, r1 = 0)
 *        3. If h == 1: adjust r1 -> (r1 + 1) % 16 if r0 > 0, else (r1 + 15) % 16
 *        4. Pack 4 results (4-bit each) into 2 bytes: 4 x 4 = 16 = 2 x 8
 *
 *      Output: 768 bytes = 6 rows x 128 bytes (256 coefficients x 4 bits / 8)
 *
 * @param h Hint matrix (6 x 256 binary values)
 * @param r Coefficient matrix (6 x 256 values mod q)
 * @return hint Packed 768-byte hint encoding
 */
function useHintDilithium(uint256[][] memory h, uint256[][] memory r) pure returns (bytes memory hint) {
    hint = new bytes(768);

    assembly {
        let hintData := add(hint, 32) // skip bytes length prefix

        for { let i := 0 } lt(i, 6) { i := add(i, 1) } { // k = 6
            // Resolve h[i] and r[i] inner array pointers
            let iOff := shl(5, i) // i * 32
            let hi_arr := mload(add(add(h, 32), iOff)) // pointer to h[i]
            let ri_arr := mload(add(add(r, 32), iOff)) // pointer to r[i]
            let hi_data := add(hi_arr, 32) // skip length word
            let ri_data := add(ri_arr, 32) // skip length word
            let writePtr := add(hintData, mul(i, 128)) // destination offset in hint

            for { let j := 0 } lt(j, 256) { j := add(j, 4) } {
                let packed := 0
                let baseOff := shl(5, j) // j * 32

                for { let s := 0 } lt(s, 4) { s := add(s, 1) } {
                    let off := add(baseOff, shl(5, s)) // (j + s) * 32
                    let h_val := mload(add(hi_data, off))
                    let r_val := mload(add(ri_data, off))

                    // ======== Inline decompose + useHint ========
                    //
                    // decompose(r_val) computes:
                    //   r0 = reduceModPm(r_val)  -- centered mod 2*GAMMA_2
                    //   r1 = (r_val - r0) / (2*GAMMA_2)
                    //   with edge case at r_val - r0 == q-1
                    //
                    // useHint uses sign(r0) and h to adjust r1 mod 44

                    // Step 1: unsigned modulo
                    let r0_raw := mod(r_val, 523776) // r_val % (2 * GAMMA_2)
                    let r1 := 0
                    let r0_pos := 0 // tracks whether signed r0 > 0

                    switch iszero(r0_raw)
                    case 1 {
                        // r0_raw == 0: signed r0 = 0 (not positive)
                        // r1_premul = r_val itself
                        // Edge case: r_val == q-1 = 8380416 -> r1 = 0, r0 becomes -1
                        switch eq(r_val, 8380416)
                        case 1 { r1 := 0 }
                        default { r1 := div(r_val, 523776) }
                    }
                    default {
                        switch gt(r0_raw, 261888) // compare with GAMMA_2
                        case 0 {
                            // 0 < r0_raw <= GAMMA_2: signed r0 = r0_raw > 0
                            r1 := div(sub(r_val, r0_raw), 523776)
                            r0_pos := 1
                            // Note: r_val - r0_raw < q when r0_raw > 0,
                            // so edge case (== q-1) is impossible here
                        }
                        default {
                            // r0_raw > GAMMA_2: signed r0 = r0_raw - 523776 < 0
                            // r1_premul = r_val - (r0_raw - 523776) = r_val - r0_raw + 523776
                            let premul := add(sub(r_val, r0_raw), 523776)
                            switch eq(premul, 8380416)
                            case 1 { r1 := 0 }
                            default { r1 := div(premul, 523776) }
                            // r0_pos stays 0 (r0 is negative)
                        }
                    }

                    // Apply hint adjustment: if h == 1, rotate r1
                    if eq(h_val, 1) {
                        switch r0_pos
                        case 1 { r1 := mod(add(r1, 1), 16) } // (r1 + 1) mod m, m = (q-1)/(2*GAMMA_2)
                        default { r1 := mod(add(r1, 15), 16) } // (r1 + m - 1) mod m
                    }

                    // Pack r1 (4-bit value) into a 16-bit accumulator.
                    // Level III w1 is in [0,15], against [0,43] at level II, so
                    // this is 4 bits per coefficient rather than 6 -- a change
                    // to the packing itself, not to a bound.
                    packed := or(packed, shl(mul(s, 4), r1))
                }

                // Write 2 bytes from the 16-bit packed value (FIPS 204
                // SimpleBitPack, little-endian bit order):
                //   byte 0 = (coeff1 << 4) | coeff0
                //   byte 1 = (coeff3 << 4) | coeff2
                mstore8(writePtr, packed) // mstore8 writes lowest byte of value
                mstore8(add(writePtr, 1), shr(8, packed))
                writePtr := add(writePtr, 2)
            }
        }
    }
}
