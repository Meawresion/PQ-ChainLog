// SPDX-License-Identifier: MIT
// -----------------------------------------------------------------------------
// DERIVED WORK -- not upstream code.
//
// Source : ZKNoxHQ/ETHDILITHIUM, ZKNOX_dilithium.sol
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
// FILE: ZKNOX_dilithium.sol
// Description: Dilithium Signature verifier following NIST specification
pragma solidity ^0.8.25;

import {SSTORE2} from "sstore2/SSTORE2.sol";
import {nttFw} from "../../lib/ETHDILITHIUM/src/ZKNOX_NTT_dilithium.sol";
import {dilithiumCore1, dilithiumCore2} from "./MLDSA65_core.sol";
// SampleInBall takes tau and c_tilde as arguments, so it is already
// parameter-generic and is used unmodified from upstream.
import {sampleInBallNist} from "../../lib/ETHDILITHIUM/src/ZKNOX_SampleInBall.sol";
import {CtxShake, shakeUpdate, shakeDigest} from "../../lib/ETHDILITHIUM/src/ZKNOX_shake.sol";
import {
    q,
    expandVec,
    OMEGA,
    GAMMA_1_MINUS_BETA,
    TAU,
    d,
    l,
    PubKey,
    Signature,
    slice
} from "./MLDSA65_utils.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";

contract MLDSA65Verifier is ISigVerifier {
    /**
     * @notice Stores the given public key on-chain using SSTORE2.
     * @param pubkey The serialized Dilithium public key.
     * @return The ABI-encoded address of the SSTORE2 pointer.
     */
    function setKey(bytes memory pubkey) external returns (bytes memory) {
        address pointer = SSTORE2.write(pubkey);
        return abi.encodePacked(pointer);
    }

    /**
     * @notice Verifies a Dilithium signature with context.
     * @dev Compatible with context-aware Dilithium verification.
     *      Extracts the public key contract address from `pk`.
     * @param pk ABI-encoded address of the PKContract.
     * @param m The message to verify.
     * @param signature The Dilithium signature.
     * @param ctx Optional context bytes (max length 255).
     * @return True if the signature is valid, false otherwise.
     */
    function verify(bytes memory pk, bytes memory m, bytes memory signature, bytes memory ctx)
        external
        view
        returns (bool)
    {
        require(signature.length == 3309, "invalid signature length");

        address pubKeyAddress;
        assembly {
            pubKeyAddress := mload(add(pk, 20))
        }
        PubKey memory publicKey = _readPubKey(pubKeyAddress);

        if (ctx.length > 255) {
            revert("ctx bytes must have length at most 255");
        }
        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(uint8(ctx.length)), ctx, m);

        Signature memory sig =
            Signature({cTilde: slice(signature, 0, 48), z: slice(signature, 48, 3200), h: slice(signature, 3248, 61)});

        return verifyInternal(publicKey, mPrime, sig);
    }

    /**
     * @notice Verifies a Dilithium signature (EIP-style interface).
     * @dev Implements ISigVerifier interface.
     *      Does not support custom context.
     * @param pk Encoded PKContract address.
     * @param m Message hash.
     * @param signature Dilithium signature.
     * @return Selector on success, 0xFFFFFFFF on failure.
     */
    function verify(bytes calldata pk, bytes32 m, bytes calldata signature) external view returns (bytes4) {
        if (signature.length != 3309) {
            return 0xFFFFFFFF;
        }

        address pkContractAddress;
        assembly {
            pkContractAddress := shr(96, calldataload(pk.offset))
        }

        PubKey memory publicKey = _readPubKey(pkContractAddress);

        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(0), m);

        Signature memory sig =
            Signature({cTilde: slice(signature, 0, 48), z: slice(signature, 48, 3200), h: slice(signature, 3248, 61)});

        if (verifyInternal(publicKey, mPrime, sig)) {
            return ISigVerifier.verify.selector;
        }
        return 0xFFFFFFFF;
    }

    /**
     * @notice Reads a PubKey from an SSTORE2 pointer.
     */
    function _readPubKey(address pointer) internal view returns (PubKey memory) {
        (bytes memory aHatEncoded, bytes memory tr, bytes memory t1Encoded) =
            abi.decode(SSTORE2.read(pointer), (bytes, bytes, bytes));
        uint256[][][] memory aHat = abi.decode(aHatEncoded, (uint256[][][]));
        uint256[][] memory t1 = abi.decode(t1Encoded, (uint256[][]));
        return PubKey({aHat: aHat, tr: tr, t1: t1});
    }

    /**
     * @notice Performs the core Dilithium signature verification.
     * @dev Implements the full NIST Dilithium verification algorithm.
     *      Uses optimized assembly routines for gas efficiency.
     * @param pk Expanded public key structure.
     * @param mPrime Encoded message with context.
     * @param signature Parsed Dilithium signature.
     * @return True if the signature is valid, false otherwise.
     */
    function verifyInternal(PubKey memory pk, bytes memory mPrime, Signature memory signature)
        internal
        pure
        returns (bool)
    {
        // FIRST CORE STEP
        (bool foo, uint256 normH, uint256[][] memory h, uint256[][] memory z) = dilithiumCore1(signature);

        if (foo == false) {
            return false;
        }
        if (normH > OMEGA) {
            return false;
        }

        // z-norm check in assembly - avoids bounds checks on 1024 accesses
        {
            uint256 _q = q;
            uint256 _bound = GAMMA_1_MINUS_BETA;
            // `l`, not a literal: z has one polynomial per column of A, and at
            // level III that is 5 rather than 4. Assembly cannot read a
            // Solidity constant, so it is copied to a local first.
            uint256 _l = l;
            bool failed = false;
            assembly {
                for { let i := 0 } lt(i, _l) { i := add(i, 1) } {
                    let zi_ptr := mload(add(add(z, 32), mul(i, 32))) // z[i] pointer
                    let data_ptr := add(zi_ptr, 32) // skip length
                    for { let j := 0 } lt(j, 256) { j := add(j, 1) } {
                        let zij := mload(add(data_ptr, mul(j, 32)))
                        // if zij > bound && (q - zij) > bound → fail
                        if and(gt(zij, _bound), gt(sub(_q, zij), _bound)) {
                            failed := 1
                        }
                    }
                }
            }
            if (failed) return false;
        }

        // C_NTT
        uint256[] memory cNtt = sampleInBallNist(signature.cTilde, TAU, q);

        cNtt = nttFw(cNtt);

        // t1 is stored in the NTT domain, with a 1<<d shift
        uint256[][] memory t1New = expandVec(pk.t1);

        // SECOND CORE STEP
        bytes memory wPrimeBytes = dilithiumCore2(pk, z, cNtt, h, t1New);

        // FINAL HASH
        CtxShake memory sctx;
        sctx = shakeUpdate(sctx, pk.tr);
        sctx = shakeUpdate(sctx, mPrime);
        bytes memory mu = shakeDigest(sctx, 64);

        CtxShake memory sctx2;
        sctx2 = shakeUpdate(sctx2, mu);
        sctx2 = shakeUpdate(sctx2, wPrimeBytes);
        bytes memory finalHash = shakeDigest(sctx2, 48);

        // keccak, not a bytes32 cast: c_tilde is 48 bytes here, and casting
        // would silently compare only the first 32.
        return keccak256(finalHash) == keccak256(signature.cTilde);
    }
}
