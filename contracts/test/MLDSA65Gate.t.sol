// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {MLDSA65Verifier} from "../src/mldsa65/MLDSA65.sol";

/// @title ⭐ The binding ACVP-65 gate on the ported verifier
/// @notice the design record, condition 1: *"No gas number leaves
/// an unvalidated verifier."*
///
/// The port changed 47 things across four files of somebody else's
/// cryptographic Solidity. "It compiles" and "it looks ported" are worth
/// nothing here — two of the changes were only found because a value-level
/// sweep went looking:
///
///  * `GAMMA_2` lives in `ZKNOX_hint.sol`, a file that names none of `k`, `l`,
///    `TAU`, `OMEGA` or `GAMMA_1`, so a grep for the obvious parameters misses
///    it entirely. Level II uses `(q-1)/88`; level III uses `(q-1)/32`.
///  * The same file inlines `2*GAMMA_2` as a **literal inside `assembly`**,
///    where a Solidity constant is unreachable. Editing the named constants
///    alone leaves `decompose()` running at level II in a file that reads as
///    fully ported.
///
/// Either would produce a verifier that compiles, deploys, and quietly computes
/// the wrong thing. This test is the only reason to believe it does not.
contract MLDSA65GateTest is Test {
    /// Alphabetical order — that is how Foundry maps JSON onto a struct.
    struct AcvpCase {
        bytes context;
        bool expected;
        bytes message;
        bytes pk;
        string reason;
        bool reverts;
        bytes signature;
        uint256 tcId;
    }

    MLDSA65Verifier internal verifier;
    AcvpCase[] internal cases;

    function setUp() public {
        verifier = new MLDSA65Verifier();
        string memory raw = vm.readFile("test/vectors/mldsa65-acvp.json");
        AcvpCase[] memory parsed = abi.decode(vm.parseJson(raw, ".cases"), (AcvpCase[]));
        for (uint256 i = 0; i < parsed.length; i++) {
            cases.push(parsed[i]);
        }
    }

    function test_GateHasBothOutcomes() public view {
        uint256 valid;
        for (uint256 i = 0; i < cases.length; i++) {
            if (cases[i].expected) valid++;
        }
        assertGt(cases.length, 0, "fixture is empty");
        assertGt(valid, 0, "no expect-valid cases: cannot detect a verifier that always rejects");
        assertLt(valid, cases.length, "no expect-invalid cases: cannot detect one that always accepts");
    }

    /// ⭐ The gate. Every ACVP ML-DSA-65 external/pure case, against the port.
    function test_PortedVerifierMatchesAcvp65() public {
        uint256 checked;
        for (uint256 i = 0; i < cases.length; i++) {
            AcvpCase memory c = cases[i];

            // `setKey` is hoisted out deliberately: `vm.expectRevert` binds to
            // the *next* external call, and nesting the two made it guard
            // `setKey` instead of `verify`.
            bytes memory keyPtr = verifier.setKey(c.pk);

            if (c.reverts) {
                vm.expectRevert();
                verifier.verify(keyPtr, c.message, c.signature, c.context);
                checked++;
                continue;
            }

            bool got = verifier.verify(keyPtr, c.message, c.signature, c.context);
            assertEq(
                got,
                c.expected,
                string.concat(
                    "ACVP-65 tcId ",
                    vm.toString(c.tcId),
                    " disagrees with the ported verifier. reason: ",
                    c.reason,
                    " -- the ACVP-44 control passes on the unported upstream, so this is the port."
                )
            );
            checked++;
        }
        assertEq(checked, cases.length, "not every case ran");
        console.log("ported ML-DSA-65 verifier: ACVP cases checked", checked);
    }

    /// A level-II signature must not be accepted by a level-III verifier.
    ///
    /// Cheap, and it catches the failure mode where a half-finished port still
    /// happens to satisfy the level-III vectors for the wrong reason: the
    /// length check alone should reject 2420 bytes.
    function test_ALevelTwoSignatureIsRejected() public {
        AcvpCase memory c = cases[0];
        bytes memory keyPtr = verifier.setKey(c.pk);
        bytes memory shortSig = new bytes(2420);
        vm.expectRevert();
        verifier.verify(keyPtr, c.message, shortSig, c.context);
    }
}
