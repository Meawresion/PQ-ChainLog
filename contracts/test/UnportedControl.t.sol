// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ZKNOX_dilithium} from "../lib/ETHDILITHIUM/src/ZKNOX_dilithium.sol";
import {ZKNOX_ethdilithium} from "../lib/ETHDILITHIUM/src/ZKNOX_ethdilithium.sol";

/// @title The control run, before ETHDILITHIUM is touched
/// @notice the design record, condition 2.
///
/// The vendored verifier is ML-DSA-**44**; our system signs at **65**, so it
/// has to be ported. Before changing a line of somebody else's cryptographic
/// Solidity, establish what it does *now* against NIST's own vectors. If the
/// port later fails ACVP-65, this is what separates "I broke it" from "it was
/// already non-conformant at commit `c8b6a60d`".
///
/// It is also an independent check on the upstream repo's "KATs pass" badge.
/// Their KAT is one vector from their own generator and contains **no negative
/// cases**; this control has twelve.
contract UnportedControlTest is Test {
    /// Mirrors `tools/acvp_to_fixture.py`. Fields must stay in **alphabetical
    /// order** — that is how Foundry maps JSON keys onto a struct, and a
    /// reordering here silently shifts every field.
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

    ZKNOX_dilithium internal nist;
    ZKNOX_ethdilithium internal ethVariant;
    AcvpCase[] internal cases;

    function setUp() public {
        nist = new ZKNOX_dilithium();
        ethVariant = new ZKNOX_ethdilithium();

        string memory raw = vm.readFile("test/vectors/mldsa44-control.json");
        AcvpCase[] memory parsed = abi.decode(vm.parseJson(raw, ".cases"), (AcvpCase[]));
        for (uint256 i = 0; i < parsed.length; i++) {
            cases.push(parsed[i]);
        }
    }

    /// A control made only of valid signatures cannot tell a working verifier
    /// from one that returns `true` unconditionally. Assert the shape of the
    /// fixture before trusting what it proves.
    function test_ControlHasBothOutcomes() public view {
        uint256 valid;
        uint256 invalid;
        for (uint256 i = 0; i < cases.length; i++) {
            if (cases[i].expected) valid++;
            else invalid++;
        }
        assertGt(cases.length, 0, "fixture is empty");
        assertGt(valid, 0, "no expect-valid cases: cannot detect a verifier that always rejects");
        assertGt(invalid, 0, "no expect-invalid cases: cannot detect a verifier that always accepts");
        console.log("control cases", cases.length, "valid", valid);
    }

    /// ⭐ The control itself: the **unported** NIST-faithful verifier against
    /// NIST's own ML-DSA-44 vectors.
    function test_UnportedNistVerifierMatchesAcvp() public {
        uint256 checked;
        for (uint256 i = 0; i < cases.length; i++) {
            AcvpCase memory c = cases[i];

            // A wrong-length signature is refused by a `require` before any
            // verification work, so the contract reverts instead of returning
            // false. The fixture records which, so this asserts the right
            // outcome rather than accepting either.
            // Hoisted: `vm.expectRevert` binds to the next external call, so
            // nesting `_deploy` inside would guard the wrong one.
            bytes memory keyPtr = _deploy(c.pk);

            if (c.reverts) {
                vm.expectRevert();
                nist.verify(keyPtr, c.message, c.signature, c.context);
                checked++;
                continue;
            }

            bool got = nist.verify(keyPtr, c.message, c.signature, c.context);
            assertEq(
                got,
                c.expected,
                string.concat(
                    "ACVP tcId ", vm.toString(c.tcId), " disagrees with the unported verifier. reason: ", c.reason
                )
            );
            checked++;
        }
        assertEq(checked, cases.length, "not every case ran");
        console.log("unported NIST verifier: ACVP-44 cases checked", checked);
    }

    /// ⭐ Config C should be **unable** to verify a FIPS-204 signature at all.
    ///
    /// The design record asks for this to be falsifiable rather
    /// than assumed. `ZKNOX_ethdilithium` substitutes a Keccak-based PRNG for
    /// SHAKE256, which makes it a *different algorithm*; a real FIPS-204
    /// signature must therefore fail. If this test ever fails — that is, if the
    /// EVM-tuned variant accepts a NIST vector — the assumption that config C
    /// is non-conformant is wrong, and §9.1 caveat 1 needs revisiting before
    /// anything is built on it.
    function test_EvmTunedVariantCannotVerifyFipsSignatures() public {
        uint256 tried;
        for (uint256 i = 0; i < cases.length; i++) {
            AcvpCase memory c = cases[i];
            if (!c.expected || c.reverts) continue; // only the genuinely valid ones prove anything

            try ethVariant.verify(_deploy(c.pk), c.message, c.signature, c.context) returns (bool got) {
                assertFalse(
                    got,
                    string.concat(
                        "the EVM-tuned variant ACCEPTED FIPS-204 tcId ",
                        vm.toString(c.tcId),
                        ". It substitutes a Keccak PRNG for SHAKE256, so it should not be able to. ",
                        "Config C's non-conformance is assumed by plan 9.1 caveat 1 -- recheck it."
                    )
                );
            } catch {
                // Reverting is an equally good answer: it did not verify.
            }
            tried++;
        }
        assertGt(tried, 0, "no valid vectors were tried, so this proved nothing");
        console.log("EVM-tuned variant rejected valid FIPS-204 vectors", tried);
    }

    /// Store a public key blob and return the encoded pointer the verifier wants.
    function _deploy(bytes memory blob) internal returns (bytes memory) {
        return nist.setKey(blob);
    }
}
