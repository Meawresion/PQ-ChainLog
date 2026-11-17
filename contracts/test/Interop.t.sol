// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {MLDSA65Verifier} from "../src/mldsa65/MLDSA65.sol";
import {ZKNOX_dilithium} from "../lib/ETHDILITHIUM/src/ZKNOX_dilithium.sol";

/// @title Interop gate — a signature *we* produced, verified on-chain
/// @notice the build plan (M7) requires this before any on-chain
/// benchmarking: "a signature produced by our Rust/liboqs signer must verify in
/// the deployed Solidity verifier... If the two disagree on encoding,
/// endianness or domain separation, the gas number is measuring the wrong
/// thing."
///
/// ⭐ **This is the direction the ACVP gate cannot cover.** `MLDSA65Gate.t.sol`
/// proves the contract agrees with NIST, and `pqcl-primitives/tests/kat.rs`
/// proves our Rust agrees with NIST — both pinned to the same referee, which is
/// the right arrangement. What neither shows is that a key and signature our
/// own signer generated are accepted here. Two implementations can each pass a
/// vector set and still disagree on freshly generated material, because vectors
/// exercise only the encodings NIST chose to include.
///
/// The fixture is committed rather than generated at test time: liboqs exposes
/// no seeded key generation and its signing is hedged, so regeneration yields a
/// different-but-valid file. Rebuild it with `cargo xtask interop-fixture`.
///
/// ⚠️ **Fields are parsed with typed cheatcodes, not `abi.decode` of a struct.**
/// `vm.parseJson` *infers* Solidity types from JSON, and it infers a 66-char
/// hex string as `bytes32` — a fixed-size type that ABI-decodes incompatibly
/// with dynamic `bytes`. Our message is exactly 32 bytes, so the struct form
/// reverts here while working fine for the ACVP fixtures, whose messages are
/// all longer. The failure is an opaque `EvmError: Revert` inside `abi.decode`
/// with nothing pointing at the cause. `vm.parseJsonBytes` states the type
/// instead of inferring it, so the length of the data cannot change how it is
/// read.
contract InteropTest is Test {
    string internal constant FIXTURE = "test/vectors/rust-interop-mldsa65.json";

    uint256 internal constant BLOCK_GAS_LIMIT = 36_000_000;

    struct Case {
        bytes context;
        bytes message;
        bytes pk;
        bytes signature;
    }

    function _case() internal view returns (Case memory c) {
        string memory raw = vm.readFile(FIXTURE);
        c.context = vm.parseJsonBytes(raw, ".cases[0].context");
        c.message = vm.parseJsonBytes(raw, ".cases[0].message");
        c.pk = vm.parseJsonBytes(raw, ".cases[0].pk");
        c.signature = vm.parseJsonBytes(raw, ".cases[0].signature");

        // The gate is about a specific workload; silently accepting a fixture
        // of some other shape would let it keep passing while measuring
        // something else.
        assertEq(c.signature.length, 3309, "not an ML-DSA-65 signature");
        assertEq(c.context.length, 0, "the gate's workload has an empty context");
    }

    function test_OurOwnSignatureVerifiesOnChain() public {
        Case memory c = _case();
        MLDSA65Verifier v = new MLDSA65Verifier();

        bytes memory keyPtr = v.setKey(c.pk);
        bool ok = v.verify(keyPtr, c.message, c.signature, c.context);

        assertTrue(ok, "the Solidity verifier rejected a signature our own signer produced");
    }

    /// A gate that cannot fail is not a gate. Corrupting one signature byte must
    /// flip the outcome — otherwise the test above could be passing because
    /// `verify` returns true unconditionally.
    function test_ATamperedSignatureIsRejected() public {
        Case memory c = _case();
        MLDSA65Verifier v = new MLDSA65Verifier();

        // Flip a bit in the hint region at the tail rather than in `cTilde`: a
        // corrupted challenge hash can be caught by the cheap early comparison,
        // which would not exercise the lattice arithmetic this gate is about.
        c.signature[c.signature.length - 1] ^= 0x01;

        bytes memory keyPtr = v.setKey(c.pk);
        bool ok = v.verify(keyPtr, c.message, c.signature, c.context);

        assertFalse(ok, "a tampered signature verified; the gate above proves nothing");
    }

    /// ⭐ **The reconciliation with upstream's published figure.**
    ///
    /// This fixture's message is 32 bytes with an empty context — upstream
    /// ETHDILITHIUM's benchmark workload exactly. `GasProfile.t.sol` shows
    /// verification cost is linear in message length (~1.9 k gas/byte at level
    /// III), so this is the only measurement of ours directly comparable to
    /// theirs rather than merely adjacent to it.
    ///
    /// ⛔ Still not a paper number. Every published figure comes from AWS
    /// through the results pipeline.
    function test_ShortMessageGasMatchesUpstreamWorkload() public {
        Case memory c = _case();
        MLDSA65Verifier v = new MLDSA65Verifier();
        bytes memory keyPtr = v.setKey(c.pk);

        uint256 before = gasleft();
        bool ok = v.verify(keyPtr, c.message, c.signature, c.context);
        uint256 verifyGas = before - gasleft();
        assertTrue(ok, "profiling an invalid signature would understate the cost");

        console.log("== ML-DSA-65, upstream's benchmark workload ==");
        console.log("  message bytes      ", c.message.length);
        console.log("  context bytes      ", c.context.length);
        console.log("  verify gas         ", verifyGas);
        console.log("  ppm of a 36M block ", (verifyGas * 1_000_000) / BLOCK_GAS_LIMIT);

        assertLt(verifyGas, BLOCK_GAS_LIMIT, "a single verification does not fit in a realistic block");
    }

    /// ⭐ **The other half of the reconciliation: level II at their workload.**
    ///
    /// Upstream publishes 8.1 M for the NIST variant, and our first level-II
    /// measurement was 12 502 346 — a 54% gap over a *vendored* verifier, which
    /// is the kind of discrepancy that quietly invalidates a cost analysis if
    /// left alone.
    ///
    /// This measures their verifier, unmodified, on a signature produced by
    /// their own reference implementation at their own benchmark workload: a
    /// 32-byte message with an empty context. Everything that could differ has
    /// been held equal, so whatever remains is the honest residual rather than
    /// an artefact of comparing two different workloads.
    ///
    /// The fixture is deterministic — `dilithium_py` has a seedable DRBG — so
    /// unlike the liboqs one it regenerates byte-identically.
    function test_UpstreamWorkloadAtLevelTwo() public {
        string memory raw = vm.readFile("test/vectors/mldsa44-upstream-workload.json");
        bytes memory ctx = vm.parseJsonBytes(raw, ".cases[0].context");
        bytes memory msg_ = vm.parseJsonBytes(raw, ".cases[0].message");
        bytes memory pk = vm.parseJsonBytes(raw, ".cases[0].pk");
        bytes memory sig = vm.parseJsonBytes(raw, ".cases[0].signature");

        assertEq(msg_.length, 32, "not upstream's benchmark workload");
        assertEq(ctx.length, 0, "not upstream's benchmark workload");
        assertEq(sig.length, 2420, "not an ML-DSA-44 signature");

        ZKNOX_dilithium v = new ZKNOX_dilithium();
        bytes memory keyPtr = v.setKey(pk);

        uint256 before = gasleft();
        bool ok = v.verify(keyPtr, msg_, sig, ctx);
        uint256 verifyGas = before - gasleft();

        assertTrue(ok, "the upstream verifier rejected its own reference implementation's signature");

        console.log("== ML-DSA-44 (upstream verifier, upstream workload) ==");
        console.log("  verify gas                 ", verifyGas);
        console.log("  upstream README publishes   8100000");
    }
}
