// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {MLDSA65Verifier} from "../src/mldsa65/MLDSA65.sol";

/// @title A Rust-signed court order, checked against the ML-DSA-65 verifier
/// @notice The fixture is an order our Rust signer issued
/// (`cargo run -p pqcl-interop --bin redaction-order`).
///
/// ⚠️ **Since D4 (2026-10-06) the anchor no longer verifies orders**: only the
/// order's digest goes on chain (`Anchor.t.sol`), and the AIS and auditors
/// verify `σ_CO` under the court key off chain. What stays true, and is still
/// pinned here, is the cross-language encoding (`Order::message` is
/// `abi.encodePacked` of the six fields) and that the court signature binds
/// every one of them: the §1u.3 property that `mode` and `exp` are signed.
contract RedactionTest is Test {
    MLDSA65Verifier internal verifier;
    bytes internal courtKey;

    bytes32 internal oid;
    bytes32 internal tgt;
    uint8 internal scope;
    uint8 internal mode;
    uint64 internal ts;
    uint64 internal exp;
    bytes internal message;
    bytes internal sig;

    function setUp() public {
        string memory raw = vm.readFile("test/vectors/redaction-order-mldsa65.json");
        oid = vm.parseJsonBytes32(raw, ".orderId");
        tgt = vm.parseJsonBytes32(raw, ".target");
        scope = uint8(vm.parseJsonUint(raw, ".scope"));
        mode = uint8(vm.parseJsonUint(raw, ".mode"));
        ts = uint64(vm.parseJsonUint(raw, ".ts"));
        exp = uint64(vm.parseJsonUint(raw, ".exp"));
        message = vm.parseJsonBytes(raw, ".message");
        sig = vm.parseJsonBytes(raw, ".signature");

        verifier = new MLDSA65Verifier();
        courtKey = verifier.setKey(vm.parseJsonBytes(raw, ".pk"));
    }

    function _verifies(bytes32 o, bytes32 t, uint8 sc, uint8 m, uint64 a, uint64 b) internal view returns (bool) {
        return verifier.verify(courtKey, abi.encodePacked(o, t, sc, m, a, b), sig, "");
    }

    /// The Rust encoding (`Order::message`) is `abi.encodePacked` of the six
    /// fields. If this fails, the two sides sign different bytes.
    function test_RustMessageIsAbiEncodePacked() public view {
        assertEq(abi.encodePacked(oid, tgt, scope, mode, ts, exp), message);
        assertEq(message.length, 82);
    }

    function test_TheGenuineOrderVerifies() public view {
        assertTrue(_verifies(oid, tgt, scope, mode, ts, exp));
    }

    /// ⭐ §1u.3: `ERASED` relayed as `SEALED` does not verify.
    function test_AFlippedModeDoesNotVerify() public view {
        assertFalse(_verifies(oid, tgt, scope, mode == 2 ? 1 : 2, ts, exp));
    }

    /// ⭐ §1u.3: an extended expiry does not verify.
    function test_AFlippedExpDoesNotVerify() public view {
        assertFalse(_verifies(oid, tgt, scope, mode, ts, exp + 1));
    }

    function test_AFlippedScopeTsOrTargetDoesNotVerify() public view {
        assertFalse(_verifies(oid, tgt, scope == 3 ? 1 : 3, mode, ts, exp));
        assertFalse(_verifies(oid, tgt, scope, mode, ts - 1, exp));
        assertFalse(_verifies(oid, keccak256("another target"), scope, mode, ts, exp));
    }
}
