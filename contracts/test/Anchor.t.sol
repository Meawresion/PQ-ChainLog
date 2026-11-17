// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Anchor} from "../src/Anchor.sol";

/// @title The anchor as a registry (draft8 Phase 1 Step 3, Phase 7 Steps 3–4,
/// Phase 11 Step 1; user decision D4)
/// @notice M7's acceptance criteria that survive D4 and M13 A21, made
/// executable: the checkpoint link, single-spend nullifiers, and the **absence**
/// of a leaf count.
///
/// ⚠️ **Moved off chain by D4:** "a redaction order signed with the warrant key
/// is rejected" and "an anchor signed with the wrong key is rejected". No
/// signature goes on chain any more; the AIS and auditors verify `σ_CO` under
/// the court key (`pqcl-pipeline`'s redaction tests) and the approval set under
/// the registered custodian keys (`pqcl-pipeline::checkpoint`).
contract AnchorTest is Test {
    bytes32 internal constant CASE_A = keccak256("cid:case-A");
    bytes32 internal constant REG_A = keccak256("reg:case-A");
    bytes32 internal constant ROOT_1 = keccak256("R_e:1");
    bytes32 internal constant ROOT_2 = keccak256("R_e:2");
    bytes32 internal constant D_1 = keccak256("d_1");
    bytes32 internal constant D_2 = keccak256("d_2");
    bytes32 internal constant A_E = keccak256("A_e");

    function _registered() internal returns (Anchor a) {
        a = new Anchor();
        a.registerCase(CASE_A, REG_A);
    }

    // ------------------------------------------------------ registration

    function test_ACaseRegistersOnce() public {
        Anchor a = _registered();
        assertEq(a.registration(CASE_A), REG_A);
        vm.expectRevert(abi.encodeWithSelector(Anchor.CaseAlreadyRegistered.selector, CASE_A));
        a.registerCase(CASE_A, keccak256("another reg"));
    }

    function test_AnUnregisteredCaseCannotAnchor() public {
        Anchor a = new Anchor();
        vm.expectRevert(abi.encodeWithSelector(Anchor.CaseNotRegistered.selector, CASE_A));
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
    }

    // ------------------------------------------------------ the checkpoint link

    /// ⭐ The first checkpoint must name `reg` as its predecessor.
    function test_TheFirstCheckpointExtendsTheRegistration() public {
        Anchor a = _registered();
        vm.expectRevert(abi.encodeWithSelector(Anchor.CheckpointNotLinked.selector, REG_A, D_1));
        a.commitRoot(CASE_A, ROOT_1, D_1, D_2, A_E);
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
        assertEq(a.latestEpoch(CASE_A).checkpoint, D_1);
    }

    /// ⭐ Each later checkpoint must extend the last: two histories of the same
    /// length cannot both extend one chain.
    function test_ACheckpointMustExtendTheLastOne() public {
        Anchor a = _registered();
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
        bytes32 fork = keccak256("a forked predecessor");
        vm.expectRevert(abi.encodeWithSelector(Anchor.CheckpointNotLinked.selector, D_1, fork));
        a.commitRoot(CASE_A, ROOT_2, fork, D_2, A_E);
        a.commitRoot(CASE_A, ROOT_2, D_1, D_2, A_E);
        Anchor.Epoch memory e = a.latestEpoch(CASE_A);
        assertEq(e.root, ROOT_2);
        assertEq(e.checkpoint, D_2);
        assertEq(e.approval, A_E);
    }

    // ------------------------------------------- no leaf count (M13 A21)

    /// ⭐ **Acceptance A21 (a): no count is stored, checked or emitted.**
    ///
    /// Asserted against the **ABI**, not by reading the source: the event's
    /// non-indexed data is exactly `(root, anchoredAt, checkpoint, approval)`,
    /// and `Epoch` is exactly those four fields. A count reintroduced anywhere
    /// in either makes this fail.
    function test_NoLeafCountIsStoredOrEmitted() public {
        Anchor a = _registered();
        vm.roll(99);
        vm.recordLogs();
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        // topic0 plus the indexed cid; everything else is in `data`.
        assertEq(logs[0].topics.length, 2);
        assertEq(logs[0].data.length, 4 * 32, "RootCommitted carries a fifth word");
        (bytes32 root, uint64 at, bytes32 dE, bytes32 aE) =
            abi.decode(logs[0].data, (bytes32, uint64, bytes32, bytes32));
        assertEq(root, ROOT_1);
        assertEq(at, 99);
        assertEq(dE, D_1);
        assertEq(aE, A_E);
        assertEq(abi.encode(a.latestEpoch(CASE_A)).length, 4 * 32, "Epoch carries a fifth field");
    }

    /// ⭐ Acceptance A21 (a): a stale predecessor and a fork both revert — the
    /// link is doing the whole job the count used to look like it was doing.
    function test_AStalePredecessorAndAForkBothRevert() public {
        Anchor a = _registered();
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
        a.commitRoot(CASE_A, ROOT_2, D_1, D_2, A_E);
        // Stale: `reg` was consumed by the first epoch.
        vm.expectRevert(abi.encodeWithSelector(Anchor.CheckpointNotLinked.selector, D_2, REG_A));
        a.commitRoot(CASE_A, ROOT_1, REG_A, keccak256("d_1'"), A_E);
        // Fork: a second epoch 2 extending epoch 1, which is no longer the head.
        vm.expectRevert(abi.encodeWithSelector(Anchor.CheckpointNotLinked.selector, D_2, D_1));
        a.commitRoot(CASE_A, ROOT_2, D_1, keccak256("d_2'"), A_E);
    }

    /// ⭐ Acceptance A21 (c), the on-chain half: a small case and a large one
    /// produce **identical-shaped** anchors. Nothing in the call or the event
    /// scales with how much the epoch held.
    function test_TwoCasesOfDifferentSizeAnchorIdenticalShapes() public {
        Anchor a = _registered();
        bytes32 caseB = keccak256("cid:case-B");
        bytes32 regB = keccak256("reg:case-B");
        a.registerCase(caseB, regB);
        bytes memory small = abi.encodeCall(Anchor.commitRoot, (CASE_A, ROOT_1, REG_A, D_1, A_E));
        bytes memory large = abi.encodeCall(Anchor.commitRoot, (caseB, ROOT_2, regB, D_2, A_E));
        assertEq(small.length, large.length);

        vm.recordLogs();
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
        a.commitRoot(caseB, ROOT_2, regB, D_2, A_E);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2);
        assertEq(logs[0].data.length, logs[1].data.length);
        assertEq(logs[0].topics.length, logs[1].topics.length);
    }

    function test_TheLinkIsPerCase() public {
        Anchor a = _registered();
        bytes32 caseB = keccak256("cid:case-B");
        a.registerCase(caseB, keccak256("reg:case-B"));
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
        a.commitRoot(caseB, ROOT_1, keccak256("reg:case-B"), D_1, A_E);
        assertEq(a.latestEpoch(caseB).checkpoint, D_1);
    }

    function test_EmptyRootOrDigestIsRejected() public {
        Anchor a = _registered();
        vm.expectRevert(Anchor.EmptyRoot.selector);
        a.commitRoot(CASE_A, bytes32(0), REG_A, D_1, A_E);
        vm.expectRevert(Anchor.EmptyDigest.selector);
        a.commitRoot(CASE_A, ROOT_1, REG_A, bytes32(0), A_E);
        vm.expectRevert(Anchor.EmptyDigest.selector);
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, bytes32(0));
    }

    /// ⭐ D4: the anchor carries no signature, so its calldata is fixed — and
    /// since A21 it is one word shorter: a selector and five 32-byte words,
    /// whatever the signature scheme and whatever the epoch held.
    function test_TheAnchorCarriesNoSignature() public pure {
        bytes memory call = abi.encodeCall(Anchor.commitRoot, (CASE_A, ROOT_1, REG_A, D_1, A_E));
        assertEq(call.length, 4 + 5 * 32);
    }

    function test_AnchorRecordsTheBlockItLandedIn() public {
        Anchor a = _registered();
        vm.roll(1234);
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
        assertEq(a.latestEpoch(CASE_A).anchoredAt, 1234);
    }

    function test_UnknownCaseReverts() public {
        Anchor a = new Anchor();
        vm.expectRevert(abi.encodeWithSelector(Anchor.UnknownEpoch.selector, CASE_A));
        a.latestEpoch(CASE_A);
    }

    // ------------------------------------------------------ redaction orders

    /// Phase 11 Step 1: the order's digest is recorded before anything is
    /// deleted, once.
    function test_AnOrderDigestIsRecordedOnce() public {
        Anchor a = _registered();
        bytes32 oid = keccak256("order-1");
        bytes32 digest = keccak256("0x05 leaf digest");
        vm.expectEmit(true, true, false, true);
        emit Anchor.RedactionOrdered(CASE_A, oid, digest);
        a.orderRedaction(CASE_A, oid, digest);
        assertEq(a.recordedOrder(CASE_A, oid), digest);
        vm.expectRevert(abi.encodeWithSelector(Anchor.RedactionOrderAlreadyRecorded.selector, oid));
        a.orderRedaction(CASE_A, oid, keccak256("a different order under the same id"));
        vm.expectRevert(Anchor.EmptyDigest.selector);
        a.orderRedaction(CASE_A, keccak256("order-2"), bytes32(0));
    }

    // ------------------------------------------------------ caller binding (M13 A16)

    address constant STRANGER = address(0xBAD);

    /// ⭐ **Acceptance A16: a third-party `commitRoot` reverts.** Before A16 a
    /// stranger could extend a case's chain with a junk checkpoint, and the
    /// honest AIS's next anchor then failed to link: integrity held, liveness
    /// did not (`audit/06` W18, K11).
    function test_AStrangerCannotExtendACasesChain() public {
        Anchor a = _registered();
        assertEq(a.anchorer(CASE_A), address(this), "registration records its sender");
        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(Anchor.NotCaseAnchorer.selector, CASE_A, STRANGER));
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
        // And the honest flow is untouched: the chain still links from reg.
        a.commitRoot(CASE_A, ROOT_1, REG_A, D_1, A_E);
        a.commitRoot(CASE_A, ROOT_2, D_1, D_2, A_E);
        assertEq(a.latestEpoch(CASE_A).checkpoint, D_2);
    }

    /// The same for orders: a stranger cannot record — or pre-empt — an order
    /// in a case, and one case's anchorer cannot squat on another's order id.
    function test_OrdersAreBoundToTheirCaseAndItsAnchorer() public {
        Anchor a = _registered();
        bytes32 oid = keccak256("order-1");
        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(Anchor.NotCaseAnchorer.selector, CASE_A, STRANGER));
        a.orderRedaction(CASE_A, oid, keccak256("junk"));

        // A stranger registers a case of its own and records the same id there.
        bytes32 caseB = keccak256("case-B");
        vm.prank(STRANGER);
        a.registerCase(caseB, keccak256("reg:case-B"));
        vm.prank(STRANGER);
        a.orderRedaction(caseB, oid, keccak256("junk"));

        // The honest order in case A is unaffected.
        bytes32 digest = keccak256("0x05 leaf digest");
        a.orderRedaction(CASE_A, oid, digest);
        assertEq(a.recordedOrder(CASE_A, oid), digest);
        assertEq(a.recordedOrder(caseB, oid), keccak256("junk"));
    }

    function test_AnUnregisteredCaseTakesNoOrder() public {
        Anchor a = new Anchor();
        vm.expectRevert(abi.encodeWithSelector(Anchor.CaseNotRegistered.selector, CASE_A));
        a.orderRedaction(CASE_A, keccak256("order-1"), keccak256("d"));
    }

    // ------------------------------------------------------ nullifiers

    /// ⭐ Acceptance: a replayed nullifier is rejected.
    function test_ANullifierCannotBeSpentTwice() public {
        Anchor a = new Anchor();
        bytes32 n = keccak256("N:epoch-7");
        a.authoriseSearch(n, keccak256("scope"));
        assertTrue(a.nullifierSpent(n));
        vm.expectRevert(abi.encodeWithSelector(Anchor.NullifierAlreadySpent.selector, n));
        a.authoriseSearch(n, keccak256("scope"));
    }

    /// Rejection must not depend on *who* replays it.
    function test_ANullifierCannotBeReplayedByAnotherSender() public {
        Anchor a = new Anchor();
        bytes32 n = keccak256("N:epoch-8");
        vm.prank(address(0xA11CE));
        a.authoriseSearch(n, keccak256("scope"));
        vm.prank(address(0xB0B));
        vm.expectRevert(abi.encodeWithSelector(Anchor.NullifierAlreadySpent.selector, n));
        a.authoriseSearch(n, keccak256("scope"));
    }

    /// Distinct nullifiers are independent: single-use per epoch.
    function test_DistinctNullifiersAreIndependent() public {
        Anchor a = new Anchor();
        a.authoriseSearch(keccak256("N:epoch-7"), keccak256("scope"));
        a.authoriseSearch(keccak256("N:epoch-8"), keccak256("scope"));
    }
}
