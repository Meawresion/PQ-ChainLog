// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {PqablAnchor} from "../src/PqablAnchor.sol";

/// @title PQ-ABL's epoch commitment as ported: append-only, latest wins
contract PqablAnchorTest is Test {
    PqablAnchor internal a;
    address internal logger = address(0x10);

    function setUp() public {
        a = new PqablAnchor(logger);
    }

    function test_a_recommit_supersedes_and_keeps_the_original() public {
        vm.startPrank(logger);
        a.commit(3, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)));
        a.commit(3, bytes32(uint256(4)), bytes32(uint256(5)), bytes32(uint256(6)));
        vm.stopPrank();
        assertEq(a.anchorCount(3), 2);
        (bytes32 r,,,) = a.getAnchorData(3);
        assertEq(r, bytes32(uint256(4)));
        (bytes32 r0, bytes32 c0,,) = a.anchorAt(3, 0);
        assertEq(r0, bytes32(uint256(1)));
        assertEq(c0, bytes32(uint256(2)));
    }

    function test_only_the_logger_commits() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(PqablAnchor.NotLogger.selector, address(0xBAD)));
        a.commit(0, bytes32(0), bytes32(0), bytes32(0));
    }

    function test_an_epoch_never_committed_has_no_anchor_data() public {
        vm.expectRevert(abi.encodeWithSelector(PqablAnchor.NoAnchor.selector, uint64(9)));
        a.getAnchorData(9);
        assertEq(a.anchorCount(9), 0);
    }
}
