// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {BDems} from "../src/BDems.sol";

/// @title B-DEMS as ported: registration, sharing and destruction
/// @notice Every signature check the paper's transactions carry is exercised
/// with a forged signer as well as an honest one, so a check that cannot fail
/// would show here.
contract BDemsTest is Test {
    BDems internal b;
    uint256 internal senderKey = 0xA11CE;
    uint256 internal providerKey = 0xB0B;
    uint256 internal courtKey = 0xC0C;
    uint256 internal receiverKey = 0xD0D;
    uint256 internal outsiderKey = 0xE0E;
    address internal sender;
    address internal provider;
    address internal court;
    address internal receiver;
    address internal outsider;
    bytes32 internal eid = keccak256("evidence 1");
    bytes32 internal meta = keccak256("meta");
    bytes32 internal hEnc = sha256("ciphertext");

    function setUp() public {
        sender = vm.addr(senderKey);
        provider = vm.addr(providerKey);
        court = vm.addr(courtKey);
        receiver = vm.addr(receiverKey);
        outsider = vm.addr(outsiderKey);
        b = new BDems();
        b.grantSender(sender);
        b.grantSender(receiver);
        b.grantCourt(court);
    }

    function _sig(uint256 key, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, d);
        return abi.encodePacked(r, s, v);
    }

    function _register(bytes32 id, bool voluntary) internal {
        bytes32 d = b.txaDigest(id, meta, provider, voluntary, sender);
        bytes memory sigs = abi.encodePacked(_sig(senderKey, d), _sig(voluntary ? providerKey : courtKey, d));
        vm.prank(sender);
        b.registerEvidence(id, meta, provider, voluntary, sigs);
    }

    function _approve(bytes32 id) internal {
        bytes32 policy = keccak256("policy");
        bytes memory sig = _sig(courtKey, b.txbDigest(id, policy));
        vm.prank(court);
        b.approveRegistration(id, policy, sig);
    }

    function _complete(bytes32 id) internal {
        vm.prank(sender);
        b.completeRegistration(id, hEnc);
    }

    function _request(bytes32 id, bytes32 purpose) internal returns (bytes32 ref) {
        vm.prank(receiver);
        ref = b.requestShare(id, purpose);
    }

    function _destroy(bytes32 id) internal returns (bytes32 conf) {
        vm.prank(sender);
        b.requestDestruction(id, "court-ordered destruction", 1_700_000_000);
        bytes32 txe = b.txeDigest(id, sender, "court-ordered destruction", 1_700_000_000);
        conf = sha256(abi.encodePacked(txe, hEnc));
        vm.prank(sender);
        b.confirmDestruction(id, conf);
    }

    // ------------------------------------------------------------ TxA, TxB

    function test_registration_takes_sender_and_provider_when_voluntary() public {
        _register(eid, true);
        _approve(eid);
        _complete(eid);
    }

    function test_registration_takes_sender_and_court_when_compulsory() public {
        _register(eid, false);
    }

    function test_txa_refuses_a_forged_second_signature() public {
        bytes32 d = b.txaDigest(eid, meta, provider, true, sender);
        bytes memory sigs = abi.encodePacked(_sig(senderKey, d), _sig(outsiderKey, d));
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(BDems.BadSigner.selector, 1, outsider));
        b.registerEvidence(eid, meta, provider, true, sigs);
    }

    function test_txa_refuses_a_signature_not_the_senders() public {
        bytes32 d = b.txaDigest(eid, meta, provider, false, sender);
        bytes memory sigs = abi.encodePacked(_sig(outsiderKey, d), _sig(courtKey, d));
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(BDems.BadSigner.selector, 0, outsider));
        b.registerEvidence(eid, meta, provider, false, sigs);
    }

    function test_txa_refuses_fewer_than_the_threshold() public {
        bytes32 d = b.txaDigest(eid, meta, provider, true, sender);
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(BDems.BadSignatures.selector, 65));
        b.registerEvidence(eid, meta, provider, true, _sig(senderKey, d));
    }

    function test_a_duplicate_identifier_is_refused() public {
        _register(eid, true);
        bytes32 d = b.txaDigest(eid, meta, provider, true, sender);
        bytes memory sigs = abi.encodePacked(_sig(senderKey, d), _sig(providerKey, d));
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(BDems.AlreadyRegistered.selector, eid));
        b.registerEvidence(eid, meta, provider, true, sigs);
    }

    function test_only_a_whitelisted_sender_registers() public {
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(BDems.NotSender.selector, outsider));
        b.registerEvidence(eid, meta, provider, true, "");
    }

    function test_txb_refuses_a_non_court_signature() public {
        _register(eid, true);
        bytes32 policy = keccak256("policy");
        bytes memory sig = _sig(outsiderKey, b.txbDigest(eid, policy));
        vm.expectRevert(abi.encodeWithSelector(BDems.BadSigner.selector, 0, outsider));
        b.approveRegistration(eid, policy, sig);
    }

    function test_only_the_registering_sender_completes() public {
        _register(eid, true);
        vm.prank(receiver);
        vm.expectRevert(abi.encodeWithSelector(BDems.NotRegisteringSender.selector, eid, receiver));
        b.completeRegistration(eid, hEnc);
    }

    // ------------------------------------------------------------ TxC, TxD

    function test_sharing_needs_txc_then_the_senders_and_providers_txd() public {
        _register(eid, true);
        _approve(eid);
        bytes32 ref = _request(eid, keccak256("purpose 1"));
        assertEq(ref, b.txcDigest(eid, keccak256("purpose 1"), receiver));
        assertEq(b.shareStatus(ref), 1);
        bytes32 d = b.txdDigest(ref);
        bytes memory sigs = abi.encodePacked(_sig(senderKey, d), _sig(providerKey, d));
        vm.prank(sender);
        b.approveShare(ref, sigs);
        assertEq(b.shareStatus(ref), 2);
    }

    function test_a_compulsory_item_shares_on_the_senders_signature_alone() public {
        _register(eid, false);
        _approve(eid);
        bytes32 ref = _request(eid, keccak256("p"));
        bytes memory sig = _sig(senderKey, b.txdDigest(ref));
        vm.prank(sender);
        b.approveShare(ref, sig);
        assertEq(b.shareStatus(ref), 2);
    }

    function test_txd_refuses_a_missing_provider_signature() public {
        _register(eid, true);
        _approve(eid);
        bytes32 ref = _request(eid, keccak256("p"));
        bytes memory sig = _sig(senderKey, b.txdDigest(ref));
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(BDems.BadSignatures.selector, 65));
        b.approveShare(ref, sig);
    }

    function test_txd_refuses_before_the_courts_approval() public {
        _register(eid, false);
        bytes32 ref = _request(eid, keccak256("p"));
        bytes memory sig = _sig(senderKey, b.txdDigest(ref));
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(BDems.NotApproved.selector, eid));
        b.approveShare(ref, sig);
    }

    function test_txd_refuses_a_reference_to_no_pending_txc() public {
        bytes32 ref = keccak256("no such TxC");
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(BDems.NotPending.selector, ref));
        b.approveShare(ref, "");
    }

    function test_an_outsider_cannot_request_a_share() public {
        _register(eid, false);
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(BDems.NotSender.selector, outsider));
        b.requestShare(eid, keccak256("p"));
    }

    // ------------------------------------------------------------- TxE

    function test_destruction_is_recorded_and_its_hash_matches() public {
        _register(eid, true);
        _complete(eid);
        bytes32 conf = _destroy(eid);
        (address s, string memory reason, uint64 ts, bytes32 c, bool destroyed, bytes32 h) = b.destructionOf(eid);
        assertEq(s, sender);
        assertEq(reason, "court-ordered destruction");
        assertEq(ts, 1_700_000_000);
        assertEq(c, conf);
        assertTrue(destroyed);
        assertEq(sha256(abi.encodePacked(b.txeDigest(eid, s, reason, ts), h)), c);
    }

    function test_only_a_whitelisted_sender_requests_destruction() public {
        _register(eid, true);
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(BDems.NotSender.selector, outsider));
        b.requestDestruction(eid, "r", 1);
    }

    function test_only_the_requesting_sender_confirms() public {
        _register(eid, true);
        vm.prank(sender);
        b.requestDestruction(eid, "r", 1);
        vm.prank(receiver);
        vm.expectRevert(abi.encodeWithSelector(BDems.NotRequester.selector, eid, receiver));
        b.confirmDestruction(eid, bytes32(uint256(1)));
    }

    function test_a_second_txe_for_one_item_is_refused() public {
        _register(eid, true);
        _complete(eid);
        _destroy(eid);
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(BDems.AlreadyRequested.selector, eid));
        b.requestDestruction(eid, "a different reason", 2);
    }

    function test_an_unregistered_item_cannot_be_destroyed() public {
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(BDems.NotRegistered.selector, keccak256("x")));
        b.requestDestruction(keccak256("x"), "r", 1);
    }

    function test_no_txe_reads_as_the_zero_sender() public view {
        (address s,,,, bool destroyed,) = b.destructionOf(keccak256("never"));
        assertEq(s, address(0));
        assertFalse(destroyed);
    }
}
