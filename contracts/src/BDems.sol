// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title B-DEMS (Park & Jeong, IP&M 63, 2026, art. 104654), ported
/// @notice SAC's B-DEMS comparator on our Besu network, the same substitution
/// LEChain's contract runs under (`baselines/UPGRADES.md`, "B-DEMS"). Exp. 1
/// drives its whole custody workflow, Exp. 4 its destruction.
///
/// # The transactions, as the paper fixes them
///
/// * **TxA** (Alg. 1 Step 1, §3.2.1): `(H, M, P, A)` with `H = SHA-256(E)` the
///   evidence identifier. ECDSA signatures of the participants, and a
///   threshold of them reached off chain with Shamir's scheme: Provider and
///   Sender for a voluntary submission, Sender and Court for a compulsory
///   seizure. The contract checks the threshold-many signatures by
///   `ecrecover` ([`THRESHOLD`]).
/// * **TxB** (Alg. 1 Step 2, §3.2.2): the Court's access policy, under the
///   Court's signature.
/// * **TxA.Completed** (§3.2.3): after encryption, the Sender records `H(E′)`.
/// * **TxC** (Alg. 2 Step 1, §3.3.1): `(EvidenceID, Purpose, ReceiverAddr,
///   pending)`, submitted by a whitelisted Receiver; one per request.
/// * **TxD** (Alg. 2 Steps 3–4): references `keccak256(TxC)`, carries the
///   Sender's signature, and the Provider's too for a voluntary submission;
///   the contract checks the reference, that TxC is pending, and the
///   signatures, then marks it approved and emits `KeyDecryptionApproved`.
/// * **TxE** (Alg. 3, Fig. 4): `(EvidenceID, SenderAddr, Reason, Timestamp)`,
///   one per item, by a whitelisted Sender. **No court-signed order**:
///   authority is the enrolled role.
/// * **The destruction confirmation hash** is "generated from the deletion
///   process and recorded in the blockchain" (§3.4.1, Alg. 3 lines 8–9) with
///   no construction given. We fix it as `SHA-256(keccak256(TxE) ‖ H(E′))`,
///   written by the TxE's Sender in a second transaction, which also sets the
///   status to "destroyed" (Alg. 3 lines 18–19).
///
/// Every digest a signature covers is a pure function here, so a test, the
/// harness and a court compute it the same way.
///
/// Left out: TxF (admissibility record, outside both experiments), the pause
/// switch, and per-jurisdiction whitelists (one jurisdiction).
contract BDems {
    // ------------------------------------------------------------- constants

    /// Signatures TxA must carry: the Shamir threshold, reached off chain.
    uint256 public constant THRESHOLD = 2;

    bytes32 internal constant TAG_A = keccak256("B-DEMS TxA");
    bytes32 internal constant TAG_B = keccak256("B-DEMS TxB");
    bytes32 internal constant TAG_C = keccak256("B-DEMS TxC");
    bytes32 internal constant TAG_D = keccak256("B-DEMS TxD");

    // ----------------------------------------------------------------- state

    /// The governance account: grants roles.
    address public immutable admin;

    /// The whitelist of investigative agencies: Senders and Receivers.
    mapping(address => bool) public isSender;

    /// The Courts.
    mapping(address => bool) public isCourt;

    /// TxA, with what TxB and TxA.Completed add.
    struct Evidence {
        bytes32 meta; // H(M)
        bytes32 policy; // TxB's access policy
        bytes32 hEnc; // H(E′), from TxA.Completed
        address sender; // A
        bool voluntary; // the collection method
        bool approved; // TxB recorded
        bool completed; // TxA.Completed
        address provider; // P
    }

    /// TxC and its status.
    struct Share {
        bytes32 eid;
        address receiver;
        uint8 status; // 0 none, 1 pending, 2 approved
    }

    /// TxE (Fig. 4) and its confirmation.
    struct Destruction {
        address sender; // SenderAddr
        uint64 timestamp; // Timestamp, time of request
        bool destroyed; // status "destroyed" (Alg. 3 line 19)
        bytes32 confirmation; // the destruction confirmation hash
        string reason; // Reason for disposal
    }

    mapping(bytes32 => Evidence) private _evidence;
    mapping(bytes32 => Share) private _share;
    mapping(bytes32 => Destruction) private _destruction;

    // ---------------------------------------------------------------- events

    event EvidenceRegistered(bytes32 indexed eid, address indexed sender, address provider, bool voluntary);
    event RegistrationApproved(bytes32 indexed eid, address indexed court, bytes32 policy);
    event RegistrationCompleted(bytes32 indexed eid, bytes32 hEnc);
    event ShareRequested(bytes32 indexed ref, bytes32 indexed eid, address indexed receiver, bytes32 purpose);
    event KeyDecryptionApproved(bytes32 indexed ref, bytes32 indexed eid, address indexed receiver);
    event DestructionRequested(bytes32 indexed eid, address indexed sender, string reason, uint64 timestamp);
    event DestructionConfirmed(bytes32 indexed eid, bytes32 confirmation);

    // ---------------------------------------------------------------- errors

    error NotAdmin(address caller);
    error NotSender(address caller);
    error NotRegisteringSender(bytes32 eid, address caller);
    error BadSignatures(uint256 given);
    error BadSigner(uint256 index, address signer);
    error AlreadyRegistered(bytes32 eid);
    error NotRegistered(bytes32 eid);
    error AlreadyApproved(bytes32 eid);
    error AlreadyCompleted(bytes32 eid);
    error NotApproved(bytes32 eid);
    error AlreadyShared(bytes32 ref);
    error NotPending(bytes32 ref);
    error AlreadyRequested(bytes32 eid);
    error NotRequested(bytes32 eid);
    error NotRequester(bytes32 eid, address caller);
    error AlreadyDestroyed(bytes32 eid);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin(msg.sender);
        _;
    }

    modifier onlySender() {
        if (!isSender[msg.sender]) revert NotSender(msg.sender);
        _;
    }

    /// Governance: put an agency on the whitelist.
    function grantSender(address agency) external onlyAdmin {
        isSender[agency] = true;
    }

    /// Governance: enrol a Court.
    function grantCourt(address court) external onlyAdmin {
        isCourt[court] = true;
    }

    // ---------------------------------------------------- signature digests

    /// What TxA's participants sign.
    function txaDigest(bytes32 eid, bytes32 meta, address provider, bool voluntary, address sender)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(TAG_A, eid, meta, provider, voluntary, sender));
    }

    /// What the Court signs in TxB.
    function txbDigest(bytes32 eid, bytes32 policy) public pure returns (bytes32) {
        return keccak256(abi.encode(TAG_B, eid, policy));
    }

    /// `keccak256(TxC)`: the reference TxD must carry.
    function txcDigest(bytes32 eid, bytes32 purpose, address receiver) public pure returns (bytes32) {
        return keccak256(abi.encode(TAG_C, eid, purpose, receiver));
    }

    /// What TxD's signers sign.
    function txdDigest(bytes32 ref) public pure returns (bytes32) {
        return keccak256(abi.encode(TAG_D, ref));
    }

    /// `keccak256(TxE)`, the TxE digest the confirmation hash binds:
    /// `keccak256(abi.encode(eid, sender, keccak256(reason), timestamp))`.
    function txeDigest(bytes32 eid, address sender, string calldata reason, uint64 timestamp)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(eid, sender, keccak256(bytes(reason)), timestamp));
    }

    /// The signer of the `i`-th 65-byte `r ‖ s ‖ v` signature in `sigs`.
    function _signer(bytes32 digest, bytes calldata sigs, uint256 i) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            let p := add(sigs.offset, mul(i, 65))
            r := calldataload(p)
            s := calldataload(add(p, 32))
            v := byte(0, calldataload(add(p, 64)))
        }
        return ecrecover(digest, v, r, s);
    }

    // ------------------------------------------------------------ registration

    /// TxA. `sigs` is the threshold: the Sender's signature, then the
    /// Provider's (voluntary) or a Court's (compulsory). Identifier
    /// duplication is refused (§4.3).
    function registerEvidence(bytes32 eid, bytes32 meta, address provider, bool voluntary, bytes calldata sigs)
        external
        onlySender
    {
        if (_evidence[eid].sender != address(0)) revert AlreadyRegistered(eid);
        if (sigs.length != 65 * THRESHOLD) revert BadSignatures(sigs.length);
        bytes32 d = txaDigest(eid, meta, provider, voluntary, msg.sender);
        address a = _signer(d, sigs, 0);
        if (a != msg.sender) revert BadSigner(0, a);
        address b = _signer(d, sigs, 1);
        if (voluntary ? b != provider : !isCourt[b]) revert BadSigner(1, b);
        _evidence[eid] = Evidence({
            meta: meta,
            policy: 0,
            hEnc: 0,
            sender: msg.sender,
            voluntary: voluntary,
            approved: false,
            completed: false,
            provider: provider
        });
        emit EvidenceRegistered(eid, msg.sender, provider, voluntary);
    }

    /// TxB: the Court's access policy over a registered item.
    function approveRegistration(bytes32 eid, bytes32 policy, bytes calldata sig) external {
        Evidence storage e = _evidence[eid];
        if (e.sender == address(0)) revert NotRegistered(eid);
        if (e.approved) revert AlreadyApproved(eid);
        if (sig.length != 65) revert BadSignatures(sig.length);
        address c = _signer(txbDigest(eid, policy), sig, 0);
        if (!isCourt[c]) revert BadSigner(0, c);
        e.policy = policy;
        e.approved = true;
        emit RegistrationApproved(eid, c, policy);
    }

    /// TxA.Completed: the registering Sender records `H(E′)` once the evidence
    /// is stored encrypted.
    function completeRegistration(bytes32 eid, bytes32 hEnc) external {
        Evidence storage e = _evidence[eid];
        if (e.sender == address(0)) revert NotRegistered(eid);
        if (e.sender != msg.sender) revert NotRegisteringSender(eid, msg.sender);
        if (e.completed) revert AlreadyCompleted(eid);
        e.hEnc = hEnc;
        e.completed = true;
        emit RegistrationCompleted(eid, hEnc);
    }

    // ----------------------------------------------------------------- sharing

    /// TxC: a whitelisted Receiver requests one item for one purpose.
    function requestShare(bytes32 eid, bytes32 purpose) external onlySender returns (bytes32 ref) {
        if (_evidence[eid].sender == address(0)) revert NotRegistered(eid);
        ref = txcDigest(eid, purpose, msg.sender);
        if (_share[ref].status != 0) revert AlreadyShared(ref);
        _share[ref] = Share({eid: eid, receiver: msg.sender, status: 1});
        emit ShareRequested(ref, eid, msg.sender, purpose);
    }

    /// TxD: the registering Sender approves TxC `ref`, with the Provider's
    /// signature too for a voluntary submission (Alg. 2 Step 3). The item's
    /// registration must carry the Court's approval (§3.3.2).
    function approveShare(bytes32 ref, bytes calldata sigs) external {
        Share storage sh = _share[ref];
        if (sh.status != 1) revert NotPending(ref);
        Evidence storage e = _evidence[sh.eid];
        if (e.sender != msg.sender) revert NotRegisteringSender(sh.eid, msg.sender);
        if (!e.approved) revert NotApproved(sh.eid);
        uint256 need = e.voluntary ? 2 : 1;
        if (sigs.length != 65 * need) revert BadSignatures(sigs.length);
        bytes32 d = txdDigest(ref);
        address a = _signer(d, sigs, 0);
        if (a != e.sender) revert BadSigner(0, a);
        if (need == 2) {
            address p = _signer(d, sigs, 1);
            if (p != e.provider) revert BadSigner(1, p);
        }
        sh.status = 2;
        emit KeyDecryptionApproved(ref, sh.eid, sh.receiver);
    }

    /// TxC's status: 0 none, 1 pending, 2 approved.
    function shareStatus(bytes32 ref) external view returns (uint8) {
        return _share[ref].status;
    }

    // ------------------------------------------------------------- destruction

    /// Algorithm 3 Step 1: the Sender submits TxE for one evidence item.
    function requestDestruction(bytes32 eid, string calldata reason, uint64 timestamp) external onlySender {
        if (_evidence[eid].sender == address(0)) revert NotRegistered(eid);
        if (_destruction[eid].sender != address(0)) revert AlreadyRequested(eid);
        _destruction[eid] =
            Destruction({sender: msg.sender, timestamp: timestamp, destroyed: false, confirmation: 0, reason: reason});
        emit DestructionRequested(eid, msg.sender, reason, timestamp);
    }

    /// Algorithm 3 Steps 2 and 4: after the off-chain copy is destroyed, the
    /// TxE's Sender records the destruction confirmation hash and the status
    /// becomes "destroyed".
    function confirmDestruction(bytes32 eid, bytes32 confirmation) external {
        Destruction storage d = _destruction[eid];
        if (d.sender == address(0)) revert NotRequested(eid);
        if (d.sender != msg.sender) revert NotRequester(eid, msg.sender);
        if (d.destroyed) revert AlreadyDestroyed(eid);
        d.confirmation = confirmation;
        d.destroyed = true;
        emit DestructionConfirmed(eid, confirmation);
    }

    /// What the court queries (Alg. 3 line 12): the TxE for `eid`, if any, its
    /// confirmation, and the registered `H(E′)` the confirmation is over.
    /// `sender == address(0)` means no TxE exists.
    function destructionOf(bytes32 eid)
        external
        view
        returns (
            address sender,
            string memory reason,
            uint64 timestamp,
            bytes32 confirmation,
            bool destroyed,
            bytes32 hEnc
        )
    {
        Destruction storage d = _destruction[eid];
        return (d.sender, d.reason, d.timestamp, d.confirmation, d.destroyed, _evidence[eid].hEnc);
    }
}
