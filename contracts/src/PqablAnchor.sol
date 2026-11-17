// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PQ-ABL's epoch commitment (Fugkeaw et al., IEEE TCC 14(2), 2026), ported
/// @notice SAC Exp. 4's second arm: PQ-ABL's
/// Phase 4 Step 4, `Tx_e = Commit(R_e, CID_epoch, CID_Proof, t_e)`, and
/// Phase 5 Step 1, `SC.getAnchorData(e)`, on our Besu network.
///
/// PQ-ABL defines no deletion. Ours extends it the only way its structure
/// allows (`baselines/UPGRADES.md`, "PQ-ABL in Exp. 4"): the logger removes the
/// ciphertexts, rebuilds the epoch and **commits again for the same epoch**.
/// A commitment is appended and never overwritten, so the chain keeps every
/// root an epoch has had; `getAnchorData` returns the latest, which is what an
/// auditor takes as the epoch's root.
///
/// One logger per deployment: the verifier role that anchors in the paper.
/// There is no court and no order, as in the paper.
contract PqablAnchor {
    /// The logger: the only account that commits.
    address public immutable logger;

    /// One commitment: `(R_e, CID_epoch, CID_Proof, t_e)`.
    struct Anchor {
        bytes32 root;
        bytes32 cidEpoch;
        bytes32 cidProof;
        uint64 t;
    }

    mapping(uint64 => Anchor[]) private _anchors;

    event EpochCommitted(uint64 indexed e, uint256 version, bytes32 root, bytes32 cidEpoch, bytes32 cidProof);

    error NotLogger(address caller);
    error NoAnchor(uint64 e);

    constructor(address logger_) {
        logger = logger_;
    }

    /// Phase 4 Step 4, and every re-commit after a deletion. `t_e` is the
    /// block timestamp, as the paper has it.
    function commit(uint64 e, bytes32 root, bytes32 cidEpoch, bytes32 cidProof) external {
        if (msg.sender != logger) revert NotLogger(msg.sender);
        _anchors[e].push(Anchor({root: root, cidEpoch: cidEpoch, cidProof: cidProof, t: uint64(block.timestamp)}));
        emit EpochCommitted(e, _anchors[e].length - 1, root, cidEpoch, cidProof);
    }

    /// Phase 5 Step 1: the epoch's latest commitment.
    function getAnchorData(uint64 e)
        external
        view
        returns (bytes32 root, bytes32 cidEpoch, bytes32 cidProof, uint64 t)
    {
        uint256 n = _anchors[e].length;
        if (n == 0) revert NoAnchor(e);
        Anchor storage a = _anchors[e][n - 1];
        return (a.root, a.cidEpoch, a.cidProof, a.t);
    }

    /// How many commitments epoch `e` has had: more than one means it was
    /// rebuilt.
    function anchorCount(uint64 e) external view returns (uint256) {
        return _anchors[e].length;
    }

    /// The `i`-th commitment of epoch `e`, the first being the original.
    function anchorAt(uint64 e, uint256 i)
        external
        view
        returns (bytes32 root, bytes32 cidEpoch, bytes32 cidProof, uint64 t)
    {
        Anchor storage a = _anchors[e][i];
        return (a.root, a.cidEpoch, a.cidProof, a.t);
    }
}
