// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PQ-ChainLog Tier-3 anchor: case registration, the checkpoint chain,
/// redaction-order digests, and search authorisation (draft8, user decision D4)
/// @notice A registry. It records and orders; it verifies no signature.
///
/// # No post-quantum signature goes on chain (D4, 2026-10-06)
///
/// draft8 Phase 7 Steps 3–4: each custodian signs the epoch checkpoint
/// `d_e = H(0x12 ‖ ⟪cid, e, R_e, n_e, d_{e−1}⟫)` with ML-DSA off chain;
/// M of the N registered custodians approve it and the co-signer adds SLH-DSA.
/// The anchor stores `d_e` and `A_e = H(0x13 ‖ ⟪S_e, σ_SLH⟫)`, a digest of the
/// approval set, and the signatures travel in the off-chain audit package. So
/// the anchor's size and gas do not depend on the signature scheme.
///
/// This contract checks only what consensus can check cheaply and an auditor
/// could not reconstruct afterwards: that each checkpoint **extends** the last
/// one — `d_{e−1}` equals the stored `d_e`, back to the registered `reg`. It
/// does not recompute SHAKE256; auditors do, from the registered keys and the
/// audit package.
///
/// # No leaf count on chain (M13 A21, amending D4)
///
/// ⭐ **The cumulative `leafCount` is gone: it is not stored, checked or
/// emitted.** `audit/07` D2: a public running total makes case size public,
/// which defeated the per-epoch unlinkability the forest is built for. What it
/// looked like it protected, it did not:
///
/// * **rollback** and **forks** are caught by the `d_{e−1}` link, not by the
///   count — two histories of the same length cannot both extend one chain;
/// * **omission** was never caught here. The count is the server's own claim,
///   so a server that omits leaves reports the count matching its short root;
///   a receipt holder's inclusion proof is what fails.
///
/// And since M13 A20 gave every epoch its own MMR, `n_e` is **not cumulative**,
/// so monotonicity has nothing left to mean: an epoch may legitimately hold
/// fewer leaves than its predecessor. The count still exists — `d_e` commits to
/// it — but it travels in the off-chain audit package, which D4 already made
/// mandatory. The argument is recorded in the design record.
///
/// ⚠️ The earlier design verified ML-DSA here (config B, the ETHDILITHIUM port)
/// and was measured; D4 made the store-only fallback the design. The verifier
/// contract and its conformance gate stay in the tree, uncalled by this one.
///
/// # First registration wins
///
/// `registerCase` is open: the Case Authority registers `reg` once. A party who
/// front-runs a registration can only deny that `cid` (a hiding commitment it
/// must first observe), never forge a history under it, because an auditor
/// recomputes `reg` from the registered keys before trusting any checkpoint.
contract Anchor {
    // -------------------------------------------------------------- errors

    error CaseAlreadyRegistered(bytes32 cidC);
    error CaseNotRegistered(bytes32 cidC);
    error EmptyDigest();
    error CheckpointNotLinked(bytes32 expected, bytes32 got);
    error EmptyRoot();
    error RedactionOrderAlreadyRecorded(bytes32 orderId);
    error NullifierAlreadySpent(bytes32 nullifier);
    error UnknownEpoch(bytes32 cidC);
    error NotCaseAnchorer(bytes32 cidC, address caller);

    // -------------------------------------------------------------- types

    /// One case's most recent anchored epoch.
    ///
    /// No leaf count: see the A21 note above. `anchoredAt` stays, because the
    /// restart-survival check needs it and the block number is public anyway.
    struct Epoch {
        bytes32 root; // R_e, the Tier-2 MMR root for that epoch alone
        uint64 anchoredAt; // block number, for the restart-survival check
        bytes32 checkpoint; // d_e
        bytes32 approval; // A_e = H(0x13 ‖ ⟪S_e, σ_SLH⟫)
    }

    // -------------------------------------------------------------- state

    /// cid → reg, the checkpoint chain's d_{−1}. Zero means "not registered".
    mapping(bytes32 => bytes32) public registration;

    /// cid → the account that registered the case: its AIS, and the only
    /// account that may extend its checkpoint chain or record its orders
    /// (M13 A16).
    ///
    /// ⭐ **Why the contract binds callers at all, when integrity never needed
    /// it** (`audit/06` W18, K11). An auditor rejects a junk anchor, because it
    /// does not verify against `reg`; but it still becomes the chain's head,
    /// and the honest AIS's next `dPrev` then fails to link. Anyone could stop
    /// a case's anchoring with one transaction. The same held for orders: a
    /// junk digest recorded first under an honest order id made the real one
    /// revert. Integrity was intact; liveness was not.
    ///
    /// ⚠️ Registration itself is still first-come, so a party that front-runs
    /// `registerCase` becomes the case's anchorer. That is denial of service,
    /// which the threat model places out of scope, and it is why the paper
    /// should say "on a permissioned network".
    mapping(bytes32 => address) public anchorer;

    /// cid → latest anchored epoch.
    mapping(bytes32 => Epoch) private _latest;

    /// Nullifier → spent. Consensus-enforced single-spend, design §7b′.
    mapping(bytes32 => bool) public nullifierSpent;

    /// cid → order id → the order's digest. Phase 11 Step 1: recorded here
    /// **before** anything is deleted, and the AIS gates erasure on it; `σ_CO`
    /// is verified by the AIS and auditors under the court key. A second
    /// recording of the same id in the same case reverts.
    ///
    /// Keyed by case as well as id (M13 A16), so another case's anchorer cannot
    /// squat on this case's order id.
    mapping(bytes32 => mapping(bytes32 => bytes32)) public recordedOrder;

    // -------------------------------------------------------------- events

    event CaseRegistered(bytes32 indexed cidC, bytes32 reg);

    event RootCommitted(
        bytes32 indexed cidC, bytes32 root, uint64 anchoredAt, bytes32 checkpoint, bytes32 approval
    );

    /// Design §12: erasure acts on the evidence plane; the custody plane keeps
    /// an append-only record that it happened. This event is that record.
    event RedactionOrdered(bytes32 indexed cidC, bytes32 indexed orderId, bytes32 digest);

    /// ⭐ Design §7b′: a search cannot occur without a prior public record of
    /// its authorisation. The Secure Module derives a trapdoor only against an
    /// inclusion proof of this event.
    event SearchAuthorised(bytes32 indexed nullifier, bytes32 scopeCommit);

    // -------------------------------------------------------------- registration

    /// Phase 1 Step 3 (`eq:reg`): fix the case's keys and M-of-N policy before
    /// the first checkpoint, by their digest.
    function registerCase(bytes32 cidC, bytes32 reg) external {
        if (reg == bytes32(0)) revert EmptyDigest();
        if (registration[cidC] != bytes32(0)) revert CaseAlreadyRegistered(cidC);
        registration[cidC] = reg;
        anchorer[cidC] = msg.sender;
        emit CaseRegistered(cidC, reg);
    }

    /// The case must be registered and the caller must be its anchorer.
    function _onlyAnchorer(bytes32 cidC) private view returns (bytes32 reg) {
        reg = registration[cidC];
        if (reg == bytes32(0)) revert CaseNotRegistered(cidC);
        if (msg.sender != anchorer[cidC]) revert NotCaseAnchorer(cidC, msg.sender);
    }

    // -------------------------------------------------------------- anchoring

    /// Phase 7 Step 4 (`eq:anchortx`): accept an epoch only if it extends the
    /// last checkpoint.
    ///
    /// @dev The `dPrev` link is the whole check, and it is strictly stronger
    /// than the leaf-count monotonicity it replaces (M13 A21): two different
    /// histories cannot both extend the same chain, whatever their lengths.
    /// `n_e` is committed inside `dE` and verified off chain.
    function commitRoot(bytes32 cidC, bytes32 root, bytes32 dPrev, bytes32 dE, bytes32 aE) external {
        if (root == bytes32(0)) revert EmptyRoot();
        if (dE == bytes32(0) || aE == bytes32(0)) revert EmptyDigest();
        bytes32 reg = _onlyAnchorer(cidC);

        Epoch storage prev = _latest[cidC];
        bytes32 expected = prev.checkpoint == bytes32(0) ? reg : prev.checkpoint;
        if (dPrev != expected) revert CheckpointNotLinked(expected, dPrev);

        _latest[cidC] = Epoch({root: root, anchoredAt: uint64(block.number), checkpoint: dE, approval: aE});
        emit RootCommitted(cidC, root, uint64(block.number), dE, aE);
    }

    /// The latest anchored epoch for a case.
    function latestEpoch(bytes32 cidC) external view returns (Epoch memory) {
        Epoch memory e = _latest[cidC];
        if (e.root == bytes32(0)) revert UnknownEpoch(cidC);
        return e;
    }

    // -------------------------------------------------------------- redaction

    /// Phase 11 Step 1: record a court-ordered redaction's digest before
    /// anything is deleted.
    ///
    /// The anchored history is **not** rewritten. Design §12: erasure deletes
    /// the payload from the evidence plane and *appends* a disposal record;
    /// removing an anchored leaf would itself be tampering. The order itself
    /// (`eq:order`, with `σ_CO`) is verified under the court key, never a search
    /// key, by the AIS and auditors, who also hold it to its digest here.
    function orderRedaction(bytes32 cidC, bytes32 orderId, bytes32 digest) external {
        if (digest == bytes32(0)) revert EmptyDigest();
        _onlyAnchorer(cidC);
        if (recordedOrder[cidC][orderId] != bytes32(0)) {
            revert RedactionOrderAlreadyRecorded(orderId);
        }
        recordedOrder[cidC][orderId] = digest;
        emit RedactionOrdered(cidC, orderId, digest);
    }

    // -------------------------------------------------------------- search

    /// Register a warrant nullifier and publish the request.
    ///
    /// ⭐ **The contract is a registry. It records and orders; it does not
    /// verify.** Settled by the design record. An SP1 STARK cannot be
    /// verified on the EVM at feasible cost — that is precisely what SP1's
    /// pairing-based wrappers exist for, and those are banned because they
    /// would move warrant unforgeability from a hash assumption to one Shor
    /// breaks (row 13).
    ///
    /// Three parties, three jobs, and the failure mode is assuming one covers
    /// another:
    ///
    /// * **this contract** — rejects a spent `N`, emits `SearchAuthorised`. It
    ///   is the only party consensus enforces, so single-spend and public
    ///   ordering belong here and nowhere else.
    /// * **the AIS** — verifies `pi_auth` *and binds it to this event*.
    /// * **the investigator's Secure Module** — enforces scope and releases only
    ///   the result set, against an inclusion proof of this event.
    ///
    /// ⚠️ **This event attests a *request*, not an authorisation.** Anyone can
    /// call this function, so the record says a search was announced, not that
    /// it was permitted. The `0x04` audit leaf anchors the served request after,
    /// and an auditor reconciles the two sets.
    function authoriseSearch(bytes32 nullifier, bytes32 scopeCommit) external {
        if (nullifierSpent[nullifier]) revert NullifierAlreadySpent(nullifier);
        nullifierSpent[nullifier] = true;
        emit SearchAuthorised(nullifier, scopeCommit);
    }
}
