// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * BVCRSALedger — On-chain anchor for BVCRSA Edge Blockchain
 *
 * This contract stores cryptographic commitments from the edge node's
 * SCRAT construction pipeline. Each block record anchors:
 *   - SHA-256 data hash (of SCRAT operation metadata)
 *   - SHA-256 block hash (proof-of-work mined hash)
 *
 * Epoch roots anchor Merkle tree roots for batch verification.
 *
 * Deployed on Ganache (local Ethereum) for real blockchain guarantees:
 *   - Immutability: once anchored, records cannot be altered
 *   - Auditability: all events are permanently logged
 *   - Verifiability: anyone can verify on-chain state
 */
contract BVCRSALedger {

    // ─── Data Structures ────────────────────────────────────────

    struct BlockRecord {
        uint256 index;
        uint256 timestamp;
        bytes32 dataHash;      // SHA-256 hash of SCRAT operation data
        bytes32 blockHash;     // SHA-256 proof-of-work block hash
        address anchoredBy;    // Address that submitted this record
    }

    struct EpochRecord {
        uint256 epoch;
        bytes32 epochRoot;     // H(Root_idx || Root_agg || epoch)
        uint256 timestamp;
        uint256 blockCount;    // Number of blocks in this epoch
    }

    // ─── State ──────────────────────────────────────────────────

    BlockRecord[] public blockRecords;
    mapping(uint256 => EpochRecord) public epochRecords;
    uint256 public totalEpochs;
    address public owner;

    // ─── Events ─────────────────────────────────────────────────

    event BlockAnchored(
        uint256 indexed index,
        bytes32 dataHash,
        bytes32 blockHash,
        uint256 timestamp
    );

    event EpochAnchored(
        uint256 indexed epoch,
        bytes32 epochRoot,
        uint256 blockCount,
        uint256 timestamp
    );

    event ChainValidated(
        uint256 chainLength,
        bool isValid,
        uint256 timestamp
    );

    // ─── Constructor ────────────────────────────────────────────

    constructor() {
        owner = msg.sender;

        // Genesis block — mirrors the Python EdgeBlockchain genesis
        blockRecords.push(BlockRecord({
            index: 0,
            timestamp: block.timestamp,
            dataHash: keccak256("GENESIS_BLOCK"),
            blockHash: bytes32(0),
            anchoredBy: msg.sender
        }));

        emit BlockAnchored(0, keccak256("GENESIS_BLOCK"), bytes32(0), block.timestamp);
    }

    // ─── Core Functions ─────────────────────────────────────────

    /**
     * @notice Anchor a new block record from the edge node
     * @param dataHash  SHA-256 hash of the SCRAT operation data
     * @param blockHash SHA-256 proof-of-work block hash from edge
     */
    function anchorBlock(bytes32 dataHash, bytes32 blockHash) external {
        uint256 idx = blockRecords.length;

        blockRecords.push(BlockRecord({
            index: idx,
            timestamp: block.timestamp,
            dataHash: dataHash,
            blockHash: blockHash,
            anchoredBy: msg.sender
        }));

        emit BlockAnchored(idx, dataHash, blockHash, block.timestamp);
    }

    /**
     * @notice Anchor an epoch root (Merkle root commitment)
     * @param epoch     The epoch number
     * @param epochRoot The epoch root hash: H(Root_idx || Root_agg || epoch)
     */
    function anchorEpochRoot(uint256 epoch, bytes32 epochRoot) external {
        epochRecords[epoch] = EpochRecord({
            epoch: epoch,
            epochRoot: epochRoot,
            timestamp: block.timestamp,
            blockCount: blockRecords.length
        });
        totalEpochs = epoch > totalEpochs ? epoch : totalEpochs;

        emit EpochAnchored(epoch, epochRoot, blockRecords.length, block.timestamp);
    }

    // ─── Query Functions ────────────────────────────────────────

    /**
     * @notice Get total number of anchored blocks
     */
    function getChainLength() external view returns (uint256) {
        return blockRecords.length;
    }

    /**
     * @notice Get a specific block record
     * @param index Block index to retrieve
     */
    function getBlock(uint256 index) external view returns (
        uint256 idx,
        uint256 timestamp,
        bytes32 dataHash,
        bytes32 blockHash,
        address anchoredBy
    ) {
        require(index < blockRecords.length, "Block index out of range");
        BlockRecord memory rec = blockRecords[index];
        return (rec.index, rec.timestamp, rec.dataHash, rec.blockHash, rec.anchoredBy);
    }

    /**
     * @notice Get the latest anchored block
     */
    function getLatestBlock() external view returns (
        uint256 idx,
        uint256 timestamp,
        bytes32 dataHash,
        bytes32 blockHash,
        address anchoredBy
    ) {
        require(blockRecords.length > 0, "No blocks");
        BlockRecord memory rec = blockRecords[blockRecords.length - 1];
        return (rec.index, rec.timestamp, rec.dataHash, rec.blockHash, rec.anchoredBy);
    }

    /**
     * @notice Verify a block hash matches the on-chain record
     * @param index        Block index to verify
     * @param expectedHash Expected block hash
     * @return matches     Whether the hash matches
     */
    function verifyBlockHash(uint256 index, bytes32 expectedHash) external view returns (bool matches) {
        require(index < blockRecords.length, "Block index out of range");
        return blockRecords[index].blockHash == expectedHash;
    }

    /**
     * @notice Verify an epoch root matches the on-chain record
     * @param epoch        Epoch number to verify
     * @param expectedRoot Expected epoch root
     * @return matches     Whether the root matches
     */
    function verifyEpochRoot(uint256 epoch, bytes32 expectedRoot) external view returns (bool matches) {
        return epochRecords[epoch].epochRoot == expectedRoot;
    }

    /**
     * @notice Get a summary of the on-chain state
     */
    function getChainSummary() external view returns (
        uint256 chainLength,
        uint256 epochs,
        bytes32 latestBlockHash,
        bytes32 genesisDataHash,
        address contractOwner
    ) {
        return (
            blockRecords.length,
            totalEpochs,
            blockRecords.length > 0 ? blockRecords[blockRecords.length - 1].blockHash : bytes32(0),
            blockRecords.length > 0 ? blockRecords[0].dataHash : bytes32(0),
            owner
        );
    }
}
