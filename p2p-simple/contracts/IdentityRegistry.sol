// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IdentityRegistry
 * @dev Decentralized Public Key Infrastructure (DPKI) smart contract for P2P libp2p networks.
 *      Provides key registration, discovery/distribution, rotation, and cryptographic revocation.
 */
contract IdentityRegistry {

    enum RevocationReason {
        NONE,               // 0: Active / Not revoked
        KEY_COMPROMISE,     // 1: Private key compromised
        SUPERSEDED,         // 2: Key replaced/superseded
        DECOMMISSIONED,     // 3: Peer node decommissioned
        MALICIOUS_ACTIVITY  // 4: Slashed/flagged for malicious behavior
    }

    struct IdentityRecord {
        address owner;              // Ethereum address that registered/controls this identity
        string peerId;              // libp2p Peer ID (e.g. 12D3KooW...)
        string publicKeyHex;        // ECDSA Public Key in hex format (SPKI DER)
        string didUri;              // W3C DID URI (e.g. did:peer:12D3KooW...)
        bool isRevoked;             // Revocation flag
        RevocationReason reason;    // Reason code if revoked
        uint256 createdAt;          // Initial registration timestamp
        uint256 updatedAt;          // Last rotation/update timestamp
        uint256 revokedAt;          // Revocation timestamp (0 if active)
    }

    // Mapping from libp2p peerId to its IdentityRecord
    mapping(string => IdentityRecord) private identities;

    // Mapping from peerId to historical public keys (for audit trail)
    mapping(string => string[]) private keyHistories;

    // Array of all registered peer IDs for network discovery
    string[] private registeredPeers;

    // Events for real-time P2P client subscription
    event KeyRegistered(
        string peerId,
        address indexed owner,
        string publicKeyHex,
        string didUri,
        uint256 timestamp
    );

    event KeyRevoked(
        string peerId,
        address indexed owner,
        uint8 reason,
        uint256 timestamp
    );

    event KeyUnrevoked(
        string peerId,
        address indexed owner,
        uint256 timestamp
    );

    event KeyRotated(
        string peerId,
        address indexed owner,
        string oldPublicKeyHex,
        string newPublicKeyHex,
        uint256 timestamp
    );

    /**
     * @notice Register a new peer identity and public key on-chain
     * @param peerId The libp2p Peer ID string
     * @param publicKeyHex Hex-encoded ECDSA public key
     * @param didUri W3C DID string
     */
    function registerKey(
        string calldata peerId,
        string calldata publicKeyHex,
        string calldata didUri
    ) external {
        require(bytes(peerId).length > 0, "Peer ID cannot be empty");
        require(bytes(publicKeyHex).length > 0, "Public key cannot be empty");

        IdentityRecord storage record = identities[peerId];

        if (record.owner == address(0)) {
            // First time registration
            identities[peerId] = IdentityRecord({
                owner: msg.sender,
                peerId: peerId,
                publicKeyHex: publicKeyHex,
                didUri: didUri,
                isRevoked: false,
                reason: RevocationReason.NONE,
                createdAt: block.timestamp,
                updatedAt: block.timestamp,
                revokedAt: 0
            });

            registeredPeers.push(peerId);
            keyHistories[peerId].push(publicKeyHex);

            emit KeyRegistered(peerId, msg.sender, publicKeyHex, didUri, block.timestamp);
        } else {
            // Already registered - only owner can update (if not revoked)
            require(record.owner == msg.sender, "Unauthorized: Only identity owner can modify key");
            require(!record.isRevoked, "Key is revoked. Must use a new peer identity");

            string memory oldKey = record.publicKeyHex;
            record.publicKeyHex = publicKeyHex;
            record.didUri = didUri;
            record.updatedAt = block.timestamp;
            keyHistories[peerId].push(publicKeyHex);

            emit KeyRotated(peerId, msg.sender, oldKey, publicKeyHex, block.timestamp);
        }
    }

    /**
     * @notice Revoke a peer's public key on-chain
     * @param peerId The libp2p Peer ID to revoke
     * @param reason Revocation reason code
     */
    function revokeKey(string calldata peerId, uint8 reason) external {
        IdentityRecord storage record = identities[peerId];
        require(record.owner != address(0), "Identity does not exist");
        require(record.owner == msg.sender, "Unauthorized: Only owner can revoke key");
        require(!record.isRevoked, "Key is already revoked");
        require(reason > 0 && reason <= 4, "Invalid revocation reason");

        record.isRevoked = true;
        record.reason = RevocationReason(reason);
        record.revokedAt = block.timestamp;
        record.updatedAt = block.timestamp;

        emit KeyRevoked(peerId, msg.sender, reason, block.timestamp);
    }

    /**
     * @notice Unrevoke / reinstate a previously revoked key (Owner only)
     * @param peerId The libp2p Peer ID to reinstate
     */
    function unrevokeKey(string calldata peerId) external {
        IdentityRecord storage record = identities[peerId];
        require(record.owner != address(0), "Identity does not exist");
        require(record.owner == msg.sender, "Unauthorized: Only owner can unrevoke key");
        require(record.isRevoked, "Key is not revoked");

        record.isRevoked = false;
        record.reason = RevocationReason.NONE;
        record.revokedAt = 0;
        record.updatedAt = block.timestamp;

        emit KeyUnrevoked(peerId, msg.sender, block.timestamp);
    }

    /**
     * @notice Rotate an active public key to a new keypair
     * @param peerId The libp2p Peer ID
     * @param newPublicKeyHex The new ECDSA public key in hex
     * @param newDidUri The updated DID URI
     */
    function rotateKey(
        string calldata peerId,
        string calldata newPublicKeyHex,
        string calldata newDidUri
    ) external {
        IdentityRecord storage record = identities[peerId];
        require(record.owner != address(0), "Identity does not exist");
        require(record.owner == msg.sender, "Unauthorized: Only owner can rotate key");
        require(!record.isRevoked, "Cannot rotate a revoked key");
        require(bytes(newPublicKeyHex).length > 0, "New public key cannot be empty");

        string memory oldKey = record.publicKeyHex;
        record.publicKeyHex = newPublicKeyHex;
        record.didUri = newDidUri;
        record.updatedAt = block.timestamp;
        keyHistories[peerId].push(newPublicKeyHex);

        emit KeyRotated(peerId, msg.sender, oldKey, newPublicKeyHex, block.timestamp);
    }

    /**
     * @notice Resolve a peer ID to its active on-chain identity record
     * @param peerId The libp2p Peer ID to look up
     */
    function resolveKey(string calldata peerId) external view returns (IdentityRecord memory) {
        require(identities[peerId].owner != address(0), "Identity not found on-chain");
        return identities[peerId];
    }

    /**
     * @notice Fast verification check for P2P message handlers
     * @param peerId The sender's libp2p Peer ID
     * @param publicKeyHex The public key to check
     * @return isValid True if key is currently active and matches registered key
     * @return isRevoked True if the key has been revoked on-chain
     */
    function isKeyValid(
        string calldata peerId,
        string calldata publicKeyHex
    ) external view returns (bool isValid, bool isRevoked) {
        IdentityRecord memory record = identities[peerId];
        if (record.owner == address(0)) {
            return (false, false); // Not registered
        }
        if (record.isRevoked) {
            return (false, true); // Revoked
        }
        bool matches = keccak256(bytes(record.publicKeyHex)) == keccak256(bytes(publicKeyHex));
        return (matches, false);
    }

    /**
     * @notice Return all registered peer IDs
     */
    function getAllRegisteredPeers() external view returns (string[] memory) {
        return registeredPeers;
    }

    /**
     * @notice Retrieve the historical public keys for a peer
     */
    function getKeyHistory(string calldata peerId) external view returns (string[] memory) {
        return keyHistories[peerId];
    }
}
