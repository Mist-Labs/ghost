// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title GhostRegistry
/// @notice On-chain registry of protocols authorized for Ghost monitoring.
/// @dev Admin role is granted to a Ghost-controlled wallet that syncs
///      protocol authorization automatically. Owner retains the ability
///      to grant/revoke admin and pause the registry in emergencies.
contract GhostRegistry is Ownable, AccessControl, Pausable, ReentrancyGuard {
    // ─────────────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Admin role — granted to Ghost's automated sync wallet.
    ///         Can register and revoke protocols without manual owner action.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // ─────────────────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Monitoring tier granted to a registered protocol.
    enum Tier {
        None,       // not registered
        Sentinel,   // < $50M TVL
        Guardian,   // $50M – $500M TVL
        Fortress    // $500M+ TVL
    }

    /// @notice Full registration record for a monitored protocol.
    struct ProtocolRecord {
        bool active;
        Tier tier;
        uint256 registeredAt;
        uint256 updatedAt;
        string name;
        string contactEmail;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice protocol address → registration record
    mapping(address => ProtocolRecord) private _records;

    /// @notice flat list of all ever-registered protocol addresses
    address[] private _allProtocols;

    /// @notice total number of currently active protocols
    uint256 public activeCount;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    event ProtocolRegistered(
        address indexed protocol,
        Tier tier,
        string name,
        uint256 timestamp
    );

    event ProtocolUpdated(
        address indexed protocol,
        Tier oldTier,
        Tier newTier,
        uint256 timestamp
    );

    event ProtocolRevoked(address indexed protocol, uint256 timestamp);

    event AdminGranted(address indexed account);
    event AdminRevoked(address indexed account);

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    error AlreadyRegistered(address protocol);
    error NotRegistered(address protocol);
    error ZeroAddress();
    error EmptyName();

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    /// @param initialOwner  Multisig or deployer wallet — retains owner rights.
    /// @param initialAdmin  Ghost's automated sync wallet — gets ADMIN_ROLE.
    constructor(address initialOwner, address initialAdmin)
        Ownable(initialOwner)
    {
        if (initialAdmin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);
        _grantRole(ADMIN_ROLE, initialAdmin);

        emit AdminGranted(initialAdmin);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Admin — protocol management (automated sync wallet)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Register a new protocol for Ghost monitoring.
    /// @dev Callable by ADMIN_ROLE (Ghost sync wallet) or owner.
    function registerProtocol(
        address protocol,
        Tier tier,
        string calldata name,
        string calldata contactEmail
    )
        external
        onlyRole(ADMIN_ROLE)
        whenNotPaused
        nonReentrant
    {
        if (protocol == address(0)) revert ZeroAddress();
        if (bytes(name).length == 0) revert EmptyName();
        if (_records[protocol].registeredAt != 0) revert AlreadyRegistered(protocol);

        _records[protocol] = ProtocolRecord({
            active: true,
            tier: tier,
            registeredAt: block.timestamp,
            updatedAt: block.timestamp,
            name: name,
            contactEmail: contactEmail
        });

        _allProtocols.push(protocol);
        activeCount++;

        emit ProtocolRegistered(protocol, tier, name, block.timestamp);
    }

    /// @notice Update tier for an already-registered protocol.
    function updateTier(address protocol, Tier newTier)
        external
        onlyRole(ADMIN_ROLE)
        whenNotPaused
    {
        if (_records[protocol].registeredAt == 0) revert NotRegistered(protocol);

        Tier oldTier = _records[protocol].tier;
        _records[protocol].tier = newTier;
        _records[protocol].updatedAt = block.timestamp;

        emit ProtocolUpdated(protocol, oldTier, newTier, block.timestamp);
    }

    /// @notice Revoke monitoring authorization for a protocol.
    function revokeProtocol(address protocol)
        external
        onlyRole(ADMIN_ROLE)
        whenNotPaused
    {
        if (_records[protocol].registeredAt == 0) revert NotRegistered(protocol);
        if (!_records[protocol].active) revert NotRegistered(protocol);

        _records[protocol].active = false;
        _records[protocol].updatedAt = block.timestamp;
        activeCount--;

        emit ProtocolRevoked(protocol, block.timestamp);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Owner — role management and emergency controls
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Grant ADMIN_ROLE to a new Ghost sync wallet.
    function grantAdmin(address account) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        _grantRole(ADMIN_ROLE, account);
        emit AdminGranted(account);
    }

    /// @notice Revoke ADMIN_ROLE from a Ghost sync wallet.
    function revokeAdmin(address account) external onlyOwner {
        _revokeRole(ADMIN_ROLE, account);
        emit AdminRevoked(account);
    }

    /// @notice Pause all state-changing operations. Emergency use only.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the registry.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Views
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Returns true if protocol is currently authorized for monitoring.
    function isAuthorized(address protocol) external view returns (bool) {
        return _records[protocol].active;
    }

    /// @notice Returns the full registration record for a protocol.
    function getRecord(address protocol)
        external
        view
        returns (ProtocolRecord memory)
    {
        return _records[protocol];
    }

    /// @notice Returns the monitoring tier for a protocol.
    function getTier(address protocol) external view returns (Tier) {
        return _records[protocol].tier;
    }

    /// @notice Returns all protocol addresses ever registered (including revoked).
    function allProtocols() external view returns (address[] memory) {
        return _allProtocols;
    }

    /// @notice Returns all currently active protocol addresses.
    function activeProtocols() external view returns (address[] memory) {
        address[] memory active = new address[](_allProtocols.length);
        uint256 count = 0;

        for (uint256 i = 0; i < _allProtocols.length; i++) {
            if (_records[_allProtocols[i]].active) {
                active[count++] = _allProtocols[i];
            }
        }

        // Trim to actual size
        assembly {
            mstore(active, count)
        }

        return active;
    }
}
