// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {SwapParams} from "v4-core/src/types/PoolOperation.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {FixedPointMathLib} from "solmate/src/utils/FixedPointMathLib.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";

/// @title GhostHook
/// @notice Uniswap v4 hook that gives Ghost pool-level visibility into every
///         swap. Snapshots reserves in beforeSwap, compares the actual delta
///         against expected AMM output in afterSwap, and emits a SwapAlert
///         when the delta violates the pool's invariant or exceeds the USD
///         threshold. Ghost's Rust detection engine subscribes to SwapAlert
///         events and feeds them into the confidence tier pipeline.
///
/// @dev Operator role is granted to Ghost's detection wallet. Owner is the
///      Ghost multisig. Emergency pause cuts off all hook callbacks.
contract GhostHook is BaseHook, Ownable, AccessControl, Pausable, ReentrancyGuard {
    using PoolIdLibrary for PoolKey;
    using FixedPointMathLib for uint256;

    // ─────────────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Operator role — Ghost's detection wallet. Can update thresholds
    ///         and trigger emergency pause on individual pools.
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ─────────────────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Snapshot of pool reserves taken in beforeSwap.
    struct PoolSnapshot {
        uint128 reserve0;
        uint128 reserve1;
        uint160 sqrtPriceX96;
        uint256 timestamp;
        address sender;
    }

    /// @notice Per-pool configuration.
    struct PoolConfig {
        bool registered;
        bool paused;
        uint256 alertThresholdUSD;   // alert if swap value exceeds this (18 decimals)
        uint256 maxInvariantBps;     // alert if output exceeds expected by this bps
    }

    // ─────────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice pool id → configuration
    mapping(PoolId => PoolConfig) public poolConfigs;

    /// @notice pool id → last snapshot (written in beforeSwap, read in afterSwap)
    mapping(PoolId => PoolSnapshot) private _snapshots;

    /// @notice pool id → paused state (operator-level pause per pool)
    mapping(PoolId => bool) public poolPaused;

    /// @notice Default USD alert threshold — applies to unregistered pools.
    uint256 public defaultAlertThresholdUSD;

    /// @notice Default max invariant overshoot in bps before alert fires.
    uint256 public defaultMaxInvariantBps;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Primary signal consumed by Ghost's Rust detection engine.
    event SwapAlert(
        PoolId indexed poolId,
        address indexed sender,
        int128 amount0Delta,
        int128 amount1Delta,
        uint256 valueUSD,
        uint256 overshootBps,
        AlertReason reason,
        uint256 timestamp
    );

    event PoolRegistered(PoolId indexed poolId, uint256 thresholdUSD);
    event PoolPaused(PoolId indexed poolId, address operator);
    event PoolUnpaused(PoolId indexed poolId, address operator);
    event EmergencyPause(PoolId indexed poolId, string reason);
    event ThresholdUpdated(PoolId indexed poolId, uint256 oldThreshold, uint256 newThreshold);

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    error PoolAlreadyRegistered();
    error PoolNotRegistered();
    error ZeroThreshold();
    error ZeroAddress();

    // ─────────────────────────────────────────────────────────────────────────
    // Enums
    // ─────────────────────────────────────────────────────────────────────────

    enum AlertReason {
        ThresholdExceeded,      // swap value > USD threshold
        InvariantViolated,      // output > expected by > maxInvariantBps
        Both                    // both conditions met simultaneously
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    /// @param _manager               Uniswap v4 PoolManager on Base.
    /// @param _owner                 Ghost multisig.
    /// @param _operator              Ghost detection wallet.
    /// @param _defaultThresholdUSD   Default swap value alert threshold (18 decimals).
    /// @param _defaultMaxInvariantBps Default max overshoot bps (e.g. 500 = 5%).
    constructor(
        IPoolManager _manager,
        address _owner,
        address _operator,
        uint256 _defaultThresholdUSD,
        uint256 _defaultMaxInvariantBps
    )
        BaseHook(_manager)
        Ownable(_owner)
    {
        if (_operator == address(0)) revert ZeroAddress();
        if (_defaultThresholdUSD == 0) revert ZeroThreshold();

        defaultAlertThresholdUSD = _defaultThresholdUSD;
        defaultMaxInvariantBps   = _defaultMaxInvariantBps;

        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(OPERATOR_ROLE, _operator);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hook permissions
    // ─────────────────────────────────────────────────────────────────────────

    function getHookPermissions()
        public
        pure
        override
        returns (Hooks.Permissions memory)
    {
        return Hooks.Permissions({
            beforeInitialize:        false,
            afterInitialize:         false,
            beforeAddLiquidity:      false,
            afterAddLiquidity:       false,
            beforeRemoveLiquidity:   false,
            afterRemoveLiquidity:    false,
            beforeSwap:              true,   // snapshot reserves
            afterSwap:               true,   // compare delta, emit alert
            beforeDonate:            false,
            afterDonate:             false,
            beforeSwapReturnDelta:   false,
            afterSwapReturnDelta:    false,
            afterAddLiquidityReturnDelta:    false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hook callbacks
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Snapshot pool state before swap executes.
    function _beforeSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata,
        bytes calldata
    )
        internal override
        whenNotPaused
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        PoolId id = key.toId();
        if (poolPaused[id]) {
            return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }

        (uint160 sqrtPriceX96, , ,) = StateLibrary.getSlot0(poolManager, id);
        (uint128 reserve0, uint128 reserve1) = _getReserves(id);

        _snapshots[id] = PoolSnapshot({
            reserve0:     reserve0,
            reserve1:     reserve1,
            sqrtPriceX96: sqrtPriceX96,
            timestamp:    block.timestamp,
            sender:       sender
        });

        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    /// @notice Compare post-swap delta against snapshot. Emit SwapAlert if
    ///         threshold exceeded or invariant violated.
    function _afterSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata,
        BalanceDelta delta,
        bytes calldata
    )
        internal override
        whenNotPaused
        returns (bytes4, int128)
    {
        PoolId id = key.toId();
        if (poolPaused[id]) {
            return (BaseHook.afterSwap.selector, 0);
        }

        PoolSnapshot memory snap = _snapshots[id];
        PoolConfig memory cfg    = _resolveConfig(id);

        int128 amount0 = delta.amount0();
        int128 amount1 = delta.amount1();

        uint256 valueUSD    = _estimateUSD(key, amount0, amount1);
        uint256 overshootBps = _computeOvershoot(snap, amount0, amount1);

        bool thresholdHit  = valueUSD >= cfg.alertThresholdUSD;
        bool invariantHit  = overshootBps > cfg.maxInvariantBps;

        if (thresholdHit || invariantHit) {
            AlertReason reason;
            if (thresholdHit && invariantHit) {
                reason = AlertReason.Both;
            } else if (invariantHit) {
                reason = AlertReason.InvariantViolated;
            } else {
                reason = AlertReason.ThresholdExceeded;
            }

            emit SwapAlert(
                id,
                sender,
                amount0,
                amount1,
                valueUSD,
                overshootBps,
                reason,
                block.timestamp
            );
        }

        return (BaseHook.afterSwap.selector, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Operator — pool management
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Register a pool with a custom alert threshold.
    function registerPool(
        PoolKey calldata key,
        uint256 alertThresholdUSD,
        uint256 maxInvariantBps
    )
        external
        onlyRole(OPERATOR_ROLE)
    {
        if (alertThresholdUSD == 0) revert ZeroThreshold();
        PoolId id = key.toId();
        if (poolConfigs[id].registered) revert PoolAlreadyRegistered();

        poolConfigs[id] = PoolConfig({
            registered:         true,
            paused:             false,
            alertThresholdUSD:  alertThresholdUSD,
            maxInvariantBps:    maxInvariantBps
        });

        emit PoolRegistered(id, alertThresholdUSD);
    }

    /// @notice Pause a specific pool's hook callbacks.
    function pausePool(PoolKey calldata key, string calldata reason)
        external
        onlyRole(OPERATOR_ROLE)
    {
        PoolId id = key.toId();
        poolPaused[id] = true;
        emit PoolPaused(id, msg.sender);
        emit EmergencyPause(id, reason);
    }

    /// @notice Unpause a specific pool's hook callbacks.
    function unpausePool(PoolKey calldata key)
        external
        onlyRole(OPERATOR_ROLE)
    {
        PoolId id = key.toId();
        poolPaused[id] = false;
        emit PoolUnpaused(id, msg.sender);
    }

    /// @notice Update alert threshold for a registered pool.
    function updateThreshold(PoolKey calldata key, uint256 newThreshold)
        external
        onlyRole(OPERATOR_ROLE)
    {
        if (newThreshold == 0) revert ZeroThreshold();
        PoolId id = key.toId();
        if (!poolConfigs[id].registered) revert PoolNotRegistered();

        uint256 old = poolConfigs[id].alertThresholdUSD;
        poolConfigs[id].alertThresholdUSD = newThreshold;
        emit ThresholdUpdated(id, old, newThreshold);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Owner — global controls
    // ─────────────────────────────────────────────────────────────────────────

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    function setDefaultThreshold(uint256 threshold) external onlyOwner {
        if (threshold == 0) revert ZeroThreshold();
        defaultAlertThresholdUSD = threshold;
    }

    function setDefaultMaxInvariantBps(uint256 bps) external onlyOwner {
        defaultMaxInvariantBps = bps;
    }

    function grantOperator(address account) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        _grantRole(OPERATOR_ROLE, account);
    }

    function revokeOperator(address account) external onlyOwner {
        _revokeRole(OPERATOR_ROLE, account);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Returns pool config, falling back to defaults for unregistered pools.
    function _resolveConfig(PoolId id)
        internal
        view
        returns (PoolConfig memory cfg)
    {
        if (poolConfigs[id].registered) {
            return poolConfigs[id];
        }
        return PoolConfig({
            registered:        false,
            paused:            false,
            alertThresholdUSD: defaultAlertThresholdUSD,
            maxInvariantBps:   defaultMaxInvariantBps
        });
    }

    /// @dev Fetches current pool reserves from PoolManager liquidity state.
    function _getReserves(PoolId id)
        internal
        view
        returns (uint128 reserve0, uint128 reserve1)
    {
        // In v4, liquidity is tracked per position rather than as global reserves.
        // We use total liquidity as a proxy for comparative delta analysis.
        uint128 liquidity = StateLibrary.getLiquidity(poolManager, id);
        reserve0 = liquidity;
        reserve1 = liquidity;
    }

    /// @dev Estimates USD value of a swap delta. In production this should
    ///      be replaced with a Chainlink price feed lookup per token pair.
    ///      Current implementation uses absolute token amounts as a proxy.
    function _estimateUSD(
        PoolKey calldata,
        int128 amount0,
        int128 amount1
    )
        internal
        pure
        returns (uint256)
    {
        uint256 abs0 = amount0 < 0 ? uint256(uint128(-amount0)) : uint256(uint128(amount0));
        uint256 abs1 = amount1 < 0 ? uint256(uint128(-amount1)) : uint256(uint128(amount1));
        // Return the larger of the two absolute deltas as the value proxy
        return abs0 > abs1 ? abs0 : abs1;
    }

    /// @dev Computes how much the actual output overshoots expected AMM output
    ///      in basis points. Used to detect invariant violations.
    ///      Simplified: compares actual delta to snapshot-based expected output.
    function _computeOvershoot(
        PoolSnapshot memory snap,
        int128 amount0,
        int128 amount1
    )
        internal
        pure
        returns (uint256 overshootBps)
    {
        if (snap.reserve0 == 0 || snap.reserve1 == 0) return 0;

        // Constant product: expected output = (amountIn * reserve_out) / (reserve_in + amountIn)
        // Using absolute values for direction-agnostic calculation
        uint256 amountIn;
        uint256 reserveIn;
        uint256 reserveOut;
        uint256 actualOut;

        if (amount0 < 0) {
            // token0 going in, token1 coming out
            amountIn   = uint256(uint128(-amount0));
            reserveIn  = snap.reserve0;
            reserveOut = snap.reserve1;
            actualOut  = amount1 > 0 ? uint256(uint128(amount1)) : 0;
        } else {
            // token1 going in, token0 coming out
            amountIn   = uint256(uint128(-amount1));
            reserveIn  = snap.reserve1;
            reserveOut = snap.reserve0;
            actualOut  = amount0 > 0 ? uint256(uint128(amount0)) : 0;
        }

        if (amountIn == 0 || reserveIn == 0 || actualOut == 0) return 0;

        uint256 expectedOut = (amountIn * reserveOut) / (reserveIn + amountIn);
        if (expectedOut == 0) return 0;

        if (actualOut <= expectedOut) return 0;

        overshootBps = ((actualOut - expectedOut) * 10_000) / expectedOut;
    }
}
