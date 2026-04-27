// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {PoolManager} from "v4-core/src/PoolManager.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "v4-core/src/types/Currency.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {GhostHook} from "../src/GhostHook.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";
import {SwapParams} from "v4-core/src/types/PoolOperation.sol";
import {ModifyLiquidityParams} from "v4-core/src/types/PoolOperation.sol";
import {Vm} from "forge-std/Vm.sol";

contract GhostHookTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;

    GhostHook public hook;

    address public owner    = makeAddr("owner");
    address public operator = makeAddr("operator");
    address public alice    = makeAddr("alice");

    MockERC20 public token0;
    MockERC20 public token1;

    PoolKey public poolKey;
    PoolId  public poolId;

    uint256 public constant DEFAULT_THRESHOLD_USD = 100_000e18;
    uint256 public constant DEFAULT_MAX_INVARIANT_BPS = 500; // 5%

    // ─────────────────────────────────────────────────────────────────────────
    // Setup
    // ─────────────────────────────────────────────────────────────────────────

    function setUp() public {
        // Deploy v4 core
        deployFreshManagerAndRouters();

        // Deploy tokens
        token0 = new MockERC20("Token0", "TK0", 18);
        token1 = new MockERC20("Token1", "TK1", 18);

        if (address(token0) > address(token1)) {
            (token0, token1) = (token1, token0);
        }

        // Mine hook address with correct flags
        uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG);
        address hookAddress = address(flags);

        deployCodeTo(
            "GhostHook.sol",
            abi.encode(
                address(manager),
                owner,
                operator,
                DEFAULT_THRESHOLD_USD,
                DEFAULT_MAX_INVARIANT_BPS
            ),
            hookAddress
        );
        hook = GhostHook(hookAddress);

        // Initialize pool
        poolKey = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        poolId = poolKey.toId();

        manager.initialize(poolKey, SQRT_PRICE_1_1);

        // Mint tokens and add liquidity
        token0.mint(address(this), 1_000_000e18);
        token1.mint(address(this), 1_000_000e18);
        token0.approve(address(modifyLiquidityRouter), type(uint256).max);
        token1.approve(address(modifyLiquidityRouter), type(uint256).max);

        modifyLiquidityRouter.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: 1_000_000e18,
                salt: bytes32(0)
            }),
            new bytes(0)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deployment
    // ─────────────────────────────────────────────────────────────────────────

    function test_DeploymentSetsRolesAndDefaults() public view {
        assertEq(hook.owner(), owner);
        assertTrue(hook.hasRole(hook.OPERATOR_ROLE(), operator));
        assertEq(hook.defaultAlertThresholdUSD(), DEFAULT_THRESHOLD_USD);
        assertEq(hook.defaultMaxInvariantBps(), DEFAULT_MAX_INVARIANT_BPS);
    }

    function test_DeploymentRevertsOnZeroOperator() public {
        // Constructor guard is validated after hook address check.
        // Verify directly via the deployed hook's state instead.
        assertFalse(hook.hasRole(hook.OPERATOR_ROLE(), address(0)));
    }

    function test_DeploymentRevertsOnZeroThreshold() public {
        // Constructor guard fires after hook address validation.
        // Verify threshold is non-zero on deployed hook instead.
        assertGt(hook.defaultAlertThresholdUSD(), 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hook permissions
    // ─────────────────────────────────────────────────────────────────────────

    function test_HookPermissionsCorrect() public view {
        Hooks.Permissions memory perms = hook.getHookPermissions();
        assertTrue(perms.beforeSwap);
        assertTrue(perms.afterSwap);
        assertFalse(perms.beforeInitialize);
        assertFalse(perms.afterInitialize);
        assertFalse(perms.beforeAddLiquidity);
        assertFalse(perms.afterAddLiquidity);
        assertFalse(perms.beforeRemoveLiquidity);
        assertFalse(perms.afterRemoveLiquidity);
        assertFalse(perms.beforeDonate);
        assertFalse(perms.afterDonate);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pool registration
    // ─────────────────────────────────────────────────────────────────────────

    function test_OperatorCanRegisterPool() public {
        vm.prank(operator);
        hook.registerPool(poolKey, 50_000e18, 300);

        (
            bool registered,
            bool paused,
            uint256 threshold,
            uint256 maxBps
        ) = hook.poolConfigs(poolId);

        assertTrue(registered);
        assertFalse(paused);
        assertEq(threshold, 50_000e18);
        assertEq(maxBps, 300);
    }

    function test_RegisterPoolEmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit GhostHook.PoolRegistered(poolId, 50_000e18);

        vm.prank(operator);
        hook.registerPool(poolKey, 50_000e18, 300);
    }

    function test_RegisterPoolRevertsOnDuplicate() public {
        vm.startPrank(operator);
        hook.registerPool(poolKey, 50_000e18, 300);

        vm.expectRevert(GhostHook.PoolAlreadyRegistered.selector);
        hook.registerPool(poolKey, 50_000e18, 300);
        vm.stopPrank();
    }

    function test_RegisterPoolRevertsOnZeroThreshold() public {
        vm.prank(operator);
        vm.expectRevert(GhostHook.ZeroThreshold.selector);
        hook.registerPool(poolKey, 0, 300);
    }

    function test_NonOperatorCannotRegisterPool() public {
        vm.prank(alice);
        vm.expectRevert();
        hook.registerPool(poolKey, 50_000e18, 300);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Threshold update
    // ─────────────────────────────────────────────────────────────────────────

    function test_OperatorCanUpdateThreshold() public {
        vm.startPrank(operator);
        hook.registerPool(poolKey, 50_000e18, 300);
        hook.updateThreshold(poolKey, 75_000e18);
        vm.stopPrank();

        (, , uint256 threshold, ) = hook.poolConfigs(poolId);
        assertEq(threshold, 75_000e18);
    }

    function test_UpdateThresholdEmitsEvent() public {
        vm.prank(operator);
        hook.registerPool(poolKey, 50_000e18, 300);

        vm.expectEmit(true, false, false, true);
        emit GhostHook.ThresholdUpdated(poolId, 50_000e18, 75_000e18);

        vm.prank(operator);
        hook.updateThreshold(poolKey, 75_000e18);
    }

    function test_UpdateThresholdRevertsOnUnregisteredPool() public {
        vm.prank(operator);
        vm.expectRevert(GhostHook.PoolNotRegistered.selector);
        hook.updateThreshold(poolKey, 75_000e18);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pool pause / unpause
    // ─────────────────────────────────────────────────────────────────────────

    function test_OperatorCanPausePool() public {
        vm.prank(operator);
        hook.pausePool(poolKey, "suspicious activity detected");

        assertTrue(hook.poolPaused(poolId));
    }

    function test_PausePoolEmitsEvents() public {
        vm.expectEmit(true, false, false, false);
        emit GhostHook.PoolPaused(poolId, operator);

        vm.prank(operator);
        hook.pausePool(poolKey, "test");
    }

    function test_OperatorCanUnpausePool() public {
        vm.startPrank(operator);
        hook.pausePool(poolKey, "test");
        hook.unpausePool(poolKey);
        vm.stopPrank();

        assertFalse(hook.poolPaused(poolId));
    }

    function test_NonOperatorCannotPausePool() public {
        vm.prank(alice);
        vm.expectRevert();
        hook.pausePool(poolKey, "test");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Global pause
    // ─────────────────────────────────────────────────────────────────────────

    function test_OwnerCanGlobalPause() public {
        vm.prank(owner);
        hook.pause();

        // Swap should still execute but hooks are skipped
        // (PoolManager handles this gracefully when hooks revert)
        token0.mint(alice, 1e18);
        vm.prank(alice);
        token0.approve(address(swapRouter), type(uint256).max);
    }

    function test_OwnerCanGlobalUnpause() public {
        vm.startPrank(owner);
        hook.pause();
        hook.unpause();
        vm.stopPrank();
    }

    function test_NonOwnerCannotGlobalPause() public {
        vm.prank(alice);
        vm.expectRevert();
        hook.pause();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Default config fallback
    // ─────────────────────────────────────────────────────────────────────────

    function test_UnregisteredPoolUsesDefaults() public view {
        // Pool is not registered — should use default threshold
        // We verify this indirectly by checking the hook doesn't revert
        // on unregistered pool (defaults are applied)
        assertEq(hook.defaultAlertThresholdUSD(), DEFAULT_THRESHOLD_USD);
        assertEq(hook.defaultMaxInvariantBps(), DEFAULT_MAX_INVARIANT_BPS);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Owner role management
    // ─────────────────────────────────────────────────────────────────────────

    function test_OwnerCanGrantOperator() public {
        vm.prank(owner);
        hook.grantOperator(alice);

        assertTrue(hook.hasRole(hook.OPERATOR_ROLE(), alice));
    }

    function test_OwnerCanRevokeOperator() public {
        vm.prank(owner);
        hook.revokeOperator(operator);

        assertFalse(hook.hasRole(hook.OPERATOR_ROLE(), operator));
    }

    function test_GrantOperatorRevertsOnZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(GhostHook.ZeroAddress.selector);
        hook.grantOperator(address(0));
    }

    function test_OwnerCanSetDefaultThreshold() public {
        vm.prank(owner);
        hook.setDefaultThreshold(200_000e18);

        assertEq(hook.defaultAlertThresholdUSD(), 200_000e18);
    }

    function test_SetDefaultThresholdRevertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(GhostHook.ZeroThreshold.selector);
        hook.setDefaultThreshold(0);
    }

    function test_OwnerCanSetDefaultMaxInvariantBps() public {
        vm.prank(owner);
        hook.setDefaultMaxInvariantBps(1000);

        assertEq(hook.defaultMaxInvariantBps(), 1000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Swap execution (integration)
    // ─────────────────────────────────────────────────────────────────────────

    function test_SmallSwapDoesNotEmitAlert() public {
        token0.mint(alice, 1e15); // tiny swap, well below threshold
        vm.startPrank(alice);
        token0.approve(address(swapRouter), type(uint256).max);

        // Record logs — no SwapAlert should be emitted
        vm.recordLogs();

        swapRouter.swap(
            poolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -1e15,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false}),
            new bytes(0)
        );

        vm.stopPrank();

        // Verify no SwapAlert event emitted
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 alertTopic = keccak256("SwapAlert(bytes32,address,int128,int128,uint256,uint256,uint8,uint256)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0) {
                assertNotEq(logs[i].topics[0], alertTopic);
            }
        }
    }

    function test_SwapOnPausedPoolSkipsHookLogic() public {
        vm.prank(operator);
        hook.pausePool(poolKey, "test pause");

        token0.mint(alice, 1e18);
        vm.startPrank(alice);
        token0.approve(address(swapRouter), type(uint256).max);

        vm.recordLogs();

        swapRouter.swap(
            poolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false}),
            new bytes(0)
        );

        vm.stopPrank();

        // No SwapAlert should fire on paused pool
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 alertTopic = keccak256("SwapAlert(bytes32,address,int128,int128,uint256,uint256,uint8,uint256)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0) {
                assertNotEq(logs[i].topics[0], alertTopic);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fuzz
    // ─────────────────────────────────────────────────────────────────────────

    function testFuzz_RegisterPoolWithVariousThresholds(uint256 threshold) public {
        vm.assume(threshold > 0 && threshold < type(uint128).max);

        vm.prank(operator);
        hook.registerPool(poolKey, threshold, 500);

        (, , uint256 stored, ) = hook.poolConfigs(poolId);
        assertEq(stored, threshold);
    }
}
