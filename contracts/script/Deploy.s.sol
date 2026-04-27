// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {GhostRegistry} from "../src/GhostRegistry.sol";
import {GhostHook} from "../src/GhostHook.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";

/// @notice Deploys GhostRegistry, GhostBounty (demo), and GhostHook to Base.
/// @dev Run with:
///      forge script script/Deploy.s.sol \
///        --rpc-url $ALCHEMY_HTTP_URL \
///        --private-key $DEPLOYER_PRIVATE_KEY \
///        --broadcast \
///        --verify \
///        --etherscan-api-key $BASESCAN_API_KEY
contract DeployGhost is Script {
    // ── Base mainnet addresses ─────────────────────────────────────────────
    address constant UNISWAP_V4_POOL_MANAGER =
        0x498581fF718922c3f8e6A244956aF099B2652b2b;

    address constant WORLD_ID_ROUTER =
        0x163B09b4fE21177c455D850BD815B8d9b93D3Cad; // World ID on Base

    // ── Deployment params (override via env) ──────────────────────────────
    uint256 constant DEFAULT_HOOK_THRESHOLD_USD = 100_000e18; // $100k
    uint256 constant DEFAULT_MAX_INVARIANT_BPS  = 500;        // 5%

    // ── Demo bounty params ────────────────────────────────────────────────
    uint256 constant DEMO_BOUNTY_ETH = 0.01 ether;

    function run() external {
        address deployer = vm.addr(vm.envUint("DEMO_DEPLOYER_PRIVATE_KEY"));
        address admin    = vm.envOr("GHOST_ADMIN_ADDRESS", deployer);
        address operator = vm.envOr("GHOST_OPERATOR_ADDRESS", deployer);

        // Demo attacker and protocol — use real addresses in production

        vm.startBroadcast();

        // ── 1. GhostRegistry ──────────────────────────────────────────────
        GhostRegistry registry = new GhostRegistry(deployer, admin);
        console2.log("GhostRegistry deployed at:", address(registry));

        // ── 2. GhostHook ──────────────────────────────────────────────────

        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000002ead;
        address hookAddress = 0xcab70EC481892C16f381E30DABf1763d5B1580c0;

        GhostHook ghostHook = new GhostHook{salt: salt}(
            IPoolManager(UNISWAP_V4_POOL_MANAGER),
            deployer,
            operator,
            DEFAULT_HOOK_THRESHOLD_USD,
            DEFAULT_MAX_INVARIANT_BPS
        );

        require(address(ghostHook) == hookAddress, "Hook address mismatch");
        console2.log("GhostHook deployed at:", address(ghostHook));

        vm.stopBroadcast();

        // ── Summary ───────────────────────────────────────────────────────
        console2.log("\n=== Ghost Deployment Summary ===");
        console2.log("GhostRegistry :", address(registry));
        console2.log("GhostHook     :", address(ghostHook));
        console2.log("Network       : Base Mainnet (8453)");
        console2.log("\nVerify with:");
        console2.log(
            "forge verify-contract <address> src/GhostRegistry.sol:GhostRegistry --chain base --etherscan-api-key $BASESCAN_API_KEY"
        );
    }
}
