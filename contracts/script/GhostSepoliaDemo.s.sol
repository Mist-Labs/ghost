// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {GhostSepoliaDemo} from "../src/GhostSepoliaDemo.sol";

contract DeployGhostSepoliaDemo is Script {
    function run() external returns (GhostSepoliaDemo deployed) {
        uint256 deployerKey = vm.envUint("DEMO_DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerKey);
        deployed = new GhostSepoliaDemo();
        vm.stopBroadcast();
    }
}

