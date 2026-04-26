// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {GhostBounty} from "../src/GhostBounty.sol";

contract DeployGhostBounty is Script {
    function run() external returns (GhostBounty deployed) {
        uint256 deployerKey = vm.envUint("BOUNTY_PRIVATE_KEY");
        address attacker = vm.envAddress("BOUNTY_ATTACKER");
        address recoveryRecipient = vm.envAddress("BOUNTY_RECOVERY_RECIPIENT");
        uint256 minimumReturn = vm.envUint("BOUNTY_MINIMUM_RETURN_WEI");
        uint256 bountyValue = vm.envUint("BOUNTY_VALUE_WEI");
        string memory caseReference = vm.envString("BOUNTY_CASE_REFERENCE");

        vm.startBroadcast(deployerKey);
        deployed = new GhostBounty{value: bountyValue}(attacker, recoveryRecipient, minimumReturn, caseReference);
        vm.stopBroadcast();
    }
}
