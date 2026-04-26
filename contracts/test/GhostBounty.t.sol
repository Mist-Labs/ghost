// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {GhostBounty} from "../src/GhostBounty.sol";

contract GhostBountyTest is Test {
    address internal constant ATTACKER = address(0xBEEF);
    address internal constant RECOVERY_RECIPIENT = address(0xCAFE);
    uint256 internal constant INITIAL_BOUNTY = 1 ether;
    uint256 internal constant MINIMUM_RETURN = 5 ether;
    string internal constant CASE_REFERENCE = "ghost|demo";

    GhostBounty internal bounty;

    receive() external payable {}

    function setUp() public {
        bounty = new GhostBounty{value: INITIAL_BOUNTY}(ATTACKER, RECOVERY_RECIPIENT, MINIMUM_RETURN, CASE_REFERENCE);
    }

    function testConstructorSetsExpectedState() public view {
        assertEq(bounty.protocol(), address(this), "protocol should be deployer");
        assertEq(bounty.attacker(), ATTACKER, "attacker mismatch");
        assertEq(bounty.recoveryRecipient(), RECOVERY_RECIPIENT, "recipient mismatch");
        assertEq(bounty.minimumReturnAmount(), MINIMUM_RETURN, "minimum return mismatch");
        assertEq(bounty.caseReference(), CASE_REFERENCE, "case reference mismatch");
        assertEq(bounty.currentBounty(), INITIAL_BOUNTY, "initial bounty mismatch");
        assertEq(address(bounty).balance, INITIAL_BOUNTY, "contract should hold initial bounty");
    }

    function testCurrentBountyDecaysOverTime() public {
        vm.warp(block.timestamp + 1 days);
        assertEq(
            bounty.currentBounty(), (INITIAL_BOUNTY * 9500) / 10000, "bounty should decay by 5 percent after one day"
        );
    }

    function testClaimPaysRecoveryRecipientAndAttacker() public {
        vm.deal(ATTACKER, MINIMUM_RETURN);

        vm.prank(ATTACKER);
        bounty.claim{value: MINIMUM_RETURN}();

        assertEq(RECOVERY_RECIPIENT.balance, MINIMUM_RETURN, "recipient should receive returned funds");
        assertEq(ATTACKER.balance, INITIAL_BOUNTY, "attacker should receive only the bounty balance");
        assertTrue(bounty.claimed(), "claim flag should be set");
        assertEq(address(bounty).balance, 0, "contract should be emptied after claim");
    }

    function testReclaimReturnsFundsToProtocolAfterExpiry() public {
        uint256 balanceBefore = address(this).balance;

        vm.warp(block.timestamp + 30 days);
        bounty.reclaim();

        assertEq(
            address(this).balance,
            balanceBefore + INITIAL_BOUNTY,
            "protocol should recover remaining bounty after expiry"
        );
        assertEq(address(bounty).balance, 0, "contract should be empty after reclaim");
    }
}
