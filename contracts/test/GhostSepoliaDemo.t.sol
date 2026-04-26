// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {GhostSepoliaDemo} from "../src/GhostSepoliaDemo.sol";

contract GhostSepoliaDemoTest is Test {
    address internal constant OWNER = address(0xABCD);
    address internal constant ORACLE = address(0x0A11CE);
    address internal constant ATTACKER = address(0xBEEF);
    address internal constant IMPLEMENTATION = address(0x1234);
    address internal constant RECIPIENT = address(0xCAFE);

    GhostSepoliaDemo internal demo;

    receive() external payable {}

    function setUp() public {
        demo = new GhostSepoliaDemo();
        vm.deal(address(this), 20 ether);
    }

    function testInitializeIsUnprotected() public {
        demo.initialize(OWNER, ORACLE);

        assertEq(demo.owner(), OWNER, "owner should be updated");
        assertEq(demo.oracle(), ORACLE, "oracle should be updated");
        assertEq(demo.initialized(), true, "initializer flag should be set");
    }

    function testUpgradePathIsUnprotected() public {
        demo.upgradeImplementation(IMPLEMENTATION);
        assertEq(demo.implementation(), IMPLEMENTATION, "implementation should be updated");
    }

    function testSameBlockOracleBorrowCanDrainLiquidity() public {
        demo.seedVault{value: 10 ether}();
        demo.setOracle(ATTACKER);

        vm.deal(ATTACKER, 1 ether);
        uint256 attackerBalanceBefore = ATTACKER.balance;

        vm.prank(ATTACKER);
        demo.updateSpotPrice(5 ether);

        vm.prank(ATTACKER);
        uint256 loanOut = demo.borrowAgainstSpot{value: 1 ether}();

        assertEq(loanOut, 5 ether, "borrow amount should reflect same-block spot price");
        assertEq(
            ATTACKER.balance,
            attackerBalanceBefore - 1 ether + 5 ether,
            "attacker should net the manipulated borrow proceeds"
        );
        assertEq(address(demo).balance, 6 ether, "vault balance should be reduced after the borrow");
        assertEq(demo.lastOracleUpdateBlock(), block.number, "spot update should be current block");
    }

    function testEmergencySweepDrainsEntireVault() public {
        demo.seedVault{value: 4 ether}();
        demo.emergencySweep(payable(RECIPIENT));

        assertEq(RECIPIENT.balance, 4 ether, "recipient should receive the full vault");
        assertEq(address(demo).balance, 0, "vault should be emptied");
    }
}

