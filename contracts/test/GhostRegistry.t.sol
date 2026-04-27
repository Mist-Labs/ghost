// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {GhostRegistry} from "../src/GhostRegistry.sol";

contract GhostRegistryTest is Test {
    GhostRegistry public registry;

    address public owner   = makeAddr("owner");
    address public admin   = makeAddr("admin");
    address public alice   = makeAddr("alice");
    address public bob     = makeAddr("bob");
    address public charlie = makeAddr("charlie");

    // ─────────────────────────────────────────────────────────────────────────
    // Setup
    // ─────────────────────────────────────────────────────────────────────────

    function setUp() public {
        vm.prank(owner);
        registry = new GhostRegistry(owner, admin);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deployment
    // ─────────────────────────────────────────────────────────────────────────

    function test_DeploymentSetsOwnerAndAdmin() public view {
        assertEq(registry.owner(), owner);
        assertTrue(registry.hasRole(registry.ADMIN_ROLE(), admin));
    }

    function test_DeploymentRevertsOnZeroAdmin() public {
        vm.expectRevert(GhostRegistry.ZeroAddress.selector);
        new GhostRegistry(owner, address(0));
    }

    function test_InitialActiveCountIsZero() public view {
        assertEq(registry.activeCount(), 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Register protocol
    // ─────────────────────────────────────────────────────────────────────────

    function test_AdminCanRegisterProtocol() public {
        vm.prank(admin);
        registry.registerProtocol(
            alice,
            GhostRegistry.Tier.Guardian,
            "AliceProtocol",
            "security@alice.fi"
        );

        assertTrue(registry.isAuthorized(alice));
        assertEq(registry.activeCount(), 1);

        GhostRegistry.ProtocolRecord memory rec = registry.getRecord(alice);
        assertTrue(rec.active);
        assertEq(uint8(rec.tier), uint8(GhostRegistry.Tier.Guardian));
        assertEq(rec.name, "AliceProtocol");
        assertEq(rec.contactEmail, "security@alice.fi");
    }

    function test_RegisterEmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit GhostRegistry.ProtocolRegistered(
            alice,
            GhostRegistry.Tier.Sentinel,
            "AliceProtocol",
            block.timestamp
        );

        vm.prank(admin);
        registry.registerProtocol(
            alice,
            GhostRegistry.Tier.Sentinel,
            "AliceProtocol",
            "security@alice.fi"
        );
    }

    function test_RegisterRevertsOnZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(GhostRegistry.ZeroAddress.selector);
        registry.registerProtocol(
            address(0),
            GhostRegistry.Tier.Sentinel,
            "Test",
            "test@test.fi"
        );
    }

    function test_RegisterRevertsOnEmptyName() public {
        vm.prank(admin);
        vm.expectRevert(GhostRegistry.EmptyName.selector);
        registry.registerProtocol(
            alice,
            GhostRegistry.Tier.Sentinel,
            "",
            "test@test.fi"
        );
    }

    function test_RegisterRevertsOnDuplicate() public {
        vm.startPrank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");

        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.AlreadyRegistered.selector, alice));
        registry.registerProtocol(alice, GhostRegistry.Tier.Guardian, "A2", "a2@a.fi");
        vm.stopPrank();
    }

    function test_NonAdminCannotRegister() public {
        vm.prank(charlie);
        vm.expectRevert();
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");
    }

    function test_OwnerCanAlsoRegister() public {
        // Owner has DEFAULT_ADMIN_ROLE which can grant ADMIN_ROLE,
        // but cannot call registerProtocol directly without ADMIN_ROLE.
        // Owner must grant themselves ADMIN_ROLE first.
        vm.startPrank(owner);
        registry.grantAdmin(owner);
        registry.registerProtocol(alice, GhostRegistry.Tier.Fortress, "A", "a@a.fi");
        vm.stopPrank();

        assertTrue(registry.isAuthorized(alice));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Update tier
    // ─────────────────────────────────────────────────────────────────────────

    function test_AdminCanUpdateTier() public {
        vm.startPrank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");
        registry.updateTier(alice, GhostRegistry.Tier.Fortress);
        vm.stopPrank();

        assertEq(uint8(registry.getTier(alice)), uint8(GhostRegistry.Tier.Fortress));
    }

    function test_UpdateTierEmitsEvent() public {
        vm.prank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");

        vm.expectEmit(true, false, false, false);
        emit GhostRegistry.ProtocolUpdated(
            alice,
            GhostRegistry.Tier.Sentinel,
            GhostRegistry.Tier.Guardian,
            block.timestamp
        );

        vm.prank(admin);
        registry.updateTier(alice, GhostRegistry.Tier.Guardian);
    }

    function test_UpdateTierRevertsOnUnregistered() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.NotRegistered.selector, alice));
        registry.updateTier(alice, GhostRegistry.Tier.Guardian);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Revoke protocol
    // ─────────────────────────────────────────────────────────────────────────

    function test_AdminCanRevokeProtocol() public {
        vm.startPrank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");
        registry.revokeProtocol(alice);
        vm.stopPrank();

        assertFalse(registry.isAuthorized(alice));
        assertEq(registry.activeCount(), 0);
    }

    function test_RevokeEmitsEvent() public {
        vm.prank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");

        vm.expectEmit(true, false, false, false);
        emit GhostRegistry.ProtocolRevoked(alice, block.timestamp);

        vm.prank(admin);
        registry.revokeProtocol(alice);
    }

    function test_RevokeRevertsOnUnregistered() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.NotRegistered.selector, alice));
        registry.revokeProtocol(alice);
    }

    function test_RevokeRevertsOnAlreadyRevoked() public {
        vm.startPrank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");
        registry.revokeProtocol(alice);

        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.NotRegistered.selector, alice));
        registry.revokeProtocol(alice);
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Admin role management
    // ─────────────────────────────────────────────────────────────────────────

    function test_OwnerCanGrantAdmin() public {
        vm.prank(owner);
        registry.grantAdmin(charlie);

        assertTrue(registry.hasRole(registry.ADMIN_ROLE(), charlie));
    }

    function test_OwnerCanRevokeAdmin() public {
        vm.prank(owner);
        registry.revokeAdmin(admin);

        assertFalse(registry.hasRole(registry.ADMIN_ROLE(), admin));
    }

    function test_GrantAdminRevertsOnZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(GhostRegistry.ZeroAddress.selector);
        registry.grantAdmin(address(0));
    }

    function test_NonOwnerCannotGrantAdmin() public {
        vm.prank(charlie);
        vm.expectRevert();
        registry.grantAdmin(charlie);
    }

    function test_RevokedAdminCannotRegister() public {
        vm.prank(owner);
        registry.revokeAdmin(admin);

        vm.prank(admin);
        vm.expectRevert();
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pause / unpause
    // ─────────────────────────────────────────────────────────────────────────

    function test_OwnerCanPause() public {
        vm.prank(owner);
        registry.pause();

        vm.prank(admin);
        vm.expectRevert();
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");
    }

    function test_OwnerCanUnpause() public {
        vm.startPrank(owner);
        registry.pause();
        registry.unpause();
        vm.stopPrank();

        vm.prank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");
        assertTrue(registry.isAuthorized(alice));
    }

    function test_NonOwnerCannotPause() public {
        vm.prank(charlie);
        vm.expectRevert();
        registry.pause();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Active protocol enumeration
    // ─────────────────────────────────────────────────────────────────────────

    function test_ActiveProtocolsReturnsCorrectList() public {
        vm.startPrank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");
        registry.registerProtocol(bob, GhostRegistry.Tier.Guardian, "B", "b@b.fi");
        registry.registerProtocol(charlie, GhostRegistry.Tier.Fortress, "C", "c@c.fi");
        registry.revokeProtocol(bob);
        vm.stopPrank();

        address[] memory active = registry.activeProtocols();
        assertEq(active.length, 2);
        assertEq(active[0], alice);
        assertEq(active[1], charlie);
    }

    function test_AllProtocolsIncludesRevoked() public {
        vm.startPrank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");
        registry.registerProtocol(bob, GhostRegistry.Tier.Guardian, "B", "b@b.fi");
        registry.revokeProtocol(alice);
        vm.stopPrank();

        address[] memory all = registry.allProtocols();
        assertEq(all.length, 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fuzz
    // ─────────────────────────────────────────────────────────────────────────

    function testFuzz_RegisterAndRevoke(address protocol) public {
        vm.assume(protocol != address(0));

        vm.startPrank(admin);
        registry.registerProtocol(protocol, GhostRegistry.Tier.Sentinel, "Fuzz", "f@f.fi");
        assertTrue(registry.isAuthorized(protocol));
        assertEq(registry.activeCount(), 1);

        registry.revokeProtocol(protocol);
        assertFalse(registry.isAuthorized(protocol));
        assertEq(registry.activeCount(), 0);
        vm.stopPrank();
    }

    function testFuzz_TierUpdate(uint8 rawTier) public {
        // Tier enum has 4 values (None=0, Sentinel=1, Guardian=2, Fortress=3)
        vm.assume(rawTier <= 3);
        GhostRegistry.Tier tier = GhostRegistry.Tier(rawTier);

        vm.prank(admin);
        registry.registerProtocol(alice, GhostRegistry.Tier.Sentinel, "A", "a@a.fi");

        vm.prank(admin);
        if (rawTier == 0) {
            // Tier.None is valid to set — just unusual
            registry.updateTier(alice, tier);
        } else {
            registry.updateTier(alice, tier);
            assertEq(uint8(registry.getTier(alice)), rawTier);
        }
    }
}
