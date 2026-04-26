// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Vm} from "./Vm.sol";

abstract contract Test {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertTrue(bool condition, string memory message) internal pure {
        require(condition, message);
    }

    function assertEq(address lhs, address rhs, string memory message) internal pure {
        require(lhs == rhs, message);
    }

    function assertEq(uint256 lhs, uint256 rhs, string memory message) internal pure {
        require(lhs == rhs, message);
    }

    function assertEq(bool lhs, bool rhs, string memory message) internal pure {
        require(lhs == rhs, message);
    }

    function assertEq(string memory lhs, string memory rhs, string memory message) internal pure {
        require(keccak256(bytes(lhs)) == keccak256(bytes(rhs)), message);
    }
}

