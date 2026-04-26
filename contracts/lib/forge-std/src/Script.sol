// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Vm} from "./Vm.sol";

abstract contract Script {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
}

