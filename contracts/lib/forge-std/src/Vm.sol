// SPDX-License-Identifier: MIT
pragma solidity >=0.6.2 <0.9.0;

interface Vm {
    function warp(uint256 newTimestamp) external;
    function deal(address who, uint256 newBalance) external;
    function prank(address msgSender) external;
    function startBroadcast() external;
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
    function envUint(string calldata name) external returns (uint256 value);
    function envAddress(string calldata name) external returns (address value);
    function envString(string calldata name) external returns (string memory value);
}

