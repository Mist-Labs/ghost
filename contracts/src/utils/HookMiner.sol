// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.19;

library HookMiner {
    uint160 constant FLAG_MASK = 0xfff << 148;
    uint256 constant MAX_LOOP = 160_000;

    function find(
        address deployer,
        uint160 flags,
        bytes memory creationCode,
        bytes memory constructorArgs
    ) internal pure returns (address, bytes32) {
        address hookAddress;
        bytes memory creationCodeWithArgs = abi.encodePacked(creationCode, constructorArgs);
        uint256 salt;
        for (salt; salt < MAX_LOOP;) {
            hookAddress = computeAddress(deployer, salt, creationCodeWithArgs);
            if (uint160(hookAddress) & FLAG_MASK == flags) {
                return (hookAddress, bytes32(salt));
            }
            unchecked { ++salt; }
        }
        revert("HookMiner: could not find salt");
    }

    function computeAddress(
        address deployer,
        uint256 salt,
        bytes memory creationCode
    ) public pure returns (address hookAddress) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            deployer,
                            salt,
                            keccak256(creationCode)
                        )
                    )
                )
            )
        );
    }
}
