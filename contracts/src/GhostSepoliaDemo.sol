// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GhostSepoliaDemo
/// @notice Intentionally vulnerable demo contract for Ghost end-to-end testing on Base Sepolia.
/// @dev Do not deploy to production. This contract deliberately includes:
/// 1. unprotected initializer
/// 2. unprotected upgrade/admin path
/// 3. same-block oracle dependence
/// 4. simple drainable vault behavior
contract GhostSepoliaDemo {
    address public owner;
    address public oracle;
    address public implementation;
    uint256 public lastSpotPrice;
    uint256 public lastOracleUpdateBlock;
    bool public initialized;

    event Initialized(address indexed owner, address indexed oracle);
    event OracleUpdated(address indexed caller, uint256 newPrice, uint256 blockNumber);
    event OracleAddressChanged(address indexed caller, address indexed newOracle);
    event ImplementationChanged(address indexed caller, address indexed newImplementation);
    event Borrowed(address indexed borrower, uint256 collateralIn, uint256 loanOut);
    event Swept(address indexed caller, address indexed recipient, uint256 amount);
    event LiquidityAdded(address indexed funder, uint256 amount);

    receive() external payable {}

    /// @notice Intentionally unprotected initializer for demo purposes.
    function initialize(address newOwner, address newOracle) external {
        owner = newOwner;
        oracle = newOracle;
        initialized = true;
        emit Initialized(newOwner, newOracle);
    }

    /// @notice Intentionally unprotected admin path for demo purposes.
    function upgradeImplementation(address newImplementation) external {
        implementation = newImplementation;
        emit ImplementationChanged(msg.sender, newImplementation);
    }

    /// @notice Intentionally unprotected oracle setter for demo purposes.
    function setOracle(address newOracle) external {
        oracle = newOracle;
        emit OracleAddressChanged(msg.sender, newOracle);
    }

    function seedVault() external payable {
        require(msg.value > 0, "value required");
        emit LiquidityAdded(msg.sender, msg.value);
    }

    function updateSpotPrice(uint256 newPrice) external {
        require(msg.sender == oracle, "not oracle");
        require(newPrice > 0, "price required");
        lastSpotPrice = newPrice;
        lastOracleUpdateBlock = block.number;
        emit OracleUpdated(msg.sender, newPrice, block.number);
    }

    /// @notice Intentionally uses the latest spot price immediately without TWAP or delay.
    /// @dev Attack flow: set yourself as oracle, push an inflated price, then borrow in the same block.
    function borrowAgainstSpot() external payable returns (uint256 loanOut) {
        require(msg.value > 0, "collateral required");
        require(lastSpotPrice > 0, "oracle not set");

        loanOut = (msg.value * lastSpotPrice) / 1e18;
        require(address(this).balance >= loanOut, "insufficient vault liquidity");

        (bool ok,) = payable(msg.sender).call{value: loanOut}("");
        require(ok, "borrow transfer failed");

        emit Borrowed(msg.sender, msg.value, loanOut);
    }

    /// @notice Intentionally unauthenticated drain path for demo purposes.
    function emergencySweep(address payable recipient) external {
        uint256 amount = address(this).balance;
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "sweep failed");
        emit Swept(msg.sender, recipient, amount);
    }
}
