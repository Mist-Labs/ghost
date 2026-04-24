// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GhostBounty {
    address public immutable protocol;
    address public immutable attacker;
    address public immutable recoveryRecipient;
    uint256 public immutable deployedAt;
    uint256 public immutable originalBounty;
    uint256 public immutable minimumReturnAmount;
    uint256 public constant DECAY_RATE_BPS = 500; // 5% per day
    uint256 public constant DECAY_INTERVAL = 1 days;
    uint256 public constant EXPIRY = 30 days;
    string public caseReference;
    bool public claimed;

    event BountyClaimed(address indexed claimer, uint256 fundsReturnedWei, uint256 bountyWei);
    event BountyExpired(uint256 returnedToProtocol);

    constructor(
        address _attacker,
        address _recoveryRecipient,
        uint256 _minimumReturnAmount,
        string memory _caseReference
    ) payable {
        require(_attacker != address(0), "attacker required");
        require(_recoveryRecipient != address(0), "recipient required");
        require(_minimumReturnAmount > 0, "minimum return required");
        protocol = msg.sender;
        attacker = _attacker;
        recoveryRecipient = _recoveryRecipient;
        minimumReturnAmount = _minimumReturnAmount;
        caseReference = _caseReference;
        deployedAt = block.timestamp;
        originalBounty = msg.value;
    }

    function currentBounty() public view returns (uint256) {
        uint256 elapsed = (block.timestamp - deployedAt) / DECAY_INTERVAL;
        uint256 decayBps = elapsed * DECAY_RATE_BPS;
        if (decayBps >= 10000) return 0;
        return originalBounty * (10000 - decayBps) / 10000;
    }

    function claim() external payable {
        require(msg.sender == attacker, "Not the attacker");
        require(block.timestamp < deployedAt + EXPIRY, "Bounty expired");
        require(!claimed, "Already claimed");
        uint256 bounty = currentBounty();
        require(bounty > 0, "No bounty remaining");
        require(msg.value >= minimumReturnAmount, "Returned amount too low");

        claimed = true;

        (bool returnedFunds, ) = payable(recoveryRecipient).call{value: msg.value}("");
        require(returnedFunds, "Return transfer failed");

        (bool paidBounty, ) = payable(attacker).call{value: bounty}("");
        require(paidBounty, "Bounty payout failed");

        emit BountyClaimed(attacker, msg.value, bounty);
    }

    function reclaim() external {
        require(msg.sender == protocol, "Not protocol");
        require(block.timestamp >= deployedAt + EXPIRY, "Not expired");
        emit BountyExpired(address(this).balance);
        payable(protocol).transfer(address(this).balance);
    }
}
