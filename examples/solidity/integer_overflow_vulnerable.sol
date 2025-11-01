// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;  // Older version without automatic overflow checks

/**
 * @title VulnerableToken - Integer Overflow/Underflow Vulnerabilities
 * @dev This contract demonstrates integer overflow and underflow vulnerabilities
 * Common in ERC-20 tokens before SafeMath adoption
 *
 * VULNERABILITY: Integer overflow/underflow without SafeMath
 * IMPACT: Arbitrary token creation, balance manipulation
 * CWE-190: Integer Overflow, CWE-191: Integer Underflow
 */

contract VulnerableToken {
    string public name = "VulnerableToken";
    string public symbol = "VULN";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    address public owner;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    constructor(uint256 _initialSupply) {
        owner = msg.sender;
        totalSupply = _initialSupply * 10**decimals;
        balances[msg.sender] = totalSupply;
    }

    /**
     * @dev Transfer tokens between accounts
     * VULNERABLE: Integer underflow in sender balance
     * VULNERABLE: Integer overflow in receiver balance
     */
    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "Transfer to zero address");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: Can underflow if amount > balance (despite require check)
        // In some edge cases, this check might be bypassed
        balances[msg.sender] -= amount;  // Potential underflow

        // VULNERABILITY: Can overflow if to's balance + amount > uint256 max
        balances[to] += amount;  // Potential overflow

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @dev Transfer tokens on behalf of another account
     * VULNERABLE: Multiple overflow/underflow points
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(from != address(0), "Transfer from zero address");
        require(to != address(0), "Transfer to zero address");
        require(balances[from] >= amount, "Insufficient balance");
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");

        // VULNERABILITY: Potential underflow
        balances[from] -= amount;
        allowances[from][msg.sender] -= amount;

        // VULNERABILITY: Potential overflow
        balances[to] += amount;

        emit Transfer(from, to, amount);
        return true;
    }

    /**
     * @dev Mint new tokens
     * VULNERABLE: Can overflow totalSupply and user balance
     */
    function mint(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Mint to zero address");

        // VULNERABILITY: totalSupply can overflow
        totalSupply += amount;  // Potential overflow

        // VULNERABILITY: User balance can overflow
        balances[to] += amount;  // Potential overflow

        emit Mint(to, amount);
        emit Transfer(address(0), to, amount);
    }

    /**
     * @dev Burn tokens from account
     * VULNERABLE: Underflow without proper checks
     */
    function burn(uint256 amount) external {
        // Weak check - can be bypassed in edge cases
        require(balances[msg.sender] >= amount, "Insufficient balance to burn");

        // VULNERABILITY: Can underflow
        balances[msg.sender] -= amount;  // Potential underflow
        totalSupply -= amount;           // Potential underflow

        emit Transfer(msg.sender, address(0), amount);
    }

    /**
     * @dev Batch transfer to multiple recipients
     * VULNERABLE: Overflow in loop calculations
     */
    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
        require(recipients.length == amounts.length, "Array length mismatch");

        uint256 totalAmount = 0;

        // VULNERABILITY: totalAmount can overflow in accumulation
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount += amounts[i];  // Potential overflow
        }

        require(balances[msg.sender] >= totalAmount, "Insufficient balance");

        // Transfer to each recipient
        for (uint256 i = 0; i < recipients.length; i++) {
            // VULNERABILITY: Multiple underflow/overflow points
            balances[msg.sender] -= amounts[i];     // Potential underflow
            balances[recipients[i]] += amounts[i];  // Potential overflow

            emit Transfer(msg.sender, recipients[i], amounts[i]);
        }
    }

    /**
     * @dev Approve spender to transfer tokens
     * VULNERABLE: No consideration for allowance overflow
     */
    function approve(address spender, uint256 amount) external returns (bool) {
        require(spender != address(0), "Approve to zero address");

        // VULNERABILITY: No check for overflow
        allowances[msg.sender][spender] = amount;  // Direct assignment, but could be used in overflow

        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /**
     * @dev Increase allowance
     * VULNERABLE: Direct overflow vulnerability
     */
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        require(spender != address(0), "Increase allowance to zero address");

        // VULNERABILITY: Direct overflow - no SafeMath
        allowances[msg.sender][spender] += addedValue;  // Definite overflow risk

        emit Approval(msg.sender, spender, allowances[msg.sender][spender]);
        return true;
    }

    /**
     * @dev Decrease allowance
     * VULNERABLE: Direct underflow vulnerability
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        require(spender != address(0), "Decrease allowance to zero address");

        // VULNERABILITY: Direct underflow - no SafeMath
        allowances[msg.sender][spender] -= subtractedValue;  // Definite underflow risk

        emit Approval(msg.sender, spender, allowances[msg.sender][spender]);
        return true;
    }

    /**
     * @dev Airdrop tokens to multiple addresses
     * VULNERABLE: Multiple overflow points
     */
    function airdrop(address[] calldata recipients, uint256 amountEach) external onlyOwner {
        // VULNERABILITY: Can overflow in multiplication
        uint256 totalRequired = recipients.length * amountEach;  // Potential overflow

        require(balances[owner] >= totalRequired, "Insufficient balance for airdrop");

        for (uint256 i = 0; i < recipients.length; i++) {
            // VULNERABILITY: Multiple overflow/underflow points
            balances[owner] -= amountEach;              // Potential underflow
            balances[recipients[i]] += amountEach;      // Potential overflow

            emit Transfer(owner, recipients[i], amountEach);
        }
    }

    /**
     * @dev Compound interest calculation
     * VULNERABLE: Exponential overflow in calculations
     */
    function applyInterest(uint256 rate) external onlyOwner {
        // VULNERABILITY: Interest calculation can overflow
        for (uint256 i = 0; i < 100; i++) {  // Simulate addresses
            address user = address(uint160(i + 1000));
            if (balances[user] > 0) {
                // VULNERABILITY: Can overflow in multiplication
                uint256 interest = balances[user] * rate / 100;  // Potential overflow
                balances[user] += interest;                      // Potential overflow
                totalSupply += interest;                         // Potential overflow

                emit Transfer(address(0), user, interest);
            }
        }
    }

    /**
     * @dev Get balance
     */
    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    /**
     * @dev Get allowance
     */
    function allowance(address _owner, address spender) external view returns (uint256) {
        return allowances[_owner][spender];
    }
}

/**
 * @title OverflowExploit - Demonstrates overflow attack
 * @dev Shows how to exploit integer overflow vulnerabilities
 * FOR EDUCATIONAL PURPOSES ONLY
 */
contract OverflowExploit {
    VulnerableToken public target;

    constructor(address _target) {
        target = VulnerableToken(_target);
    }

    /**
     * @dev Exploit overflow in increaseAllowance
     */
    function exploitAllowanceOverflow() external {
        // Set allowance to maximum value
        uint256 maxValue = type(uint256).max;

        // This will overflow and wrap around to a small number
        target.increaseAllowance(address(this), maxValue);
        target.increaseAllowance(address(this), 1);  // Overflow!
    }

    /**
     * @dev Exploit underflow in decreaseAllowance
     */
    function exploitAllowanceUnderflow() external {
        // Try to decrease from 0, causing underflow to max value
        target.decreaseAllowance(address(this), 1);  // Underflow!
    }
}