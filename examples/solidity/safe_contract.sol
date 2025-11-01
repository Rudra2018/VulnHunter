// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
 * @title SafeBank - Secure Implementation
 * @dev This contract demonstrates secure coding practices for smart contracts
 *
 * SECURITY FEATURES:
 * - Reentrancy protection
 * - Access controls
 * - Safe math operations
 * - Proper error handling
 * - Emergency controls
 */

contract SafeBank is ReentrancyGuard, Ownable, Pausable {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    uint256 public constant MAX_DEPOSIT = 100 ether;
    uint256 public constant MIN_WITHDRAWAL = 0.001 ether;

    // Events for transparency
    event Deposit(address indexed user, uint256 amount, uint256 timestamp);
    event Withdrawal(address indexed user, uint256 amount, uint256 timestamp);
    event EmergencyWithdrawal(address indexed admin, uint256 amount, uint256 timestamp);

    // Modifiers for additional security
    modifier validAmount(uint256 amount) {
        require(amount > 0, "Amount must be positive");
        require(amount >= MIN_WITHDRAWAL, "Amount below minimum");
        _;
    }

    modifier sufficientBalance(uint256 amount) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        _;
    }

    constructor() {
        // Initialize with secure defaults
        _transferOwnership(msg.sender);
    }

    /**
     * @dev Secure deposit function with limits and checks
     */
    function deposit() external payable whenNotPaused nonReentrant {
        require(msg.value > 0, "Must deposit something");
        require(msg.value <= MAX_DEPOSIT, "Deposit exceeds maximum");
        require(balances[msg.sender].add(msg.value) <= MAX_DEPOSIT.mul(10), "User balance limit exceeded");

        // Safe math operations
        balances[msg.sender] = balances[msg.sender].add(msg.value);
        totalDeposits = totalDeposits.add(msg.value);

        emit Deposit(msg.sender, msg.value, block.timestamp);
    }

    /**
     * @dev Secure withdrawal function with reentrancy protection
     * Follows checks-effects-interactions pattern
     */
    function withdraw(uint256 amount)
        external
        whenNotPaused
        nonReentrant
        validAmount(amount)
        sufficientBalance(amount)
    {
        require(address(this).balance >= amount, "Contract has insufficient balance");

        // SECURE: State changes BEFORE external call (checks-effects-interactions)
        balances[msg.sender] = balances[msg.sender].sub(amount);
        totalDeposits = totalDeposits.sub(amount);

        // External call AFTER state changes
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount, block.timestamp);
    }

    /**
     * @dev Secure emergency withdrawal with proper access control
     */
    function emergencyWithdraw() external onlyOwner {
        uint256 contractBalance = address(this).balance;
        require(contractBalance > 0, "No funds to withdraw");

        // Reset all balances in emergency
        totalDeposits = 0;

        (bool success, ) = payable(owner()).call{value: contractBalance}("");
        require(success, "Emergency withdrawal failed");

        emit EmergencyWithdrawal(owner(), contractBalance, block.timestamp);
    }

    /**
     * @dev Secure batch withdrawal with gas limits and checks
     */
    function batchWithdraw(address[] calldata users, uint256[] calldata amounts)
        external
        onlyOwner
        whenNotPaused
        nonReentrant
    {
        require(users.length == amounts.length, "Arrays length mismatch");
        require(users.length <= 50, "Too many users in batch"); // Gas limit protection

        uint256 totalAmount = 0;

        // Calculate total amount first
        for (uint256 i = 0; i < amounts.length; i++) {
            require(amounts[i] > 0, "Invalid amount");
            require(balances[users[i]] >= amounts[i], "Insufficient balance");
            totalAmount = totalAmount.add(amounts[i]);
        }

        require(address(this).balance >= totalAmount, "Contract insufficient balance");

        // Process all withdrawals
        for (uint256 i = 0; i < users.length; i++) {
            // Update state first
            balances[users[i]] = balances[users[i]].sub(amounts[i]);
            totalDeposits = totalDeposits.sub(amounts[i]);

            // Then make external call
            (bool success, ) = payable(users[i]).call{value: amounts[i]}("");
            require(success, "Transfer failed");

            emit Withdrawal(users[i], amounts[i], block.timestamp);
        }
    }

    /**
     * @dev Secure transfer between users with proper checks
     */
    function transfer(address to, uint256 amount)
        external
        whenNotPaused
        nonReentrant
        validAmount(amount)
        sufficientBalance(amount)
    {
        require(to != address(0), "Invalid recipient");
        require(to != msg.sender, "Cannot transfer to self");

        // Safe math operations prevent overflow/underflow
        balances[msg.sender] = balances[msg.sender].sub(amount);
        balances[to] = balances[to].add(amount);

        emit Withdrawal(msg.sender, amount, block.timestamp);
        emit Deposit(to, amount, block.timestamp);
    }

    /**
     * @dev Pause contract in emergency
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause contract
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Get contract balance safely
     */
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @dev Get user balance safely
     */
    function getUserBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    /**
     * @dev Check if user has sufficient balance
     */
    function hasSufficientBalance(address user, uint256 amount) external view returns (bool) {
        return balances[user] >= amount;
    }

    /**
     * @dev Get total deposits
     */
    function getTotalDeposits() external view returns (uint256) {
        return totalDeposits;
    }

    /**
     * @dev Fallback function with reentrancy protection
     */
    receive() external payable whenNotPaused nonReentrant {
        require(msg.value > 0, "Must send Ether");
        require(msg.value <= MAX_DEPOSIT, "Deposit exceeds maximum");

        balances[msg.sender] = balances[msg.sender].add(msg.value);
        totalDeposits = totalDeposits.add(msg.value);

        emit Deposit(msg.sender, msg.value, block.timestamp);
    }
}

/**
 * @title SafeToken - Secure ERC-20 Implementation
 * @dev Demonstrates secure token contract with overflow protection
 */
contract SafeToken is Ownable {
    using SafeMath for uint256;

    string public constant name = "SafeToken";
    string public constant symbol = "SAFE";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    uint256 public constant MAX_SUPPLY = 1000000 * 10**decimals;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor(uint256 _initialSupply) {
        require(_initialSupply <= MAX_SUPPLY, "Initial supply exceeds maximum");

        totalSupply = _initialSupply.mul(10**decimals);
        balances[msg.sender] = totalSupply;

        emit Transfer(address(0), msg.sender, totalSupply);
    }

    /**
     * @dev Secure transfer with SafeMath
     */
    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "Transfer to zero address");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // SafeMath prevents overflow/underflow
        balances[msg.sender] = balances[msg.sender].sub(amount);
        balances[to] = balances[to].add(amount);

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @dev Secure transferFrom with SafeMath
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(from != address(0), "Transfer from zero address");
        require(to != address(0), "Transfer to zero address");
        require(balances[from] >= amount, "Insufficient balance");
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");

        // SafeMath prevents overflow/underflow
        balances[from] = balances[from].sub(amount);
        allowances[from][msg.sender] = allowances[from][msg.sender].sub(amount);
        balances[to] = balances[to].add(amount);

        emit Transfer(from, to, amount);
        return true;
    }

    /**
     * @dev Secure mint with supply cap
     */
    function mint(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Mint to zero address");
        require(totalSupply.add(amount) <= MAX_SUPPLY, "Would exceed max supply");

        // SafeMath prevents overflow
        totalSupply = totalSupply.add(amount);
        balances[to] = balances[to].add(amount);

        emit Mint(to, amount);
        emit Transfer(address(0), to, amount);
    }

    /**
     * @dev Secure burn with proper checks
     */
    function burn(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance to burn");

        // SafeMath prevents underflow
        balances[msg.sender] = balances[msg.sender].sub(amount);
        totalSupply = totalSupply.sub(amount);

        emit Burn(msg.sender, amount);
        emit Transfer(msg.sender, address(0), amount);
    }

    /**
     * @dev Secure approve function
     */
    function approve(address spender, uint256 amount) external returns (bool) {
        require(spender != address(0), "Approve to zero address");

        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /**
     * @dev Secure increase allowance
     */
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        require(spender != address(0), "Increase allowance to zero address");

        // SafeMath prevents overflow
        allowances[msg.sender][spender] = allowances[msg.sender][spender].add(addedValue);
        emit Approval(msg.sender, spender, allowances[msg.sender][spender]);
        return true;
    }

    /**
     * @dev Secure decrease allowance
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        require(spender != address(0), "Decrease allowance to zero address");
        require(allowances[msg.sender][spender] >= subtractedValue, "Decreased allowance below zero");

        // SafeMath prevents underflow
        allowances[msg.sender][spender] = allowances[msg.sender][spender].sub(subtractedValue);
        emit Approval(msg.sender, spender, allowances[msg.sender][spender]);
        return true;
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