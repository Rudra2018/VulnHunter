#!/usr/bin/env python3
"""
VulnHunter V7 - Basic Usage Examples
===================================
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnhunter import VulnHunter

def main():
    print("🛡️ VulnHunter V7 - Basic Usage Examples")
    print("=" * 50)

    # Initialize detector
    detector = VulnHunter()

    # Example 1: Buffer overflow detection
    print("\n📝 Example 1: Buffer Overflow (C)")
    code_c = '''
    #include <string.h>
    void vulnerable_function(char* user_input) {
        char buffer[10];
        strcpy(buffer, user_input);  // Vulnerable!
    }
    '''
    result = detector.scan(code_c, "c")
    print(f"Result: {'VULNERABLE' if result.vulnerable else 'SAFE'}")
    print(f"Confidence: {result.confidence:.3f}")
    print(f"Risk: {result.risk_level}")

    # Example 2: Safe Python function
    print("\n📝 Example 2: Safe Python Function")
    code_python = '''
    def safe_user_input(data):
        if validate_input(data):
            return sanitize(data)
        return None
    '''
    result = detector.scan(code_python, "python")
    print(f"Result: {'VULNERABLE' if result.vulnerable else 'SAFE'}")
    print(f"Confidence: {result.confidence:.3f}")
    print(f"Risk: {result.risk_level}")

    # Example 3: Solidity contract with potential issue
    print("\n📝 Example 3: Solidity Contract")
    code_solidity = '''
    function withdraw(uint amount) public {
        balances[msg.sender] -= amount;  // Potential underflow
        msg.sender.transfer(amount);
    }
    '''
    result = detector.scan(code_solidity, "solidity")
    print(f"Result: {'VULNERABLE' if result.vulnerable else 'SAFE'}")
    print(f"Confidence: {result.confidence:.3f}")
    print(f"Risk: {result.risk_level}")

if __name__ == "__main__":
    main()