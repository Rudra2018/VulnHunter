# VulnHunter Ωmega + VHS Specialized Modules Usage Guide

## 🎯 Quick Start Examples

### Smart Contract Analysis
```python
from vulnhunter_specialized_modules import SmartContractAnalyzer

# Analyze Solidity contract
with SmartContractAnalyzer(cleanup_policy="moderate") as analyzer:
    result = analyzer.analyze_smart_contract("MyContract.sol")
    print(f"Security Score: {result.security_score}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
```

### Android APK Analysis
```python
from vulnhunter_specialized_modules import MobileSecurityAnalyzer

# Deep APK analysis
with MobileSecurityAnalyzer(cleanup_policy="aggressive") as analyzer:
    result = analyzer.analyze_android_apk("app.apk", deep_analysis=True)
    print(f"Security Issues: {len(result.vulnerabilities)}")
```

## 🔧 Configuration Options

### Cleanup Policies
- **aggressive**: Maximum cleanup, minimal disk usage
- **moderate**: Balanced approach, keep important artifacts
- **minimal**: Keep most analysis data for manual review

### Analysis Depth
- **surface**: Quick pattern-based analysis
- **deep**: Comprehensive analysis with tool integration
- **forensic**: Maximum depth with reverse engineering

## 📊 Output Formats

All analyzers support multiple output formats:
- JSON (detailed results)
- Markdown (executive summary)
- SARIF (for CI/CD integration)
- PDF (for reporting)

## 🛡️ Security Best Practices

1. **Always run in isolated environment**
2. **Use appropriate cleanup policies**
3. **Verify tool dependencies before analysis**
4. **Review results manually for false positives**
5. **Keep analysis logs for audit trails**

## 🔍 Advanced Usage

### Custom Pattern Addition
```python
analyzer.contract_patterns['solidity']['custom_vulnerability'] = [
    r'your_custom_pattern_here'
]
```

### Tool Integration
```python
# Check tool availability
tools_status = analyzer.mobile_tools
print(f"JADX available: {tools_status['jadx']}")
```

### Mathematical Analysis
```python
# Access VHS mathematical results
math_analysis = result.mathematical_analysis
print(f"Topology: {math_analysis['simplicial_complex']}")
print(f"Homotopy: {math_analysis['homotopy_invariants']}")
```
