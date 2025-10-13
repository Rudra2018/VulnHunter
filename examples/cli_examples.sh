#!/bin/bash
# VulnHunter CLI Integration Examples

echo "🛠️  VulnHunter CLI Integration Examples"
echo "========================================"

# Make sure we're in the right directory
cd /Users/ankitthakur/vuln_ml_research

echo ""
echo "1️⃣  Show Model Statistics"
echo "------------------------"
python3 vulnhunter_cli.py stats

echo ""
echo "2️⃣  Create Sample Analysis Files"
echo "--------------------------------"
mkdir -p examples/sample_analyses

# Create fabricated analysis sample
cat << 'EOF' > examples/sample_analyses/fabricated_analysis.json
{
  "security_analysis": {
    "tool": "FakeSecurityScanner",
    "version": "3.1.0",
    "scan_timestamp": "2025-10-13T14:30:00Z",
    "target_repository": "example/vulnerable-app",
    "vulnerabilities_found": 1847,
    "critical_vulnerabilities": 127,
    "vulnerability_details": [
      {
        "cve_id": "CVE-2025-FAKE1",
        "severity": "CRITICAL",
        "description": "Impossible buffer overflow in non-existent function",
        "file_path": "src/nonexistent/fake.cpp",
        "line_numbers": [999999, 1000001],
        "code_snippet": "impossible_function(overflow_data, SIZE_MAX);",
        "exploit_likelihood": 1.0
      }
    ],
    "confidence_metrics": {
      "overall_confidence": 0.99,
      "false_positive_rate": 0.001,
      "detection_accuracy": 0.999
    }
  },
  "metadata": {
    "analysis_type": "automated_scan",
    "analyst": "AI-Fabricator-Bot"
  }
}
EOF

# Create optimistic analysis sample
cat << 'EOF' > examples/sample_analyses/optimistic_analysis.json
{
  "security_analysis": {
    "tool": "BountyMaximizer",
    "version": "2.8.0",
    "scan_timestamp": "2025-10-13T15:00:00Z",
    "target_programs": ["Microsoft", "Google", "Apple", "Meta", "Tesla"],
    "total_opportunities": 5234,
    "estimated_total_value": 15750000,
    "confidence_metrics": {
      "success_probability": 0.95,
      "average_payout": 3010,
      "market_saturation": 0.15
    },
    "projections": {
      "monthly_revenue": 450000,
      "annual_roi": 680,
      "market_growth": 0.89
    }
  },
  "metadata": {
    "analysis_type": "market_opportunity",
    "analyst": "OptiMax-AI",
    "confidence_level": "EXTREME"
  }
}
EOF

# Create legitimate analysis sample
cat << 'EOF' > examples/sample_analyses/legitimate_analysis.json
{
  "security_analysis": {
    "tool": "OWASP ZAP",
    "version": "2.12.0",
    "scan_timestamp": "2025-10-13T16:00:00Z",
    "target": "https://testsite.example.com",
    "vulnerabilities_found": 4,
    "findings": [
      {
        "type": "Missing Security Headers",
        "severity": "MEDIUM",
        "description": "X-Content-Type-Options header not set",
        "location": "/login",
        "recommendation": "Add X-Content-Type-Options: nosniff header"
      },
      {
        "type": "Weak Password Policy",
        "severity": "LOW",
        "description": "Password minimum length is 6 characters",
        "location": "/register",
        "recommendation": "Increase minimum password length to 8+ characters"
      },
      {
        "type": "Information Disclosure",
        "severity": "LOW",
        "description": "Server version exposed in HTTP headers",
        "recommendation": "Configure server to hide version information"
      },
      {
        "type": "Session Management",
        "severity": "MEDIUM",
        "description": "Session timeout not configured",
        "recommendation": "Set session timeout to 30 minutes"
      }
    ]
  },
  "metadata": {
    "analysis_type": "web_application_scan",
    "analyst": "security-team@example.com",
    "scan_duration": "45 minutes",
    "verified": true
  }
}
EOF

echo "✅ Sample analysis files created in examples/sample_analyses/"

echo ""
echo "3️⃣  Validate Single Analysis (Fabricated)"
echo "-----------------------------------------"
python3 vulnhunter_cli.py validate examples/sample_analyses/fabricated_analysis.json --format summary

echo ""
echo "4️⃣  Validate Single Analysis (Optimistic)"
echo "-----------------------------------------"
python3 vulnhunter_cli.py validate examples/sample_analyses/optimistic_analysis.json --format detailed

echo ""
echo "5️⃣  Validate Single Analysis (Legitimate)"
echo "-----------------------------------------"
python3 vulnhunter_cli.py validate examples/sample_analyses/legitimate_analysis.json --format summary

echo ""
echo "6️⃣  Batch Validation"
echo "-------------------"
python3 vulnhunter_cli.py batch-validate examples/sample_analyses/ --output examples/validation_results/ --format summary

echo ""
echo "7️⃣  JSON Output Example"
echo "-----------------------"
echo "Getting JSON output for API integration:"
python3 vulnhunter_cli.py validate examples/sample_analyses/fabricated_analysis.json --format json | head -20
echo "... (truncated for brevity)"

echo ""
echo "8️⃣  Validation Results"
echo "---------------------"
if [ -d "examples/validation_results" ]; then
    echo "Batch validation results saved to:"
    ls -la examples/validation_results/
    echo ""
    echo "Summary file contents:"
    if [ -f "examples/validation_results/batch_validation_summary.json" ]; then
        python3 -c "import json; data=json.load(open('examples/validation_results/batch_validation_summary.json')); print(f'Total: {data[\"total_files\"]}, Successful: {data[\"successful\"]}, Failed: {data[\"failed\"]}')"
    fi
fi

echo ""
echo "9️⃣  Integration with Other Tools"
echo "-------------------------------"
echo "# Example: Integrate with CI/CD pipeline"
echo "# In your .github/workflows/security.yml:"
echo ""
cat << 'EOF'
name: Security Analysis Validation
on: [push, pull_request]

jobs:
  validate-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install VulnHunter
        run: pip install -r requirements.txt
      - name: Validate Security Analyses
        run: |
          python3 vulnhunter_cli.py batch-validate security_reports/ \
            --output validation_results/ \
            --format json
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: validation-results
          path: validation_results/
EOF

echo ""
echo "🔟 Advanced Usage Examples"
echo "-------------------------"
echo "# Train model with new data:"
echo "python3 vulnhunter_cli.py train"
echo ""
echo "# Validate with custom output directory:"
echo "python3 vulnhunter_cli.py batch-validate /path/to/analyses/ -o /custom/output/"
echo ""
echo "# JSON output for programmatic use:"
echo "python3 vulnhunter_cli.py validate analysis.json --format json | jq '.overall_assessment.primary_classification'"

echo ""
echo "✅ CLI Examples Complete!"
echo ""
echo "📖 Next Steps:"
echo "- Review validation results in examples/validation_results/"
echo "- Integrate CLI commands into your security workflow"
echo "- Use JSON output format for programmatic integration"
echo "- Set up automated validation in CI/CD pipelines"