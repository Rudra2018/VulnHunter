# Reproduction Guide

## Quick Start (30 Minutes)

### Prerequisites
- Docker installed and running
- 16+ GB RAM available
- 8+ CPU cores recommended
- 50+ GB free disk space

### Step 1: Build Environment
```bash
# Clone or download the dataset
cd dataport_upload_package/

# Build Docker image
docker build -t security-intelligence-framework .
```

### Step 2: Run Smoke Tests
```bash
# Run basic validation
docker run --rm security-intelligence-framework python smoke_test.py
```

**Expected Output:**
```
🔧 Security Intelligence Framework - Smoke Test
=====================================================
✅ Environment validation passed
✅ Dependencies loaded successfully
✅ SecureRunner framework operational
✅ LLM components accessible
✅ Sample vulnerability detection working
✅ All critical components functional

🎯 Smoke test completed successfully!
Time: 2.3 minutes
```

## Standard Evaluation (2 Hours)

### Step 1: Run Representative Evaluation
```bash
# Run evaluation on representative sample
docker run --rm -v $(pwd)/results:/app/results \
  security-intelligence-framework \
  python run_evaluation.py --mode representative
```

### Step 2: Expected Results
The evaluation should produce metrics close to:
- **Precision**: 98.5% (±0.3%)
- **Recall**: 97.1% (±0.3%)
- **F1-Score**: 97.8% (±0.3%)
- **Processing Speed**: ~1.2 seconds per 1000 LOC

### Step 3: View Results
```bash
# Check generated reports
ls results/
# evaluation_report.json
# performance_metrics.csv
# detailed_analysis.html
```

## Full Reproduction (4 Hours)

### Step 1: Complete Statistical Validation
```bash
# Run full evaluation with statistical testing
docker run --rm -v $(pwd)/results:/app/results \
  security-intelligence-framework \
  python run_full_evaluation.py
```

### Step 2: Real CVE Case Studies
```bash
# Test on real CVE examples
docker run --rm -v $(pwd)/results:/app/results \
  security-intelligence-framework \
  python validate_cve_cases.py
```

### Step 3: Performance Benchmarking
```bash
# Run scalability tests
docker run --rm -v $(pwd)/results:/app/results \
  security-intelligence-framework \
  python benchmark_performance.py
```

## Advanced Reproduction

### Custom Dataset Testing
```bash
# Test on your own code samples
docker run --rm -v /path/to/your/code:/app/custom_data \
  -v $(pwd)/results:/app/results \
  security-intelligence-framework \
  python analyze_custom_code.py --input /app/custom_data
```

### Comparison with Other Tools
```bash
# Compare against baseline tools (requires tool installations)
docker run --rm -v $(pwd)/results:/app/results \
  security-intelligence-framework \
  python comparative_analysis.py --tools codeql,semgrep
```

## Troubleshooting

### Common Issues

#### Docker Build Fails
```bash
# Check Docker version
docker --version
# Should be 20.0+

# Clean Docker cache if needed
docker system prune -a
```

#### Memory Errors
```bash
# Check available memory
free -h

# Reduce batch size for limited memory
docker run --rm -e BATCH_SIZE=32 \
  security-intelligence-framework \
  python smoke_test.py
```

#### Slow Performance
```bash
# Use multi-threading
docker run --rm -e NUM_WORKERS=8 \
  security-intelligence-framework \
  python run_evaluation.py
```

#### Missing Results
```bash
# Check logs
docker run --rm security-intelligence-framework \
  cat /app/logs/evaluation.log

# Verify output directory permissions
ls -la results/
```

### Hardware Optimization

#### For Limited Resources (8GB RAM)
```bash
# Use lightweight configuration
docker run --rm -e CONFIG=lightweight \
  security-intelligence-framework \
  python smoke_test.py
```

#### For High-Performance Systems (32GB+ RAM)
```bash
# Use high-performance configuration
docker run --rm -e CONFIG=performance \
  -e NUM_WORKERS=16 \
  security-intelligence-framework \
  python run_full_evaluation.py
```

## Validation Checklist

### Basic Validation (Required)
- [ ] Docker environment builds successfully (5 minutes)
- [ ] Smoke tests pass completely (30 minutes)
- [ ] Sample detection produces expected confidence scores
- [ ] All test cases execute without errors

### Standard Validation (Recommended)
- [ ] Representative evaluation completes (2 hours)
- [ ] Performance metrics match paper within ±1%
- [ ] CVE case studies produce correct classifications
- [ ] Processing speed meets benchmarks

### Complete Validation (Optional)
- [ ] Full statistical validation completes (4 hours)
- [ ] Bootstrap confidence intervals calculated
- [ ] McNemar's test confirms significance (p < 0.001)
- [ ] Scalability tests pass up to 1M+ LOC

## Configuration Options

### Environment Variables
```bash
# Basic configuration
CONFIG=standard          # standard, lightweight, performance
BATCH_SIZE=64            # 16, 32, 64, 128
NUM_WORKERS=8            # 1, 4, 8, 16
LOG_LEVEL=INFO           # DEBUG, INFO, WARNING, ERROR

# Advanced configuration
ENABLE_FORMAL=true       # Enable formal verification
ENABLE_LLM=true          # Enable LLM reasoning
ENABLE_STATS=true        # Enable statistical validation
OUTPUT_FORMAT=json       # json, csv, html
```

### Example Usage
```bash
docker run --rm \
  -e CONFIG=performance \
  -e BATCH_SIZE=128 \
  -e NUM_WORKERS=16 \
  -e LOG_LEVEL=DEBUG \
  -v $(pwd)/results:/app/results \
  security-intelligence-framework \
  python run_full_evaluation.py
```

## Results Interpretation

### Performance Metrics
- **Precision**: Percentage of vulnerability reports that are actual vulnerabilities
- **Recall**: Percentage of actual vulnerabilities that are detected
- **F1-Score**: Harmonic mean of precision and recall
- **AUC-ROC**: Area under the receiver operating characteristic curve

### Statistical Significance
- **p-value < 0.001**: Highly significant improvement over baselines
- **Cohen's d = 2.34**: Large effect size
- **Bootstrap CI**: 95% confidence intervals for metrics

### Processing Performance
- **Speed**: Seconds per 1000 lines of code
- **Memory**: Peak memory usage during analysis
- **Scalability**: Linear scaling demonstrated up to 12.35M LOC

## Support and Contact

### Getting Help
1. **Check Logs**: Always review `/app/logs/` for error details
2. **Verify Environment**: Ensure Docker and system requirements
3. **Review Documentation**: Check README files for specific issues
4. **Contact Support**: Email with specific error messages and system info

### Contact Information
- **Primary Contact**: ankit.thakur.research@gmail.com
- **Subject Line**: "[DataPort] Reproduction Issue - [Brief Description]"
- **Include**: System specs, error logs, reproduction steps attempted

### Response Times
- **Technical Issues**: 24-48 hours
- **Bug Reports**: 1-3 business days
- **Feature Requests**: 1-2 weeks
- **General Questions**: 24 hours

## Continuous Integration

### Automated Testing
```bash
# Run CI-style validation
docker run --rm \
  security-intelligence-framework \
  python run_ci_tests.py
```

### Quality Gates
- All smoke tests must pass
- Performance metrics within 2% of baseline
- No critical security vulnerabilities
- Memory usage within limits
- Processing time within benchmarks

### Version Compatibility
- **Docker**: 20.0+
- **Python**: 3.9+
- **PyTorch**: 1.9+
- **Transformers**: 4.10+

---

For technical support: ankit.thakur.research@gmail.com
For dataset questions: Reference this guide and included documentation