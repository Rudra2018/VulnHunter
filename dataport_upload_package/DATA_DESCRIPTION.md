# Data Description and Dictionary

## Dataset Overview

**Dataset Name:** Security Intelligence Framework: Vulnerability Detection Dataset and Reproducibility Package
**Version:** 1.0
**Size:** ~2.5 GB
**Samples:** 50,000+ labeled vulnerability instances
**Languages:** C, Java, JavaScript, Python, C#

## File Structure

```
dataport_upload_package/
├── README.md                    # Main documentation
├── README_FOR_REVIEWERS.md      # Reviewer guide
├── DATA_DESCRIPTION.md          # This file
├── REPRODUCTION_GUIDE.md        # Reproduction instructions
├── Dockerfile                   # Containerized environment
├── smoke_test.py               # Quick validation script
├── case_studies/               # Real CVE examples
│   ├── cve_2021_44228_log4j.py
│   ├── cve_2014_0160_heartbleed.py
│   ├── cve_2017_5638_struts2.py
│   ├── cve_2019_19781_citrix.py
│   └── cve_2020_1472_zerologon.py
├── data/                       # Primary dataset
│   ├── vulnerability_samples.csv
│   ├── evaluation_results.json
│   └── minimal_dataset.csv
├── config/                     # Configuration files
│   ├── model_config.yaml
│   ├── evaluation_config.yaml
│   └── security_config.yaml
└── tests/                      # Test suite
    ├── test_secure_runner.py
    ├── test_llm_detector.py
    └── test_integration.py
```

## Data Dictionary

### Primary Dataset: vulnerability_samples.csv

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| `id` | int | Unique sample identifier | 1, 2, 3... |
| `code` | string | Source code snippet | "SELECT * FROM users WHERE..." |
| `language` | string | Programming language | "java", "c", "python", "javascript", "csharp" |
| `vulnerability_type` | string | Type of vulnerability | "sql_injection", "xss", "buffer_overflow" |
| `label` | int | Binary label (0=secure, 1=vulnerable) | 0, 1 |
| `confidence` | float | Expert annotation confidence | 0.85, 0.92, 0.98 |
| `source` | string | Sample origin | "synthetic", "cve", "academic" |
| `complexity` | int | Cyclomatic complexity | 1, 5, 12 |
| `loc` | int | Lines of code | 10, 25, 150 |
| `severity` | string | Vulnerability severity | "low", "medium", "high", "critical" |

### CVE Case Studies: JSON Format

```json
{
  "cve_id": "CVE-2021-44228",
  "title": "Apache Log4j Remote Code Execution",
  "vulnerability_type": "remote_code_execution",
  "cvss_score": 10.0,
  "description": "Apache Log4j2 JNDI features...",
  "vulnerable_code": "logger.info(\"User input: {}\", userInput);",
  "fixed_code": "logger.info(\"User input: {}\", Encode.forJava(userInput));",
  "detection_confidence": 0.98,
  "framework_result": {
    "formal_analysis": true,
    "ml_prediction": 0.97,
    "llm_reasoning": "High confidence RCE pattern detected",
    "combined_score": 0.98
  }
}
```

### Evaluation Results: evaluation_results.json

```json
{
  "overall_metrics": {
    "precision": 0.985,
    "recall": 0.971,
    "f1_score": 0.978,
    "auc_roc": 0.992,
    "false_positive_rate": 0.006
  },
  "by_vulnerability_type": {
    "sql_injection": {"precision": 0.992, "recall": 0.989},
    "xss": {"precision": 0.987, "recall": 0.975},
    "buffer_overflow": {"precision": 0.968, "recall": 0.963}
  },
  "statistical_tests": {
    "mcnemar_chi2": 156.7,
    "p_value": "<0.001",
    "cohens_d": 2.34,
    "bootstrap_ci": {"precision": [0.982, 0.988], "recall": [0.968, 0.974]}
  }
}
```

## Vulnerability Type Categories

### 1. SQL Injection (25% of dataset)
- **Pattern**: Direct SQL query construction with user input
- **Languages**: Java, C#, Python, JavaScript
- **Severity**: Medium to Critical
- **Examples**: String concatenation, prepared statement misuse

### 2. Cross-Site Scripting (20% of dataset)
- **Pattern**: Unescaped user input in HTML output
- **Languages**: JavaScript, Java, C#, Python
- **Severity**: Medium to High
- **Examples**: DOM manipulation, template injection

### 3. Buffer Overflow (17.5% of dataset)
- **Pattern**: Unsafe memory operations
- **Languages**: C, C++
- **Severity**: High to Critical
- **Examples**: strcpy, gets, buffer overruns

### 4. Authentication Issues (15% of dataset)
- **Pattern**: Weak authentication logic
- **Languages**: All supported languages
- **Severity**: Medium to High
- **Examples**: Hardcoded credentials, weak validation

### 5. Path Traversal (12.5% of dataset)
- **Pattern**: Unvalidated file path construction
- **Languages**: Java, C#, Python, JavaScript
- **Severity**: Medium to High
- **Examples**: Directory traversal, file inclusion

### 6. Other Vulnerabilities (10% of dataset)
- **Includes**: Command injection, LDAP injection, XML injection
- **Languages**: Mixed
- **Severity**: Variable

## Quality Assurance

### Expert Validation
- **Validators**: 3 independent security experts
- **Agreement**: κ = 0.92 (excellent inter-rater reliability)
- **Process**: Blind review with consensus resolution
- **False Label Rate**: <0.5%

### Automated Checks
- **Duplicate Detection**: Semantic similarity analysis
- **Syntax Validation**: Language-specific parsing
- **Complexity Analysis**: Automated metrics calculation
- **Consistency Checks**: Cross-validation of labels

## Usage Guidelines

### Recommended Splits
- **Training**: 70% (35,000 samples)
- **Validation**: 15% (7,500 samples)
- **Testing**: 15% (7,500 samples)

### Evaluation Protocol
1. **Stratified Sampling**: Maintain vulnerability type distribution
2. **Cross-Validation**: 5-fold stratified recommended
3. **Statistical Testing**: McNemar's test for significance
4. **Confidence Intervals**: Bootstrap with 10,000 iterations

### Performance Baselines
- **Random Classifier**: 50% accuracy
- **Simple Rule-based**: 65-70% accuracy
- **Commercial Tools**: 75-85% F1-score
- **Our Framework**: 97.8% F1-score

## Ethical Considerations

### Responsible Use
- Dataset intended for defensive security research only
- No offensive exploitation capabilities included
- Educational and research purposes prioritized

### Privacy Protection
- No personal or proprietary information included
- All samples are synthetic or from public sources
- GDPR compliance maintained

### Licensing
- MIT License allows commercial and research use
- Attribution required for academic publications
- Redistribution permitted with license retention

## Contact and Support

### Primary Contact
- **Author**: Ankit Thakur
- **Email**: ankit.thakur.research@gmail.com
- **Response Time**: 24-48 hours for technical questions

### Common Issues
- **Large File Handling**: Use provided Docker environment
- **Memory Requirements**: 16+ GB RAM recommended
- **Performance**: Multi-core processing recommended
- **Dependencies**: Use containerized environment for consistency

### Citation
```bibtex
@dataset{thakur2024security_dataset,
  title={Security Intelligence Framework: Vulnerability Detection Dataset and Reproducibility Package},
  author={Thakur, Ankit},
  publisher={IEEE DataPort},
  year={2024},
  doi={10.21227/xxxx-xxxx}
}
```