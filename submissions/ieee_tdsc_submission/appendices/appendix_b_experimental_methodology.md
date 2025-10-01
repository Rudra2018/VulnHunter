# Appendix B: Detailed Experimental Methodology

## B.1 Complete Dataset Description

### B.1.1 Synthetic Vulnerability Dataset
- **Generation Method:** Systematic vulnerability injection using AST manipulation
- **Categories:** 15 vulnerability types with balanced representation
- **Validation:** Expert review with inter-annotator agreement κ > 0.85
- **Quality Control:** Automated compilation and testing verification

### B.1.2 Real-World Dataset Collection
- **Source Selection:** GitHub repositories with >1000 stars and active maintenance
- **CVE Mapping:** Direct association with known CVE identifiers
- **Temporal Coverage:** 2015-2024 vulnerability reports
- **Language Distribution:** C/C++ (35%), Java (25%), Python (20%), JavaScript (15%), Go (5%)

## B.2 Statistical Analysis Methodology

### B.2.1 Power Analysis
- **Effect Size:** Medium effect (d = 0.5) targeted for practical significance
- **Power:** 80% minimum to detect significant differences
- **Sample Size:** 50,000+ samples ensures adequate power across vulnerability categories
- **Alpha Level:** 0.001 for strong statistical evidence

### B.2.2 Multiple Testing Correction
Applied Bonferroni correction for family-wise error rate control:
α_corrected = α / k
Where k is the number of simultaneous comparisons.

### B.2.3 Bootstrap Confidence Intervals
- **Iterations:** 10,000 bootstrap samples
- **Method:** Percentile method with bias-corrected acceleration
- **Coverage:** 95% confidence intervals for all primary metrics

## B.3 Baseline Tool Configuration

### B.3.1 CodeQL Configuration
- **Version:** 2.15.2 (latest at time of evaluation)
- **Query Packs:** security-extended.qls with all available queries
- **Database Creation:** Standard build with full dependency resolution
- **Analysis Mode:** Deep analysis with maximum sensitivity

### B.3.2 Commercial Tool Settings
All commercial tools configured according to vendor documentation:
- Maximum sensitivity settings enabled
- All available rule packs activated
- Language-specific optimizations applied
- Expert consultation for optimal configuration

## B.4 Real-World Validation Protocol

### B.4.1 Expert Review Process
- **Reviewers:** 3 independent security experts with >5 years experience
- **Review Criteria:** Exploitability, impact, and confidence assessment
- **Disagreement Resolution:** Consensus meeting with detailed technical discussion
- **Documentation:** Complete justification for all classification decisions

### B.4.2 False Positive Analysis
- **Classification:** Manual inspection of all reported vulnerabilities
- **Categories:** True positive, false positive, unclear/disputed
- **Justification:** Detailed technical explanation for each classification
- **Validation:** Independent verification by second expert

## B.5 Performance Measurement

### B.5.1 Timing Methodology
- **Environment:** Standardized cloud instances (AWS c5.4xlarge)
- **Measurement:** Wall-clock time with warm-up period
- **Statistics:** Median of 5 runs with outlier detection
- **Resource Monitoring:** CPU, memory, and I/O utilization tracking

### B.5.2 Scalability Testing
- **Code Sizes:** Logarithmic scaling from 1K to 10M lines of code
- **Resource Scaling:** Linear resource allocation testing
- **Concurrency:** Multi-threaded performance evaluation
- **Memory Profiling:** Peak and sustained memory usage analysis
