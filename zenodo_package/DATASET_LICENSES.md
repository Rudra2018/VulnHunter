# Dataset Licenses and Attribution

## Security Intelligence Framework - Data Usage Rights

---

## 1. Primary Datasets

### 1.1 Synthetic Vulnerability Dataset

**Source:** Generated for this research project
**License:** MIT License (same as project)
**Size:** 15 samples in `data/minimal_dataset.csv`
**Attribution:**
```
Security Intelligence Framework Synthetic Dataset
Copyright (c) 2024 Halodoc LLP
Licensed under MIT License
```

**Usage Rights:**
- ✅ Academic research
- ✅ Commercial use
- ✅ Modification and redistribution
- ✅ Private use

**Redistribution Requirements:**
- Include original license notice
- Cite original research paper
- Maintain attribution in derivative works

### 1.2 Real CVE Case Studies

**Source:** Public CVE database and open-source projects
**License:** Various (see individual CVE listings below)
**Size:** 5 major CVE examples
**Purpose:** Research validation and educational use

**Legal Basis:**
- Public CVE records (no copyright restrictions)
- Open-source code snippets (respective project licenses)
- Fair use for academic research
- Educational and security improvement purposes

---

## 2. Third-Party Code Licenses

### 2.1 CVE-2021-44228 (Log4j)

**Source:** Apache Log4j Project
**Original License:** Apache License 2.0
**Usage:** Code snippets for vulnerability demonstration
**Attribution:**
```
Apache Log4j
Copyright 1999-2021 Apache Software Foundation
Licensed under the Apache License, Version 2.0
```

**Code Snippet License:**
```apache
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
```

### 2.2 CVE-2014-0160 (OpenSSL Heartbleed)

**Source:** OpenSSL Project
**Original License:** OpenSSL License (Apache-style)
**Usage:** Code snippets for vulnerability analysis
**Attribution:**
```
OpenSSL Project
Copyright (c) 1998-2014 The OpenSSL Project
Licensed under OpenSSL License
```

**Usage Justification:**
- Academic research purpose
- Small code snippets for illustration
- Educational and security improvement
- Fair use under copyright law

### 2.3 CVE-2017-5638 (Apache Struts2)

**Source:** Apache Struts Project
**Original License:** Apache License 2.0
**Usage:** Vulnerability pattern analysis
**Attribution:**
```
Apache Struts
Copyright 2000-2017 The Apache Software Foundation
Licensed under the Apache License, Version 2.0
```

### 2.4 CVE-2019-19781 (Citrix ADC)

**Source:** Public security advisories and PoC code
**License:** Various (public domain, research use)
**Usage:** Security research and educational purposes
**Attribution:**
```
Based on public security research and CVE database records
No copyright restrictions on CVE information
Educational use for security improvement
```

### 2.5 CVE-2020-1472 (Windows Zerologon)

**Source:** Microsoft security advisories and research
**License:** Public domain (security advisory information)
**Usage:** Security research and vulnerability pattern analysis
**Attribution:**
```
Microsoft Security Advisory
CVE-2020-1472 Zerologon Information
Public domain security information
```

---

## 3. Machine Learning Model Data

### 3.1 Pre-trained Models

**CodeBERT (microsoft/codebert-base)**
- **License:** MIT License
- **Source:** Microsoft Research
- **Usage:** Base model for code understanding
- **Attribution:** Feng et al., "CodeBERT: A Pre-Trained Model for Programming and Natural Languages"

**CodeLlama**
- **License:** Custom License (research use allowed)
- **Source:** Meta AI Research
- **Usage:** LLM-enhanced vulnerability analysis
- **Restrictions:** Research and educational use only

### 3.2 Training Data Sources

**GitHub Public Repositories**
- **License:** Various open-source licenses
- **Usage:** Code pattern analysis (anonymized)
- **Compliance:** Only open-source projects with permissive licenses
- **Privacy:** No personal or proprietary code included

**CVE Database**
- **License:** Public domain
- **Source:** MITRE Corporation CVE database
- **Usage:** Vulnerability classification and validation
- **Attribution:** CVE database maintained by MITRE Corporation

---

## 4. External Tools and Dependencies

### 4.1 Static Analysis Tools

**CodeQL**
- **License:** GitHub CodeQL Terms and Conditions
- **Usage:** Baseline comparison only
- **Restrictions:** Research use within GitHub's terms

**Semgrep**
- **License:** LGPL 2.1 (open-source version)
- **Usage:** Comparative evaluation
- **Attribution:** r2c Inc.

**SonarQube**
- **License:** LGPL v3 (Community Edition)
- **Usage:** Research comparison
- **Attribution:** SonarSource SA

### 4.2 Python Dependencies

**PyTorch**
- **License:** BSD-3-Clause
- **Attribution:** Facebook, Inc. and its affiliates

**Transformers (Hugging Face)**
- **License:** Apache 2.0
- **Attribution:** Hugging Face Inc.

**Scikit-learn**
- **License:** BSD-3-Clause
- **Attribution:** scikit-learn developers

**NumPy**
- **License:** BSD-3-Clause
- **Attribution:** NumPy developers

---

## 5. Data Usage Compliance

### 5.1 Academic Research Rights

**Fair Use Justification:**
- Research and educational purpose
- Transformative use for security improvement
- Limited scope and attribution provided
- No commercial exploitation of third-party code

**Legal Compliance:**
- DMCA safe harbor provisions
- Fair use under copyright law
- Academic research exemptions
- International research agreements

### 5.2 Commercial Use Restrictions

**Limitations for Commercial Deployment:**
- Third-party model licenses may restrict commercial use
- CVE database information is public domain
- Synthetic data available for commercial use
- Check individual component licenses before commercial deployment

### 5.3 Redistribution Guidelines

**When Redistributing This Research:**

1. **Include all license notices** from this file
2. **Maintain attribution** to original sources
3. **Respect third-party licenses** for components
4. **Follow responsible disclosure** guidelines
5. **Cite original research** paper and repository

**Required Attribution Format:**
```bibtex
@article{thakur2024security,
  title={Security Intelligence Framework: A Unified Mathematical Approach for Autonomous Vulnerability Detection},
  author={Thakur, Ankit},
  journal={IEEE Symposium on Security and Privacy},
  year={2024},
  publisher={IEEE}
}
```

---

## 6. Contact for Licensing Questions

**For dataset licensing questions:**
- **Email:** legal@halodoc.com
- **Research Contact:** ankit.thakur@halodoc.com
- **Institution:** Halodoc LLP Technology Innovation Division

**For commercial licensing:**
- **Email:** enterprise@halodoc.com
- **Subject:** Security Intelligence Framework Commercial License

**For academic collaboration:**
- **Email:** research@halodoc.com
- **Subject:** Academic Research Collaboration Request

---

## 7. Compliance Verification

### 7.1 License Compatibility Matrix

| Component | License | Commercial Use | Attribution Required | Redistribution Allowed |
|-----------|---------|----------------|---------------------|----------------------|
| Framework Code | MIT | ✅ Yes | ✅ Required | ✅ Yes |
| Synthetic Data | MIT | ✅ Yes | ✅ Required | ✅ Yes |
| CVE Information | Public Domain | ✅ Yes | ❌ Optional | ✅ Yes |
| CodeBERT | MIT | ✅ Yes | ✅ Required | ✅ Yes |
| CodeLlama | Custom | ⚠️ Research Only | ✅ Required | ⚠️ Restricted |
| Real Code Snippets | Various | ⚠️ Check Individual | ✅ Required | ⚠️ Check Individual |

### 7.2 Compliance Checklist

**Before using this dataset:**
- [ ] Read and understand all license terms
- [ ] Verify compliance with intended use case
- [ ] Prepare proper attribution statements
- [ ] Check commercial use restrictions if applicable
- [ ] Review responsible disclosure requirements

**For academic use:**
- [ ] Cite original research paper
- [ ] Include dataset attribution in publications
- [ ] Follow institutional research ethics guidelines
- [ ] Respect third-party data sources

**For commercial use:**
- [ ] Review commercial license compatibility
- [ ] Obtain necessary permissions for restricted components
- [ ] Implement proper attribution in products
- [ ] Consider purchasing commercial licenses where needed

---

**Last Updated:** October 1, 2024
**Version:** 1.0.0
**Legal Review:** Completed