# IEEE DataPort Upload Guide

## Step-by-Step Upload Process

### 1. Access IEEE DataPort
- Visit: https://ieee-dataport.org/
- Login with IEEE account (create if needed)
- Click "Submit Dataset" or "Upload Data"

### 2. Dataset Information to Enter

**Title:**
```
Security Intelligence Framework: Vulnerability Detection Dataset and Reproducibility Package
```

**Description:**
```
Comprehensive dataset and reproducibility package for the Security Intelligence Framework research presented in IEEE TDSC submission "Security Intelligence Framework: A Unified Mathematical Approach for Autonomous Vulnerability Detection".

This package includes:
- 50,000+ labeled vulnerability samples across multiple programming languages
- Real CVE case studies (Log4j, Heartbleed, Struts2, Citrix ADC, Zerologon)
- Complete reproducibility environment with Docker containerization
- Evaluation datasets for statistical validation
- Synthetic vulnerability generation templates
- Configuration files and documentation

The dataset enables reproduction of all experimental results presented in the manuscript, including the 98.5% precision and 97.1% recall performance metrics, statistical significance testing, and real-world validation on 12.35 million lines of production code.
```

**Keywords/Tags:**
```
vulnerability detection, machine learning, security, formal methods, reproducibility, CVE, static analysis, neural networks
```

**Subject Categories:**
- Computer Science
- Security
- Machine Learning
- Software Engineering

**License:**
```
MIT License - Open access for research and commercial use
```

### 3. Author Information

**Primary Author:**
- Name: Ankit Thakur
- Affiliation: Independent Researcher
- Email: ankit.thakur.research@gmail.com
- Location: Jakarta, Indonesia

### 4. Files to Upload

**Core Dataset Files:**
- `vulnerability_samples.csv` (labeled vulnerability dataset)
- `cve_case_studies.json` (real CVE examples)
- `evaluation_results.json` (complete experimental results)

**Reproducibility Package:**
- `Dockerfile` (containerized environment)
- `requirements.txt` (Python dependencies)
- `smoke_test.py` (quick validation script)
- `run_full_evaluation.py` (complete reproduction script)

**Documentation:**
- `README.md` (comprehensive usage guide)
- `REPRODUCTION_GUIDE.md` (step-by-step reproduction)
- `DATA_DESCRIPTION.md` (dataset format and structure)
- `VALIDATION_PROTOCOL.md` (evaluation methodology)

**Configuration:**
- `config/` directory with all configuration files
- `scripts/` directory with utility scripts

### 5. Upload Process

1. **Create New Dataset Entry**
2. **Fill Required Fields** (use information above)
3. **Upload Files** (drag and drop or browse)
4. **Add Documentation** (README and descriptions)
5. **Set Permissions** (public access)
6. **Review and Submit**

### 6. Post-Upload Actions

1. **Obtain DOI** - Will appear on right side of dataset page
2. **Copy DOI** - Format: 10.21227/xxxx-xxxx
3. **Update IEEE TDSC Submission** - Enter DOI in submission portal
4. **Verify Public Access** - Check dataset is accessible

## Expected DataPort Information

**Dataset Size:** ~2.5 GB
**Upload Time:** 15-30 minutes (depending on connection)
**Processing Time:** 24-48 hours for public availability
**DOI Assignment:** Immediate upon successful upload

## Files Already Prepared for Upload

The following files are ready in your local directory and should be uploaded to DataPort:

### Primary Dataset Files
- CVE case studies in `case_studies/`
- Evaluation data in `data/`
- Test cases in `tests/`

### Reproducibility Files
- `Dockerfile` (ready for upload)
- `smoke_test.py` (validation script)
- Configuration files in `config/`
- Source code in `src/` (core framework)

### Documentation
- `README_FOR_REVIEWERS.md` (reviewer guide)
- `DATAPORT_INFORMATION.md` (this upload guide)

## Troubleshooting

**Common Issues:**
- File size limits: Break large files into chunks if needed
- Upload timeout: Use stable internet connection
- Format issues: Ensure files are in accepted formats

**Support:**
- IEEE DataPort Support: dataport@ieee.org
- Upload Issues: Use DataPort help center
- Technical Questions: Contact via support portal

## After DOI Assignment

Once you receive the DataPort DOI:

1. **Update IEEE TDSC Submission Portal:**
   - Enter DOI in "DOI for your data/dataset" field
   - Enter title in "Title of your data/dataset" field

2. **Reference in Manuscript (if needed):**
   ```
   The complete dataset and reproducibility package are available at IEEE DataPort [DOI: 10.21227/xxxx-xxxx].
   ```

3. **Include in Cover Letter:**
   - Mention DataPort availability
   - Emphasize reproducibility commitment
   - Highlight open science contribution

## Contact Information

**For Upload Issues:**
- Email: dataport@ieee.org
- IEEE DataPort Help Center

**For Dataset Questions:**
- Primary Contact: ankit.thakur.research@gmail.com
- Research Inquiry: ankit.thakur.research@gmail.com