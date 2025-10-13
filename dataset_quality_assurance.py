#!/usr/bin/env python3
"""
Dataset Quality Assurance System for VulnHunter AI
Implements comprehensive validation and quality checks for vulnerability datasets
"""

import os
import json
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Tuple, Set
from pathlib import Path
import hashlib
import logging
from collections import Counter, defaultdict
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dataset_quality_assurance.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('DatasetQualityAssurance')

class DatasetQualityAssurance:
    """Comprehensive dataset quality assurance and validation system"""

    def __init__(self, datasets_dir: str = "realistic_datasets"):
        self.datasets_dir = Path(datasets_dir)
        self.output_dir = Path("quality_assurance_results")
        self.output_dir.mkdir(exist_ok=True)

        # Quality metrics thresholds
        self.quality_thresholds = {
            "min_code_length": 10,
            "max_duplicate_ratio": 0.05,  # 5% max duplicates
            "min_description_length": 20,
            "max_missing_fields": 0.02,  # 2% max missing fields
            "min_cwe_coverage": 10,  # Minimum CWE types
            "min_language_coverage": 3,  # Minimum languages
            "vulnerability_balance_min": 0.2,  # 20% min vulnerable samples
            "vulnerability_balance_max": 0.8   # 80% max vulnerable samples
        }

        # CWE validation mapping
        self.valid_cwe_patterns = {
            "CWE-22": ["path", "traversal", "directory", "file"],
            "CWE-78": ["command", "injection", "exec", "system"],
            "CWE-79": ["xss", "script", "html", "javascript"],
            "CWE-89": ["sql", "injection", "query", "database"],
            "CWE-119": ["buffer", "overflow", "bounds"],
            "CWE-120": ["buffer", "overflow", "copy"],
            "CWE-125": ["buffer", "read", "bounds"],
            "CWE-190": ["integer", "overflow", "wraparound"],
            "CWE-200": ["information", "disclosure", "exposure"],
            "CWE-327": ["crypto", "weak", "algorithm", "hash"],
            "CWE-362": ["race", "condition", "toctou"],
            "CWE-415": ["double", "free", "memory"],
            "CWE-416": ["use", "after", "free", "dangling"],
            "CWE-476": ["null", "pointer", "dereference"],
            "CWE-502": ["deserialization", "pickle", "unserialize"],
            "CWE-787": ["buffer", "overflow", "write", "bounds"],
            "CWE-862": ["authorization", "access", "permission"]
        }

    def load_dataset(self, dataset_path: str) -> pd.DataFrame:
        """Load dataset from various formats"""

        try:
            path = Path(dataset_path)

            if path.suffix == '.csv':
                df = pd.read_csv(path)
            elif path.suffix == '.json':
                with open(path, 'r') as f:
                    data = json.load(f)
                df = pd.DataFrame(data)
            else:
                raise ValueError(f"Unsupported file format: {path.suffix}")

            logger.info(f"📥 Loaded dataset: {len(df)} records from {path.name}")
            return df

        except Exception as e:
            logger.error(f"❌ Failed to load dataset {dataset_path}: {e}")
            return pd.DataFrame()

    def validate_data_completeness(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Validate data completeness and missing fields"""

        logger.info("🔍 Validating data completeness...")

        required_fields = [
            'cve_id', 'cwe_id', 'severity', 'description', 'code_snippet',
            'language', 'file_path', 'function_name', 'vulnerability_type',
            'is_vulnerable', 'source_dataset'
        ]

        completeness_report = {
            "total_records": len(df),
            "missing_fields": {},
            "empty_fields": {},
            "overall_completeness": 0.0,
            "quality_score": 0.0
        }

        for field in required_fields:
            if field in df.columns:
                missing_count = df[field].isna().sum()
                empty_count = (df[field].astype(str).str.strip() == '').sum()

                completeness_report["missing_fields"][field] = missing_count
                completeness_report["empty_fields"][field] = empty_count

                logger.info(f"  📊 {field}: {missing_count} missing, {empty_count} empty")
            else:
                logger.warning(f"  ⚠️ Required field missing: {field}")
                completeness_report["missing_fields"][field] = len(df)

        # Calculate overall completeness
        total_fields = len(required_fields) * len(df)
        total_missing = sum(completeness_report["missing_fields"].values())
        total_empty = sum(completeness_report["empty_fields"].values())

        completeness_report["overall_completeness"] = 1.0 - (total_missing + total_empty) / total_fields

        # Quality score based on threshold
        missing_ratio = total_missing / total_fields
        if missing_ratio <= self.quality_thresholds["max_missing_fields"]:
            completeness_report["quality_score"] = 1.0
        else:
            completeness_report["quality_score"] = max(0.0, 1.0 - missing_ratio / 0.1)

        logger.info(f"  ✅ Overall completeness: {completeness_report['overall_completeness']:.3f}")
        logger.info(f"  🎯 Quality score: {completeness_report['quality_score']:.3f}")

        return completeness_report

    def detect_duplicates(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Detect and analyze duplicate records"""

        logger.info("🔍 Detecting duplicate records...")

        duplicate_report = {
            "total_records": len(df),
            "exact_duplicates": 0,
            "code_duplicates": 0,
            "description_duplicates": 0,
            "duplicate_ratio": 0.0,
            "quality_score": 0.0,
            "duplicate_samples": []
        }

        # Exact duplicates (all fields)
        exact_duplicates = df.duplicated().sum()
        duplicate_report["exact_duplicates"] = exact_duplicates

        # Code snippet duplicates
        if 'code_snippet' in df.columns:
            code_duplicates = df['code_snippet'].duplicated().sum()
            duplicate_report["code_duplicates"] = code_duplicates

        # Description duplicates
        if 'description' in df.columns:
            desc_duplicates = df['description'].duplicated().sum()
            duplicate_report["description_duplicates"] = desc_duplicates

        # Overall duplicate ratio
        max_duplicates = max(exact_duplicates, code_duplicates, desc_duplicates)
        duplicate_report["duplicate_ratio"] = max_duplicates / len(df)

        # Quality score
        if duplicate_report["duplicate_ratio"] <= self.quality_thresholds["max_duplicate_ratio"]:
            duplicate_report["quality_score"] = 1.0
        else:
            duplicate_report["quality_score"] = max(0.0, 1.0 - duplicate_report["duplicate_ratio"] / 0.2)

        # Sample duplicate records for review
        if exact_duplicates > 0:
            duplicate_indices = df[df.duplicated(keep=False)].index[:10].tolist()
            duplicate_report["duplicate_samples"] = duplicate_indices

        logger.info(f"  📊 Exact duplicates: {exact_duplicates}")
        logger.info(f"  📊 Code duplicates: {code_duplicates}")
        logger.info(f"  📊 Description duplicates: {desc_duplicates}")
        logger.info(f"  📊 Duplicate ratio: {duplicate_report['duplicate_ratio']:.4f}")
        logger.info(f"  🎯 Quality score: {duplicate_report['quality_score']:.3f}")

        return duplicate_report

    def validate_cwe_consistency(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Validate CWE label consistency and accuracy"""

        logger.info("🔍 Validating CWE consistency...")

        cwe_report = {
            "total_vulnerable_records": 0,
            "valid_cwe_mappings": 0,
            "invalid_cwe_mappings": 0,
            "missing_cwe_labels": 0,
            "cwe_coverage": {},
            "inconsistent_mappings": [],
            "quality_score": 0.0
        }

        # Filter vulnerable records
        vuln_records = df[df['is_vulnerable'] == True]
        cwe_report["total_vulnerable_records"] = len(vuln_records)

        if len(vuln_records) == 0:
            logger.warning("  ⚠️ No vulnerable records found")
            return cwe_report

        # Analyze CWE mappings
        for idx, row in vuln_records.iterrows():
            cwe_id = str(row.get('cwe_id', '')).strip()
            vuln_type = str(row.get('vulnerability_type', '')).lower()
            code_snippet = str(row.get('code_snippet', '')).lower()
            description = str(row.get('description', '')).lower()

            if not cwe_id or cwe_id == 'nan':
                cwe_report["missing_cwe_labels"] += 1
                continue

            # Validate CWE format
            if not re.match(r'^CWE-\d+$', cwe_id):
                cwe_report["invalid_cwe_mappings"] += 1
                continue

            # Check if CWE is in our validation set
            if cwe_id in self.valid_cwe_patterns:
                expected_patterns = self.valid_cwe_patterns[cwe_id]

                # Check if any expected pattern appears in code or description
                pattern_found = any(
                    pattern in code_snippet or pattern in description or pattern in vuln_type
                    for pattern in expected_patterns
                )

                if pattern_found:
                    cwe_report["valid_cwe_mappings"] += 1
                    cwe_report["cwe_coverage"][cwe_id] = cwe_report["cwe_coverage"].get(cwe_id, 0) + 1
                else:
                    cwe_report["invalid_cwe_mappings"] += 1
                    cwe_report["inconsistent_mappings"].append({
                        "index": idx,
                        "cwe_id": cwe_id,
                        "vulnerability_type": vuln_type,
                        "expected_patterns": expected_patterns
                    })
            else:
                # Unknown CWE, but count as valid if properly formatted
                cwe_report["valid_cwe_mappings"] += 1
                cwe_report["cwe_coverage"][cwe_id] = cwe_report["cwe_coverage"].get(cwe_id, 0) + 1

        # Calculate quality score
        total_checked = cwe_report["valid_cwe_mappings"] + cwe_report["invalid_cwe_mappings"]
        if total_checked > 0:
            accuracy = cwe_report["valid_cwe_mappings"] / total_checked
            cwe_report["quality_score"] = accuracy
        else:
            cwe_report["quality_score"] = 0.0

        logger.info(f"  📊 Valid CWE mappings: {cwe_report['valid_cwe_mappings']}")
        logger.info(f"  📊 Invalid CWE mappings: {cwe_report['invalid_cwe_mappings']}")
        logger.info(f"  📊 Missing CWE labels: {cwe_report['missing_cwe_labels']}")
        logger.info(f"  📊 CWE coverage: {len(cwe_report['cwe_coverage'])} types")
        logger.info(f"  🎯 Quality score: {cwe_report['quality_score']:.3f}")

        return cwe_report

    def analyze_dataset_distribution(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze dataset distribution and balance"""

        logger.info("🔍 Analyzing dataset distribution...")

        distribution_report = {
            "total_records": len(df),
            "vulnerable_records": 0,
            "safe_records": 0,
            "vulnerability_ratio": 0.0,
            "language_distribution": {},
            "severity_distribution": {},
            "vulnerability_type_distribution": {},
            "source_distribution": {},
            "balance_quality_score": 0.0,
            "diversity_quality_score": 0.0
        }

        # Vulnerability balance
        vuln_count = len(df[df['is_vulnerable'] == True])
        safe_count = len(df[df['is_vulnerable'] == False])

        distribution_report["vulnerable_records"] = vuln_count
        distribution_report["safe_records"] = safe_count
        distribution_report["vulnerability_ratio"] = vuln_count / len(df) if len(df) > 0 else 0

        # Language distribution
        if 'language' in df.columns:
            lang_counts = df['language'].value_counts().to_dict()
            distribution_report["language_distribution"] = lang_counts

        # Severity distribution (for vulnerable records)
        vuln_df = df[df['is_vulnerable'] == True]
        if 'severity' in df.columns and len(vuln_df) > 0:
            severity_counts = vuln_df['severity'].value_counts().to_dict()
            distribution_report["severity_distribution"] = severity_counts

        # Vulnerability type distribution
        if 'vulnerability_type' in df.columns and len(vuln_df) > 0:
            vuln_type_counts = vuln_df['vulnerability_type'].value_counts().to_dict()
            distribution_report["vulnerability_type_distribution"] = vuln_type_counts

        # Source distribution
        if 'source_dataset' in df.columns:
            source_counts = df['source_dataset'].value_counts().to_dict()
            distribution_report["source_distribution"] = source_counts

        # Balance quality score
        vuln_ratio = distribution_report["vulnerability_ratio"]
        if (self.quality_thresholds["vulnerability_balance_min"] <= vuln_ratio <=
            self.quality_thresholds["vulnerability_balance_max"]):
            distribution_report["balance_quality_score"] = 1.0
        else:
            # Penalize based on distance from ideal range
            if vuln_ratio < self.quality_thresholds["vulnerability_balance_min"]:
                distribution_report["balance_quality_score"] = vuln_ratio / self.quality_thresholds["vulnerability_balance_min"]
            else:
                excess = vuln_ratio - self.quality_thresholds["vulnerability_balance_max"]
                distribution_report["balance_quality_score"] = max(0.0, 1.0 - excess / 0.2)

        # Diversity quality score
        num_languages = len(distribution_report["language_distribution"])
        num_vuln_types = len(distribution_report["vulnerability_type_distribution"])

        lang_score = min(1.0, num_languages / self.quality_thresholds["min_language_coverage"])
        vuln_score = min(1.0, num_vuln_types / self.quality_thresholds["min_cwe_coverage"])
        distribution_report["diversity_quality_score"] = (lang_score + vuln_score) / 2

        logger.info(f"  📊 Vulnerable ratio: {vuln_ratio:.3f}")
        logger.info(f"  📊 Languages: {num_languages}")
        logger.info(f"  📊 Vulnerability types: {num_vuln_types}")
        logger.info(f"  🎯 Balance score: {distribution_report['balance_quality_score']:.3f}")
        logger.info(f"  🎯 Diversity score: {distribution_report['diversity_quality_score']:.3f}")

        return distribution_report

    def validate_code_quality(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Validate code snippet quality and characteristics"""

        logger.info("🔍 Validating code quality...")

        code_report = {
            "total_records": len(df),
            "valid_code_samples": 0,
            "empty_code_samples": 0,
            "short_code_samples": 0,
            "avg_code_length": 0.0,
            "language_consistency": {},
            "syntax_issues": [],
            "quality_score": 0.0
        }

        if 'code_snippet' not in df.columns:
            logger.warning("  ⚠️ No code_snippet column found")
            return code_report

        code_lengths = []
        language_mismatches = 0

        for idx, row in df.iterrows():
            code_snippet = str(row.get('code_snippet', '')).strip()
            language = str(row.get('language', '')).strip()

            if not code_snippet or code_snippet == 'nan':
                code_report["empty_code_samples"] += 1
                continue

            code_length = len(code_snippet)
            code_lengths.append(code_length)

            if code_length < self.quality_thresholds["min_code_length"]:
                code_report["short_code_samples"] += 1
            else:
                code_report["valid_code_samples"] += 1

            # Basic language consistency check
            if language:
                if self.check_language_consistency(code_snippet, language):
                    code_report["language_consistency"][language] = code_report["language_consistency"].get(language, 0) + 1
                else:
                    language_mismatches += 1

        # Calculate statistics
        if code_lengths:
            code_report["avg_code_length"] = np.mean(code_lengths)

        # Quality score
        total_valid = code_report["valid_code_samples"]
        total_samples = len(df)

        if total_samples > 0:
            code_quality_ratio = total_valid / total_samples
            language_consistency_ratio = 1.0 - (language_mismatches / total_samples)
            code_report["quality_score"] = (code_quality_ratio + language_consistency_ratio) / 2
        else:
            code_report["quality_score"] = 0.0

        logger.info(f"  📊 Valid code samples: {code_report['valid_code_samples']}")
        logger.info(f"  📊 Empty code samples: {code_report['empty_code_samples']}")
        logger.info(f"  📊 Short code samples: {code_report['short_code_samples']}")
        logger.info(f"  📊 Average code length: {code_report['avg_code_length']:.1f}")
        logger.info(f"  📊 Language mismatches: {language_mismatches}")
        logger.info(f"  🎯 Quality score: {code_report['quality_score']:.3f}")

        return code_report

    def check_language_consistency(self, code_snippet: str, language: str) -> bool:
        """Check if code snippet matches declared language"""

        language_patterns = {
            "Python": [r"def\s+\w+", r"import\s+\w+", r"from\s+\w+", r":\s*$"],
            "Java": [r"public\s+class", r"public\s+static", r"{\s*$", r"}\s*$"],
            "C": [r"#include\s*<", r"int\s+main", r"printf\s*\(", r";\s*$"],
            "C++": [r"#include\s*<", r"using\s+namespace", r"cout\s*<<", r"{\s*$"],
            "JavaScript": [r"function\s+\w+", r"var\s+\w+", r"let\s+\w+", r"=>\s*"],
            "PHP": [r"<\?php", r"\$\w+", r"echo\s+", r"->\s*\w+"],
            "C#": [r"using\s+System", r"public\s+class", r"Console\.Write", r"{\s*$"]
        }

        if language not in language_patterns:
            return True  # Unknown language, assume consistent

        patterns = language_patterns[language]
        matches = sum(1 for pattern in patterns if re.search(pattern, code_snippet, re.MULTILINE))

        # At least one pattern should match
        return matches > 0

    def generate_quality_report(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate comprehensive quality assessment report"""

        logger.info("🔄 GENERATING COMPREHENSIVE QUALITY REPORT")
        logger.info("=" * 70)

        # Run all quality checks
        completeness = self.validate_data_completeness(df)
        duplicates = self.detect_duplicates(df)
        cwe_consistency = self.validate_cwe_consistency(df)
        distribution = self.analyze_dataset_distribution(df)
        code_quality = self.validate_code_quality(df)

        # Calculate overall quality score
        quality_scores = [
            completeness["quality_score"],
            duplicates["quality_score"],
            cwe_consistency["quality_score"],
            distribution["balance_quality_score"],
            distribution["diversity_quality_score"],
            code_quality["quality_score"]
        ]

        overall_quality = np.mean(quality_scores)

        # Determine quality grade
        if overall_quality >= 0.9:
            quality_grade = "A (Excellent)"
        elif overall_quality >= 0.8:
            quality_grade = "B (Good)"
        elif overall_quality >= 0.7:
            quality_grade = "C (Acceptable)"
        elif overall_quality >= 0.6:
            quality_grade = "D (Needs Improvement)"
        else:
            quality_grade = "F (Poor)"

        # Generate recommendations
        recommendations = self.generate_recommendations(
            completeness, duplicates, cwe_consistency, distribution, code_quality
        )

        quality_report = {
            "dataset_info": {
                "total_records": len(df),
                "assessment_date": datetime.now().isoformat(),
                "quality_framework": "VulnHunter QA v1.0"
            },
            "overall_quality": {
                "score": overall_quality,
                "grade": quality_grade,
                "individual_scores": {
                    "completeness": completeness["quality_score"],
                    "duplicates": duplicates["quality_score"],
                    "cwe_consistency": cwe_consistency["quality_score"],
                    "balance": distribution["balance_quality_score"],
                    "diversity": distribution["diversity_quality_score"],
                    "code_quality": code_quality["quality_score"]
                }
            },
            "detailed_analysis": {
                "completeness": completeness,
                "duplicates": duplicates,
                "cwe_consistency": cwe_consistency,
                "distribution": distribution,
                "code_quality": code_quality
            },
            "recommendations": recommendations,
            "quality_thresholds": self.quality_thresholds
        }

        logger.info("📊 QUALITY ASSESSMENT SUMMARY:")
        logger.info(f"  🎯 Overall Quality Score: {overall_quality:.3f}")
        logger.info(f"  📋 Quality Grade: {quality_grade}")
        logger.info(f"  📈 Total Records: {len(df):,}")
        logger.info(f"  🔍 Assessment Complete!")

        return quality_report

    def generate_recommendations(self, completeness, duplicates, cwe_consistency,
                                distribution, code_quality) -> List[str]:
        """Generate actionable recommendations based on quality analysis"""

        recommendations = []

        # Completeness recommendations
        if completeness["quality_score"] < 0.8:
            recommendations.append("Improve data completeness - fill missing required fields")

        # Duplicate recommendations
        if duplicates["quality_score"] < 0.8:
            recommendations.append("Remove or review duplicate records to improve data quality")

        # CWE consistency recommendations
        if cwe_consistency["quality_score"] < 0.8:
            recommendations.append("Review and correct CWE label mappings for better consistency")

        # Balance recommendations
        if distribution["balance_quality_score"] < 0.8:
            vuln_ratio = distribution["vulnerability_ratio"]
            if vuln_ratio < 0.2:
                recommendations.append("Increase number of vulnerable samples for better balance")
            elif vuln_ratio > 0.8:
                recommendations.append("Add more safe samples to improve dataset balance")

        # Diversity recommendations
        if distribution["diversity_quality_score"] < 0.8:
            recommendations.append("Expand language and vulnerability type coverage for better diversity")

        # Code quality recommendations
        if code_quality["quality_score"] < 0.8:
            recommendations.append("Improve code snippet quality - add more substantial code examples")

        if not recommendations:
            recommendations.append("Dataset meets quality standards - ready for production training")

        return recommendations

    def save_quality_report(self, quality_report: Dict[str, Any], dataset_name: str):
        """Save comprehensive quality report"""

        logger.info("💾 Saving quality assessment report...")

        # Save detailed JSON report
        report_path = self.output_dir / f"{dataset_name}_quality_report.json"
        with open(report_path, 'w') as f:
            json.dump(quality_report, f, indent=2, default=str)

        # Save summary CSV for easy analysis
        summary_data = [{
            "dataset_name": dataset_name,
            "total_records": quality_report["dataset_info"]["total_records"],
            "overall_quality_score": quality_report["overall_quality"]["score"],
            "quality_grade": quality_report["overall_quality"]["grade"],
            "completeness_score": quality_report["overall_quality"]["individual_scores"]["completeness"],
            "duplicates_score": quality_report["overall_quality"]["individual_scores"]["duplicates"],
            "cwe_consistency_score": quality_report["overall_quality"]["individual_scores"]["cwe_consistency"],
            "balance_score": quality_report["overall_quality"]["individual_scores"]["balance"],
            "diversity_score": quality_report["overall_quality"]["individual_scores"]["diversity"],
            "code_quality_score": quality_report["overall_quality"]["individual_scores"]["code_quality"],
            "assessment_date": quality_report["dataset_info"]["assessment_date"]
        }]

        summary_df = pd.DataFrame(summary_data)
        summary_path = self.output_dir / f"{dataset_name}_quality_summary.csv"
        summary_df.to_csv(summary_path, index=False)

        logger.info(f"  ✅ Detailed report: {report_path}")
        logger.info(f"  ✅ Summary: {summary_path}")

        return quality_report

def main():
    """Run quality assurance on realistic dataset"""

    logger.info("🎬 Initializing Dataset Quality Assurance System")

    # Initialize QA system
    qa_system = DatasetQualityAssurance()

    # Load the realistic dataset
    dataset_path = "realistic_datasets/comprehensive_realistic_dataset.csv"

    # Check if dataset exists, if not generate it
    if not Path(dataset_path).exists():
        logger.info("📥 Dataset not found, generating realistic dataset first...")
        import realistic_dataset_generator
        records, stats = realistic_dataset_generator.main()

        # Save as CSV for QA
        df_temp = pd.DataFrame(records)
        Path("realistic_datasets").mkdir(exist_ok=True)
        df_temp.to_csv(dataset_path, index=False)
        logger.info(f"✅ Dataset saved to {dataset_path}")

    # Load dataset
    df = qa_system.load_dataset(dataset_path)

    if df.empty:
        logger.error("❌ Failed to load dataset for quality assurance")
        return 1

    # Generate quality report
    quality_report = qa_system.generate_quality_report(df)

    # Save report
    qa_system.save_quality_report(quality_report, "comprehensive_realistic_dataset")

    logger.info("✅ Dataset Quality Assurance Completed Successfully!")

    return quality_report

if __name__ == "__main__":
    quality_report = main()