"""
Unit tests for CVE examples and case studies.
"""

import unittest
from case_studies.real_cve_examples import RealCVEDatabase, CVESeverity, CVEExample


class TestCVEDatabase(unittest.TestCase):
    """Test cases for CVE database functionality."""

    def setUp(self):
        """Set up test environment."""
        self.cve_db = RealCVEDatabase()

    def test_database_initialization(self):
        """Test CVE database initialization."""
        self.assertIsNotNone(self.cve_db.cve_examples)
        self.assertGreater(len(self.cve_db.cve_examples), 0)

    def test_cve_retrieval_by_id(self):
        """Test retrieving CVE by ID."""
        log4j_cve = self.cve_db.get_cve_by_id("CVE-2021-44228")
        self.assertIsNotNone(log4j_cve)
        self.assertEqual(log4j_cve.cve_id, "CVE-2021-44228")
        self.assertEqual(log4j_cve.vulnerability_type, "remote_code_execution")

    def test_cve_retrieval_by_severity(self):
        """Test retrieving CVEs by severity."""
        critical_cves = self.cve_db.get_cves_by_severity(CVESeverity.CRITICAL)
        self.assertGreater(len(critical_cves), 0)

        for cve in critical_cves:
            self.assertEqual(cve.severity, CVESeverity.CRITICAL)

    def test_cve_retrieval_by_type(self):
        """Test retrieving CVEs by vulnerability type."""
        rce_cves = self.cve_db.get_cves_by_type("remote_code_execution")
        self.assertGreater(len(rce_cves), 0)

        for cve in rce_cves:
            self.assertEqual(cve.vulnerability_type, "remote_code_execution")

    def test_test_dataset_generation(self):
        """Test generation of test dataset from CVEs."""
        test_dataset = self.cve_db.generate_test_dataset()
        self.assertGreater(len(test_dataset), 0)

        # Should have both vulnerable and fixed examples
        vulnerable_count = sum(1 for item in test_dataset if item['label'] == 1)
        safe_count = sum(1 for item in test_dataset if item['label'] == 0)

        self.assertGreater(vulnerable_count, 0)
        self.assertGreater(safe_count, 0)

    def test_cve_data_completeness(self):
        """Test that CVE examples have required fields."""
        for cve_id, cve in self.cve_db.cve_examples.items():
            self.assertIsNotNone(cve.cve_id)
            self.assertIsNotNone(cve.title)
            self.assertIsNotNone(cve.vulnerable_code)
            self.assertIsNotNone(cve.fixed_code)
            self.assertIsInstance(cve.severity, CVESeverity)
            self.assertGreater(cve.cvss_score, 0.0)
            self.assertLessEqual(cve.cvss_score, 10.0)

    def test_code_quality(self):
        """Test that vulnerable and fixed code examples are meaningful."""
        for cve in self.cve_db.get_all_cves():
            # Vulnerable code should be substantial
            self.assertGreater(len(cve.vulnerable_code.strip()), 50)
            # Fixed code should be substantial
            self.assertGreater(len(cve.fixed_code.strip()), 50)
            # Should have remediation steps
            self.assertGreater(len(cve.remediation_steps), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)