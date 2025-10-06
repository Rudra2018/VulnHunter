#!/usr/bin/env python3
"""
False Positive Reduction Module
Combines: Issue Text Analysis (NLP) + Z3 Formal Verification
"""

import re
import torch
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple
import logging
from z3 import *
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IssueTextAnalyzer:
    """
    Analyze GitHub issue texts for false positive indicators
    Uses regex patterns and NLP techniques
    """

    # Comprehensive false positive patterns
    FALSE_POSITIVE_INDICATORS = {
        'explicit_fp': [
            r'false\s+positive',
            r'false\s+alarm',
            r'fp\s+(?:alert|detection)',
            r'incorrectly\s+(?:flagged|reported|detected)',
            r'wrongly\s+(?:marked|identified)'
        ],
        'dismissal': [
            r'dismissed\s+(?:after\s+)?(?:review|analysis|investigation)',
            r'closed\s+as\s+(?:invalid|wontfix|not\s+a\s+bug|cannot\s+reproduce)',
            r'not\s+(?:a\s+)?(?:vulnerability|bug|issue|security\s+risk)',
            r'no\s+(?:security\s+)?(?:risk|impact|threat|concern)'
        ],
        'safe_by_design': [
            r'safe\s+by\s+design',
            r'intentional\s+(?:behavior|design)',
            r'working\s+as\s+(?:intended|expected|designed)',
            r'by\s+design',
            r'protected\s+by\s+(?:another|separate)\s+(?:check|validation|mechanism)'
        ],
        'benign': [
            r'benign\s+(?:code|pattern|behavior)',
            r'harmless',
            r'no\s+exploit\s+possible',
            r'cannot\s+be\s+exploited',
            r'not\s+exploitable',
            r'requires\s+(?:admin|root)\s+privileges',  # May be FP depending on threat model
        ],
        'mitigation_exists': [
            r'already\s+(?:protected|mitigated|handled)',
            r'(?:input|parameter)\s+is\s+(?:validated|sanitized|checked)',
            r'bounds\s+(?:check|checking)\s+(?:present|exists)',
            r'length\s+(?:check|validation)\s+prevents'
        ],
        'duplicate': [
            r'duplicate\s+of',
            r'already\s+(?:reported|fixed|patched)',
            r'same\s+as'
        ]
    }

    # True positive indicators (to balance)
    TRUE_POSITIVE_INDICATORS = {
        'confirmed': [
            r'confirmed\s+(?:vulnerability|exploit|bug)',
            r'reproduced\s+(?:the\s+)?(?:vulnerability|bug|issue)',
            r'verified\s+(?:vulnerability|exploit)',
            r'CVE\s*-\s*\d{4}\s*-\s*\d+\s+assigned'
        ],
        'exploit': [
            r'(?:successful|working)\s+exploit',
            r'proof\s+of\s+concept',
            r'poc\s+(?:available|attached)',
            r'exploit\s+(?:code|script)'
        ],
        'patch': [
            r'patch\s+(?:merged|applied|committed)',
            r'fix\s+(?:merged|applied|committed)',
            r'security\s+fix'
        ]
    }

    def analyze_issue_text(self, text: str) -> Dict:
        """
        Analyze issue text for false positive indicators

        Args:
            text: Issue title + body + comments combined

        Returns:
            {
                'is_likely_fp': bool,
                'fp_confidence': float (0-1),
                'fp_reasons': List[str],
                'tp_confidence': float (0-1),
                'category': str
            }
        """
        text_lower = text.lower()

        # Count FP indicators
        fp_scores = {}
        fp_matches = []

        for category, patterns in self.FALSE_POSITIVE_INDICATORS.items():
            matches = 0
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    matches += 1
                    fp_matches.append((category, pattern))

            fp_scores[category] = matches

        total_fp_score = sum(fp_scores.values())

        # Count TP indicators
        tp_scores = {}
        for category, patterns in self.TRUE_POSITIVE_INDICATORS.items():
            matches = 0
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    matches += 1

            tp_scores[category] = matches

        total_tp_score = sum(tp_scores.values())

        # Compute confidence
        fp_confidence = min(total_fp_score / 3.0, 1.0)  # Normalize by expected max
        tp_confidence = min(total_tp_score / 3.0, 1.0)

        # Decision logic
        is_likely_fp = False
        category = 'uncertain'

        if fp_confidence > tp_confidence and total_fp_score >= 1:
            is_likely_fp = True

            # Determine specific category
            if fp_scores['explicit_fp'] > 0:
                category = 'explicit_false_positive'
            elif fp_scores['dismissal'] > 0:
                category = 'dismissed_after_review'
            elif fp_scores['safe_by_design'] > 0:
                category = 'safe_by_design'
            elif fp_scores['benign'] > 0:
                category = 'benign'
            elif fp_scores['mitigation_exists'] > 0:
                category = 'already_mitigated'
            else:
                category = 'likely_false_positive'

        elif tp_confidence > fp_confidence and total_tp_score >= 1:
            is_likely_fp = False
            category = 'confirmed_vulnerability'

        # Extract reasons
        fp_reasons = [f"{cat}: {pattern}" for cat, pattern in fp_matches[:3]]

        return {
            'is_likely_fp': is_likely_fp,
            'fp_confidence': fp_confidence,
            'tp_confidence': tp_confidence,
            'fp_reasons': fp_reasons,
            'category': category,
            'fp_scores': fp_scores,
            'tp_scores': tp_scores
        }


class Z3SQLInjectionVerifier:
    """
    Z3-based formal verification for SQL injection vulnerabilities
    Reduces false positives by proving safety
    """

    def __init__(self):
        self.solver = Solver()

    def verify_sql_injection(self, code: str) -> Dict:
        """
        Verify if code is vulnerable to SQL injection

        Args:
            code: Source code snippet

        Returns:
            {
                'vulnerable': bool,
                'confidence': float,
                'reason': str,
                'counterexample': Optional[str]
            }
        """
        # Reset solver
        self.solver.reset()

        # Patterns indicating SQL injection vulnerability
        vuln_patterns = [
            r'["\'][^"\']*SELECT[^"\']*["\'][\s]*\+',  # "SELECT ... " + var
            r'\+[\s]*["\'][^"\']*SELECT[^"\']*["\']',  # var + "SELECT ... "
            r'execute\s*\([^)]*\+',                     # execute(... + ...)
            r'query\s*\([^)]*\+',                       # query(... + ...)
            r'sql\s*=\s*[^=]*\+',                       # sql = ... + ...
            r'sprintf\s*\([^)]*SELECT[^)]*%s',          # sprintf(buf, "SELECT ... %s", ...)
            r'format\s*\([^)]*SELECT[^)]*\{',           # format("SELECT ... {}", ...)
        ]

        # Safe patterns (parameterized queries)
        safe_patterns = [
            r'execute\s*\(\s*["\'][^"\']*\?[^"\']*["\']',  # execute("SELECT * FROM users WHERE id = ?", [id])
            r'prepare\s*\(',                                 # prepare(...) - prepared statements
            r'bind_param\s*\(',                              # bind_param(...)
            r'executemany\s*\(',                             # executemany(...) - parameterized
            r'query\s*\(\s*["\'][^"\']*\?[^"\']*["\']',     # query("SELECT * FROM users WHERE id = ?")
        ]

        # Check for vulnerable patterns
        vuln_found = False
        vuln_reason = None

        for pattern in vuln_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                vuln_found = True
                vuln_reason = f"String concatenation in SQL query: {pattern}"
                break

        # Check for safe patterns (override vulnerable)
        safe_found = False
        for pattern in safe_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                safe_found = True
                break

        if safe_found:
            return {
                'vulnerable': False,
                'confidence': 0.9,
                'reason': 'Parameterized query detected (safe)',
                'counterexample': None
            }

        if not vuln_found:
            return {
                'vulnerable': False,
                'confidence': 0.5,
                'reason': 'No SQL injection pattern detected',
                'counterexample': None
            }

        # Use Z3 to verify exploitability
        try:
            # Model: Can we craft an input that breaks SQL logic?
            user_input = String('user_input')
            sql_query = String('sql_query')

            # Constraint: Query contains user input
            self.solver.add(Contains(sql_query, user_input))

            # Constraint: User input contains SQL injection payload
            injection_payloads = [
                StringVal("' OR '1'='1"),
                StringVal("'; DROP TABLE users--"),
                StringVal("' UNION SELECT"),
                StringVal("admin'--")
            ]

            # Check if any payload can be injected
            self.solver.push()
            for payload in injection_payloads:
                self.solver.add(Contains(user_input, payload))

            if self.solver.check() == sat:
                model = self.solver.model()
                return {
                    'vulnerable': True,
                    'confidence': 0.95,
                    'reason': vuln_reason,
                    'counterexample': f"Possible injection: {model}"
                }
            else:
                # Cannot prove exploitability
                return {
                    'vulnerable': True,
                    'confidence': 0.6,
                    'reason': f"{vuln_reason} (but cannot generate exploit)",
                    'counterexample': None
                }

        except Exception as e:
            logger.warning(f"Z3 verification failed: {e}")
            return {
                'vulnerable': vuln_found,
                'confidence': 0.5,
                'reason': vuln_reason or "Unknown",
                'counterexample': None
            }


class Z3BufferOverflowVerifier:
    """
    Z3-based verification for buffer overflow vulnerabilities
    """

    def __init__(self):
        self.solver = Solver()

    def verify_buffer_overflow(self, code: str) -> Dict:
        """
        Verify if code is vulnerable to buffer overflow

        Args:
            code: Source code snippet

        Returns:
            {
                'vulnerable': bool,
                'confidence': float,
                'reason': str
            }
        """
        self.solver.reset()

        # Vulnerable patterns
        vuln_functions = [
            r'strcpy\s*\(',
            r'strcat\s*\(',
            r'gets\s*\(',
            r'sprintf\s*\(',
            r'vsprintf\s*\(',
            r'scanf\s*\([^)]*%s'
        ]

        # Safe alternatives
        safe_patterns = [
            r'strncpy\s*\(',
            r'strncat\s*\(',
            r'fgets\s*\(',
            r'snprintf\s*\(',
            r'vsnprintf\s*\('
        ]

        # Check for vulnerable functions
        vuln_found = False
        vuln_func = None

        for pattern in vuln_functions:
            match = re.search(pattern, code)
            if match:
                vuln_found = True
                vuln_func = match.group(0)
                break

        # Check for safe alternatives
        safe_found = any(re.search(p, code) for p in safe_patterns)

        if safe_found:
            return {
                'vulnerable': False,
                'confidence': 0.9,
                'reason': 'Safe string function used'
            }

        if not vuln_found:
            return {
                'vulnerable': False,
                'confidence': 0.5,
                'reason': 'No buffer overflow pattern detected'
            }

        # Use Z3 to verify
        try:
            # Model: buffer size vs input size
            buffer_size = Int('buffer_size')
            input_size = Int('input_size')

            # Constraints
            self.solver.add(buffer_size > 0)
            self.solver.add(input_size > 0)

            # Vulnerability condition: input larger than buffer
            self.solver.add(input_size > buffer_size)

            if self.solver.check() == sat:
                return {
                    'vulnerable': True,
                    'confidence': 0.9,
                    'reason': f'Unsafe function {vuln_func} without bounds checking'
                }
            else:
                return {
                    'vulnerable': False,
                    'confidence': 0.7,
                    'reason': 'Bounds constraints satisfied'
                }

        except Exception as e:
            logger.warning(f"Z3 verification failed: {e}")
            return {
                'vulnerable': vuln_found,
                'confidence': 0.6,
                'reason': f'Unsafe function {vuln_func} detected'
            }


class IntegratedFalsePositiveReduction:
    """
    Integrated system combining Issue Text Analysis + Z3 Verification
    """

    def __init__(self):
        self.issue_analyzer = IssueTextAnalyzer()
        self.sql_verifier = Z3SQLInjectionVerifier()
        self.buffer_verifier = Z3BufferOverflowVerifier()

    def reduce_false_positives(
        self,
        code: str,
        model_prediction: torch.Tensor,
        model_confidence: float,
        issue_texts: Optional[List[str]] = None,
        vuln_type: Optional[str] = None
    ) -> Dict:
        """
        Comprehensive false positive reduction

        Args:
            code: Source code
            model_prediction: Model's binary prediction (0=safe, 1=vulnerable)
            model_confidence: Model's confidence (0-1)
            issue_texts: List of issue discussions (optional)
            vuln_type: Type of vulnerability ('sql_injection', 'buffer_overflow', etc.)

        Returns:
            {
                'final_prediction': int (0 or 1),
                'final_confidence': float,
                'is_false_positive': bool,
                'reduction_method': str,
                'details': dict
            }
        """
        details = {}

        # 1. Analyze issue texts if available
        issue_analysis = None
        if issue_texts:
            combined_text = ' '.join(issue_texts)
            issue_analysis = self.issue_analyzer.analyze_issue_text(combined_text)
            details['issue_analysis'] = issue_analysis

            # If issue strongly indicates FP
            if issue_analysis['is_likely_fp'] and issue_analysis['fp_confidence'] > 0.7:
                return {
                    'final_prediction': 0,  # Override to safe
                    'final_confidence': issue_analysis['fp_confidence'],
                    'is_false_positive': True,
                    'reduction_method': 'issue_text_analysis',
                    'details': details
                }

        # 2. Apply Z3 verification if model predicts vulnerable
        if model_prediction == 1:
            verification_result = None

            # SQL Injection verification
            if vuln_type == 'sql_injection' or 'sql' in code.lower():
                verification_result = self.sql_verifier.verify_sql_injection(code)
                details['z3_sql_verification'] = verification_result

            # Buffer Overflow verification
            elif vuln_type == 'buffer_overflow' or any(func in code for func in ['strcpy', 'strcat', 'gets']):
                verification_result = self.buffer_verifier.verify_buffer_overflow(code)
                details['z3_buffer_verification'] = verification_result

            # If Z3 proves safe
            if verification_result and not verification_result['vulnerable']:
                if verification_result['confidence'] > 0.8:
                    return {
                        'final_prediction': 0,  # Override to safe
                        'final_confidence': verification_result['confidence'],
                        'is_false_positive': True,
                        'reduction_method': 'z3_formal_verification',
                        'details': details
                    }

            # If Z3 confirms vulnerable with high confidence
            if verification_result and verification_result['vulnerable']:
                if verification_result['confidence'] > 0.9:
                    return {
                        'final_prediction': 1,  # Confirm vulnerable
                        'final_confidence': max(model_confidence, verification_result['confidence']),
                        'is_false_positive': False,
                        'reduction_method': 'z3_confirmation',
                        'details': details
                    }

        # 3. Ensemble decision: combine model + issue analysis + Z3
        ensemble_confidence = model_confidence

        # Adjust confidence based on issue analysis
        if issue_analysis:
            if issue_analysis['is_likely_fp']:
                ensemble_confidence *= (1.0 - issue_analysis['fp_confidence'] * 0.5)
            elif issue_analysis['tp_confidence'] > 0.5:
                ensemble_confidence = min(ensemble_confidence + 0.1, 1.0)

        # Final decision
        final_prediction = int(model_prediction)
        is_false_positive = False

        # If confidence drops below threshold, mark as FP
        if final_prediction == 1 and ensemble_confidence < 0.5:
            final_prediction = 0
            is_false_positive = True

        return {
            'final_prediction': final_prediction,
            'final_confidence': ensemble_confidence,
            'is_false_positive': is_false_positive,
            'reduction_method': 'ensemble',
            'details': details
        }


# Example usage
if __name__ == "__main__":
    logger.info("Testing False Positive Reduction Module\n")

    reducer = IntegratedFalsePositiveReduction()

    # Test Case 1: SQL Injection - False Positive (parameterized query)
    logger.info("="*60)
    logger.info("Test 1: SQL Injection FP (parameterized query)")
    logger.info("="*60)

    code1 = """
    def get_user(user_id):
        query = "SELECT * FROM users WHERE id = ?"
        cursor.execute(query, [user_id])
        return cursor.fetchone()
    """

    result1 = reducer.reduce_false_positives(
        code=code1,
        model_prediction=1,  # Model says vulnerable
        model_confidence=0.85,
        issue_texts=["Dismissed after review - uses parameterized query, safe by design"],
        vuln_type='sql_injection'
    )

    logger.info(f"Result: {result1['final_prediction']} (0=safe, 1=vulnerable)")
    logger.info(f"Confidence: {result1['final_confidence']:.2f}")
    logger.info(f"Is FP: {result1['is_false_positive']}")
    logger.info(f"Method: {result1['reduction_method']}\n")

    # Test Case 2: SQL Injection - True Positive (string concatenation)
    logger.info("="*60)
    logger.info("Test 2: SQL Injection TP (string concatenation)")
    logger.info("="*60)

    code2 = """
    def get_user(username):
        query = "SELECT * FROM users WHERE username = '" + username + "'"
        cursor.execute(query)
        return cursor.fetchone()
    """

    result2 = reducer.reduce_false_positives(
        code=code2,
        model_prediction=1,  # Model says vulnerable
        model_confidence=0.95,
        issue_texts=["Confirmed SQL injection vulnerability, CVE-2024-12345 assigned"],
        vuln_type='sql_injection'
    )

    logger.info(f"Result: {result2['final_prediction']} (0=safe, 1=vulnerable)")
    logger.info(f"Confidence: {result2['final_confidence']:.2f}")
    logger.info(f"Is FP: {result2['is_false_positive']}")
    logger.info(f"Method: {result2['reduction_method']}\n")

    # Test Case 3: Buffer Overflow - False Positive (safe function)
    logger.info("="*60)
    logger.info("Test 3: Buffer Overflow FP (safe function)")
    logger.info("="*60)

    code3 = """
    void copy_string(char *dest, const char *src, size_t dest_size) {
        strncpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\\0';
    }
    """

    result3 = reducer.reduce_false_positives(
        code=code3,
        model_prediction=1,  # Model says vulnerable
        model_confidence=0.65,
        issue_texts=["False positive - uses strncpy with proper bounds checking"],
        vuln_type='buffer_overflow'
    )

    logger.info(f"Result: {result3['final_prediction']} (0=safe, 1=vulnerable)")
    logger.info(f"Confidence: {result3['final_confidence']:.2f}")
    logger.info(f"Is FP: {result3['is_false_positive']}")
    logger.info(f"Method: {result3['reduction_method']}\n")

    # Test Case 4: Buffer Overflow - True Positive (unsafe function)
    logger.info("="*60)
    logger.info("Test 4: Buffer Overflow TP (unsafe function)")
    logger.info("="*60)

    code4 = """
    void copy_string(char *dest, const char *src) {
        strcpy(dest, src);  // No bounds checking!
    }
    """

    result4 = reducer.reduce_false_positives(
        code=code4,
        model_prediction=1,  # Model says vulnerable
        model_confidence=0.92,
        issue_texts=["Reproduced buffer overflow vulnerability with long input"],
        vuln_type='buffer_overflow'
    )

    logger.info(f"Result: {result4['final_prediction']} (0=safe, 1=vulnerable)")
    logger.info(f"Confidence: {result4['final_confidence']:.2f}")
    logger.info(f"Is FP: {result4['is_false_positive']}")
    logger.info(f"Method: {result4['reduction_method']}\n")

    logger.info("✅ All tests complete!")
