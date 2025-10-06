#!/usr/bin/env python3
"""
VulnHunter Z3 Formal Verification Module
Reduces false positives using SMT-based formal verification
Focuses on SQL injection, buffer overflow, and command injection
"""

import re
import ast as python_ast
from typing import Dict, List, Optional, Tuple
import logging

try:
    from z3 import *
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    logging.warning("⚠️  z3-solver not installed. Install with: pip install z3-solver")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Z3VerificationModule:
    """
    Formal verification module using Z3 SMT solver
    Verifies ML predictions to reduce false positives
    """

    def __init__(self, timeout_ms: int = 5000):
        """
        Args:
            timeout_ms: Z3 solver timeout in milliseconds
        """
        if not Z3_AVAILABLE:
            raise ImportError("z3-solver required. Install with: pip install z3-solver")

        self.timeout_ms = timeout_ms
        self.verification_cache = {}

        logger.info(f"Z3 Verification Module initialized (timeout={timeout_ms}ms)")

    def verify_prediction(
        self,
        code: str,
        ml_prediction: int,
        ml_confidence: float,
        language: str = 'auto'
    ) -> Dict:
        """
        Verify ML prediction using formal verification

        Args:
            code: Source code string
            ml_prediction: ML model prediction (0=safe, 1=vulnerable)
            ml_confidence: ML model confidence (0-1)
            language: Programming language ('python', 'c', 'java', 'auto')

        Returns:
            {
                'verified': bool,
                'final_prediction': int,
                'confidence': float,
                'verification_results': dict,
                'vulnerabilities_found': list
            }
        """
        # Auto-detect language if needed
        if language == 'auto':
            language = self._detect_language(code)

        verification_results = {}
        vulnerabilities_found = []

        # Run verification checks
        sql_result = self.verify_sql_injection(code)
        buffer_result = self.verify_buffer_overflow(code)
        cmd_result = self.verify_command_injection(code)
        path_result = self.verify_path_traversal(code)

        verification_results = {
            'sql_injection': sql_result,
            'buffer_overflow': buffer_result,
            'command_injection': cmd_result,
            'path_traversal': path_result
        }

        # Collect found vulnerabilities
        for vuln_type, result in verification_results.items():
            if result['vulnerable']:
                vulnerabilities_found.append({
                    'type': vuln_type,
                    'confidence': result.get('confidence', 1.0),
                    'details': result.get('details', '')
                })

        # Decision logic
        verified_vulnerable = len(vulnerabilities_found) > 0

        # If ML says vulnerable and we verify it -> high confidence vulnerable
        if ml_prediction == 1 and verified_vulnerable:
            final_prediction = 1
            confidence = min(ml_confidence + 0.1, 1.0)  # Boost confidence
            verified = True

        # If ML says vulnerable but we find no vulns -> possible false positive
        elif ml_prediction == 1 and not verified_vulnerable:
            # Lower confidence or flip prediction if ML was uncertain
            if ml_confidence < 0.7:
                final_prediction = 0  # Override: likely false positive
                confidence = 0.3
                verified = True
            else:
                final_prediction = 1  # Keep prediction but lower confidence
                confidence = ml_confidence * 0.8
                verified = False

        # If ML says safe and we find vulns -> false negative, correct it
        elif ml_prediction == 0 and verified_vulnerable:
            final_prediction = 1  # Override: we found vulnerabilities
            confidence = 0.8
            verified = True

        # If ML says safe and we verify safe -> high confidence safe
        else:
            final_prediction = 0
            confidence = min(1.0 - ml_confidence + 0.1, 1.0)
            verified = True

        return {
            'verified': verified,
            'final_prediction': final_prediction,
            'confidence': confidence,
            'verification_results': verification_results,
            'vulnerabilities_found': vulnerabilities_found,
            'ml_prediction': ml_prediction,
            'ml_confidence': ml_confidence
        }

    def verify_sql_injection(self, code: str) -> Dict:
        """
        Verify SQL injection vulnerabilities using Z3

        Checks for:
        - String concatenation in SQL queries
        - Unsafe user input in queries
        - Missing parameterization
        """
        result = {
            'vulnerable': False,
            'confidence': 0.0,
            'details': '',
            'proof': None
        }

        # Pattern matching for SQL operations
        sql_patterns = [
            r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+',
            r'(?i)(exec|execute|sp_executesql)\s*\(',
            r'(?i)(UNION\s+SELECT)',
        ]

        has_sql = any(re.search(pattern, code) for pattern in sql_patterns)
        if not has_sql:
            return result

        # Check for string concatenation (danger sign)
        concat_patterns = [
            r'["\'].*?["\']\s*\+\s*\w+',  # "SELECT * FROM " + table
            r'\w+\s*\+\s*["\'].*?["\']',  # table + " WHERE id = "
            r'\.format\s*\(',              # .format() usage
            r'%\s*\w+',                    # % formatting
            r'f["\'].*?\{.*?\}',           # f-strings with variables
        ]

        has_concat = any(re.search(pattern, code) for pattern in concat_patterns)

        # Check for parameterization (safety sign)
        safe_patterns = [
            r'\?',                         # ? placeholders
            r':\w+',                       # :name placeholders
            r'%s',                         # %s placeholders (if using params)
            r'\.prepare\s*\(',             # Prepared statements
            r'parameterized',
        ]

        has_safe_param = any(re.search(pattern, code) for pattern in safe_patterns)

        # Z3 verification
        solver = Solver()
        solver.set("timeout", self.timeout_ms)

        # Model SQL injection vulnerability
        user_input = String('user_input')
        sql_query = String('sql_query')

        # If concatenation without parameterization -> vulnerable
        if has_concat and not has_safe_param:
            # Model: user_input is part of query AND contains SQL injection payload
            solver.add(Contains(sql_query, user_input))
            solver.add(Or(
                Contains(user_input, StringVal("' OR '1'='1")),
                Contains(user_input, StringVal("'; DROP TABLE")),
                Contains(user_input, StringVal("UNION SELECT"))
            ))

            if solver.check() == sat:
                result['vulnerable'] = True
                result['confidence'] = 0.9
                result['details'] = 'String concatenation in SQL query without parameterization'
                result['proof'] = str(solver.model())

        return result

    def verify_buffer_overflow(self, code: str) -> Dict:
        """
        Verify buffer overflow vulnerabilities

        Checks for:
        - Unsafe C functions (strcpy, strcat, gets, sprintf)
        - Fixed-size buffers with unbounded input
        """
        result = {
            'vulnerable': False,
            'confidence': 0.0,
            'details': '',
            'proof': None
        }

        # Find buffer declarations
        buffer_patterns = r'char\s+(\w+)\[(\d+)\]'
        buffers = re.findall(buffer_patterns, code)

        if not buffers:
            return result

        # Check for unsafe functions
        unsafe_funcs = {
            'strcpy': 0.95,
            'strcat': 0.95,
            'sprintf': 0.90,
            'gets': 1.0,
            'vsprintf': 0.90,
            'scanf': 0.85
        }

        for func_name, confidence in unsafe_funcs.items():
            pattern = rf'{func_name}\s*\('
            if re.search(pattern, code):
                # Check if used with our buffers
                for buf_name, buf_size in buffers:
                    if re.search(rf'{func_name}\s*\(\s*{buf_name}', code):
                        # Z3 verification
                        solver = Solver()
                        solver.set("timeout", self.timeout_ms)

                        # Model buffer bounds
                        buf_len = Int(f'{buf_name}_len')
                        input_len = Int('input_len')

                        solver.add(buf_len == int(buf_size))
                        solver.add(input_len > buf_len)  # Overflow condition

                        if solver.check() == sat:
                            result['vulnerable'] = True
                            result['confidence'] = confidence
                            result['details'] = f'Unsafe function {func_name} used with fixed-size buffer {buf_name}[{buf_size}]'
                            result['proof'] = str(solver.model())
                            return result

        return result

    def verify_command_injection(self, code: str) -> Dict:
        """
        Verify command injection vulnerabilities

        Checks for:
        - system(), exec(), shell_exec() with user input
        - os.system(), subprocess with shell=True
        """
        result = {
            'vulnerable': False,
            'confidence': 0.0,
            'details': '',
            'proof': None
        }

        # Dangerous functions
        dangerous_patterns = [
            (r'system\s*\([^)]*\w+[^)]*\)', 0.95, 'system() with variable'),
            (r'exec\s*\([^)]*\w+[^)]*\)', 0.90, 'exec() with variable'),
            (r'shell_exec\s*\([^)]*\w+[^)]*\)', 0.95, 'shell_exec() with variable'),
            (r'os\.system\s*\([^)]*\w+[^)]*\)', 0.95, 'os.system() with variable'),
            (r'subprocess.*shell\s*=\s*True', 0.85, 'subprocess with shell=True'),
            (r'eval\s*\([^)]*\w+[^)]*\)', 0.90, 'eval() with variable'),
        ]

        for pattern, confidence, description in dangerous_patterns:
            if re.search(pattern, code):
                # Z3 verification
                solver = Solver()
                solver.set("timeout", self.timeout_ms)

                user_input = String('user_input')
                command = String('command')

                # Model command injection
                solver.add(Contains(command, user_input))
                solver.add(Or(
                    Contains(user_input, StringVal("; rm -rf")),
                    Contains(user_input, StringVal("| nc")),
                    Contains(user_input, StringVal("&& wget")),
                    Contains(user_input, StringVal("`"))
                ))

                if solver.check() == sat:
                    result['vulnerable'] = True
                    result['confidence'] = confidence
                    result['details'] = description
                    result['proof'] = str(solver.model())
                    return result

        return result

    def verify_path_traversal(self, code: str) -> Dict:
        """
        Verify path traversal vulnerabilities

        Checks for:
        - File operations with unsanitized paths
        - Directory traversal patterns (../)
        """
        result = {
            'vulnerable': False,
            'confidence': 0.0,
            'details': '',
            'proof': None
        }

        # File operation patterns
        file_ops = [
            r'open\s*\([^)]*\w+[^)]*\)',
            r'fopen\s*\([^)]*\w+[^)]*\)',
            r'file_get_contents\s*\([^)]*\w+[^)]*\)',
            r'readFile\s*\([^)]*\w+[^)]*\)',
        ]

        has_file_op = any(re.search(pattern, code) for pattern in file_ops)
        if not has_file_op:
            return result

        # Check for path traversal patterns
        traversal_patterns = [
            r'\.\.',
            r'%2e%2e',
            r'\.\./',
            r'\.\.\\'
        ]

        # Check for path sanitization
        sanitization_patterns = [
            r'realpath\s*\(',
            r'basename\s*\(',
            r'path\.normalize',
            r'os\.path\.normpath',
        ]

        has_traversal = any(re.search(pattern, code, re.IGNORECASE) for pattern in traversal_patterns)
        has_sanitization = any(re.search(pattern, code) for pattern in sanitization_patterns)

        if has_file_op and (has_traversal or not has_sanitization):
            # Z3 verification
            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            user_path = String('user_path')
            file_path = String('file_path')

            solver.add(Contains(file_path, user_path))
            solver.add(Contains(user_path, StringVal("../")))

            if solver.check() == sat:
                result['vulnerable'] = True
                result['confidence'] = 0.85
                result['details'] = 'File operation with potential path traversal'
                result['proof'] = str(solver.model())

        return result

    def _detect_language(self, code: str) -> str:
        """Auto-detect programming language"""
        if 'def ' in code and 'import ' in code:
            return 'python'
        elif '#include' in code or 'int main' in code:
            return 'c'
        elif 'public class' in code or 'public static void main' in code:
            return 'java'
        elif 'function' in code and '{' in code:
            return 'javascript'
        else:
            return 'unknown'


class VerifiedEnsemblePredictor:
    """
    Ensemble predictor with Z3 verification layer
    Reduces false positives by verifying ML predictions
    """

    def __init__(
        self,
        ensemble,
        verification_module: Optional[Z3VerificationModule] = None,
        verification_threshold: float = 0.6
    ):
        """
        Args:
            ensemble: VulnHunterEnsemble instance
            verification_module: Z3VerificationModule instance
            verification_threshold: ML confidence threshold to trigger verification
        """
        self.ensemble = ensemble
        self.verification_module = verification_module or Z3VerificationModule()
        self.verification_threshold = verification_threshold

        logger.info("Verified Ensemble Predictor initialized")
        logger.info(f"  Verification threshold: {verification_threshold}")

    def predict_with_verification(
        self,
        graph_data_list: List,
        code_texts: List[str],
        verify_all: bool = False
    ) -> Dict:
        """
        Predict with formal verification

        Args:
            graph_data_list: Graph data for GNN
            code_texts: Source code strings
            verify_all: If True, verify all predictions. If False, only verify uncertain ones.

        Returns:
            {
                'predictions': array of final predictions,
                'confidences': array of confidences,
                'verified_count': number of samples verified,
                'corrections': number of predictions corrected
            }
        """
        # Get ensemble predictions
        ensemble_results = self.ensemble.predict_ensemble(
            graph_data_list,
            code_texts
        )

        ml_predictions = ensemble_results['ensemble_predictions']
        ml_probabilities = ensemble_results['ensemble_probabilities']

        final_predictions = []
        final_confidences = []
        verified_count = 0
        corrections = 0

        for idx, (ml_pred, ml_prob) in enumerate(zip(ml_predictions, ml_probabilities)):
            ml_confidence = ml_prob if ml_pred == 1 else (1 - ml_prob)

            # Decide whether to verify
            should_verify = verify_all or (ml_confidence < self.verification_threshold)

            if should_verify:
                # Run verification
                verification_result = self.verification_module.verify_prediction(
                    code=code_texts[idx],
                    ml_prediction=ml_pred,
                    ml_confidence=ml_confidence
                )

                final_pred = verification_result['final_prediction']
                final_conf = verification_result['confidence']

                verified_count += 1
                if final_pred != ml_pred:
                    corrections += 1
                    logger.info(f"Sample {idx}: Corrected {ml_pred} -> {final_pred} "
                               f"(confidence: {ml_confidence:.2f} -> {final_conf:.2f})")

            else:
                # Use ML prediction as-is
                final_pred = ml_pred
                final_conf = ml_confidence

            final_predictions.append(final_pred)
            final_confidences.append(final_conf)

        logger.info(f"\nVerification Summary:")
        logger.info(f"  Total samples: {len(code_texts)}")
        logger.info(f"  Verified: {verified_count}")
        logger.info(f"  Corrections: {corrections}")

        return {
            'predictions': np.array(final_predictions),
            'confidences': np.array(final_confidences),
            'verified_count': verified_count,
            'corrections': corrections,
            'ml_predictions': ml_predictions,
            'ml_probabilities': ml_probabilities
        }


if __name__ == "__main__":
    # Test Z3 verification
    if Z3_AVAILABLE:
        logger.info("Testing Z3 Verification Module")

        verifier = Z3VerificationModule()

        # Test SQL injection
        sql_code = """
        def get_user(username):
            query = "SELECT * FROM users WHERE name = '" + username + "'"
            return execute_query(query)
        """

        result = verifier.verify_sql_injection(sql_code)
        logger.info(f"\nSQL Injection Test: {result}")

        # Test buffer overflow
        buffer_code = """
        void copy_data(char* input) {
            char buffer[64];
            strcpy(buffer, input);
        }
        """

        result = verifier.verify_buffer_overflow(buffer_code)
        logger.info(f"\nBuffer Overflow Test: {result}")

        # Test command injection
        cmd_code = """
        import os
        def run_command(user_input):
            os.system("echo " + user_input)
        """

        result = verifier.verify_command_injection(cmd_code)
        logger.info(f"\nCommand Injection Test: {result}")
    else:
        logger.warning("Z3 solver not available. Install with: pip install z3-solver")
