#!/usr/bin/env python3
"""
Comprehensive Vulnerability Dataset Generator
===========================================

Generates training data for all CWE types with mathematical validation.
Follows the VulnHunter MathCore architecture for complete vulnerability coverage.
"""

import os
import sys
import json
import random
import hashlib
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

# Add parent directories to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

from core.vulnerability import VulnType, VulnSeverity

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityExample:
    """Training example for vulnerability detection"""
    id: str
    code: str
    language: str
    vulnerability_type: str
    severity: str
    cwe_id: str
    description: str
    is_vulnerable: bool
    exploit_proof: Optional[str] = None
    mathematical_signature: Optional[str] = None
    topology_features: Optional[Dict[str, Any]] = None

class ComprehensiveVulnDatasetGenerator:
    """Generates comprehensive vulnerability datasets for training"""

    def __init__(self):
        self.vulnerability_patterns = self._initialize_vulnerability_patterns()
        self.safe_patterns = self._initialize_safe_patterns()
        self.generated_count = 0

    def _initialize_vulnerability_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize comprehensive vulnerability patterns for all major CWE types"""

        patterns = {
            # CWE-89: SQL Injection
            'sql_injection': [
                {
                    'template': '''
def login(username, password):
    query = "SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()
''',
                    'cwe': 'CWE-89',
                    'severity': 'critical',
                    'description': 'SQL injection through string concatenation'
                },
                {
                    'template': '''
def search_products(category):
    query = f"SELECT * FROM products WHERE category = '{category}'"
    return db.execute(query).fetchall()
''',
                    'cwe': 'CWE-89',
                    'severity': 'critical',
                    'description': 'SQL injection through f-string'
                },
                {
                    'template': '''
def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return execute_query(query)
''',
                    'cwe': 'CWE-89',
                    'severity': 'critical',
                    'description': 'SQL injection through numeric concatenation'
                }
            ],

            # CWE-78: Command Injection
            'command_injection': [
                {
                    'template': '''
import os
def backup_file(filename):
    os.system(f"cp {filename} backup/")
    return True
''',
                    'cwe': 'CWE-78',
                    'severity': 'critical',
                    'description': 'Command injection through os.system'
                },
                {
                    'template': '''
import subprocess
def process_image(image_path):
    subprocess.call(f"convert {image_path} -resize 50% output.jpg", shell=True)
''',
                    'cwe': 'CWE-78',
                    'severity': 'critical',
                    'description': 'Command injection through subprocess with shell=True'
                },
                {
                    'template': '''
import os
def ping_host(hostname):
    result = os.popen(f"ping -c 1 {hostname}").read()
    return result
''',
                    'cwe': 'CWE-78',
                    'severity': 'critical',
                    'description': 'Command injection through os.popen'
                }
            ],

            # CWE-79: Cross-Site Scripting (XSS)
            'xss': [
                {
                    'template': '''
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template_string(f"<h1>Results for: {query}</h1>")
''',
                    'cwe': 'CWE-79',
                    'severity': 'medium',
                    'description': 'Reflected XSS through template rendering'
                },
                {
                    'template': '''
def generate_profile_page(username):
    html = f"<div>Welcome {username}!</div>"
    return html
''',
                    'cwe': 'CWE-79',
                    'severity': 'medium',
                    'description': 'XSS through direct HTML generation'
                }
            ],

            # CWE-22: Path Traversal
            'path_traversal': [
                {
                    'template': '''
def read_file(filename):
    path = "/var/www/files/" + filename
    with open(path, 'r') as f:
        return f.read()
''',
                    'cwe': 'CWE-22',
                    'severity': 'high',
                    'description': 'Path traversal through string concatenation'
                },
                {
                    'template': '''
import os
def download_file(file_path):
    return open(os.path.join("uploads", file_path), 'rb').read()
''',
                    'cwe': 'CWE-22',
                    'severity': 'high',
                    'description': 'Path traversal through os.path.join without validation'
                }
            ],

            # CWE-502: Unsafe Deserialization
            'unsafe_deserialization': [
                {
                    'template': '''
import pickle
def load_user_data(data):
    return pickle.loads(data)
''',
                    'cwe': 'CWE-502',
                    'severity': 'critical',
                    'description': 'Unsafe pickle deserialization'
                },
                {
                    'template': '''
import yaml
def parse_config(config_data):
    return yaml.load(config_data)
''',
                    'cwe': 'CWE-502',
                    'severity': 'critical',
                    'description': 'Unsafe YAML deserialization'
                },
                {
                    'template': '''
import marshal
def load_compiled_code(data):
    code = marshal.loads(data)
    return exec(code)
''',
                    'cwe': 'CWE-502',
                    'severity': 'critical',
                    'description': 'Unsafe marshal deserialization'
                }
            ],

            # CWE-798: Hardcoded Credentials
            'hardcoded_credentials': [
                {
                    'template': '''
def connect_database():
    password = "admin123"
    return connect("localhost", "admin", password)
''',
                    'cwe': 'CWE-798',
                    'severity': 'high',
                    'description': 'Hardcoded database password'
                },
                {
                    'template': '''
API_KEY = "sk-1234567890abcdef"
def api_request():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get(url, headers=headers)
''',
                    'cwe': 'CWE-798',
                    'severity': 'high',
                    'description': 'Hardcoded API key'
                },
                {
                    'template': '''
SECRET_TOKEN = "super_secret_token_12345"
def authenticate(token):
    return token == SECRET_TOKEN
''',
                    'cwe': 'CWE-798',
                    'severity': 'high',
                    'description': 'Hardcoded authentication token'
                }
            ],

            # CWE-120: Buffer Overflow (C/C++)
            'buffer_overflow': [
                {
                    'template': '''
#include <string.h>
void copy_data(char* input) {
    char buffer[100];
    strcpy(buffer, input);  // Vulnerable to buffer overflow
}
''',
                    'cwe': 'CWE-120',
                    'severity': 'critical',
                    'description': 'Buffer overflow using strcpy',
                    'language': 'c'
                },
                {
                    'template': '''
#include <stdio.h>
void get_user_input() {
    char buffer[50];
    gets(buffer);  // Vulnerable to buffer overflow
    printf("Input: %s", buffer);
}
''',
                    'cwe': 'CWE-120',
                    'severity': 'critical',
                    'description': 'Buffer overflow using gets',
                    'language': 'c'
                }
            ],

            # CWE-416: Use After Free
            'use_after_free': [
                {
                    'template': '''
#include <stdlib.h>
void vulnerable_function() {
    char* ptr = malloc(100);
    free(ptr);
    strcpy(ptr, "data");  // Use after free
}
''',
                    'cwe': 'CWE-416',
                    'severity': 'critical',
                    'description': 'Use after free vulnerability',
                    'language': 'c'
                }
            ],

            # CWE-134: Format String Vulnerability
            'format_string': [
                {
                    'template': '''
#include <stdio.h>
void log_message(char* user_input) {
    printf(user_input);  // Format string vulnerability
}
''',
                    'cwe': 'CWE-134',
                    'severity': 'high',
                    'description': 'Format string vulnerability',
                    'language': 'c'
                }
            ],

            # CWE-190: Integer Overflow
            'integer_overflow': [
                {
                    'template': '''
def calculate_total(price, quantity):
    total = price * quantity
    if total < 0:  # Overflow check too late
        return 0
    return total
''',
                    'cwe': 'CWE-190',
                    'severity': 'medium',
                    'description': 'Integer overflow in calculation'
                }
            ],

            # CWE-362: Race Condition
            'race_condition': [
                {
                    'template': '''
import threading
balance = 1000

def withdraw(amount):
    global balance
    if balance >= amount:
        # Race condition here
        time.sleep(0.1)  # Simulating processing time
        balance -= amount
        return True
    return False
''',
                    'cwe': 'CWE-362',
                    'severity': 'medium',
                    'description': 'Race condition in balance check'
                }
            ],

            # CWE-476: NULL Pointer Dereference
            'null_pointer_dereference': [
                {
                    'template': '''
#include <stdio.h>
void process_data(char* data) {
    if (data == NULL) {
        return;
    }
    // Later in code, forgot to check again
    printf("Data: %s", data);  // Potential NULL dereference
}
''',
                    'cwe': 'CWE-476',
                    'severity': 'medium',
                    'description': 'NULL pointer dereference',
                    'language': 'c'
                }
            ],

            # CWE-611: XML External Entity (XXE)
            'xxe': [
                {
                    'template': '''
import xml.etree.ElementTree as ET
def parse_xml(xml_data):
    root = ET.fromstring(xml_data)  # Vulnerable to XXE
    return root
''',
                    'cwe': 'CWE-611',
                    'severity': 'high',
                    'description': 'XML External Entity vulnerability'
                }
            ],

            # CWE-918: Server-Side Request Forgery (SSRF)
            'ssrf': [
                {
                    'template': '''
import requests
def fetch_url(url):
    response = requests.get(url)  # No URL validation
    return response.content
''',
                    'cwe': 'CWE-918',
                    'severity': 'high',
                    'description': 'Server-Side Request Forgery'
                }
            ],

            # CWE-129: Array Index Out of Bounds
            'array_index_oob': [
                {
                    'template': '''
def get_item(items, index):
    return items[index]  # No bounds checking
''',
                    'cwe': 'CWE-129',
                    'severity': 'medium',
                    'description': 'Array index out of bounds'
                }
            ],

            # CWE-295: Certificate Validation Bypass
            'cert_validation_bypass': [
                {
                    'template': '''
import ssl
import urllib.request

def fetch_data(url):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=context)
''',
                    'cwe': 'CWE-295',
                    'severity': 'high',
                    'description': 'SSL certificate validation bypass'
                }
            ],

            # CWE-94: Code Injection
            'code_injection': [
                {
                    'template': '''
def execute_formula(formula):
    result = eval(formula)  # Code injection vulnerability
    return result
''',
                    'cwe': 'CWE-94',
                    'severity': 'critical',
                    'description': 'Code injection through eval'
                },
                {
                    'template': '''
def run_command(cmd):
    exec(cmd)  # Code injection vulnerability
''',
                    'cwe': 'CWE-94',
                    'severity': 'critical',
                    'description': 'Code injection through exec'
                }
            ]
        }

        return patterns

    def _initialize_safe_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize safe code patterns for negative examples"""

        patterns = {
            'sql_safe': [
                {
                    'template': '''
def login(username, password):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone()
''',
                    'description': 'Safe SQL query using parameterized statements'
                },
                {
                    'template': '''
from sqlalchemy import text
def search_products(category):
    query = text("SELECT * FROM products WHERE category = :category")
    return db.execute(query, category=category).fetchall()
''',
                    'description': 'Safe SQL query using SQLAlchemy parameterized query'
                }
            ],

            'command_safe': [
                {
                    'template': '''
import subprocess
def backup_file(filename):
    # Validate filename first
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        raise ValueError("Invalid filename")
    subprocess.run(['cp', filename, 'backup/'], check=True)
    return True
''',
                    'description': 'Safe command execution with validation and no shell'
                }
            ],

            'deserialization_safe': [
                {
                    'template': '''
import json
def load_user_data(data):
    return json.loads(data)  # Safe JSON deserialization
''',
                    'description': 'Safe deserialization using JSON'
                },
                {
                    'template': '''
import yaml
def parse_config(config_data):
    return yaml.safe_load(config_data)  # Safe YAML loading
''',
                    'description': 'Safe YAML deserialization using safe_load'
                }
            ],

            'credentials_safe': [
                {
                    'template': '''
import os
def connect_database():
    password = os.environ.get('DB_PASSWORD')
    return connect("localhost", "admin", password)
''',
                    'description': 'Safe credential management using environment variables'
                }
            ]
        }

        return patterns

    def generate_comprehensive_dataset(self, size: int = 10000) -> List[VulnerabilityExample]:
        """Generate comprehensive dataset with all vulnerability types"""
        dataset = []

        # Calculate distribution
        total_vuln_types = len(self.vulnerability_patterns)
        examples_per_type = max(size // (total_vuln_types * 2), 10)  # Half vulnerable, half safe

        logger.info(f"Generating {size} examples ({examples_per_type} per vulnerability type)")

        # Generate vulnerable examples
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for i in range(examples_per_type):
                pattern = random.choice(patterns)
                example = self._create_vulnerable_example(vuln_type, pattern, i)
                dataset.append(example)

        # Generate safe examples
        for safe_type, patterns in self.safe_patterns.items():
            for i in range(examples_per_type // 4):  # Fewer safe examples
                pattern = random.choice(patterns)
                example = self._create_safe_example(safe_type, pattern, i)
                dataset.append(example)

        # Add some completely safe generic examples
        for i in range(examples_per_type):
            example = self._create_generic_safe_example(i)
            dataset.append(example)

        # Shuffle dataset
        random.shuffle(dataset)

        logger.info(f"Generated {len(dataset)} total examples")
        return dataset[:size]  # Trim to exact size

    def _create_vulnerable_example(self, vuln_type: str, pattern: Dict[str, Any], index: int) -> VulnerabilityExample:
        """Create a vulnerable code example"""
        code = pattern['template'].strip()
        language = pattern.get('language', 'python')

        # Add variations to make dataset more diverse
        code = self._add_code_variations(code, vuln_type)

        # Generate unique ID
        example_id = hashlib.md5(f"{vuln_type}_{index}_{code}".encode()).hexdigest()[:16]

        # Generate mathematical signature
        math_signature = self._generate_mathematical_signature(code, vuln_type, True)

        # Generate topology features
        topology_features = self._generate_topology_features(code, vuln_type)

        return VulnerabilityExample(
            id=example_id,
            code=code,
            language=language,
            vulnerability_type=vuln_type,
            severity=pattern['severity'],
            cwe_id=pattern['cwe'],
            description=pattern['description'],
            is_vulnerable=True,
            exploit_proof=self._generate_exploit_proof(vuln_type, code),
            mathematical_signature=math_signature,
            topology_features=topology_features
        )

    def _create_safe_example(self, safe_type: str, pattern: Dict[str, Any], index: int) -> VulnerabilityExample:
        """Create a safe code example"""
        code = pattern['template'].strip()

        # Generate unique ID
        example_id = hashlib.md5(f"{safe_type}_safe_{index}_{code}".encode()).hexdigest()[:16]

        # Generate mathematical signature for safe code
        math_signature = self._generate_mathematical_signature(code, safe_type, False)

        return VulnerabilityExample(
            id=example_id,
            code=code,
            language='python',
            vulnerability_type='safe',
            severity='none',
            cwe_id='',
            description=pattern['description'],
            is_vulnerable=False,
            mathematical_signature=math_signature
        )

    def _create_generic_safe_example(self, index: int) -> VulnerabilityExample:
        """Create generic safe code examples"""
        safe_templates = [
            '''
def add_numbers(a, b):
    return a + b
''',
            '''
def get_user_name():
    return "John Doe"
''',
            '''
import hashlib
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
''',
            '''
def validate_email(email):
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
''',
            '''
def calculate_area(length, width):
    if length > 0 and width > 0:
        return length * width
    return 0
'''
        ]

        code = random.choice(safe_templates).strip()
        example_id = hashlib.md5(f"generic_safe_{index}_{code}".encode()).hexdigest()[:16]

        return VulnerabilityExample(
            id=example_id,
            code=code,
            language='python',
            vulnerability_type='safe',
            severity='none',
            cwe_id='',
            description='Generic safe code example',
            is_vulnerable=False,
            mathematical_signature=self._generate_mathematical_signature(code, 'safe', False)
        )

    def _add_code_variations(self, code: str, vuln_type: str) -> str:
        """Add variations to make code examples more diverse"""
        variations = [
            lambda c: c.replace('username', random.choice(['user_name', 'login', 'user_id'])),
            lambda c: c.replace('password', random.choice(['passwd', 'pwd', 'auth_token'])),
            lambda c: c.replace('filename', random.choice(['file_path', 'file_name', 'path'])),
            lambda c: c.replace('query', random.choice(['sql_query', 'db_query', 'statement'])),
        ]

        # Apply random variations
        if random.random() < 0.3:  # 30% chance of variation
            variation = random.choice(variations)
            code = variation(code)

        return code

    def _generate_mathematical_signature(self, code: str, vuln_type: str, is_vulnerable: bool) -> str:
        """Generate mathematical signature for the code"""
        # Simple mathematical signature based on code structure
        code_length = len(code)
        complexity = code.count('if') + code.count('for') + code.count('while')
        dangerous_funcs = sum(1 for func in ['exec', 'eval', 'system', 'execute'] if func in code)

        if is_vulnerable:
            signature = f"vuln_sig(L={code_length}, C={complexity}, D={dangerous_funcs}, T={vuln_type})"
        else:
            signature = f"safe_sig(L={code_length}, C={complexity}, D={dangerous_funcs})"

        return signature

    def _generate_topology_features(self, code: str, vuln_type: str) -> Dict[str, Any]:
        """Generate topological features for the code"""
        # Simple topology features based on code structure
        lines = code.split('\n')
        indentation_levels = []

        for line in lines:
            if line.strip():
                indent = len(line) - len(line.lstrip())
                indentation_levels.append(indent)

        max_depth = max(indentation_levels) if indentation_levels else 0
        avg_depth = sum(indentation_levels) / len(indentation_levels) if indentation_levels else 0

        return {
            'max_indentation_depth': max_depth,
            'avg_indentation_depth': avg_depth,
            'total_lines': len([l for l in lines if l.strip()]),
            'complexity_estimate': code.count('{') + code.count('(') + code.count('['),
            'vulnerability_type': vuln_type
        }

    def _generate_exploit_proof(self, vuln_type: str, code: str) -> str:
        """Generate exploit proof for vulnerable code"""
        exploit_templates = {
            'sql_injection': "payload = \"' OR '1'='1' --\"",
            'command_injection': "payload = \"; rm -rf / #\"",
            'xss': "payload = \"<script>alert('XSS')</script>\"",
            'path_traversal': "payload = \"../../../etc/passwd\"",
            'unsafe_deserialization': "payload = pickle.dumps(__import__('os').system('id'))",
            'code_injection': "payload = \"__import__('os').system('whoami')\"",
        }

        return exploit_templates.get(vuln_type, f"Exploit for {vuln_type} vulnerability")

    def save_dataset(self, dataset: List[VulnerabilityExample], filepath: str):
        """Save dataset to JSON file"""
        data = [asdict(example) for example in dataset]

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved {len(dataset)} examples to {filepath}")

    def generate_cwe_coverage_report(self, dataset: List[VulnerabilityExample]) -> Dict[str, Any]:
        """Generate CWE coverage report"""
        cwe_counts = {}
        vuln_type_counts = {}
        severity_counts = {}

        for example in dataset:
            if example.is_vulnerable:
                cwe_counts[example.cwe_id] = cwe_counts.get(example.cwe_id, 0) + 1
                vuln_type_counts[example.vulnerability_type] = vuln_type_counts.get(example.vulnerability_type, 0) + 1
                severity_counts[example.severity] = severity_counts.get(example.severity, 0) + 1

        return {
            'total_examples': len(dataset),
            'vulnerable_examples': len([e for e in dataset if e.is_vulnerable]),
            'safe_examples': len([e for e in dataset if not e.is_vulnerable]),
            'cwe_coverage': len(cwe_counts),
            'cwe_distribution': cwe_counts,
            'vulnerability_type_distribution': vuln_type_counts,
            'severity_distribution': severity_counts,
            'unique_cwes': list(cwe_counts.keys())
        }

def main():
    """Generate comprehensive vulnerability dataset"""
    generator = ComprehensiveVulnDatasetGenerator()

    # Generate dataset
    dataset = generator.generate_comprehensive_dataset(size=20000)

    # Save dataset
    output_dir = Path(__file__).parent.parent / "training_data"
    output_dir.mkdir(exist_ok=True)

    dataset_file = output_dir / "comprehensive_vulnerability_dataset.json"
    generator.save_dataset(dataset, str(dataset_file))

    # Generate coverage report
    coverage_report = generator.generate_cwe_coverage_report(dataset)

    report_file = output_dir / "dataset_coverage_report.json"
    with open(report_file, 'w') as f:
        json.dump(coverage_report, f, indent=2)

    print(f"✅ Generated comprehensive dataset with {len(dataset)} examples")
    print(f"📊 CWE Coverage: {coverage_report['cwe_coverage']} unique CWEs")
    print(f"🎯 Vulnerability Types: {len(coverage_report['vulnerability_type_distribution'])}")
    print(f"📁 Saved to: {dataset_file}")
    print(f"📋 Report: {report_file}")

if __name__ == "__main__":
    main()