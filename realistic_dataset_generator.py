#!/usr/bin/env python3
"""
Realistic Dataset Generator for VulnHunter AI Training
Generates comprehensive vulnerability datasets based on real-world patterns
"""

import os
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from pathlib import Path
import hashlib
import random
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('realistic_dataset_generation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('RealisticDatasetGenerator')

class RealisticDatasetGenerator:
    """Generates realistic vulnerability datasets for training"""

    def __init__(self, output_dir: str = "realistic_datasets"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Real vulnerability patterns from research
        self.vulnerability_patterns = {
            "SQL_INJECTION": {
                "cwe_ids": ["CWE-89"],
                "patterns": [
                    'query = "SELECT * FROM users WHERE id = " + user_id',
                    'cursor.execute("DELETE FROM table WHERE id = %s" % id)',
                    'sql = f"INSERT INTO logs VALUES ({user_input})"',
                    'db.query("SELECT * FROM data WHERE name = \'" + name + "\'")'
                ],
                "languages": ["Python", "Java", "PHP", "C#"],
                "severity_dist": [0.6, 0.3, 0.1]  # High, Medium, Low
            },
            "BUFFER_OVERFLOW": {
                "cwe_ids": ["CWE-119", "CWE-120", "CWE-787"],
                "patterns": [
                    'char buffer[256];\nstrcpy(buffer, user_input);',
                    'gets(input_buffer);',
                    'sprintf(dest, "%s", source);',
                    'memcpy(dst, src, len);  // No bounds checking'
                ],
                "languages": ["C", "C++"],
                "severity_dist": [0.8, 0.2, 0.0]  # High, Medium, Low
            },
            "COMMAND_INJECTION": {
                "cwe_ids": ["CWE-78"],
                "patterns": [
                    'os.system("ls " + user_path)',
                    'subprocess.call(["ping", user_input], shell=True)',
                    'exec("rm -rf " + directory)',
                    'system("cat " + filename);'
                ],
                "languages": ["Python", "C", "Java", "Shell"],
                "severity_dist": [0.7, 0.25, 0.05]
            },
            "XSS": {
                "cwe_ids": ["CWE-79"],
                "patterns": [
                    'document.innerHTML = user_input;',
                    'response.write("<div>" + request.params.name + "</div>");',
                    'echo "<script>alert(\'" + $_GET["msg"] + "\')</script>";',
                    'output += "<h1>" + title + "</h1>";'
                ],
                "languages": ["JavaScript", "PHP", "Java", "C#"],
                "severity_dist": [0.4, 0.5, 0.1]
            },
            "PATH_TRAVERSAL": {
                "cwe_ids": ["CWE-22"],
                "patterns": [
                    'file_path = "/uploads/" + filename',
                    'open("../data/" + user_file, "r")',
                    'FileInputStream(base_path + file_name)',
                    'include($_GET["page"] . ".php");'
                ],
                "languages": ["Python", "Java", "PHP", "C"],
                "severity_dist": [0.5, 0.4, 0.1]
            },
            "WEAK_CRYPTO": {
                "cwe_ids": ["CWE-327", "CWE-328"],
                "patterns": [
                    'hashlib.md5(password.encode()).hexdigest()',
                    'DES.new(key, DES.MODE_ECB)',
                    'cipher = AES.new(key, AES.MODE_ECB)',
                    'MessageDigest.getInstance("SHA1")'
                ],
                "languages": ["Python", "Java", "C++", "C#"],
                "severity_dist": [0.3, 0.6, 0.1]
            },
            "DESERIALIZATION": {
                "cwe_ids": ["CWE-502"],
                "patterns": [
                    'pickle.loads(user_data)',
                    'ObjectInputStream.readObject()',
                    'unserialize($_POST["data"])',
                    'JsonConvert.DeserializeObject<T>(json)'
                ],
                "languages": ["Python", "Java", "PHP", "C#"],
                "severity_dist": [0.8, 0.15, 0.05]
            },
            "RACE_CONDITION": {
                "cwe_ids": ["CWE-362"],
                "patterns": [
                    'if (file.exists()) {\n    file.delete();\n}',
                    'check_then_use_pattern()',
                    'if (!lock.tryLock()) return;',
                    'temp_file = mktemp();'
                ],
                "languages": ["C", "C++", "Java", "Python"],
                "severity_dist": [0.6, 0.3, 0.1]
            },
            "NULL_POINTER": {
                "cwe_ids": ["CWE-476"],
                "patterns": [
                    'ptr->value = 42;  // ptr not checked',
                    'object.method();  // object could be null',
                    'return array[index];  // array could be null',
                    'strcpy(dest, src);  // src could be null'
                ],
                "languages": ["C", "C++", "Java", "C#"],
                "severity_dist": [0.4, 0.5, 0.1]
            },
            "INTEGER_OVERFLOW": {
                "cwe_ids": ["CWE-190"],
                "patterns": [
                    'size_t len = strlen(input) + 1;',
                    'int total = a + b;  // No overflow check',
                    'buffer = malloc(count * sizeof(int));',
                    'index = base + offset;'
                ],
                "languages": ["C", "C++"],
                "severity_dist": [0.5, 0.4, 0.1]
            }
        }

        # Safe code patterns
        self.safe_patterns = {
            "SQL_SAFE": [
                'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                'query = "SELECT * FROM data WHERE name = %s"\ncursor.execute(query, (name,))',
                'stmt = connection.prepareStatement("SELECT * FROM table WHERE id = ?");'
            ],
            "BUFFER_SAFE": [
                'strncpy(buffer, user_input, sizeof(buffer) - 1);',
                'snprintf(dest, sizeof(dest), "%s", source);',
                'if (len < sizeof(buffer)) strcpy(buffer, input);'
            ],
            "COMMAND_SAFE": [
                'subprocess.run(["ls", sanitized_path])',
                'os.path.join(base_dir, filename)',
                'shlex.quote(user_input)'
            ],
            "XSS_SAFE": [
                'document.textContent = user_input;',
                'output += htmlspecialchars($user_input);',
                'element.appendChild(document.createTextNode(data));'
            ]
        }

        # Project and file name generators
        self.project_names = [
            "apache-httpd", "nginx", "openssl", "curl", "sqlite", "postgresql",
            "mysql", "redis", "mongodb", "elasticsearch", "prometheus",
            "kubernetes", "docker", "tensorflow", "pytorch", "numpy",
            "scipy", "pandas", "flask", "django", "rails", "nodejs",
            "react", "vue", "angular", "jquery", "bootstrap", "webpack"
        ]

        self.file_extensions = {
            "C": ".c",
            "C++": ".cpp",
            "Java": ".java",
            "Python": ".py",
            "JavaScript": ".js",
            "PHP": ".php",
            "C#": ".cs",
            "Shell": ".sh"
        }

    def generate_vulnerability_record(self, vuln_type: str, index: int) -> Dict[str, Any]:
        """Generate a realistic vulnerability record"""

        vuln_config = self.vulnerability_patterns[vuln_type]

        # Select random elements
        cwe_id = random.choice(vuln_config["cwe_ids"])
        pattern = random.choice(vuln_config["patterns"])
        language = random.choice(vuln_config["languages"])
        project = random.choice(self.project_names)

        # Generate severity based on distribution
        severities = ["HIGH", "MEDIUM", "LOW"]
        severity = np.random.choice(severities, p=vuln_config["severity_dist"])

        # Generate realistic file path
        file_ext = self.file_extensions[language]
        file_path = f"/src/{project}/security/{vuln_type.lower()}_{index}{file_ext}"

        # Generate function name
        function_name = f"process_{vuln_type.lower()}_{index}"

        # Create full code snippet with context
        code_snippet = self.generate_code_context(pattern, language, function_name)

        # Generate CVE ID (realistic format)
        year = random.randint(2019, 2024)
        cve_num = random.randint(1000, 99999)
        cve_id = f"CVE-{year}-{cve_num}"

        # Generate description
        description = f"{vuln_type.replace('_', ' ').title()} vulnerability in {function_name} function allowing potential security compromise"

        record = {
            "cve_id": cve_id,
            "cwe_id": cwe_id,
            "severity": severity,
            "description": description,
            "code_snippet": code_snippet,
            "language": language,
            "file_path": file_path,
            "function_name": function_name,
            "vulnerability_type": vuln_type.replace("_", " ").title(),
            "is_vulnerable": True,
            "source_dataset": "Realistic_Generated",
            "project_name": project,
            "commit_hash": hashlib.md5(f"{project}_{index}".encode()).hexdigest()[:10],
            "line_numbers": [random.randint(10, 100)],
            "confidence_score": random.uniform(0.85, 0.98),
            "metadata": {
                "generated": True,
                "pattern_based": True,
                "review_required": False
            }
        }

        return record

    def generate_safe_record(self, index: int) -> Dict[str, Any]:
        """Generate a safe (non-vulnerable) code record"""

        safe_types = list(self.safe_patterns.keys())
        safe_type = random.choice(safe_types)
        pattern = random.choice(self.safe_patterns[safe_type])

        # Map safe type to language
        language_mapping = {
            "SQL_SAFE": ["Python", "Java", "C#"],
            "BUFFER_SAFE": ["C", "C++"],
            "COMMAND_SAFE": ["Python", "Shell"],
            "XSS_SAFE": ["JavaScript", "PHP", "Java"]
        }

        language = random.choice(language_mapping.get(safe_type, ["Python", "Java", "C"]))
        project = random.choice(self.project_names)

        # Generate file info
        file_ext = self.file_extensions[language]
        file_path = f"/src/{project}/safe/safe_{index}{file_ext}"
        function_name = f"safe_function_{index}"

        # Create code snippet
        code_snippet = self.generate_code_context(pattern, language, function_name, is_safe=True)

        record = {
            "cve_id": "",
            "cwe_id": "",
            "severity": "NONE",
            "description": f"Safe implementation in {function_name} with proper security controls",
            "code_snippet": code_snippet,
            "language": language,
            "file_path": file_path,
            "function_name": function_name,
            "vulnerability_type": "NONE",
            "is_vulnerable": False,
            "source_dataset": "Realistic_Generated",
            "project_name": project,
            "commit_hash": hashlib.md5(f"{project}_safe_{index}".encode()).hexdigest()[:10],
            "line_numbers": [random.randint(10, 100)],
            "confidence_score": random.uniform(0.90, 0.99),
            "metadata": {
                "generated": True,
                "pattern_based": True,
                "safe_implementation": True
            }
        }

        return record

    def generate_code_context(self, pattern: str, language: str, function_name: str, is_safe: bool = False) -> str:
        """Generate realistic code context around the vulnerability pattern"""

        if language == "Python":
            return f'''#!/usr/bin/env python3
"""
{function_name} - {'Safe' if is_safe else 'Vulnerable'} implementation
"""

import os
import sys
import logging

def {function_name}(user_input, options=None):
    """
    Process user input with {'proper' if is_safe else 'insufficient'} validation
    """
    try:
        if not user_input:
            return None

        # {'Proper input validation' if is_safe else 'Insufficient validation'}
        {'if not validate_input(user_input): return None' if is_safe else '# TODO: Add input validation'}

        # Main processing logic
        {pattern}

        return True

    except Exception as e:
        logging.error(f"Error in {function_name}: {{e}}")
        return False
'''

        elif language in ["C", "C++"]:
            return f'''/*
 * {function_name} - {'Safe' if is_safe else 'Vulnerable'} implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int {function_name}(char* user_input, size_t input_len) {{
    if (!user_input) {{
        return -1;
    }}

    {'// Proper bounds checking' if is_safe else '// Missing bounds checking'}
    {'if (input_len >= MAX_BUFFER_SIZE) return -1;' if is_safe else ''}

    // Main processing
    {pattern}

    return 0;
}}
'''

        elif language == "Java":
            return f'''/**
 * {function_name} - {'Safe' if is_safe else 'Vulnerable'} implementation
 */

public class SecurityHandler {{

    public boolean {function_name}(String userInput) {{
        if (userInput == null || userInput.isEmpty()) {{
            return false;
        }}

        {'// Proper input validation' if is_safe else '// Missing input validation'}
        {'if (!validateInput(userInput)) return false;' if is_safe else ''}

        try {{
            // Main processing
            {pattern}
            return true;
        }} catch (Exception e) {{
            logger.error("Error in {function_name}: " + e.getMessage());
            return false;
        }}
    }}
}}
'''

        else:  # Default format
            return f'''/*
 * {function_name} - {'Safe' if is_safe else 'Vulnerable'} implementation
 */

function {function_name}(userInput) {{
    if (!userInput) {{
        return null;
    }}

    {'// Proper input sanitization' if is_safe else '// Missing input sanitization'}
    {'userInput = sanitizeInput(userInput);' if is_safe else ''}

    // Main processing
    {pattern}

    return true;
}}
'''

    def generate_comprehensive_dataset(self, total_samples: int = 100000) -> List[Dict[str, Any]]:
        """Generate comprehensive realistic dataset"""

        logger.info("🔄 Generating Comprehensive Realistic Dataset")
        logger.info("=" * 60)
        logger.info(f"Target samples: {total_samples:,}")

        all_records = []

        # Calculate distribution (70% vulnerable, 30% safe)
        vulnerable_samples = int(total_samples * 0.7)
        safe_samples = total_samples - vulnerable_samples

        logger.info(f"  📊 Vulnerable samples: {vulnerable_samples:,}")
        logger.info(f"  📊 Safe samples: {safe_samples:,}")

        # Generate vulnerable samples
        vuln_types = list(self.vulnerability_patterns.keys())
        samples_per_type = vulnerable_samples // len(vuln_types)

        logger.info("🔍 Generating vulnerable samples...")

        for vuln_type in vuln_types:
            logger.info(f"  📝 Generating {vuln_type}: {samples_per_type:,} samples")

            for i in range(samples_per_type):
                record = self.generate_vulnerability_record(vuln_type, i)
                all_records.append(record)

                if len(all_records) % 5000 == 0:
                    logger.info(f"    📈 Generated {len(all_records):,} total records")

        # Generate safe samples
        logger.info("✅ Generating safe samples...")

        for i in range(safe_samples):
            record = self.generate_safe_record(i)
            all_records.append(record)

            if len(all_records) % 5000 == 0:
                logger.info(f"    📈 Generated {len(all_records):,} total records")

        # Shuffle the dataset
        random.shuffle(all_records)

        logger.info(f"✅ Dataset generation completed: {len(all_records):,} records")

        return all_records

    def save_dataset(self, records: List[Dict[str, Any]], dataset_name: str = "comprehensive_realistic_dataset"):
        """Save dataset in multiple formats"""

        logger.info("💾 Saving realistic dataset...")

        # Convert to DataFrame
        df = pd.DataFrame(records)

        # Basic statistics
        stats = {
            "total_records": len(records),
            "vulnerable_records": len(df[df['is_vulnerable'] == True]),
            "safe_records": len(df[df['is_vulnerable'] == False]),
            "languages": df['language'].value_counts().to_dict(),
            "vulnerability_types": df[df['is_vulnerable'] == True]['vulnerability_type'].value_counts().to_dict(),
            "severity_distribution": df[df['is_vulnerable'] == True]['severity'].value_counts().to_dict(),
            "cwe_distribution": df[df['is_vulnerable'] == True]['cwe_id'].value_counts().to_dict(),
            "generation_date": datetime.now().isoformat()
        }

        # Save files
        base_path = self.output_dir / dataset_name

        # Parquet (for ML training)
        df.to_parquet(f"{base_path}.parquet", compression='gzip')
        logger.info(f"  ✅ Saved Parquet: {base_path}.parquet")

        # CSV (human readable)
        df.to_csv(f"{base_path}.csv", index=False)
        logger.info(f"  ✅ Saved CSV: {base_path}.csv")

        # JSON (structured)
        with open(f"{base_path}.json", 'w') as f:
            json.dump(records, f, indent=2, default=str)
        logger.info(f"  ✅ Saved JSON: {base_path}.json")

        # Statistics
        with open(f"{base_path}_statistics.json", 'w') as f:
            json.dump(stats, f, indent=2, default=str)
        logger.info(f"  ✅ Saved statistics: {base_path}_statistics.json")

        # Dataset summary
        logger.info("📊 Dataset Summary:")
        logger.info(f"  📈 Total Records: {stats['total_records']:,}")
        logger.info(f"  🔴 Vulnerable: {stats['vulnerable_records']:,}")
        logger.info(f"  🟢 Safe: {stats['safe_records']:,}")
        logger.info(f"  🌐 Languages: {len(stats['languages'])}")
        logger.info(f"  🔍 Vulnerability Types: {len(stats['vulnerability_types'])}")

        return stats

def main():
    """Generate comprehensive realistic dataset"""

    logger.info("🎬 Initializing Realistic Dataset Generator")

    # Initialize generator
    generator = RealisticDatasetGenerator()

    # Generate comprehensive dataset
    logger.info("🚀 Starting dataset generation...")

    # Generate large-scale dataset
    records = generator.generate_comprehensive_dataset(total_samples=50000)  # 50K samples for demo

    # Save dataset
    stats = generator.save_dataset(records)

    logger.info("✅ Realistic Dataset Generation Completed Successfully!")
    return records, stats

if __name__ == "__main__":
    records, stats = main()