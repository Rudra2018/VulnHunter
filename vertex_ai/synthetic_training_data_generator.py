#!/usr/bin/env python3
"""
Synthetic Training Data Generator for VulnHunter V4
Generates comprehensive training examples to enhance model performance
"""

import json
import random
import numpy as np
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

class SyntheticTrainingDataGenerator:
    """Generate synthetic training data for VulnHunter V4 enhancement."""

    def __init__(self, output_path: str):
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)

    def generate_false_positive_examples(self, count: int = 1000) -> List[Dict]:
        """Generate false positive examples based on known patterns."""
        examples = []

        # False positive patterns from validation
        fp_patterns = {
            "file_fabrication": {
                "weight": 0.3,
                "examples": [
                    {
                        "claim": "SQL injection in user_auth.py:145",
                        "reality": "File has only 89 lines",
                        "pattern": "line_number_beyond_file_length"
                    },
                    {
                        "claim": "XSS vulnerability in templates/user_profile.html",
                        "reality": "File does not exist",
                        "pattern": "non_existent_file_reference"
                    }
                ]
            },
            "function_invention": {
                "weight": 0.25,
                "examples": [
                    {
                        "claim": "Buffer overflow in unsafeMemcpy() function",
                        "reality": "Function does not exist in codebase",
                        "pattern": "fabricated_function_name"
                    },
                    {
                        "claim": "Path traversal in readUserFile() method",
                        "reality": "No such method in the class",
                        "pattern": "non_existent_method"
                    }
                ]
            },
            "framework_ignorance": {
                "weight": 0.2,
                "examples": [
                    {
                        "claim": "Unsafe JSON parsing without validation",
                        "reality": "Express.js middleware provides automatic validation",
                        "pattern": "framework_protection_ignored"
                    },
                    {
                        "claim": "Type confusion vulnerability",
                        "reality": "TypeScript provides compile-time type safety",
                        "pattern": "type_system_safety_ignored"
                    }
                ]
            },
            "secure_misidentification": {
                "weight": 0.15,
                "examples": [
                    {
                        "claim": "Command injection in system call",
                        "reality": "Hardcoded system path with no user input",
                        "pattern": "secure_implementation_flagged"
                    },
                    {
                        "claim": "Path traversal vulnerability",
                        "reality": "Explicit path validation with boundary checks",
                        "pattern": "validated_input_flagged"
                    }
                ]
            },
            "inflation_patterns": {
                "weight": 0.1,
                "examples": [
                    {
                        "claim": "1,500 critical vulnerabilities found",
                        "reality": "150 actual patterns, mostly in test code",
                        "pattern": "vulnerability_count_inflation"
                    },
                    {
                        "claim": "Average bounty value: $50,000",
                        "reality": "Market average is $5,000",
                        "pattern": "bounty_value_inflation"
                    }
                ]
            }
        }

        # Generate examples based on patterns
        for i in range(count):
            pattern_type = np.random.choice(
                list(fp_patterns.keys()),
                p=[fp_patterns[k]["weight"] for k in fp_patterns.keys()]
            )

            base_example = np.random.choice(fp_patterns[pattern_type]["examples"])

            example = {
                "example_id": f"synthetic_fp_{i:04d}",
                "pattern_type": pattern_type,
                "pattern_subtype": base_example["pattern"],
                "claimed_vulnerability": {
                    "description": base_example["claim"],
                    "severity": np.random.choice(["Critical", "High", "Medium", "Low"], p=[0.4, 0.3, 0.2, 0.1]),
                    "confidence": np.random.uniform(0.6, 0.95),
                    "file_path": self._generate_realistic_file_path(),
                    "function_name": self._generate_function_name(pattern_type),
                    "line_number": np.random.randint(1, 500),
                    "framework": np.random.choice(["Express.js", "React", "Node.js", "TypeScript", "Unknown"])
                },
                "reality": {
                    "description": base_example["reality"],
                    "actual_severity": "None",
                    "validation_method": "source_code_inspection"
                },
                "validation_features": {
                    "file_exists": pattern_type != "file_fabrication",
                    "function_exists": pattern_type != "function_invention",
                    "line_number_valid": pattern_type != "file_fabrication",
                    "has_security_controls": pattern_type in ["framework_ignorance", "secure_misidentification"],
                    "framework_protection": pattern_type == "framework_ignorance"
                },
                "training_labels": {
                    "is_false_positive": True,
                    "confidence_adjustment": np.random.uniform(0.8, 1.0),
                    "false_positive_probability": np.random.uniform(0.7, 0.95)
                }
            }

            examples.append(example)

        return examples

    def generate_true_positive_examples(self, count: int = 300) -> List[Dict]:
        """Generate legitimate vulnerability examples."""
        examples = []

        # True positive patterns
        tp_patterns = {
            "input_validation": {
                "weight": 0.3,
                "examples": [
                    {
                        "description": "SQL injection via unsanitized user input",
                        "severity": "Critical",
                        "confidence_range": (0.8, 0.95)
                    },
                    {
                        "description": "XSS via unescaped user content",
                        "severity": "High",
                        "confidence_range": (0.75, 0.9)
                    }
                ]
            },
            "authentication": {
                "weight": 0.25,
                "examples": [
                    {
                        "description": "JWT token validation bypass",
                        "severity": "Critical",
                        "confidence_range": (0.85, 0.95)
                    },
                    {
                        "description": "Session fixation vulnerability",
                        "severity": "High",
                        "confidence_range": (0.7, 0.85)
                    }
                ]
            },
            "authorization": {
                "weight": 0.2,
                "examples": [
                    {
                        "description": "Privilege escalation via role confusion",
                        "severity": "High",
                        "confidence_range": (0.75, 0.9)
                    },
                    {
                        "description": "Direct object reference without authorization",
                        "severity": "Medium",
                        "confidence_range": (0.65, 0.8)
                    }
                ]
            },
            "crypto": {
                "weight": 0.15,
                "examples": [
                    {
                        "description": "Weak cryptographic algorithm usage",
                        "severity": "Medium",
                        "confidence_range": (0.6, 0.8)
                    },
                    {
                        "description": "Hardcoded cryptographic key",
                        "severity": "High",
                        "confidence_range": (0.8, 0.9)
                    }
                ]
            },
            "configuration": {
                "weight": 0.1,
                "examples": [
                    {
                        "description": "Debug mode enabled in production",
                        "severity": "Medium",
                        "confidence_range": (0.7, 0.85)
                    },
                    {
                        "description": "Default credentials not changed",
                        "severity": "High",
                        "confidence_range": (0.85, 0.95)
                    }
                ]
            }
        }

        for i in range(count):
            pattern_type = np.random.choice(
                list(tp_patterns.keys()),
                p=[tp_patterns[k]["weight"] for k in tp_patterns.keys()]
            )

            base_example = np.random.choice(tp_patterns[pattern_type]["examples"])
            conf_range = base_example["confidence_range"]

            example = {
                "example_id": f"synthetic_tp_{i:04d}",
                "pattern_type": pattern_type,
                "claimed_vulnerability": {
                    "description": base_example["description"],
                    "severity": base_example["severity"],
                    "confidence": np.random.uniform(conf_range[0], conf_range[1]),
                    "file_path": self._generate_realistic_file_path(),
                    "function_name": self._generate_function_name("legitimate"),
                    "line_number": np.random.randint(1, 200),
                    "framework": np.random.choice(["Express.js", "React", "Node.js", "Django", "Flask"])
                },
                "reality": {
                    "description": "Legitimate security vulnerability confirmed",
                    "actual_severity": base_example["severity"],
                    "validation_method": "manual_verification"
                },
                "validation_features": {
                    "file_exists": True,
                    "function_exists": True,
                    "line_number_valid": True,
                    "has_security_controls": False,
                    "framework_protection": False
                },
                "training_labels": {
                    "is_false_positive": False,
                    "confidence_adjustment": np.random.uniform(0.0, 0.2),
                    "false_positive_probability": np.random.uniform(0.05, 0.3)
                }
            }

            examples.append(example)

        return examples

    def generate_framework_specific_examples(self, count: int = 500) -> List[Dict]:
        """Generate framework-specific examples."""
        examples = []

        frameworks = {
            "express_nodejs": {
                "security_features": ["express.json() middleware", "helmet middleware", "CORS protection"],
                "common_vulnerabilities": ["prototype pollution", "regex DoS", "path traversal"],
                "protection_patterns": ["input validation", "rate limiting", "sanitization"]
            },
            "typescript": {
                "security_features": ["type safety", "compile-time checks", "strict null checks"],
                "common_vulnerabilities": ["type confusion", "any type usage", "unsafe assertions"],
                "protection_patterns": ["interface definitions", "type guards", "readonly properties"]
            },
            "react": {
                "security_features": ["JSX escaping", "props validation", "state immutability"],
                "common_vulnerabilities": ["XSS via dangerouslySetInnerHTML", "state manipulation"],
                "protection_patterns": ["controlled components", "prop types", "context security"]
            },
            "django": {
                "security_features": ["CSRF protection", "SQL injection prevention", "XSS protection"],
                "common_vulnerabilities": ["template injection", "unsafe eval", "permission bypass"],
                "protection_patterns": ["ORM usage", "template escaping", "middleware protection"]
            }
        }

        for i in range(count):
            framework = np.random.choice(list(frameworks.keys()))
            framework_info = frameworks[framework]

            # 70% framework protection examples, 30% legitimate vulnerabilities
            is_protected = np.random.random() < 0.7

            if is_protected:
                # Framework provides protection
                vuln_type = np.random.choice(framework_info["common_vulnerabilities"])
                protection = np.random.choice(framework_info["security_features"])

                example = {
                    "example_id": f"synthetic_fw_{i:04d}",
                    "pattern_type": "framework_protection",
                    "framework": framework,
                    "claimed_vulnerability": {
                        "description": f"{vuln_type} vulnerability",
                        "severity": np.random.choice(["High", "Medium"], p=[0.3, 0.7]),
                        "confidence": np.random.uniform(0.6, 0.85),
                        "file_path": self._generate_framework_file_path(framework),
                        "function_name": self._generate_function_name("framework"),
                        "line_number": np.random.randint(1, 150)
                    },
                    "reality": {
                        "description": f"Protected by {protection}",
                        "actual_severity": "Low",
                        "framework_protection": protection
                    },
                    "validation_features": {
                        "file_exists": True,
                        "function_exists": True,
                        "line_number_valid": True,
                        "has_security_controls": True,
                        "framework_protection": True
                    },
                    "training_labels": {
                        "is_false_positive": False,
                        "confidence_adjustment": np.random.uniform(0.3, 0.6),
                        "false_positive_probability": np.random.uniform(0.2, 0.5)
                    }
                }
            else:
                # Legitimate framework-specific vulnerability
                vuln_type = np.random.choice(framework_info["common_vulnerabilities"])

                example = {
                    "example_id": f"synthetic_fw_{i:04d}",
                    "pattern_type": "framework_vulnerability",
                    "framework": framework,
                    "claimed_vulnerability": {
                        "description": f"Unprotected {vuln_type}",
                        "severity": np.random.choice(["Critical", "High", "Medium"], p=[0.2, 0.5, 0.3]),
                        "confidence": np.random.uniform(0.7, 0.9),
                        "file_path": self._generate_framework_file_path(framework),
                        "function_name": self._generate_function_name("framework"),
                        "line_number": np.random.randint(1, 150)
                    },
                    "reality": {
                        "description": "Legitimate vulnerability confirmed",
                        "actual_severity": np.random.choice(["Critical", "High", "Medium"], p=[0.2, 0.5, 0.3]),
                        "framework_protection": None
                    },
                    "validation_features": {
                        "file_exists": True,
                        "function_exists": True,
                        "line_number_valid": True,
                        "has_security_controls": False,
                        "framework_protection": False
                    },
                    "training_labels": {
                        "is_false_positive": False,
                        "confidence_adjustment": np.random.uniform(0.0, 0.2),
                        "false_positive_probability": np.random.uniform(0.05, 0.25)
                    }
                }

            examples.append(example)

        return examples

    def _generate_realistic_file_path(self) -> str:
        """Generate realistic file paths."""
        dirs = ["src", "lib", "components", "utils", "services", "controllers", "models"]
        subdirs = ["auth", "user", "admin", "api", "core", "common", "helpers"]
        files = ["index", "main", "app", "server", "client", "config", "utils"]
        extensions = [".js", ".ts", ".py", ".java", ".rb", ".php", ".go"]

        return f"{np.random.choice(dirs)}/{np.random.choice(subdirs)}/{np.random.choice(files)}{np.random.choice(extensions)}"

    def _generate_framework_file_path(self, framework: str) -> str:
        """Generate framework-specific file paths."""
        framework_paths = {
            "express_nodejs": ["routes/api.js", "middleware/auth.js", "controllers/user.js"],
            "typescript": ["src/types.ts", "lib/utils.ts", "components/App.tsx"],
            "react": ["components/UserProfile.jsx", "hooks/useAuth.ts", "pages/Dashboard.tsx"],
            "django": ["views.py", "models.py", "urls.py", "settings.py"]
        }

        return np.random.choice(framework_paths.get(framework, ["src/main.js"]))

    def _generate_function_name(self, context: str) -> str:
        """Generate appropriate function names based on context."""
        if context == "file_fabrication" or context == "function_invention":
            # Fabricated function names that don't exist
            return np.random.choice([
                "executeCommand", "readUserFile", "mergeUserConfig", "handleApiRequest",
                "createTempFile", "validateInput", "processData", "authenticateUser"
            ])
        elif context == "framework":
            # Framework-specific function names
            return np.random.choice([
                "middleware", "handler", "component", "reducer", "action",
                "validator", "serializer", "view", "controller"
            ])
        else:
            # Legitimate function names
            return np.random.choice([
                "authenticate", "authorize", "validate", "sanitize", "encrypt",
                "decrypt", "hash", "verify", "process", "handle"
            ])

    def generate_comprehensive_dataset(self) -> Dict:
        """Generate comprehensive training dataset."""
        print("Generating comprehensive training dataset...")

        # Generate different types of examples
        false_positives = self.generate_false_positive_examples(1000)
        true_positives = self.generate_true_positive_examples(300)
        framework_examples = self.generate_framework_specific_examples(500)

        # Combine all examples
        all_examples = false_positives + true_positives + framework_examples

        # Shuffle the dataset
        np.random.shuffle(all_examples)

        dataset = {
            "metadata": {
                "dataset_id": "synthetic_vulnhunter_v4_training",
                "generation_date": datetime.now().isoformat(),
                "total_examples": len(all_examples),
                "false_positive_examples": len(false_positives),
                "true_positive_examples": len(true_positives),
                "framework_examples": len(framework_examples),
                "purpose": "Enhanced VulnHunter V4 training with false positive elimination"
            },
            "examples": all_examples,
            "statistics": {
                "false_positive_rate": len(false_positives) / len(all_examples),
                "severity_distribution": self._calculate_severity_distribution(all_examples),
                "framework_distribution": self._calculate_framework_distribution(all_examples),
                "confidence_statistics": self._calculate_confidence_statistics(all_examples)
            }
        }

        # Save dataset
        output_file = self.output_path / "synthetic_training_dataset.json"
        with open(output_file, 'w') as f:
            json.dump(dataset, f, indent=2, default=str)

        print(f"Generated {len(all_examples)} training examples")
        print(f"Dataset saved to: {output_file}")

        return dataset

    def _calculate_severity_distribution(self, examples: List[Dict]) -> Dict:
        """Calculate severity distribution."""
        severities = [ex["claimed_vulnerability"]["severity"] for ex in examples]
        unique, counts = np.unique(severities, return_counts=True)
        return dict(zip(unique, counts.tolist()))

    def _calculate_framework_distribution(self, examples: List[Dict]) -> Dict:
        """Calculate framework distribution."""
        frameworks = [ex["claimed_vulnerability"].get("framework", "Unknown") for ex in examples]
        unique, counts = np.unique(frameworks, return_counts=True)
        return dict(zip(unique, counts.tolist()))

    def _calculate_confidence_statistics(self, examples: List[Dict]) -> Dict:
        """Calculate confidence statistics."""
        confidences = [ex["claimed_vulnerability"]["confidence"] for ex in examples]
        return {
            "mean": np.mean(confidences),
            "std": np.std(confidences),
            "min": np.min(confidences),
            "max": np.max(confidences),
            "median": np.median(confidences)
        }

def main():
    """Main function to generate synthetic training data."""
    output_path = "/Users/ankitthakur/vuln_ml_research/data/training/synthetic"

    generator = SyntheticTrainingDataGenerator(output_path)
    dataset = generator.generate_comprehensive_dataset()

    print("\nDataset Statistics:")
    print(f"Total examples: {dataset['metadata']['total_examples']}")
    print(f"False positive rate: {dataset['statistics']['false_positive_rate']:.2%}")
    print(f"Severity distribution: {dataset['statistics']['severity_distribution']}")

if __name__ == "__main__":
    main()