#!/usr/bin/env python3
"""
HackerOne-Style Dataset Builder
Creates training data based on real-world HackerOne vulnerability patterns
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Tuple
import random
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HackerOneDatasetBuilder:
    """
    Build training datasets based on HackerOne disclosure patterns
    """

    def __init__(self, output_dir: str = "data/hackerone_synthetic"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Real-world vulnerability types from HackerOne
        self.vulnerability_types = {
            'sql_injection': {
                'severity': ['critical', 'high', 'medium'],
                'cwe': 'CWE-89',
                'fp_rate': 0.15,  # 15% false positive rate
                'patterns': self._sql_injection_patterns()
            },
            'xss': {
                'severity': ['high', 'medium', 'low'],
                'cwe': 'CWE-79',
                'fp_rate': 0.25,
                'patterns': self._xss_patterns()
            },
            'csrf': {
                'severity': ['medium', 'low'],
                'cwe': 'CWE-352',
                'fp_rate': 0.30,
                'patterns': self._csrf_patterns()
            },
            'auth_bypass': {
                'severity': ['critical', 'high'],
                'cwe': 'CWE-287',
                'fp_rate': 0.10,
                'patterns': self._auth_bypass_patterns()
            },
            'idor': {
                'severity': ['high', 'medium'],
                'cwe': 'CWE-639',
                'fp_rate': 0.20,
                'patterns': self._idor_patterns()
            },
            'xxe': {
                'severity': ['high', 'medium'],
                'cwe': 'CWE-611',
                'fp_rate': 0.12,
                'patterns': self._xxe_patterns()
            },
            'rce': {
                'severity': ['critical'],
                'cwe': 'CWE-94',
                'fp_rate': 0.08,
                'patterns': self._rce_patterns()
            },
            'path_traversal': {
                'severity': ['high', 'medium'],
                'cwe': 'CWE-22',
                'fp_rate': 0.18,
                'patterns': self._path_traversal_patterns()
            }
        }

        # False positive indicators from real HackerOne reports
        self.fp_indicators = [
            "Uses parameterized queries",
            "Input validation present",
            "Already mitigated by WAF",
            "Requires authentication",
            "Rate limiting in place",
            "CSRF token validation active",
            "Content Security Policy blocks this",
            "Same-origin policy prevents exploit",
            "Duplicate of existing report",
            "Not applicable to this implementation",
            "Working as designed",
            "Requires admin privileges",
            "Cannot be reproduced",
            "Out of scope per policy"
        ]

        # True positive indicators
        self.tp_indicators = [
            "Confirmed by security team",
            "CVE assigned",
            "Patch deployed",
            "Bounty awarded",
            "Proof of concept works",
            "Successfully exploited in staging",
            "Security fix merged",
            "Reproducible vulnerability",
            "Valid security issue",
            "Critical impact confirmed"
        ]

    def _sql_injection_patterns(self) -> Dict:
        return {
            'vulnerable': [
                "query = 'SELECT * FROM users WHERE id = ' + user_id",
                "cursor.execute('SELECT * FROM data WHERE name = \"%s\"' % name)",
                "db.query(f'SELECT * FROM accounts WHERE user = {username}')",
                "sql = 'DELETE FROM logs WHERE id = ' + str(log_id); execute(sql)"
            ],
            'safe': [
                "cursor.execute('SELECT * FROM users WHERE id = ?', [user_id])",
                "query = db.prepare('SELECT * FROM data WHERE name = ?'); query.bind(name)",
                "User.where(id: params[:id]).first",  # ORM parameterized
                "db.query('SELECT * FROM accounts WHERE user = $1', [username])"
            ],
            'ambiguous': [
                "query = build_query(table, filters)  # Dynamic query builder",
                "db.raw('SELECT * FROM %s WHERE active = true' % table_name)",
                "admin_query = 'SELECT * FROM admin_' + department"
            ]
        }

    def _xss_patterns(self) -> Dict:
        return {
            'vulnerable': [
                "document.write(userInput)",
                "innerHTML = request.params.message",
                "eval(user_provided_code)",
                "<div>" + comment + "</div>"
            ],
            'safe': [
                "textContent = userInput",
                "innerHTML = DOMPurify.sanitize(request.params.message)",
                "createElement('div').textContent = comment",
                "render(<div>{escapeHTML(comment)}</div>)"
            ],
            'ambiguous': [
                "innerHTML = processComment(comment)  # Unknown sanitization",
                "render(marked(userMarkdown))  # Markdown processor",
                "$(element).html(filtered_content)"
            ]
        }

    def _csrf_patterns(self) -> Dict:
        return {
            'vulnerable': [
                "app.post('/transfer', (req, res) => { transfer(req.body.amount) })",
                "def delete_account(request): Account.delete(request.POST['id'])",
                "@app.route('/change_email', methods=['POST']) def change(): ...",
            ],
            'safe': [
                "if not verify_csrf_token(request): return 403",
                "@csrf_protect def transfer_money(request): ...",
                "app.post('/transfer', csrfMiddleware, handler)",
            ],
            'ambiguous': [
                "@login_required def sensitive_action(request): ...",
                "if request.method == 'POST' and validate_request(request): ...",
            ]
        }

    def _auth_bypass_patterns(self) -> Dict:
        return {
            'vulnerable': [
                "if username == 'admin': is_admin = True",
                "token = request.headers.get('Authorization', 'default_token')",
                "if password == user.password: login(user)  # Plain comparison",
                "is_authenticated = (user_id in session or DEBUG_MODE)"
            ],
            'safe': [
                "if bcrypt.verify(password, user.password_hash): login(user)",
                "token = jwt.decode(request.headers['Authorization'], secret_key)",
                "@require_authentication @require_role('admin') def admin_panel(): ...",
                "if not current_user.is_authenticated: abort(401)"
            ],
            'ambiguous': [
                "if check_permissions(user, resource): allow_access()",
                "auth_result = external_auth_service.verify(token)",
            ]
        }

    def _idor_patterns(self) -> Dict:
        return {
            'vulnerable': [
                "file = get_file(request.params.id)  # No ownership check",
                "return User.find(params[:user_id]).private_data",
                "document = Document.objects.get(id=doc_id)",
            ],
            'safe': [
                "if file.owner == current_user: return file",
                "return current_user.documents.find(doc_id)",
                "if not authorize(current_user, 'read', document): abort(403)",
            ],
            'ambiguous': [
                "doc = get_document(doc_id, current_user)  # Unknown authz",
                "if has_access(user, resource_id): return resource",
            ]
        }

    def _xxe_patterns(self) -> Dict:
        return {
            'vulnerable': [
                "xml.etree.ElementTree.parse(user_xml)",
                "doc = parseXML(request.body, resolve_entities=True)",
                "parser = XMLParser(); parser.parse(untrusted_xml)"
            ],
            'safe': [
                "XMLParser(resolve_entities=False).parse(xml)",
                "defusedxml.ElementTree.parse(user_xml)",
                "parser.setFeature('http://xml.org/sax/features/external-general-entities', False)"
            ],
            'ambiguous': [
                "xml_data = parse_config(xml_string)  # Unknown parser",
                "doc = safe_xml_parse(user_input)",
            ]
        }

    def _rce_patterns(self) -> Dict:
        return {
            'vulnerable': [
                "eval(user_code)",
                "exec(request.params.command)",
                "os.system('echo ' + user_input)",
                "subprocess.call(shell_command, shell=True)"
            ],
            'safe': [
                "subprocess.run(['echo', user_input], shell=False)",
                "# Code execution sandboxed in container",
                "if command not in ALLOWED_COMMANDS: reject()",
            ],
            'ambiguous': [
                "run_in_sandbox(user_code)",
                "execute_safe_command(validated_input)",
            ]
        }

    def _path_traversal_patterns(self) -> Dict:
        return {
            'vulnerable': [
                "open(user_filename)",
                "fs.readFile('/uploads/' + filename)",
                "File.read(params[:path])",
            ],
            'safe': [
                "open(os.path.join(UPLOAD_DIR, os.path.basename(filename)))",
                "if '..' in path or path.startswith('/'): reject()",
                "fs.readFile(path.join(__dirname, 'uploads', sanitize(filename)))",
            ],
            'ambiguous': [
                "read_user_file(validate_path(filename))",
                "File.read(safe_join(BASE_DIR, path))",
            ]
        }

    def generate_sample(
        self,
        vuln_type: str,
        is_vulnerable: bool,
        is_false_positive: bool = False
    ) -> Dict:
        """Generate a single vulnerability sample"""

        vuln_info = self.vulnerability_types[vuln_type]
        patterns = vuln_info['patterns']

        if is_vulnerable and not is_false_positive:
            # True positive: vulnerable code
            code = random.choice(patterns['vulnerable'])
            label = 1
            substate = random.choice(['resolved', 'informative'])
            severity = random.choice(vuln_info['severity'][:2])  # Higher severity
            bounty = random.randint(500, 10000)
            indicators = random.sample(self.tp_indicators, k=random.randint(1, 3))

        elif is_vulnerable and is_false_positive:
            # False positive: looks vulnerable but isn't
            code = random.choice(patterns.get('ambiguous', patterns['safe']))
            label = 0
            substate = random.choice(['not-applicable', 'duplicate', 'informative'])
            severity = random.choice(vuln_info['severity'])
            bounty = 0
            indicators = random.sample(self.fp_indicators, k=random.randint(1, 3))

        else:
            # True negative: clearly safe code
            code = random.choice(patterns['safe'])
            label = 0
            substate = random.choice(['resolved', 'not-applicable'])
            severity = random.choice(vuln_info['severity'])
            bounty = 0 if random.random() > 0.3 else random.randint(100, 500)
            indicators = random.sample(self.fp_indicators, k=random.randint(0, 2))

        return {
            'code': code,
            'vulnerability_type': vuln_type,
            'label': label,
            'is_false_positive': is_false_positive,
            'severity': severity,
            'cwe': vuln_info['cwe'],
            'substate': substate,
            'bounty': bounty,
            'indicators': '; '.join(indicators),
            'description': f"{vuln_type} vulnerability pattern"
        }

    def build_dataset(
        self,
        num_samples: int = 5000,
        balance_ratio: float = 0.5
    ) -> pd.DataFrame:
        """
        Build a balanced dataset with true/false positives

        Args:
            num_samples: Total number of samples
            balance_ratio: Ratio of vulnerable to safe samples

        Returns:
            DataFrame with training data
        """
        logger.info(f"Building dataset with {num_samples} samples...")

        samples = []

        num_vulnerable = int(num_samples * balance_ratio)
        num_safe = num_samples - num_vulnerable

        # Generate samples for each vulnerability type
        for vuln_type, vuln_info in self.vulnerability_types.items():
            # Calculate samples for this type
            type_samples = num_samples // len(self.vulnerability_types)
            type_vulnerable = int(type_samples * balance_ratio)

            # Generate vulnerable samples (with some false positives)
            for i in range(type_vulnerable):
                is_fp = random.random() < vuln_info['fp_rate']
                sample = self.generate_sample(vuln_type, is_vulnerable=True, is_false_positive=is_fp)
                samples.append(sample)

            # Generate safe samples
            for i in range(type_samples - type_vulnerable):
                sample = self.generate_sample(vuln_type, is_vulnerable=False)
                samples.append(sample)

        # Create DataFrame
        df = pd.DataFrame(samples)

        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

        logger.info(f"Dataset created:")
        logger.info(f"  Total samples: {len(df)}")
        logger.info(f"  Vulnerable: {(df['label'] == 1).sum()}")
        logger.info(f"  Safe: {(df['label'] == 0).sum()}")
        logger.info(f"  False positives: {df['is_false_positive'].sum()}")
        logger.info(f"  FP rate: {df['is_false_positive'].sum() / len(df):.2%}")

        return df

    def add_contextual_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add contextual features from HackerOne metadata"""

        df['reporter_reputation'] = np.random.randint(100, 10000, size=len(df))
        df['team_response_time_hours'] = np.random.exponential(24, size=len(df))
        df['has_cve'] = (df['label'] == 1) & (np.random.random(len(df)) > 0.7)
        df['activities_count'] = np.random.poisson(8, size=len(df))
        df['triaged'] = np.random.random(len(df)) > 0.2

        # Higher bounties for valid vulnerabilities
        df.loc[df['label'] == 1, 'bounty'] *= 2

        return df

    def save_dataset(self, df: pd.DataFrame, name: str = "hackerone_training"):
        """Save dataset to disk"""

        # Save full dataset
        csv_path = self.output_dir / f"{name}.csv"
        df.to_csv(csv_path, index=False)
        logger.info(f"Saved dataset to: {csv_path}")

        # Save train/val/test splits
        train_df = df.sample(frac=0.8, random_state=42)
        remaining = df.drop(train_df.index)
        val_df = remaining.sample(frac=0.5, random_state=42)
        test_df = remaining.drop(val_df.index)

        train_df.to_csv(self.output_dir / f"{name}_train.csv", index=False)
        val_df.to_csv(self.output_dir / f"{name}_val.csv", index=False)
        test_df.to_csv(self.output_dir / f"{name}_test.csv", index=False)

        logger.info(f"  Train: {len(train_df)} samples")
        logger.info(f"  Val: {len(val_df)} samples")
        logger.info(f"  Test: {len(test_df)} samples")

        return csv_path


if __name__ == "__main__":
    logger.info("HackerOne Dataset Builder\n")

    builder = HackerOneDatasetBuilder()

    # Build comprehensive dataset
    df = builder.build_dataset(num_samples=10000, balance_ratio=0.5)

    # Add contextual features
    df = builder.add_contextual_features(df)

    # Analyze dataset
    logger.info("\n" + "="*60)
    logger.info("DATASET ANALYSIS")
    logger.info("="*60)

    logger.info("\nVulnerability Type Distribution:")
    print(df['vulnerability_type'].value_counts())

    logger.info("\nSeverity Distribution:")
    print(df['severity'].value_counts())

    logger.info("\nSubstate Distribution:")
    print(df['substate'].value_counts())

    logger.info(f"\nAverage Bounty: ${df['bounty'].mean():.2f}")
    logger.info(f"Total Bounties: ${df['bounty'].sum():.2f}")

    # Save dataset
    builder.save_dataset(df, name="hackerone_training_v1")

    logger.info("\n✅ Dataset building complete!")
