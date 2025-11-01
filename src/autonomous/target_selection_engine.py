#!/usr/bin/env python3
"""
🎯 VulnHunter Ψ (Psi) - Target Selection Engine
=============================================
Phase 5 Q1: Zero-Day Hunter Component

Objective: Autonomously discover high-impact zero-day vulnerabilities in the wild
Mission: Rank repos by: stars, dependents, CVSS potential, language

Target: 50+ novel zero-days, 10+ accepted into Google/Microsoft VRP
"""

import os
import json
import requests
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
import numpy as np
from sklearn.preprocessing import MinMaxScaler

# GitHub GraphQL API
GITHUB_API = "https://api.github.com/graphql"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')  # Required for high rate limits

@dataclass
class RepoTarget:
    """Repository target for zero-day hunting"""
    name: str
    owner: str
    url: str
    stars: int
    forks: int
    language: str
    last_commit: str
    dependents_count: int
    vulnerabilities_history: int
    cvss_potential: float
    target_score: float
    security_files: List[str]
    contributors: int
    release_frequency: float
    complexity_score: float

@dataclass
class TargetingCriteria:
    """Criteria for selecting high-value targets"""
    min_stars: int = 1000
    min_dependents: int = 100
    target_languages: List[str] = None
    exclude_archived: bool = True
    exclude_forks: bool = True
    min_cvss_potential: float = 7.0
    max_repos_per_batch: int = 10000

class GitHubGraphQLClient:
    """GitHub GraphQL client for advanced repository analysis"""

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = datetime.now()

    def query(self, query: str, variables: Dict = None) -> Dict:
        """Execute GraphQL query with rate limiting"""

        if self.rate_limit_remaining < 100:
            sleep_time = (self.rate_limit_reset - datetime.now()).total_seconds()
            if sleep_time > 0:
                logging.info(f"Rate limit low, sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)

        response = requests.post(
            GITHUB_API,
            headers=self.headers,
            json={'query': query, 'variables': variables or {}}
        )

        if response.status_code == 200:
            data = response.json()

            # Update rate limit info
            if 'extensions' in data and 'rateLimit' in data['extensions']:
                rate_limit = data['extensions']['rateLimit']
                self.rate_limit_remaining = rate_limit['remaining']
                reset_at = datetime.fromisoformat(rate_limit['resetAt'].replace('Z', '+00:00'))
                self.rate_limit_reset = reset_at

            return data
        else:
            raise Exception(f"GraphQL query failed: {response.status_code} - {response.text}")

    def search_repositories(self, criteria: TargetingCriteria, cursor: str = None) -> Dict:
        """Search for repositories matching targeting criteria"""

        # Build search query
        search_terms = []
        if criteria.min_stars:
            search_terms.append(f"stars:>={criteria.min_stars}")
        if criteria.target_languages:
            for lang in criteria.target_languages:
                search_terms.append(f"language:{lang}")
        if criteria.exclude_archived:
            search_terms.append("archived:false")
        if criteria.exclude_forks:
            search_terms.append("fork:false")

        search_query = " ".join(search_terms)

        query = """
        query SearchRepos($searchQuery: String!, $cursor: String) {
          search(query: $searchQuery, type: REPOSITORY, first: 100, after: $cursor) {
            repositoryCount
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              ... on Repository {
                name
                owner {
                  login
                }
                url
                stargazerCount
                forkCount
                primaryLanguage {
                  name
                }
                pushedAt
                vulnerabilityAlerts {
                  totalCount
                }
                object(expression: "HEAD:") {
                  ... on Tree {
                    entries {
                      name
                      type
                    }
                  }
                }
                releases {
                  totalCount
                }
                collaborators {
                  totalCount
                }
                isArchived
                isFork
                createdAt
                updatedAt
                diskUsage
                description
              }
            }
          }
        }
        """

        variables = {
            'searchQuery': search_query,
            'cursor': cursor
        }

        return self.query(query, variables)

class CVSSPotentialCalculator:
    """Calculate CVSS potential based on repository characteristics"""

    def __init__(self):
        self.vulnerability_patterns = {
            'deserialization': ['pickle', 'marshal', 'yaml.load', 'eval('],
            'injection': ['exec(', 'eval(', 'subprocess', 'system('],
            'path_traversal': ['os.path.join', 'open(', 'file('],
            'crypto_weak': ['md5', 'sha1', 'des', 'rc4'],
            'auth_bypass': ['session', 'token', 'auth', 'login'],
            'buffer_overflow': ['strcpy', 'sprintf', 'gets', 'malloc'],
            'race_condition': ['thread', 'lock', 'mutex', 'atomic'],
            'xxe': ['xml', 'xpath', 'parser'],
            'ssrf': ['requests.get', 'urllib', 'curl', 'fetch'],
            'lfi_rfi': ['include', 'require', 'import']
        }

        self.language_risk_scores = {
            'C': 9.0,           # Memory safety issues
            'C++': 9.0,         # Memory safety + complexity
            'JavaScript': 8.5,  # Dynamic, web-facing
            'PHP': 8.0,         # Web vulnerabilities
            'Python': 7.5,      # Deserialization, injection
            'Java': 7.0,        # Deserialization, XXE
            'Go': 6.5,          # Memory safe but network services
            'Rust': 4.0,        # Memory safe by design
            'TypeScript': 6.0,  # Better than JS but still web
            'Swift': 5.5,       # Memory safe, mobile
            'Kotlin': 6.5,      # Similar to Java
            'Ruby': 7.0,        # Dynamic language risks
            'Perl': 8.0,        # Complex regex, file handling
            'Shell': 8.5,       # Command injection paradise
        }

    def calculate_cvss_potential(self, repo_data: Dict, security_files: List[str]) -> float:
        """Calculate CVSS potential score (0-10)"""

        base_score = 0.0

        # Language risk (40% weight)
        language = repo_data.get('primaryLanguage', {})
        if language:
            lang_name = language.get('name', 'Unknown')
            language_risk = self.language_risk_scores.get(lang_name, 5.0)
            base_score += language_risk * 0.4

        # Project size and complexity (20% weight)
        stars = repo_data.get('stargazerCount', 0)
        size_factor = min(stars / 10000, 1.0)  # Normalize to 0-1
        base_score += size_factor * 2.0 * 0.2

        # Security awareness (10% weight - inverse)
        security_score = len(security_files) * 0.5
        security_penalty = max(0, 1.0 - security_score * 0.1)
        base_score += security_penalty * 2.0 * 0.1

        # Vulnerability history (20% weight)
        vuln_alerts = repo_data.get('vulnerabilityAlerts', {}).get('totalCount', 0)
        vuln_factor = min(vuln_alerts / 10, 1.0)  # More vulns = higher potential
        base_score += vuln_factor * 2.0 * 0.2

        # Activity and maintenance (10% weight - inverse)
        last_push = repo_data.get('pushedAt')
        if last_push:
            last_push_date = datetime.fromisoformat(last_push.replace('Z', '+00:00'))
            days_since_push = (datetime.now().replace(tzinfo=None) - last_push_date.replace(tzinfo=None)).days
            staleness_factor = min(days_since_push / 365, 1.0)  # Stale = higher risk
            base_score += staleness_factor * 2.0 * 0.1

        return min(base_score, 10.0)

class DependentsAnalyzer:
    """Analyze repository dependents for impact assessment"""

    def __init__(self, github_client: GitHubGraphQLClient):
        self.github_client = github_client

    def count_dependents(self, owner: str, repo: str) -> int:
        """Count repository dependents using dependency graph"""

        query = """
        query GetDependents($owner: String!, $name: String!) {
          repository(owner: $owner, name: $name) {
            dependencyGraphManifests {
              totalCount
            }
            repositoryTopics {
              totalCount
            }
          }
        }
        """

        try:
            result = self.github_client.query(query, {'owner': owner, 'name': repo})
            repo_data = result.get('data', {}).get('repository', {})

            # Use manifest count as proxy for dependents
            manifests = repo_data.get('dependencyGraphManifests', {})
            return manifests.get('totalCount', 0)
        except:
            # Fallback to estimating from stars/forks
            return 0

class TargetSelectionEngine:
    """
    Main Target Selection Engine for VulnHunter Ψ Zero-Day Hunter

    Ranks repositories by vulnerability potential and impact
    """

    def __init__(self, github_token: str):
        self.github_client = GitHubGraphQLClient(github_token)
        self.cvss_calculator = CVSSPotentialCalculator()
        self.dependents_analyzer = DependentsAnalyzer(self.github_client)
        self.db_path = "target_selection.db"
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for target tracking"""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS repo_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner TEXT NOT NULL,
            url TEXT NOT NULL,
            stars INTEGER,
            forks INTEGER,
            language TEXT,
            last_commit TEXT,
            dependents_count INTEGER,
            vulnerabilities_history INTEGER,
            cvss_potential REAL,
            target_score REAL,
            security_files TEXT,
            contributors INTEGER,
            release_frequency REAL,
            complexity_score REAL,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            UNIQUE(owner, name)
        )
        """)

        conn.commit()
        conn.close()

    def detect_security_files(self, repo_entries: List[Dict]) -> List[str]:
        """Detect security-related files in repository"""

        security_indicators = [
            'SECURITY.md', 'security.md',
            'SECURITY.txt', 'security.txt',
            '.github/SECURITY.md',
            'VULNERABILITY.md',
            'CHANGELOG.md',
            'HISTORY.md',
            'codeql.yml',
            'security.yml',
            'dependabot.yml',
            'snyk.yml'
        ]

        detected_files = []
        for entry in repo_entries or []:
            file_name = entry.get('name', '')
            if any(indicator.lower() in file_name.lower() for indicator in security_indicators):
                detected_files.append(file_name)

        return detected_files

    def calculate_target_score(self, repo_data: Dict, dependents: int, security_files: List[str]) -> float:
        """Calculate overall target score for zero-day hunting"""

        # CVSS potential (40% weight)
        cvss_score = self.cvss_calculator.calculate_cvss_potential(repo_data, security_files)

        # Impact score based on stars and dependents (30% weight)
        stars = repo_data.get('stargazerCount', 0)
        impact_score = np.log10(max(stars + dependents, 1)) / np.log10(100000)  # Normalize to 0-1

        # Activity score (20% weight)
        last_push = repo_data.get('pushedAt')
        activity_score = 0.5
        if last_push:
            last_push_date = datetime.fromisoformat(last_push.replace('Z', '+00:00'))
            days_since_push = (datetime.now().replace(tzinfo=None) - last_push_date.replace(tzinfo=None)).days
            activity_score = max(0, 1.0 - days_since_push / 365)

        # Novelty score (10% weight) - fewer security files = higher novelty
        novelty_score = max(0, 1.0 - len(security_files) * 0.1)

        # Weighted combination
        target_score = (
            cvss_score * 0.4 +
            impact_score * 10 * 0.3 +  # Scale impact to match CVSS range
            activity_score * 10 * 0.2 +
            novelty_score * 10 * 0.1
        )

        return min(target_score, 10.0)

    def search_high_value_targets(self, criteria: TargetingCriteria) -> List[RepoTarget]:
        """Search for high-value repositories for zero-day hunting"""

        targets = []
        cursor = None
        processed_repos = 0

        logging.info(f"🎯 Starting target selection with criteria: {criteria}")

        while processed_repos < criteria.max_repos_per_batch:
            try:
                # Search repositories
                result = self.github_client.search_repositories(criteria, cursor)

                if 'errors' in result:
                    logging.error(f"GraphQL errors: {result['errors']}")
                    break

                search_data = result.get('data', {}).get('search', {})
                repos = search_data.get('nodes', [])

                if not repos:
                    break

                # Process each repository
                for repo_data in repos:
                    if processed_repos >= criteria.max_repos_per_batch:
                        break

                    try:
                        # Extract basic info
                        name = repo_data.get('name', '')
                        owner = repo_data.get('owner', {}).get('login', '')

                        if not name or not owner:
                            continue

                        # Skip if already processed recently
                        if self._is_recently_analyzed(owner, name):
                            continue

                        # Detect security files
                        entries = []
                        if repo_data.get('object') and repo_data['object'].get('entries'):
                            entries = repo_data['object']['entries']
                        security_files = self.detect_security_files(entries)

                        # Count dependents (expensive operation)
                        dependents = self.dependents_analyzer.count_dependents(owner, name)

                        # Calculate CVSS potential
                        cvss_potential = self.cvss_calculator.calculate_cvss_potential(repo_data, security_files)

                        # Skip if CVSS potential is too low
                        if cvss_potential < criteria.min_cvss_potential:
                            continue

                        # Calculate target score
                        target_score = self.calculate_target_score(repo_data, dependents, security_files)

                        # Create target object
                        target = RepoTarget(
                            name=name,
                            owner=owner,
                            url=repo_data.get('url', ''),
                            stars=repo_data.get('stargazerCount', 0),
                            forks=repo_data.get('forkCount', 0),
                            language=repo_data.get('primaryLanguage', {}).get('name', 'Unknown'),
                            last_commit=repo_data.get('pushedAt', ''),
                            dependents_count=dependents,
                            vulnerabilities_history=repo_data.get('vulnerabilityAlerts', {}).get('totalCount', 0),
                            cvss_potential=cvss_potential,
                            target_score=target_score,
                            security_files=security_files,
                            contributors=repo_data.get('collaborators', {}).get('totalCount', 0),
                            release_frequency=repo_data.get('releases', {}).get('totalCount', 0) / 12,  # Per month
                            complexity_score=repo_data.get('diskUsage', 0) / 1000  # MB to complexity proxy
                        )

                        targets.append(target)
                        self._save_target_to_db(target)

                        processed_repos += 1
                        logging.info(f"📊 Processed {processed_repos}/{criteria.max_repos_per_batch}: {owner}/{name} (score: {target_score:.2f})")

                    except Exception as e:
                        logging.error(f"Error processing repo {repo_data.get('name', 'unknown')}: {e}")
                        continue

                # Check for next page
                page_info = search_data.get('pageInfo', {})
                if not page_info.get('hasNextPage'):
                    break
                cursor = page_info.get('endCursor')

            except Exception as e:
                logging.error(f"Error in search iteration: {e}")
                break

        # Sort by target score (highest first)
        targets.sort(key=lambda x: x.target_score, reverse=True)

        logging.info(f"🎯 Target selection complete: {len(targets)} high-value targets identified")
        return targets

    def _is_recently_analyzed(self, owner: str, name: str, days: int = 7) -> bool:
        """Check if repository was analyzed recently"""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff_date = datetime.now() - timedelta(days=days)
        cursor.execute("""
        SELECT 1 FROM repo_targets
        WHERE owner = ? AND name = ? AND analyzed_at > ?
        """, (owner, name, cutoff_date.isoformat()))

        result = cursor.fetchone()
        conn.close()

        return result is not None

    def _save_target_to_db(self, target: RepoTarget):
        """Save target to database"""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT OR REPLACE INTO repo_targets (
            name, owner, url, stars, forks, language, last_commit,
            dependents_count, vulnerabilities_history, cvss_potential,
            target_score, security_files, contributors, release_frequency,
            complexity_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            target.name, target.owner, target.url, target.stars, target.forks,
            target.language, target.last_commit, target.dependents_count,
            target.vulnerabilities_history, target.cvss_potential, target.target_score,
            json.dumps(target.security_files), target.contributors,
            target.release_frequency, target.complexity_score
        ))

        conn.commit()
        conn.close()

    def get_top_targets(self, limit: int = 50) -> List[RepoTarget]:
        """Get top targets from database"""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        SELECT * FROM repo_targets
        WHERE status = 'pending'
        ORDER BY target_score DESC
        LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        conn.close()

        targets = []
        for row in rows:
            target = RepoTarget(
                name=row[1], owner=row[2], url=row[3], stars=row[4], forks=row[5],
                language=row[6], last_commit=row[7], dependents_count=row[8],
                vulnerabilities_history=row[9], cvss_potential=row[10],
                target_score=row[11], security_files=json.loads(row[12] or '[]'),
                contributors=row[13], release_frequency=row[14], complexity_score=row[15]
            )
            targets.append(target)

        return targets

    def export_targets(self, targets: List[RepoTarget], filename: str = None) -> str:
        """Export targets to JSON file"""

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"zero_day_targets_{timestamp}.json"

        export_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_targets': len(targets),
                'generator': 'VulnHunter Ψ Target Selection Engine v1.0'
            },
            'targets': [asdict(target) for target in targets]
        }

        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)

        return filename

def test_target_selection():
    """Test the target selection engine"""

    if not GITHUB_TOKEN:
        print("❌ GITHUB_TOKEN environment variable required")
        return

    print("🎯 Testing VulnHunter Ψ Target Selection Engine")
    print("=" * 50)

    # Initialize engine
    engine = TargetSelectionEngine(GITHUB_TOKEN)

    # Define criteria for high-impact targets
    criteria = TargetingCriteria(
        min_stars=5000,
        min_dependents=50,
        target_languages=['JavaScript', 'Python', 'Java', 'C++', 'Go'],
        min_cvss_potential=7.0,
        max_repos_per_batch=100
    )

    # Search for targets
    targets = engine.search_high_value_targets(criteria)

    if targets:
        print(f"\n🎯 Found {len(targets)} high-value zero-day targets:")
        for i, target in enumerate(targets[:10], 1):
            print(f"  {i:2d}. {target.owner}/{target.name}")
            print(f"      Score: {target.target_score:.2f} | CVSS: {target.cvss_potential:.1f} | Stars: {target.stars:,}")
            print(f"      Language: {target.language} | Dependents: {target.dependents_count}")

        # Export results
        export_file = engine.export_targets(targets)
        print(f"\n📁 Targets exported to: {export_file}")
    else:
        print("❌ No targets found matching criteria")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_target_selection()