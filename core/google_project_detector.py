#!/usr/bin/env python3
"""
Google OSS Project Detector
Identifies if a project is eligible for Google's Open Source VRP
"""

import os
import json
import subprocess
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class GoogleProjectInfo:
    """Information about a Google OSS project"""
    is_google_oss: bool
    project_name: str
    priority_level: str  # "high", "medium", "low"
    github_org: Optional[str]
    github_repo: Optional[str]
    eligible_for_vrp: bool
    vrp_tier: str  # "tier1" ($31,337), "tier2" ($10k), "tier3" ($1k-$5k)
    notes: List[str]


class GoogleOSSProjectDetector:
    """
    Detect if a project is part of Google's OSS VRP scope
    """

    # High-priority Google OSS projects
    HIGH_PRIORITY_PROJECTS = {
        'bazel': {'tier': 'tier1', 'languages': ['java', 'python', 'c++']},
        'angular': {'tier': 'tier1', 'languages': ['typescript', 'javascript']},
        'golang': {'tier': 'tier1', 'languages': ['go']},
        'protobuf': {'tier': 'tier1', 'languages': ['c++', 'python', 'java', 'go']},
        'protocol-buffers': {'tier': 'tier1', 'languages': ['c++', 'python', 'java', 'go']},
        'fuchsia': {'tier': 'tier1', 'languages': ['c++', 'rust']},
    }

    # Eligible GitHub organizations
    GOOGLE_GITHUB_ORGS = [
        'google',
        'googleapis',
        'googlecloudplatform',
        'googlecodelabs',
        'googlemaps',
        'googlefonts',
        'googlesamples',
        'googlearchive',
        'googleprojectzero',
    ]

    # Medium-priority projects
    MEDIUM_PRIORITY_PROJECTS = {
        'tensorflow': {'tier': 'tier2', 'languages': ['python', 'c++']},
        'kubernetes': {'tier': 'tier2', 'languages': ['go']},
        'chromium': {'tier': 'tier2', 'languages': ['c++', 'javascript']},
        'android': {'tier': 'tier2', 'languages': ['java', 'c++', 'kotlin']},
        'firebase': {'tier': 'tier2', 'languages': ['javascript', 'typescript']},
        'flutter': {'tier': 'tier2', 'languages': ['dart', 'c++']},
        'gvisor': {'tier': 'tier2', 'languages': ['go']},
        'istio': {'tier': 'tier2', 'languages': ['go']},
    }

    # Indicators in project files
    GOOGLE_INDICATORS = [
        'Copyright Google',
        'Copyright The Google',
        'Copyright Alphabet',
        '@google.com',
        'google/go-',
        'golang.org',
        'cloud.google.com',
    ]

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()

    def detect_project(self) -> GoogleProjectInfo:
        """
        Detect if project is eligible for Google OSS VRP

        Returns:
            GoogleProjectInfo with detection results
        """
        logger.info(f"Analyzing project: {self.project_path}")

        # Check git remote
        github_org, github_repo = self._get_github_info()

        # Check project name and priority
        project_name = self._get_project_name()
        priority_level, vrp_tier = self._determine_priority(project_name, github_org)

        # Check for Google indicators in source
        has_google_copyright = self._check_google_copyright()

        # Determine eligibility
        is_google_oss = self._is_google_oss(github_org, has_google_copyright)
        eligible_for_vrp = is_google_oss and priority_level in ['high', 'medium']

        # Gather notes
        notes = []
        if github_org:
            notes.append(f"GitHub organization: {github_org}")
        if has_google_copyright:
            notes.append("Contains Google copyright notices")
        if priority_level == 'high':
            notes.append("⭐ HIGH PRIORITY PROJECT - Top rewards available")
        if eligible_for_vrp:
            notes.append(f"✅ Eligible for Google OSS VRP (up to ${self._get_max_reward(vrp_tier)})")
        else:
            notes.append("❌ Not eligible for Google OSS VRP")

        return GoogleProjectInfo(
            is_google_oss=is_google_oss,
            project_name=project_name,
            priority_level=priority_level,
            github_org=github_org,
            github_repo=github_repo,
            eligible_for_vrp=eligible_for_vrp,
            vrp_tier=vrp_tier,
            notes=notes
        )

    def _get_github_info(self) -> Tuple[Optional[str], Optional[str]]:
        """Extract GitHub org and repo from git remote"""
        try:
            result = subprocess.run(
                ['git', 'remote', 'get-url', 'origin'],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                remote_url = result.stdout.strip()

                # Parse GitHub URL
                # Examples:
                # https://github.com/google/bazel
                # git@github.com:google/bazel.git
                if 'github.com' in remote_url:
                    parts = remote_url.split('github.com')[-1].strip('/:').replace('.git', '').split('/')
                    if len(parts) >= 2:
                        org = parts[0].lower()
                        repo = parts[1].lower()
                        return org, repo

        except Exception as e:
            logger.debug(f"Could not get git remote: {e}")

        return None, None

    def _get_project_name(self) -> str:
        """Determine project name from directory or package files"""
        # Try directory name
        project_name = self.project_path.name.lower()

        # Try package.json
        package_json = self.project_path / 'package.json'
        if package_json.exists():
            try:
                with open(package_json) as f:
                    data = json.load(f)
                    if 'name' in data:
                        project_name = data['name'].lower()
            except:
                pass

        # Try setup.py
        setup_py = self.project_path / 'setup.py'
        if setup_py.exists():
            try:
                with open(setup_py) as f:
                    content = f.read()
                    if 'name=' in content:
                        # Extract name from setup(name='...')
                        import re
                        match = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", content)
                        if match:
                            project_name = match.group(1).lower()
            except:
                pass

        # Try pyproject.toml
        pyproject = self.project_path / 'pyproject.toml'
        if pyproject.exists():
            try:
                with open(pyproject) as f:
                    content = f.read()
                    if 'name =' in content:
                        import re
                        match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
                        if match:
                            project_name = match.group(1).lower()
            except:
                pass

        return project_name

    def _determine_priority(self, project_name: str, github_org: Optional[str]) -> Tuple[str, str]:
        """Determine project priority level and VRP tier"""
        # Check high-priority projects
        for proj_key, info in self.HIGH_PRIORITY_PROJECTS.items():
            if proj_key in project_name or project_name in proj_key:
                return 'high', info['tier']

        # Check medium-priority projects
        for proj_key, info in self.MEDIUM_PRIORITY_PROJECTS.items():
            if proj_key in project_name or project_name in proj_key:
                return 'medium', info['tier']

        # Check if from Google org (lower priority but still eligible)
        if github_org and github_org in self.GOOGLE_GITHUB_ORGS:
            return 'medium', 'tier3'

        return 'low', 'tier3'

    def _check_google_copyright(self) -> bool:
        """Check if project contains Google copyright notices"""
        # Common files to check
        files_to_check = [
            'LICENSE', 'LICENSE.txt', 'LICENSE.md',
            'NOTICE', 'NOTICE.txt',
            'COPYRIGHT', 'COPYRIGHT.txt',
            'README.md', 'README.txt', 'README'
        ]

        for filename in files_to_check:
            filepath = self.project_path / filename
            if filepath.exists():
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(10000)  # First 10KB
                        for indicator in self.GOOGLE_INDICATORS:
                            if indicator in content:
                                return True
                except:
                    continue

        # Check first few source files
        for ext in ['.py', '.js', '.ts', '.go', '.java', '.cpp', '.h']:
            for filepath in list(self.project_path.rglob(f'*{ext}'))[:10]:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(2000)  # First 2KB (header comments)
                        for indicator in self.GOOGLE_INDICATORS:
                            if indicator in content:
                                return True
                except:
                    continue

        return False

    def _is_google_oss(self, github_org: Optional[str], has_google_copyright: bool) -> bool:
        """Determine if project is Google OSS"""
        # Definitive: GitHub org
        if github_org and github_org in self.GOOGLE_GITHUB_ORGS:
            return True

        # Strong indicator: Google copyright
        if has_google_copyright:
            return True

        return False

    def _get_max_reward(self, tier: str) -> str:
        """Get maximum reward for tier"""
        rewards = {
            'tier1': '31,337',
            'tier2': '10,000',
            'tier3': '5,000'
        }
        return rewards.get(tier, '1,000')

    def get_vrp_url(self, project_info: GoogleProjectInfo) -> str:
        """Get URL to submit to Google VRP"""
        if project_info.eligible_for_vrp:
            return "https://bughunters.google.com/report"
        return ""

    def generate_summary(self, project_info: GoogleProjectInfo) -> str:
        """Generate human-readable summary"""
        lines = [
            "=" * 80,
            "GOOGLE OSS VRP PROJECT ANALYSIS",
            "=" * 80,
            f"Project: {project_info.project_name}",
            f"Path: {self.project_path}",
            ""
        ]

        if project_info.github_org:
            lines.append(f"GitHub: {project_info.github_org}/{project_info.github_repo}")

        lines.extend([
            f"Google OSS: {'✅ Yes' if project_info.is_google_oss else '❌ No'}",
            f"VRP Eligible: {'✅ Yes' if project_info.eligible_for_vrp else '❌ No'}",
            f"Priority: {project_info.priority_level.upper()}",
            f"VRP Tier: {project_info.vrp_tier.upper()}",
            ""
        ])

        if project_info.notes:
            lines.append("Notes:")
            for note in project_info.notes:
                lines.append(f"  • {note}")
            lines.append("")

        if project_info.eligible_for_vrp:
            lines.extend([
                "🎯 SUBMISSION INFORMATION:",
                f"  Submit to: {self.get_vrp_url(project_info)}",
                f"  Max Reward: Up to ${self._get_max_reward(project_info.vrp_tier)}",
                "  Requirements:",
                "    - Review program rules before submitting",
                "    - For 3rd party deps: notify upstream first",
                "    - Include clear reproduction steps",
                "    - Provide proof of concept",
                ""
            ])
        else:
            lines.extend([
                "ℹ️  This project is not eligible for Google OSS VRP.",
                "   Consider:",
                "   - General Google VRP (if Google product affected)",
                "   - HackerOne or other bug bounty platforms",
                "   - Responsible disclosure to project maintainers",
                ""
            ])

        lines.append("=" * 80)
        return "\n".join(lines)


def main():
    """Test the detector"""
    import sys

    if len(sys.argv) > 1:
        project_path = sys.argv[1]
    else:
        project_path = '.'

    detector = GoogleOSSProjectDetector(project_path)
    project_info = detector.detect_project()

    print(detector.generate_summary(project_info))

    # Return exit code based on eligibility
    sys.exit(0 if project_info.eligible_for_vrp else 1)


if __name__ == '__main__':
    main()
