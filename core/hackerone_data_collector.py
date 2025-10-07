#!/usr/bin/env python3
"""
HackerOne Hacktivity Data Collector
Collects disclosed vulnerability reports for training ML models
"""

import requests
import json
import time
import logging
from typing import List, Dict, Optional
from datetime import datetime
import pandas as pd
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HackerOneDataCollector:
    """
    Collect disclosed vulnerability reports from HackerOne
    """

    def __init__(self, output_dir: str = "data/hackerone"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # HackerOne GraphQL API endpoint
        self.api_url = "https://hackerone.com/graphql"

        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "VulnResearch/1.0 (Security Research)"
        }

        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def fetch_hacktivity_page(self, page: int = 0, page_size: int = 25) -> Optional[Dict]:
        """
        Fetch a page of hacktivity reports

        Args:
            page: Page number (0-indexed)
            page_size: Number of reports per page

        Returns:
            Dictionary with reports data
        """
        # GraphQL query for hacktivity
        query = """
        query Hacktivity($queryString: String, $first: Int, $after: String) {
          hacktivity_items(
            first: $first
            after: $after
            query_string: $queryString
            order_by: {field: latest_disclosable_activity_at, direction: DESC}
          ) {
            edges {
              node {
                id
                databaseId: _id
                type
                disclosed: is_disclosed
                title
                substate
                severity_rating
                submitted_at
                disclosed_at
                latest_disclosable_activity_at
                reporter {
                  username
                  reputation
                }
                team {
                  handle
                  name
                }
                cve_ids
                bounty_amount
                bonus_amount
                currency
                vulnerability_types
                weakness {
                  name
                  description
                }
                activities_count
                source_data
              }
            }
            pageInfo {
              hasNextPage
              endCursor
            }
            total_count
          }
        }
        """

        variables = {
            "queryString": "disclosed:true",
            "first": page_size,
            "after": None if page == 0 else str(page * page_size)
        }

        try:
            response = self.session.post(
                self.api_url,
                json={"query": query, "variables": variables},
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"API returned status {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error fetching data: {e}")
            return None

    def fetch_report_details(self, report_id: int) -> Optional[Dict]:
        """
        Fetch detailed information for a specific report

        Args:
            report_id: HackerOne report ID

        Returns:
            Detailed report data
        """
        query = """
        query Report($id: ID!) {
          report(id: $id) {
            id
            title
            vulnerability_information
            vulnerability_information_html
            weakness {
              name
              external_id
            }
            severity {
              rating
              score
              attack_vector
              attack_complexity
            }
            structured_scope {
              asset_identifier
              asset_type
            }
            activities {
              edges {
                node {
                  type
                  message
                  created_at
                }
              }
            }
            attachments {
              file_name
              file_size
            }
          }
        }
        """

        try:
            response = self.session.post(
                self.api_url,
                json={"query": query, "variables": {"id": report_id}},
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            return None

        except Exception as e:
            logger.error(f"Error fetching report {report_id}: {e}")
            return None

    def extract_vulnerability_patterns(self, report: Dict) -> Dict:
        """
        Extract key patterns from a vulnerability report

        Args:
            report: Report data

        Returns:
            Extracted patterns and features
        """
        node = report.get('node', {})

        # Extract key information
        patterns = {
            'report_id': node.get('databaseId'),
            'title': node.get('title', ''),
            'type': node.get('type', ''),
            'substate': node.get('substate', ''),
            'severity': node.get('severity_rating', ''),
            'disclosed': node.get('disclosed', False),
            'bounty': node.get('bounty_amount', 0),
            'cve_ids': node.get('cve_ids', []),
            'weakness': node.get('weakness', {}).get('name', ''),
            'vuln_types': node.get('vulnerability_types', []),
            'submitted_at': node.get('submitted_at', ''),
            'disclosed_at': node.get('disclosed_at', ''),
            'team': node.get('team', {}).get('handle', ''),
            'reporter_reputation': node.get('reporter', {}).get('reputation', 0)
        }

        # Classify as true positive or false positive based on substate
        # "resolved", "informative" = TP
        # "not-applicable", "duplicate" = FP or low value
        patterns['is_valid_vulnerability'] = node.get('substate') in [
            'resolved', 'informative'
        ]

        patterns['is_false_positive'] = node.get('substate') in [
            'not-applicable', 'duplicate', 'spam'
        ]

        return patterns

    def collect_dataset(
        self,
        num_pages: int = 100,
        delay_seconds: float = 1.0
    ) -> pd.DataFrame:
        """
        Collect a dataset of vulnerability reports

        Args:
            num_pages: Number of pages to collect
            delay_seconds: Delay between requests

        Returns:
            DataFrame with collected reports
        """
        logger.info(f"Starting data collection for {num_pages} pages...")

        all_reports = []

        for page in range(num_pages):
            logger.info(f"Fetching page {page + 1}/{num_pages}...")

            data = self.fetch_hacktivity_page(page=page)

            if not data or 'data' not in data:
                logger.warning(f"No data on page {page}")
                continue

            hacktivity = data.get('data', {}).get('hacktivity_items', {})
            edges = hacktivity.get('edges', [])

            if not edges:
                logger.info("No more reports found")
                break

            # Extract patterns from each report
            for edge in edges:
                try:
                    patterns = self.extract_vulnerability_patterns(edge)
                    all_reports.append(patterns)
                except Exception as e:
                    logger.error(f"Error processing report: {e}")
                    continue

            logger.info(f"Collected {len(edges)} reports from page {page + 1}")

            # Check if there are more pages
            has_next = hacktivity.get('pageInfo', {}).get('hasNextPage', False)
            if not has_next:
                logger.info("Reached end of available data")
                break

            # Rate limiting
            time.sleep(delay_seconds)

        # Create DataFrame
        df = pd.DataFrame(all_reports)

        logger.info(f"\nCollection complete!")
        logger.info(f"Total reports: {len(df)}")
        logger.info(f"Valid vulnerabilities: {df['is_valid_vulnerability'].sum()}")
        logger.info(f"False positives: {df['is_false_positive'].sum()}")

        # Save to file
        output_file = self.output_dir / f"hackerone_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(output_file, index=False)
        logger.info(f"Saved to: {output_file}")

        return df

    def collect_by_weakness_type(self, weakness: str, num_reports: int = 100) -> pd.DataFrame:
        """
        Collect reports for a specific weakness type

        Args:
            weakness: Weakness type (e.g., "SQL Injection", "XSS")
            num_reports: Number of reports to collect

        Returns:
            DataFrame with filtered reports
        """
        logger.info(f"Collecting {num_reports} reports for weakness: {weakness}")

        # This would require filtering in the query
        # For now, collect general data and filter
        df = self.collect_dataset(num_pages=num_reports // 25)

        if not df.empty:
            filtered = df[df['weakness'].str.contains(weakness, case=False, na=False)]
            logger.info(f"Found {len(filtered)} reports for {weakness}")
            return filtered

        return pd.DataFrame()

    def analyze_false_positive_patterns(self, df: pd.DataFrame) -> Dict:
        """
        Analyze patterns in false positive reports

        Args:
            df: DataFrame with reports

        Returns:
            Dictionary with FP patterns
        """
        fp_reports = df[df['is_false_positive'] == True]
        valid_reports = df[df['is_valid_vulnerability'] == True]

        analysis = {
            'total_reports': len(df),
            'false_positives': len(fp_reports),
            'valid_vulnerabilities': len(valid_reports),
            'fp_rate': len(fp_reports) / len(df) if len(df) > 0 else 0,

            # FP patterns
            'fp_by_severity': fp_reports['severity'].value_counts().to_dict(),
            'fp_by_weakness': fp_reports['weakness'].value_counts().head(10).to_dict(),
            'fp_by_team': fp_reports['team'].value_counts().head(10).to_dict(),

            # Valid patterns
            'valid_by_severity': valid_reports['severity'].value_counts().to_dict(),
            'valid_by_weakness': valid_reports['weakness'].value_counts().head(10).to_dict(),

            # Bounty analysis
            'avg_bounty_valid': valid_reports['bounty'].mean(),
            'avg_bounty_fp': fp_reports['bounty'].mean(),
        }

        return analysis


# Fallback: Public HackerOne data extractor using RSS/public endpoints
class HackerOnePublicCollector:
    """
    Collector for publicly available HackerOne data
    Uses public disclosures and RSS feeds
    """

    def __init__(self, output_dir: str = "data/hackerone_public"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()

    def collect_from_hackerone_directory(self) -> List[Dict]:
        """
        Collect from publicly disclosed reports directory
        """
        reports = []

        # Known public bug bounty programs with high disclosure rates
        programs = [
            'gitlab', 'hackerone', 'github', 'shopify', 'twitter',
            'uber', 'slack', 'reddit', 'paypal', 'coinbase'
        ]

        for program in programs:
            try:
                url = f"https://hackerone.com/{program}/hacktivity"
                logger.info(f"Checking {program}...")

                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    # This would require HTML parsing
                    # For now, log that we found the program
                    logger.info(f"✓ Found {program}")

            except Exception as e:
                logger.error(f"Error fetching {program}: {e}")

        return reports


if __name__ == "__main__":
    logger.info("HackerOne Data Collector - Starting\n")

    # Try GraphQL API approach
    collector = HackerOneDataCollector()

    # Collect dataset
    logger.info("Attempting to collect disclosed reports...")
    df = collector.collect_dataset(num_pages=10, delay_seconds=2.0)

    if not df.empty:
        # Analyze FP patterns
        logger.info("\nAnalyzing false positive patterns...")
        analysis = collector.analyze_false_positive_patterns(df)

        logger.info("\n" + "="*60)
        logger.info("FALSE POSITIVE ANALYSIS")
        logger.info("="*60)
        logger.info(f"Total Reports: {analysis['total_reports']}")
        logger.info(f"False Positives: {analysis['false_positives']}")
        logger.info(f"Valid Vulnerabilities: {analysis['valid_vulnerabilities']}")
        logger.info(f"FP Rate: {analysis['fp_rate']:.2%}")

        logger.info("\nTop FP Weaknesses:")
        for weakness, count in list(analysis['fp_by_weakness'].items())[:5]:
            logger.info(f"  {weakness}: {count}")

        # Save analysis
        analysis_file = Path("data/hackerone") / "fp_analysis.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        logger.info(f"\nAnalysis saved to: {analysis_file}")

    else:
        logger.warning("No data collected - API may require authentication")
        logger.info("\nTrying public collector fallback...")

        public_collector = HackerOnePublicCollector()
        public_reports = public_collector.collect_from_hackerone_directory()

        if public_reports:
            logger.info(f"Collected {len(public_reports)} public reports")
        else:
            logger.info("Public collection requires manual setup")

    logger.info("\n✅ Collection complete!")
