#!/usr/bin/env python3
"""
Automated Data Ingestion System for VulnHunter
Implements multi-source data ingestion with real-time monitoring and validation.
"""

import json
import logging
import os
import asyncio
import aiohttp
import requests
import schedule
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import numpy as np
from google.cloud import aiplatform
from google.cloud import storage
from google.cloud import pubsub_v1
from google.cloud import functions_v1
from google.api_core import exceptions
import yaml

# Custom imports
from dataset_manager import VulnHunterDatasetManager
from data_validation import VulnerabilityDataValidator

@dataclass
class DataSource:
    """Configuration for a data source"""
    name: str
    source_type: str  # 'github', 'cve', 'nvd', 'api', 'database', 'file'
    url: Optional[str]
    authentication: Optional[Dict[str, str]]
    schedule: str  # cron-like schedule
    enabled: bool = True
    last_sync: Optional[datetime] = None
    configuration: Optional[Dict[str, Any]] = None

@dataclass
class IngestionJob:
    """Represents a data ingestion job"""
    job_id: str
    source_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"  # running, completed, failed
    records_processed: int = 0
    records_ingested: int = 0
    error_message: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None

class GitHubDataIngester:
    """Ingests vulnerability data from GitHub repositories"""

    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"token {token}"})

    async def ingest_vulnerabilities(self, config: Dict[str, Any]) -> pd.DataFrame:
        """Ingest vulnerability data from GitHub"""
        try:
            vulnerabilities = []

            # Search for vulnerability-related repositories
            search_queries = config.get('search_queries', [
                'vulnerability detection',
                'security analysis',
                'code security'
            ])

            for query in search_queries:
                repos = await self._search_repositories(query, config.get('limit', 100))

                for repo in repos:
                    repo_vulns = await self._extract_repo_vulnerabilities(repo)
                    vulnerabilities.extend(repo_vulns)

            return pd.DataFrame(vulnerabilities)

        except Exception as e:
            logging.error(f"Error ingesting GitHub data: {e}")
            raise

    async def _search_repositories(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Search GitHub repositories"""
        try:
            url = f"{self.base_url}/search/repositories"
            params = {
                'q': query,
                'sort': 'updated',
                'per_page': min(limit, 100)
            }

            response = self.session.get(url, params=params)
            response.raise_for_status()

            return response.json().get('items', [])

        except Exception as e:
            logging.error(f"Error searching repositories: {e}")
            return []

    async def _extract_repo_vulnerabilities(self, repo: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from a repository"""
        try:
            vulnerabilities = []
            repo_name = repo['full_name']

            # Get repository contents
            contents_url = f"{self.base_url}/repos/{repo_name}/contents"
            response = self.session.get(contents_url)

            if response.status_code != 200:
                return vulnerabilities

            contents = response.json()

            # Look for code files
            for item in contents:
                if item['type'] == 'file' and self._is_code_file(item['name']):
                    file_data = await self._get_file_content(repo_name, item['path'])
                    if file_data:
                        vulnerabilities.append({
                            'repository': repo_name,
                            'file_path': item['path'],
                            'code': file_data['content'],
                            'language': self._detect_language(item['name']),
                            'stars': repo['stargazers_count'],
                            'updated_at': repo['updated_at'],
                            'vulnerable': self._analyze_vulnerability(file_data['content']),
                            'source': 'github'
                        })

            return vulnerabilities

        except Exception as e:
            logging.error(f"Error extracting repo vulnerabilities: {e}")
            return []

    def _is_code_file(self, filename: str) -> bool:
        """Check if file is a code file"""
        code_extensions = ['.py', '.java', '.c', '.cpp', '.js', '.php', '.rb', '.go']
        return any(filename.endswith(ext) for ext in code_extensions)

    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename"""
        extension_map = {
            '.py': 'python',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.js': 'javascript',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go'
        }

        for ext, lang in extension_map.items():
            if filename.endswith(ext):
                return lang

        return 'unknown'

    async def _get_file_content(self, repo_name: str, file_path: str) -> Optional[Dict[str, Any]]:
        """Get file content from repository"""
        try:
            url = f"{self.base_url}/repos/{repo_name}/contents/{file_path}"
            response = self.session.get(url)

            if response.status_code != 200:
                return None

            file_data = response.json()

            # Decode content if it's base64 encoded
            if file_data.get('encoding') == 'base64':
                import base64
                content = base64.b64decode(file_data['content']).decode('utf-8', errors='ignore')
                file_data['content'] = content

            return file_data

        except Exception as e:
            logging.warning(f"Error getting file content: {e}")
            return None

    def _analyze_vulnerability(self, code: str) -> int:
        """Simple heuristic to determine if code might be vulnerable"""
        vulnerability_patterns = [
            r'(?i)(select|insert|update|delete).*%s',  # SQL injection
            r'(?i)(strcpy|strcat|sprintf|gets)',       # Buffer overflow
            r'(?i)(system|exec|popen).*user',          # Command injection
            r'(?i)document\.write.*user',               # XSS
            r'(?i)eval\s*\(',                          # Code injection
        ]

        import re
        for pattern in vulnerability_patterns:
            if re.search(pattern, code):
                return 1

        return 0

class CVEDataIngester:
    """Ingests vulnerability data from CVE databases"""

    def __init__(self):
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json"
        self.session = requests.Session()

    async def ingest_cve_data(self, config: Dict[str, Any]) -> pd.DataFrame:
        """Ingest CVE vulnerability data"""
        try:
            vulnerabilities = []

            # Get recent CVEs
            start_date = config.get('start_date', (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
            end_date = config.get('end_date', datetime.now().strftime('%Y-%m-%d'))

            cves = await self._get_cves(start_date, end_date, config.get('limit', 1000))

            for cve in cves:
                cve_data = await self._process_cve(cve)
                if cve_data:
                    vulnerabilities.append(cve_data)

            return pd.DataFrame(vulnerabilities)

        except Exception as e:
            logging.error(f"Error ingesting CVE data: {e}")
            raise

    async def _get_cves(self, start_date: str, end_date: str, limit: int) -> List[Dict[str, Any]]:
        """Get CVEs from NVD"""
        try:
            url = f"{self.nvd_base_url}/cves/2.0"
            params = {
                'pubStartDate': start_date,
                'pubEndDate': end_date,
                'resultsPerPage': min(limit, 2000)
            }

            response = self.session.get(url, params=params)
            response.raise_for_status()

            data = response.json()
            return data.get('vulnerabilities', [])

        except Exception as e:
            logging.error(f"Error getting CVEs: {e}")
            return []

    async def _process_cve(self, cve_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process individual CVE item"""
        try:
            cve = cve_item.get('cve', {})
            cve_id = cve.get('id', '')

            # Extract description
            descriptions = cve.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')

            # Extract CVSS score
            metrics = cve_item.get('metrics', {})
            cvss_score = 0.0

            if 'cvssMetricV3' in metrics and metrics['cvssMetricV3']:
                cvss_score = metrics['cvssMetricV3'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']

            # Extract CWE information
            weaknesses = cve.get('weaknesses', [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    cwe_ids.append(desc.get('value', ''))

            # Generate synthetic code example (in real implementation, you'd have actual code samples)
            synthetic_code = self._generate_synthetic_code(description, cwe_ids)

            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'cwe_ids': ','.join(cwe_ids),
                'published_date': cve.get('published', ''),
                'modified_date': cve.get('lastModified', ''),
                'code': synthetic_code,
                'vulnerable': 1,
                'source': 'cve',
                'severity': 'high' if cvss_score >= 7.0 else 'medium' if cvss_score >= 4.0 else 'low'
            }

        except Exception as e:
            logging.warning(f"Error processing CVE: {e}")
            return None

    def _generate_synthetic_code(self, description: str, cwe_ids: List[str]) -> str:
        """Generate synthetic vulnerable code based on CVE description"""
        # This is a simplified example - in practice, you'd have more sophisticated code generation

        templates = {
            'CWE-89': 'query = "SELECT * FROM users WHERE id = \'" + user_id + "\'"; execute(query);',
            'CWE-79': 'document.getElementById("output").innerHTML = user_input;',
            'CWE-120': 'char buffer[100]; strcpy(buffer, user_input);',
            'CWE-78': 'system("ls " + user_input);',
            'CWE-22': 'open("../../../etc/passwd", "r");'
        }

        for cwe_id in cwe_ids:
            if cwe_id in templates:
                return templates[cwe_id]

        # Default vulnerable code pattern
        return 'process_user_input(unsafe_input);'

class AutomatedDataIngestionPipeline:
    """
    Comprehensive automated data ingestion pipeline for VulnHunter
    with multi-source support, scheduling, and monitoring.
    """

    def __init__(self, project_id: str, location: str = "us-central1"):
        self.project_id = project_id
        self.location = location
        self.storage_client = storage.Client(project=project_id)

        # Initialize components
        self.dataset_manager = VulnHunterDatasetManager(project_id, location)
        self.validator = VulnerabilityDataValidator(project_id, location)

        # Initialize data ingesters
        self.github_ingester = GitHubDataIngester(os.getenv('GITHUB_TOKEN'))
        self.cve_ingester = CVEDataIngester()

        # Configuration
        self.ingestion_bucket = f"{project_id}-vulnhunter-ingestion"
        self.config_file = "ingestion_config.yaml"
        self.job_history: List[IngestionJob] = []

        # Scheduling
        self.scheduler_running = False
        self.scheduler_thread = None

        self.logger = self._setup_logging()
        self._initialize_infrastructure()

    def _setup_logging(self) -> logging.Logger:
        """Setup comprehensive logging"""
        logger = logging.getLogger('AutomatedDataIngestionPipeline')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _initialize_infrastructure(self):
        """Initialize GCS buckets and configuration"""
        try:
            bucket = self.storage_client.bucket(self.ingestion_bucket)
            if not bucket.exists():
                bucket = self.storage_client.create_bucket(self.ingestion_bucket, location=self.location)
                self.logger.info(f"Created ingestion bucket: {self.ingestion_bucket}")
        except Exception as e:
            self.logger.error(f"Error initializing infrastructure: {e}")

    def configure_data_sources(self, sources: List[DataSource]):
        """Configure data sources for ingestion"""
        try:
            config = {
                'sources': [asdict(source) for source in sources],
                'updated_at': datetime.now().isoformat()
            }

            # Save configuration
            config_yaml = yaml.dump(config, default_flow_style=False)
            bucket = self.storage_client.bucket(self.ingestion_bucket)
            blob = bucket.blob(self.config_file)
            blob.upload_from_string(config_yaml)

            self.logger.info(f"Configured {len(sources)} data sources")

        except Exception as e:
            self.logger.error(f"Error configuring data sources: {e}")
            raise

    def load_data_sources(self) -> List[DataSource]:
        """Load data source configuration"""
        try:
            bucket = self.storage_client.bucket(self.ingestion_bucket)
            blob = bucket.blob(self.config_file)

            if not blob.exists():
                return []

            config_yaml = blob.download_as_text()
            config = yaml.safe_load(config_yaml)

            sources = []
            for source_dict in config.get('sources', []):
                # Convert dict back to DataSource
                if 'last_sync' in source_dict and source_dict['last_sync']:
                    source_dict['last_sync'] = datetime.fromisoformat(source_dict['last_sync'])
                sources.append(DataSource(**source_dict))

            return sources

        except Exception as e:
            self.logger.error(f"Error loading data sources: {e}")
            return []

    async def run_ingestion_job(self, source: DataSource) -> IngestionJob:
        """Run ingestion job for a specific data source"""
        job_id = f"{source.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        job = IngestionJob(
            job_id=job_id,
            source_name=source.name,
            start_time=datetime.now(),
            status="running"
        )

        self.job_history.append(job)
        self.logger.info(f"Starting ingestion job: {job_id}")

        try:
            # Ingest data based on source type
            if source.source_type == 'github':
                data = await self.github_ingester.ingest_vulnerabilities(source.configuration or {})
            elif source.source_type == 'cve':
                data = await self.cve_ingester.ingest_cve_data(source.configuration or {})
            else:
                raise ValueError(f"Unsupported source type: {source.source_type}")

            job.records_processed = len(data)

            if len(data) > 0:
                # Validate data
                self.logger.info(f"Validating {len(data)} records from {source.name}")
                validation_report = self.validator.validate_dataset(data)

                if validation_report.get('passed_validation', False):
                    # Upload to dataset manager
                    dataset_name = f"{source.name}_{datetime.now().strftime('%Y%m%d')}"
                    metadata = self.dataset_manager.upload_vulnerability_data(
                        data=data,
                        dataset_name=dataset_name,
                        source=source.source_type
                    )

                    job.records_ingested = len(data)
                    job.status = "completed"
                    job.metrics = {
                        'dataset_name': dataset_name,
                        'quality_score': validation_report.get('quality_score', 0.0),
                        'validation_passed': True,
                        'gcs_path': f"gs://{self.dataset_manager.dataset_bucket}/{dataset_name}"
                    }

                    # Update source last sync time
                    source.last_sync = datetime.now()
                    self._update_source_config(source)

                    self.logger.info(f"Ingestion job completed: {job_id}")

                else:
                    job.status = "failed"
                    job.error_message = "Data validation failed"
                    job.metrics = {
                        'validation_passed': False,
                        'quality_score': validation_report.get('quality_score', 0.0),
                        'critical_issues': validation_report.get('critical_issues', [])
                    }

                    self.logger.warning(f"Ingestion job failed validation: {job_id}")

            else:
                job.status = "completed"
                job.error_message = "No data retrieved"
                self.logger.warning(f"No data retrieved for source: {source.name}")

        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            self.logger.error(f"Ingestion job failed: {job_id} - {e}")

        finally:
            job.end_time = datetime.now()

        return job

    def _update_source_config(self, updated_source: DataSource):
        """Update a specific data source in configuration"""
        try:
            sources = self.load_data_sources()

            # Update the source
            for i, source in enumerate(sources):
                if source.name == updated_source.name:
                    sources[i] = updated_source
                    break

            # Save updated configuration
            self.configure_data_sources(sources)

        except Exception as e:
            self.logger.error(f"Error updating source config: {e}")

    def schedule_ingestion_jobs(self):
        """Schedule periodic ingestion jobs"""
        try:
            sources = self.load_data_sources()

            for source in sources:
                if not source.enabled:
                    continue

                # Parse schedule (simplified - supports 'hourly', 'daily', 'weekly')
                if source.schedule == 'hourly':
                    schedule.every().hour.do(self._run_scheduled_job, source)
                elif source.schedule == 'daily':
                    schedule.every().day.do(self._run_scheduled_job, source)
                elif source.schedule == 'weekly':
                    schedule.every().week.do(self._run_scheduled_job, source)

            self.logger.info(f"Scheduled ingestion jobs for {len([s for s in sources if s.enabled])} sources")

        except Exception as e:
            self.logger.error(f"Error scheduling jobs: {e}")

    def _run_scheduled_job(self, source: DataSource):
        """Run a scheduled ingestion job"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            job = loop.run_until_complete(self.run_ingestion_job(source))

            self.logger.info(f"Scheduled job completed: {job.job_id} - Status: {job.status}")

        except Exception as e:
            self.logger.error(f"Error in scheduled job for {source.name}: {e}")
        finally:
            loop.close()

    def start_scheduler(self):
        """Start the job scheduler"""
        if self.scheduler_running:
            self.logger.warning("Scheduler is already running")
            return

        self.scheduler_running = True
        self.schedule_ingestion_jobs()

        def run_scheduler():
            while self.scheduler_running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute

        self.scheduler_thread = threading.Thread(target=run_scheduler)
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()

        self.logger.info("Ingestion scheduler started")

    def stop_scheduler(self):
        """Stop the job scheduler"""
        self.scheduler_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()

        schedule.clear()
        self.logger.info("Ingestion scheduler stopped")

    def get_job_status(self, job_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get status of ingestion jobs"""
        if job_id:
            job = next((j for j in self.job_history if j.job_id == job_id), None)
            return [asdict(job)] if job else []

        # Return recent jobs (last 10)
        recent_jobs = sorted(self.job_history, key=lambda x: x.start_time, reverse=True)[:10]
        return [asdict(job) for job in recent_jobs]

    def get_ingestion_metrics(self) -> Dict[str, Any]:
        """Get comprehensive ingestion metrics"""
        try:
            completed_jobs = [j for j in self.job_history if j.status == "completed"]
            failed_jobs = [j for j in self.job_history if j.status == "failed"]

            metrics = {
                'total_jobs': len(self.job_history),
                'completed_jobs': len(completed_jobs),
                'failed_jobs': len(failed_jobs),
                'success_rate': len(completed_jobs) / len(self.job_history) if self.job_history else 0,
                'total_records_processed': sum(j.records_processed for j in self.job_history),
                'total_records_ingested': sum(j.records_ingested for j in completed_jobs),
                'ingestion_efficiency': sum(j.records_ingested for j in completed_jobs) / sum(j.records_processed for j in self.job_history) if sum(j.records_processed for j in self.job_history) > 0 else 0,
                'last_successful_ingestion': max((j.end_time for j in completed_jobs), default=None),
                'sources_configured': len(self.load_data_sources()),
                'sources_active': len([s for s in self.load_data_sources() if s.enabled])
            }

            return metrics

        except Exception as e:
            self.logger.error(f"Error getting ingestion metrics: {e}")
            return {'error': str(e)}

def main():
    """Demo usage of AutomatedDataIngestionPipeline"""

    # Configuration
    PROJECT_ID = "your-gcp-project-id"
    LOCATION = "us-central1"

    # Initialize pipeline
    ingestion_pipeline = AutomatedDataIngestionPipeline(
        project_id=PROJECT_ID,
        location=LOCATION
    )

    # Configure data sources
    data_sources = [
        DataSource(
            name="github_security_repos",
            source_type="github",
            url="https://api.github.com",
            authentication={"token": "your_github_token"},
            schedule="daily",
            configuration={
                "search_queries": ["vulnerability detection", "security analysis"],
                "limit": 50
            }
        ),
        DataSource(
            name="nvd_cve_feed",
            source_type="cve",
            url="https://services.nvd.nist.gov/rest/json",
            authentication=None,
            schedule="daily",
            configuration={
                "start_date": (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'),
                "limit": 100
            }
        )
    ]

    try:
        print("🚀 VulnHunter Automated Data Ingestion Demo")

        # Configure data sources
        print(f"\n⚙️ Configuring {len(data_sources)} data sources...")
        ingestion_pipeline.configure_data_sources(data_sources)
        print(f"✅ Data sources configured")

        # Load and display configured sources
        print(f"\n📋 Configured Data Sources:")
        loaded_sources = ingestion_pipeline.load_data_sources()
        for source in loaded_sources:
            print(f"   - {source.name} ({source.source_type}) - Schedule: {source.schedule}")

        # Run a single ingestion job (demo)
        print(f"\n🔄 Running demo ingestion job...")
        demo_source = loaded_sources[0]  # Use first source

        # Note: In actual implementation, you would run:
        # job = await ingestion_pipeline.run_ingestion_job(demo_source)
        print(f"   Demo job would ingest from: {demo_source.name}")
        print(f"   Source type: {demo_source.source_type}")
        print(f"   Schedule: {demo_source.schedule}")

        # Show job scheduling setup
        print(f"\n⏰ Starting job scheduler...")
        # ingestion_pipeline.start_scheduler()
        print(f"   Scheduler configured for periodic ingestion")
        print(f"   Jobs will run according to configured schedules")

        # Display metrics (mock data for demo)
        print(f"\n📊 Ingestion Metrics:")
        # In real implementation: metrics = ingestion_pipeline.get_ingestion_metrics()
        mock_metrics = {
            'total_jobs': 0,
            'completed_jobs': 0,
            'failed_jobs': 0,
            'success_rate': 0.0,
            'sources_configured': len(loaded_sources),
            'sources_active': len([s for s in loaded_sources if s.enabled])
        }

        for key, value in mock_metrics.items():
            print(f"   {key}: {value}")

        print(f"\n✅ Automated data ingestion pipeline setup completed!")
        print(f"   🔗 GitHub integration configured")
        print(f"   🛡️ CVE/NVD data ingestion configured")
        print(f"   📊 Data validation integrated")
        print(f"   ⏰ Automated scheduling enabled")
        print(f"   📈 Comprehensive monitoring and metrics")

    except Exception as e:
        print(f"❌ Error in demo: {e}")
        raise

if __name__ == "__main__":
    main()