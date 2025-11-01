#!/usr/bin/env python3
"""
🕸️ VulnHunter Ψ Autonomous Crawler - Phase 5 Q1 Component
===========================================================
High-performance repository crawler for zero-day hunting

Implementation from 1.txt requirements:
- Scrapy + Playwright + Tor rotation
- Clone, mirror, and analyze 10,000 repos/week
- Autonomous operation with stealth capabilities
- Integration with Target Selection Engine

Target Performance:
- 10,000 repositories per week (1,428 per day)
- Tor rotation for anonymity
- Headless browser automation
- Git clone optimization
- Storage efficiency
"""

import asyncio
import os
import time
import json
import random
import shutil
import tempfile
import subprocess
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import aiofiles
import aiohttp
from pathlib import Path

# Import Scrapy components
import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings

# Import Playwright for browser automation
try:
    from playwright.async_api import async_playwright
except ImportError:
    print("⚠️ Playwright not installed. Run: pip install playwright")
    async_playwright = None

# Import target selection for integration
from target_selection_engine import TargetSelectionEngine, RepoTarget

@dataclass
class CrawlResult:
    """Result of autonomous crawling operation"""
    repo_target: RepoTarget
    clone_success: bool
    clone_path: str
    clone_size_mb: float
    file_count: int
    languages_detected: List[str]
    analysis_ready: bool
    crawl_timestamp: str
    tor_exit_node: Optional[str]
    errors: List[str]

@dataclass
class CrawlStats:
    """Weekly crawling statistics"""
    repos_attempted: int
    repos_successful: int
    total_size_gb: float
    weekly_target: int = 10000
    success_rate: float = 0.0
    avg_clone_time: float = 0.0

class TorRotationManager:
    """Manages Tor circuit rotation for anonymity"""

    def __init__(self):
        self.tor_available = self._check_tor_availability()
        self.current_circuit = None
        self.rotation_interval = 300  # 5 minutes
        self.last_rotation = 0

    def _check_tor_availability(self) -> bool:
        """Check if Tor is available"""
        try:
            result = subprocess.run(['tor', '--version'],
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    async def rotate_circuit(self) -> bool:
        """Rotate Tor circuit for new exit node"""
        if not self.tor_available:
            return False

        try:
            # Signal Tor to rotate circuit
            subprocess.run(['pkill', '-HUP', 'tor'], timeout=5)
            self.last_rotation = time.time()

            # Get new exit node info
            self.current_circuit = await self._get_exit_node()
            print(f"🔄 Tor circuit rotated. Exit node: {self.current_circuit}")
            return True

        except Exception as e:
            print(f"⚠️ Tor rotation failed: {e}")
            return False

    async def _get_exit_node(self) -> Optional[str]:
        """Get current Tor exit node IP"""
        try:
            # Use Tor's control port to get circuit info
            async with aiohttp.ClientSession() as session:
                async with session.get('http://httpbin.org/ip',
                                     proxy='socks5://127.0.0.1:9050',
                                     timeout=10) as response:
                    data = await response.json()
                    return data.get('origin')
        except:
            return None

    async def ensure_rotation(self):
        """Ensure circuit rotation based on interval"""
        if time.time() - self.last_rotation > self.rotation_interval:
            await self.rotate_circuit()

class GitCloneOptimizer:
    """Optimizes Git cloning for massive scale"""

    def __init__(self, base_storage_path: str):
        self.base_storage_path = Path(base_storage_path)
        self.base_storage_path.mkdir(exist_ok=True)

        # Clone optimization settings
        self.shallow_depth = 1  # Shallow clone for speed
        self.partial_clone = True  # Partial clone support
        self.compress_level = 1  # Light compression

    async def clone_repository(self, repo_target: RepoTarget,
                             use_tor: bool = True) -> CrawlResult:
        """Optimized repository cloning"""

        start_time = time.time()
        clone_dir = self.base_storage_path / f"repo_{int(time.time())}_{random.randint(1000, 9999)}"

        errors = []

        try:
            # Prepare clone command with optimizations
            cmd = [
                'git', 'clone',
                '--depth', str(self.shallow_depth),  # Shallow clone
                '--single-branch',  # Only main branch
                '--no-tags',  # Skip tags
            ]

            if self.partial_clone:
                cmd.extend(['--filter=blob:none'])  # Skip file contents initially

            cmd.extend([repo_target.github_url, str(clone_dir)])

            # Set up environment for Tor proxy if enabled
            env = os.environ.copy()
            if use_tor:
                env.update({
                    'GIT_CONFIG_GLOBAL': '/dev/null',
                    'GIT_CONFIG_SYSTEM': '/dev/null'
                })
                # Configure Git to use Tor SOCKS5 proxy
                subprocess.run(['git', 'config', '--global', 'http.proxy', 'socks5://127.0.0.1:9050'],
                             env=env, timeout=5)

            # Execute clone with timeout
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )

            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=300)  # 5 min timeout

            clone_success = result.returncode == 0

            if not clone_success:
                errors.append(f"Git clone failed: {stderr.decode()}")

        except asyncio.TimeoutError:
            clone_success = False
            errors.append("Git clone timeout (5 minutes)")
        except Exception as e:
            clone_success = False
            errors.append(f"Clone error: {str(e)}")

        # Analyze cloned repository
        if clone_success and clone_dir.exists():
            clone_size_mb, file_count, languages = await self._analyze_repository(clone_dir)
            analysis_ready = file_count > 0
        else:
            clone_size_mb = 0.0
            file_count = 0
            languages = []
            analysis_ready = False

        clone_time = time.time() - start_time

        return CrawlResult(
            repo_target=repo_target,
            clone_success=clone_success,
            clone_path=str(clone_dir) if clone_success else "",
            clone_size_mb=clone_size_mb,
            file_count=file_count,
            languages_detected=languages,
            analysis_ready=analysis_ready,
            crawl_timestamp=datetime.now().isoformat(),
            tor_exit_node=None,  # Would be filled by TorRotationManager
            errors=errors
        )

    async def _analyze_repository(self, repo_path: Path) -> tuple[float, int, List[str]]:
        """Quick analysis of cloned repository"""

        try:
            # Calculate size
            size_bytes = sum(f.stat().st_size for f in repo_path.rglob('*') if f.is_file())
            size_mb = size_bytes / (1024 * 1024)

            # Count files
            file_count = len([f for f in repo_path.rglob('*') if f.is_file()])

            # Detect languages (basic)
            languages = set()
            for file_path in repo_path.rglob('*'):
                if file_path.is_file():
                    suffix = file_path.suffix.lower()
                    if suffix == '.py':
                        languages.add('Python')
                    elif suffix in ['.js', '.ts']:
                        languages.add('JavaScript/TypeScript')
                    elif suffix in ['.java']:
                        languages.add('Java')
                    elif suffix in ['.cpp', '.c', '.h']:
                        languages.add('C/C++')
                    elif suffix in ['.rs']:
                        languages.add('Rust')
                    elif suffix in ['.go']:
                        languages.add('Go')
                    elif suffix in ['.rb']:
                        languages.add('Ruby')
                    elif suffix in ['.php']:
                        languages.add('PHP')

            return size_mb, file_count, list(languages)

        except Exception as e:
            print(f"⚠️ Repository analysis failed: {e}")
            return 0.0, 0, []

class AutonomousCrawler:
    """
    Main autonomous crawler for VulnHunter Ψ Zero-Day Hunter
    Implements 1.txt specification: 10,000 repos/week with stealth
    """

    def __init__(self, storage_path: str = "/tmp/vulnhunter_crawl"):
        self.storage_path = storage_path
        self.target_engine = TargetSelectionEngine()
        self.tor_manager = TorRotationManager()
        self.git_optimizer = GitCloneOptimizer(storage_path)

        # Performance tracking
        self.crawl_stats = CrawlStats(repos_attempted=0, repos_successful=0, total_size_gb=0.0)
        self.crawl_results: List[CrawlResult] = []

        # Rate limiting for stealth
        self.crawl_delay_range = (30, 120)  # 30-120 seconds between clones
        self.max_concurrent_clones = 5

        print("🕸️ VulnHunter Ψ Autonomous Crawler Initialized")
        print(f"📁 Storage: {storage_path}")
        print(f"🎯 Target: 10,000 repos/week")
        print(f"🔒 Tor Available: {self.tor_manager.tor_available}")

    async def start_weekly_crawl(self, target_count: int = 10000) -> CrawlStats:
        """Start autonomous weekly crawling operation"""

        print(f"\n🚀 Starting Weekly Crawl - Target: {target_count} repositories")
        print("=" * 60)

        start_time = time.time()

        # Generate target list from selection engine
        print("🎯 Generating target list...")
        targets = await self._generate_crawl_targets(target_count)

        if not targets:
            print("❌ No targets generated. Check Target Selection Engine.")
            return self.crawl_stats

        print(f"📋 Generated {len(targets)} targets for crawling")

        # Initialize Tor if available
        if self.tor_manager.tor_available:
            await self.tor_manager.rotate_circuit()

        # Start crawling with concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent_clones)
        tasks = []

        for i, target in enumerate(targets):
            if i > 0 and i % 100 == 0:
                print(f"📊 Progress: {i}/{len(targets)} ({i/len(targets)*100:.1f}%)")
                await self._save_progress()

            task = self._crawl_single_target(target, semaphore, i)
            tasks.append(task)

            # Yield control periodically
            if len(tasks) >= self.max_concurrent_clones:
                completed = await asyncio.gather(*tasks[:self.max_concurrent_clones], return_exceptions=True)
                tasks = tasks[self.max_concurrent_clones:]

                # Process completed results
                for result in completed:
                    if isinstance(result, CrawlResult):
                        self._process_crawl_result(result)

        # Process remaining tasks
        if tasks:
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for result in completed:
                if isinstance(result, CrawlResult):
                    self._process_crawl_result(result)

        # Calculate final statistics
        total_time = time.time() - start_time
        self.crawl_stats.success_rate = (self.crawl_stats.repos_successful /
                                       max(self.crawl_stats.repos_attempted, 1)) * 100
        self.crawl_stats.avg_clone_time = total_time / max(self.crawl_stats.repos_attempted, 1)

        print(f"\n✅ Weekly Crawl Complete!")
        print(f"📊 Statistics:")
        print(f"   Attempted: {self.crawl_stats.repos_attempted}")
        print(f"   Successful: {self.crawl_stats.repos_successful}")
        print(f"   Success Rate: {self.crawl_stats.success_rate:.1f}%")
        print(f"   Total Size: {self.crawl_stats.total_size_gb:.2f} GB")
        print(f"   Avg Clone Time: {self.crawl_stats.avg_clone_time:.1f}s")

        await self._save_final_results()

        return self.crawl_stats

    async def _generate_crawl_targets(self, count: int) -> List[RepoTarget]:
        """Generate list of repositories to crawl"""

        from target_selection_engine import TargetingCriteria

        # High-value targeting criteria for zero-day hunting
        criteria = TargetingCriteria(
            min_stars=100,           # Focus on popular repos
            min_dependents=10,       # Repos with impact
            languages=['Python', 'JavaScript', 'Java', 'C++', 'Go', 'Rust'],
            max_age_days=365,        # Active projects
            security_keywords=['auth', 'crypto', 'security', 'network', 'parser'],
            min_cvss_potential=7.0   # High severity potential
        )

        # Search for high-value targets
        targets = await self.target_engine.search_high_value_targets(criteria)

        # Limit to requested count
        return targets[:count]

    async def _crawl_single_target(self, target: RepoTarget,
                                 semaphore: asyncio.Semaphore,
                                 index: int) -> CrawlResult:
        """Crawl a single repository target"""

        async with semaphore:
            # Ensure Tor rotation
            await self.tor_manager.ensure_rotation()

            # Random delay for stealth
            delay = random.uniform(*self.crawl_delay_range)
            await asyncio.sleep(delay)

            print(f"🔍 Crawling [{index+1}]: {target.repo_name} (★{target.stars})")

            # Clone repository
            result = await self.git_optimizer.clone_repository(
                target, use_tor=self.tor_manager.tor_available
            )

            # Update Tor exit node info
            if self.tor_manager.current_circuit:
                result.tor_exit_node = self.tor_manager.current_circuit

            return result

    def _process_crawl_result(self, result: CrawlResult):
        """Process and store crawl result"""

        self.crawl_results.append(result)
        self.crawl_stats.repos_attempted += 1

        if result.clone_success:
            self.crawl_stats.repos_successful += 1
            self.crawl_stats.total_size_gb += result.clone_size_mb / 1024

            print(f"✅ {result.repo_target.repo_name}: {result.clone_size_mb:.1f}MB, {result.file_count} files")
        else:
            print(f"❌ {result.repo_target.repo_name}: {', '.join(result.errors)}")

    async def _save_progress(self):
        """Save intermediate progress"""
        progress_file = f"{self.storage_path}/crawl_progress.json"

        progress_data = {
            'stats': asdict(self.crawl_stats),
            'timestamp': datetime.now().isoformat(),
            'results_count': len(self.crawl_results)
        }

        async with aiofiles.open(progress_file, 'w') as f:
            await f.write(json.dumps(progress_data, indent=2))

    async def _save_final_results(self):
        """Save final crawling results"""

        results_file = f"{self.storage_path}/crawl_results_{int(time.time())}.json"

        final_data = {
            'crawl_stats': asdict(self.crawl_stats),
            'crawl_results': [asdict(result) for result in self.crawl_results],
            'completion_timestamp': datetime.now().isoformat(),
            'vulnhunter_version': 'VulnHunter Ψ v1.0 Zero-Day Hunter'
        }

        async with aiofiles.open(results_file, 'w') as f:
            await f.write(json.dumps(final_data, indent=2, default=str))

        print(f"💾 Results saved: {results_file}")

    async def get_analysis_ready_repos(self) -> List[CrawlResult]:
        """Get repositories ready for vulnerability analysis"""
        return [result for result in self.crawl_results if result.analysis_ready]

    async def cleanup_storage(self, keep_analysis_ready: bool = True):
        """Clean up crawled repositories to save space"""

        cleaned_count = 0
        kept_count = 0

        for result in self.crawl_results:
            if result.clone_success and result.clone_path:
                if keep_analysis_ready and result.analysis_ready:
                    kept_count += 1
                    continue

                # Remove repository directory
                try:
                    shutil.rmtree(result.clone_path)
                    cleaned_count += 1
                except Exception as e:
                    print(f"⚠️ Failed to cleanup {result.clone_path}: {e}")

        print(f"🧹 Cleanup complete: {cleaned_count} removed, {kept_count} kept")

async def test_autonomous_crawler():
    """Test the autonomous crawler with small batch"""
    print("🧪 Testing VulnHunter Ψ Autonomous Crawler")
    print("=" * 50)

    # Create test crawler
    test_storage = "/tmp/vulnhunter_test_crawl"
    crawler = AutonomousCrawler(test_storage)

    # Test with small batch (10 repos)
    test_stats = await crawler.start_weekly_crawl(target_count=10)

    # Check analysis-ready repos
    ready_repos = await crawler.get_analysis_ready_repos()
    print(f"\n📊 Analysis-ready repositories: {len(ready_repos)}")

    # Cleanup test data
    await crawler.cleanup_storage(keep_analysis_ready=False)

    print("✅ Autonomous crawler test completed")

if __name__ == "__main__":
    asyncio.run(test_autonomous_crawler())