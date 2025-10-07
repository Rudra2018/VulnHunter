#!/usr/bin/env python3
"""
VulnHunter - Unified Vulnerability Detection System

Combines all security ML models into a single, powerful vulnerability hunter.
Automatically detects and analyzes:
  - iOS/macOS applications (.ipa, .dmg, .ipsw)
  - Binary executables (.exe, .elf, .so, .dylib)
  - HTTP/Web requests and APIs
  - Source code (Python, C, JavaScript, etc.)

Usage:
    from vulnhunter import VulnHunter

    hunter = VulnHunter()
    result = hunter.hunt('/path/to/target')
    print(result)
"""

import os
import sys
import pickle
import logging
from pathlib import Path
from typing import Dict, Any, Union, List
from dataclasses import dataclass
from enum import Enum

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = 0
    MINIMAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class TargetType(Enum):
    """Target analysis types"""
    IOS_MACOS_APP = "ios_macos_app"
    BINARY_EXECUTABLE = "binary_executable"
    HTTP_REQUEST = "http_request"
    SOURCE_CODE = "source_code"
    UNKNOWN = "unknown"


@dataclass
class VulnHunterResult:
    """Unified vulnerability detection result"""
    target_path: str
    target_type: TargetType
    threat_level: ThreatLevel
    threat_score: float  # 0-10 scale
    is_vulnerable: bool
    vulnerability_type: str
    confidence: float  # 0-1 scale
    analyzer_used: str
    details: Dict[str, Any]
    recommendations: List[str]

    def __str__(self):
        status = "🚨 VULNERABLE" if self.is_vulnerable else "✅ SAFE"
        threat_emoji = {
            ThreatLevel.SAFE: "✅",
            ThreatLevel.MINIMAL: "🟢",
            ThreatLevel.LOW: "🟡",
            ThreatLevel.MEDIUM: "🟠",
            ThreatLevel.HIGH: "🔴",
            ThreatLevel.CRITICAL: "🔥"
        }

        return f"""
╔════════════════════════════════════════════════════════════════
║ VULNHUNTER ANALYSIS REPORT
╠════════════════════════════════════════════════════════════════
║ Target: {self.target_path}
║ Type: {self.target_type.value}
║
║ {status}
║ Threat Level: {threat_emoji[self.threat_level]} {self.threat_level.name}
║ Threat Score: {self.threat_score:.2f}/10
║ Vulnerability: {self.vulnerability_type}
║ Confidence: {self.confidence*100:.1f}%
║ Analyzer: {self.analyzer_used}
╠════════════════════════════════════════════════════════════════
║ RECOMMENDATIONS:
║ {chr(10).join('║   ' + str(i+1) + '. ' + rec for i, rec in enumerate(self.recommendations))}
╚════════════════════════════════════════════════════════════════
"""


class VulnHunter:
    """
    VulnHunter - The Ultimate Unified Vulnerability Detection System

    Combines 4 specialized ML analyzers:
      1. iOS/macOS Analyzer (83% accuracy)
      2. Binary Analyzer (5-model ensemble)
      3. HTTP Security Analyzer (100% accuracy)
      4. Code/SAST Analyzer (100% accuracy)

    Total: 13 ML models, 18K+ training samples, 71.7MB
    """

    def __init__(self, models_dir: str = None):
        """Initialize VulnHunter with all security models"""
        self.models_dir = models_dir or os.path.expanduser("~/Documents/models")
        self.analyzers = {}
        self.ready = False

        logger.info("🦾 Initializing VulnHunter...")
        logger.info(f"📁 Models directory: {self.models_dir}")

        # Add vuln_ml_research to path
        sys.path.insert(0, os.path.expanduser("~/vuln_ml_research"))

        # Load all analyzers
        self._load_analyzers()

        if len(self.analyzers) > 0:
            self.ready = True
            logger.info(f"✅ VulnHunter ready with {len(self.analyzers)}/4 analyzers")
        else:
            logger.error("❌ VulnHunter initialization failed - no analyzers loaded")

    def _load_analyzers(self):
        """Load all security analyzers"""

        # 1. iOS/macOS Analyzer
        try:
            sys.path.insert(0, os.path.expanduser("~/Documents"))
            from ios_macos_security_analyzer import VulnerabilityDetector

            ios_model = os.path.join(self.models_dir, "ios_vuln_detector.pkl")
            if os.path.exists(ios_model):
                detector = VulnerabilityDetector()
                detector.load_model(ios_model)
                self.analyzers['ios_macos'] = detector
                logger.info("✅ Loaded iOS/macOS analyzer")
            else:
                logger.warning("⚠️  iOS/macOS model not found")
        except Exception as e:
            logger.error(f"❌ Failed to load iOS/macOS analyzer: {e}")

        # 2. Binary Analyzer
        try:
            from core.binary_vulnerability_trainer import BinaryVulnerabilityTrainer
            binary_model = os.path.join(self.models_dir, "binary_vuln_models.pkl")

            if os.path.exists(binary_model):
                trainer = BinaryVulnerabilityTrainer()
                trainer.load_models(binary_model)
                self.analyzers['binary'] = trainer
                logger.info("✅ Loaded Binary analyzer (5 models)")
            else:
                logger.warning("⚠️  Binary model not found")
        except Exception as e:
            logger.error(f"❌ Failed to load Binary analyzer: {e}")

        # 3. HTTP Security Analyzer
        try:
            from core.http_security_trainer import HTTPSecurityTrainer

            # Look for HTTP model with or without timestamp
            http_model = os.path.join(self.models_dir, "http_security_models.pkl")
            if not os.path.exists(http_model):
                import glob
                http_models = glob.glob(os.path.join(self.models_dir, "http_security_models*.pkl"))
                http_model = http_models[0] if http_models else None

            if http_model and os.path.exists(http_model):
                trainer = HTTPSecurityTrainer()
                trainer.load_models(http_model)
                self.analyzers['http'] = trainer
                logger.info("✅ Loaded HTTP Security analyzer (4 models)")
            else:
                logger.warning("⚠️  HTTP model not found")
        except Exception as e:
            logger.error(f"❌ Failed to load HTTP analyzer: {e}")

        # 4. Code/SAST Analyzer
        try:
            from core.http_security_trainer import VulnGuardIntegratedTrainer

            # Look for Code model with or without timestamp
            code_model = os.path.join(self.models_dir, "code_vuln_models.pkl")
            if not os.path.exists(code_model):
                import glob
                code_models = glob.glob(os.path.join(self.models_dir, "code_vuln_models*.pkl"))
                code_model = code_models[0] if code_models else None

            if code_model and os.path.exists(code_model):
                trainer = VulnGuardIntegratedTrainer()
                trainer.load_models(code_model)
                self.analyzers['code'] = trainer
                logger.info("✅ Loaded Code/SAST analyzer (3 models)")
            else:
                logger.warning("⚠️  Code model not found")
        except Exception as e:
            logger.error(f"❌ Failed to load Code analyzer: {e}")

    def detect_target_type(self, target: Union[str, Dict]) -> TargetType:
        """Detect the type of target for analysis"""

        # Dict input = HTTP request
        if isinstance(target, dict):
            if 'url' in target or 'method' in target or 'headers' in target:
                return TargetType.HTTP_REQUEST
            return TargetType.UNKNOWN

        # String input = file path or code
        if isinstance(target, str):
            # Check if it's a file path
            if os.path.exists(target):
                ext = Path(target).suffix.lower()

                # iOS/macOS apps
                if ext in ['.ipa', '.dmg'] or target.endswith('.ipsw'):
                    return TargetType.IOS_MACOS_APP

                # Binary executables
                if ext in ['.exe', '.dll', '.so', '.dylib', '.bin'] or os.access(target, os.X_OK):
                    return TargetType.BINARY_EXECUTABLE

                # Source code
                if ext in ['.py', '.js', '.c', '.cpp', '.h', '.java', '.go', '.rb', '.php']:
                    return TargetType.SOURCE_CODE
            else:
                # Inline code snippet
                if len(target) > 10 and any(keyword in target for keyword in ['def ', 'function ', 'void ', 'class ', 'import ']):
                    return TargetType.SOURCE_CODE

        return TargetType.UNKNOWN

    def hunt(self, target: Union[str, Dict]) -> VulnHunterResult:
        """
        Hunt for vulnerabilities in any target

        Args:
            target: File path, code snippet, or HTTP request dict

        Returns:
            VulnHunterResult with complete analysis
        """
        if not self.ready:
            raise RuntimeError("VulnHunter not initialized - no analyzers loaded")

        # Detect target type
        target_type = self.detect_target_type(target)
        target_path = target if isinstance(target, str) else str(target.get('url', 'http_request'))

        logger.info(f"🎯 Hunting vulnerabilities in: {target_path}")
        logger.info(f"🔍 Detected type: {target_type.value}")

        # Route to appropriate analyzer
        if target_type == TargetType.IOS_MACOS_APP and 'ios_macos' in self.analyzers:
            return self._analyze_ios_macos(target, target_path)

        elif target_type == TargetType.BINARY_EXECUTABLE and 'binary' in self.analyzers:
            return self._analyze_binary(target, target_path)

        elif target_type == TargetType.HTTP_REQUEST and 'http' in self.analyzers:
            return self._analyze_http(target, target_path)

        elif target_type == TargetType.SOURCE_CODE and 'code' in self.analyzers:
            return self._analyze_code(target, target_path)

        else:
            # No suitable analyzer
            return VulnHunterResult(
                target_path=target_path,
                target_type=target_type,
                threat_level=ThreatLevel.MINIMAL,
                threat_score=0.0,
                is_vulnerable=False,
                vulnerability_type="unknown",
                confidence=0.0,
                analyzer_used="none",
                details={'error': 'No suitable analyzer available'},
                recommendations=["Unsupported target type or analyzer not loaded"]
            )

    def _analyze_ios_macos(self, target: str, target_path: str) -> VulnHunterResult:
        """Analyze iOS/macOS application"""
        from ios_macos_security_analyzer import FileParser

        detector = self.analyzers['ios_macos']
        parser = FileParser()

        # Parse file into BinaryInfo object
        if target_path.endswith('.ipsw'):
            binary_info = parser.parse_ipsw(target_path)
        elif target_path.endswith('.ipa'):
            binary_info = parser.parse_ipa(target_path)
        elif target_path.endswith('.dmg'):
            binary_info = parser.parse_dmg(target_path)
        else:
            binary_info = parser.parse_macho(target_path)

        result = detector.predict(binary_info)

        is_vuln = result.get('prediction') == 'vulnerable'
        confidence = result.get('confidence', 0.5)

        # Map to threat level
        threat_score = confidence * 10 if is_vuln else (1 - confidence) * 2
        threat_level = self._score_to_level(threat_score)

        recommendations = []
        if is_vuln:
            recommendations = [
                "🚨 IMMEDIATE: Do not deploy this app to production",
                "Review the binary for security vulnerabilities",
                "Run additional security scans (static analysis, dynamic testing)",
                "Consult with security experts before release"
            ]
        else:
            recommendations = [
                "✅ App appears safe, but manual review recommended",
                "Continue regular security updates",
                "Monitor for new vulnerabilities"
            ]

        return VulnHunterResult(
            target_path=target_path,
            target_type=TargetType.IOS_MACOS_APP,
            threat_level=threat_level,
            threat_score=threat_score,
            is_vulnerable=is_vuln,
            vulnerability_type=result.get('vulnerability_type', 'unknown'),
            confidence=confidence,
            analyzer_used="iOS/macOS Analyzer (Random Forest, 83% acc)",
            details=result,
            recommendations=recommendations
        )

    def _analyze_binary(self, target: str, target_path: str) -> VulnHunterResult:
        """Analyze binary executable"""
        trainer = self.analyzers['binary']
        result = trainer.predict_binary_vulnerability(target)

        is_vuln = result.get('is_vulnerable', False)
        confidence = result.get('confidence', 0.5)
        vuln_type = result.get('vulnerability_type', 'unknown')

        threat_score = result.get('risk_score', confidence * 10)
        threat_level = self._score_to_level(threat_score)

        recommendations = []
        if is_vuln:
            recommendations = [
                f"🚨 CRITICAL: {vuln_type} detected in binary",
                "Do not execute this binary in production",
                "Analyze with reverse engineering tools (IDA, Ghidra, Binary Ninja)",
                "Check for malware with antivirus/sandbox",
                "Verify binary signature and source"
            ]
        else:
            recommendations = [
                "✅ Binary appears safe",
                "Verify digital signature if available",
                "Test in isolated environment before deployment"
            ]

        return VulnHunterResult(
            target_path=target_path,
            target_type=TargetType.BINARY_EXECUTABLE,
            threat_level=threat_level,
            threat_score=threat_score,
            is_vulnerable=is_vuln,
            vulnerability_type=vuln_type,
            confidence=confidence,
            analyzer_used="Binary Analyzer (5-model ensemble, 35% acc)",
            details=result,
            recommendations=recommendations
        )

    def _analyze_http(self, target: Union[str, Dict], target_path: str) -> VulnHunterResult:
        """Analyze HTTP request"""
        trainer = self.analyzers['http']

        # Convert to dict if needed
        if isinstance(target, str):
            # Parse as simple URL
            target = {'url': target, 'method': 'GET'}

        result = trainer.predict_vulnerability(target)

        is_vuln = result.get('is_vulnerable', False)
        confidence = result.get('confidence', 0.5)
        vuln_type = result.get('vulnerability_type', 'unknown')

        threat_score = result.get('risk_score', confidence * 10)
        threat_level = self._score_to_level(threat_score)

        recommendations = []
        if is_vuln:
            vuln_name = vuln_type.replace('_', ' ').title()
            recommendations = [
                f"🚨 CRITICAL: {vuln_name} vulnerability detected",
                "Implement input validation and sanitization",
                "Use parameterized queries (for SQL injection)",
                "Escape output (for XSS)",
                "Validate and sanitize all user input",
                "Use security headers (CSP, X-Frame-Options, etc.)"
            ]
        else:
            recommendations = [
                "✅ Request appears safe",
                "Continue monitoring for suspicious patterns",
                "Implement rate limiting and WAF"
            ]

        return VulnHunterResult(
            target_path=target_path,
            target_type=TargetType.HTTP_REQUEST,
            threat_level=threat_level,
            threat_score=threat_score,
            is_vulnerable=is_vuln,
            vulnerability_type=vuln_type,
            confidence=confidence,
            analyzer_used="HTTP Security Analyzer (4-model ensemble, 100% acc)",
            details=result,
            recommendations=recommendations
        )

    def _analyze_code(self, target: str, target_path: str) -> VulnHunterResult:
        """Analyze source code"""
        trainer = self.analyzers['code']

        # Read code if file path
        if os.path.exists(target):
            with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        else:
            code = target

        result = trainer.predict_vulnerability(code)

        is_vuln = result.get('is_vulnerable', False)
        confidence = result.get('confidence', 0.5)
        vuln_type = result.get('vulnerability_type', 'unknown')

        threat_score = result.get('risk_score', confidence * 10)
        threat_level = self._score_to_level(threat_score)

        recommendations = []
        if is_vuln:
            vuln_name = vuln_type.replace('_', ' ').title()
            recommendations = [
                f"🚨 CRITICAL: {vuln_name} found in code",
                "Refactor vulnerable code patterns",
                "Use secure coding practices",
                "Implement proper input validation",
                "Use security libraries (e.g., parameterized queries, HTML escaping)",
                "Run SAST tools (SonarQube, Semgrep, CodeQL)"
            ]
        else:
            recommendations = [
                "✅ Code appears secure",
                "Continue code reviews and security testing",
                "Keep dependencies updated"
            ]

        return VulnHunterResult(
            target_path=target_path,
            target_type=TargetType.SOURCE_CODE,
            threat_level=threat_level,
            threat_score=threat_score,
            is_vulnerable=is_vuln,
            vulnerability_type=vuln_type,
            confidence=confidence,
            analyzer_used="Code/SAST Analyzer (3-model ensemble, 100% acc)",
            details=result,
            recommendations=recommendations
        )

    def _score_to_level(self, score: float) -> ThreatLevel:
        """Convert threat score to threat level"""
        if score < 1.0:
            return ThreatLevel.SAFE
        elif score < 2.5:
            return ThreatLevel.MINIMAL
        elif score < 4.0:
            return ThreatLevel.LOW
        elif score < 6.0:
            return ThreatLevel.MEDIUM
        elif score < 8.0:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL

    def status(self) -> Dict[str, Any]:
        """Get VulnHunter status"""
        return {
            'ready': self.ready,
            'analyzers': {
                'ios_macos': 'ios_macos' in self.analyzers,
                'binary': 'binary' in self.analyzers,
                'http': 'http' in self.analyzers,
                'code': 'code' in self.analyzers
            },
            'total_models': len(self.analyzers),
            'version': '1.0.0'
        }


def main():
    """Command-line interface for VulnHunter"""
    import argparse

    parser = argparse.ArgumentParser(
        description='VulnHunter - Unified Vulnerability Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnhunter.py status
  vulnhunter.py hunt app.ipa
  vulnhunter.py hunt malware.exe
  vulnhunter.py hunt vulnerable.py
  vulnhunter.py hunt --url "https://api.example.com?id=1"
        """
    )

    parser.add_argument('command', choices=['status', 'hunt'], help='Command to execute')
    parser.add_argument('target', nargs='?', help='Target to analyze (file path or URL)')
    parser.add_argument('--url', help='HTTP URL to analyze')
    parser.add_argument('--models-dir', help='Custom models directory')

    args = parser.parse_args()

    # Initialize VulnHunter
    hunter = VulnHunter(models_dir=args.models_dir)

    if args.command == 'status':
        status = hunter.status()
        print("\n🦾 VulnHunter Status")
        print("=" * 60)
        print(f"Ready: {'✅ YES' if status['ready'] else '❌ NO'}")
        print(f"Version: {status['version']}")
        print(f"\nAnalyzers Loaded: {status['total_models']}/4")
        print("  iOS/macOS:", "✅" if status['analyzers']['ios_macos'] else "❌")
        print("  Binary:", "✅" if status['analyzers']['binary'] else "❌")
        print("  HTTP:", "✅" if status['analyzers']['http'] else "❌")
        print("  Code:", "✅" if status['analyzers']['code'] else "❌")
        print()

    elif args.command == 'hunt':
        if not args.target and not args.url:
            print("❌ Error: Target required for hunt command")
            print("Usage: vulnhunter.py hunt <file> or vulnhunter.py hunt --url <url>")
            sys.exit(1)

        target = args.target or args.url

        # Convert URL to dict format
        if args.url:
            target = {'url': args.url, 'method': 'GET'}

        result = hunter.hunt(target)
        print(result)


if __name__ == '__main__':
    main()
