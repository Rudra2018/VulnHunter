#!/usr/bin/env python3
"""
Analysis result data structures for VulnHunter Professional
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

from .vulnerability import Vulnerability, VulnSeverity


@dataclass
class PerformanceMetrics:
    """Performance metrics for analysis"""
    analysis_time_ms: float
    memory_usage_mb: float
    cpu_usage_percent: float
    files_analyzed: int
    lines_of_code: int
    plugins_used: List[str] = field(default_factory=list)


@dataclass
class QualityMetrics:
    """Quality metrics for analysis results"""
    confidence_avg: float
    false_positive_rate: float
    coverage_percentage: float
    completeness_score: float


@dataclass
class StatisticalSummary:
    """Statistical summary of vulnerabilities found"""
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    unique_cwe_count: int
    affected_files: int
    risk_score: float


@dataclass
class AnalysisResult:
    """Comprehensive analysis result container"""

    # Core results
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    # Analysis metadata
    analysis_id: str = ""
    target_path: str = ""
    analysis_type: str = "comprehensive"  # "sast", "dast", "binary", "network"

    # Timestamps
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    # Metrics
    performance_metrics: Optional[PerformanceMetrics] = None
    quality_metrics: Optional[QualityMetrics] = None
    statistical_summary: Optional[StatisticalSummary] = None

    # Configuration used
    config: Dict[str, Any] = field(default_factory=dict)

    # Additional context
    environment_info: Dict[str, Any] = field(default_factory=dict)
    tool_versions: Dict[str, str] = field(default_factory=dict)

    # Status and errors
    status: str = "pending"  # "pending", "running", "completed", "failed"
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def calculate_summary(self) -> None:
        """Calculate statistical summary from vulnerabilities"""
        if not self.vulnerabilities:
            self.statistical_summary = StatisticalSummary(
                total_vulnerabilities=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                unique_cwe_count=0,
                affected_files=0,
                risk_score=0.0
            )
            return

        # Count vulnerabilities by severity
        severity_counts = {
            VulnSeverity.CRITICAL: 0,
            VulnSeverity.HIGH: 0,
            VulnSeverity.MEDIUM: 0,
            VulnSeverity.LOW: 0
        }

        unique_cwes = set()
        affected_files = set()
        total_risk = 0.0

        for vuln in self.vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1

            if vuln.cwe_id:
                unique_cwes.add(vuln.cwe_id)

            if vuln.location.file_path:
                affected_files.add(vuln.location.file_path)

            total_risk += vuln.get_risk_score()

        self.statistical_summary = StatisticalSummary(
            total_vulnerabilities=len(self.vulnerabilities),
            critical_count=severity_counts[VulnSeverity.CRITICAL],
            high_count=severity_counts[VulnSeverity.HIGH],
            medium_count=severity_counts[VulnSeverity.MEDIUM],
            low_count=severity_counts[VulnSeverity.LOW],
            unique_cwe_count=len(unique_cwes),
            affected_files=len(affected_files),
            risk_score=total_risk
        )

    def get_vulnerabilities_by_severity(self, severity: VulnSeverity) -> List[Vulnerability]:
        """Get vulnerabilities filtered by severity"""
        return [v for v in self.vulnerabilities if v.severity == severity]

    def get_vulnerabilities_by_cwe(self, cwe_id: str) -> List[Vulnerability]:
        """Get vulnerabilities filtered by CWE ID"""
        return [v for v in self.vulnerabilities if v.cwe_id == cwe_id]

    def get_high_confidence_vulnerabilities(self, threshold: float = 0.8) -> List[Vulnerability]:
        """Get vulnerabilities with confidence above threshold"""
        return [v for v in self.vulnerabilities if v.confidence >= threshold]

    def filter_false_positives(self, threshold: float = 0.5) -> List[Vulnerability]:
        """Filter out likely false positives"""
        return [v for v in self.vulnerabilities if v.false_positive_probability < threshold]

    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary"""
        self.calculate_summary()

        return {
            'analysis_id': self.analysis_id,
            'target_path': self.target_path,
            'analysis_type': self.analysis_type,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'statistical_summary': {
                'total_vulnerabilities': self.statistical_summary.total_vulnerabilities,
                'critical_count': self.statistical_summary.critical_count,
                'high_count': self.statistical_summary.high_count,
                'medium_count': self.statistical_summary.medium_count,
                'low_count': self.statistical_summary.low_count,
                'unique_cwe_count': self.statistical_summary.unique_cwe_count,
                'affected_files': self.statistical_summary.affected_files,
                'risk_score': self.statistical_summary.risk_score
            } if self.statistical_summary else None,
            'performance_metrics': {
                'analysis_time_ms': self.performance_metrics.analysis_time_ms,
                'memory_usage_mb': self.performance_metrics.memory_usage_mb,
                'files_analyzed': self.performance_metrics.files_analyzed,
                'lines_of_code': self.performance_metrics.lines_of_code
            } if self.performance_metrics else None,
            'errors': self.errors,
            'warnings': self.warnings
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert analysis result to JSON string"""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_sarif(self) -> Dict[str, Any]:
        """Convert analysis result to SARIF format"""
        # Implementation of SARIF (Static Analysis Results Interchange Format)
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VulnHunter Professional",
                            "version": "5.0.0",
                            "informationUri": "https://vulnhunter.ai"
                        }
                    },
                    "results": []
                }
            ]
        }

        for vuln in self.vulnerabilities:
            sarif_result = {
                "ruleId": vuln.cwe_id or vuln.vuln_type.value,
                "level": self._severity_to_sarif_level(vuln.severity),
                "message": {
                    "text": vuln.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": vuln.location.file_path
                            },
                            "region": {
                                "startLine": vuln.location.line_number,
                                "startColumn": vuln.location.column_number
                            }
                        }
                    }
                ]
            }
            sarif["runs"][0]["results"].append(sarif_result)

        return sarif

    def _severity_to_sarif_level(self, severity: VulnSeverity) -> str:
        """Convert VulnSeverity to SARIF level"""
        mapping = {
            VulnSeverity.CRITICAL: "error",
            VulnSeverity.HIGH: "error",
            VulnSeverity.MEDIUM: "warning",
            VulnSeverity.LOW: "note",
            VulnSeverity.NONE: "note"
        }
        return mapping.get(severity, "note")