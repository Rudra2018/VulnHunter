#!/usr/bin/env python3
"""
Microsoft Bounty Analysis Validator

Specific validation for Microsoft bug bounty analysis claims.
This validator checks mathematical consistency, realistic bounty estimates,
and cross-references with actual Microsoft bounty program data.
"""

import json
import numpy as np
from typing import Dict, List, Any, Tuple

class MicrosoftBountyAnalysisValidator:
    """Validate Microsoft bug bounty analysis for accuracy and realism."""

    def __init__(self):
        # Actual Microsoft bounty program data (verified from web search)
        self.actual_bounty_limits = {
            "hyper_v": {"max": 250000, "min": 5000},
            "windows_insider": {"max": 100000, "min": 500},
            "azure": {"max": 60000, "min": 500},
            "microsoft_identity": {"max": 100000, "min": 750},
            "m365": {"max": 19500, "min": 500},
            "dynamics": {"max": 30000, "min": 500},
            "copilot": {"max": 30000, "min": 500},
            "edge": {"max": 30000, "min": 500},
            "azure_devops": {"max": 20000, "min": 500},
            "defender": {"max": 20000, "min": 500},
            "xbox": {"max": 20000, "min": 500},
            "dotnet": {"max": 15000, "min": 500}
        }

        # Historical data from web search
        self.historical_context = {
            "total_payouts_2024": 17000000,  # $17M total
            "researchers_paid_2024": 344,
            "average_payout_2024": 17000000 / 344,  # ~$49,400 average
            "largest_single_award": 200000,  # $200K for Hyper-V
            "zero_day_quest_submissions": 600,  # 600+ submissions for major event
            "zero_day_quest_payouts": 1600000  # $1.6M for that event
        }

    def validate_analysis(self, analysis_file: str) -> Dict[str, Any]:
        """Comprehensive validation of Microsoft bounty analysis."""

        with open(analysis_file, 'r') as f:
            analysis = json.load(f)

        validation_results = {
            "analysis_file": analysis_file,
            "validation_timestamp": "2025-10-13",
            "overall_assessment": "PENDING",
            "critical_issues": [],
            "warnings": [],
            "mathematical_validation": {},
            "realism_assessment": {},
            "recommendation": "PENDING"
        }

        # 1. Mathematical consistency validation
        self._validate_mathematics(analysis, validation_results)

        # 2. Bounty amount realism validation
        self._validate_bounty_amounts(analysis, validation_results)

        # 3. Vulnerability count realism validation
        self._validate_vulnerability_counts(analysis, validation_results)

        # 4. Detection confidence analysis
        self._validate_detection_confidence(analysis, validation_results)

        # 5. Market reality check
        self._validate_market_reality(analysis, validation_results)

        # Calculate overall assessment
        self._calculate_overall_assessment(validation_results)

        return validation_results

    def _validate_mathematics(self, analysis: Dict, results: Dict) -> None:
        """Validate mathematical consistency in the analysis."""

        math_issues = []
        total_estimated_value = 0
        total_vulnerabilities = 0

        for program_name, program_data in analysis.items():
            if isinstance(program_data, dict) and 'vulnerabilities' in program_data:
                vulnerabilities = program_data['vulnerabilities']
                program_total = 0

                for vuln in vulnerabilities:
                    if 'bounty_potential' in vuln:
                        estimated_value = vuln['bounty_potential'].get('estimated_value', 0)
                        program_total += estimated_value
                        total_estimated_value += estimated_value
                        total_vulnerabilities += 1

                # Check if program totals make sense
                if program_total > 50000000:  # $50M per program is unrealistic
                    math_issues.append(f"Program {program_name}: Unrealistic total bounty potential ${program_total:,}")

        # Overall totals check
        if total_estimated_value > 100000000:  # $100M total is unrealistic
            math_issues.append(f"Total estimated value ${total_estimated_value:,} exceeds realistic market size")

        results["mathematical_validation"] = {
            "total_estimated_value": total_estimated_value,
            "total_vulnerabilities": total_vulnerabilities,
            "average_value_per_vulnerability": total_estimated_value / max(total_vulnerabilities, 1),
            "issues": math_issues
        }

        if math_issues:
            results["critical_issues"].extend(math_issues)

    def _validate_bounty_amounts(self, analysis: Dict, results: Dict) -> None:
        """Validate that bounty amounts are within realistic ranges."""

        bounty_issues = []

        for program_name, program_data in analysis.items():
            if isinstance(program_data, dict) and 'vulnerabilities' in program_data:
                vulnerabilities = program_data['vulnerabilities']

                for vuln in vulnerabilities:
                    if 'bounty_potential' in vuln:
                        bp = vuln['bounty_potential']
                        estimated = bp.get('estimated_value', 0)
                        max_val = bp.get('max_value', 0)
                        min_val = bp.get('min_value', 0)

                        # Check for unrealistic individual bounty amounts
                        if estimated > 250000:  # Max Microsoft bounty is $250K
                            bounty_issues.append(f"Unrealistic bounty estimate ${estimated:,} exceeds Microsoft's maximum")

                        # Check for impossible math (estimated outside min/max range)
                        if estimated < min_val or estimated > max_val:
                            bounty_issues.append(f"Mathematical error: estimated ${estimated} outside range ${min_val}-${max_val}")

        results["realism_assessment"]["bounty_amounts"] = {
            "issues": bounty_issues,
            "status": "VALID" if not bounty_issues else "INVALID"
        }

        if bounty_issues:
            results["critical_issues"].extend(bounty_issues)

    def _validate_vulnerability_counts(self, analysis: Dict, results: Dict) -> None:
        """Validate that vulnerability counts are realistic."""

        count_issues = []
        program_counts = {}

        for program_name, program_data in analysis.items():
            if isinstance(program_data, dict) and 'vulnerabilities' in program_data:
                count = len(program_data['vulnerabilities'])
                program_counts[program_name] = count

                # Check against realistic expectations
                if count > 200:  # More than 200 vulnerabilities per program is suspicious
                    count_issues.append(f"Program {program_name}: Unrealistic vulnerability count {count}")

        # Total vulnerabilities across all programs
        total_count = sum(program_counts.values())

        # Compare to historical data
        # Microsoft paid 344 researchers in 2024 - having 1000+ vulnerabilities from one analysis is suspicious
        if total_count > 1000:
            count_issues.append(f"Total vulnerability count {total_count} exceeds realistic discovery rate")

        results["realism_assessment"]["vulnerability_counts"] = {
            "program_counts": program_counts,
            "total_count": total_count,
            "issues": count_issues
        }

        if count_issues:
            results["warnings"].extend(count_issues)

    def _validate_detection_confidence(self, analysis: Dict, results: Dict) -> None:
        """Analyze detection confidence patterns."""

        confidence_values = []
        confidence_issues = []

        for program_name, program_data in analysis.items():
            if isinstance(program_data, dict) and 'vulnerabilities' in program_data:
                for vuln in program_data['vulnerabilities']:
                    if 'detection_confidence' in vuln:
                        confidence = vuln['detection_confidence']
                        confidence_values.append(confidence)

        if confidence_values:
            confidence_array = np.array(confidence_values)

            # Statistical analysis of confidence values
            mean_confidence = np.mean(confidence_array)
            std_confidence = np.std(confidence_array)
            unique_values = len(set(confidence_values))

            # Red flags for artificial generation
            if std_confidence < 0.1:  # Too uniform
                confidence_issues.append("Detection confidence values show unrealistic uniformity")

            if unique_values == len(confidence_values):  # Every value unique (suspicious)
                confidence_issues.append("Every confidence value is unique - suggests artificial generation")

            if mean_confidence > 0.9:  # Too high average
                confidence_issues.append(f"Average confidence {mean_confidence:.3f} is unrealistically high")

        results["realism_assessment"]["detection_confidence"] = {
            "mean": float(np.mean(confidence_values)) if confidence_values else 0,
            "std": float(np.std(confidence_values)) if confidence_values else 0,
            "count": len(confidence_values),
            "unique_values": len(set(confidence_values)),
            "issues": confidence_issues
        }

        if confidence_issues:
            results["warnings"].extend(confidence_issues)

    def _validate_market_reality(self, analysis: Dict, results: Dict) -> None:
        """Validate against known market reality and Microsoft's actual programs."""

        market_issues = []

        # Calculate claimed total value
        total_claimed_value = results["mathematical_validation"]["total_estimated_value"]

        # Compare to historical reality
        historical_annual = self.historical_context["total_payouts_2024"]

        # If claiming more than 2x Microsoft's entire annual payout, it's suspicious
        if total_claimed_value > historical_annual * 2:
            market_issues.append(
                f"Claimed total value ${total_claimed_value:,} is {total_claimed_value/historical_annual:.1f}x "
                f"Microsoft's entire 2024 payout (${historical_annual:,})"
            )

        # Check if the analysis claims to have found more vulnerabilities than submitted
        # to Microsoft's largest bounty event
        total_vulns = results["mathematical_validation"]["total_vulnerabilities"]
        if total_vulns > self.historical_context["zero_day_quest_submissions"] * 2:
            market_issues.append(
                f"Claims {total_vulns} vulnerabilities, more than 2x the submissions "
                f"to Microsoft's major Zero Day Quest event ({self.historical_context['zero_day_quest_submissions']})"
            )

        results["realism_assessment"]["market_reality"] = {
            "claimed_vs_historical_ratio": total_claimed_value / historical_annual,
            "vulnerability_vs_major_event_ratio": total_vulns / self.historical_context["zero_day_quest_submissions"],
            "issues": market_issues
        }

        if market_issues:
            results["critical_issues"].extend(market_issues)

    def _calculate_overall_assessment(self, results: Dict) -> None:
        """Calculate overall assessment and recommendation."""

        critical_count = len(results["critical_issues"])
        warning_count = len(results["warnings"])

        if critical_count >= 3:
            results["overall_assessment"] = "HIGHLY SUSPICIOUS"
            results["recommendation"] = "REJECT - Multiple critical issues suggest inflated or fabricated analysis"
        elif critical_count >= 1:
            results["overall_assessment"] = "SUSPICIOUS"
            results["recommendation"] = "REVIEW REQUIRED - Critical issues need investigation"
        elif warning_count >= 3:
            results["overall_assessment"] = "QUESTIONABLE"
            results["recommendation"] = "CAUTION - Multiple warnings suggest overly optimistic analysis"
        else:
            results["overall_assessment"] = "PLAUSIBLE"
            results["recommendation"] = "ACCEPT WITH VERIFICATION - Analysis appears reasonable"

    def print_validation_report(self, results: Dict) -> None:
        """Print formatted validation report."""

        print("=" * 80)
        print("🔍 MICROSOFT BOUNTY ANALYSIS VALIDATION REPORT")
        print("=" * 80)
        print(f"Analysis File: {results['analysis_file']}")
        print(f"Overall Assessment: {results['overall_assessment']}")
        print(f"Recommendation: {results['recommendation']}")
        print()

        # Mathematical validation
        math = results["mathematical_validation"]
        print(f"💰 MATHEMATICAL ANALYSIS:")
        print(f"   Total Estimated Value: ${math['total_estimated_value']:,}")
        print(f"   Total Vulnerabilities: {math['total_vulnerabilities']:,}")
        print(f"   Average Value per Vuln: ${math['average_value_per_vulnerability']:,.0f}")
        print()

        # Market reality check
        market = results["realism_assessment"]["market_reality"]
        print(f"📊 MARKET REALITY CHECK:")
        print(f"   Claimed vs 2024 Microsoft Total: {market['claimed_vs_historical_ratio']:.1f}x")
        print(f"   Vulnerabilities vs Major Event: {market['vulnerability_vs_major_event_ratio']:.1f}x")
        print()

        # Critical issues
        if results["critical_issues"]:
            print("🚩 CRITICAL ISSUES:")
            for i, issue in enumerate(results["critical_issues"], 1):
                print(f"   {i}. {issue}")
            print()

        # Warnings
        if results["warnings"]:
            print("⚠️  WARNINGS:")
            for i, warning in enumerate(results["warnings"], 1):
                print(f"   {i}. {warning}")
            print()

        print("=" * 80)


def main():
    """Main validation function."""

    validator = MicrosoftBountyAnalysisValidator()

    analysis_file = "/Users/ankitthakur/Downloads/microsoft_bounty_analysis/microsoft_bounty_comprehensive_analysis.json"

    results = validator.validate_analysis(analysis_file)
    validator.print_validation_report(results)

    # Save results
    results_file = "/Users/ankitthakur/vuln_ml_research/microsoft_bounty_validation_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"✅ Detailed results saved to: {results_file}")

    return results


if __name__ == "__main__":
    results = main()