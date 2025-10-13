#!/usr/bin/env python3
"""
Benchmark Performance Validator for VulnHunter AI
Validates model performance against established benchmarks and research standards
"""

import os
import json
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Tuple
from pathlib import Path
import logging
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('benchmark_validation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('BenchmarkValidator')

class BenchmarkPerformanceValidator:
    """Validates model performance against established benchmarks"""

    def __init__(self, results_dir: str = "benchmark_validation_results"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(exist_ok=True)

        # Benchmark standards from research literature
        self.benchmark_standards = {
            "state_of_the_art_models": {
                "VulDeePecker": {"accuracy": 0.891, "precision": 0.928, "recall": 0.943, "f1": 0.935},
                "DeepWukong": {"accuracy": 0.896, "precision": 0.934, "recall": 0.901, "f1": 0.917},
                "VulBERTa": {"accuracy": 0.911, "precision": 0.942, "recall": 0.924, "f1": 0.933},
                "CodeBERT": {"accuracy": 0.887, "precision": 0.919, "recall": 0.912, "f1": 0.915},
                "GraphCodeBERT": {"accuracy": 0.903, "precision": 0.935, "recall": 0.918, "f1": 0.926},
                "LineVul": {"accuracy": 0.874, "precision": 0.907, "recall": 0.895, "f1": 0.901},
                "IVDetect": {"accuracy": 0.923, "precision": 0.951, "recall": 0.938, "f1": 0.944},
                "Devign": {"accuracy": 0.879, "precision": 0.912, "recall": 0.889, "f1": 0.900}
            },
            "performance_tiers": {
                "excellent": {"accuracy": 0.95, "f1": 0.94, "auc_roc": 0.97},
                "good": {"accuracy": 0.90, "f1": 0.89, "auc_roc": 0.93},
                "acceptable": {"accuracy": 0.85, "f1": 0.83, "auc_roc": 0.88},
                "poor": {"accuracy": 0.80, "f1": 0.78, "auc_roc": 0.83}
            },
            "vulnerability_specific_benchmarks": {
                "CWE-89": {"accuracy": 0.932, "precision": 0.945, "recall": 0.918, "f1": 0.931},
                "CWE-79": {"accuracy": 0.896, "precision": 0.921, "recall": 0.894, "f1": 0.907},
                "CWE-78": {"accuracy": 0.915, "precision": 0.938, "recall": 0.923, "f1": 0.930},
                "CWE-119": {"accuracy": 0.943, "precision": 0.957, "recall": 0.941, "f1": 0.949},
                "CWE-120": {"accuracy": 0.938, "precision": 0.952, "recall": 0.936, "f1": 0.944},
                "CWE-22": {"accuracy": 0.924, "precision": 0.941, "recall": 0.928, "f1": 0.934},
                "CWE-327": {"accuracy": 0.887, "precision": 0.912, "recall": 0.901, "f1": 0.906},
                "CWE-502": {"accuracy": 0.901, "precision": 0.925, "recall": 0.908, "f1": 0.916}
            },
            "language_specific_benchmarks": {
                "C": {"accuracy": 0.923, "f1": 0.918},
                "C++": {"accuracy": 0.917, "f1": 0.912},
                "Java": {"accuracy": 0.909, "f1": 0.904},
                "Python": {"accuracy": 0.895, "f1": 0.891},
                "JavaScript": {"accuracy": 0.881, "f1": 0.877},
                "PHP": {"accuracy": 0.874, "f1": 0.869}
            }
        }

        # Industry performance requirements
        self.industry_requirements = {
            "financial_services": {"accuracy": 0.97, "false_positive_rate": 0.02, "recall": 0.95},
            "healthcare": {"accuracy": 0.96, "false_positive_rate": 0.03, "recall": 0.94},
            "government": {"accuracy": 0.98, "false_positive_rate": 0.01, "recall": 0.97},
            "enterprise": {"accuracy": 0.93, "false_positive_rate": 0.05, "recall": 0.90},
            "open_source": {"accuracy": 0.90, "false_positive_rate": 0.07, "recall": 0.88}
        }

    def load_training_results(self, results_path: str) -> Dict[str, Any]:
        """Load training results from JSON file"""

        try:
            with open(results_path, 'r') as f:
                results = json.load(f)
            logger.info(f"📥 Loaded training results from {results_path}")
            return results
        except Exception as e:
            logger.error(f"❌ Failed to load training results: {e}")
            return {}

    def validate_against_sota(self, model_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate against state-of-the-art models"""

        logger.info("🔍 Validating Against State-of-the-Art Models")
        logger.info("=" * 60)

        our_metrics = model_results.get("evaluation_results", {}).get("overall_metrics", {})
        sota_models = self.benchmark_standards["state_of_the_art_models"]

        validation_results = {
            "our_model_metrics": our_metrics,
            "comparisons": {},
            "ranking": {},
            "improvement_analysis": {}
        }

        # Compare against each SOTA model
        for model_name, benchmarks in sota_models.items():
            comparison = {}

            for metric in ["accuracy", "precision", "recall", "f1"]:
                our_value = our_metrics.get(metric, 0.0)
                bench_value = benchmarks.get(metric, 0.0)

                if metric == "f1":
                    our_value = our_metrics.get("f1_score", our_value)

                improvement = our_value - bench_value
                percentage_improvement = (improvement / bench_value * 100) if bench_value > 0 else 0

                comparison[metric] = {
                    "our_value": our_value,
                    "benchmark_value": bench_value,
                    "improvement": improvement,
                    "percentage_improvement": percentage_improvement,
                    "better": our_value > bench_value
                }

            validation_results["comparisons"][model_name] = comparison

            # Overall performance score
            better_count = sum(1 for m in comparison.values() if m["better"])
            validation_results["ranking"][model_name] = {
                "metrics_better": better_count,
                "total_metrics": len(comparison),
                "percentage_better": better_count / len(comparison) * 100
            }

        # Calculate average improvements
        improvements = {}
        for metric in ["accuracy", "precision", "recall", "f1"]:
            metric_improvements = [
                comp[metric]["improvement"]
                for comp in validation_results["comparisons"].values()
            ]
            improvements[metric] = {
                "average_improvement": np.mean(metric_improvements),
                "max_improvement": max(metric_improvements),
                "min_improvement": min(metric_improvements),
                "models_beaten": sum(1 for imp in metric_improvements if imp > 0)
            }

        validation_results["improvement_analysis"] = improvements

        # Log results
        logger.info("📊 SOTA Comparison Results:")
        our_acc = our_metrics.get("accuracy", 0)
        our_f1 = our_metrics.get("f1_score", 0)

        logger.info(f"  🎯 Our Model - Accuracy: {our_acc:.4f}, F1: {our_f1:.4f}")

        best_models = sorted(
            validation_results["ranking"].items(),
            key=lambda x: x[1]["percentage_better"],
            reverse=True
        )

        for model, ranking in best_models[:3]:
            logger.info(f"  📈 vs {model}: {ranking['metrics_better']}/{ranking['total_metrics']} metrics better "
                       f"({ranking['percentage_better']:.1f}%)")

        return validation_results

    def validate_performance_tiers(self, model_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate against performance tier standards"""

        logger.info("🔍 Validating Against Performance Tiers")
        logger.info("=" * 60)

        our_metrics = model_results.get("evaluation_results", {}).get("overall_metrics", {})
        tiers = self.benchmark_standards["performance_tiers"]

        tier_validation = {
            "our_metrics": our_metrics,
            "tier_classification": {},
            "tier_achievement": "poor"  # Default
        }

        # Check which tier we achieve
        our_accuracy = our_metrics.get("accuracy", 0)
        our_f1 = our_metrics.get("f1_score", 0)
        our_auc = our_metrics.get("auc_roc", 0)

        for tier_name, requirements in tiers.items():
            meets_accuracy = our_accuracy >= requirements["accuracy"]
            meets_f1 = our_f1 >= requirements["f1"]
            meets_auc = our_auc >= requirements["auc_roc"]

            meets_tier = meets_accuracy and meets_f1 and meets_auc

            tier_validation["tier_classification"][tier_name] = {
                "meets_accuracy": meets_accuracy,
                "meets_f1": meets_f1,
                "meets_auc": meets_auc,
                "meets_tier": meets_tier,
                "requirements": requirements,
                "gaps": {
                    "accuracy": max(0, requirements["accuracy"] - our_accuracy),
                    "f1": max(0, requirements["f1"] - our_f1),
                    "auc_roc": max(0, requirements["auc_roc"] - our_auc)
                }
            }

            if meets_tier:
                tier_validation["tier_achievement"] = tier_name

        # Log tier achievement
        achieved_tier = tier_validation["tier_achievement"]
        logger.info(f"🏆 Performance Tier Achieved: {achieved_tier.upper()}")
        logger.info(f"  🎯 Accuracy: {our_accuracy:.4f}")
        logger.info(f"  🎯 F1 Score: {our_f1:.4f}")
        logger.info(f"  🎯 AUC-ROC: {our_auc:.4f}")

        return tier_validation

    def validate_vulnerability_specific(self, model_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate vulnerability-specific performance"""

        logger.info("🔍 Validating Vulnerability-Specific Performance")
        logger.info("=" * 60)

        vuln_performance = model_results.get("evaluation_results", {}).get("vulnerability_performance", {})
        vuln_benchmarks = self.benchmark_standards["vulnerability_specific_benchmarks"]

        vuln_validation = {
            "vulnerability_comparisons": {},
            "summary": {
                "total_types_evaluated": len(vuln_performance),
                "types_above_benchmark": 0,
                "average_improvement": 0.0
            }
        }

        improvements = []

        for vuln_type, our_metrics in vuln_performance.items():
            # Map vulnerability type to CWE if needed
            cwe_mapping = {
                "Sql Injection": "CWE-89",
                "Xss": "CWE-79",
                "Command Injection": "CWE-78",
                "Buffer Overflow": "CWE-119",
                "Path Traversal": "CWE-22",
                "Weak Crypto": "CWE-327",
                "Deserialization": "CWE-502"
            }

            cwe_id = cwe_mapping.get(vuln_type, f"CWE-{vuln_type}")

            if cwe_id in vuln_benchmarks:
                benchmark = vuln_benchmarks[cwe_id]

                our_acc = our_metrics.get("accuracy", 0)
                our_f1 = our_metrics.get("f1_score", 0)
                bench_acc = benchmark.get("accuracy", 0)
                bench_f1 = benchmark.get("f1", 0)

                comparison = {
                    "our_accuracy": our_acc,
                    "benchmark_accuracy": bench_acc,
                    "accuracy_improvement": our_acc - bench_acc,
                    "our_f1": our_f1,
                    "benchmark_f1": bench_f1,
                    "f1_improvement": our_f1 - bench_f1,
                    "above_benchmark": our_acc > bench_acc and our_f1 > bench_f1,
                    "sample_count": our_metrics.get("samples", 0)
                }

                vuln_validation["vulnerability_comparisons"][vuln_type] = comparison

                if comparison["above_benchmark"]:
                    vuln_validation["summary"]["types_above_benchmark"] += 1

                improvements.append(comparison["accuracy_improvement"])

                logger.info(f"  🔍 {vuln_type}:")
                logger.info(f"    Acc: {our_acc:.3f} vs {bench_acc:.3f} "
                          f"({'↑' if our_acc > bench_acc else '↓'}{abs(our_acc - bench_acc):.3f})")
                logger.info(f"    F1:  {our_f1:.3f} vs {bench_f1:.3f} "
                          f"({'↑' if our_f1 > bench_f1 else '↓'}{abs(our_f1 - bench_f1):.3f})")

        if improvements:
            vuln_validation["summary"]["average_improvement"] = np.mean(improvements)

        above_benchmark = vuln_validation["summary"]["types_above_benchmark"]
        total_types = vuln_validation["summary"]["total_types_evaluated"]

        logger.info(f"📊 Vulnerability Performance Summary:")
        logger.info(f"  🎯 Types Above Benchmark: {above_benchmark}/{total_types} "
                   f"({above_benchmark/total_types*100:.1f}%)")
        logger.info(f"  📈 Average Improvement: {vuln_validation['summary']['average_improvement']:.3f}")

        return vuln_validation

    def validate_industry_requirements(self, model_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate against industry-specific requirements"""

        logger.info("🔍 Validating Against Industry Requirements")
        logger.info("=" * 60)

        our_metrics = model_results.get("evaluation_results", {}).get("overall_metrics", {})

        our_accuracy = our_metrics.get("accuracy", 0)
        our_recall = our_metrics.get("recall", 0)
        our_specificity = our_metrics.get("specificity", 0)
        our_fpr = 1.0 - our_specificity  # False positive rate

        industry_validation = {
            "industry_suitability": {},
            "recommended_industries": [],
            "requirements_analysis": {}
        }

        for industry, requirements in self.industry_requirements.items():
            meets_accuracy = our_accuracy >= requirements["accuracy"]
            meets_fpr = our_fpr <= requirements["false_positive_rate"]
            meets_recall = our_recall >= requirements["recall"]

            suitable = meets_accuracy and meets_fpr and meets_recall

            industry_validation["industry_suitability"][industry] = {
                "suitable": suitable,
                "meets_accuracy": meets_accuracy,
                "meets_fpr": meets_fpr,
                "meets_recall": meets_recall,
                "requirements": requirements,
                "our_values": {
                    "accuracy": our_accuracy,
                    "false_positive_rate": our_fpr,
                    "recall": our_recall
                },
                "gaps": {
                    "accuracy": max(0, requirements["accuracy"] - our_accuracy),
                    "false_positive_rate": max(0, our_fpr - requirements["false_positive_rate"]),
                    "recall": max(0, requirements["recall"] - our_recall)
                }
            }

            if suitable:
                industry_validation["recommended_industries"].append(industry)

            logger.info(f"  🏢 {industry.title()}:")
            logger.info(f"    Suitable: {'✅ YES' if suitable else '❌ NO'}")
            logger.info(f"    Accuracy: {our_accuracy:.3f} ≥ {requirements['accuracy']:.3f} "
                       f"({'✅' if meets_accuracy else '❌'})")
            logger.info(f"    FPR: {our_fpr:.3f} ≤ {requirements['false_positive_rate']:.3f} "
                       f"({'✅' if meets_fpr else '❌'})")
            logger.info(f"    Recall: {our_recall:.3f} ≥ {requirements['recall']:.3f} "
                       f"({'✅' if meets_recall else '❌'})")

        recommended = industry_validation["recommended_industries"]
        logger.info(f"📊 Industry Suitability Summary:")
        logger.info(f"  🎯 Recommended Industries: {len(recommended)}/{len(self.industry_requirements)}")
        if recommended:
            logger.info(f"  ✅ Suitable for: {', '.join(recommended)}")

        return industry_validation

    def generate_comprehensive_benchmark_report(self, model_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive benchmark validation report"""

        logger.info("🔄 GENERATING COMPREHENSIVE BENCHMARK REPORT")
        logger.info("=" * 80)

        # Run all validation tests
        sota_validation = self.validate_against_sota(model_results)
        tier_validation = self.validate_performance_tiers(model_results)
        vuln_validation = self.validate_vulnerability_specific(model_results)
        industry_validation = self.validate_industry_requirements(model_results)

        # Calculate overall benchmark score
        benchmark_score = self.calculate_benchmark_score(
            sota_validation, tier_validation, vuln_validation, industry_validation
        )

        # Generate recommendations
        recommendations = self.generate_benchmark_recommendations(
            sota_validation, tier_validation, vuln_validation, industry_validation
        )

        comprehensive_report = {
            "report_metadata": {
                "generation_date": datetime.now().isoformat(),
                "model_name": "VulnHunter BGNN4VD Enhanced",
                "benchmark_framework": "Comprehensive Vulnerability Detection Benchmark v1.0",
                "validation_categories": 4
            },
            "overall_benchmark_score": benchmark_score,
            "detailed_validations": {
                "state_of_the_art_comparison": sota_validation,
                "performance_tier_validation": tier_validation,
                "vulnerability_specific_validation": vuln_validation,
                "industry_requirements_validation": industry_validation
            },
            "recommendations": recommendations,
            "summary": self.generate_executive_summary(
                benchmark_score, sota_validation, tier_validation,
                vuln_validation, industry_validation
            )
        }

        return comprehensive_report

    def calculate_benchmark_score(self, sota_val, tier_val, vuln_val, industry_val) -> Dict[str, Any]:
        """Calculate overall benchmark score"""

        # SOTA comparison score (0-100)
        models_beaten = sum(
            ranking["percentage_better"] / 100
            for ranking in sota_val["ranking"].values()
        )
        sota_score = min(100, (models_beaten / len(sota_val["ranking"])) * 100)

        # Tier achievement score (0-100)
        tier_scores = {"poor": 25, "acceptable": 50, "good": 75, "excellent": 100}
        tier_score = tier_scores.get(tier_val["tier_achievement"], 0)

        # Vulnerability-specific score (0-100)
        if vuln_val["summary"]["total_types_evaluated"] > 0:
            vuln_score = (vuln_val["summary"]["types_above_benchmark"] /
                         vuln_val["summary"]["total_types_evaluated"]) * 100
        else:
            vuln_score = 0

        # Industry suitability score (0-100)
        industry_score = (len(industry_val["recommended_industries"]) /
                         len(self.industry_requirements)) * 100

        # Weighted overall score
        weights = {"sota": 0.3, "tier": 0.25, "vulnerability": 0.25, "industry": 0.2}
        overall_score = (
            sota_score * weights["sota"] +
            tier_score * weights["tier"] +
            vuln_score * weights["vulnerability"] +
            industry_score * weights["industry"]
        )

        return {
            "overall_score": round(overall_score, 2),
            "component_scores": {
                "sota_comparison": round(sota_score, 2),
                "tier_achievement": round(tier_score, 2),
                "vulnerability_specific": round(vuln_score, 2),
                "industry_suitability": round(industry_score, 2)
            },
            "score_interpretation": self.interpret_benchmark_score(overall_score),
            "weights_used": weights
        }

    def interpret_benchmark_score(self, score: float) -> str:
        """Interpret benchmark score"""

        if score >= 90:
            return "Outstanding - Exceeds research state-of-the-art"
        elif score >= 80:
            return "Excellent - Competitive with best research models"
        elif score >= 70:
            return "Good - Above average research performance"
        elif score >= 60:
            return "Acceptable - Meets basic research standards"
        else:
            return "Needs Improvement - Below research standards"

    def generate_benchmark_recommendations(self, sota_val, tier_val, vuln_val, industry_val) -> List[str]:
        """Generate actionable recommendations based on benchmark validation"""

        recommendations = []

        # SOTA recommendations
        worst_metrics = []
        for model, comparison in sota_val["comparisons"].items():
            for metric, data in comparison.items():
                if not data["better"]:
                    worst_metrics.append(metric)

        if worst_metrics:
            common_weak = max(set(worst_metrics), key=worst_metrics.count)
            recommendations.append(f"Focus on improving {common_weak} - underperforming vs SOTA models")

        # Tier recommendations
        if tier_val["tier_achievement"] != "excellent":
            next_tier_gaps = []
            current_tier = tier_val["tier_achievement"]
            tiers = ["poor", "acceptable", "good", "excellent"]
            if current_tier in tiers and tiers.index(current_tier) < len(tiers) - 1:
                next_tier = tiers[tiers.index(current_tier) + 1]
                gaps = tier_val["tier_classification"][next_tier]["gaps"]
                for metric, gap in gaps.items():
                    if gap > 0:
                        next_tier_gaps.append(f"{metric}: +{gap:.3f}")

            if next_tier_gaps:
                recommendations.append(f"To reach {next_tier} tier, improve: {', '.join(next_tier_gaps)}")

        # Vulnerability-specific recommendations
        weak_vulns = []
        for vuln_type, comparison in vuln_val["vulnerability_comparisons"].items():
            if not comparison["above_benchmark"]:
                weak_vulns.append(vuln_type)

        if weak_vulns:
            recommendations.append(f"Improve detection for: {', '.join(weak_vulns[:3])}")

        # Industry recommendations
        unsuitable_industries = []
        for industry, suitability in industry_val["industry_suitability"].items():
            if not suitability["suitable"]:
                unsuitable_industries.append(industry)

        if len(industry_val["recommended_industries"]) < 3:
            recommendations.append("Reduce false positive rate to meet stricter industry requirements")

        if not recommendations:
            recommendations.append("Model meets all benchmark standards - ready for production deployment")

        return recommendations

    def generate_executive_summary(self, benchmark_score, sota_val, tier_val, vuln_val, industry_val) -> Dict[str, Any]:
        """Generate executive summary of benchmark validation"""

        our_metrics = None
        for validation in [sota_val, tier_val, vuln_val, industry_val]:
            if "our_model_metrics" in validation:
                our_metrics = validation["our_model_metrics"]
                break
            elif "our_metrics" in validation:
                our_metrics = validation["our_metrics"]
                break

        models_outperformed = sum(
            1 for ranking in sota_val["ranking"].values()
            if ranking["percentage_better"] > 50
        )

        return {
            "overall_performance": {
                "benchmark_score": benchmark_score["overall_score"],
                "score_interpretation": benchmark_score["score_interpretation"],
                "tier_achieved": tier_val["tier_achievement"]
            },
            "competitive_analysis": {
                "sota_models_outperformed": f"{models_outperformed}/{len(sota_val['ranking'])}",
                "average_improvement": round(np.mean([
                    imp["average_improvement"] for imp in sota_val["improvement_analysis"].values()
                ]), 3)
            },
            "vulnerability_coverage": {
                "types_above_benchmark": f"{vuln_val['summary']['types_above_benchmark']}/{vuln_val['summary']['total_types_evaluated']}",
                "average_improvement": round(vuln_val["summary"]["average_improvement"], 3)
            },
            "industry_readiness": {
                "suitable_industries": len(industry_val["recommended_industries"]),
                "recommended_sectors": industry_val["recommended_industries"]
            },
            "key_strengths": self.identify_key_strengths(sota_val, tier_val, vuln_val, industry_val),
            "improvement_areas": self.identify_improvement_areas(sota_val, tier_val, vuln_val, industry_val)
        }

    def identify_key_strengths(self, sota_val, tier_val, vuln_val, industry_val) -> List[str]:
        """Identify key model strengths"""

        strengths = []

        # Check if we outperform most SOTA models
        strong_models = sum(
            1 for ranking in sota_val["ranking"].values()
            if ranking["percentage_better"] > 75
        )
        if strong_models >= len(sota_val["ranking"]) * 0.6:
            strengths.append("Outperforms majority of state-of-the-art models")

        # Check tier achievement
        if tier_val["tier_achievement"] in ["excellent", "good"]:
            strengths.append(f"Achieves {tier_val['tier_achievement']} performance tier")

        # Check vulnerability coverage
        if vuln_val["summary"]["types_above_benchmark"] >= vuln_val["summary"]["total_types_evaluated"] * 0.7:
            strengths.append("Strong performance across vulnerability types")

        # Check industry suitability
        if len(industry_val["recommended_industries"]) >= 3:
            strengths.append("Suitable for multiple industry deployments")

        return strengths

    def identify_improvement_areas(self, sota_val, tier_val, vuln_val, industry_val) -> List[str]:
        """Identify areas needing improvement"""

        improvements = []

        # Check weakest metrics vs SOTA
        metric_performance = {}
        for comparison in sota_val["comparisons"].values():
            for metric, data in comparison.items():
                if metric not in metric_performance:
                    metric_performance[metric] = []
                metric_performance[metric].append(1 if data["better"] else 0)

        weak_metrics = [
            metric for metric, scores in metric_performance.items()
            if np.mean(scores) < 0.5
        ]

        if weak_metrics:
            improvements.append(f"Improve {', '.join(weak_metrics)} metrics")

        # Check tier gaps
        if tier_val["tier_achievement"] not in ["excellent"]:
            improvements.append("Enhance overall performance to reach excellent tier")

        # Check vulnerability weaknesses
        weak_vulns = sum(
            1 for comp in vuln_val["vulnerability_comparisons"].values()
            if not comp["above_benchmark"]
        )
        if weak_vulns > 0:
            improvements.append("Strengthen vulnerability-specific detection")

        return improvements

    def save_benchmark_report(self, report: Dict[str, Any], model_name: str = "vulnhunter_enhanced"):
        """Save comprehensive benchmark report"""

        logger.info("💾 Saving benchmark validation report...")

        # Save detailed JSON report
        report_path = self.results_dir / f"{model_name}_benchmark_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        # Save executive summary
        summary_path = self.results_dir / f"{model_name}_benchmark_summary.json"
        with open(summary_path, 'w') as f:
            json.dump({
                "executive_summary": report["summary"],
                "benchmark_score": report["overall_benchmark_score"],
                "recommendations": report["recommendations"]
            }, f, indent=2)

        logger.info(f"  ✅ Detailed report: {report_path}")
        logger.info(f"  ✅ Executive summary: {summary_path}")

        return report

def main():
    """Run comprehensive benchmark validation"""

    logger.info("🎬 Initializing Benchmark Performance Validator")

    # Initialize validator
    validator = BenchmarkPerformanceValidator()

    # Load training results
    results_path = "real_world_training_results/real_world_training_results.json"

    if not Path(results_path).exists():
        logger.error(f"❌ Training results not found at {results_path}")
        logger.info("Please run real_world_dataset_trainer.py first")
        return None

    model_results = validator.load_training_results(results_path)

    if not model_results:
        logger.error("❌ Failed to load model results")
        return None

    # Generate comprehensive benchmark report
    benchmark_report = validator.generate_comprehensive_benchmark_report(model_results)

    # Save report
    validator.save_benchmark_report(benchmark_report)

    # Display final summary
    logger.info("🎉 BENCHMARK VALIDATION COMPLETED!")
    logger.info("=" * 80)
    logger.info("📊 BENCHMARK VALIDATION SUMMARY:")

    score = benchmark_report["overall_benchmark_score"]["overall_score"]
    interpretation = benchmark_report["overall_benchmark_score"]["score_interpretation"]
    tier = benchmark_report["detailed_validations"]["performance_tier_validation"]["tier_achievement"]

    logger.info(f"  🎯 Overall Benchmark Score: {score}/100")
    logger.info(f"  📋 Performance Interpretation: {interpretation}")
    logger.info(f"  🏆 Performance Tier: {tier.upper()}")

    sota_outperformed = benchmark_report["summary"]["competitive_analysis"]["sota_models_outperformed"]
    industry_suitable = len(benchmark_report["summary"]["industry_readiness"]["recommended_sectors"])

    logger.info(f"  📈 SOTA Models Outperformed: {sota_outperformed}")
    logger.info(f"  🏢 Industry Sectors Suitable: {industry_suitable}/5")

    strengths = benchmark_report["summary"]["key_strengths"]
    if strengths:
        logger.info("  💪 Key Strengths:")
        for strength in strengths:
            logger.info(f"    • {strength}")

    logger.info("=" * 80)

    return benchmark_report

if __name__ == "__main__":
    benchmark_report = main()