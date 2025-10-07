#!/bin/bash
#
# Run All Experiments for TDSC Submission
#
# This script runs all experiments to reproduce:
# - Table 1: Performance metrics
# - Table 2: SOTA comparison
# - Table 3: Ablation study
# - Theorem validation
#
# Usage:
#   bash run_all_experiments.sh [--quick]
#
# Options:
#   --quick    Use smaller sample sizes for faster execution

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Parse arguments
QUICK_MODE=false
if [[ "$1" == "--quick" ]]; then
    QUICK_MODE=true
    echo "Running in QUICK MODE (reduced samples)"
fi

# Create results directory
mkdir -p results

echo "========================================================================"
echo "Running All Experiments for TDSC Submission"
echo "========================================================================"
echo "Start time: $(date)"
echo ""

# Table 1: Performance Metrics
echo "------------------------------------------------------------------------"
echo "1/5: Reproducing Table 1 (Performance Metrics)"
echo "------------------------------------------------------------------------"
if [ "$QUICK_MODE" = true ]; then
    python3 experiments/reproduce_table1.py \
        --output results/table1 \
        --bootstrap 20 \
        --skip-ci
else
    python3 experiments/reproduce_table1.py \
        --output results/table1 \
        --bootstrap 100
fi
echo "✓ Table 1 complete"
echo ""

# Table 2: SOTA Comparison
echo "------------------------------------------------------------------------"
echo "2/5: Reproducing Table 2 (SOTA Comparison)"
echo "------------------------------------------------------------------------"
if [ "$QUICK_MODE" = true ]; then
    python3 experiments/reproduce_table2_sota.py \
        --baselines Devign LineVul \
        --output results/table2 \
        --skip-statistical-tests
else
    python3 experiments/reproduce_table2_sota.py \
        --baselines all \
        --output results/table2
fi
echo "✓ Table 2 complete"
echo ""

# Table 3: Ablation Study
echo "------------------------------------------------------------------------"
echo "3/5: Reproducing Table 3 (Ablation Study)"
echo "------------------------------------------------------------------------"
python3 experiments/reproduce_table3_ablation.py \
    --output results/table3
echo "✓ Table 3 complete"
echo ""

# Theorem Validation
echo "------------------------------------------------------------------------"
echo "4/5: Validating Theorems 5.1 and 5.2"
echo "------------------------------------------------------------------------"
if [ "$QUICK_MODE" = true ]; then
    python3 experiments/validate_theorems.py \
        --samples 100 \
        --output results/theorem_validation
else
    python3 experiments/validate_theorems.py \
        --samples 1000 \
        --output results/theorem_validation
fi
echo "✓ Theorem validation complete"
echo ""

# Generate Summary Report
echo "------------------------------------------------------------------------"
echo "5/5: Generating Summary Report"
echo "------------------------------------------------------------------------"

cat > results/EXPERIMENT_SUMMARY.md << 'EOF'
# Experiment Results Summary

## Table 1: Performance on Comprehensive Test Suite

See: `table1.csv`, `table1.json`, `table1.tex`

## Table 2: Comparison with State-of-the-Art

See: `table2.csv`, `table2.json`, `table2.tex`

## Table 3: Ablation Study

See: `table3.csv`, `table3.json`, `table3.tex`

## Theorem Validation

See: `theorem_validation_combined.json`

### Theorem 5.1 (FPR Bound)
- **Status**: See `theorem_validation_theorem51.json`

### Theorem 5.2 (FNR Bound)
- **Status**: See `theorem_validation_theorem52.json`

## Files Generated

All results are in the `results/` directory:
- CSV files (for analysis)
- JSON files (detailed data)
- TEX files (LaTeX tables for paper)

## Next Steps

1. Review all results
2. Copy LaTeX tables to manuscript
3. Update manuscript with actual numbers
4. Generate final figures

---
Generated: $(date)
EOF

echo "✓ Summary report generated"
echo ""

# Final summary
echo "========================================================================"
echo "All Experiments Complete!"
echo "========================================================================"
echo "End time: $(date)"
echo ""
echo "Results saved to: results/"
echo ""
echo "Files generated:"
echo "  - results/table1.{csv,json,tex}"
echo "  - results/table2.{csv,json,tex}"
echo "  - results/table3.{csv,json,tex}"
echo "  - results/theorem_validation_*.json"
echo "  - results/EXPERIMENT_SUMMARY.md"
echo ""
echo "Next: Review results and update manuscript!"
echo ""

# List all generated files
echo "All output files:"
ls -lh results/
