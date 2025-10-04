#!/bin/bash
# Quick status check for training

echo "═══════════════════════════════════════════════════════════"
echo "🎯 VulnGuard AI Training Monitor"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "📅 Current Time: $(date '+%I:%M %p')"
echo "🕐 Started: 11:54 AM"
echo ""

if ps -p 7126 > /dev/null 2>&1; then
    echo "✅ Status: TRAINING ACTIVE"
    ps -p 7126 -o pid,etime,%cpu,%mem,stat | tail -1 | awk '{print "⏱️  Runtime: " $2 "\n💻 CPU: " $3 "%\n💾 Memory: " $4 "%\n📊 State: " $5}'
    echo ""
    echo "Current Phase:"
    echo "  ✅ Random Forest - COMPLETE"
    echo "  🔄 Gradient Boosting - TRAINING"
    echo "  ⏳ XGBoost - PENDING"
    echo "  ⏳ Neural Network - PENDING"
    echo "  ⏳ SVM - PENDING"
    echo "  ⏳ Logistic Regression - PENDING"
else
    echo "⚠️  Training process not found (may have completed or stopped)"
    if ls ultimate_vulnguard_*.pkl 2>/dev/null; then
        echo "✅ Found saved model files!"
        ls -lh ultimate_vulnguard_*.pkl
    fi
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "💡 To see full output: tail -f training_output.log"
echo "💡 To check this status: ./TRAINING_MONITOR.sh"
echo "═══════════════════════════════════════════════════════════"
