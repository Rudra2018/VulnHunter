#!/usr/bin/env python3
"""
Quick Start Bounty Hunting
Simplified interface to start hunting immediately
"""

import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        🦾 HUNTR BOUNTY HUNTER - QUICK START                     ║
║                                                                  ║
║        Your VulnGuard AI is ready for real bounty hunting!      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")

def show_menu():
    print("""
What would you like to do?

1. 🎯 AGGRESSIVE MODE - More detections, some false positives
   (4/7 layers, 85% confidence - Better for learning)

2. 🛡️  CONSERVATIVE MODE - Fewer detections, very high quality
   (5/7 layers, 95% confidence - Default, best for submissions)

3. ⚡ BALANCED MODE - Middle ground
   (4/7 layers, 90% confidence - Good compromise)

4. 🔍 TEST CURRENT SETTINGS - See what mode you're in

5. 🚀 START BOUNTY HUNTING - Run with current settings

6. 📊 VIEW STATISTICS - See scan results

7. 📚 READ DOCUMENTATION

8. ❌ EXIT

Enter choice (1-8):""")

def update_threshold_settings(layers: int, confidence: float):
    """Update zero-FP engine settings"""
    file_path = 'core/zero_false_positive_engine.py'

    try:
        with open(file_path, 'r') as f:
            content = f.read()

        # Update settings
        import re
        content = re.sub(
            r'self\.min_layers_passed\s*=\s*\d+',
            f'self.min_layers_passed = {layers}',
            content
        )
        content = re.sub(
            r'self\.confidence_threshold\s*=\s*[\d.]+',
            f'self.confidence_threshold = {confidence}',
            content
        )

        with open(file_path, 'w') as f:
            f.write(content)

        logger.info(f"✅ Updated settings: {layers}/7 layers, {confidence:.0%} confidence")
        return True

    except Exception as e:
        logger.error(f"❌ Error updating settings: {e}")
        return False

def get_current_settings():
    """Read current threshold settings"""
    try:
        with open('core/zero_false_positive_engine.py', 'r') as f:
            content = f.read()

        import re
        layers_match = re.search(r'self\.min_layers_passed\s*=\s*(\d+)', content)
        conf_match = re.search(r'self\.confidence_threshold\s*=\s*([\d.]+)', content)

        if layers_match and conf_match:
            layers = int(layers_match.group(1))
            confidence = float(conf_match.group(1))
            return layers, confidence

        return 5, 0.95  # defaults

    except:
        return 5, 0.95

def run_bounty_hunter(script='focused_bounty_targets.py'):
    """Run the bounty hunting script"""
    logger.info(f"\n🚀 Starting bounty hunting with {script}...")
    logger.info("=" * 70)

    import subprocess
    result = subprocess.run(['python3', script], capture_output=False)
    return result.returncode == 0

def show_statistics():
    """Show scanning statistics"""
    import glob

    json_reports = glob.glob('bounty_report_*.json')
    md_reports = glob.glob('bounty_report_*.md')
    summaries = glob.glob('huntr_bounty_hunting_summary_*.json')

    print(f"""
📊 SCANNING STATISTICS
═══════════════════════════════════════════════════════════════════

Reports Generated:
  • JSON Reports: {len(json_reports)}
  • Markdown Reports: {len(md_reports)}
  • Summary Files: {len(summaries)}

""")

    if json_reports:
        print("Recent Reports:")
        for report in sorted(json_reports)[-5:]:
            print(f"  • {report}")
    else:
        print("No reports generated yet. Run a scan to create reports!")

def show_documentation():
    """Display documentation info"""
    print("""
📚 DOCUMENTATION
═══════════════════════════════════════════════════════════════════

Available Documentation:

1. QUICKSTART.md - Quick start guide (start here!)
2. SYSTEM_SUMMARY.md - Complete system overview
3. HUNTR_INTEGRATION_GUIDE.md - Full integration guide
4. NEXT_ACTIONS.md - 30-day action plan

Scripts Available:

• focused_bounty_targets.py - Scan high-value patterns
• real_world_scanner.py - Scan real GitHub repos
• huntr_bounty_hunter.py - Complete pipeline
• test_huntr_system.py - Test suite

To read a file:
  cat QUICKSTART.md
  cat NEXT_ACTIONS.md

═══════════════════════════════════════════════════════════════════
""")

def main():
    print_banner()

    while True:
        show_menu()

        try:
            choice = input().strip()

            if choice == '1':
                # Aggressive mode
                print("\n🎯 Setting AGGRESSIVE MODE...")
                if update_threshold_settings(4, 0.85):
                    print("""
✅ Aggressive mode enabled!

This mode will:
  • Find MORE vulnerabilities
  • Accept 4/7 verification layers (was 5/7)
  • Use 85% confidence threshold (was 95%)
  • May have 5-10% false positives

Best for: Learning, research, exploring patterns
                    """)

            elif choice == '2':
                # Conservative mode
                print("\n🛡️  Setting CONSERVATIVE MODE...")
                if update_threshold_settings(5, 0.95):
                    print("""
✅ Conservative mode enabled! (Default)

This mode will:
  • Find FEWER but HIGH-QUALITY vulnerabilities
  • Require 5/7 verification layers
  • Use 95% confidence threshold
  • <3% false positive rate

Best for: Production bounty submissions
                    """)

            elif choice == '3':
                # Balanced mode
                print("\n⚡ Setting BALANCED MODE...")
                if update_threshold_settings(4, 0.90):
                    print("""
✅ Balanced mode enabled!

This mode will:
  • Find MODERATE number of vulnerabilities
  • Require 4/7 verification layers
  • Use 90% confidence threshold
  • ~5% false positive rate

Best for: Balanced approach between quality and quantity
                    """)

            elif choice == '4':
                # Show current settings
                layers, confidence = get_current_settings()
                print(f"""
📊 CURRENT SETTINGS
═══════════════════════════════════════════════════════════════════

Verification Layers Required: {layers}/7
Confidence Threshold: {confidence:.0%}

""")
                if layers == 5 and confidence >= 0.95:
                    print("Mode: 🛡️  CONSERVATIVE (Best for submissions)")
                elif layers == 4 and confidence <= 0.85:
                    print("Mode: 🎯 AGGRESSIVE (Better for learning)")
                else:
                    print("Mode: ⚡ BALANCED (Middle ground)")

            elif choice == '5':
                # Start hunting
                print("""
🚀 STARTING BOUNTY HUNTING
═══════════════════════════════════════════════════════════════════

Choose what to scan:

1. High-value patterns (2 minutes)
2. Real GitHub repositories (5-10 minutes)
3. Complete pipeline (10-15 minutes)

Enter choice (1-3):""")

                scan_choice = input().strip()

                if scan_choice == '1':
                    run_bounty_hunter('focused_bounty_targets.py')
                elif scan_choice == '2':
                    run_bounty_hunter('real_world_scanner.py')
                elif scan_choice == '3':
                    run_bounty_hunter('huntr_bounty_hunter.py')
                else:
                    print("Invalid choice")

            elif choice == '6':
                # Statistics
                show_statistics()

            elif choice == '7':
                # Documentation
                show_documentation()

            elif choice == '8':
                # Exit
                print("""
Thanks for using Huntr Bounty Hunter! 🎯

Next steps:
1. Read NEXT_ACTIONS.md for your 30-day plan
2. Run a scan with option 5
3. Submit findings to huntr.dev

Good luck hunting! 💰
""")
                break

            else:
                print("❌ Invalid choice. Please enter 1-8.")

            input("\nPress Enter to continue...")

        except KeyboardInterrupt:
            print("\n\nExiting... Goodbye! 👋")
            break
        except Exception as e:
            logger.error(f"Error: {e}")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
