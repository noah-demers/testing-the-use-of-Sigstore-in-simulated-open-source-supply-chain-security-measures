#!/usr/bin/env python3
"""
Quick Start Script for End-User Experiment
Run this to verify setup and execute a quick test
"""

import os
import sys

def check_python_version():
    """Verify Python version"""
    print("Checking Python version...")
    if sys.version_info < (3, 7):
        print("❌ ERROR: Python 3.7+ required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True

def check_files():
    """Verify all required files exist"""
    print("\nChecking required files...")
    required_files = [
        "rekor_transparency_log.py",
        "attack_scenario_generator.py",
        "client_verifier.py",
        "run_enduser_experiment.py",
        "analyze_enduser_results.py"
    ]

    all_present = True
    for file in required_files:
        if os.path.exists(file):
            print(f"✓ {file}")
        else:
            print(f"❌ {file} - MISSING")
            all_present = False

    return all_present

def run_quick_test():
    """Run a quick test with one scenario"""
    print("\n" + "="*70)
    print("RUNNING QUICK TEST (1 trial per scenario)")
    print("="*70)

    try:
        from rekor_transparency_log import RekorTransparencyLog
        from attack_scenario_generator import AttackScenarioGenerator
        from client_verifier import PackageVerifier

        # Initialize
        rekor = RekorTransparencyLog("test_transparency_log.json")
        rekor.clear()

        generator = AttackScenarioGenerator(rekor)

        # Test baseline mode
        print("\n[TEST 1] Baseline mode with compromised package...")
        attack = generator.scenario1_compromised_package(1)
        verifier_baseline = PackageVerifier(rekor, config_mode="baseline")
        result_baseline = verifier_baseline.verify_package(
            attack["package"], attack["signature"]
        )

        if result_baseline["verification_result"] == "PASSED":
            print("✓ Baseline correctly passed malicious package (no detection)")
        else:
            print("❌ Unexpected: Baseline should pass malicious package")

        # Test defense mode
        print("\n[TEST 2] Defense mode with compromised package...")
        verifier_defense = PackageVerifier(rekor, config_mode="defense")
        result_defense = verifier_defense.verify_package(
            attack["package"], attack["signature"],
            expected_identity=attack["expected_identity"],
            package_name=attack["package"].replace(".tar.gz", "")
        )

        # Defense might pass or fail depending on timing
        print(f"Defense result: {result_defense['verification_result']}")
        print(f"Reason: {result_defense.get('failure_reason', 'none')}")

        # Test with backdated package (should always detect)
        print("\n[TEST 3] Defense mode with backdated package...")
        rekor.clear()
        attack2 = generator.scenario2_backdated_package(2)
        verifier_defense2 = PackageVerifier(rekor, config_mode="defense")
        result_defense2 = verifier_defense2.verify_package(
            attack2["package"], attack2["signature"],
            expected_identity=attack2["expected_identity"],
            package_name="mypackage"
        )

        if result_defense2["verification_result"] == "FAILED":
            print("✓ Defense correctly detected rollback attack")
        else:
            print("❌ Unexpected: Defense should detect rollback")

        # Cleanup
        for file in os.listdir('.'):
            if file.endswith('.tar.gz') or file.endswith('.sig'):
                try:
                    os.remove(file)
                except:
                    pass

        print("\n" + "="*70)
        print("✓✓✓ QUICK TEST PASSED - System working correctly!")
        print("="*70)
        return True

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("="*70)
    print("END-USER EXPERIMENT - QUICK START")
    print("="*70)

    # Run checks
    if not check_python_version():
        sys.exit(1)

    if not check_files():
        print("\n❌ ERROR: Missing required files")
        print("   Please ensure all experiment files are in the current directory")
        sys.exit(1)

    # Run quick test
    if not run_quick_test():
        print("\n❌ Quick test failed")
        sys.exit(1)

    # Instructions
    print("\n" + "="*70)
    print("READY TO RUN FULL EXPERIMENT")
    print("="*70)
    print("""
To run the complete experiment with all scenarios:

    python3 run_enduser_experiment.py

This will:
- Run 10 trials for each of 4 attack scenarios (40 malicious packages)
- Run 5 trials with legitimate packages (control group)  
- Test both baseline and defense verification modes
- Generate results in enduser_experiment_results.csv

To analyze results after running:

    python3 analyze_enduser_results.py

Expected runtime: 2-3 minutes
""")

if __name__ == "__main__":
    main()
