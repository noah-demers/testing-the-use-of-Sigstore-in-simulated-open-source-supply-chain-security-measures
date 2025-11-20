#!/usr/bin/env python3
"""
Analyze End-User Experiment Results
Generate statistics and visualizations
"""

import pandas as pd
import json

def analyze_results(csv_file="enduser_experiment_results.csv"):
    """Analyze experiment results from CSV"""

    print("="*70)
    print("END-USER EXPERIMENT ANALYSIS")
    print("="*70)

    # Load data
    df = pd.read_csv(csv_file)

    print(f"\nTotal trials: {len(df)}")
    print(f"Configurations: {df['config'].unique()}")
    print(f"Scenarios: {df['scenario'].unique()}")

    # Analysis by configuration
    for config in df['config'].unique():
        config_df = df[df['config'] == config]

        print(f"\n{'='*70}")
        print(f"{config.upper()} CONFIGURATION ANALYSIS")
        print(f"{'='*70}")

        # Overall metrics
        total = len(config_df)
        passed = (config_df['verification_result'] == 'PASSED').sum()
        failed = (config_df['verification_result'] == 'FAILED').sum()

        print(f"\nOverall Verification Results:")
        print(f"  Total: {total}")
        print(f"  Passed: {passed} ({100*passed/total:.1f}%)")
        print(f"  Failed: {failed} ({100*failed/total:.1f}%)")

        # Detection rate (for malicious packages)
        malicious_df = config_df[config_df['is_malicious'] == True]
        if len(malicious_df) > 0:
            detected = (malicious_df['verification_result'] == 'FAILED').sum()
            detection_rate = 100 * detected / len(malicious_df)

            print(f"\nMalicious Package Detection:")
            print(f"  Total malicious: {len(malicious_df)}")
            print(f"  Detected (blocked): {detected} ({detection_rate:.1f}%)")
            print(f"  Missed (allowed): {len(malicious_df) - detected} ({100-detection_rate:.1f}%)")

        # False positive rate (for legitimate packages)
        legit_df = config_df[config_df['is_malicious'] == False]
        if len(legit_df) > 0:
            false_pos = (legit_df['verification_result'] == 'FAILED').sum()
            fp_rate = 100 * false_pos / len(legit_df)

            print(f"\nLegitimate Package Verification:")
            print(f"  Total legitimate: {len(legit_df)}")
            print(f"  Correctly accepted: {len(legit_df) - false_pos}")
            print(f"  False positives (incorrectly rejected): {false_pos} ({fp_rate:.1f}%)")

        # Latency statistics
        avg_latency = config_df['verification_latency_ms'].mean()
        min_latency = config_df['verification_latency_ms'].min()
        max_latency = config_df['verification_latency_ms'].max()

        print(f"\nVerification Latency:")
        print(f"  Average: {avg_latency:.1f}ms")
        print(f"  Min: {min_latency:.1f}ms")
        print(f"  Max: {max_latency:.1f}ms")

        # By scenario breakdown
        print(f"\nDetection Rate by Attack Scenario:")
        for scenario in sorted(config_df['scenario'].unique()):
            scenario_df = config_df[(config_df['scenario'] == scenario) & 
                                   (config_df['is_malicious'] == True)]
            if len(scenario_df) > 0:
                detected = (scenario_df['verification_result'] == 'FAILED').sum()
                rate = 100 * detected / len(scenario_df)
                print(f"  {scenario:25s}: {detected}/{len(scenario_df):2d} detected ({rate:5.1f}%)")

        # Failure reasons (for defense mode)
        if config == "defense":
            print(f"\nFailure Reasons (Defense Mode):")
            failure_df = config_df[config_df['verification_result'] == 'FAILED']
            if len(failure_df) > 0:
                failure_counts = failure_df['failure_reason'].value_counts()
                for reason, count in failure_counts.items():
                    if reason != "none":
                        print(f"  {reason:40s}: {count:2d} ({100*count/len(failure_df):.1f}%)")

    # Comparative analysis
    print(f"\n{'='*70}")
    print("COMPARATIVE ANALYSIS: BASELINE vs DEFENSE")
    print(f"{'='*70}")

    baseline_df = df[df['config'] == 'baseline']
    defense_df = df[df['config'] == 'defense']

    # Detection rate comparison
    baseline_malicious = baseline_df[baseline_df['is_malicious'] == True]
    defense_malicious = defense_df[defense_df['is_malicious'] == True]

    baseline_detection = 100 * (baseline_malicious['verification_result'] == 'FAILED').sum() / len(baseline_malicious)
    defense_detection = 100 * (defense_malicious['verification_result'] == 'FAILED').sum() / len(defense_malicious)

    print(f"\nMalicious Package Detection Rate:")
    print(f"  Baseline: {baseline_detection:.1f}%")
    print(f"  Defense:  {defense_detection:.1f}%")
    print(f"  Improvement: {defense_detection - baseline_detection:+.1f} percentage points")

    # Latency comparison
    baseline_latency = baseline_df['verification_latency_ms'].mean()
    defense_latency = defense_df['verification_latency_ms'].mean()
    latency_overhead = defense_latency - baseline_latency
    latency_overhead_pct = 100 * latency_overhead / baseline_latency

    print(f"\nVerification Latency:")
    print(f"  Baseline: {baseline_latency:.1f}ms")
    print(f"  Defense:  {defense_latency:.1f}ms")
    print(f"  Overhead: +{latency_overhead:.1f}ms (+{latency_overhead_pct:.1f}%)")

    # Scenario-specific comparison
    print(f"\nDetection Rate by Scenario (Baseline → Defense):")
    for scenario in sorted(df['scenario'].unique()):
        if scenario == "legitimate":
            continue

        baseline_scenario = baseline_df[(baseline_df['scenario'] == scenario) & 
                                       (baseline_df['is_malicious'] == True)]
        defense_scenario = defense_df[(defense_df['scenario'] == scenario) & 
                                      (defense_df['is_malicious'] == True)]

        if len(baseline_scenario) > 0 and len(defense_scenario) > 0:
            baseline_rate = 100 * (baseline_scenario['verification_result'] == 'FAILED').sum() / len(baseline_scenario)
            defense_rate = 100 * (defense_scenario['verification_result'] == 'FAILED').sum() / len(defense_scenario)
            improvement = defense_rate - baseline_rate

            print(f"  {scenario:25s}: {baseline_rate:5.1f}% → {defense_rate:5.1f}% ({improvement:+6.1f}pp)")

    print(f"\n{'='*70}")
    print("KEY FINDINGS")
    print(f"{'='*70}")

    print(f"""
1. DETECTION EFFECTIVENESS:
   - Baseline (traditional) detection rate: {baseline_detection:.1f}%
   - Defense (Sigstore) detection rate: {defense_detection:.1f}%
   - Improvement: {defense_detection - baseline_detection:.1f} percentage points

2. PERFORMANCE OVERHEAD:
   - Average latency increase: {latency_overhead:.1f}ms ({latency_overhead_pct:.1f}%)
   - Trade-off: Slightly slower verification for dramatically better security

3. FALSE POSITIVE RATE:
   - Both configurations should have low false positive rates on legitimate packages
   - Any false positives indicate verification policy tuning needed

4. SCENARIO-SPECIFIC INSIGHTS:
   - Compromised packages: Tests detection of stolen key attacks
   - Backdated packages: Tests rollback attack prevention
   - Malicious mirrors: Tests hash verification against transparency log
   - Typosquatting: Tests identity-package name matching
""")

if __name__ == "__main__":
    import sys
    csv_file = sys.argv[1] if len(sys.argv) > 1 else "enduser_experiment_results.csv"

    try:
        analyze_results(csv_file)
    except FileNotFoundError:
        print(f"[ERROR] Results file not found: {csv_file}")
        print("Run the experiment first: python3 run_enduser_experiment.py")
        sys.exit(1)
