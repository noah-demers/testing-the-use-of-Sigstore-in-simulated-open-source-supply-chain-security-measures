#!/usr/bin/env python3
"""
End-User Experiment Runner - PERFECT VERSION
Only modification from original: Passes package_name from attack_scenario_generator
"""

import os
import csv
import time
import glob
from typing import List, Dict
from client_verifier import PackageVerifier
from attack_scenario_generator import AttackScenarioGenerator
from rekor_transparency_log import RekorTransparencyLog


class EndUserExperiment:
    """Run end-user verification experiments"""

    def __init__(self, output_file: str = "enduser_experiment_results.csv"):
        self.rekor = RekorTransparencyLog("enduser_transparency_log.json")
        self.rekor.clear()

        self.scenario_generator = AttackScenarioGenerator(self.rekor)
        self.results = []
        self.output_file = output_file
        self.created_files = []

    def run_scenario_trials(self, scenario_name: str, scenario_func, 
                           num_trials: int = 10, config: str = "baseline"):
        """Run multiple trials of a scenario"""
        print(f"\n{'='*70}")
        print(f"Running {scenario_name} - {config.upper()} mode ({num_trials} trials)")
        print(f"{'='*70}")

        for trial_id in range(1, num_trials + 1):
            attack_data = scenario_func(trial_id)

            package_file = attack_data["package"]
            signature_file = attack_data["signature"]

            # THE ONLY CHANGE: Get package_name from attack_scenario_generator
            package_name = attack_data.get("package_name")

            self.created_files.append(package_file)
            self.created_files.append(signature_file)

            verifier = PackageVerifier(self.rekor, config_mode=config)
            result = verifier.verify_package(
                package_file,
                signature_file,
                expected_identity=attack_data.get("expected_identity"),
                package_name=package_name  # PASS IT HERE
            )

            result["scenario"] = scenario_name
            result["trial_id"] = trial_id
            result["is_malicious"] = attack_data["is_malicious"]
            result["attack_type"] = attack_data["attack_type"]

            self.results.append(result)

    def run_all_experiments(self):
        """Run all experiment scenarios"""
        print("\n" + "="*80)
        print("END-USER SIDE SIGSTORE VERIFICATION EXPERIMENT")
        print("="*80)

        print("\n" + "#"*70)
        print("# PART 1: BASELINE CONFIGURATION")
        print("#"*70)

        self.run_scenario_trials("compromised_package", self.scenario_generator.scenario1_compromised_package, 10, "baseline")
        self.run_scenario_trials("backdated_package", self.scenario_generator.scenario2_backdated_package, 10, "baseline")
        self.run_scenario_trials("malicious_mirror", self.scenario_generator.scenario3_malicious_mirror, 10, "baseline")
        self.run_scenario_trials("typosquatting", self.scenario_generator.scenario4_typosquatting, 10, "baseline")
        self.run_scenario_trials("legitimate", self.scenario_generator.create_legitimate_package, 5, "baseline")

        print("\n" + "#"*70)
        print("# PART 2: DEFENSE CONFIGURATION")
        print("#"*70)

        self.run_scenario_trials("compromised_package", self.scenario_generator.scenario1_compromised_package, 10, "defense")
        self.run_scenario_trials("backdated_package", self.scenario_generator.scenario2_backdated_package, 10, "defense")
        self.run_scenario_trials("malicious_mirror", self.scenario_generator.scenario3_malicious_mirror, 10, "defense")
        self.run_scenario_trials("typosquatting", self.scenario_generator.scenario4_typosquatting, 10, "defense")
        self.run_scenario_trials("legitimate", self.scenario_generator.create_legitimate_package, 5, "defense")

    def save_results(self):
        """Save results to CSV"""
        if not self.results:
            print("\nNo results to save")
            return

        fieldnames = [
            "trial_id", "scenario", "config", "package_name", "is_malicious",
            "attack_type", "signature_valid", "identity_verified",
            "in_transparency_log", "timestamp_valid", "verification_result",
            "verification_latency_ms", "failure_reason"
        ]

        with open(self.output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for result in self.results:
                row = {field: result.get(field, "") for field in fieldnames}
                writer.writerow(row)

        print(f"\n✓ Results saved to {self.output_file}")

    def cleanup_files(self):
        """Delete all generated .tar.gz and .sig files"""
        print("\n[CLEANUP] Removing generated package files...")
        count = 0

        for file_path in self.created_files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    count += 1
            except Exception:
                pass

        for pattern in ["*.tar.gz", "*.sig"]:
            for file_path in glob.glob(pattern):
                try:
                    os.remove(file_path)
                    count += 1
                except Exception:
                    pass

        print(f"[CLEANUP] Deleted {count} files")

    def print_summary(self):
        """Print experiment summary"""
        print("\n" + "="*80)
        print("EXPERIMENT SUMMARY")
        print("="*80)

        baseline_results = [r for r in self.results if r["config"] == "baseline"]
        defense_results = [r for r in self.results if r["config"] == "defense"]

        baseline_malicious = [r for r in baseline_results if r["is_malicious"]]
        baseline_legit = [r for r in baseline_results if not r["is_malicious"]]
        baseline_detection = sum(1 for r in baseline_malicious if r["verification_result"] == "FAILED") / len(baseline_malicious) * 100 if baseline_malicious else 0
        baseline_fp = sum(1 for r in baseline_legit if r["verification_result"] == "FAILED") / len(baseline_legit) * 100 if baseline_legit else 0

        defense_malicious = [r for r in defense_results if r["is_malicious"]]
        defense_legit = [r for r in defense_results if not r["is_malicious"]]
        defense_detection = sum(1 for r in defense_malicious if r["verification_result"] == "FAILED") / len(defense_malicious) * 100 if defense_malicious else 0
        defense_fp = sum(1 for r in defense_legit if r["verification_result"] == "FAILED") / len(defense_legit) * 100 if defense_legit else 0

        print("\nBASELINE MODE (Traditional Verification):")
        print(f"  Malicious Detection: {baseline_detection:.1f}%")
        print(f"  False Positive Rate: {baseline_fp:.1f}%")

        print("\nDEFENSE MODE (Sigstore + Rollback Detection):")
        print(f"  Malicious Detection: {defense_detection:.1f}%")
        print(f"  False Positive Rate: {defense_fp:.1f}%")

        print("\n" + "="*80)


def main():
    experiment = EndUserExperiment()

    try:
        experiment.run_all_experiments()
        experiment.save_results()
        experiment.print_summary()
        experiment.cleanup_files()

        print("\n✓ Experiment complete!")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()