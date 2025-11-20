#!/usr/bin/env python3
import os
import time
import csv
import json
import threading
from kam_client import KAMService
from attacker import run_attack_scenario
from monitor import RekorMonitor

class ExperimentConfig:
    def __init__(self, config_type):
        self.config_type = config_type
        self.kam_url = "http://localhost:8000"
        self.package_name = "example_package"
        self.legitimate_signer = "publisher@example.com"
        
        # Key TTL based on mode
        if config_type == "baseline":
            self.key_ttl = None  # No expiration
        else:  # defense (Sigstore ephemeral)
            self.key_ttl = 600  # 10 minutes

class TrialRunner:
    def __init__(self, config):
        self.config = config
        self.kam_service = KAMService(config.kam_url)
        self.results = []
        self.monitor = None
        self.monitor_thread = None
        self.artifacts_before_detection = 0  # Track cumulative accepted artifacts
        
    def setup_trial_environment(self):
        os.environ["EXPERIMENT_CONFIG"] = self.config.config_type
        
        # Clear detection log
        if os.path.exists("detections.json"):
            os.remove("detections.json")
        
        self.artifacts_before_detection = 0  # Reset counter for each config
        
        if self.config.config_type == "baseline":
            # Baseline: No KAM authorization, start monitor to detect all uploads
            print("[SETUP] Baseline mode: No key authorization (long-lived keys)")
            self.start_monitor(baseline_mode=True)
        else:
            # Defense: Authorize with TTL AND start monitor for second line of defense
            print(f"[SETUP] Defense mode: Authorizing key with TTL={self.config.key_ttl}s (Sigstore ephemeral)")
            print("[SETUP] Also starting monitor as secondary detection layer")
            self.kam_service.authorize_key(
                self.config.package_name,
                self.config.legitimate_signer,
                ttl_seconds=self.config.key_ttl
            )
            self.start_monitor(baseline_mode=False)  # Monitor checks KAM auth in defense mode
    
    def start_monitor(self, baseline_mode=False):
        """Start monitor in background"""
        mode_name = "baseline" if baseline_mode else "defense"
        print(f"[TRIAL] Starting background monitor ({mode_name} mode, 60s polling)")
        self.monitor = RekorMonitor(baseline_mode=baseline_mode)
        self.monitor_thread = threading.Thread(
            target=self.monitor.run_monitor_loop,
            args=(400,),  # Run for 6-7 min max
            daemon=True
        )
        self.monitor_thread.start()
    
    def get_detection_time(self, upload_time):
        """Wait for and retrieve detection time from monitor log"""
        print("[TRIAL] Waiting for monitor detection...")
        time.sleep(70)  # Wait for next poll cycle (60s + 10s buffer)
        
        if os.path.exists("detections.json"):
            with open("detections.json", 'r') as f:
                detections = json.load(f)
            for detection in detections:
                if detection["detection_time"] >= upload_time:
                    print(f"[TRIAL] Detection found at {detection['detection_time']}")
                    return detection["detection_time"]
        print("[TRIAL] No detection found in monitoring window")
        return None
    
    def run_stolen_key_trial(self, trial_id, theft_delay=0):
        """
        Run a stolen key attack trial
        theft_delay: seconds after key generation before attacker uses it
        """
        print(f"\n{'='*50}")
        print(f"Trial {trial_id}: theft_delay={theft_delay}s")
        print('='*50)
        
        trial_result = {
            "trial_id": trial_id,
            "config": self.config.config_type,
            "key_ttl": self.config.key_ttl or "none",
            "theft_delay": theft_delay,
            "upload_time": time.time(),
            "registry_response": "REJECTED",
            "detection_latency": None,
            "blocked_by": None,
            "artifacts_accepted_before_detection": 0,  # NEW: count accepted artifacts
            "monitor_would_have_detected": False  # NEW: did monitor find it (for defense mode)
        }
        
        upload_time = trial_result["upload_time"]
        attack_result = run_attack_scenario(theft_delay=theft_delay)
        trial_result["registry_response"] = "ACCEPTED" if attack_result["success"] else "REJECTED"
        
        print(f"[RESULT] Upload: {trial_result['registry_response']}")
        
        # Calculate latency and blocking mechanism
        if self.config.config_type == "baseline":
            # Baseline: Monitor detects (or should detect)
            if attack_result["success"]:
                print("[RESULT] Attack accepted, waiting for monitor to detect...")
                
                # Track this accepted artifact
                self.artifacts_before_detection += 1
                trial_result["artifacts_accepted_before_detection"] = self.artifacts_before_detection
                
                detection_time = self.get_detection_time(upload_time)
                if detection_time:
                    latency = detection_time - upload_time
                    trial_result["detection_latency"] = latency
                    trial_result["blocked_by"] = "transparency_log_monitor"
                    trial_result["monitor_would_have_detected"] = True
                    print(f"[RESULT] Detected by monitor after {latency:.1f}s")
                    print(f"[RESULT] Total malicious artifacts accepted before detection: {self.artifacts_before_detection}")
                    # Reset counter after detection
                    self.artifacts_before_detection = 0
                else:
                    trial_result["detection_latency"] = None
                    trial_result["blocked_by"] = "none"
                    trial_result["monitor_would_have_detected"] = False
                    print("[RESULT] Not detected by monitor (window closed)")
                    print(f"[RESULT] Undetected artifacts so far: {self.artifacts_before_detection}")
            else:
                trial_result["detection_latency"] = 0
                trial_result["artifacts_accepted_before_detection"] = 0
                print("[RESULT] Upload rejected")
        else:
            # Defense: Ephemeral keys with expiration AND monitor detection
            if attack_result["success"]:
                # Track accepted artifact in defense mode too
                self.artifacts_before_detection += 1
                trial_result["artifacts_accepted_before_detection"] = self.artifacts_before_detection
                trial_result["detection_latency"] = None
                trial_result["blocked_by"] = "none"
                print("[RESULT] Attack succeeded - key still valid")
                print(f"[RESULT] Total malicious artifacts accepted (will expire): {self.artifacts_before_detection}")
                
                # Check if monitor would have detected it (second layer of defense)
                detection_time = self.get_detection_time(upload_time)
                if detection_time:
                    monitor_latency = detection_time - upload_time
                    trial_result["monitor_would_have_detected"] = True
                    print(f"[RESULT] Monitor WOULD have detected after {monitor_latency:.1f}s (but key expires first)")
                else:
                    trial_result["monitor_would_have_detected"] = False
                    print("[RESULT] Monitor did not detect in window")
            else:
                # Key expired - primary defense successful
                trial_result["detection_latency"] = 0
                trial_result["blocked_by"] = "key_expiration"
                trial_result["artifacts_accepted_before_detection"] = self.artifacts_before_detection
                trial_result["monitor_would_have_detected"] = False
                print("[RESULT] Attack blocked by key expiration (PRIMARY DEFENSE)")
                print(f"[RESULT] Artifacts accepted during this TTL window: {self.artifacts_before_detection}")
                # Reset counter for next TTL window
                self.artifacts_before_detection = 0
        
        self.results.append(trial_result)
        return trial_result

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Sigstore ephemeral key experiment with dual detection layers")
    parser.add_argument("--trials", "-t", type=int, default=3)
    parser.add_argument("--config", "-c", choices=["baseline", "defense", "both"], default="both")
    args = parser.parse_args()
    
    configs = ["baseline", "defense"] if args.config == "both" else [args.config]
    
    for config_type in configs:
        print(f"\n{'='*60}")
        print(f"Running {config_type.upper()} configuration")
        print('='*60)
        
        config = ExperimentConfig(config_type)
        runner = TrialRunner(config)
        runner.setup_trial_environment()
        
        # Determine theft delays based on config
        if config_type == "defense":
            theft_delays = [0, 300, 700]  # 0s, 5min (within TTL), 11min (expired)
        else:
            theft_delays = [0]  # Baseline always accepts (no expiration)
        
        trial_id = 1
        for delay in theft_delays:
            for _ in range(args.trials):
                runner.run_stolen_key_trial(trial_id, theft_delay=delay)
                trial_id += 1
        
        # Save results
        if runner.results:
            fieldnames = list(runner.results[0].keys())
            with open(f"experiment_results_{config_type}.csv", 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(runner.results)
            
            print(f"\n[RESULTS] Saved to experiment_results_{config_type}.csv")
            
            # Print summary statistics
            print(f"\n[SUMMARY] {config_type.upper()}:")
            accepted = sum(1 for r in runner.results if r["registry_response"] == "ACCEPTED")
            rejected = sum(1 for r in runner.results if r["registry_response"] == "REJECTED")
            total_artifacts_accepted = sum(r.get("artifacts_accepted_before_detection", 0) for r in runner.results if r["registry_response"] == "ACCEPTED")
            
            print(f"  Total trials: {len(runner.results)}")
            print(f"  Accepted: {accepted}")
            print(f"  Rejected: {rejected}")
            print(f"  Total malicious artifacts accepted: {total_artifacts_accepted}")
            
            if config_type == "defense":
                monitor_detections = sum(1 for r in runner.results if r.get("monitor_would_have_detected", False))
                print(f"  Artifacts that would have been caught by monitor: {monitor_detections}")
                print(f"  Defense layers: Primary (key expiration) + Secondary (transparency log monitor)")
    
    print("\n" + "="*60)
    print("Experiment Complete")
    print("="*60)

if __name__ == "__main__":
    main()
