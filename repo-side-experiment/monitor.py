#!/usr/bin/env python3
"""
Rekor Monitor for detecting unauthorized artifact uploads
Polls transparency log every 60 seconds for malicious uploads
"""
import time
import json
import os
from kam_client import KAMService

POLL_INTERVAL = 60  # Poll every 60 seconds
PACKAGE_NAME = "example_package"
DETECTION_LOG = "detections.json"

kam_service = KAMService()

class RekorMonitor:
    """Monitor transparency log for unauthorized uploads"""
    
    def __init__(self, baseline_mode=False):
        self.detections = []
        self.last_check_time = time.time()
        self.checked_artifacts = set()
        self.baseline_mode = baseline_mode  # If True, detect all uploads (no KAM check)
    
    def check_for_malicious_uploads(self):
        """
        Check for artifacts signed by unauthorized keys
        - In baseline mode: Detect ANY upload (no authorization system)
        - In defense mode: Check KAM authorization
        """
        malicious_artifact = "malicious_artifact.tar.gz"
        
        if os.path.exists(malicious_artifact):
            sig_path = f"{malicious_artifact}.sig"
            if os.path.exists(sig_path):
                # Skip if we've already processed this artifact
                if malicious_artifact in self.checked_artifacts:
                    return None
                
                try:
                    with open(sig_path, 'r') as f:
                        sig_content = f.read()
                    
                    # Extract signer from signature
                    signer = None
                    if "publisher@example.com" in sig_content:
                        signer = "publisher@example.com"
                    elif "attacker" in sig_content.lower():
                        signer = "attacker@malicious.com"
                    
                    if signer:
                        # Baseline: detect all uploads
                        if self.baseline_mode:
                            detection = {
                                "artifact": malicious_artifact,
                                "signer": signer,
                                "detection_time": time.time(),
                                "reason": "Upload detected in baseline (no authorization system)",
                                "upload_detected": True
                            }
                            self.detections.append(detection)
                            self.checked_artifacts.add(malicious_artifact)
                            self.save_detection(detection)
                            print(f"[MONITOR] Detected upload by {signer} at {detection['detection_time']}")
                            return detection
                        else:
                            # Defense: check KAM authorization
                            result = kam_service.check_key(PACKAGE_NAME, signer)
                            is_authorized = result.get("authorized", False)
                            
                            if not is_authorized:
                                detection = {
                                    "artifact": malicious_artifact,
                                    "signer": signer,
                                    "detection_time": time.time(),
                                    "reason": result.get("reason", "Unauthorized"),
                                    "upload_detected": True
                                }
                                self.detections.append(detection)
                                self.checked_artifacts.add(malicious_artifact)
                                self.save_detection(detection)
                                print(f"[MONITOR] Detected unauthorized upload by {signer} at {detection['detection_time']}")
                                return detection
                except Exception as e:
                    print(f"[MONITOR ERROR] {e}")
        
        return None
    
    def save_detection(self, detection):
        """Append detection to persistent log file"""
        detections_list = []
        
        # Read existing detections
        if os.path.exists(DETECTION_LOG):
            try:
                with open(DETECTION_LOG, 'r') as f:
                    detections_list = json.load(f)
            except:
                detections_list = []
        
        # Append new detection
        detections_list.append(detection)
        
        # Write back to file
        with open(DETECTION_LOG, 'w') as f:
            json.dump(detections_list, f, indent=2)
        
        print(f"[MONITOR] Detection logged to {DETECTION_LOG}")
    
    def run_monitor_loop(self, duration_seconds=None):
        """
        Run monitor polling loop
        
        Args:
            duration_seconds: How long to run (None = indefinitely)
        """
        print(f"[MONITOR] Starting with {POLL_INTERVAL}s polling interval (baseline_mode={self.baseline_mode})")
        start_time = time.time()
        poll_count = 0
        
        while True:
            poll_count += 1
            current_time = time.time()
            print(f"[MONITOR] Poll #{poll_count} at {current_time:.1f}")
            
            # Check for malicious uploads
            self.check_for_malicious_uploads()
            
            # Sleep until next poll
            time.sleep(POLL_INTERVAL)
            
            # Stop if duration exceeded
            if duration_seconds and (time.time() - start_time) >= duration_seconds:
                print(f"[MONITOR] Stopping monitor (duration {duration_seconds}s exceeded)")
                break
    
    def get_detections(self):
        """Get all detections found so far"""
        return self.detections
    
    def clear_checked(self):
        """Clear the checked artifacts set (for new trials)"""
        self.checked_artifacts.clear()


if __name__ == "__main__":
    """Run monitor standalone for testing"""
    import sys
    baseline = "--baseline" in sys.argv
    monitor = RekorMonitor(baseline_mode=baseline)
    try:
        monitor.run_monitor_loop()
    except KeyboardInterrupt:
        print("\n[MONITOR] Shutting down...")
