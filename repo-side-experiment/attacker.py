#!/usr/bin/env python3
import time
import os
from kam_client import KAMService

ARTIFACT_PATH = "malicious_artifact.tar.gz"
PACKAGE_NAME = "example_package"

kam_service = KAMService()

class StolenKeyAttack:
    def __init__(self, stolen_identity="publisher@example.com", theft_delay=0):
        self.scenario_name = "Stolen Legitimate Key Attack"
        self.stolen_identity = stolen_identity
        self.theft_delay = theft_delay  # Simulates time between key issue and theft
        self.start_time = None
        self.end_time = None
        self.success = False
    
    def execute(self):
        self.start_time = time.time()
        try:
            self._create_malicious_artifact()
            self._sign_with_stolen_key()
            
            # Simulate theft delay
            if self.theft_delay > 0:
                print(f"[ATTACK] Waiting {self.theft_delay}s (simulating time until key theft/use)")
                time.sleep(self.theft_delay)
            
            self._attempt_upload()
            self.success = True
        except Exception as e:
            print(f"[ATTACK] FAILED: {e}")
            self.success = False
        
        self.end_time = time.time()
        return {"success": self.success}
    
    def _create_malicious_artifact(self):
        with open(ARTIFACT_PATH, 'wb') as f:
            f.write(b"MALICIOUS PAYLOAD - Stolen key attack")
        print(f"[ATTACK] Created malicious artifact: {ARTIFACT_PATH}")
    
    def _sign_with_stolen_key(self):
        with open(f"{ARTIFACT_PATH}.sig", 'w') as f:
            f.write(f"FAKE_SIGNATURE_{self.stolen_identity}")
        print("[ATTACK] Simulated signing with stolen key")
    
    def _attempt_upload(self):
        config_mode = os.environ.get("EXPERIMENT_CONFIG", "defense")
        
        if config_mode == "defense":
            # Check if key is still valid (not expired)
            result = kam_service.check_key(PACKAGE_NAME, self.stolen_identity)
            if not result.get("authorized"):
                reason = result.get("reason", "Not authorized")
                print(f"[ATTACK] Upload blocked: {reason}")
                raise Exception(f"Upload blocked: {reason}")
        
        print("[ATTACK] Upload would be accepted by registry")


# Helper function for easy calling from other scripts
def run_attack_scenario(theft_delay=0):
    """
    Run a stolen key attack scenario
    
    Args:
        theft_delay: Seconds to wait after key generation before using it
                    (simulates time until attacker steals and uses key)
    
    Returns:
        dict with 'success' key indicating if attack succeeded
    """
    attack = StolenKeyAttack(theft_delay=theft_delay)
    return attack.execute()


# For standalone testing
if __name__ == "__main__":
    import sys
    delay = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    result = run_attack_scenario(theft_delay=delay)
    print(f"\n[FINAL] Attack {'succeeded' if result['success'] else 'failed'}")
    sys.exit(0 if result['success'] else 1)
