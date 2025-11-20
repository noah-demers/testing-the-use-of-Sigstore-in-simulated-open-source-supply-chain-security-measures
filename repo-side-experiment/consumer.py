#!/usr/bin/env python3
import subprocess
import sys
import os
import time
import argparse
from kam_client import KAMService

ARTIFACT_PATH = "artifact.tar.gz"
PACKAGE_NAME = "example_package"
EXPECTED_SIGNER = "publisher@example.com"

kam_service = KAMService()

def verify_cosign_signature(artifact_path: str) -> bool:
    try:
        env = os.environ.copy()
        env["COSIGN_PASSWORD"] = "testpassword"
        result = subprocess.run([
            "cosign", "verify-blob",
            "--key", "cosign.pub",
            "--signature", f"{artifact_path}.sig",
            artifact_path
        ], check=True, capture_output=True, text=True, timeout=30, env=env)
        print("[INFO] cosign verify-blob signature verification passed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] cosign verify-blob failed: {e}")
        return False
    except subprocess.TimeoutExpired:
        print("[ERROR] verify-blob timed out")
        return False

def verify_kam_authorization() -> bool:
    try:
        result = kam_service.check_key(PACKAGE_NAME, EXPECTED_SIGNER)
        if not result.get("authorized", False):
            print(f"[ERROR] Signer '{EXPECTED_SIGNER}' not authorized in KAM or expired")
            return False
        print("[INFO] KAM authorization verified")
        return True
    except Exception as e:
        print(f"[ERROR] KAM verification failed: {e}")
        return False

def verify_rekor_entry(artifact_path: str) -> bool:
    # Just checks signature file for demo
    sig_path = f"{artifact_path}.sig"
    if os.path.exists(sig_path):
        print("[INFO] Rekor entry verification passed (simulated)")
        return True
    print("[ERROR] No Rekor entry found")
    return False

def verify_baseline_mode(artifact_path: str) -> bool:
    print("[INFO] Verifying in baseline mode with cosign verify-blob...")
    return verify_cosign_signature(artifact_path)

def verify_defense_mode(artifact_path: str) -> bool:
    print("[INFO] Verifying in defense mode...")
    if not verify_kam_authorization():
        return False
    if not verify_cosign_signature(artifact_path):
        return False
    if not verify_rekor_entry(artifact_path):
        return False
    print("[INFO] All defense mode verifications passed")
    return True

def verify_artifact(artifact_path: str, config_mode: str) -> bool:
    if not os.path.exists(artifact_path):
        print(f"[ERROR] Artifact not found: {artifact_path}")
        return False
    print(f"[INFO] Verifying artifact: {artifact_path}")
    print(f"[INFO] Configuration mode: {config_mode}")
    verification_start = time.time()
    if config_mode == "baseline":
        result = verify_baseline_mode(artifact_path)
    else:
        result = verify_defense_mode(artifact_path)
    verification_end = time.time()
    print(f"[INFO] Verification completed in {verification_end - verification_start:.3f} seconds")
    if result:
        print("[SUCCESS] ✓ Artifact verification PASSED - Safe to use")
    else:
        print("[FAILURE] ✗ Artifact verification FAILED - Do not use")
    return result

def create_test_artifact():
    with open(ARTIFACT_PATH, 'w') as f:
        f.write(f"Test artifact content - {time.time()}")
    print(f"[INFO] Created test artifact: {ARTIFACT_PATH}")

def main():
    parser = argparse.ArgumentParser(description="Package consumer with Sigstore verification")
    parser.add_argument("--config", choices=["baseline", "defense"],
                       default="defense", help="Verification mode")
    parser.add_argument("--artifact", default=ARTIFACT_PATH,
                       help="Path to artifact to verify")
    parser.add_argument("--create-test", action="store_true",
                       help="Create test artifact for verification")
    args = parser.parse_args()
    os.environ["EXPERIMENT_CONFIG"] = args.config
    if args.create_test:
        create_test_artifact()
    success = verify_artifact(args.artifact, args.config)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
