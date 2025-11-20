#!/usr/bin/env python3
import subprocess
import sys
import os
import time
import argparse
from kam_client import KAMService

ARTIFACT_PATH = "artifact.tar.gz"
PACKAGE_NAME = "example_package"
SIGNER_IDENTITY = "publisher@example.com"
PRIVATE_KEY_PATH = "cosign.key"
PUBLIC_KEY_PATH = "cosign.pub"

kam_service = KAMService()

def create_test_artifact():
    content = f"Test package content - {time.time()}"
    with open(ARTIFACT_PATH, 'w') as f:
        f.write(content)
    print(f"[INFO] Created test artifact: {ARTIFACT_PATH}")

def check_kam_authorization():
    config_mode = os.environ.get("EXPERIMENT_CONFIG", "defense")
    if config_mode == "baseline":
        print("[INFO] Baseline mode - skipping KAM check")
        return True
    try:
        result = kam_service.check_key(PACKAGE_NAME, SIGNER_IDENTITY)
        if not result["authorized"]:
            print(f"[ERROR] Signer '{SIGNER_IDENTITY}' not authorized in KAM or expired")
            return False
        print("[INFO] KAM authorization check passed")
        return True
    except Exception as e:
        print(f"[ERROR] KAM check failed: {e}")
        return False

def generate_cosign_key():
    if not (os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
        print("[INFO] Generating cosign key pair...")
        env = os.environ.copy()
        env["COSIGN_PASSWORD"] = "testpassword"
        subprocess.run([
            "cosign", "generate-key-pair"
        ], env=env, check=True)

def sign_baseline():
    print("[INFO] Signing artifact with cosign sign-blob/local key (baseline mode)")
    generate_cosign_key()
    try:
        env = os.environ.copy()
        env["COSIGN_PASSWORD"] = "testpassword"
        # Pipe in "y\n" to automatically accept Sigstore terms prompt
        result = subprocess.run([
            "cosign", "sign-blob",
            "--key", PRIVATE_KEY_PATH,
            "--output-signature", f"{ARTIFACT_PATH}.sig",
            ARTIFACT_PATH
        ],
        input="y\n",
        check=True,
        env=env,
        capture_output=True,
        text=True,
        timeout=30)
        print(f"[DEBUG] sign-blob stdout: {result.stdout}")
        print(f"[DEBUG] sign-blob stderr: {result.stderr}")
        print("[INFO] Artifact signed with sign-blob and local key")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Baseline sign-blob signing failed: {e}")
        return False
    except subprocess.TimeoutExpired:
        print("[ERROR] sign-blob timed out")
        return False

def sign_defense():
    print("[INFO] (Simulated) Signing for defense mode. Using sign-blob for test automation.")
    return sign_baseline()

def upload_to_registry():
    print("[INFO] Uploading to registry... (simulated)")
    return True

def main():
    parser = argparse.ArgumentParser(description="Package publisher with Sigstore support")
    parser.add_argument("--config", choices=["baseline", "defense"],
                       default="defense", help="Configuration mode")
    args = parser.parse_args()
    os.environ["EXPERIMENT_CONFIG"] = args.config
    print(f"[INFO] Running in {args.config} mode")
    # Clean up old files for repeatability
    for f in [ARTIFACT_PATH, f"{ARTIFACT_PATH}.sig"]:
        if os.path.exists(f): os.remove(f)
    create_test_artifact()
    if not check_kam_authorization():
        print("[ERROR] Authorization check failed")
        sys.exit(1)
    if args.config == "baseline":
        if not sign_baseline():
            print("[ERROR] Baseline signing failed")
            sys.exit(1)
    else:
        if not sign_defense():
            print("[ERROR] Defense signing failed")
            sys.exit(1)
    if not upload_to_registry():
        print("[ERROR] Upload failed")
        sys.exit(1)
    print("[SUCCESS] Publishing workflow completed successfully")

if __name__ == "__main__":
    main()
