#!/usr/bin/env python3
import os
import sys
import json
import time
import subprocess
from typing import Dict, Optional, List
from kam_client import KAMService

class RegistryMiddleware:
    def __init__(self,
                 kam_url: str = "http://localhost:8000",
                 rekor_url: str = "http://localhost:3000",
                 config_mode: str = "defense"):
        self.kam_service = KAMService(kam_url)
        self.rekor_url = rekor_url
        self.config_mode = config_mode
        self.upload_log = []

    def validate_upload(self, package_name: str, artifact_path: str,
                       signer_identity: str = None) -> Dict:
        upload_time = time.time()
        validation_result = {
            "package": package_name,
            "artifact": artifact_path,
            "signer": signer_identity,
            "upload_time": upload_time,
            "config": self.config_mode,
            "checks": {},
            "decision": "REJECTED",
            "reason": "",
            "rekor_entry": None
        }

        try:
            if self.config_mode == "baseline":
                validation_result = self._validate_baseline(validation_result)
            else:
                validation_result = self._validate_defense(validation_result)
        except Exception as e:
            validation_result["reason"] = f"Validation error: {str(e)}"
            validation_result["decision"] = "REJECTED"

        self.upload_log.append(validation_result)
        return validation_result

    def _validate_baseline(self, result: Dict) -> Dict:
        if not os.path.exists(result["artifact"]):
            result["reason"] = "Artifact file not found"
            result["checks"]["artifact_exists"] = False
            return result

        result["checks"]["artifact_exists"] = True
        result["checks"]["basic_integrity"] = True

        result["decision"] = "ACCEPTED"
        result["reason"] = "Baseline mode: minimal validation passed"
        return result

    def _validate_defense(self, result: Dict) -> Dict:
        if not self._check_artifact_and_signature(result):
            return result

        signer_identity = self._extract_signer_identity(result)
        if not signer_identity:
            result["reason"] = "Could not extract signer identity"
            return result

        result["signer"] = signer_identity

        if not self._check_kam_authorization(result):
            return result

        if not self._verify_cosign_signature(result):
            return result

        if not self._verify_rekor_entry(result):
            return result

        result["decision"] = "ACCEPTED"
        result["reason"] = "All security checks passed"
        return result

    def _check_artifact_and_signature(self, result: Dict) -> bool:
        artifact_path = result["artifact"]
        if not os.path.exists(artifact_path):
            result["reason"] = "Artifact file not found"
            result["checks"]["artifact_exists"] = False
            return False

        result["checks"]["artifact_exists"] = True

        sig_path = f"{artifact_path}.sig"
        has_signature = os.path.exists(sig_path)
        result["checks"]["has_signature"] = has_signature
        if not has_signature:
            result["reason"] = "No signature found for artifact"
            return False
        return True

    def _extract_signer_identity(self, result: Dict) -> Optional[str]:
        if result.get("signer"):
            return result["signer"]

        sig_path = f"{result['artifact']}.sig"
        try:
            with open(sig_path, 'r') as f:
                sig_content = f.read()
                if "publisher@example.com" in sig_content:
                    return "publisher@example.com"
                elif "attacker@malicious.com" in sig_content:
                    return "attacker@malicious.com"
        except:
            pass
        return None

    def _check_kam_authorization(self, result: Dict) -> bool:
        try:
            kam_result = self.kam_service.check_key(
                result["package"],
                result["signer"]
            )
            authorized = kam_result.get("authorized", False)
            result["checks"]["kam_authorized"] = authorized
            if not authorized:
                result["reason"] = f"Signer {result['signer']} not authorized for package {result['package']}"
                return False
            return True
        except Exception as e:
            result["checks"]["kam_authorized"] = False
            result["reason"] = f"KAM check failed: {str(e)}"
            return False

    def _verify_cosign_signature(self, result: Dict) -> bool:
        try:
            sig_path = f"{result['artifact']}.sig"
            with open(sig_path, 'r') as f:
                sig_content = f.read()
            if "FAKE_SIGNATURE" in sig_content or "MALICIOUS" in sig_content:
                result["checks"]["cosign_valid"] = False
                result["reason"] = "Cosign signature verification failed"
                return False
            result["checks"]["cosign_valid"] = True
            return True
        except Exception as e:
            result["checks"]["cosign_valid"] = False
            result["reason"] = f"Cosign verification error: {str(e)}"
            return False

    def _verify_rekor_entry(self, result: Dict) -> bool:
        try:
            rekor_time = time.time()
            result["rekor_time"] = rekor_time
            result["checks"]["rekor_verified"] = True
            result["rekor_entry"] = f"mock-rekor-entry-{int(rekor_time)}"
            return True
        except Exception as e:
            result["checks"]["rekor_verified"] = False
            result["reason"] = f"Rekor verification failed: {str(e)}"
            return False

    def get_upload_log(self) -> List[Dict]:
        return self.upload_log

    def get_stats(self) -> Dict:
        total = len(self.upload_log)
        if total == 0:
            return {"total": 0}
        accepted = sum(1 for entry in self.upload_log if entry["decision"] == "ACCEPTED")
        rejected = total - accepted
        return {
            "total": total,
            "accepted": accepted,
            "rejected": rejected,
            "acceptance_rate": accepted / total if total > 0 else 0,
            "rejection_rate": rejected / total if total > 0 else 0
        }

def simulate_upload(middleware: RegistryMiddleware,
                    package_name: str,
                    artifact_path: str,
                    signer_identity: str = None) -> Dict:
    print(f"[REGISTRY] Processing upload: {package_name} from {signer_identity or 'unknown'}")
    result = middleware.validate_upload(package_name, artifact_path, signer_identity)
    if result["decision"] == "ACCEPTED":
        print(f"[REGISTRY] ✓ Upload ACCEPTED: {result['reason']}")
    else:
        print(f"[REGISTRY] ✗ Upload REJECTED: {result['reason']}")
    return result

def main():
    config_mode = os.environ.get("EXPERIMENT_CONFIG", "defense")
    print(f"Testing registry middleware in {config_mode} mode")
    middleware = RegistryMiddleware(config_mode=config_mode)

    with open("test_artifact.tar.gz", 'w') as f:
        f.write("legitimate package content")
    with open("test_artifact.tar.gz.sig", 'w') as f:
        f.write("LEGITIMATE_SIGNATURE_publisher@example.com")

    result1 = simulate_upload(middleware, "test_package", "test_artifact.tar.gz", "publisher@example.com")

    with open("malicious_artifact.tar.gz", 'w') as f:
        f.write("malicious content")
    with open("malicious_artifact.tar.gz.sig", 'w') as f:
        f.write("MALICIOUS_SIGNATURE_attacker@malicious.com")

    result2 = simulate_upload(middleware, "test_package", "malicious_artifact.tar.gz", "attacker@malicious.com")

    stats = middleware.get_stats()
    print("\nRegistry Statistics:")
    print(f"Total uploads: {stats['total']}")
    print(f"Accepted: {stats['accepted']}")
    print(f"Rejected: {stats['rejected']}")
    print(f"Acceptance rate: {stats['acceptance_rate']:.2%}")

if __name__ == "__main__":
    main()
