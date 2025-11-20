
#!/usr/bin/env python3

"""
Client-Side Package Verifier - FIXED VERSION
Implements both baseline and Sigstore defense verification modes
FIXED: Uses PolicyEngine for identity-package authorization checks
"""

import os
import time
import hashlib
from typing import Dict, Tuple
from rekor_transparency_log import RekorTransparencyLog, compute_artifact_hash
from policy_engine import PolicyEngine

class PackageVerifier:
    """Verify package authenticity using baseline or Sigstore defense mode"""

    def __init__(self, rekor_log: RekorTransparencyLog, config_mode: str = "defense"):
        self.rekor = rekor_log
        self.config_mode = config_mode
        self.verification_steps = []
        # FIXED: Initialize PolicyEngine for identity-package authorization
        self.policy_engine = PolicyEngine("package_policies.json")

    def verify_signature_cryptographically(self, package_file: str, 
                                          signature_file: str) -> Tuple[bool, str]:
        """Verify cryptographic signature (simplified simulation)
        In real implementation, this would use cosign verify-blob
        """
        if not os.path.exists(signature_file):
            return False, "Signature file not found"

        # Read signature
        with open(signature_file, 'r') as f:
            sig_content = f.read()

        # Check if signature references this package
        if package_file in sig_content:
            return True, "Cryptographic signature valid"

        return False, "Signature does not match package"

    def extract_certificate_identity(self, signature_file: str) -> str:
        """Extract signer identity from certificate in signature"""
        with open(signature_file, 'r') as f:
            for line in f:
                if line.startswith("Signer:"):
                    return line.split(":", 1)[1].strip()
        return "unknown"

    def extract_cert_validity_period(self, signature_file: str) -> Tuple[float, float]:
        """Extract certificate validity period from signature"""
        cert_from = None
        cert_until = None

        with open(signature_file, 'r') as f:
            for line in f:
                if line.startswith("CertValidFrom:"):
                    cert_from = float(line.split(":", 1)[1].strip())
                elif line.startswith("CertValidUntil:"):
                    cert_until = float(line.split(":", 1)[1].strip())

        return cert_from, cert_until

    def extract_signing_time(self, signature_file: str) -> float:
        """Extract signing timestamp from signature"""
        with open(signature_file, 'r') as f:
            for line in f:
                if line.startswith("Signed:"):
                    return float(line.split(":", 1)[1].strip())
        return time.time()

    # ==================== BASELINE MODE ====================

    def verify_baseline(self, package_file: str, signature_file: str) -> Dict:
        """Baseline verification: Only cryptographic signature check
        No transparency log, no identity verification, no timestamp checks
        """
        print(f"\n[BASELINE] Verifying {package_file}")
        start_time = time.time()

        result = {
            "config": "baseline",
            "package": package_file,
            "verification_result": "FAILED",
            "signature_valid": False,
            "identity_verified": "N/A",
            "in_transparency_log": "N/A",
            "timestamp_valid": "N/A",
            "verification_latency_ms": 0,
            "failure_reason": "none"
        }

        # ONLY check: Cryptographic signature
        sig_valid, msg = self.verify_signature_cryptographically(package_file, signature_file)
        result["signature_valid"] = sig_valid

        if sig_valid:
            result["verification_result"] = "PASSED"
            print(f"[BASELINE] ✓ Signature valid - PASSED")
        else:
            result["verification_result"] = "FAILED"
            result["failure_reason"] = msg
            print(f"[BASELINE] ✗ Signature invalid - FAILED: {msg}")

        latency = (time.time() - start_time) * 1000
        result["verification_latency_ms"] = round(latency, 2)

        return result

    # ==================== DEFENSE MODE (SIGSTORE) ====================

    def verify_defense(self, package_file: str, signature_file: str,
                      expected_identity: str, package_name: str = None) -> Dict:
        """Defense verification with full Sigstore checks:
        1. Cryptographic signature
        2. Certificate identity matches expected publisher (using PolicyEngine)
        3. Package in transparency log
        4. Signing happened within certificate validity period
        5. No newer versions (rollback detection)
        6. Hash matches transparency log (mirror detection)
        """
        print(f"\n[DEFENSE] Verifying {package_file}")
        start_time = time.time()

        result = {
            "config": "defense",
            "package": package_file,
            "verification_result": "FAILED",
            "signature_valid": False,
            "identity_verified": False,
            "in_transparency_log": False,
            "timestamp_valid": False,
            "verification_latency_ms": 0,
            "failure_reason": "none"
        }

        # Step 1: Cryptographic signature verification
        print("[DEFENSE] Step 1: Verifying cryptographic signature...")
        sig_valid, msg = self.verify_signature_cryptographically(package_file, signature_file)
        result["signature_valid"] = sig_valid

        if not sig_valid:
            result["failure_reason"] = f"signature_invalid: {msg}"
            result["verification_latency_ms"] = round((time.time() - start_time) * 1000, 2)
            print(f"[DEFENSE] ✗ FAILED: {result['failure_reason']}")
            return result

        print("[DEFENSE] ✓ Signature cryptographically valid")

        # Step 2: Identity-Package Authorization Check (FIXED)
        print("[DEFENSE] Step 2: Verifying identity-package authorization...")
        cert_identity = self.extract_certificate_identity(signature_file)

        # FIXED: Use PolicyEngine to check authorization
        if package_name:
            # Extract base package name from filename if needed
            # e.g., "legitimate_pkg_v1_1.tar.gz" -> "legitimate_pkg"
            package_base = package_name.replace(".tar.gz", "").split("_v")[0]
            package_base = package_base.split("_")
            # Remove trial ID suffix if present (e.g., "_1", "_2")
            if package_base and package_base[-1].isdigit():
                package_base = "_".join(package_base[:-1])
            else:
                package_base = "_".join(package_base)

            # Use PolicyEngine for authorization check
            if not self.policy_engine.is_authorized(cert_identity, package_base):
                result["failure_reason"] = f"identity_not_authorized: {cert_identity} cannot publish {package_base}"
                result["verification_latency_ms"] = round((time.time() - start_time) * 1000, 2)
                print(f"[DEFENSE] ✗ FAILED: {result['failure_reason']}")
                return result

        # Check identity matches expected
        if cert_identity == expected_identity:
            result["identity_verified"] = True
            print(f"[DEFENSE] ✓ Identity verified and authorized: {cert_identity}")
        else:
            result["failure_reason"] = f"identity_mismatch: expected={expected_identity}, got={cert_identity}"
            result["verification_latency_ms"] = round((time.time() - start_time) * 1000, 2)
            print(f"[DEFENSE] ✗ FAILED: {result['failure_reason']}")
            return result

        # Step 3: Transparency log inclusion check
        print("[DEFENSE] Step 3: Checking transparency log inclusion...")
        artifact_hash = compute_artifact_hash(package_file)
        log_entry = self.rekor.query_by_hash(artifact_hash)

        if log_entry:
            result["in_transparency_log"] = True
            print(f"[DEFENSE] ✓ Package found in transparency log (index {log_entry['log_index']})")
        else:
            # Check if a DIFFERENT hash is logged (mirror attack)
            result["failure_reason"] = "not_in_transparency_log_or_hash_mismatch"
            result["verification_latency_ms"] = round((time.time() - start_time) * 1000, 2)
            print(f"[DEFENSE] ✗ FAILED: Package not in transparency log or hash mismatch")
            return result

        # Step 4: Timestamp validation (ephemeral cert check)
        print("[DEFENSE] Step 4: Validating signing timestamp...")
        cert_from, cert_until = self.extract_cert_validity_period(signature_file)
        signing_time = self.extract_signing_time(signature_file)
        current_time = time.time()

        # Check if signing happened within cert validity
        if cert_from <= signing_time <= cert_until:
            print(f"[DEFENSE] ✓ Signing time within certificate validity")

            # Check if cert has expired NOW
            if current_time > cert_until:
                # Cert expired, but signing was valid at the time
                time_since_signing = current_time - signing_time
                if time_since_signing < 3600:  # Signed less than 1 hour ago but cert expired
                    result["failure_reason"] = "certificate_expired_suspicious_timing"
                    result["verification_latency_ms"] = round((time.time() - start_time) * 1000, 2)
                    print(f"[DEFENSE] ✗ FAILED: Certificate expired, suspicious timing")
                    return result

            result["timestamp_valid"] = True
        else:
            result["failure_reason"] = "signing_time_outside_cert_validity"
            result["verification_latency_ms"] = round((time.time() - start_time) * 1000, 2)
            print(f"[DEFENSE] ✗ FAILED: Signing time outside certificate validity period")
            return result

        # Step 5: Rollback attack detection
        if package_name:
            print("[DEFENSE] Step 5: Checking for rollback attacks...")
            newer_versions = self.rekor.check_for_newer_versions(
                package_name.split("_")[0],  # Remove trial ID
                signing_time
            )

            if newer_versions:
                result["failure_reason"] = f"rollback_detected: {len(newer_versions)} newer versions exist"
                result["verification_latency_ms"] = round((time.time() - start_time) * 1000, 2)
                print(f"[DEFENSE] ✗ FAILED: Rollback attack detected ({len(newer_versions)} newer versions)")
                return result

            print("[DEFENSE] ✓ No rollback detected")

        # All checks passed!
        result["verification_result"] = "PASSED"
        result["verification_latency_ms"] = round((time.time() - start_time) * 1000, 2)
        print(f"[DEFENSE] ✓✓✓ ALL CHECKS PASSED - Safe to install")

        return result

    # ==================== Main verification dispatcher ====================

    def verify_package(self, package_file: str, signature_file: str,
                      expected_identity: str = None, package_name: str = None) -> Dict:
        """Main entry point for package verification"""
        if self.config_mode == "baseline":
            return self.verify_baseline(package_file, signature_file)
        else:  # defense
            if not expected_identity:
                expected_identity = "publisher@example.com"  # Default

            return self.verify_defense(package_file, signature_file,
                                      expected_identity, package_name)


if __name__ == "__main__":
    # Test verification
    from attack_scenario_generator import AttackScenarioGenerator

    rekor = RekorTransparencyLog("test_transparency_log.json")
    rekor.clear()

    generator = AttackScenarioGenerator(rekor)

    # Generate a compromised package
    attack = generator.scenario1_compromised_package(1)

    # Test baseline verification (should pass - only checks signature)
    print("\n" + "="*60)
    print("TESTING BASELINE MODE")
    print("="*60)
    verifier_baseline = PackageVerifier(rekor, config_mode="baseline")
    result_baseline = verifier_baseline.verify_package(
        attack["package"], attack["signature"]
    )
    print(f"\nResult: {result_baseline['verification_result']}")

    # Test defense verification
    print("\n" + "="*60)
    print("TESTING DEFENSE MODE")
    print("="*60)
    verifier_defense = PackageVerifier(rekor, config_mode="defense")
    result_defense = verifier_defense.verify_package(
        attack["package"], attack["signature"],
        expected_identity=attack["expected_identity"],
        package_name=attack["package"].replace(".tar.gz", "")
    )
    print(f"\nResult: {result_defense['verification_result']}")