
#!/usr/bin/env python3
"""
Attack Scenario Generator for End-User Experiment (FINAL FIX)
Uses correct base package names that match policy engine mappings
"""

import os
import time
import hashlib
from rekor_transparency_log import RekorTransparencyLog

class AttackScenarioGenerator:
    """Generate attack scenarios for end-user verification testing"""

    def __init__(self, rekor: RekorTransparencyLog):
        self.rekor = rekor
        self.base_time = time.time()

    def _create_package_file(self, filename: str, content: str = "malicious code"):
        """Create a simulated package file"""
        with open(filename, 'w') as f:
            f.write(f"Package: {filename}\n")
            f.write(f"Content: {content}\n")
            f.write(f"Timestamp: {time.time()}\n")

    def _create_signature(self, package_file: str, signer_identity: str, 
                         cert_valid_from: float = None, cert_valid_until: float = None,
                         signing_time: float = None) -> str:
        """Create a simulated signature file"""
        if cert_valid_from is None:
            cert_valid_from = self.base_time
        if cert_valid_until is None:
            cert_valid_until = self.base_time + 600  # 10 minutes
        if signing_time is None:
            signing_time = self.base_time + 1

        # Compute hash
        with open(package_file, 'rb') as f:
            package_hash = hashlib.sha256(f.read()).hexdigest()

        sig_file = package_file + ".sig"
        with open(sig_file, 'w') as f:
            f.write(f"SignedPackage: {package_file}\n")
            f.write(f"Signer: {signer_identity}\n")
            f.write(f"PackageHash: {package_hash}\n")
            f.write(f"CertValidFrom: {cert_valid_from}\n")
            f.write(f"CertValidUntil: {cert_valid_until}\n")
            f.write(f"Signed: {signing_time}\n")

        return sig_file

    # ==================== SCENARIO 1: Compromised Package ====================
    def scenario1_compromised_package(self, trial_id: int):
        """
        Attacker steals key and signs malicious package with compromised identity
        Uses "attacker@malicious.com" which has NO authorization
        """
        # FIXED: Use base name "compromised" not "compromised_pkg_N"
        package = f"compromised_{trial_id}.tar.gz"
        package_name = "compromised"  # Base name for policy check

        # Create malicious package
        self._create_package_file(package, "malicious payload")

        # Sign with UNAUTHORIZED attacker identity
        signer = "attacker@malicious.com"
        cert_valid_from = self.base_time
        cert_valid_until = self.base_time + 600
        signing_time = self.base_time + 5

        sig_file = self._create_signature(
            package, signer, cert_valid_from, cert_valid_until, signing_time
        )

        # Log to Rekor
        with open(package, 'rb') as f:
            artifact_hash = hashlib.sha256(f.read()).hexdigest()

        self.rekor.add_entry(
            package_name=package_name,
            artifact_hash=artifact_hash,
            signer_identity=signer,
            signing_time=signing_time,
            cert_valid_from=cert_valid_from,
            cert_valid_until=cert_valid_until
        )

        return {
            "package": package,
            "signature": sig_file,
            "is_malicious": True,
            "attack_type": "stolen_key_within_ttl",
            "signer_identity": signer,
            "expected_identity": signer,
            "package_name": package_name
        }

    # ==================== SCENARIO 2: Backdated Package ====================
    def scenario2_backdated_package(self, trial_id: int):
        """
        Rollback attack: old version with expired cert
        Uses authorized publisher@example.com for mypackage
        """
        # FIXED: Use base name "mypackage" not "mypackage_v1_N"
        package = f"mypackage_v1_{trial_id}.tar.gz"
        package_name = "mypackage"  # Base name for policy check

        # Create old version package
        self._create_package_file(package, f"old version {trial_id}")

        # Use AUTHORIZED identity for mypackage
        signer = "publisher@example.com"

        # But certificate is expired
        cert_valid_from = self.base_time - 1000
        cert_valid_until = self.base_time - 400  # Expired
        signing_time = self.base_time - 500

        sig_file = self._create_signature(
            package, signer, cert_valid_from, cert_valid_until, signing_time
        )

        # Log to Rekor
        with open(package, 'rb') as f:
            artifact_hash = hashlib.sha256(f.read()).hexdigest()

        self.rekor.add_entry(
            package_name=package_name,
            artifact_hash=artifact_hash,
            signer_identity=signer,
            signing_time=signing_time,
            cert_valid_from=cert_valid_from,
            cert_valid_until=cert_valid_until
        )

        return {
            "package": package,
            "signature": sig_file,
            "is_malicious": True,
            "attack_type": "rollback_attack",
            "signer_identity": signer,
            "expected_identity": signer,
            "package_name": package_name
        }

    # ==================== SCENARIO 3: Malicious Mirror ====================
    def scenario3_malicious_mirror(self, trial_id: int):
        """
        Mirror substitution: package hash doesn't match transparency log
        Uses attacker identity (not authorized)
        """
        # FIXED: Use base name "mirror" not "mirror_pkg_malicious_N"
        package = f"mirror_{trial_id}.tar.gz"
        package_name = "mirror"  # Base name for policy check

        # Create package
        self._create_package_file(package, "malicious mirror content")

        # Use UNAUTHORIZED attacker identity
        signer = "attacker@malicious.com"
        cert_valid_from = self.base_time
        cert_valid_until = self.base_time + 600
        signing_time = self.base_time + 5

        sig_file = self._create_signature(
            package, signer, cert_valid_from, cert_valid_until, signing_time
        )

        # Log DIFFERENT hash to Rekor (simulate mirror attack)
        fake_hash = "0" * 64  # Fake hash that won't match actual package

        self.rekor.add_entry(
            package_name=package_name,
            artifact_hash=fake_hash,  # Mismatch!
            signer_identity=signer,
            signing_time=signing_time,
            cert_valid_from=cert_valid_from,
            cert_valid_until=cert_valid_until
        )

        return {
            "package": package,
            "signature": sig_file,
            "is_malicious": True,
            "attack_type": "mirror_substitution",
            "signer_identity": signer,
            "expected_identity": signer,
            "package_name": package_name
        }

    # ==================== SCENARIO 4: Typosquatting ====================
    def scenario4_typosquatting(self, trial_id: int):
        """
        Typosquatting: similar package name but wrong identity
        Uses legitimate requests maintainer identity but wrong package name
        """
        # FIXED: Typo package name stays as typo
        package = f"reqeusts_{trial_id}.tar.gz"
        package_name = "reqeusts"  # Typo - not authorized

        # Create typosquatted package
        self._create_package_file(package, "typosquatting malware")

        # Attacker stole the REAL requests maintainer credentials
        signer = "requests-maintainer@python.org"
        cert_valid_from = self.base_time
        cert_valid_until = self.base_time + 600
        signing_time = self.base_time + 5

        sig_file = self._create_signature(
            package, signer, cert_valid_from, cert_valid_until, signing_time
        )

        # Log to Rekor
        with open(package, 'rb') as f:
            artifact_hash = hashlib.sha256(f.read()).hexdigest()

        self.rekor.add_entry(
            package_name=package_name,
            artifact_hash=artifact_hash,
            signer_identity=signer,
            signing_time=signing_time,
            cert_valid_from=cert_valid_from,
            cert_valid_until=cert_valid_until
        )

        return {
            "package": package,
            "signature": sig_file,
            "is_malicious": True,
            "attack_type": "typosquatting_with_stolen_key",
            "signer_identity": signer,
            "expected_identity": signer,
            "package_name": package_name
        }

    # ==================== LEGITIMATE PACKAGE ====================
    def create_legitimate_package(self, trial_id: int):
        """
        Create a legitimate package with correct identity-package binding
        Uses publisher@example.com authorized for legitimate_pkg
        """
        # FIXED: Use base name "legitimate_pkg" not "legitimate_pkg_N"
        package = f"legitimate_pkg_v1_{trial_id}.tar.gz"
        package_name = "legitimate_pkg"  # Base name matches policy!

        # Create legitimate package
        self._create_package_file(package, "legitimate library code")

        # Use AUTHORIZED identity for legitimate_pkg
        signer = "publisher@example.com"
        cert_valid_from = self.base_time
        cert_valid_until = self.base_time + 600
        signing_time = self.base_time + 5

        sig_file = self._create_signature(
            package, signer, cert_valid_from, cert_valid_until, signing_time
        )

        # Log to Rekor
        with open(package, 'rb') as f:
            artifact_hash = hashlib.sha256(f.read()).hexdigest()

        self.rekor.add_entry(
            package_name=package_name,
            artifact_hash=artifact_hash,
            signer_identity=signer,
            signing_time=signing_time,
            cert_valid_from=cert_valid_from,
            cert_valid_until=cert_valid_until
        )

        return {
            "package": package,
            "signature": sig_file,
            "is_malicious": False,
            "attack_type": "none",
            "signer_identity": signer,
            "expected_identity": signer,
            "package_name": package_name
        }

if __name__ == "__main__":
    # Test
    from rekor_transparency_log import RekorTransparencyLog

    rekor = RekorTransparencyLog("test_log.json")
    rekor.clear()

    generator = AttackScenarioGenerator(rekor)

    print("Testing scenario generation...")

    # Test legitimate (should pass with policy)
    legit = generator.create_legitimate_package(1)
    print(f"\nLegitimate: {legit['package']}, Base name: {legit['package_name']}")

    # Test compromised (should fail - attacker not authorized)
    comp = generator.scenario1_compromised_package(1)
    print(f"Compromised: {comp['package']}, Base name: {comp['package_name']}")

    # Test typosquatting (should fail - identity mismatch)
    typo = generator.scenario4_typosquatting(1)
    print(f"Typosquatting: {typo['package']}, Base name: {typo['package_name']}")

    print("\nScenario generation working correctly!")