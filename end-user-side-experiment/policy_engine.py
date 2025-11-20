#!/usr/bin/env python3
"""
Policy Engine for Identity-to-Package Authorization
Simulates production policy management (like PyPI + GitHub OIDC)
"""

import json
import os

class PolicyEngine:
    """
    Manages identity-to-package authorization policies
    Similar to how PyPI manages which GitHub accounts can publish which packages
    """

    def __init__(self, policy_file="package_policies.json"):
        self.policy_file = policy_file
        self.policies = {}
        self.load_policies()

    def load_policies(self):
        """Load policies from file"""
        if os.path.exists(self.policy_file):
            with open(self.policy_file, 'r') as f:
                self.policies = json.load(f)
        else:
            # Initialize with default policies
            self.policies = self._create_default_policies()
            self.save_policies()

    def _create_default_policies(self):
        """
        Create default policies matching production scenarios
        Maps OIDC identities to packages they can publish
        """
        return {
            # Legitimate publisher (like a verified PyPI maintainer)
            "publisher@example.com": {
                "authorized_packages": [
                    "legitimate_pkg",  # Can publish legitimate packages
                    "example_package",
                    "mypackage"
                ],
                "description": "Verified example.com maintainer"
            },

            # Real-world example: requests library maintainer
            "requests-maintainer@python.org": {
                "authorized_packages": [
                    "requests"  # Only authorized for actual requests package
                ],
                "description": "Official requests library maintainer"
            },

            # Package-specific maintainers
            "mirror-maintainer@cdn.org": {
                "authorized_packages": [
                    "mirror_pkg"  # Can publish mirror packages
                ],
                "description": "CDN mirror package maintainer"
            },

            # Attacker identities (NOT authorized for anything legitimate)
            "attacker@malicious.com": {
                "authorized_packages": [],
                "description": "Unauthorized attacker account"
            }
        }

    def save_policies(self):
        """Save policies to file"""
        with open(self.policy_file, 'w') as f:
            json.dump(self.policies, f, indent=2)

    def is_authorized(self, identity: str, package_name: str) -> bool:
        """
        Check if identity is authorized to publish package

        Args:
            identity: Signer identity from certificate (e.g., "publisher@example.com")
            package_name: Package name being verified (e.g., "legitimate_pkg_1.tar.gz")

        Returns:
            True if authorized, False otherwise
        """
        # Extract base package name (remove version/trial ID suffixes)
        base_package = self._extract_base_package_name(package_name)

        # Check if identity exists in policies
        if identity not in self.policies:
            print(f"[POLICY] Identity '{identity}' not found in policies")
            return False

        # Check if package is in authorized list
        authorized = base_package in self.policies[identity]["authorized_packages"]

        if authorized:
            print(f"[POLICY] ✓ '{identity}' authorized for '{base_package}'")
        else:
            print(f"[POLICY] ✗ '{identity}' NOT authorized for '{base_package}'")
            if self.policies[identity]["authorized_packages"]:
                print(f"[POLICY]   Authorized for: {self.policies[identity]['authorized_packages']}")
            else:
                print(f"[POLICY]   Not authorized for ANY packages")

        return authorized

    def _extract_base_package_name(self, package_name: str) -> str:
        """
        Extract base package name from full package filename

        Examples:
            "legitimate_pkg_1.tar.gz" -> "legitimate_pkg"
            "compromised_pkg_5.tar.gz" -> "compromised_pkg"
            "reqeusts_3.tar.gz" -> "reqeusts"
            "mypackage_v1_2.tar.gz" -> "mypackage"
        """
        # Remove file extension
        name = package_name.replace(".tar.gz", "")

        # Remove trial ID suffix (e.g., "_1", "_2")
        # But keep the base name
        parts = name.split("_")

        # Handle different naming patterns
        if len(parts) >= 2 and parts[-1].isdigit():
            # "legitimate_pkg_1" -> "legitimate_pkg"
            base = "_".join(parts[:-1])
        elif len(parts) >= 3 and parts[-2].startswith("v") and parts[-1].isdigit():
            # "mypackage_v1_2" -> "mypackage"
            base = parts[0]
        else:
            # Keep as-is
            base = name

        return base

    def add_policy(self, identity: str, authorized_packages: list, description: str = ""):
        """Add or update a policy"""
        self.policies[identity] = {
            "authorized_packages": authorized_packages,
            "description": description
        }
        self.save_policies()
        print(f"[POLICY] Added policy for '{identity}'")

    def list_policies(self):
        """Print all policies"""
        print("\n" + "="*70)
        print("PACKAGE AUTHORIZATION POLICIES")
        print("="*70)
        for identity, policy in self.policies.items():
            print(f"\n{identity}:")
            print(f"  Description: {policy['description']}")
            print(f"  Authorized packages: {policy['authorized_packages']}")

if __name__ == "__main__":
    # Test policy engine
    engine = PolicyEngine("test_policies.json")

    print("Testing policy checks:")

    # Should pass
    print("\n1. Legitimate package by authorized publisher:")
    engine.is_authorized("publisher@example.com", "legitimate_pkg_1.tar.gz")

    # Should fail - typosquatting
    print("\n2. Typosquatting attempt:")
    engine.is_authorized("requests-maintainer@python.org", "reqeusts_1.tar.gz")

    # Should fail - compromised package
    print("\n3. Compromised package by publisher:")
    engine.is_authorized("publisher@example.com", "compromised_pkg_1.tar.gz")

    # Should fail - attacker
    print("\n4. Attacker trying to publish requests:")
    engine.is_authorized("attacker@malicious.com", "requests_1.tar.gz")

    # List all policies
    engine.list_policies()
