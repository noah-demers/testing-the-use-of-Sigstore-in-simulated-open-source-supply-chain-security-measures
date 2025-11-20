#!/usr/bin/env python3
"""
Mock Rekor Transparency Log
Stores signing events with timestamps and provides verification APIs
"""

import json
import time
import hashlib
from typing import Dict, List, Optional

class TransparencyLogEntry:
    """Single entry in the transparency log"""
    def __init__(self, package_name: str, artifact_hash: str, 
                 signer_identity: str, signing_time: float, 
                 cert_valid_from: float, cert_valid_until: float):
        self.package_name = package_name
        self.artifact_hash = artifact_hash
        self.signer_identity = signer_identity
        self.signing_time = signing_time
        self.cert_valid_from = cert_valid_from
        self.cert_valid_until = cert_valid_until
        self.log_index = None  # Set when added to log
        self.logged_at = time.time()

    def to_dict(self):
        return {
            "log_index": self.log_index,
            "package_name": self.package_name,
            "artifact_hash": self.artifact_hash,
            "signer_identity": self.signer_identity,
            "signing_time": self.signing_time,
            "cert_valid_from": self.cert_valid_from,
            "cert_valid_until": self.cert_valid_until,
            "logged_at": self.logged_at
        }

class RekorTransparencyLog:
    """Mock Rekor transparency log for experiment"""

    def __init__(self, log_file="transparency_log.json"):
        self.log_file = log_file
        self.entries: List[TransparencyLogEntry] = []
        self.next_index = 0
        self.load_log()

    def add_entry(self, package_name: str, artifact_hash: str,
                  signer_identity: str, signing_time: float,
                  cert_valid_from: float, cert_valid_until: float) -> int:
        """Add entry to transparency log, returns log index"""
        entry = TransparencyLogEntry(
            package_name, artifact_hash, signer_identity,
            signing_time, cert_valid_from, cert_valid_until
        )
        entry.log_index = self.next_index
        self.next_index += 1
        self.entries.append(entry)
        self.save_log()
        print(f"[REKOR] Added entry {entry.log_index} for {package_name} by {signer_identity}")
        return entry.log_index

    def query_by_hash(self, artifact_hash: str) -> Optional[Dict]:
        """Query log by artifact hash"""
        for entry in self.entries:
            if entry.artifact_hash == artifact_hash:
                return entry.to_dict()
        return None

    def query_by_identity(self, signer_identity: str) -> List[Dict]:
        """Query all entries by signer identity"""
        return [e.to_dict() for e in self.entries if e.signer_identity == signer_identity]

    def query_by_package(self, package_name: str) -> List[Dict]:
        """Query all entries for a package"""
        results = [e.to_dict() for e in self.entries if e.package_name == package_name]
        # Sort by signing time, newest first
        results.sort(key=lambda x: x['signing_time'], reverse=True)
        return results

    def verify_inclusion(self, artifact_hash: str) -> bool:
        """Verify artifact is in transparency log"""
        return self.query_by_hash(artifact_hash) is not None

    def verify_timestamp(self, artifact_hash: str, expected_time: float, 
                        tolerance_seconds: float = 300) -> bool:
        """Verify signing timestamp is reasonable"""
        entry = self.query_by_hash(artifact_hash)
        if not entry:
            return False
        time_diff = abs(entry['signing_time'] - expected_time)
        return time_diff <= tolerance_seconds

    def check_for_newer_versions(self, package_name: str, 
                                 signing_time: float) -> List[Dict]:
        """Check if newer versions exist (for rollback detection)"""
        all_versions = self.query_by_package(package_name)
        newer = [v for v in all_versions if v['signing_time'] > signing_time]
        return newer

    def save_log(self):
        """Persist log to disk"""
        data = [e.to_dict() for e in self.entries]
        with open(self.log_file, 'w') as f:
            json.dump({"entries": data, "next_index": self.next_index}, f, indent=2)

    def load_log(self):
        """Load log from disk"""
        try:
            with open(self.log_file, 'r') as f:
                data = json.load(f)
                self.next_index = data.get("next_index", 0)
                for entry_dict in data.get("entries", []):
                    entry = TransparencyLogEntry(
                        entry_dict["package_name"],
                        entry_dict["artifact_hash"],
                        entry_dict["signer_identity"],
                        entry_dict["signing_time"],
                        entry_dict["cert_valid_from"],
                        entry_dict["cert_valid_until"]
                    )
                    entry.log_index = entry_dict["log_index"]
                    entry.logged_at = entry_dict["logged_at"]
                    self.entries.append(entry)
        except FileNotFoundError:
            # New log
            pass

    def clear(self):
        """Clear all entries (for testing)"""
        self.entries.clear()
        self.next_index = 0
        self.save_log()

def compute_artifact_hash(file_path: str) -> str:
    """Compute SHA256 hash of artifact file"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()
