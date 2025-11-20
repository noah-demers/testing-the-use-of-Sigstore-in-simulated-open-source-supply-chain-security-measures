#!/usr/bin/env python3
import requests
import time

class KAMService:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
    
    def authorize_key(self, package_name: str, signer_identity: str, ttl_seconds: int = None):
        """
        Authorize a key with optional TTL (Time-To-Live)
        ttl_seconds: None = no expiration, or seconds until expiration
        """
        data = {
            "package": package_name,
            "signer": signer_identity,
            "authorized_at": time.time()
        }
        
        if ttl_seconds:
            data["expires_at"] = time.time() + ttl_seconds
            data["ttl_seconds"] = ttl_seconds
        
        try:
            response = requests.post(f"{self.base_url}/authorize", json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            print(f"[ERROR] KAM authorization failed: {e}")
            print(f"[ERROR] Response: {response.text}")
            raise
    
    def check_key(self, package_name: str, signer_identity: str):
        """Check if key is authorized and not expired"""
        try:
            response = requests.post(
                f"{self.base_url}/check",
                json={"package": package_name, "signer": signer_identity}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            print(f"[ERROR] KAM check failed: {e}")
            return {"authorized": False, "reason": "KAM service error"}
    
    def get_authorized_signers(self, package_name: str):
        """Get all authorized signers (for compatibility)"""
        try:
            response = requests.get(f"{self.base_url}/all")
            response.raise_for_status()
            all_keys = response.json().get("authorized_keys", [])
            return [k["signer"] for k in all_keys if k["package"] == package_name]
        except:
            return []
