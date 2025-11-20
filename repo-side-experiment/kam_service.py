#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import time

app = FastAPI()

# In-memory storage for authorized keys
authorized_keys = {}

class AuthorizeRequest(BaseModel):
    package: str
    signer: str
    authorized_at: Optional[float] = None
    expires_at: Optional[float] = None
    ttl_seconds: Optional[int] = None

class CheckRequest(BaseModel):
    package: str
    signer: str

class RevokeRequest(BaseModel):
    package: str
    signer: str

@app.post("/authorize")
def authorize(req: AuthorizeRequest):
    """Authorize a key for a package with optional TTL"""
    key = f"{req.package}:{req.signer}"
    
    authorized_keys[key] = {
        "package": req.package,
        "signer": req.signer,
        "authorized_at": req.authorized_at or time.time(),
        "expires_at": req.expires_at,
        "ttl_seconds": req.ttl_seconds
    }
    
    return {
        "status": "ok",
        "package": req.package,
        "signer": req.signer,
        "authorized_at": authorized_keys[key]["authorized_at"],
        "expires_at": req.expires_at,
        "ttl_seconds": req.ttl_seconds
    }

@app.post("/check")
def check(req: CheckRequest):
    """Check if a key is authorized and not expired"""
    key = f"{req.package}:{req.signer}"
    
    if key not in authorized_keys:
        return {
            "authorized": False,
            "reason": "Key not found"
        }
    
    key_data = authorized_keys[key]
    
    # Check expiration
    if key_data.get("expires_at"):
        if time.time() > key_data["expires_at"]:
            return {
                "authorized": False,
                "reason": "Key expired",
                "expires_at": key_data["expires_at"],
                "current_time": time.time()
            }
    
    return {
        "authorized": True,
        "package": req.package,
        "signer": req.signer,
        "authorized_at": key_data.get("authorized_at"),
        "expires_at": key_data.get("expires_at"),
        "ttl_seconds": key_data.get("ttl_seconds")
    }

@app.post("/revoke")
def revoke(req: RevokeRequest):
    """Revoke authorization for a key"""
    key = f"{req.package}:{req.signer}"
    if key in authorized_keys:
        del authorized_keys[key]
        return {"status": "ok", "message": "Key revoked"}
    
    raise HTTPException(status_code=404, detail="Key not found")

@app.get("/all")
def get_all():
    """Get all authorized keys"""
    return {"authorized_keys": list(authorized_keys.values())}

@app.get("/health")
def health():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": time.time()}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
