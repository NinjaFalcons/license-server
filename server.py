import os
import time
import json
import base64
import requests
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

app = FastAPI()

KEYGEN_API_TOKEN = os.environ["KEYGEN_API_TOKEN"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
POLICY_ID = os.environ["POLICY_ID"]
LEASE_SECONDS = int(os.getenv("LEASE_SECONDS", "86400"))  # 24h by default

# Ed25519 private key as hex (64 hex bytes for seed, nacl accepts hex-encoded seed)
SIGNING_KEY = SigningKey(os.environ["SERVER_PRIVATE_KEY_HEX"], encoder=HexEncoder)

KEYGEN_HEADERS = {
    "Authorization": f"Bearer {KEYGEN_API_TOKEN}",
    "Content-Type": "application/vnd.api+json",
    "Accept": "application/vnd.api+json",
}

# Very small in-memory rate limit (good enough to prevent basic brute force)
_RATE = {}
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "60"))       # req per window
RATE_WINDOW = int(os.getenv("RATE_WINDOW", "60"))     # seconds


class LeaseRequest(BaseModel):
    license_key: str
    fingerprint: str


def _rate_limit(ip: str) -> None:
    now = time.time()
    bucket = _RATE.get(ip, [])
    bucket = [t for t in bucket if now - t < RATE_WINDOW]
    if len(bucket) >= RATE_LIMIT:
        raise HTTPException(429, "Too many requests")
    bucket.append(now)
    _RATE[ip] = bucket


def _keygen_validate(license_key: str, fingerprint: str) -> None:
    """
    Validates the license + subscription via Keygen.
    Raises HTTPException if not allowed.
    """
    url = f"https://api.keygen.sh/v1/accounts/{ACCOUNT_ID}/licenses/actions/validate-key"
    payload = {
        "meta": {
            "key": license_key,
            "scope": {
                "fingerprint": fingerprint,
                "policy": POLICY_ID,  # enforce policy on Keygen side too
            },
        }
    }

    r = requests.post(url, headers=KEYGEN_HEADERS, json=payload, timeout=10)

    if r.status_code != 200:
        raise HTTPException(403, "Invalid license or subscription")

    j = r.json()
    meta = j.get("meta", {})

    # Keygen validate-key returns meta.valid when successful
    if not meta.get("valid", False):
        raise HTTPException(403, "Subscription inactive or expired")


def _sign(payload: dict) -> dict:
    """
    Returns {"payload": <payload>, "signature": <base64>} where signature is Ed25519 over canonical JSON.
    """
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = SIGNING_KEY.sign(raw).signature
    return {"payload": payload, "signature": base64.b64encode(sig).decode("ascii")}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/lease")
def lease(req: LeaseRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    _rate_limit(ip)

    _keygen_validate(req.license_key, req.fingerprint)

    now = int(time.time())
    lease_payload = {
        "license": req.license_key,
        "fingerprint": req.fingerprint,
        "issued_at": now,
        "expires_at": now + LEASE_SECONDS,
        "version": 1,
    }

    return _sign(lease_payload)
