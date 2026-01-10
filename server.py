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

class ActivateRequest(BaseModel):
    license_key: str
    fingerprint: str



@app.post("/activate")
def activate(req: ActivateRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    _rate_limit(ip)

    # 1) Validate license WITHOUT fingerprint so it succeeds even on first run,
    # and so we can get the license UUID (id).
    j = _keygen_validate(req.license_key, fingerprint=req.fingerprint, allow_inactive=True)


    license_id = j["data"]["id"]
    policy_id = j["data"]["relationships"]["policy"]["data"]["id"]

    if policy_id != POLICY_ID:
        raise HTTPException(403, detail={"code": "POLICY_MISMATCH", "detail": "Wrong policy"})

    # Optional: enforce max machines (Keygen also enforces, but this gives nicer error)
    machines_count = (
        j["data"].get("relationships", {})
              .get("machines", {})
              .get("meta", {})
              .get("count", 0)
    )
    max_machines = j["data"]["attributes"].get("maxMachines")
    if isinstance(max_machines, int) and machines_count >= max_machines:
        raise HTTPException(403, detail={"code": "MACHINE_LIMIT", "detail": "Machine limit exceeded"})

    # 2) Create machine bound to the license
    url = f"https://api.keygen.sh/v1/accounts/{ACCOUNT_ID}/machines"
    payload = {
        "data": {
            "type": "machines",
            "attributes": {"fingerprint": req.fingerprint},
            "relationships": {
                "license": {"data": {"type": "licenses", "id": license_id}}
            },
        }
    }

    r = requests.post(url, headers=KEYGEN_HEADERS, json=payload, timeout=10)

    # 201 Created = new machine
    if r.status_code in (200, 201):
        return {"activated": True}

    # 409 can happen if machine already exists / already activated (Keygen dependent)
    if r.status_code == 409:
        return {"activated": True}

    # Otherwise bubble up Keygen error details
    j2 = r.json() if r.headers.get("content-type", "").startswith("application") else {}
    err = (j2.get("errors") or [{}])[0]
    raise HTTPException(
        403,
        detail={
            "code": err.get("code") or "ACTIVATION_FAILED",
            "detail": err.get("detail") or "Activation failed",
        },
    )


def _rate_limit(ip: str) -> None:
    now = time.time()
    bucket = _RATE.get(ip, [])
    bucket = [t for t in bucket if now - t < RATE_WINDOW]
    if len(bucket) >= RATE_LIMIT:
        raise HTTPException(429, "Too many requests")
    bucket.append(now)
    _RATE[ip] = bucket


def _keygen_validate(license_key: str, fingerprint: str | None, allow_inactive: bool = False):
    url = f"https://api.keygen.sh/v1/accounts/{ACCOUNT_ID}/licenses/actions/validate-key"
    meta = {"key": license_key}
    if fingerprint is not None:
        meta["scope"] = {"fingerprint": fingerprint}
    

    r = requests.post(url, headers=KEYGEN_HEADERS, json={"meta": meta}, timeout=10)

    # Keygen returns JSON even on 4xx
    j = r.json() if r.headers.get("content-type", "").startswith("application") else {}
    kg_meta = j.get("meta", {})
    data = j.get("data", {})

    if r.status_code != 200:
        raise HTTPException(
            status_code=403,
            detail={
                "code": kg_meta.get("code") or "VALIDATION_FAILED",
                "detail": kg_meta.get("detail") or "License validation failed",
                "license_id": (data.get("id") if isinstance(data, dict) else None),
                "policy_id": (
                    data.get("relationships", {})
                        .get("policy", {})
                        .get("data", {})
                        .get("id")
                    if isinstance(data, dict) else None
                ),
            },
        )

    # If valid is false, only raise if allow_inactive is False
    if not kg_meta.get("valid", False) and not allow_inactive:
        raise HTTPException(
            status_code=403,
            detail={
                "code": kg_meta.get("code") or "VALIDATION_FAILED",
                "detail": kg_meta.get("detail") or "License validation failed",
                "license_id": (data.get("id") if isinstance(data, dict) else None),
                "policy_id": (
                    data.get("relationships", {})
                        .get("policy", {})
                        .get("data", {})
                        .get("id")
                    if isinstance(data, dict) else None
                ),
            },
        )


    # Optional: enforce policy on server side too
    policy_id = (
        data.get("relationships", {})
            .get("policy", {})
            .get("data", {})
            .get("id")
    )
    if policy_id and policy_id != POLICY_ID:
        raise HTTPException(
            status_code=403,
            detail={"code": "POLICY_MISMATCH", "detail": "Wrong policy"},
        )

    return j



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
