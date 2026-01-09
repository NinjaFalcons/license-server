from fastapi import FastAPI, HTTPException
import requests, os, time, json, base64
from datetime import datetime, timezone
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

app = FastAPI()

KEYGEN_TOKEN = os.environ["KEYGEN_API_TOKEN"]    # prod-f4394350d89cdd1ca473c20c5be8837f9b97a40f308c9251e200d76d51eaefdbv3
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
POLICY_ID = os.environ["POLICY_ID"]
PRIVATE_KEY = SigningKey(bytes.fromhex(os.environ["SERVER_PRIVATE_KEY"]), encoder=RawEncoder)

HEADERS = {
    "Authorization": f"Bearer {KEYGEN_TOKEN}",
    "Content-Type": "application/vnd.api+json",
    "Accept": "application/vnd.api+json"
}

LEASE_SECONDS = 24 * 3600  # 24h leases

@app.post("/lease")
def issue_lease(license_key: str, fingerprint: str):
    # 1️⃣ Validate license with Keygen
    r = requests.post(
        f"https://api.keygen.sh/v1/accounts/{ACCOUNT_ID}/licenses/actions/validate-key",
        headers=HEADERS,
        json={
            "meta": {
                "key": license_key,
                "scope": {
                    "fingerprint": fingerprint,
                    "policy": POLICY_ID
                }
            }
        },
        timeout=10
    )

    if r.status_code != 200:
        raise HTTPException(403, "Invalid license")

    data = r.json()["meta"]

    # 2️⃣ Subscription checks
    sub = data.get("subscription")
    if not sub or sub["status"] != "active":
        raise HTTPException(403, "Subscription inactive")

    period_end = int(
        datetime.fromisoformat(
            sub["current_period_end"].replace("Z", "+00:00")
        ).timestamp()
    )

    now = int(time.time())
    if now >= period_end:
        raise HTTPException(403, "Subscription expired")

    # 3️⃣ Build lease
    lease = {
        "license": license_key,
        "machine": fingerprint,
        "issued_at": now,
        "expires_at": now + LEASE_SECONDS,
        "subscription_ends_at": period_end,
        "plan": sub.get("plan", "default")
    }

    # 4️⃣ Sign lease
    signature = PRIVATE_KEY.sign(
        json.dumps(lease, sort_keys=True).encode()
    ).signature

    return {
        "lease": lease,
        "signature": base64.b64encode(signature).decode()
    }
