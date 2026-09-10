"""Example webhook receiver for MHC — verifies the eKYC signature (HMAC).

Run standalone:
    pip install fastapi uvicorn httpx
    EKYC_WEBHOOK_SECRET=<webhook_secret> uvicorn clients.mhc.webhook_receiver:app --port 9000

In production, look up the webhook secret per tenant and persist an idempotency
key (event + session_id) so a replayed delivery is processed at most once.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException, Request

from clients.mhc.ekyc_client import WebhookVerificationError, verify_webhook

app = FastAPI(title="MHC eKYC webhook receiver")

WEBHOOK_SECRET = os.environ.get("EKYC_WEBHOOK_SECRET", "")

# Handlers keyed by event. Replace the bodies with real MHC business logic.
_HANDLERS = {
    "KYC_VERIFIED": lambda p: print(f"[MHC] {p['customer_reference']} verified -> unlock record"),
    "KYC_REJECTED": lambda p: print(f"[MHC] {p['customer_reference']} rejected -> notify agent"),
    "KYC_REVIEW_REQUIRED": lambda p: print(f"[MHC] {p['customer_reference']} needs manual review"),
    "KYC_EXPIRED": lambda p: print(f"[MHC] {p['customer_reference']} session expired"),
}


@app.post("/webhooks/kyc")
async def receive_kyc_webhook(
    request: Request,
    x_ekyc_signature: str | None = Header(default=None),
    x_ekyc_timestamp: str | None = Header(default=None),
) -> dict[str, str]:
    if not WEBHOOK_SECRET:
        raise HTTPException(500, "EKYC_WEBHOOK_SECRET is not configured")

    body = await request.body()
    try:
        payload = verify_webhook(WEBHOOK_SECRET, body, x_ekyc_signature, x_ekyc_timestamp)
    except WebhookVerificationError as exc:
        raise HTTPException(400, str(exc)) from exc

    handler = _HANDLERS.get(payload.get("event", ""))
    if handler:
        handler(payload)
    # Always 200 once verified so the platform stops retrying.
    return {"status": "accepted"}
