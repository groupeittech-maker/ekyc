# MHC eKYC Connector (reference)

Standalone integration kit for consuming the IT-TECH eKYC API from MHC
(Mobility Healthcare) — or any other tenant. Copy the `clients/mhc` folder into
the MHC application; the only hard dependency is `httpx`.

## What it covers

- OAuth2 `client_credentials` token acquisition + caching (`EkycClient`)
- KYC session creation and result polling
- Document sealing (SHA-256 + signature + timestamp + archive)
- Signed webhook verification (`verify_webhook`, HMAC-SHA256, constant-time)
- An example FastAPI webhook receiver (`webhook_receiver.py`)

## One-time onboarding (platform admin)

MHC is provisioned as a tenant by the eKYC operator:

```bash
curl -X POST $EKYC_BASE_URL/v1/admin/tenants -H "X-Admin-Key: $EKYC_ADMIN_API_KEY" \
  -H 'content-type: application/json' \
  -d '{"name":"MHC","allowed_flows":["TRAVEL_INSURANCE"],
       "webhook_url":"https://mhc.example/webhooks/kyc"}'
```

The response returns `client_id`, `client_secret` and `webhook_secret`
**once** — store them in MHC's secret manager.

## Usage

```python
from clients.mhc import EkycClient

client = EkycClient(
    base_url="https://ekyc.example.com",
    client_id="...",
    client_secret="...",
)

# 1. Create a session and redirect the end-user to verification_url
session = client.create_session(customer_reference="MHC-123456", flow="TRAVEL_INSURANCE")
redirect_to = session["verification_url"]

# 2. Later (webhook is preferred; polling is a fallback)
result = client.get_result(session["session_id"])
if result.is_verified:
    print(result.identity, result.checks)
```

## Webhooks

The platform `POST`s to your `webhook_url` on every terminal status with headers
`X-EKYC-Signature: sha256=<hmac>` and `X-EKYC-Timestamp`. Verify before trusting:

```python
from clients.mhc import verify_webhook, WebhookVerificationError

try:
    payload = verify_webhook(webhook_secret, raw_body, sig_header, ts_header)
except WebhookVerificationError:
    return 400
# payload["event"] in {KYC_VERIFIED, KYC_REJECTED, KYC_REVIEW_REQUIRED, KYC_EXPIRED}
```

Recommendations:
- Persist an idempotency key `(event, session_id)` — deliveries are retried.
- Reconcile with `GET /v1/kyc/sessions/{id}` if a webhook is ever missed.
- Handle `KYC_REVIEW_REQUIRED` (manual review) and `KYC_EXPIRED` explicitly.

## Run the example receiver

```bash
pip install -r clients/mhc/requirements.txt
EKYC_WEBHOOK_SECRET=<webhook_secret> \
  uvicorn clients.mhc.webhook_receiver:app --port 9000
```
