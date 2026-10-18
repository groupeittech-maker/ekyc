# IT-TECH eKYC — Python SDK

Generic integration kit for consuming the IT-TECH eKYC API from any tenant
application (MHC, bank, fintech, administration…). The only hard dependency is
`httpx`.

## Install

```bash
# Option A — pip-install from the repo (exposes `import ekyc`)
pip install <path-to-repo>/clients

# Option B — copy the `clients/ekyc` folder into your application
#            (imports become `from ekyc import EkycClient`)

# In this repository, the package is also importable as `clients.ekyc`.
```

## One-time onboarding (platform side)

The eKYC operator provisions your application as a tenant:

```bash
curl -X POST $EKYC_BASE_URL/v1/admin/tenants -H "X-Admin-Key: $EKYC_ADMIN_API_KEY" \
  -H 'content-type: application/json' \
  -d '{"name":"MyApp","allowed_flows":["TRAVEL_INSURANCE"],
       "webhook_url":"https://myapp.example/webhooks/kyc"}'
```

The response returns `client_id`, `client_secret` and `webhook_secret`
**once** — store them in your secret manager.

## Quickstart

```python
from ekyc import EkycClient

client = EkycClient(
    base_url="https://ekyc.example.com",
    client_id="...",
    client_secret="...",
)

# 1. Create a session and redirect the end-user to verification_url
session = client.create_session(
    customer_reference="APP-123456",
    flow="TRAVEL_INSURANCE",
    jurisdiction="CI",  # regulatory context (optional) — NOT the document's country
)
redirect_to = session["verification_url"]

# 2. Later (webhook is preferred; polling is a fallback)
result = client.get_result(session["session_id"])
if result.is_verified:
    print(result.identity, result.checks)

# 3. Evidence: sealed certificate, audit trail, contracts
cert = client.download_certificate(session["session_id"])   # DocumentArtifact (PDF bytes)
audit = client.get_audit_export(session["session_id"])       # chained events + integrity
signed = client.seal_document(session["session_id"],         # seal a contract PDF
    document_reference="CONTRACT-42", title="Policy", fields={...})
pdf = client.download_signed_document(session["session_id"], signed["signed_document_id"])
```

## API coverage

| SDK method | Endpoint | Auth |
| --- | --- | --- |
| `health()` | `GET /health` | public |
| `create_session(...)` | `POST /v1/kyc/sessions` | Bearer |
| `get_result(session_id)` | `GET /v1/kyc/sessions/{id}` | Bearer |
| `wait_for_result(...)` | polling on `get_result` | Bearer |
| `get_audit_export(session_id)` | `GET /v1/kyc/sessions/{id}/audit` | Bearer |
| `seal_document(...)` | `POST /v1/kyc/sessions/{id}/documents` | Bearer |
| `download_signed_document(...)` | `GET /v1/kyc/sessions/{id}/documents/{doc}` | Bearer |
| `download_certificate(session_id)` | `GET /v1/kyc/sessions/{id}/certificate` | Bearer |
| `verify_webhook(...)` | local HMAC check | — |

## Webhooks

The platform `POST`s to your `webhook_url` on every terminal status with
headers `X-EKYC-Signature: sha256=<hmac>` and `X-EKYC-Timestamp`. Verify before
trusting:

```python
from ekyc import verify_webhook, WebhookVerificationError

try:
    payload = verify_webhook(webhook_secret, raw_body, sig_header, ts_header)
except WebhookVerificationError:
    return 400
# payload["event"] in {KYC_VERIFIED, KYC_REJECTED, KYC_REVIEW_REQUIRED, KYC_EXPIRED}
```

Recommendations:

- Persist an idempotency key `(event, session_id)` — deliveries are retried.
- Reconcile with `get_result(session_id)` if a webhook is ever missed.
- Handle `KYC_REVIEW_REQUIRED` (manual review) and `KYC_EXPIRED` explicitly.

## Example receiver

```bash
pip install -r ekyc/requirements.txt
EKYC_WEBHOOK_SECRET=<webhook_secret> \
  uvicorn ekyc.webhook_receiver:app --port 9000
```

## Errors

- `EkycError` — any non-2xx API response (message carries status + body).
- `WebhookVerificationError` — missing/mismatched signature or replayed timestamp.
