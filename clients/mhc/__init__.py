"""Reference eKYC connector for MHC (and any other tenant).

This package is intentionally standalone (only ``httpx`` is required) so it can
be copied into the MHC application as-is. It covers the full tenant integration:
OAuth2 client_credentials, session creation, result polling, document sealing
and signed-webhook verification.
"""

from clients.mhc.ekyc_client import (
    EkycClient,
    EkycError,
    KycResult,
    WebhookVerificationError,
    verify_webhook,
)

__all__ = [
    "EkycClient",
    "EkycError",
    "KycResult",
    "WebhookVerificationError",
    "verify_webhook",
]
