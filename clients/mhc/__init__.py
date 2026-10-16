"""Reference eKYC connector for MHC — thin adapter over the generic SDK.

The implementation lives in ``clients.ekyc`` (generic, reusable by any tenant);
this package re-exports it under the MHC name and ships MHC's example webhook
receiver.
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
