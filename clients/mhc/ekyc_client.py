"""Backwards-compatible shim — the implementation moved to the generic SDK.

``clients.mhc`` remains the MHC-flavored entry point; everything it used to
implement now lives in ``clients.ekyc`` so any tenant can reuse it. Existing
imports (``from clients.mhc.ekyc_client import EkycClient``) keep working.
"""

from clients.ekyc import (
    DocumentArtifact,
    EkycClient,
    EkycError,
    KycResult,
    WebhookVerificationError,
    verify_webhook,
)

__all__ = [
    "DocumentArtifact",
    "EkycClient",
    "EkycError",
    "KycResult",
    "WebhookVerificationError",
    "verify_webhook",
]
