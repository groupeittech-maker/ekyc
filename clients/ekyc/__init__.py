"""IT-TECH eKYC SDK — generic connector for tenant applications.

Self-contained package (only ``httpx`` required): copy this folder into your
application or install it (``pip install <repo>/clients``), then::

    from ekyc import EkycClient            # installed package
    # or: from clients.ekyc import EkycClient   # vendored inside this repo

    client = EkycClient(base_url, client_id, client_secret)
"""

from .client import EkycClient, __version__
from .exceptions import EkycError, WebhookVerificationError
from .models import DocumentArtifact, KycResult
from .webhook import verify_webhook

__all__ = [
    "DocumentArtifact",
    "EkycClient",
    "EkycError",
    "KycResult",
    "WebhookVerificationError",
    "__version__",
    "verify_webhook",
]
