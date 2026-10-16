"""Error types raised by the eKYC SDK."""


class EkycError(RuntimeError):
    """Raised when the eKYC API returns an error response."""


class WebhookVerificationError(RuntimeError):
    """Raised when an incoming webhook signature cannot be verified."""
