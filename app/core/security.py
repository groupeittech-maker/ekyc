import hashlib
import hmac
import secrets
from datetime import timedelta

import jwt

from app.core.config import settings
from app.db.base import utcnow


def hash_secret(secret: str) -> str:
    """Deterministic keyed hash: API secrets are high-entropy, so HMAC is sufficient."""
    return hmac.new(settings.jwt_secret.encode(), secret.encode(), hashlib.sha256).hexdigest()


def verify_secret(secret: str, secret_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), secret_hash)


def create_access_token(tenant_id: str, scope: str = "kyc") -> tuple[str, int]:
    ttl = settings.access_token_ttl_seconds
    now = utcnow()
    payload = {
        "sub": tenant_id,
        "scope": scope,
        "typ": "tenant",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256"), ttl


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])


def new_session_access_token() -> tuple[str, str]:
    """Returns (clear token handed to the end-user UI, stored hash)."""
    token = secrets.token_urlsafe(32)
    return token, hash_secret(token)


def sign_webhook(secret: str, timestamp: str, body: bytes) -> str:
    payload = timestamp.encode() + b"." + body
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
