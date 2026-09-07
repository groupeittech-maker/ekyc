import secrets
import string
from datetime import datetime, timezone

_ALPHABET = string.ascii_uppercase + string.digits


def new_session_id() -> str:
    year = datetime.now(timezone.utc).year
    suffix = "".join(secrets.choice(_ALPHABET) for _ in range(10))
    return f"KYC-{year}-{suffix}"


def new_client_id() -> str:
    return "cid_" + secrets.token_hex(12)


def new_secret(prefix: str = "sk") -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"
