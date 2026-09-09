"""Generate strong production secrets.

Usage:
    python -m scripts.generate_secrets            # print to stdout
    python -m scripts.generate_secrets >> .env    # append to an env file

Never reuse the development defaults (``change-me-*``) in production.
"""

from __future__ import annotations

import secrets


def _token() -> str:
    return secrets.token_urlsafe(48)


def main() -> None:
    print(f"EKYC_ADMIN_API_KEY={_token()}")
    print(f"EKYC_JWT_SECRET={_token()}")


if __name__ == "__main__":
    main()
