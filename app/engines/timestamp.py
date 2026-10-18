"""Trusted timestamping — compatibility wrapper.

The provider registry, policy resolution (``internal`` / ``qualified`` /
named provider) and token verification live in ``app.engines.tsa`` (TSA
Manager). This module keeps the original API so existing call sites and
tests keep working:

* ``request_timestamp(digest, qualified=True)`` → qualified provider, with
  honest fallback to the internal soft timestamp when no TSA is configured;
* ``request_timestamp(digest, qualified=False)`` → internal soft timestamp,
  always flagged ``qualified=False`` and ``NOT_A_QUALIFIED_TSA_TOKEN``.
"""

from __future__ import annotations

from app.engines.tsa import TimestampToken, timestamp

__all__ = ["TimestampToken", "request_timestamp"]


def request_timestamp(digest_hex: str, *, qualified: bool = False) -> TimestampToken:
    return timestamp(digest_hex, "qualified" if qualified else "internal")
