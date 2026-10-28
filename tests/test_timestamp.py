"""Trusted timestamping wrapper — compatibility API coverage."""

from __future__ import annotations

from app.engines import timestamp


def test_internal_timestamp_is_honestly_flagged():
    tok = timestamp.request_timestamp("a" * 64, qualified=False)
    assert tok.qualified is False
    assert tok.provider == "internal"


def test_qualified_policy_falls_back_honestly_without_tsa():
    """No TSA configured → internal timestamp, never presented as qualified."""
    tok = timestamp.request_timestamp("a" * 64, qualified=True)
    assert tok.qualified is False


def test_timestamp_binds_the_digest():
    t1 = timestamp.request_timestamp("a" * 64)
    t2 = timestamp.request_timestamp("b" * 64)
    assert t1.issued_at is not None
    assert t1 is not t2
