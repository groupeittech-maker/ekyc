"""Typed payloads returned by :class:`~ekyc.client.EkycClient`.

Raw JSON is always kept on ``raw`` so fields added by newer platform versions
remain reachable without upgrading the SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KycResult:
    """Minimized KYC verdict returned to tenants (internal scores never leave)."""

    session_id: str
    status: str
    flow: str | None = None
    jurisdiction: str | None = None
    identity: dict[str, Any] | None = None
    checks: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_verified(self) -> bool:
        return self.status == "VERIFIED"

    @property
    def is_terminal(self) -> bool:
        return self.status in {"VERIFIED", "REJECTED", "REVIEW", "EXPIRED"}


@dataclass
class DocumentArtifact:
    """A sealed PDF downloaded from the platform (certificate or contract)."""

    content: bytes
    sha256: str | None = None
    signature_algorithm: str | None = None
    timestamp_authority: str | None = None
    timestamp_qualified: bool | None = None
    filename: str | None = None
