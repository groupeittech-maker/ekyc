"""Regulatory orchestrator: jurisdiction → vault, retention, trust services.

The routing decision is an *explicit policy*, never inferred from the identity
document alone: an Ivorian policyholder may hold a Congolese passport, and the
document's country, the insurer's country and the processing location are
distinct concerns.

Resolution order for the applicable jurisdiction:

1. ``jurisdiction`` on the session-create request — the tenant asserts the
   regulatory context of the operation,
2. ``tenant.default_jurisdiction`` — the tenant's home market,
3. ``EKYC_DEFAULT_JURISDICTION`` — platform fallback (``GLOBAL``).

The resolved :class:`RegulatoryProfile` is *snapshotted onto the session* at
creation and recorded in the audit chain: the routing choice itself becomes
part of the evidence.

Jurisdictions map to a **vault profile** (a named storage target, see
``services/storage.get_vault``), a retention policy and the required trust
services (timestamp authority mode, signature level). Per-deployment rules can
be added or overridden without code changes through
``EKYC_JURISDICTIONS_JSON``, e.g.::

    EKYC_JURISDICTIONS_JSON='{"CI": {"vault_profile": "vps-abidjan",
        "retention_days": 3650, "tsa_policy": "internal"},
        "FR": {"vault_profile": "s3-eu", "tsa_policy": "qualified"}}'
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.core.config import settings


class UnknownJurisdictionError(ValueError):
    """Raised when a session requests a jurisdiction with no defined profile."""


@dataclass(frozen=True)
class RegulatoryProfile:
    jurisdiction: str
    vault_profile: str
    retention_days: int
    # "internal" = platform soft timestamp; "qualified" = external RFC 3161 TSA.
    tsa_policy: str
    # "platform" = platform signer; reserved: "qualified" for external signing.
    signature_level: str
    # How the jurisdiction was selected — evidence for the audit payload.
    source: str  # "request" | "tenant_default" | "platform_default"


# Code-level registry: every key must resolve to a configured vault (see
# EKYC_VAULTS_JSON). Defaults stay conservative — identical to the platform's
# behaviour before jurisdictions existed.
_RULES: dict[str, dict[str, Any]] = {
    "GLOBAL": {
        "vault_profile": "default",
        "retention_days": 3650,
        "tsa_policy": "internal",
        "signature_level": "platform",
    },
    "EU": {
        "vault_profile": "default",
        "retention_days": 3650,
        "tsa_policy": "qualified",
        "signature_level": "platform",
    },
    "FR": {
        "vault_profile": "default",
        "retention_days": 3650,
        "tsa_policy": "qualified",
        "signature_level": "platform",
    },
}


def _env_rules() -> dict[str, dict[str, Any]]:
    if not settings.jurisdictions_json:
        return {}
    parsed = json.loads(settings.jurisdictions_json)
    if not isinstance(parsed, dict):
        raise ValueError("EKYC_JURISDICTIONS_JSON must be a JSON object")
    return parsed


def jurisdictions() -> dict[str, dict[str, Any]]:
    """Effective jurisdiction rules: code registry overlaid by the env config."""
    merged = dict(_RULES)
    merged.update(_env_rules())
    return merged


def resolve(
    tenant: Any,
    requested: str | None,
) -> RegulatoryProfile:
    """Resolve the regulatory profile for a new session.

    ``tenant`` only needs a ``default_jurisdiction`` attribute (the ORM model
    provides it). ``requested`` is the tenant-asserted jurisdiction on the
    session-create call.
    """
    if requested:
        code, source = requested.upper(), "request"
    elif getattr(tenant, "default_jurisdiction", None):
        code, source = str(tenant.default_jurisdiction).upper(), "tenant_default"
    else:
        code, source = settings.default_jurisdiction.upper(), "platform_default"

    rule = jurisdictions().get(code)
    if rule is None:
        raise UnknownJurisdictionError(
            f"Unknown jurisdiction: {code} " f"(configured: {', '.join(sorted(jurisdictions()))})"
        )
    return RegulatoryProfile(
        jurisdiction=code,
        vault_profile=rule.get("vault_profile", "default"),
        retention_days=int(rule.get("retention_days", 3650)),
        tsa_policy=rule.get("tsa_policy", "internal"),
        signature_level=rule.get("signature_level", "platform"),
        source=source,
    )
