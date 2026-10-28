"""Country profile schema + attested activation gate (Trusdy National).

A national deployment is configured through an explicit *country profile*
(JSON, strict schema — ``EKYC_COUNTRY_PROFILE``). Three activation conditions
are enforced in production:

- ``legal_review``             — the deployment has a legal basis,
- ``hosting_approved``         — the storage location is approved,
- ``trust_services_validated`` — the trust connectors are validated.

Each flag must be true AND backed by a signed *activation attestation* issued
by Trusdy Central (Ed25519 over a canonical payload, verified against
``EKYC_CENTRAL_PUBLIC_KEY``). Editing the file locally cannot unlock the
instance: only Central's private key produces a valid attestation. A profile
without Central signing is a self-declared profile — acceptable in
development, refused in production.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pydantic import BaseModel, Field

import logging

from app.core.config import InsecureConfigError, settings

logger = logging.getLogger(__name__)


class DataPolicy(BaseModel, extra="forbid"):
    storage_location: str = "approved-location"
    encryption_at_rest: bool = True
    # "deny-by-default" | "tenant-explicit" | "allowed"
    external_transfer: str = "deny-by-default"


class IdentityCapabilities(BaseModel, extra="forbid"):
    ocr: bool = True
    mrz: bool = True
    nfc: bool = True
    face_match: bool = True
    liveness: bool = True


class TrustConnectors(BaseModel, extra="forbid"):
    """Named connectors — must resolve to configured providers, not inline URLs."""
    tsa_provider: str | None = None
    signature_provider: str | None = None
    certificate_profile: str | None = None


class ActivationState(BaseModel, extra="forbid"):
    legal_review: bool = False
    hosting_approved: bool = False
    trust_services_validated: bool = False


class ActivationAttestation(BaseModel, extra="forbid"):
    """Central-signed proof that the activation flags were validated.

    ``signature`` is base64 Ed25519 over the canonical payload
    ``country|legal|hosting|trust|issued_at|not_after``.
    """

    country: str
    legal_review: bool
    hosting_approved: bool
    trust_services_validated: bool
    issued_at: datetime
    not_after: datetime
    signature: str  # base64 Ed25519

    def canonical_payload(self) -> bytes:
        return "|".join(
            [
                self.country,
                "1" if self.legal_review else "0",
                "1" if self.hosting_approved else "0",
                "1" if self.trust_services_validated else "0",
                self.issued_at.isoformat(),
                self.not_after.isoformat(),
            ]
        ).encode()


class CountryProfile(BaseModel, extra="forbid"):
    country_code: str = Field(min_length=2, max_length=3)
    deployment_mode: str = "national"  # national | central
    environment: str = "production"
    data: DataPolicy = Field(default_factory=DataPolicy)
    identity: IdentityCapabilities = Field(default_factory=IdentityCapabilities)
    trust: TrustConnectors = Field(default_factory=TrustConnectors)
    activation: ActivationState = Field(default_factory=ActivationState)
    activation_attestation: ActivationAttestation | None = None

    def to_audit_dict(self) -> dict:
        return {
            "country_code": self.country_code,
            "deployment_mode": self.deployment_mode,
            "external_transfer": self.data.external_transfer,
            "activated": True,
        }


def load_profile(path: str | Path) -> CountryProfile:
    return CountryProfile.model_validate_json(Path(path).read_text())


def _verify_attestation(att: ActivationAttestation) -> str | None:
    """Return None when valid, else a reason string (labels only — no secrets)."""
    if not (att.legal_review and att.hosting_approved and att.trust_services_validated):
        return "attestation flags not all true"
    if att.not_after.replace(tzinfo=att.not_after.tzinfo or timezone.utc) < datetime.now(
        timezone.utc
    ):
        return "attestation expired"
    key_b64 = settings.central_public_key
    if not key_b64:
        return "EKYC_CENTRAL_PUBLIC_KEY not configured — cannot verify attestation"
    try:
        key = _load_public_key(key_b64)
        key.verify(base64.b64decode(att.signature), att.canonical_payload())
    except InvalidSignature:
        return "attestation signature invalid"
    except Exception:
        return "central public key unreadable or malformed"
    return None


def _load_public_key(value: str):
    """Accept a raw base64/hex Ed25519 key or a PEM public key."""
    value = value.strip()
    if value.startswith("-----BEGIN"):
        return load_pem_public_key(value.encode())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw = bytes.fromhex(value) if len(value) == 64 else base64.b64decode(value)
    if len(raw) != 32:
        raise ValueError("central public key must be a 32-byte Ed25519 key")
    return Ed25519PublicKey.from_public_bytes(raw)


def enforce_country_profile() -> CountryProfile | None:
    """Load and gate the configured country profile. Called at startup in
    production — raising here must block boot (fail-closed activation)."""
    if not settings.country_profile:
        return None
    profile = load_profile(settings.country_profile)
    act = profile.activation
    if not (act.legal_review and act.hosting_approved and act.trust_services_validated):
        raise InsecureConfigError(
            f"Country profile {profile.country_code} not activated "
            "(legal_review/hosting_approved/trust_services_validated)"
        )
    if profile.activation_attestation is None:
        raise InsecureConfigError(
            f"Country profile {profile.country_code} has no Central attestation"
        )
    att = profile.activation_attestation
    if att.country != profile.country_code:
        raise InsecureConfigError(
            f"Attestation country {att.country} does not match profile "
            f"{profile.country_code} — attestation is non-transferable"
        )
    if (
        att.legal_review != act.legal_review
        or att.hosting_approved != act.hosting_approved
        or att.trust_services_validated != act.trust_services_validated
    ):
        raise InsecureConfigError(
            f"Profile {profile.country_code} activation flags do not match "
            "the signed attestation — file tampered"
        )
    reason = _verify_attestation(att)
    if reason is not None:
        raise InsecureConfigError(
            f"Country profile {profile.country_code} attestation rejected: {reason}"
        )
    return profile


_active_cache: dict[str, CountryProfile] = {}


def active_profile() -> CountryProfile | None:
    """The currently configured country profile (read at runtime — the same
    gate applies in production, but a missing profile is allowed when the
    instance isn't gated). Cached per path to avoid re-parsing per session."""
    path = settings.country_profile
    if not path:
        return None
    if path not in _active_cache:
        try:
            _active_cache[path] = load_profile(path)
        except Exception:
            logger.warning("country profile %s unreadable — defaults apply", path)
            return None
    return _active_cache[path]
