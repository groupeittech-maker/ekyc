"""Central key management + signing — mirrors the national-side verification
in ``app/core/country_profile`` (same canonical payload format)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from apps.control_plane.config import settings

_key: Ed25519PrivateKey | None = None


def central_key() -> Ed25519PrivateKey:
    """Load or lazily generate the Central signing key (persisted, chmod 600)."""
    global _key
    if _key is not None:
        return _key
    path = Path(settings.private_key_path)
    if path.exists():
        _key = load_pem_private_key(path.read_bytes(), password=None)
        return _key
    _key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        _key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    path.chmod(0o600)
    return _key


def public_key_b64() -> str:
    raw = central_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def canonical_attestation_payload(
    country: str,
    legal: bool,
    hosting: bool,
    trust: bool,
    issued_at_iso: str,
    not_after_iso: str,
) -> bytes:
    return "|".join(
        [
            country,
            "1" if legal else "0",
            "1" if hosting else "0",
            "1" if trust else "0",
            issued_at_iso,
            not_after_iso,
        ]
    ).encode()


def sign_attestation(payload: bytes) -> str:
    return base64.b64encode(central_key().sign(payload)).decode()


def sign_manifest(version: str, not_before_iso: str, overlay: dict, artifacts: list) -> str:
    canonical = json.dumps(
        {
            "version": version,
            "not_before": not_before_iso,
            "config_overlay": overlay,
            "artifacts": artifacts,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return base64.b64encode(central_key().sign(canonical)).decode()


def load_instance_public_key(stored: str) -> Ed25519PublicKey:
    """PEM or raw (b64/hex) Ed25519 — same acceptance as the national side."""
    stored = stored.strip()
    if stored.startswith("-----BEGIN"):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        return load_pem_public_key(stored.encode())
    raw = bytes.fromhex(stored) if len(stored) == 64 else base64.b64decode(stored)
    return Ed25519PublicKey.from_public_bytes(raw)
