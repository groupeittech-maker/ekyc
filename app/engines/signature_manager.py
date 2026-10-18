"""Electronic Signature Manager — signing providers and certificate lifecycle.

Module B of the trust-services layer.

* **Internal** — the platform signer (``platform``): RSA key on disk today,
  HSM/KMS later via the same ``Signer`` interface — key material stays behind
  the provider, services never touch it.
* **External** — a qualified signing service (DSS/eSignature provider) plugs in
  by implementing ``Signer`` and registering under a name; sessions select it
  through ``signature_level`` in their jurisdiction rule. Not yet bundled:
  unknown names fail fast at session creation with a clear 400.

Certificate lifecycle visibility: ``provider_info`` reports the signing
certificate fingerprint and its expiry (``days_to_expiry``), which the
evidence layer embeds into every sealed document so later validation keeps
the elements it needs. Revocation is a key-rotation concern: rotating the key
changes the fingerprint; already-sealed documents remain verifiable from the
public key embedded in the sealed PDF metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.db.base import utcnow
from app.engines.providers.signers import Signer, get_signer
from app.engines.signature import Signature


class UnknownSignerError(ValueError):
    pass


@dataclass(frozen=True)
class SignatureProviderInfo:
    name: str
    backend: str
    algorithm: str
    level: str  # "platform" — a named external signer could carry "qualified"
    certificate_fingerprint: str | None
    cert_expires_at: str | None
    days_to_expiry: int | None


def resolve(level_or_name: str) -> Signer:
    """Map a session's ``signature_level`` to a signing provider."""
    if level_or_name in ("platform", "local", "internal"):
        return get_signer()
    raise UnknownSignerError(
        f"Unknown signature provider: {level_or_name} "
        "(configured: platform; external providers implement Signer)"
    )


def sign(payload: bytes, level_or_name: str = "platform") -> Signature:
    signer = resolve(level_or_name)
    return Signature(
        value=signer.sign(payload),
        algorithm=signer.algorithm,
        certificate_fingerprint=signer.certificate_fingerprint(),
        provider=signer_provider_name(signer),
    )


def verify(
    payload: bytes,
    signature: bytes,
    *,
    level_or_name: str = "platform",
    public_key_pem: str | None = None,
) -> bool:
    """Verify a signature; with ``public_key_pem`` (e.g. embedded in a sealed
    PDF) the check stays possible even after key rotation."""
    if public_key_pem:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        pub = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(pub, rsa.RSAPublicKey):
            return False
        try:
            pub.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False
    return resolve(level_or_name).verify(payload, signature)


def signer_provider_name(signer: Signer) -> str:
    return type(signer).__name__.replace("Signer", "").lower() or "platform"


def provider_info(level_or_name: str = "platform") -> SignatureProviderInfo:
    signer = resolve(level_or_name)
    not_after = signer.certificate_not_after()
    days = None
    if not_after is not None:
        days = (not_after - utcnow()).days
    return SignatureProviderInfo(
        name=signer_provider_name(signer),
        backend=type(signer).__name__,
        algorithm=signer.algorithm,
        level=level_or_name,
        certificate_fingerprint=signer.certificate_fingerprint(),
        cert_expires_at=not_after.isoformat() if not_after else None,
        days_to_expiry=days,
    )


def describe() -> dict[str, Any]:
    info = provider_info("platform")
    return {
        "provider": info.name,
        "algorithm": info.algorithm,
        "certificate_fingerprint": info.certificate_fingerprint,
        "cert_expires_at": info.cert_expires_at,
        "days_to_expiry": info.days_to_expiry,
    }
