"""Signature engine: SHA-256 integrity proof + server-side digital signature.

The platform builds the evidence; the tenant only submits or requests the
document. Key material lives behind a pluggable ``Signer`` backend
(``app.engines.providers.signers``): a local RSA key out of the box, an HSM/KMS
in production. This module keeps a stable, backend-agnostic API.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from app.engines.providers.signers import SIGNATURE_ALGORITHM, get_signer

__all__ = [
    "SIGNATURE_ALGORITHM",
    "Signature",
    "sign_digest",
    "verify_signature",
    "public_key_pem",
    "certificate_fingerprint",
]


@dataclass
class Signature:
    value: bytes
    algorithm: str
    certificate_fingerprint: str | None

    @property
    def b64(self) -> str:
        return base64.b64encode(self.value).decode()


def sign_digest(payload: bytes) -> Signature:
    signer = get_signer()
    return Signature(
        value=signer.sign(payload),
        algorithm=signer.algorithm,
        certificate_fingerprint=signer.certificate_fingerprint(),
    )


def verify_signature(payload: bytes, signature: bytes) -> bool:
    return get_signer().verify(payload, signature)


def public_key_pem() -> str:
    return get_signer().public_key_pem()


def certificate_fingerprint() -> str | None:
    return get_signer().certificate_fingerprint()
