"""Signature engine: SHA-256 integrity proof + server-side digital signature.

The platform builds the evidence, the tenant only submits or requests the
document. A self-generated RSA key is used when no key is provisioned, so a
developer environment works out of the box; production must mount a key backed
by an HSM/KMS through ``EKYC_SIGNING_KEY_PATH``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

from app.core.config import settings

SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"


@dataclass
class Signature:
    value: bytes
    algorithm: str
    certificate_fingerprint: str | None

    @property
    def b64(self) -> str:
        return base64.b64encode(self.value).decode()


@lru_cache
def _private_key() -> rsa.RSAPrivateKey:
    path = Path(settings.signing_key_path).expanduser()
    if path.exists():
        key = load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("Signing key must be an RSA private key")
        return key

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return key


@lru_cache
def certificate_fingerprint() -> str | None:
    if not settings.signing_cert_path:
        return None
    certificate = load_pem_x509_certificate(Path(settings.signing_cert_path).read_bytes())
    return certificate.fingerprint(hashes.SHA256()).hex()


def sign_digest(payload: bytes) -> Signature:
    value = _private_key().sign(payload, padding.PKCS1v15(), hashes.SHA256())
    return Signature(
        value=value,
        algorithm=SIGNATURE_ALGORITHM,
        certificate_fingerprint=certificate_fingerprint(),
    )


def verify_signature(payload: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        _private_key().public_key().verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def public_key_pem() -> str:
    return (
        _private_key()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
