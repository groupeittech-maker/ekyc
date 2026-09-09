"""Pluggable signing backends for the evidence layer.

The default ``LocalKeySigner`` holds an RSA key on disk — good enough for
development and small self-hosted deployments. Production should back the key
with an HSM/KMS by implementing the same ``Signer`` interface and selecting it
through ``EKYC_SIGNING_BACKEND`` (the evidence and timestamp engines never touch
the key material directly).
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

from app.core.config import settings

SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"


class Signer(ABC):
    algorithm = SIGNATURE_ALGORITHM

    @abstractmethod
    def sign(self, payload: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, payload: bytes, signature: bytes) -> bool: ...

    @abstractmethod
    def public_key_pem(self) -> str: ...

    @abstractmethod
    def certificate_fingerprint(self) -> str | None: ...


class LocalKeySigner(Signer):
    def __init__(self) -> None:
        self._key = self._load_or_create_key()
        self._certificate = self._load_or_create_certificate()

    def _load_or_create_key(self) -> rsa.RSAPrivateKey:
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

    def _load_or_create_certificate(self) -> x509.Certificate | None:
        if settings.signing_cert_path:
            return load_pem_x509_certificate(
                Path(settings.signing_cert_path).expanduser().read_bytes()
            )
        if not settings.signing_dev_self_signed_cert:
            return None
        return self._self_signed()

    def _self_signed(self) -> x509.Certificate:
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IT-TECH eKYC"),
                x509.NameAttribute(NameOID.COMMON_NAME, "IT-TECH eKYC Dev Signing"),
            ]
        )
        now = dt.datetime.now(dt.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._key, hashes.SHA256())
        )

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    def verify(self, payload: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            self._key.public_key().verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            return False
        return True

    def public_key_pem(self) -> str:
        return (
            self._key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def certificate_pem(self) -> str | None:
        if self._certificate is None:
            return None
        return self._certificate.public_bytes(serialization.Encoding.PEM).decode()

    def certificate_fingerprint(self) -> str | None:
        if self._certificate is None:
            return None
        return self._certificate.fingerprint(hashes.SHA256()).hex()


@lru_cache
def get_signer() -> Signer:
    # Additional backends (AWS KMS, Azure Key Vault, PKCS#11 HSM, ...) plug in
    # here by implementing Signer and dispatching on settings.signing_backend.
    return LocalKeySigner()
