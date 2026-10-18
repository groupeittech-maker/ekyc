"""Encrypted vault: envelope encryption for archived artifacts.

Architecture (data-vault module of the trust platform):

* KEK (key-encryption key) lives outside the data — ``EKYC_KEK`` env var in
  production (inject it from your KMS/secret store), or an auto-generated
  file for development, same pattern as the signing key.
* A per-tenant DEK is derived deterministically:
  ``DEK = HKDF-SHA256(KEK, info="ekyc-vault:<tenant_id>:<key_version>")``.
  Deterministic derivation means no key material is stored in the database;
  rotation only bumps ``EKYC_KEK_VERSION``.
* Each artifact gets a random 96-bit nonce + AES-256-GCM. The header carries
  the format and key version, so blobs are self-describing:

      EKYCENC | fmt(1) | key_version(4) | nonce(12) | ciphertext+tag

  The magic byte lets ``open()`` distinguish ciphertext from legacy
  plaintext — an archive can be migrated lazily, object by object.
* The AAD binds the header and the tenant id to the ciphertext: a blob moved
  under another tenant's key fails authentication instead of decrypting.

The tenant's ``sha256`` in the artifact row keeps hashing the *plaintext*:
integrity proofs and signed digests are computed on the cleartext and are
unaffected by at-rest encryption.

``KeyProvider`` is the KMS seam: ``local`` uses the HKDF provider; a Vault,
AWS KMS or HSM integration implements the same interface later.
"""

from __future__ import annotations

import base64
import os
import struct
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

_MAGIC = b"EKYCENC"  # 7-byte marker — cannot collide with PDF/PNG/DER headers
_FORMAT_VERSION = 1
_KEY_VERSION_LEN = 4
_NONCE_LEN = 12
_KEY_LEN = 32  # AES-256


class VaultError(RuntimeError):
    """Raised when a sealed blob cannot be authenticated or decrypted."""


class KeyProvider(ABC):
    """Resolves the data-encryption key for a tenant + key version."""

    @abstractmethod
    def data_key(self, tenant_id: str, version: int) -> bytes: ...


class HkdfKeyProvider(KeyProvider):
    """Local provider: DEKs derived from a master key kept outside the data."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != _KEY_LEN:
            raise VaultError(f"KEK must be {_KEY_LEN} bytes, got {len(master_key)}")
        self._master = master_key

    def data_key(self, tenant_id: str, version: int) -> bytes:
        info = f"ekyc-vault:{tenant_id}:{version}".encode()
        return HKDF(algorithm=SHA256(), length=_KEY_LEN, salt=None, info=info).derive(self._master)


def _decode_kek(raw: str) -> bytes:
    raw = raw.strip()
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return base64.urlsafe_b64decode(raw)


def _load_master_key() -> bytes:
    if settings.kek:
        return _decode_kek(settings.kek)
    path = Path(settings.kek_path).expanduser()
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    key = os.urandom(_KEY_LEN)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key.hex())
    try:
        path.chmod(0o600)
    except OSError:
        pass  # windows filesystems don't support chmod bits
    return key


@lru_cache
def get_key_provider() -> KeyProvider:
    # kms_backend seam: "local" is the only implementation today; AWS KMS /
    # HashiCorp Vault plug in here without touching the vault format.
    if settings.kms_backend != "local":
        raise VaultError(f"Unsupported KMS backend: {settings.kms_backend}")
    return HkdfKeyProvider(_load_master_key())


def _header(key_version: int) -> bytes:
    return _MAGIC + bytes([_FORMAT_VERSION]) + struct.pack(">I", key_version)


def is_sealed(blob: bytes) -> bool:
    return blob.startswith(_MAGIC)


def seal(tenant_id: str, data: bytes) -> bytes:
    """Encrypt ``data`` under the tenant's current DEK; return the blob."""
    version = settings.kek_version
    header = _header(version)
    key = get_key_provider().data_key(tenant_id, version)
    nonce = os.urandom(_NONCE_LEN)
    aad = header + tenant_id.encode()
    return header + nonce + AESGCM(key).encrypt(nonce, data, aad)


def open(tenant_id: str, blob: bytes) -> bytes:
    """Decrypt a blob produced by ``seal``; pass plaintext through untouched."""
    if not is_sealed(blob):
        return blob  # legacy plaintext artifact
    header_len = len(_MAGIC) + 1 + _KEY_VERSION_LEN
    if len(blob) < header_len + _NONCE_LEN + 16:  # +16: minimum GCM tag
        raise VaultError("Truncated vault blob")
    if blob[len(_MAGIC)] != _FORMAT_VERSION:
        raise VaultError(f"Unsupported vault format: {blob[len(_MAGIC)]}")
    key_version = struct.unpack(">I", blob[len(_MAGIC) + 1 : header_len])[0]
    header = blob[:header_len]
    nonce = blob[header_len : header_len + _NONCE_LEN]
    ciphertext = blob[header_len + _NONCE_LEN :]
    key = get_key_provider().data_key(tenant_id, key_version)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, header + tenant_id.encode())
    except Exception as exc:  # cryptography raises InvalidTag (a private type)
        raise VaultError("Vault blob authentication failed") from exc


__all__ = ["KeyProvider", "VaultError", "get_key_provider", "is_sealed", "open", "seal"]
