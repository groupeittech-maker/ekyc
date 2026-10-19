"""Electronic archive: object storage separated from the database.

Keys are namespaced per tenant (``tenant/<tenant_id>/...``) so retention and
access policies can be applied per client.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings


class StorageBackend(ABC):
    @abstractmethod
    def put(self, key: str, data: bytes, content_type: str) -> None: ...

    @abstractmethod
    def get(self, key: str) -> bytes: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a blob; returns True when something was removed."""
        ...


class LocalStorage(StorageBackend):
    def __init__(self, root: str) -> None:
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        root = self.root.resolve()
        if not str(path).startswith(str(root)):
            raise ValueError("Invalid storage key")
        return path

    def put(self, key: str, data: bytes, content_type: str) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def delete(self, key: str) -> bool:
        path = self._path(key)
        if not path.exists():
            return False
        path.unlink()
        return True


class S3Storage(StorageBackend):
    def __init__(self, bucket: str, endpoint_url: str, region: str) -> None:
        import boto3  # imported lazily: only required for the s3 backend

        self.bucket = bucket
        self.client = boto3.client(
            "s3", endpoint_url=endpoint_url or None, region_name=region or None
        )

    def put(self, key: str, data: bytes, content_type: str) -> None:
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
            ServerSideEncryption="AES256",
        )

    def get(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
        except ClientError:
            return False
        return True

    def delete(self, key: str) -> bool:
        existed = self.exists(key)
        if existed:
            self.client.delete_object(Bucket=self.bucket, Key=key)
        return existed


_backend: StorageBackend | None = None


def get_storage() -> StorageBackend:
    global _backend
    if _backend is None:
        if settings.storage_backend == "s3":
            _backend = S3Storage(settings.s3_bucket, settings.s3_endpoint_url, settings.s3_region)
        else:
            _backend = LocalStorage(os.path.expanduser(settings.storage_root))
    return _backend


# --------------------------------------------------------------------------- #
# Vaults: named storage targets selected by the regulatory orchestrator.
# "default" is the primary backend; extra vaults come from EKYC_VAULTS_JSON —
# each can point at a different root, bucket or host (regulatory separation).
# --------------------------------------------------------------------------- #
class UnknownVaultError(RuntimeError):
    """Raised when a session's resolved vault profile is not configured."""


def vault_configs() -> dict[str, dict[str, str]]:
    if not settings.vaults_json:
        return {}
    import json

    parsed = json.loads(settings.vaults_json)
    if not isinstance(parsed, dict):
        raise UnknownVaultError("EKYC_VAULTS_JSON must be a JSON object")
    return parsed


_vaults: dict[str, StorageBackend] = {}


def get_vault(profile: str | None) -> StorageBackend:
    """Resolve a vault profile name to a storage backend (cached)."""
    name = profile or "default"
    if name == "default":
        return get_storage()
    if name in _vaults:
        return _vaults[name]
    cfg = vault_configs().get(name)
    if cfg is None:
        raise UnknownVaultError(
            f"Vault '{name}' is not configured "
            f"(configured: default, {', '.join(sorted(vault_configs())) or 'none'})"
        )
    backend = cfg.get("backend", "local")
    if backend == "s3":
        _vaults[name] = S3Storage(
            cfg.get("bucket", ""), cfg.get("endpoint_url", ""), cfg.get("region", "")
        )
    else:
        _vaults[name] = LocalStorage(cfg["root"])
    return _vaults[name]


def build_key(tenant_id: str, session_id: str, kind: str, filename: str) -> str:
    day = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    return f"tenant/{tenant_id}/{day}/{session_id}/{kind.lower()}/{filename}"
