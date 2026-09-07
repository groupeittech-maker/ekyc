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


_backend: StorageBackend | None = None


def get_storage() -> StorageBackend:
    global _backend
    if _backend is None:
        if settings.storage_backend == "s3":
            _backend = S3Storage(settings.s3_bucket, settings.s3_endpoint_url, settings.s3_region)
        else:
            _backend = LocalStorage(os.path.expanduser(settings.storage_root))
    return _backend


def build_key(tenant_id: str, session_id: str, kind: str, filename: str) -> str:
    day = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    return f"tenant/{tenant_id}/{day}/{session_id}/{kind.lower()}/{filename}"
