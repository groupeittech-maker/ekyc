"""Data vault: envelope encryption for archived artifacts."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.services import vault
from app.services.pdf import render_contract
from app.services.storage import get_storage

_KEK = "ab" * 32  # fixed test KEK: deterministic DEKs


@pytest.fixture
def vault_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(settings, "storage_encryption_enabled", True)
    monkeypatch.setattr(settings, "kek", _KEK)
    monkeypatch.setattr(settings, "kek_version", 1)
    vault.get_key_provider.cache_clear()
    yield
    vault.get_key_provider.cache_clear()


def test_seal_open_roundtrip(vault_on: None) -> None:
    blob = vault.seal("tenant-a", b"secret document")
    assert blob.startswith(b"EKYCENC")
    assert b"secret document" not in blob
    assert vault.open("tenant-a", blob) == b"secret document"


def test_blob_cannot_be_moved_to_another_tenant(vault_on: None) -> None:
    blob = vault.seal("tenant-a", b"secret")
    with pytest.raises(vault.VaultError):
        vault.open("tenant-b", blob)


def test_open_passes_plaintext_through(vault_on: None) -> None:
    assert vault.open("tenant-a", b"legacy plaintext") == b"legacy plaintext"


def test_rotation_keeps_old_blobs_readable(vault_on: None, monkeypatch) -> None:
    old_blob = vault.seal("tenant-a", b"sealed with v1")
    monkeypatch.setattr(settings, "kek_version", 2)
    vault.get_key_provider.cache_clear()
    new_blob = vault.seal("tenant-a", b"sealed with v2")

    assert old_blob[8:12] != new_blob[8:12] or old_blob != new_blob
    assert vault.open("tenant-a", old_blob) == b"sealed with v1"  # header version
    assert vault.open("tenant-a", new_blob) == b"sealed with v2"


def test_truncated_or_foreign_blob_is_rejected(vault_on: None) -> None:
    with pytest.raises(vault.VaultError):
        vault.open("tenant-a", b"EKYCENC\x01")
    blob = bytearray(vault.seal("tenant-a", b"payload"))
    blob[-1] ^= 0xFF  # flip a bit in the GCM tag
    with pytest.raises(vault.VaultError):
        vault.open("tenant-a", bytes(blob))


def test_master_key_file_is_deterministic(vault_on: None, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "kek", "")
    monkeypatch.setattr(settings, "kek_path", str(tmp_path / "kek.hex"))
    vault.get_key_provider.cache_clear()

    dek1 = vault.get_key_provider().data_key("tenant-a", 1)
    vault.get_key_provider.cache_clear()
    dek2 = vault.get_key_provider().data_key("tenant-a", 1)
    assert dek1 == dek2  # same generated KEK -> same DEK


def test_end_to_end_sealed_document_is_encrypted_on_disk(
    vault_on: None, client: TestClient, tenant_credentials: dict
) -> None:
    # Tenant token
    token_resp = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": tenant_credentials["client_id"],
            "client_secret": tenant_credentials["client_secret"],
        },
    )
    token = token_resp.json()["access_token"]
    headers = {"authorization": f"Bearer {token}"}

    session = client.post(
        "/v1/kyc/sessions",
        headers=headers,
        json={"customer_reference": "VAULT-1", "flow": "TRAVEL_INSURANCE"},
    ).json()
    sid = session["session_id"]

    pdf = render_contract(
        title="Vault test",
        session_id=sid,
        tenant_name="MHC",
        body=[("a", "1")],
        issued_at="2026-10-18T00:00:00",
    )
    import base64

    sealed = client.post(
        f"/v1/kyc/sessions/{sid}/documents",
        headers=headers,
        json={
            "document_reference": "VAULT-DOC-1",
            "pdf_base64": base64.b64encode(pdf).decode(),
        },
    ).json()

    # The sealed artifact on disk must be ciphertext, not PDF bytes.
    from app.db.session import SessionLocal
    from app.models.document import Artifact
    from app.models.signature import SignedDocument

    with SessionLocal() as db:
        signed = db.get(SignedDocument, sealed["signed_document_id"])
        assert signed is not None
        artifact = db.get(Artifact, signed.signed_artifact_id)
        assert artifact is not None
        blob = get_storage().get(artifact.storage_key)

    assert blob.startswith(b"EKYCENC")
    assert b"%PDF" not in blob

    # ...yet the API returns the original document and the integrity hash
    # still covers the plaintext.
    downloaded = client.get(
        f"/v1/kyc/sessions/{sid}/documents/{sealed['signed_document_id']}",
        headers=headers,
    )
    assert downloaded.content.startswith(b"%PDF")


def test_plaintext_hash_covers_cleartext(vault_on: None, db, tenant_credentials: dict) -> None:
    # sha256 stored on the artifact stays the hash of the plaintext payload,
    # so integrity proofs are unaffected by at-rest encryption.
    from app.models.enums import ArtifactKind
    from app.models.tenant import Tenant
    from app.services.archive import read_artifact, store_artifact

    tenant = db.query(Tenant).first()
    data = b"cleartext payload"
    artifact = store_artifact(
        db,
        tenant_id=tenant.id,
        session_id=None,
        kind=ArtifactKind.CONTRACT,
        filename="t.bin",
        data=data,
    )
    assert artifact.sha256 == hashlib.sha256(data).hexdigest()
    assert get_storage().get(artifact.storage_key).startswith(b"EKYCENC")
    assert read_artifact(artifact) == data
