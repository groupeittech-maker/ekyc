"""R9 — approved-model manifest and download integrity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.core.config import settings
from app.engines.providers import models
from app.engines.providers.models import (
    ModelIntegrityError,
    ModelNotAvailable,
)

CONTENT = b"FAKE-ONNX-WEIGHTS-v1"
SHA = hashlib.sha256(CONTENT).hexdigest()


@pytest.fixture
def model_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    model_dir = tmp_path / "models"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "models": {
                    "fake.onnx": {
                        "sha256": SHA,
                        "source": "test",
                        "version": "1.0",
                    }
                }
            }
        )
    )
    monkeypatch.setattr(settings, "biometrics_model_dir", str(model_dir))
    monkeypatch.setattr(settings, "manifest_path", str(manifest))
    monkeypatch.setattr(settings, "face_model_base_url", "")
    models._manifest.cache_clear()
    yield {"dir": model_dir, "manifest": manifest}
    models._manifest.cache_clear()


def test_model_matching_manifest_loads(model_env: dict) -> None:
    target = model_env["dir"] / "fake.onnx"
    model_env["dir"].mkdir()
    target.write_bytes(CONTENT)
    assert models.model_path("fake.onnx") == target


def test_tampered_model_refused(model_env: dict) -> None:
    target = model_env["dir"] / "fake.onnx"
    model_env["dir"].mkdir()
    target.write_bytes(b"backdoored weights")
    with pytest.raises(ModelIntegrityError, match="Integrity check failed"):
        models.model_path("fake.onnx")


def test_missing_manifest_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "manifest_path", str(tmp_path / "none.json"))
    monkeypatch.setattr(settings, "biometrics_model_dir", str(tmp_path / "m"))
    models._manifest.cache_clear()
    try:
        with pytest.raises(ModelNotAvailable, match="manifest missing"):
            models.model_path("fake.onnx")
    finally:
        models._manifest.cache_clear()


def test_model_not_in_manifest_refused(model_env: dict) -> None:
    model_env["dir"].mkdir()
    (model_env["dir"] / "rogue.onnx").write_bytes(CONTENT)
    with pytest.raises(ModelNotAvailable, match="not in the approved manifest"):
        models.model_path("rogue.onnx")


def test_partial_part_file_never_loaded(model_env: dict) -> None:
    model_env["dir"].mkdir()
    (model_env["dir"] / "fake.onnx.part").write_bytes(CONTENT)
    with pytest.raises(ModelNotAvailable):
        models.model_path("fake.onnx", download=False)


def _fake_stream(payload: bytes):
    class _Resp:
        def raise_for_status(self) -> None:
            pass

        def iter_bytes(self):
            yield payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    return lambda *a, **k: _Resp()


def test_verified_download_installs_atomically(
    model_env: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.engines.providers.models.httpx.stream", _fake_stream(CONTENT))
    path = models.fetch_model("fake.onnx", url="https://models.test/fake.onnx")
    assert path.read_bytes() == CONTENT
    assert not (model_env["dir"] / "fake.onnx.part").exists()


def test_corrupted_download_never_installed(
    model_env: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.engines.providers.models.httpx.stream", _fake_stream(b"wrong bytes"))
    with pytest.raises(ModelIntegrityError):
        models.fetch_model("fake.onnx", url="https://models.test/fake.onnx")
    assert not (model_env["dir"] / "fake.onnx").exists()
    assert not (model_env["dir"] / "fake.onnx.part").exists()


def test_interrupted_download_leaves_nothing_loadable(
    model_env: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_stream(*a, **k):
        raise ConnectionError("link dropped")

    monkeypatch.setattr("app.engines.providers.models.httpx.stream", broken_stream)
    with pytest.raises(ConnectionError):
        models.fetch_model("fake.onnx", url="https://models.test/fake.onnx")
    assert not (model_env["dir"] / "fake.onnx").exists()
    assert not (model_env["dir"] / "fake.onnx.part").exists()


def test_manifest_update_authorizes_new_version(model_env: dict) -> None:
    new_content = b"FAKE-ONNX-WEIGHTS-v2"
    new_sha = hashlib.sha256(new_content).hexdigest()
    model_env["manifest"].write_text(
        json.dumps({"models": {"fake.onnx": {"sha256": new_sha, "source": "t", "version": "2"}}})
    )
    models._manifest.cache_clear()
    model_env["dir"].mkdir()
    target = model_env["dir"] / "fake.onnx"
    target.write_bytes(new_content)
    assert models.model_path("fake.onnx") == target
    # …and the previous version is now refused.
    target.write_bytes(CONTENT)
    with pytest.raises(ModelIntegrityError):
        models.model_path("fake.onnx")
