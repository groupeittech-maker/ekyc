"""Local ONNX model provisioning for the in-house biometric module.

Models are stored on disk under ``EKYC_BIOMETRICS_MODEL_DIR`` and loaded once.
Nothing calls a third-party inference API at runtime: the ONNX graphs are
executed locally by OpenCV. The optional download helper only fetches the model
weights once (from a configurable, self-hostable base URL) so an air-gapped
deployment can drop the files in manually instead.

Integrity (R9): every model loaded or downloaded must match the *approved
manifest* (``models_manifest.json``, shipped with the package — the checksum
never comes from the download source itself). Downloads go to a ``.part``
file, are verified, then atomically replaced; a partially downloaded file is
never loaded and a tampered file is refused at load time.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

import httpx

from app.core.config import settings


class ModelNotAvailable(RuntimeError):
    """Raised when a model file is missing, unapproved or fails integrity."""


class ModelIntegrityError(ModelNotAvailable):
    """Raised when a model file does not match the approved manifest."""


def _manifest_path() -> Path:
    if settings.manifest_path:
        return Path(settings.manifest_path).expanduser()
    return Path(__file__).parent / "models_manifest.json"


@lru_cache
def _manifest() -> dict:
    path = _manifest_path()
    if not path.exists():
        raise ModelNotAvailable(
            f"Approved model manifest missing at {path} — refusing to load or "
            "download any model without a trusted checksum reference."
        )
    return json.loads(path.read_text(encoding="utf-8")).get("models", {})


def _expected_sha256(model_ref: str) -> str:
    entry = _manifest().get(Path(model_ref).name)
    if entry is None or not entry.get("sha256"):
        raise ModelNotAvailable(
            f"Model '{Path(model_ref).name}' is not in the approved manifest — "
            "only reviewed models may be loaded or downloaded."
        )
    return entry["sha256"]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_model(path: Path, expected_sha256: str) -> None:
    """Refuse a file that does not match the approved checksum."""
    actual = _sha256_file(path)
    if actual != expected_sha256:
        raise ModelIntegrityError(
            f"Integrity check failed for '{path.name}': the file does not match "
            "the approved manifest (possible corruption or tampering) — it is "
            "refused and will NOT be loaded."
        )


def model_dir() -> Path:
    path = Path(settings.biometrics_model_dir).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def model_path(model_ref: str, *, download: bool = False) -> Path:
    """Local path for a model, referenced by its Zoo-relative path.

    Files are cached flat (by basename) under the model directory; ``model_ref``
    may include the Zoo sub-folder, which is only used to build the download URL.
    The returned file is guaranteed to match the approved manifest.
    """
    expected = _expected_sha256(model_ref)  # fails closed on unknown models
    path = model_dir() / Path(model_ref).name
    if path.exists():
        verify_model(path, expected)  # a tampered/partial file is never loaded
        return path
    if download and settings.face_model_base_url:
        fetch_model(model_ref)
        verify_model(path, expected)
        return path
    raise ModelNotAvailable(
        f"Model '{Path(model_ref).name}' not found in {model_dir()}. "
        f"Run `python -m scripts.fetch_models` or place the file manually."
    )


def fetch_model(model_ref: str, *, url: str | None = None) -> Path:
    """Download a model file, verify it, then atomically install it.

    The ``.part`` staging file is checksummed *before* replacing the
    destination — an interrupted or corrupted download is never installed.
    """
    expected = _expected_sha256(model_ref)
    base = settings.face_model_base_url.rstrip("/")
    url = url or f"{base}/{model_ref}"
    destination = model_dir() / Path(model_ref).name
    tmp = destination.with_suffix(destination.suffix + ".part")
    try:
        with httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as response:
            response.raise_for_status()
            with tmp.open("wb") as handle:
                for chunk in response.iter_bytes():
                    handle.write(chunk)
        verify_model(tmp, expected)
    except Exception:
        tmp.unlink(missing_ok=True)  # never leave an unverified blob behind
        raise
    tmp.replace(destination)  # atomic install of a verified file
    return destination
