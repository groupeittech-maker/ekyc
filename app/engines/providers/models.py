"""Local ONNX model provisioning for the in-house biometric module.

Models are stored on disk under ``EKYC_BIOMETRICS_MODEL_DIR`` and loaded once.
Nothing calls a third-party inference API at runtime: the ONNX graphs are
executed locally by OpenCV. The optional download helper only fetches the model
weights once (from a configurable, self-hostable base URL) so an air-gapped
deployment can drop the files in manually instead.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from app.core.config import settings


class ModelNotAvailable(RuntimeError):
    """Raised when an ONNX model file is missing and cannot be provisioned."""


def model_dir() -> Path:
    path = Path(settings.biometrics_model_dir).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def model_path(model_ref: str, *, download: bool = False) -> Path:
    """Local path for a model, referenced by its Zoo-relative path.

    Files are cached flat (by basename) under the model directory; ``model_ref``
    may include the Zoo sub-folder, which is only used to build the download URL.
    """
    path = model_dir() / Path(model_ref).name
    if path.exists():
        return path
    if download and settings.face_model_base_url:
        fetch_model(model_ref)
        if path.exists():
            return path
    raise ModelNotAvailable(
        f"Model '{Path(model_ref).name}' not found in {model_dir()}. "
        f"Run `python -m scripts.fetch_models` or place the file manually."
    )


def fetch_model(model_ref: str) -> Path:
    """Download a single model file (by Zoo-relative path) to the local cache."""
    base = settings.face_model_base_url.rstrip("/")
    url = f"{base}/{model_ref}"
    destination = model_dir() / Path(model_ref).name
    with httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as response:
        response.raise_for_status()
        tmp = destination.with_suffix(destination.suffix + ".part")
        with tmp.open("wb") as handle:
            for chunk in response.iter_bytes():
                handle.write(chunk)
        tmp.replace(destination)
    return destination
