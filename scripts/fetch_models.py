"""Provision the in-house biometric ONNX models into the local cache.

Usage:
    python -m scripts.fetch_models

Downloads the YuNet face detector and SFace recognizer from the configured
``EKYC_FACE_MODEL_BASE_URL`` into ``EKYC_BIOMETRICS_MODEL_DIR``. For air-gapped
deployments, copy the two .onnx files into that directory manually instead.
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import settings
from app.engines.providers.models import fetch_model, model_dir


def main() -> None:
    targets = [settings.face_detector_model, settings.face_recognizer_model]
    print(f"Model directory: {model_dir()}")
    for ref in targets:
        destination = model_dir() / Path(ref).name
        if destination.exists():
            print(f"  = {destination.name} already present")
            continue
        print(f"  + downloading {destination.name} ...")
        fetch_model(ref)
        print(f"    saved to {destination}")
    print("Done.")


if __name__ == "__main__":
    main()
