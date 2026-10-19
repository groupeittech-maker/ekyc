"""Download the MiniFAS face anti-spoofing ONNX model.

Usage:
    python -m scripts.fetch_antispoof
"""

from __future__ import annotations

from app.core.config import settings
from app.engines.providers.models import fetch_model, model_dir

SOURCE_URL = (
    "https://raw.githubusercontent.com/facenox/face-antispoof-onnx/main/"
    "models/best_model_quantized.onnx"
)


def main() -> None:
    destination = model_dir() / settings.antispoof_model
    if destination.exists():
        print(f"  = {destination.name} already present")
        return

    print(f"  + downloading {destination.name} ...")
    fetch_model(settings.antispoof_model, url=SOURCE_URL)  # verified + atomic
    print(f"    saved to {destination}")


if __name__ == "__main__":
    main()
