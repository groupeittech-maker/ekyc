"""Download the MiniFAS face anti-spoofing ONNX model.

Usage:
    python -m scripts.fetch_antispoof
"""

from __future__ import annotations

import httpx

from app.core.config import settings
from app.engines.providers.models import model_dir

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
    with httpx.stream("GET", SOURCE_URL, follow_redirects=True, timeout=120.0) as response:
        response.raise_for_status()
        tmp = destination.with_suffix(destination.suffix + ".part")
        with tmp.open("wb") as handle:
            for chunk in response.iter_bytes():
                handle.write(chunk)
        tmp.replace(destination)
    print(f"    saved to {destination}")


if __name__ == "__main__":
    main()
