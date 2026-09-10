"""In-house anti-spoofing provider using a local MiniFAS ONNX model.

Runs a 128×128 RGB face crop through the MiniFAS network and returns a
liveness score in [0, 1]. Higher means more likely to be a real, live face.

The ONNX Runtime import is deferred to ``__init__`` so the module can be
imported even when ``onnxruntime`` is not installed; the in-house face
provider will simply fall back to heuristic liveness in that case.
"""

from __future__ import annotations

import numpy as np

from app.core.config import settings
from app.engines.providers.models import model_path

_MODEL_IMG_SIZE = 128


def crop_face(image: np.ndarray, bbox: np.ndarray, expansion: float = 1.5) -> np.ndarray:
    """Extract a square face crop with reflection padding when near image edges."""
    import cv2

    h, w = image.shape[:2]
    x, y, bw, bh = bbox[:4].astype(float)
    cx, cy = x + bw / 2.0, y + bh / 2.0
    size = int(max(bw, bh) * expansion)
    x1 = int(cx - size / 2.0)
    y1 = int(cy - size / 2.0)
    x2, y2 = x1 + size, y1 + size

    top = max(0, -y1)
    left = max(0, -x1)
    bottom = max(0, y2 - h)
    right = max(0, x2 - w)

    crop = image[max(0, y1) : min(h, y2), max(0, x1) : min(w, x2)]
    return cv2.copyMakeBorder(crop, top, bottom, left, right, cv2.BORDER_REFLECT_101)


class AntiSpoofProvider:
    name = "minifas"

    def __init__(self) -> None:
        import onnxruntime as ort

        path = model_path(settings.antispoof_model, download=False)
        self._session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        self._input_name = self._session.get_inputs()[0].name

    def predict(self, face_crop: np.ndarray) -> dict[str, float]:
        """Return liveness score and supporting diagnostics for a BGR face crop."""
        import cv2

        img = cv2.resize(face_crop, (_MODEL_IMG_SIZE, _MODEL_IMG_SIZE))
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        img = img.transpose(2, 0, 1).astype(np.float32) / 255.0
        batch = np.expand_dims(img, axis=0)

        logits = self._session.run(None, {self._input_name: batch})[0][0]
        real_logit = float(logits[0])
        spoof_logit = float(logits[1])
        logit_diff = real_logit - spoof_logit
        # Soft-ish mapping of logit diff to a [0,1] probability-like score.
        real_score = 1.0 / (1.0 + float(np.exp(-logit_diff)))
        return {
            "is_real": logit_diff >= settings.antispoof_threshold,
            "real_score": real_score,
            "logit_diff": logit_diff,
            "real_logit": real_logit,
            "spoof_logit": spoof_logit,
        }
