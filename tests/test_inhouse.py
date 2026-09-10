from __future__ import annotations

import pytest

from app.engines.providers.inhouse import liveness_score, normalize_cosine


def test_normalize_cosine_calibration() -> None:
    # Below the reject band -> 0, above the accept band -> 1, linear in between.
    assert normalize_cosine(0.10) == 0.0
    assert normalize_cosine(0.55) == 1.0
    assert normalize_cosine(0.90) == 1.0
    mid = normalize_cosine(0.40)
    assert 0.0 < mid < 1.0


def test_liveness_score_rewards_sharp_large_faces() -> None:
    strong = liveness_score(sharpness=400.0, face_ratio=0.30, saturation_std=60.0)
    weak = liveness_score(sharpness=5.0, face_ratio=0.01, saturation_std=2.0)

    assert strong > 0.8
    assert weak < 0.2
    assert strong > weak


def test_liveness_score_is_bounded() -> None:
    assert 0.0 <= liveness_score(0.0, 0.0, 0.0) <= 1.0
    assert 0.0 <= liveness_score(1e6, 1.0, 255.0) <= 1.0


def _cv_and_models_available() -> bool:
    try:
        import cv2  # noqa: F401
    except Exception:
        return False
    from pathlib import Path

    from app.core.config import settings
    from app.engines.providers.models import model_dir

    return all(
        (model_dir() / Path(ref).name).exists()
        for ref in (settings.face_detector_model, settings.face_recognizer_model)
    )


@pytest.mark.skipif(not _cv_and_models_available(), reason="OpenCV and ONNX models not provisioned")
def test_inhouse_liveness_runs_and_reports_no_face_on_blank() -> None:
    import cv2
    import numpy as np

    from app.engines.providers.inhouse import InHouseFaceProvider

    _, buffer = cv2.imencode(".png", np.full((240, 320, 3), 127, np.uint8))
    result = InHouseFaceProvider().liveness(buffer.tobytes())

    assert result.provider == "inhouse"
    assert result.score == 0.0
    assert result.details["reason"] == "NO_FACE"
