"""In-house biometric and OCR providers — self-hosted, no third-party SaaS.

Face detection and recognition run locally through OpenCV's ONNX runtime
(YuNet detector + SFace recognizer). Liveness is a passive, explainable
heuristic combining sharpness, face size and colour richness; an ONNX
anti-spoofing model can be layered on the same interface later.

The heavy dependencies (``opencv-python-headless``, ``numpy``) are optional and
only imported when this provider is selected, so the default stub build stays
lightweight.
"""

from __future__ import annotations

import io
from typing import Any

from app.core.config import settings
from app.engines.providers import antispoof as _antispoof
from app.engines.providers.base import (
    DocumentAuthenticityResult,
    FaceProvider,
    FaceResult,
    OcrProvider,
    OcrResult,
)
from app.engines.providers.models import model_path
from app.engines.providers.mrz import find_mrz, parse_td3


# --------------------------------------------------------------------------- #
# Pure scoring helpers (no OpenCV) — unit-testable in isolation.
# --------------------------------------------------------------------------- #
def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def normalize_cosine(cosine: float) -> float:
    """Map an SFace cosine similarity to a calibrated [0,1] match score."""
    reject = settings.face_match_cos_reject
    accept = settings.face_match_cos_accept
    if accept <= reject:
        return _clamp(cosine)
    return round(_clamp((cosine - reject) / (accept - reject)), 4)


def liveness_score(sharpness: float, face_ratio: float, saturation_std: float) -> float:
    """Combine passive signals into a [0,1] liveness confidence.

    * ``sharpness``  — variance of the Laplacian (blurry captures score low).
    * ``face_ratio`` — face area / image area (tiny faces are suspicious).
    * ``saturation_std`` — colour spread (flat greyscale printouts score low).
    """
    sharp = _clamp(sharpness / max(settings.liveness_min_sharpness * 2.5, 1.0))
    size = _clamp(face_ratio / max(settings.liveness_min_face_ratio * 2.0, 1e-6))
    colour = _clamp(saturation_std / 45.0)
    # Sharpness and a real face dominate; colour is a lighter anti-print signal.
    return round(_clamp(0.5 * sharp + 0.35 * size + 0.15 * colour), 4)


# --------------------------------------------------------------------------- #
# OpenCV-backed engine, loaded lazily and cached.
# --------------------------------------------------------------------------- #
class _CvEngine:
    _instance: _CvEngine | None = None

    def __init__(self) -> None:
        import cv2  # noqa: F401  (validate availability early)

        self.cv2 = cv2
        self._detector = None
        self._recognizer = None

    @classmethod
    def instance(cls) -> _CvEngine:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def detector(self):
        if self._detector is None:
            path = model_path(settings.face_detector_model, download=True)
            self._detector = self.cv2.FaceDetectorYN.create(
                str(path), "", (320, 320), 0.7, 0.3, 5000
            )
        return self._detector

    def recognizer(self):
        if self._recognizer is None:
            path = model_path(settings.face_recognizer_model, download=True)
            self._recognizer = self.cv2.FaceRecognizerSF.create(str(path), "")
        return self._recognizer

    def decode(self, data: bytes):
        import numpy as np

        image = self.cv2.imdecode(np.frombuffer(data, np.uint8), self.cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError("Unreadable image payload")
        return image

    def detect_faces(self, image):
        h, w = image.shape[:2]
        detector = self.detector()
        detector.setInputSize((w, h))
        _, faces = detector.detect(image)
        return faces if faces is not None else []

    def largest_face(self, image, faces):
        best = None
        best_area = 0.0
        for face in faces:
            area = float(face[2]) * float(face[3])
            if area > best_area:
                best_area, best = area, face
        return best, best_area

    def sharpness(self, image) -> float:
        gray = self.cv2.cvtColor(image, self.cv2.COLOR_BGR2GRAY)
        return float(self.cv2.Laplacian(gray, self.cv2.CV_64F).var())

    def saturation_std(self, image) -> float:
        hsv = self.cv2.cvtColor(image, self.cv2.COLOR_BGR2HSV)
        return float(hsv[:, :, 1].std())

    def embedding(self, image, face):
        recognizer = self.recognizer()
        aligned = recognizer.alignCrop(image, face)
        return recognizer.feature(aligned)

    def cosine(self, feat_a, feat_b) -> float:
        recognizer = self.recognizer()
        return float(recognizer.match(feat_a, feat_b, self.cv2.FaceRecognizerSF_FR_COSINE))


class InHouseFaceProvider(FaceProvider):
    name = "inhouse"

    def __init__(self) -> None:
        self._antispoof = None
        self._antispoof_failed = False

    def _load_antispoof(self):
        if self._antispoof is not None or self._antispoof_failed:
            return self._antispoof
        try:
            self._antispoof = _antispoof.AntiSpoofProvider()
        except Exception:
            self._antispoof_failed = True
        return self._antispoof

    def liveness(self, selfie: bytes) -> FaceResult:
        engine = _CvEngine.instance()
        image = engine.decode(selfie)
        faces = engine.detect_faces(image)
        if len(faces) == 0:
            return FaceResult(score=0.0, provider=self.name, details={"reason": "NO_FACE"})
        best_face, area = engine.largest_face(image, faces)
        h, w = image.shape[:2]
        face_ratio = area / float(w * h)
        sharpness = engine.sharpness(image)
        saturation = engine.saturation_std(image)
        heuristic = liveness_score(sharpness, face_ratio, saturation)

        antispoof = self._load_antispoof()
        if antispoof is not None:
            crop = _antispoof.crop_face(image, best_face)
            prediction = antispoof.predict(crop)
            # Anti-spoofing dominates, but image-quality heuristics keep a small voice.
            score = round(0.85 * prediction["real_score"] + 0.15 * heuristic, 4)
            details = {
                "faces": int(len(faces)),
                "sharpness": round(sharpness, 2),
                "face_ratio": round(face_ratio, 4),
                "saturation_std": round(saturation, 2),
                "antispoof_score": round(prediction["real_score"], 4),
                "heuristic": round(heuristic, 4),
            }
        else:
            score = heuristic
            details = {
                "faces": int(len(faces)),
                "sharpness": round(sharpness, 2),
                "face_ratio": round(face_ratio, 4),
                "saturation_std": round(saturation, 2),
                "antispoof": "unavailable",
            }

        return FaceResult(score=score, provider=self.name, details=details)

    def match(self, selfie: bytes, document_image: bytes) -> FaceResult:
        engine = _CvEngine.instance()
        selfie_img = engine.decode(selfie)
        doc_img = engine.decode(document_image)

        selfie_faces = engine.detect_faces(selfie_img)
        doc_faces = engine.detect_faces(doc_img)
        if len(selfie_faces) == 0 or len(doc_faces) == 0:
            reason = "NO_FACE_IN_SELFIE" if len(selfie_faces) == 0 else "NO_FACE_IN_DOCUMENT"
            return FaceResult(score=0.0, provider=self.name, details={"reason": reason})

        selfie_face, _ = engine.largest_face(selfie_img, selfie_faces)
        doc_face, _ = engine.largest_face(doc_img, doc_faces)
        cosine = engine.cosine(
            engine.embedding(selfie_img, selfie_face),
            engine.embedding(doc_img, doc_face),
        )
        return FaceResult(
            score=normalize_cosine(cosine),
            provider=self.name,
            details={"cosine": round(cosine, 4)},
        )


class InHouseOcrProvider(OcrProvider):
    """OCR via Tesseract with OpenCV preprocessing and real authenticity signals."""

    name = "inhouse"

    def _preprocess(self, image: bytes):
        engine = _CvEngine.instance()
        img = engine.decode(image)
        gray = engine.cv2.cvtColor(img, engine.cv2.COLOR_BGR2GRAY)
        return img, gray

    def extract(self, image: bytes, document_type: str) -> OcrResult:
        import pytesseract
        from PIL import Image

        text = pytesseract.image_to_string(Image.open(io.BytesIO(image)))
        mrz = find_mrz(text)
        if mrz:
            fields = parse_td3(*mrz)
            fields["document_type"] = document_type
            return OcrResult(
                fields=fields,
                raw_text=text,
                confidence=0.95 if fields["checks_passed"] else 0.4,
                provider=self.name,
            )
        return OcrResult(fields={}, raw_text=text, confidence=0.0, provider=self.name)

    def check_authenticity(self, image: bytes, ocr: OcrResult) -> DocumentAuthenticityResult:
        engine = _CvEngine.instance()
        img, _ = self._preprocess(image)
        sharpness = engine.sharpness(img)
        faces = engine.detect_faces(img)
        mrz_ok = bool(ocr.fields.get("checks_passed"))

        signals: dict[str, Any] = {
            "sharpness": round(sharpness, 2),
            "portrait_detected": bool(len(faces) > 0),
            "mrz_checks_passed": mrz_ok,
            "mrz_checks": ocr.fields.get("checks"),
        }
        # Weighted evidence: MRZ integrity dominates, then a legible portrait,
        # then overall capture sharpness.
        confidence = (
            (0.6 if mrz_ok else 0.0)
            + (0.25 if len(faces) > 0 else 0.0)
            + 0.15 * _clamp(sharpness / (settings.liveness_min_sharpness * 2.0))
        )
        confidence = round(_clamp(confidence), 4)
        return DocumentAuthenticityResult(
            authentic=confidence >= 0.6,
            confidence=confidence,
            signals=signals,
            provider=self.name,
        )
