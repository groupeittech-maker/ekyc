"""In-house biometric and OCR providers — self-hosted, no third-party SaaS.

Face detection and recognition run locally through OpenCV's ONNX runtime
(YuNet detector + SFace recognizer). Liveness is a passive, explainable
heuristic combining sharpness, face size and colour richness; an ONNX
anti-spoofing model can be layered on the same interface later.

GPU note: ``cv2.FaceDetectorYN`` / ``cv2.FaceRecognizerSF`` do not expose a
backend selector, so they always run on CPU unless OpenCV is rebuilt with
CUDA DNN support. Both models are small (YuNet ~230 KB, SFace ~37 MB) and
stay fast on CPU; the GPU payoff goes through ONNX Runtime providers
(anti-spoofing today — see ``providers/runtime.py`` for auto-detection).

The heavy dependencies (``opencv-python-headless``, ``numpy``) are optional and
only imported when this provider is selected, so the default stub build stays
lightweight.
"""

from __future__ import annotations

import io
import logging
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
from app.engines.providers.mrz import find_mrz, parse_mrz

logger = logging.getLogger(__name__)


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

    # YuNet reliably finds faces that fill most of the frame only below this
    # long-side size — a phone front camera selfie (1280+) with a close face
    # otherwise returns zero detections and the capture is wrongly rejected.
    _DETECT_LONG_SIDE = 640

    def detect_faces(self, image):
        h, w = image.shape[:2]
        detector = self.detector()
        long_side = max(h, w)
        probes = [self._DETECT_LONG_SIDE / long_side] if long_side > self._DETECT_LONG_SIDE else []
        probes.append(1.0)  # native last: keeps small faces in large frames
        for scale in probes:
            frame = (
                image
                if scale == 1.0
                else self.cv2.resize(image, None, fx=scale, fy=scale)
            )
            fh, fw = frame.shape[:2]
            detector.setInputSize((fw, fh))
            _, faces = detector.detect(frame)
            if faces is None or len(faces) == 0:
                continue
            if scale != 1.0:
                # Columns 0..13 are box + landmark coordinates (col 14 is the score).
                faces = faces.copy()
                faces[:, :14] /= scale
            return list(faces)
        return []

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
        """Fail-closed: without the anti-spoofing model, a sharp printed photo
        can defeat the heuristic — in production the provider must not silently
        degrade; the task fails permanently and the check goes to REVIEW."""
        if self._antispoof is not None or self._antispoof_failed:
            return self._antispoof
        try:
            self._antispoof = _antispoof.AntiSpoofProvider()
        except Exception:
            self._antispoof_failed = True
            if settings.environment == "production":
                logger.exception("anti-spoofing model unavailable — refusing heuristic liveness")
                raise
            logger.warning("anti-spoofing model unavailable — heuristic liveness only (dev)")
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

    @staticmethod
    def _preprocess_for_mrz(gray):
        """Enhance a grayscale image for TD3 MRZ reading."""
        engine = _CvEngine.instance()
        # Scale to a comfortable OCR width without distorting the MRZ too much.
        scale = 1300 / max(gray.shape[1], 1)
        if scale < 0.5 or scale > 2.0:
            new_size = (int(gray.shape[1] * scale), int(gray.shape[0] * scale))
            gray = engine.cv2.resize(gray, new_size, interpolation=engine.cv2.INTER_CUBIC)
        clahe = engine.cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        # Otsu gives a clean binary; we also return the enhanced gray as fallback.
        _, binary = engine.cv2.threshold(
            enhanced, 0, 255, engine.cv2.THRESH_BINARY + engine.cv2.THRESH_OTSU
        )
        return binary, enhanced

    def _read_mrz(self, image: bytes):
        import pytesseract
        from PIL import Image

        engine = _CvEngine.instance()
        img = engine.decode(image)
        gray = engine.cv2.cvtColor(img, engine.cv2.COLOR_BGR2GRAY)
        binary, _ = self._preprocess_for_mrz(gray)

        # Constrain Tesseract to the MRZ character set and line layout.
        tesseract_config = (
            "--psm 6 -c tessedit_char_whitelist=" "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<"
        )
        text = pytesseract.image_to_string(Image.fromarray(binary), config=tesseract_config)
        mrz = find_mrz(text)
        if not mrz:
            # Fallback: try the original image with a more permissive layout.
            text = pytesseract.image_to_string(Image.open(io.BytesIO(image)))
            mrz = find_mrz(text)
        return mrz, text

    def extract(self, image: bytes, document_type: str) -> OcrResult:
        mrz, text = self._read_mrz(image)
        if mrz:
            fields = parse_mrz(mrz)
            fields["document_type"] = document_type
            return OcrResult(
                fields=fields,
                raw_text=text,
                confidence=0.95 if fields["checks_passed"] else 0.4,
                provider=self.name,
            )
        return OcrResult(fields={}, raw_text=text, confidence=0.0, provider=self.name)

    @staticmethod
    def _moire_signals(image: bytes) -> dict[str, float]:
        """Screen-recapture (moiré) detection via FFT.

        Photographing a screen leaves strong periodic high-frequency peaks
        (the pixel grid); an original document photograph is spectrally
        smoother. Returns ``moire_score`` in [0,1] — higher = cleaner.
        """
        import numpy as np

        engine = _CvEngine.instance()
        try:
            img = engine.decode(image)
        except ValueError:
            return {"moire_peaks": 0, "moire_score": 0.5}
        gray = engine.cv2.cvtColor(img, engine.cv2.COLOR_BGR2GRAY)
        gray = engine.cv2.resize(gray, (512, 512)).astype(np.float32)

        spectrum = np.log1p(np.abs(np.fft.fftshift(np.fft.fft2(gray))))
        h = spectrum.shape[0]
        y, x = np.ogrid[:h, :h]
        center = h // 2
        radius = np.sqrt((x - center) ** 2 + (y - center) ** 2)
        # Periodic screen grids live in the mid/high frequency ring.
        ring = spectrum[(radius > h * 0.12) & (radius < h * 0.45)]
        if ring.size == 0:
            return {"moire_peaks": 0, "moire_score": 0.5}
        mean, std = float(ring.mean()), float(ring.std()) or 1.0
        peaks = float((ring > mean + 5.5 * std).sum())
        # Empirical: a clean capture has < ~40 strong periodic peaks.
        suspicion = _clamp(peaks / 40.0)
        return {"moire_peaks": int(peaks), "moire_score": round(1.0 - suspicion, 4)}

    @staticmethod
    def _viz_signals(ocr: OcrResult) -> dict[str, bool]:
        """MRZ / visual-inspection-zone cross-check.

        The MRZ is trivial to forge with valid check digits; the same data
        must also appear in the printed zone (names, document number).
        Missing raw text (single-side capture that already carried the MRZ)
        is not penalised.
        """
        raw = (ocr.raw_text or "").upper()
        if not raw or not ocr.fields.get("checks_passed"):
            return {}
        surname = (ocr.fields.get("last_name") or "").upper().strip()
        doc_number = (ocr.fields.get("document_number") or "").upper().strip()
        signals: dict[str, bool] = {}
        if surname:
            signals["viz_surname_present"] = surname in raw
        if doc_number:
            signals["viz_doc_number_present"] = doc_number in raw
        return signals

    def _ela_signals(self, image: bytes) -> dict[str, float]:
        """Error Level Analysis: high residual on a re-saved JPEG can reveal editing.

        Returns a low score (0..1) when the image is very likely a re-saved or
        screen-captured composite, and a high score when it looks like an original.
        """
        from PIL import Image

        try:
            original = Image.open(io.BytesIO(image))
        except Exception:
            return {"ela_mean": 0.0, "ela_score": 0.5}

        if original.format != "JPEG":
            # ELA is only meaningful for JPEG originals.
            return {"ela_mean": 0.0, "ela_score": 0.5}

        import numpy as np

        # Re-save at a fixed quality and measure the per-pixel difference.
        resaved = io.BytesIO()
        original.save(resaved, format="JPEG", quality=90)
        resaved.seek(0)
        resaved_img = Image.open(resaved).convert("RGB")
        original_rgb = original.convert("RGB")

        original_arr = np.array(original_rgb, dtype=np.float32)
        resaved_arr = np.array(resaved_img, dtype=np.float32)
        diff = np.abs(original_arr - resaved_arr)
        ela_mean = float(np.mean(diff))

        # Empirical: very clean originals sit below ~2; heavy re-saves/screenshots
        # can climb to 20+. Anything above 8 is treated as suspicious.
        suspicious = max(0.0, min(1.0, (ela_mean - 2.0) / 8.0))
        return {"ela_mean": round(ela_mean, 2), "ela_score": round(1.0 - suspicious, 4)}

    def check_authenticity(self, image: bytes, ocr: OcrResult) -> DocumentAuthenticityResult:
        engine = _CvEngine.instance()
        img, _ = self._preprocess(image)
        sharpness = engine.sharpness(img)
        faces = engine.detect_faces(img)
        mrz_found = bool(ocr.fields) and ocr.fields.get("mrz_side", -1) >= 0
        mrz_ok = bool(ocr.fields.get("checks_passed"))
        ela = self._ela_signals(image)
        moire = self._moire_signals(image)
        viz = self._viz_signals(ocr)
        # VIZ cross-check only helps when the reference text was searchable.
        viz_score = (sum(viz.values()) / len(viz)) if viz else 0.5

        signals: dict[str, Any] = {
            "sharpness": round(sharpness, 2),
            "portrait_detected": bool(len(faces) > 0),
            "mrz_checks_passed": mrz_ok,
            "mrz_checks": ocr.fields.get("checks"),
            **viz,
            **ela,
            **moire,
        }
        # Weighted, explainable evidence — MRZ check digits alone no longer
        # suffice: they are computable by a forger, so the printed zone and
        # screen/capture signals must corroborate.
        confidence = (
            (0.40 if mrz_ok else 0.0)
            + (0.20 if len(faces) > 0 else 0.0)
            + 0.15 * viz_score
            + 0.15 * ela["ela_score"]
            + 0.10 * moire["moire_score"]
        )
        # A parsed MRZ whose check digits FAIL is a red flag (either OCR noise
        # or a hand-typed fake) — it can never look authentic on its own.
        if mrz_found and not mrz_ok:
            confidence = min(confidence, 0.4)
        # A strong moiré pattern caps the score: likely a photo of a screen.
        if moire["moire_peaks"] >= 40:
            confidence = min(confidence, 0.45)
        confidence = round(_clamp(confidence), 4)
        return DocumentAuthenticityResult(
            authentic=confidence >= 0.6,
            confidence=confidence,
            signals=signals,
            provider=self.name,
        )
