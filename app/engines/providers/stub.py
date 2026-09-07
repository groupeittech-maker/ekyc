"""Deterministic providers used for development, tests and demos.

They implement the same contracts as the production providers so the engines,
the policy layer and the evidence chain can be exercised end to end without
any external OCR / biometric vendor. Scores are derived from the payload so a
given input always yields the same decision.

Test/demo payloads may embed directives (``FACE_MATCH_FAIL``, ``LIVENESS_FAIL``,
``DOC_FAIL``) to exercise the failure branches.
"""

from __future__ import annotations

import hashlib
from datetime import date, timedelta

from app.engines.providers.base import (
    DocumentAuthenticityResult,
    FaceProvider,
    FaceResult,
    OcrProvider,
    OcrResult,
)
from app.engines.providers.mrz import find_mrz, parse_td3


def _score_from(data: bytes, salt: str, low: float, high: float) -> float:
    digest = hashlib.sha256(salt.encode() + data).digest()
    ratio = int.from_bytes(digest[:4], "big") / 0xFFFFFFFF
    return round(low + ratio * (high - low), 4)


def _as_text(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore")


class StubOcrProvider(OcrProvider):
    name = "stub"

    def extract(self, image: bytes, document_type: str) -> OcrResult:
        text = _as_text(image)
        mrz = find_mrz(text)
        if mrz:
            fields = parse_td3(*mrz)
            fields["document_type"] = document_type
            return OcrResult(
                fields=fields,
                raw_text=text,
                confidence=0.99 if fields["checks_passed"] else 0.55,
                provider=self.name,
            )

        digest = hashlib.sha256(image).hexdigest().upper()
        birth = date(1985, 1, 1) + timedelta(days=int(digest[:4], 16) % 10000)
        fields = {
            "document_type": document_type,
            "first_name": "JOHN",
            "last_name": "DOE",
            "date_of_birth": birth.isoformat(),
            "document_number": digest[:9],
            "nationality": "CG",
            "issuing_country": "CG",
            "sex": "M",
            "expiry_date": (date.today() + timedelta(days=1500)).isoformat(),
            "checks": {},
            "checks_passed": True,
        }
        return OcrResult(
            fields=fields,
            raw_text="",
            confidence=_score_from(image, "ocr", 0.75, 0.98),
            provider=self.name,
        )

    def check_authenticity(self, image: bytes, ocr: OcrResult) -> DocumentAuthenticityResult:
        text = _as_text(image)
        if "DOC_FAIL" in text:
            return DocumentAuthenticityResult(
                authentic=False,
                confidence=0.1,
                signals={"reason": "TEST_DIRECTIVE"},
                provider=self.name,
            )
        confidence = _score_from(image, "authenticity", 0.82, 0.99)
        if not ocr.fields.get("checks_passed", True):
            confidence = min(confidence, 0.45)
        return DocumentAuthenticityResult(
            authentic=confidence >= 0.6,
            confidence=confidence,
            signals={"mrz_checks_passed": ocr.fields.get("checks_passed")},
            provider=self.name,
        )


class StubFaceProvider(FaceProvider):
    name = "stub"

    def liveness(self, selfie: bytes) -> FaceResult:
        if "LIVENESS_FAIL" in _as_text(selfie):
            return FaceResult(score=0.05, provider=self.name, details={"reason": "TEST_DIRECTIVE"})
        return FaceResult(score=_score_from(selfie, "liveness", 0.75, 0.99), provider=self.name)

    def match(self, selfie: bytes, document_image: bytes) -> FaceResult:
        if "FACE_MATCH_FAIL" in _as_text(selfie):
            return FaceResult(score=0.12, provider=self.name, details={"reason": "TEST_DIRECTIVE"})
        return FaceResult(
            score=_score_from(selfie + document_image, "face_match", 0.82, 0.99),
            provider=self.name,
        )
