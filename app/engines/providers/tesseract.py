"""OCR provider backed by Tesseract (install the ``ocr`` extra to use it)."""

from __future__ import annotations

import io

from app.engines.providers.base import DocumentAuthenticityResult, OcrProvider, OcrResult
from app.engines.providers.mrz import find_mrz, parse_td3


class TesseractOcrProvider(OcrProvider):
    name = "tesseract"

    def extract(self, image: bytes, document_type: str) -> OcrResult:
        import pytesseract
        from PIL import Image

        text = pytesseract.image_to_string(Image.open(io.BytesIO(image)))
        mrz = find_mrz(text)
        if not mrz:
            return OcrResult(fields={}, raw_text=text, confidence=0.0, provider=self.name)
        fields = parse_td3(*mrz)
        fields["document_type"] = document_type
        return OcrResult(
            fields=fields,
            raw_text=text,
            confidence=0.95 if fields["checks_passed"] else 0.4,
            provider=self.name,
        )

    def check_authenticity(self, image: bytes, ocr: OcrResult) -> DocumentAuthenticityResult:
        checks_passed = bool(ocr.fields.get("checks_passed"))
        confidence = 0.9 if checks_passed else 0.3
        return DocumentAuthenticityResult(
            authentic=checks_passed,
            confidence=confidence,
            signals={"mrz_checks": ocr.fields.get("checks", {})},
            provider=self.name,
        )
