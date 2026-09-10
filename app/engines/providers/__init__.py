from __future__ import annotations

from functools import lru_cache

from app.core.config import settings
from app.engines.providers.base import FaceProvider, OcrProvider, OtpSender
from app.engines.providers.otp_senders import HttpOtpSender, LogOtpSender
from app.engines.providers.stub import StubFaceProvider, StubOcrProvider


@lru_cache
def get_ocr_provider() -> OcrProvider:
    if settings.ocr_provider == "inhouse":
        from app.engines.providers.inhouse import InHouseOcrProvider

        return InHouseOcrProvider()
    if settings.ocr_provider == "tesseract":
        from app.engines.providers.tesseract import TesseractOcrProvider

        return TesseractOcrProvider()
    return StubOcrProvider()


@lru_cache
def get_face_provider() -> FaceProvider:
    if settings.face_provider == "inhouse":
        from app.engines.providers.inhouse import InHouseFaceProvider

        return InHouseFaceProvider()
    return StubFaceProvider()


@lru_cache
def get_otp_sender() -> OtpSender:
    if settings.otp_provider == "http":
        return HttpOtpSender()
    return LogOtpSender()
