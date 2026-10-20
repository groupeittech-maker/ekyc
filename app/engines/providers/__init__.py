"""Engine provider resolution — fail closed, never silently stubbed.

Every engine selects its provider by an *explicit* name through
``EKYC_*_PROVIDER``. Two hard rules:

* an unknown name raises :class:`UnknownProviderError` listing the configured
  providers — a typo in production config can no longer degrade OCR/face/OTP
  to a stub that fabricates results;
* ``stub``/``log`` providers are development-only — selecting them in
  production raises at resolution, even if explicitly configured. Stubs stay
  available for tests and demos because ``environment`` defaults to
  ``development``.

Dependency checks run at selection time: a provider whose runtime
dependencies are missing fails with an actionable message instead of
surfacing as a cryptic ImportError mid-request.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from functools import lru_cache

from app.core.config import settings
from app.engines.providers.base import FaceProvider, OcrProvider, OtpSender
from app.engines.providers.stub import StubFaceProvider, StubOcrProvider


class UnknownProviderError(RuntimeError):
    """Raised when an EKYC_*_PROVIDER name is unknown or forbidden here."""


class ProviderDependencyError(RuntimeError):
    """Raised when a configured provider lacks runtime dependencies."""


_DEV_ONLY = {"stub", "log"}


def _resolve(name: str, registry: dict[str, Callable], kind: str):
    if name not in registry:
        raise UnknownProviderError(
            f"Unknown {kind} provider: {name!r} " f"(configured: {', '.join(sorted(registry))})"
        )
    if settings.environment == "production" and name in _DEV_ONLY:
        raise UnknownProviderError(
            f"The '{name}' {kind} provider is development-only and cannot run in production"
        )
    return registry[name]()


def _inhouse_ocr() -> OcrProvider:
    _require_cv()
    from app.engines.providers.inhouse import InHouseOcrProvider

    return InHouseOcrProvider()


def _inhouse_face() -> FaceProvider:
    _require_cv()
    from app.engines.providers.inhouse import InHouseFaceProvider

    return InHouseFaceProvider()


def _tesseract() -> OcrProvider:
    try:
        import pytesseract  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError as exc:
        raise ProviderDependencyError(
            "tesseract OCR requires the 'ocr' extra (pip install pytesseract Pillow)"
        ) from exc
    if not shutil.which("tesseract"):
        raise ProviderDependencyError(
            "tesseract OCR requires the tesseract binary on PATH " "(apt-get install tesseract-ocr)"
        )
    from app.engines.providers.tesseract import TesseractOcrProvider

    return TesseractOcrProvider()


def _http_otp() -> OtpSender:
    if not settings.otp_http_url:
        raise ProviderDependencyError("http OTP sender requires EKYC_OTP_HTTP_URL to be configured")
    from app.engines.providers.otp_senders import HttpOtpSender

    return HttpOtpSender()


def _oauth_sms_otp() -> OtpSender:
    from app.engines.providers.otp_senders import OAuthSmsOtpSender

    try:
        return OAuthSmsOtpSender()
    except RuntimeError as exc:
        raise ProviderDependencyError(str(exc)) from exc


def _log_otp() -> OtpSender:
    from app.engines.providers.otp_senders import LogOtpSender

    return LogOtpSender()


def _require_cv() -> None:
    try:
        import cv2  # noqa: F401
        import numpy  # noqa: F401
    except ImportError as exc:
        raise ProviderDependencyError(
            "inhouse providers require the 'biometrics' extra " "(opencv-python-headless numpy)"
        ) from exc


_OCR_REGISTRY: dict[str, Callable[[], OcrProvider]] = {
    "stub": StubOcrProvider,
    "tesseract": _tesseract,
    "inhouse": _inhouse_ocr,
}
_FACE_REGISTRY: dict[str, Callable[[], FaceProvider]] = {
    "stub": StubFaceProvider,
    "inhouse": _inhouse_face,
}
_OTP_REGISTRY: dict[str, Callable[[], OtpSender]] = {
    "log": _log_otp,
    "http": _http_otp,
    "oauth-sms": _oauth_sms_otp,
}


@lru_cache
def get_ocr_provider() -> OcrProvider:
    return _resolve(settings.ocr_provider, _OCR_REGISTRY, "OCR")


@lru_cache
def get_face_provider() -> FaceProvider:
    return _resolve(settings.face_provider, _FACE_REGISTRY, "face")


@lru_cache
def get_otp_sender() -> OtpSender:
    return _resolve(settings.otp_provider, _OTP_REGISTRY, "OTP")


def configured_providers() -> dict[str, list[str]]:
    """Names accepted by each engine — used by startup validation and tests."""
    return {
        "ocr": sorted(_OCR_REGISTRY),
        "face": sorted(_FACE_REGISTRY),
        "otp": sorted(_OTP_REGISTRY),
    }
