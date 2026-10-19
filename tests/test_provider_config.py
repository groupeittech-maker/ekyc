"""R7 — fail-closed provider configuration.

An unknown EKYC_*_PROVIDER name must never silently degrade to a stub;
dev-only providers must be refused in production even when selected
explicitly.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.engines import providers
from app.engines.providers import (
    ProviderDependencyError,
    UnknownProviderError,
)


@pytest.fixture(autouse=True)
def _clear_provider_caches() -> None:
    for getter in (
        providers.get_ocr_provider,
        providers.get_face_provider,
        providers.get_otp_sender,
    ):
        getter.cache_clear()
    yield
    for getter in (
        providers.get_ocr_provider,
        providers.get_face_provider,
        providers.get_otp_sender,
    ):
        getter.cache_clear()


def test_known_provider_resolves() -> None:
    assert providers.get_ocr_provider().name == "stub"  # default dev provider
    assert providers.get_face_provider().name == "stub"
    assert providers.get_otp_sender().name == "log"


def test_unknown_provider_name_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "ocr_provider", "not-a-provider")
    with pytest.raises(UnknownProviderError, match="not-a-provider") as exc:
        providers.get_ocr_provider()
    # The error is actionable: it lists what IS configured.
    assert "inhouse" in str(exc.value)


def test_stub_explicitly_selectable_in_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "face_provider", "stub")
    assert providers.get_face_provider().name == "stub"


def test_stub_refused_in_production_even_if_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "ocr_provider", "stub")
    with pytest.raises(UnknownProviderError, match="development-only"):
        providers.get_ocr_provider()


def test_log_otp_refused_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "otp_provider", "log")
    with pytest.raises(UnknownProviderError, match="development-only"):
        providers.get_otp_sender()


def test_http_otp_requires_gateway_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "otp_provider", "http")
    monkeypatch.setattr(settings, "otp_http_url", "")
    with pytest.raises(ProviderDependencyError, match="EKYC_OTP_HTTP_URL"):
        providers.get_otp_sender()


def test_configured_provider_names_are_exposed() -> None:
    names = providers.configured_providers()
    assert names["ocr"] == ["inhouse", "stub", "tesseract"]
    assert names["face"] == ["inhouse", "stub"]
    assert names["otp"] == ["http", "log"]
