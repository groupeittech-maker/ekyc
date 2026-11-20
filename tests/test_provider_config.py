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
    assert names["otp"] == ["http", "log", "oauth-sms"]
    assert names["otp_email"] == ["smtp"]


# --------------------------------------------------------------------------- #
# OAuth 2.0 SMS sender (e.g. 1smsafrica-style gateways)
# --------------------------------------------------------------------------- #
def _oauth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "otp_provider", "oauth-sms")
    monkeypatch.setattr(settings, "otp_oauth_token_url", "https://gw.test/oauth/token")
    monkeypatch.setattr(settings, "otp_oauth_client_id", "cid")
    monkeypatch.setattr(settings, "otp_oauth_client_secret", "csec")
    monkeypatch.setattr(settings, "otp_http_url", "https://gw.test/send-sms")


def _fake_httpx(calls: list, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        def raise_for_status(self) -> None:
            pass

        def json(self):
            return {"access_token": "tok-123", "expires_in": 3600}

    def post(url: str, **kwargs):
        calls.append({"url": url, **kwargs})
        return _Resp()

    monkeypatch.setattr("app.engines.providers.otp_senders.httpx.post", post)


def test_oauth_sms_sender_token_and_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _oauth_env(monkeypatch)
    monkeypatch.setattr(
        settings,
        "otp_http_body_template",
        '{"to": "{destination}", "message": "{message}", "sender_id": "{sender}"}',
    )
    calls: list = []
    _fake_httpx(calls, monkeypatch)
    sender = providers.get_otp_sender()
    sender.send("SMS", "+22507123456", "123456")
    token_call, send_call = calls
    assert token_call["url"].endswith("/oauth/token")
    assert token_call["auth"] == ("cid", "csec")
    assert send_call["headers"]["Authorization"] == "Bearer tok-123"
    assert send_call["json"]["to"] == "+22507123456"
    assert "123456" in send_call["json"]["message"]


def test_oauth_sms_token_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _oauth_env(monkeypatch)
    calls: list = []
    _fake_httpx(calls, monkeypatch)
    sender = providers.get_otp_sender()
    sender.send("SMS", "+22507123456", "123456")
    sender.send("SMS", "+22507123456", "654321")
    assert len([c for c in calls if c["url"].endswith("/oauth/token")]) == 1
    assert len([c for c in calls if c["url"].endswith("/send-sms")]) == 2


def test_oauth_sms_custom_body_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _oauth_env(monkeypatch)
    monkeypatch.setattr(
        settings,
        "otp_http_body_template",
        '{"recipient": "{destination}", "text": "{message}", "from": "{sender}"}',
    )
    calls: list = []
    _fake_httpx(calls, monkeypatch)
    providers.get_otp_sender().send("SMS", "+22507123456", "482913")
    assert calls[1]["json"] == {
        "recipient": "+22507123456",
        "text": "Votre code de verification est 482913.",
        "from": "TRUSDY",
    }


def test_oauth_sms_missing_credentials_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "otp_provider", "oauth-sms")
    monkeypatch.setattr(settings, "otp_oauth_token_url", "https://gw.test/oauth/token")
    monkeypatch.setattr(settings, "otp_oauth_client_id", "")
    monkeypatch.setattr(settings, "otp_http_url", "https://gw.test/send")
    with pytest.raises(ProviderDependencyError, match="OTP_OAUTH_CLIENT_ID"):
        providers.get_otp_sender()


# --------------------------------------------------------------------------- #
# Gateways returning HTTP 200 with an error body (e.g. 1smsafrica)
# --------------------------------------------------------------------------- #
def test_http_sender_detects_body_level_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ErrResp:
        def raise_for_status(self) -> None:
            pass  # HTTP 200 — the error lives in the JSON body

        def json(self):
            return {"status": "error", "message": "insufficient balance"}

    monkeypatch.setattr(settings, "otp_provider", "http")
    monkeypatch.setattr(settings, "otp_http_url", "https://gw.test/send")
    monkeypatch.setattr(
        "app.engines.providers.otp_senders.httpx.post",
        lambda *a, **k: _ErrResp(),
    )
    with pytest.raises(RuntimeError, match="rejected"):
        providers.get_otp_sender().send("SMS", "+22507123456", "123456")


def test_destination_digits_strips_plus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list = []
    monkeypatch.setattr(settings, "otp_provider", "http")
    monkeypatch.setattr(settings, "otp_http_url", "https://gw.test/send")
    monkeypatch.setattr(
        settings,
        "otp_http_body_template",
        '{"recipient": "{destination_digits}", "message": "{message}"}',
    )
    _fake_httpx(calls, monkeypatch)
    providers.get_otp_sender().send("SMS", "+22507123456", "482913")
    assert calls[0]["json"]["recipient"] == "22507123456"


# --------------------------------------------------------------------------- #
# SMTP e-mail sender (EMAIL channel)
# --------------------------------------------------------------------------- #
def _smtp_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "otp_email_provider", "smtp")
    monkeypatch.setattr(settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(settings, "smtp_port", 465)
    monkeypatch.setattr(settings, "smtp_security", "ssl")
    monkeypatch.setattr(settings, "smtp_user", "ekyc@test.dev")
    monkeypatch.setattr(settings, "smtp_password", "secret")
    monkeypatch.setattr(settings, "smtp_from_email", "noreply@test.dev")


def test_email_channel_uses_the_email_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: dict = {}

    class _Smtp:
        def __init__(self, host, port, timeout):
            sent["connect"] = (host, port)

        def login(self, user, password):
            sent["login"] = user

        def send_message(self, msg):
            sent["to"] = msg["To"]
            sent["subject"] = msg["Subject"]
            sent["body"] = msg.get_content()

        def quit(self):
            pass

    _smtp_env(monkeypatch)
    monkeypatch.setattr("smtplib.SMTP_SSL", _Smtp)
    providers.get_otp_sender(channel="EMAIL").send("EMAIL", "user@mail.dev", "123456")

    assert sent["connect"] == ("smtp.test", 465)
    assert sent["to"] == "user@mail.dev"
    assert "123456" in sent["body"]


def test_email_channel_without_provider_is_refused() -> None:
    with pytest.raises(RuntimeError, match="OTP_EMAIL_PROVIDER"):
        providers.get_otp_sender(channel="EMAIL")


def test_smtp_sender_requires_host(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.engines.providers.otp_senders import SmtpOtpSender

    monkeypatch.setattr(settings, "smtp_host", "")
    with pytest.raises(RuntimeError, match="SMTP_HOST"):
        SmtpOtpSender()
