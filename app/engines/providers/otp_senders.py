from __future__ import annotations

import json
import logging

import httpx

from app.core.config import settings
from app.engines.providers.base import OtpSender

logger = logging.getLogger(__name__)

_DEFAULT_BODY = {
    "channel": "{channel}",
    "destination": "{destination}",
    "code": "{code}",
}


class _KeepMissing(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _render_body(channel: str, destination: str, code: str) -> dict:
    """Render the send payload from EKYC_OTP_HTTP_BODY_TEMPLATE.

    Placeholders: ``{destination}`` ``{destination_digits}`` ``{message}``
    ``{code}`` ``{sender}`` ``{channel}`` — so each SMS gateway's field names
    stay configuration, not code. ``{destination_digits}`` strips the leading
    "+" for gateways expecting international format without it (e.g.
    1smsafrica). Empty template = the original ``{channel,destination,code}``
    body (backward compatible).
    """
    template = json.loads(settings.otp_http_body_template or "null") or _DEFAULT_BODY
    message = settings.otp_message_template.format(code=code)
    mapping = {
        "destination": destination,
        "destination_digits": destination.lstrip("+"),
        "message": message,
        "code": code,
        "sender": settings.otp_sms_sender_id,
        "channel": channel,
    }
    return {key: str(value).format_map(_KeepMissing(mapping)) for key, value in template.items()}


def _raise_on_gateway_error(response: httpx.Response) -> None:
    """Some gateways (e.g. 1smsafrica) return HTTP 200 with an error body —
    ``raise_for_status`` alone cannot see it. When EKYC_OTP_HTTP_ERROR_FIELD /
    _VALUE are configured and the JSON body matches, treat it as a failure.
    Never logs the response body (it may echo the destination number)."""
    field = settings.otp_http_error_field
    sentinel = settings.otp_http_error_value
    if not field:
        return
    try:
        payload = response.json()
    except ValueError:
        return  # non-JSON body — nothing to inspect
    if isinstance(payload, dict) and payload.get(field) == sentinel:
        raise RuntimeError(f"SMS gateway rejected the send ({field}={sentinel})")


class LogOtpSender(OtpSender):
    """Development sender: the code is only written to the application log."""

    name = "log"

    def send(self, channel: str, destination: str, code: str) -> None:
        logger.info("OTP %s to %s: %s", channel, destination, code)


class HttpOtpSender(OtpSender):
    """Delegates delivery to an SMS/email gateway exposed over HTTP.

    Optional static auth header (``EKYC_OTP_HTTP_AUTH_HEADER``) and
    configurable JSON body (``EKYC_OTP_HTTP_BODY_TEMPLATE``).
    """

    name = "http"

    def send(self, channel: str, destination: str, code: str) -> None:
        if not settings.otp_http_url:
            raise RuntimeError("EKYC_OTP_HTTP_URL is not configured")
        headers = {}
        if settings.otp_http_auth_header:
            headers["Authorization"] = settings.otp_http_auth_header
        response = httpx.post(
            settings.otp_http_url,
            json=_render_body(channel, destination, code),
            headers=headers,
            timeout=10.0,
        )
        response.raise_for_status()
        _raise_on_gateway_error(response)


class OAuthSmsOtpSender(OtpSender):
    """SMS gateway behind OAuth 2.0 ``client_credentials`` (e.g. 1smsafrica).

    Fetches an access token once and caches it until expiry; each send POSTs a
    JSON body rendered from ``EKYC_OTP_HTTP_BODY_TEMPLATE`` — the gateway's
    field names are config, not code::

        {"recipient": "{destination}", "sender_id": "{sender}",
         "message": "{message}", "type": "plain"}

    Defaults assume the common ``{to, message, sender_id}`` convention.
    """

    name = "oauth-sms"

    def __init__(self) -> None:
        for field in (
            "otp_oauth_token_url",
            "otp_oauth_client_id",
            "otp_oauth_client_secret",
            "otp_http_url",
        ):
            if not getattr(settings, field):
                raise RuntimeError(f"oauth-sms sender requires {field.upper()}")
        self._token: str | None = None
        self._token_expiry: float = 0.0

    def _access_token(self) -> str:
        import time

        if self._token and time.time() < self._token_expiry:
            return self._token
        response = httpx.post(
            settings.otp_oauth_token_url,
            data={"grant_type": "client_credentials"},
            auth=(settings.otp_oauth_client_id, settings.otp_oauth_client_secret),
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        token = str(payload["access_token"])
        self._token = token
        # Renew 30 s early — tokens typically live 1 h.
        self._token_expiry = time.time() + float(payload.get("expires_in", 3600)) - 30
        return token

    def send(self, channel: str, destination: str, code: str) -> None:
        body = _render_body(channel, destination, code)
        response = httpx.post(
            settings.otp_http_url,
            json=body,
            headers={"Authorization": f"Bearer {self._access_token()}"},
            timeout=10.0,
        )
        response.raise_for_status()
        _raise_on_gateway_error(response)
