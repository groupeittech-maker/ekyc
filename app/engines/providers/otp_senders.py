from __future__ import annotations

import logging

import httpx

from app.core.config import settings
from app.engines.providers.base import OtpSender

logger = logging.getLogger(__name__)


class LogOtpSender(OtpSender):
    """Development sender: the code is only written to the application log."""

    name = "log"

    def send(self, channel: str, destination: str, code: str) -> None:
        logger.info("OTP %s to %s: %s", channel, destination, code)


class HttpOtpSender(OtpSender):
    """Delegates delivery to an SMS/email gateway exposed over HTTP."""

    name = "http"

    def send(self, channel: str, destination: str, code: str) -> None:
        if not settings.otp_http_url:
            raise RuntimeError("EKYC_OTP_HTTP_URL is not configured")
        response = httpx.post(
            settings.otp_http_url,
            json={"channel": channel, "destination": destination, "code": code},
            timeout=10.0,
        )
        response.raise_for_status()
