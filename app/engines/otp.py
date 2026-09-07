"""OTP engine. The code never leaves the platform: tenants only get the result."""

from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.hashing import sha256_text
from app.core.security import hash_secret
from app.db.base import utcnow
from app.engines import audit
from app.models.enums import AuditEventType, CheckStatus, OtpChannel, Step
from app.models.otp import OtpChallenge
from app.models.session import KycSession
from app.services import kyc


class OtpError(RuntimeError):
    pass


def mask_destination(destination: str) -> str:
    if "@" in destination:
        name, _, domain = destination.partition("@")
        return f"{name[:2]}{'*' * max(len(name) - 2, 1)}@{domain}"
    return f"{'*' * max(len(destination) - 4, 0)}{destination[-4:]}"


def _generate_code() -> str:
    upper = 10**settings.otp_length
    return str(secrets.randbelow(upper)).zfill(settings.otp_length)


def send_otp(
    db: Session, session: KycSession, channel: OtpChannel | str, destination: str
) -> OtpChallenge:
    from app.engines.providers import get_otp_sender

    code = _generate_code()
    challenge = OtpChallenge(
        session_id=session.id,
        tenant_id=session.tenant_id,
        channel=str(channel),
        destination_masked=mask_destination(destination),
        destination_hash=sha256_text(destination),
        code_hash=hash_secret(code),
        expires_at=utcnow() + timedelta(seconds=settings.otp_ttl_seconds),
    )
    db.add(challenge)
    db.flush()

    get_otp_sender().send(str(channel), destination, code)

    audit.record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=AuditEventType.OTP_SENT,
        payload={"channel": str(channel), "destination": challenge.destination_masked},
    )
    return challenge


def _latest_challenge(db: Session, session_id: str) -> OtpChallenge | None:
    return db.scalars(
        select(OtpChallenge)
        .where(OtpChallenge.session_id == session_id)
        .order_by(OtpChallenge.created_at.desc())
        .limit(1)
    ).first()


def verify_otp(db: Session, session: KycSession, code: str) -> bool:
    challenge = _latest_challenge(db, session.id)
    if challenge is None:
        raise OtpError("No OTP challenge for this session")
    if challenge.verified_at is not None:
        return True
    if challenge.expires_at <= utcnow():
        raise OtpError("OTP expired")
    if challenge.attempts >= settings.otp_max_attempts:
        kyc.set_check(
            db, session, Step.OTP, CheckStatus.FAILED, internal={"reason": "MAX_ATTEMPTS"}
        )
        raise OtpError("Too many attempts")

    challenge.attempts += 1
    verified = secrets.compare_digest(hash_secret(code), challenge.code_hash)
    if not verified:
        db.flush()
        audit.record_event(
            db,
            tenant_id=session.tenant_id,
            session_id=session.id,
            event_type=AuditEventType.OTP_FAILED,
            payload={"attempts": challenge.attempts},
        )
        if challenge.attempts >= settings.otp_max_attempts:
            kyc.set_check(
                db, session, Step.OTP, CheckStatus.FAILED, internal={"reason": "MAX_ATTEMPTS"}
            )
        return False

    challenge.verified_at = utcnow()
    db.flush()
    audit.record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=AuditEventType.OTP_VERIFIED,
        payload={"channel": challenge.channel, "destination": challenge.destination_masked},
    )
    kyc.set_check(
        db, session, Step.OTP, CheckStatus.PASSED, internal={"attempts": challenge.attempts}
    )
    return True
