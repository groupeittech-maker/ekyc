"""KYC session service: the central object of the platform."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.ids import new_session_id
from app.core.security import new_session_access_token, verify_secret
from app.db.base import utcnow
from app.engines import audit
from app.engines.decision import decidable_steps, decide
from app.engines.policy import FlowPolicy, get_policy
from app.models.enums import AuditEventType, CheckStatus, SessionStatus, Step
from app.models.session import KycSession
from app.models.tenant import Tenant


class SessionExpiredError(RuntimeError):
    pass


class SessionClosedError(RuntimeError):
    pass


def create_session(
    db: Session,
    *,
    tenant: Tenant,
    flow: str,
    customer_reference: str | None,
    metadata: dict[str, Any] | None = None,
    ip: str | None = None,
) -> tuple[KycSession, str]:
    policy = get_policy(flow)
    if tenant.allowed_flows and flow not in tenant.allowed_flows:
        raise PermissionError(f"Flow {flow} is not enabled for this tenant")

    token, token_hash = new_session_access_token()
    session = KycSession(
        id=new_session_id(),
        tenant_id=tenant.id,
        customer_reference=customer_reference,
        flow=policy.name,
        status=SessionStatus.CREATED,
        access_token_hash=token_hash,
        expires_at=utcnow() + timedelta(seconds=settings.session_ttl_seconds),
        identity={},
        checks={str(step): CheckStatus.PENDING for step in decidable_steps(policy)},
        internal={},
        metadata_=metadata or {},
        reasons=[],
    )
    db.add(session)
    db.flush()

    audit.record_event(
        db,
        tenant_id=tenant.id,
        session_id=session.id,
        event_type=AuditEventType.KYC_SESSION_CREATED,
        payload={"flow": policy.name, "customer_reference": customer_reference},
        actor="TENANT",
        ip=ip,
    )
    return session, token


def verification_url(session: KycSession, token: str) -> str:
    return f"{settings.base_url.rstrip('/')}/verify/{session.id}?token={token}"


def authenticate_session(session: KycSession, token: str) -> None:
    if not verify_secret(token, session.access_token_hash):
        raise PermissionError("Invalid session token")
    ensure_active(session)


def ensure_active(session: KycSession) -> None:
    if session.status in {
        SessionStatus.VERIFIED,
        SessionStatus.REJECTED,
        SessionStatus.REVIEW,
        SessionStatus.EXPIRED,
    }:
        raise SessionClosedError(f"Session is already {session.status}")
    if session.expires_at <= utcnow():
        raise SessionExpiredError("Session expired")


def policy_of(session: KycSession) -> FlowPolicy:
    return get_policy(session.flow)


def set_check(
    db: Session,
    session: KycSession,
    step: Step,
    status: CheckStatus,
    *,
    internal: dict[str, Any] | None = None,
) -> None:
    checks = dict(session.checks)
    checks[str(step)] = str(status)
    session.checks = checks
    if internal:
        merged = dict(session.internal)
        merged[str(step)] = internal
        session.internal = merged
    if session.status == SessionStatus.CREATED:
        session.status = SessionStatus.IN_PROGRESS
    session.updated_at = utcnow()
    db.flush()


def evaluate(db: Session, session: KycSession) -> SessionStatus:
    """Re-run the decision engine and close the session when it is complete."""
    decision = decide(policy_of(session), session.checks, session.internal or {})
    previous_status = session.status
    session.status = decision.status
    session.reasons = decision.reasons if decision.completed else []
    session.updated_at = utcnow()

    merged = dict(session.internal)
    merged["risk"] = {
        "score": decision.score,
        "level": decision.risk_level,
    }
    session.internal = merged

    if decision.completed and session.completed_at is None:
        session.completed_at = utcnow()
        audit.record_event(
            db,
            tenant_id=session.tenant_id,
            session_id=session.id,
            event_type=AuditEventType.KYC_DECISION,
            payload={
                "status": str(decision.status),
                "reasons": decision.reasons,
                "score": decision.score,
                "risk_level": decision.risk_level,
            },
        )
    db.flush()

    if decision.completed and previous_status != decision.status:
        from app.services.webhooks import queue_session_event

        queue_session_event(db, session)
    return decision.status


def public_result(session: KycSession, *, include_identity: bool = True) -> dict[str, Any]:
    """Data minimisation: tenants only get what they need to decide."""
    identity_fields = ("first_name", "last_name", "date_of_birth", "nationality", "document_type")
    result: dict[str, Any] = {
        "session_id": session.id,
        "customer_reference": session.customer_reference,
        "flow": session.flow,
        "status": session.status,
        "checks": session.checks,
        "reasons": session.reasons,
        "created_at": session.created_at,
        "completed_at": session.completed_at,
    }
    if include_identity and session.status in {SessionStatus.VERIFIED, SessionStatus.REVIEW}:
        result["identity"] = {
            key: session.identity.get(key) for key in identity_fields if session.identity.get(key)
        }
    else:
        result["identity"] = None

    risk = (session.internal or {}).get("risk", {})
    result["risk_score"] = risk.get("score")
    return result
