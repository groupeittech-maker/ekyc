"""P0 resilience: concurrent check updates, decision guards, task recovery.

Concurrency tests run REAL transactions against the test database (two
threads, two SessionLocal connections, real writer locks) — no mock can
reproduce the lost-update race they cover.
"""

from __future__ import annotations

import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.db.base import utcnow
from app.db.session import SessionLocal
from app.engines import audit
from app.models.document import Document
from app.models.enums import (
    AuditEventType,
    CheckStatus,
    SessionStatus,
    Step,
)
from app.models.session import KycSession
from app.models.webhook import WebhookDelivery
from app.services import kyc
from tests.conftest import PASSPORT_MRZ

_ADMIN = {"X-Admin-Key": "test-admin-key"}


def _tenant_and_session(client: TestClient) -> tuple[dict, dict]:
    creds = client.post(
        "/v1/admin/tenants",
        headers=_ADMIN,
        json={
            "name": "Res",
            "allowed_flows": ["TRAVEL_INSURANCE"],
            "webhook_url": "https://tenant.example/hook",
        },
    ).json()
    token = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    ).json()["access_token"]
    session = client.post(
        "/v1/kyc/sessions",
        headers={"authorization": f"Bearer {token}"},
        json={"customer_reference": "RES-1", "flow": "TRAVEL_INSURANCE"},
    ).json()
    return {"authorization": f"Bearer {token}"}, session


def _new_session_db(client: TestClient) -> str:
    _, session = _tenant_and_session(client)
    return session["session_id"]


# --------------------------------------------------------------------------- #
# R2 — lost-update on concurrent check writes
# --------------------------------------------------------------------------- #
def test_concurrent_set_check_loses_no_update(client: TestClient) -> None:
    """T1 holds the session write lock while T2 merges a different check:
    T2 must wait, then read the *committed* T1 check before merging — both
    land in session.checks instead of one clobbering the other."""
    sid = _new_session_db(client)
    lock_held = threading.Event()
    finished = threading.Event()
    errors: list[BaseException] = []

    def writer_one() -> None:
        try:
            with SessionLocal() as db:
                # Acquire the writer lock the same way lock_session() does.
                db.execute(
                    update(KycSession).where(KycSession.id == sid).values(updated_at=utcnow())
                )
                session = db.get(KycSession, sid)
                checks = dict(session.checks)
                checks[str(Step.DOCUMENT_VERIFICATION)] = str(CheckStatus.PASSED)
                session.checks = checks
                db.flush()
                lock_held.set()
                time.sleep(0.4)  # keep the lock while T2 tries to write
                db.commit()
        except BaseException as exc:  # noqa: BLE001 - surfaced in assertions
            errors.append(exc)

    def writer_two() -> None:
        try:
            lock_held.wait(timeout=5)
            with SessionLocal() as db:
                session = db.get(KycSession, sid)
                kyc.set_check(db, session, Step.FACE_MATCH, CheckStatus.PASSED)
                db.commit()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=writer_one)
    t2 = threading.Thread(target=writer_two)
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)
    finished.set()

    assert not errors, f"concurrency errors: {errors}"
    with SessionLocal() as db:
        checks = db.get(KycSession, sid).checks
    assert checks[str(Step.DOCUMENT_VERIFICATION)] == str(CheckStatus.PASSED)
    assert checks[str(Step.FACE_MATCH)] == str(CheckStatus.PASSED)


# --------------------------------------------------------------------------- #
# R3 — terminal decisions & webhook integrity
# --------------------------------------------------------------------------- #
def _verify_session(client: TestClient, otp_sender) -> tuple[str, dict]:
    """Drive a session to VERIFIED through the hosted endpoints."""
    headers, session = _tenant_and_session(client)
    sid = session["session_id"]
    vtoken = parse_qs(urlparse(session["verification_url"]).query)["token"][0]
    vh = {"authorization": f"Bearer {vtoken}"}
    base = f"/v1/verification/{sid}"
    client.post(f"{base}/consent", headers=vh, json={"accepted": True})
    client.post(
        f"{base}/document",
        headers=vh,
        files={"file": ("p.txt", PASSPORT_MRZ.encode(), "text/plain")},
        data={"document_type": "PASSPORT"},
    )
    client.post(
        f"{base}/selfie",
        headers=vh,
        files={"file": ("s.jpg", b"fake-image", "image/jpeg")},
    )
    client.post(
        f"{base}/otp/send",
        headers=vh,
        json={"channel": "SMS", "destination": "+33612345678"},
    )
    client.post(f"{base}/otp/verify", headers=vh, json={"code": otp_sender.codes[-1]})
    return sid, headers


def test_terminal_decision_not_overwritten(client: TestClient, otp_sender) -> None:
    sid, headers = _verify_session(client, otp_sender)
    with SessionLocal() as db:
        session = db.get(KycSession, sid)
        assert session.status == SessionStatus.VERIFIED
        # Corrupt a check to force a different decision on re-evaluation.
        checks = dict(session.checks)
        checks[str(Step.LIVENESS)] = str(CheckStatus.FAILED)
        session.checks = checks
        db.commit()

        status = kyc.evaluate(db, session)
        db.commit()
        session = db.get(KycSession, sid)
        assert status == SessionStatus.VERIFIED
        assert session.status == SessionStatus.VERIFIED  # never flipped
        events = audit.list_events(db, sid)
        assert any(e.event_type == str(AuditEventType.DECISION_BLOCKED) for e in events)


def test_idempotent_same_status_evaluate_emits_once(client: TestClient, otp_sender) -> None:
    sid, headers = _verify_session(client, otp_sender)
    with SessionLocal() as db:
        session = db.get(KycSession, sid)
        before = [e for e in audit.list_events(db, sid)]
        kyc.evaluate(db, session)  # re-evaluation, same verdict
        db.commit()
        after = audit.list_events(db, sid)
    assert [e.event_type for e in after] == [e.event_type for e in before]
    with SessionLocal() as db:
        deliveries = db.scalars(
            select(WebhookDelivery).where(WebhookDelivery.session_id == sid)
        ).all()
    assert len([d for d in deliveries if d.event == "KYC_VERIFIED"]) == 1


def test_concurrent_evaluate_single_decision(client: TestClient) -> None:
    """Two threads evaluate the same session → one decision event, one webhook."""
    sid = _new_session_db(client)
    with SessionLocal() as db:
        session = db.get(KycSession, sid)
        for step, status in (
            (Step.DOCUMENT_VERIFICATION, CheckStatus.PASSED),
            (Step.LIVENESS, CheckStatus.PASSED),
            (Step.FACE_MATCH, CheckStatus.PASSED),
            (Step.OTP, CheckStatus.PASSED),
        ):
            kyc.set_check(db, session, step, status)
        db.commit()

    barrier = threading.Barrier(2)
    results: list = []

    def run_evaluate() -> None:
        with SessionLocal() as db:
            session = db.get(KycSession, sid)
            barrier.wait()
            results.append(kyc.evaluate(db, session))
            db.commit()

    threads = [threading.Thread(target=run_evaluate) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert results == [SessionStatus.VERIFIED, SessionStatus.VERIFIED]
    with SessionLocal() as db:
        decisions = [
            e
            for e in audit.list_events(db, sid)
            if e.event_type == str(AuditEventType.KYC_DECISION)
        ]
        deliveries = db.scalars(
            select(WebhookDelivery)
            .where(WebhookDelivery.session_id == sid)
            .where(WebhookDelivery.event == "KYC_VERIFIED")
        ).all()
    assert len(decisions) == 1
    assert len(deliveries) == 1


def test_explicit_override_is_audited_and_emits_webhook(client: TestClient, otp_sender) -> None:
    sid, headers = _verify_session(client, otp_sender)
    with SessionLocal() as db:
        session = db.get(KycSession, sid)
        kyc.override_decision(db, session, SessionStatus.REJECTED, reason="FRAUD_HINT")
        db.commit()
        session = db.get(KycSession, sid)
        assert session.status == SessionStatus.REJECTED
        events = audit.list_events(db, sid)
        override = next(
            e for e in events if e.event_type == str(AuditEventType.DECISION_OVERRIDDEN)
        )
        assert override.payload["previous_status"] == "VERIFIED"
        assert override.actor == "ADMIN"
        deliveries = db.scalars(
            select(WebhookDelivery)
            .where(WebhookDelivery.session_id == sid)
            .where(WebhookDelivery.event == "KYC_REJECTED")
        ).all()
        assert len(deliveries) == 1


# --------------------------------------------------------------------------- #
# R1 — retries, permanent failure, reconciliation
# --------------------------------------------------------------------------- #
def _document_session(client: TestClient) -> tuple[str, str]:
    """Session with an uploaded document; returns (session_id, document_id)."""
    sid = _new_session_db(client)
    with SessionLocal() as db:
        session = db.get(KycSession, sid)
        from app.services.archive import store_artifact

        artifact = store_artifact(
            db,
            tenant_id=session.tenant_id,
            session_id=sid,
            kind="DOCUMENT_IMAGE",
            filename="passport.txt",
            data=PASSPORT_MRZ.encode(),
            content_type="text/plain",
            vault_profile=session.vault_profile,
        )
        doc = Document(
            session_id=sid,
            tenant_id=session.tenant_id,
            document_type="PASSPORT",
            artifact_id=artifact.id,
        )
        db.add(doc)
        db.commit()
        document_id = doc.id
    return sid, document_id


def test_process_document_retries_transient_error(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sid, document_id = _document_session(client)
    from app.engines import identity
    from app.workers.tasks import process_document

    calls = {"n": 0}
    original = identity.process_document

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis blip")  # transient → retried
        return original(*args, **kwargs)

    monkeypatch.setattr(identity, "process_document", flaky)
    process_document.delay(document_id)
    assert calls["n"] >= 2  # retried at least once after the transient error
    with SessionLocal() as db:
        checks = db.get(KycSession, sid).checks
    assert checks[str(Step.DOCUMENT_VERIFICATION)] == str(CheckStatus.PASSED)


def test_permanent_failure_marks_review_never_reject(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sid, document_id = _document_session(client)
    from app.engines import identity
    from app.workers.tasks import process_document

    def broken(*args, **kwargs):
        raise FileNotFoundError("artifact gone")  # permanent → no retry

    monkeypatch.setattr(identity, "process_document", broken)
    process_document.delay(document_id)

    with SessionLocal() as db:
        session = db.get(KycSession, sid)
        # Technical failure → human review, never an automatic identity rejection.
        assert session.status in (SessionStatus.REVIEW, SessionStatus.IN_PROGRESS)
        assert session.status != SessionStatus.REJECTED
        events = audit.list_events(db, sid)
        assert any(e.event_type == str(AuditEventType.PROCESSING_FAILED) for e in events)


def test_stuck_session_reconciled_without_duplication(client: TestClient) -> None:
    """Document uploaded but its task never ran → sweep requeues, applies once."""
    sid, document_id = _document_session(client)
    with SessionLocal() as db:
        session = db.get(KycSession, sid)
        session.status = SessionStatus.IN_PROGRESS
        session.updated_at = utcnow() - __import__("datetime").timedelta(hours=1)
        db.commit()

    from app.workers.tasks import reconcile_stuck_sessions

    report1 = reconcile_stuck_sessions()
    assert sid in report1["requeued"]
    with SessionLocal() as db:
        checks = db.get(KycSession, sid).checks
    assert checks[str(Step.DOCUMENT_VERIFICATION)] == str(CheckStatus.PASSED)

    report2 = reconcile_stuck_sessions()
    assert report2["requeued"] == []
    with SessionLocal() as db:
        ocr_events = [
            e
            for e in audit.list_events(db, sid)
            if e.event_type == str(AuditEventType.OCR_COMPLETED)
        ]
    assert len(ocr_events) == 1  # applied once, not duplicated
