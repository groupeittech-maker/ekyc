"""LOT E — non-personal document observations + opt-in sample donation.

Invariants under test:
- every processed document writes ONE observation row with labels only
- no donation happens without the explicit donate_samples consent flag
- donation exports images + label sidecar, anonymized (no session/tenant)
- admin endpoint aggregates without any identity data
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import SessionLocal
from app.engines import identity
from app.models.document import Document
from app.models.document_observation import DocumentObservation
from app.models.session import KycSession
from app.services import kyc


def _session(db, donated: bool) -> KycSession:
    sess = KycSession(
        id="obs-sess",
        tenant_id="t",
        customer_reference="ref",
        flow="CITIZEN",
        status="DOCUMENT_UPLOAD",
        access_token_hash="x",
        expires_at=__import__("datetime").datetime(2999, 1, 1),
        consent={"accepted": True, "donate_samples": donated},
        jurisdiction="CI",
    )
    db.add(sess)
    db.flush()
    return sess


def test_observation_recorded_without_pii(db, monkeypatch):
    monkeypatch.setattr(settings, "dataset_donation_dir", "/tmp/nope")
    sess = _session(db, donated=False)
    doc = Document(session_id=sess.id, document_type="PASSPORT", status="PROCESSING")
    # stub provider parse — identity fields only flow through the observation
    images = [b"fake-recto"]
    class _Ocr:
        confidence = 0.9
        provider = "test"
        fields = {"mrz_format": "TD3", "issuing_country": "CGO",
                  "checks_passed": True, "document_number": "SECRET-DOC-NO"}
    class _Auth:
        authentic = True
        confidence = 0.9
        provider = "test"
        signals = ["SIG"]
    monkeypatch.setattr(identity, "_extract", lambda *a, **kw: _Ocr())
    prov = type("P", (), {"check_authenticity": lambda s, i, o: _Auth()})()
    monkeypatch.setattr(identity, "get_ocr_provider", lambda: prov)

    out = identity.process_document(db, sess, doc, images)
    obs = db.query(DocumentObservation).order_by(DocumentObservation.created_at.desc()).first()
    assert obs is not None
    assert obs.mrz_format == "TD3"
    assert obs.issuing_country == "CGO"
    assert obs.checks_passed is True
    # PII never reaches the observation row
    dumped = {c.name: getattr(obs, c.name) for c in obs.__table__.columns}
    assert "SECRET-DOC-NO" not in str(dumped)


def test_donation_writes_labeled_sample(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "dataset_donation_dir", str(tmp_path / "don"))
    sess = _session(db, donated=True)
    doc = Document(session_id=sess.id, document_type="PASSPORT", status="PROCESSING")
    images = [b"\xff\xd8\xffrecto"]

    class _Ocr:
        confidence = 0.9
        provider = "test"
        fields = {"mrz_format": "TD3", "issuing_country": "CIV",
                  "checks_passed": True}
    class _Auth:
        authentic = True
        confidence = 0.9
        provider = "test"
        signals = []
    monkeypatch.setattr(identity, "_extract", lambda *a, **kw: _Ocr())
    prov = type("P", (), {"check_authenticity": lambda s, i, o: _Auth()})()
    monkeypatch.setattr(identity, "get_ocr_provider", lambda: prov)

    identity.process_document(db, sess, doc, images)
    files = list((tmp_path / "don" / "TD3").iterdir())
    assert len(files) == 2  # image + sidecar
    sidecar = [f for f in files if f.suffix == ".json"][0].read_text()
    assert '"issuing_country": "CIV"' in sidecar
    assert sess.id not in sidecar  # anonymized


def test_no_donation_without_opt_in(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "dataset_donation_dir", str(tmp_path / "don"))
    sess = _session(db, donated=False)
    doc = Document(session_id=sess.id, document_type="PASSPORT", status="PROCESSING")

    class _Ocr:
        confidence = 0.9
        provider = "test"
        fields = {"mrz_format": "TD3", "issuing_country": "CIV", "checks_passed": True}
    class _Auth:
        authentic = True
        confidence = 0.9
        provider = "test"
        signals = []
    monkeypatch.setattr(identity, "_extract", lambda *a, **kw: _Ocr())
    prov = type("P", (), {"check_authenticity": lambda s, i, o: _Auth()})()
    monkeypatch.setattr(identity, "get_ocr_provider", lambda: prov)

    identity.process_document(db, sess, doc, [b"x"])
    assert not (tmp_path / "don").exists()


def test_document_stats_endpoint(client: TestClient, db) -> None:
    db.add(DocumentObservation(
        document_type="PASSPORT", mrz_format="TD3", issuing_country="CIV",
        status="PASSED", checks_passed=True))
    db.commit()
    resp = client.get("/v1/admin/document-stats", headers={"X-Admin-Key": "test-admin-key"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["by_country"]["CIV"]["TD3"]["PASSED"] >= 1
