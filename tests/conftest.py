from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator

import pytest

TMP_ROOT = tempfile.mkdtemp(prefix="ekyc-tests-")
os.environ.setdefault("EKYC_DATABASE_URL", f"sqlite:///{TMP_ROOT}/test.db")
os.environ.setdefault("EKYC_STORAGE_ROOT", f"{TMP_ROOT}/storage")
os.environ.setdefault("EKYC_SIGNING_KEY_PATH", f"{TMP_ROOT}/signing_key.pem")
os.environ.setdefault("EKYC_ADMIN_API_KEY", "test-admin-key")
os.environ.setdefault("EKYC_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("EKYC_CELERY_ALWAYS_EAGER", "true")

from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.engines.providers.base import OtpSender  # noqa: E402
from app.engines.providers.mrz import check_digit  # noqa: E402
from app.main import app  # noqa: E402


def build_passport_mrz(
    *,
    surname: str = "DOE",
    given: str = "JOHN",
    document_number: str = "AB1234567",
    nationality: str = "CGO",
    birth: str = "900515",
    sex: str = "M",
    expiry: str = "300515",
) -> str:
    line1 = f"P<{nationality}{surname}<<{given}".ljust(44, "<")
    body = (
        f"{document_number.ljust(9, '<')}{check_digit(document_number.ljust(9, '<'))}"
        f"{nationality}{birth}{check_digit(birth)}{sex}{expiry}{check_digit(expiry)}"
        f"{'<' * 14}0"
    )
    composite = check_digit(body[0:10] + body[13:20] + body[21:43])
    return f"{line1}\n{body}{composite}\n"


PASSPORT_MRZ = build_passport_mrz()


@pytest.fixture(scope="session", autouse=True)
def _schema() -> Iterator[None]:
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db() -> Iterator:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


class CapturingOtpSender(OtpSender):
    name = "capture"

    def __init__(self) -> None:
        self.codes: list[str] = []

    def send(self, channel: str, destination: str, code: str) -> None:
        self.codes.append(code)


@pytest.fixture
def otp_sender(monkeypatch: pytest.MonkeyPatch) -> CapturingOtpSender:
    sender = CapturingOtpSender()
    monkeypatch.setattr("app.engines.providers.get_otp_sender", lambda: sender)
    return sender


@pytest.fixture
def tenant_credentials(client: TestClient) -> dict:
    response = client.post(
        "/v1/admin/tenants",
        headers={"X-Admin-Key": "test-admin-key"},
        json={
            "name": "MHC Mobility Healthcare",
            "allowed_flows": ["TRAVEL_INSURANCE"],
            "branding": {"primary_color": "#0b5fff"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
def tenant_token(client: TestClient, tenant_credentials: dict) -> str:
    response = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": tenant_credentials["client_id"],
            "client_secret": tenant_credentials["client_secret"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]
