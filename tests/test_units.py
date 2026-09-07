from __future__ import annotations

import pytest

from app.engines.asn1 import build_timestamp_request
from app.engines.decision import decide
from app.engines.otp import mask_destination
from app.engines.policy import CITIZEN, TRAVEL_INSURANCE, get_policy
from app.engines.providers.mrz import parse_td3
from app.models.enums import CheckStatus, SessionStatus
from tests.conftest import build_passport_mrz


def test_mrz_check_digits_are_validated() -> None:
    line1, line2 = build_passport_mrz().strip().splitlines()
    parsed = parse_td3(line1, line2)

    assert parsed["checks_passed"] is True
    assert parsed["last_name"] == "DOE"
    assert parsed["first_name"] == "JOHN"
    assert parsed["date_of_birth"] == "1990-05-15"
    assert parsed["expiry_date"] == "2030-05-15"


def test_mrz_detects_a_tampered_document_number() -> None:
    line1, line2 = build_passport_mrz().strip().splitlines()
    tampered = line2[:3] + ("9" if line2[3] != "9" else "8") + line2[4:]

    assert parse_td3(line1, tampered)["checks_passed"] is False


@pytest.mark.parametrize(
    ("checks", "expected"),
    [
        ({}, SessionStatus.IN_PROGRESS),
        (
            {"DOCUMENT_VERIFICATION": "PASSED", "LIVENESS": "PASSED", "FACE_MATCH": "PASSED"},
            SessionStatus.IN_PROGRESS,
        ),
        (
            {
                "DOCUMENT_VERIFICATION": "PASSED",
                "LIVENESS": "FAILED",
                "FACE_MATCH": "PASSED",
                "OTP": "PASSED",
            },
            SessionStatus.REJECTED,
        ),
        (
            {
                "DOCUMENT_VERIFICATION": "PASSED",
                "LIVENESS": "PASSED",
                "FACE_MATCH": "FAILED",
                "OTP": "PASSED",
            },
            SessionStatus.REVIEW,
        ),
        (
            {
                "DOCUMENT_VERIFICATION": "PASSED",
                "LIVENESS": "PASSED",
                "FACE_MATCH": "PASSED",
                "OTP": "PASSED",
            },
            SessionStatus.VERIFIED,
        ),
    ],
)
def test_decision_engine(checks: dict[str, str], expected: SessionStatus) -> None:
    assert decide(TRAVEL_INSURANCE, checks).status == expected


def test_policies_only_require_their_own_steps() -> None:
    decision = decide(CITIZEN, {"DOCUMENT_VERIFICATION": CheckStatus.PASSED, "OTP": "PASSED"})

    assert decision.status == SessionStatus.VERIFIED
    assert get_policy("CITIZEN").requires_signature is False


def test_otp_destination_is_masked() -> None:
    assert mask_destination("+242060000000") == "*********0000"
    assert mask_destination("john.doe@example.com") == "jo******@example.com"


def test_timestamp_request_is_valid_der() -> None:
    request = build_timestamp_request(bytes.fromhex("ab" * 32))

    assert request[0] == 0x30  # SEQUENCE
    assert len(request) == request[1] + 2
