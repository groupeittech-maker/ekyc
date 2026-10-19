"""R8 — production startup refuses development-grade secrets."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import (
    InsecureConfigError,
    Settings,
    validate_production_settings,
)


def _prod(**overrides) -> Settings:
    base: dict = {
        "environment": "production",
        "admin_api_key": "k" * 40,
        "jwt_secret": "j" * 40,
        "signing_dev_self_signed_cert": False,
    }
    base.update(overrides)
    return Settings(**base)


def test_production_with_default_secrets_refused() -> None:
    cfg = Settings(environment="production")  # everything else = defaults
    with pytest.raises(InsecureConfigError) as exc:
        validate_production_settings(cfg)
    msg = str(exc.value)
    assert "EKYC_ADMIN_API_KEY" in msg and "EKYC_JWT_SECRET" in msg


def test_missing_or_empty_secret_refused() -> None:
    cfg = _prod(jwt_secret="")
    with pytest.raises(InsecureConfigError, match="missing or empty"):
        validate_production_settings(cfg)
    cfg = _prod(admin_api_key="   ")
    with pytest.raises(InsecureConfigError, match="missing or empty"):
        validate_production_settings(cfg)


def test_known_weak_value_refused_not_just_short() -> None:
    # "changeme" is a known dev value even if padded to a decent length —
    # length alone is not proof of secret quality.
    cfg = _prod(admin_api_key="change-me-admin-key")
    with pytest.raises(InsecureConfigError, match="known development"):
        validate_production_settings(cfg)


def test_short_secret_refused() -> None:
    cfg = _prod(jwt_secret="abc123")
    with pytest.raises(InsecureConfigError, match="shorter than 32"):
        validate_production_settings(cfg)


def test_dev_self_signed_cert_refused_in_production() -> None:
    cfg = _prod(signing_dev_self_signed_cert=True)
    with pytest.raises(InsecureConfigError, match="development certificate"):
        validate_production_settings(cfg)


def test_dev_providers_refused_in_production() -> None:
    cfg = _prod(ocr_provider="stub")
    with pytest.raises(InsecureConfigError, match="development-only"):
        validate_production_settings(cfg)
    cfg = _prod(otp_provider="log")
    with pytest.raises(InsecureConfigError, match="development-only"):
        validate_production_settings(cfg)


def test_valid_production_config_passes() -> None:
    cfg = _prod(ocr_provider="inhouse", face_provider="inhouse", otp_provider="http")
    validate_production_settings(cfg)  # no exception


def test_development_defaults_boot_fine() -> None:
    validate_production_settings(Settings(environment="development"))


def test_secret_value_never_in_error_message() -> None:
    cfg = _prod(admin_api_key="change-me-admin-key")
    with pytest.raises(InsecureConfigError) as exc:
        validate_production_settings(cfg)
    assert "change-me-admin-key" not in str(exc.value)


def test_admin_endpoint_constant_time_and_functional(client: TestClient) -> None:
    # Wrong key → 401; right key → works (compare_digest path exercised).
    assert (
        client.get("/v1/admin/storage", headers={"X-Admin-Key": "wrong"}).status_code
        == 401
    )
    assert (
        client.get(
            "/v1/admin/storage", headers={"X-Admin-Key": "test-admin-key"}
        ).status_code
        == 200
    )
