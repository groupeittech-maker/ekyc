"""Central configuration — environment-only, no hardcoded secrets."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class CentralSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CENTRAL_", env_file=".env", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./var/central.db"
    # One-time enrollment key (X-Bootstrap-Key). Required to accept new instances.
    bootstrap_key: str = "dev-bootstrap-key"
    # Operator key for admin endpoints (X-Admin-Key).
    admin_key: str = "dev-admin-key"
    # Where the Central Ed25519 signing keypair is persisted.
    private_key_path: str = "./var/keys/central_ed25519.pem"
    # Default attestation validity window (days).
    attestation_validity_days: int = 365


@lru_cache
def get_settings() -> CentralSettings:
    return CentralSettings()


settings = get_settings()
