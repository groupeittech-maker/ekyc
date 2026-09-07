from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="EKYC_", extra="ignore")

    environment: str = "development"
    base_url: str = "http://localhost:8000"

    database_url: str = "sqlite:///./ekyc.db"
    redis_url: str = "redis://localhost:6379/0"
    celery_always_eager: bool = True

    admin_api_key: str = "change-me-admin-key"
    jwt_secret: str = "change-me-jwt-secret"
    access_token_ttl_seconds: int = 3600
    session_ttl_seconds: int = 1800

    storage_backend: str = "local"  # local | s3
    storage_root: str = "./var/storage"
    s3_bucket: str = ""
    s3_endpoint_url: str = ""
    s3_region: str = "eu-west-1"

    ocr_provider: str = "stub"  # stub | tesseract
    face_provider: str = "stub"
    otp_provider: str = "log"  # log | http
    otp_http_url: str = ""
    otp_length: int = 6
    otp_ttl_seconds: int = 300
    otp_max_attempts: int = 5

    signing_key_path: str = "./var/keys/signing_key.pem"
    signing_cert_path: str = ""
    tsa_url: str = ""  # RFC 3161 Timestamp Authority; empty -> local soft timestamp

    face_match_threshold: float = 0.80
    liveness_threshold: float = 0.70
    document_review_threshold: float = 0.60

    webhook_timeout_seconds: float = 10.0
    webhook_max_attempts: int = 5


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
