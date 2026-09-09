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

    ocr_provider: str = "stub"  # stub | tesseract | inhouse
    face_provider: str = "stub"  # stub | inhouse
    otp_provider: str = "log"  # log | http
    otp_http_url: str = ""
    otp_http_auth_header: str = ""  # optional Authorization value for the OTP gateway
    otp_length: int = 6
    otp_ttl_seconds: int = 300
    otp_max_attempts: int = 5

    # In-house biometric / OCR module (self-hosted, no third-party SaaS).
    # ONNX models run locally; see scripts/fetch_models.py to provision them.
    biometrics_model_dir: str = "./var/models"
    # Relative paths within the OpenCV Zoo model tree (git-lfs backed).
    face_detector_model: str = "face_detection_yunet/face_detection_yunet_2023mar.onnx"
    face_recognizer_model: str = "face_recognition_sface/face_recognition_sface_2021dec.onnx"
    # media.githubusercontent serves the actual LFS blobs (raw returns pointers).
    face_model_base_url: str = (
        "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models"
    )
    # SFace cosine similarity calibration -> normalized [0,1] match score.
    face_match_cos_reject: float = 0.25
    face_match_cos_accept: float = 0.55
    # Passive liveness heuristics.
    liveness_min_sharpness: float = 60.0
    liveness_min_face_ratio: float = 0.06

    signing_backend: str = "local"  # local | (kms/hsm: implement Signer interface)
    signing_key_path: str = "./var/keys/signing_key.pem"
    signing_cert_path: str = ""
    # When no certificate is provisioned, auto-generate a self-signed one for
    # development so evidence carries a certificate fingerprint. Disable in prod.
    signing_dev_self_signed_cert: bool = True
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
