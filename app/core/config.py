from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="EKYC_", extra="ignore")

    environment: str = "development"
    base_url: str = "http://localhost:8000"

    database_url: str = "sqlite:///./ekyc.db"
    redis_url: str = "redis://localhost:6379/0"
    celery_always_eager: bool = True
    # Reconciliation sweep: a non-terminal session untouched for this long is
    # considered stuck (lost task) and its pending work is requeued.
    stuck_session_minutes: int = 15

    admin_api_key: str = "change-me-admin-key"
    jwt_secret: str = "change-me-jwt-secret"
    access_token_ttl_seconds: int = 3600
    session_ttl_seconds: int = 1800

    storage_backend: str = "local"  # local | s3
    storage_root: str = "./var/storage"
    s3_bucket: str = ""
    s3_endpoint_url: str = ""
    s3_region: str = "eu-west-1"

    # Data vault: at-rest envelope encryption (AES-256-GCM) for every artifact.
    # DEKs are derived per tenant from a master KEK held outside the data.
    # Enable in production; legacy plaintext blobs stay readable either way.
    storage_encryption: bool = False
    kek: str = ""  # 32-byte key, hex or base64 — inject from KMS/secrets in prod
    kek_path: str = "./var/keys/kek.hex"  # dev fallback: auto-generated file
    kek_version: int = 1  # bump to rotate DEKs; old blobs stay decryptable
    kms_backend: str = "local"  # local | (aws-kms/vault: implement KeyProvider)

    # Regulatory orchestrator: jurisdiction rules and vault topology.
    default_jurisdiction: str = "GLOBAL"
    # Extra vaults beyond "default", JSON object:
    # {"vps-abidjan": {"backend": "local", "root": "/srv/ci/storage"},
    #  "s3-eu": {"backend": "s3", "bucket": "ekyc-eu",
    #            "endpoint_url": "https://s3.eu-west-1.amazonaws.com", "region": "eu-west-1"}}
    vaults_json: str = ""
    # Extra/overriding jurisdiction rules, JSON object (see orchestrator.py).
    jurisdictions_json: str = ""

    # Trust services: named external TSA providers, JSON object:
    # {"digisign": {"endpoint": "https://tsa.example.com", "timeout_s": 10,
    #               "qualified": true, "auth_header": "Bearer …",
    #               "trusted_ca_path": "/srv/ekyc/tsa-ca.pem"}}
    # A jurisdiction's tsa_policy may then name a provider ("digisign") or use
    # the generic "qualified" (first qualified provider) / "internal" modes.
    tsas_json: str = ""

    ocr_provider: str = "stub"  # stub | tesseract | inhouse
    face_provider: str = "stub"  # stub | inhouse
    otp_provider: str = "log"  # log | http
    otp_http_url: str = ""
    otp_http_auth_header: str = ""  # optional Authorization value for the OTP gateway
    # oauth-sms sender (e.g. 1smsafrica): client_credentials token + JSON body
    otp_oauth_token_url: str = ""
    otp_oauth_client_id: str = ""
    otp_oauth_client_secret: str = ""
    otp_sms_sender_id: str = "TRUSDY"
    otp_message_template: str = "Votre code de verification est {code}."
    # JSON template of the send body; placeholders: {destination}
    # {destination_digits} {message} {code} {sender} {channel}.
    # Empty = {"channel","destination","code"} default.
    otp_http_body_template: str = ""
    # Gateways returning HTTP 200 on failure: JSON field/value meaning "error"
    # (e.g. 1smsafrica: {"status": "error"}). Empty field disables the check.
    otp_http_error_field: str = "status"
    otp_http_error_value: str = "error"
    otp_length: int = 6
    otp_ttl_seconds: int = 300
    otp_max_attempts: int = 5
    # OTP send limits (shared across workers via the Redis rate limiter).
    otp_send_cooldown_seconds: int = 60  # min delay between two sends per session
    otp_send_window_seconds: int = 3600  # window for per-session/per-destination caps
    otp_max_sends_per_session: int = 5
    otp_max_sends_per_destination: int = 10  # survives session re-creation

    # In-house biometric / OCR module (self-hosted, no third-party SaaS).
    # ONNX models run locally; see scripts/fetch_models.py to provision them.
    biometrics_model_dir: str = "./var/models"
    # Path to the approved model manifest (JSON: name -> sha256/source/version).
    # Empty = the packaged manifest shipped with the app (models_manifest.json).
    manifest_path: str = ""
    # Relative paths within the OpenCV Zoo model tree (git-lfs backed).
    face_detector_model: str = "face_detection_yunet/face_detection_yunet_2023mar.onnx"
    face_recognizer_model: str = "face_recognition_sface/face_recognition_sface_2021dec.onnx"
    # media.githubusercontent serves the actual LFS blobs (raw returns pointers).
    face_model_base_url: str = (
        "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models"
    )
    # GPU: auto-detection. When true, ONNX models use the best execution
    # provider available (CUDA > CPU); when false, force CPU. No GPU host?
    # Leave it on — the code silently falls back to CPU.
    gpu_enabled: bool = True
    # Anti-spoofing / liveness model.
    antispoof_model: str = "antispoof_quantized.onnx"
    # Logit-difference threshold for the raw MiniFAS output (0.0 = real > spoof).
    antispoof_threshold: float = 0.0
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
    tsa_qualified_certificates: bool = False  # only final KYC certificate uses paid TSA

    face_match_threshold: float = 0.80
    liveness_threshold: float = 0.70
    document_review_threshold: float = 0.60

    # Risk engine: overall confidence score (0-100) computed from per-step
    # weighted confidences. ACCEPT >= accept, REVIEW >= review, else REJECT.
    risk_accept_threshold: float = 80.0
    risk_review_threshold: float = 50.0

    webhook_timeout_seconds: float = 10.0
    webhook_max_attempts: int = 5


@lru_cache
def get_settings() -> Settings:
    return Settings()


class InsecureConfigError(RuntimeError):
    """Raised at boot when production runs with development-grade secrets."""


# Known development values — a length check alone is not proof of quality:
# these exact strings are refused outright wherever they appear.
_FORBIDDEN_SECRET_VALUES = {
    "",
    "change-me-admin-key",
    "change-me-jwt-secret",
    "test-admin-key",
    "test-jwt-secret",
    "secret",
    "changeme",
    "admin",
    "password",
}

_DEV_ONLY_PROVIDERS = {"stub", "log"}


def _weak_secret(value: str | None) -> str | None:
    """Returns a violation label or None — never the secret itself."""
    if value is None or value.strip() == "":
        return "missing or empty"
    if value.strip() in _FORBIDDEN_SECRET_VALUES:
        return "a known development/default value"
    if len(value) < 32:
        return "shorter than 32 characters"
    return None


def validate_production_settings(cfg: Settings | None = None) -> None:
    """Fail-fast boot validation — production must not run on dev secrets.

    Violations are reported by *label* only: secret values never appear in
    the exception, in logs or in responses.
    """
    cfg = cfg or settings
    if cfg.environment != "production":
        return

    violations: list[str] = []
    for field in ("admin_api_key", "jwt_secret"):
        reason = _weak_secret(getattr(cfg, field))
        if reason:
            violations.append(f"EKYC_{field.upper()}: {reason}")
    if cfg.signing_dev_self_signed_cert:
        violations.append(
            "EKYC_SIGNING_DEV_SELF_SIGNED_CERT: development certificate "
            "cannot be used in production"
        )
    for field in ("ocr_provider", "face_provider", "otp_provider"):
        if getattr(cfg, field) in _DEV_ONLY_PROVIDERS:
            violations.append(
                f"EKYC_{field.upper()}: '{getattr(cfg, field)}' provider " "is development-only"
            )
    if cfg.storage_encryption and not cfg.kek:
        violations.append("EKYC_KEK: required when storage encryption is enabled")

    if violations:
        raise InsecureConfigError(
            "Refusing to start in production — fix configuration:\n  - " + "\n  - ".join(violations)
        )


settings = get_settings()
