from __future__ import annotations

from app.engines.signature import (
    certificate_fingerprint,
    public_key_pem,
    sign_digest,
    verify_signature,
)


def test_sign_and_verify_roundtrip() -> None:
    payload = b"contract-digest" * 4
    signature = sign_digest(payload)

    assert signature.algorithm == "RSASSA-PKCS1-v1_5-SHA256"
    assert verify_signature(payload, signature.value) is True
    assert verify_signature(payload + b"tampered", signature.value) is False


def test_dev_self_signed_certificate_is_present() -> None:
    # The local signer auto-generates a dev certificate, so evidence carries a
    # real fingerprint even without a provisioned cert.
    assert certificate_fingerprint() is not None
    assert public_key_pem().startswith("-----BEGIN PUBLIC KEY-----")
