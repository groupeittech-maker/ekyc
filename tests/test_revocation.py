"""DSC revocation via CRL — the P0 trust-store layer.

Policy under test: a signature-verified CRL that lists the DSC serial
revokes it; an absent, stale or unverifiable CRL is NEVER treated as
proof of revocation — it's recorded honestly in the proof details.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID

from app.core.config import settings
from app.db.base import utcnow
from app.engines import passport_pki as pki
from tests.test_recapture_nfc import (
    _build_ef_com,
    encode_integer,
    encode_null,
    encode_octet_string,
    encode_oid,
    encode_sequence,
)


def _cert(cn, issuer_name=None, issuer_key=None, ca=False):
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name or name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utcnow() - timedelta(days=1))
        .not_valid_after(utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(issuer_key or key, hashes.SHA256()), key


def _env(tmp_path, monkeypatch, crl: str | None = None):
    """crl: None = no CRL | "fresh" | "stale" | "revoked" | "bad-sig"."""
    csca, csca_key = _cert("TEST CSCA", ca=True)
    dsc, dsc_key = _cert("TEST DSC", issuer_name=csca.subject, issuer_key=csca_key)

    csca_dir = tmp_path / "csca"
    crl_dir = csca_dir / "crls"
    crl_dir.mkdir(parents=True)
    (csca_dir / "csca.pem").write_bytes(csca.public_bytes(Encoding.PEM))
    monkeypatch.setattr(settings, "csca_dir", str(csca_dir))
    monkeypatch.setattr(settings, "crl_dir", "")

    dg1, dg2 = b"DG1-content", b"DG2-content"
    sha256_oid = (2, 16, 840, 1, 101, 3, 4, 2, 1)
    dg_hashes = encode_sequence(
        *[
            encode_sequence(encode_integer(n), encode_octet_string(hashlib.sha256(d).digest()))
            for n, d in ((1, dg1), (2, dg2))
        ]
    )
    econtent = encode_sequence(
        encode_integer(0),
        encode_sequence(encode_oid(sha256_oid), encode_null()),
        dg_hashes,
    )
    sod = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(econtent)
        .add_signer(dsc, dsc_key, hashes.SHA256())
        .sign(Encoding.DER, [])
    )

    if crl:
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(csca.subject)
            .last_update(utcnow() - timedelta(days=200 if crl == "stale" else 10))
            .next_update(
                utcnow() - timedelta(days=80)
                if crl == "stale"
                else utcnow() + timedelta(days=30)
            )
        )
        if crl == "revoked":
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(dsc.serial_number)
                .revocation_date(utcnow() - timedelta(days=2))
                .build()
            )
        signer = rsa.generate_private_key(65537, 2048) if crl == "bad-sig" else csca_key
        blob = builder.sign(signer, hashes.SHA256()).public_bytes(Encoding.DER)
        (crl_dir / "test.crl").write_bytes(blob)

    return _build_ef_com(), sod, dg1, dg2


def _run(ef_com, sod, dg1, dg2):
    return pki.verify_passport(ef_com=ef_com, ef_sod=sod, dg1=dg1, dg2=dg2)


def test_no_crl_is_unchecked_not_revoked(tmp_path, monkeypatch):
    ef, sod, dg1, dg2 = _env(tmp_path, monkeypatch)
    res = _run(ef, sod, dg1, dg2)
    assert res.status == "VALID"
    assert res.details["dsc_revocation"] == "NO_CRL"
    assert res.details["revocation_unchecked"] is True


def test_revoked_serial_invalidates(tmp_path, monkeypatch):
    ef, sod, dg1, dg2 = _env(tmp_path, monkeypatch, crl="revoked")
    res = _run(ef, sod, dg1, dg2)
    assert res.status == "INVALID"
    assert res.reason == "DSC_REVOKED"
    assert res.details["dsc_revocation"] == "REVOKED"
    assert "revocation_date" in res.details


def test_fresh_crl_confirms_not_revoked(tmp_path, monkeypatch):
    ef, sod, dg1, dg2 = _env(tmp_path, monkeypatch, crl="fresh")
    res = _run(ef, sod, dg1, dg2)
    assert res.status == "VALID"
    assert res.details["dsc_revocation"] == "NOT_REVOKED"
    assert "revocation_unchecked" not in res.details


def test_stale_crl_leaves_unknown(tmp_path, monkeypatch):
    ef, sod, dg1, dg2 = _env(tmp_path, monkeypatch, crl="stale")
    res = _run(ef, sod, dg1, dg2)
    assert res.status == "VALID"
    assert res.details["dsc_revocation"] == "STALE"
    assert res.details["revocation_unchecked"] is True


def test_wrongly_signed_crl_is_unverifiable(tmp_path, monkeypatch):
    ef, sod, dg1, dg2 = _env(tmp_path, monkeypatch, crl="bad-sig")
    res = _run(ef, sod, dg1, dg2)
    assert res.status == "VALID"
    assert res.details["dsc_revocation"] == "UNVERIFIABLE"
    assert res.details["revocation_unchecked"] is True
