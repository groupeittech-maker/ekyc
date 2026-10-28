"""ICAO 9303 eMRTD passive authentication — server side.

The mobile app reads the chip over NFC and uploads EF.COM, EF.SOD and the data
groups. This module performs passive authentication:

1. parse EF.COM — declared data groups and LDS version;
2. parse EF.SOD (CMS SignedData) — the eContent is the LDS security object
   carrying the hash of each data group; computed DG hashes must match;
3. verify the CMS signature with the embedded Document Signer Certificate;
4. chain the DSC to a CSCA certificate from the trust store
   (``EKYC_CSCA_DIR`` — a master list directory of PEM/DER certificates).

Statuses mirror the decision table: VALID, INVALID (cryptographic failure) or
INDETERMINATE (verification impossible — e.g. unknown CSCA, unsupported
algorithm). An unknown CSCA is NOT proof of forgery.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.hashes import SHA1, SHA224, SHA256, SHA384, SHA512

from app.core.config import settings

PkiStatus = str  # "VALID" | "INVALID" | "INDETERMINATE"


@dataclass
class PkiResult:
    status: PkiStatus
    reason: str
    details: dict = field(default_factory=dict)


class _DerError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# Minimal DER reader — enough to walk CMS and the LDS security object.
# --------------------------------------------------------------------------- #
def _read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, bytes, int]:
    """Return (tag, content, full_tlv, next_offset) for the TLV at ``offset``."""
    if offset >= len(data):
        raise _DerError("unexpected end of data")
    tag = data[offset]
    pos = offset + 1
    if tag & 0x1F == 0x1F:  # multi-byte tag
        tag = tag << 8 | data[pos]
        pos += 1
    if pos >= len(data):
        raise _DerError("missing length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        size = first
    elif first == 0x80:
        raise _DerError("indefinite length not supported")
    else:
        nbytes = first & 0x7F
        size = int.from_bytes(data[pos : pos + nbytes], "big")
        pos += nbytes
    end = pos + size
    if end > len(data):
        raise _DerError("length exceeds buffer")
    return tag, data[pos:end], data[offset:end], end


def _children(data: bytes) -> list[tuple[int, bytes, bytes]]:
    """All TLV children inside a constructed value: (tag, content, full_tlv)."""
    out = []
    pos = 0
    while pos < len(data):
        tag, content, full, pos = _read_tlv(data, pos)
        out.append((tag, content, full))
    return out


def _oid(content: bytes) -> str:
    if not content:
        raise _DerError("empty OID")
    first = content[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


_HASHES = {
    "1.3.14.3.2.26": (hashlib.sha1, SHA1),
    "2.16.840.1.101.3.4.2.4": (hashlib.sha224, SHA224),
    "2.16.840.1.101.3.4.2.1": (hashlib.sha256, SHA256),
    "2.16.840.1.101.3.4.2.2": (hashlib.sha384, SHA384),
    "2.16.840.1.101.3.4.2.3": (hashlib.sha512, SHA512),
}
_SIG_RSA = {
    "1.2.840.113549.1.1.5": SHA1,
    "2.16.840.1.101.3.4.3.2": SHA224,
    "1.2.840.113549.1.1.11": SHA256,
    "1.2.840.113549.1.1.12": SHA384,
    "1.2.840.113549.1.1.13": SHA512,
}
_SIG_ECDSA = {
    "1.2.840.10045.4.1": SHA1,
    "1.2.840.10045.4.3.1": SHA224,
    "1.2.840.10045.4.3.2": SHA256,
    "1.2.840.10045.4.3.3": SHA384,
    "1.2.840.10045.4.3.4": SHA512,
}
_OID_RSA_PSS = "1.2.840.113549.1.1.10"
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"


def _digest_factory(oid: str):
    entry = _HASHES.get(oid)
    return entry[0] if entry else None


def _hash_algorithm(oid: str):
    entry = _HASHES.get(oid)
    return entry[1]() if entry else None


def _first(seq: list[tuple[int, bytes, bytes]], tag: int) -> bytes | None:
    for t, content, _ in seq:
        if t == tag:
            return content
    return None


# --------------------------------------------------------------------------- #
# EF.COM — declared data groups
# --------------------------------------------------------------------------- #
# ICAO 9303 data-group tags are NOT sequential: DG1=0x61, DG2=0x75, DG3=0x63,
# DG4=0x76, DG5..DG16 = 0x65..0x70. EF.COM carries these tag values, so map
# each tag byte to its data-group number.
_DG_TAG_TO_NUMBER = {
    0x61: 1, 0x75: 2, 0x63: 3, 0x76: 4,
    0x65: 5, 0x66: 6, 0x67: 7, 0x68: 8, 0x69: 9, 0x6A: 10,
    0x6B: 11, 0x6C: 12, 0x6D: 13, 0x6E: 14, 0x6F: 15, 0x70: 16,
}


def parse_ef_com(ef_com: bytes) -> dict:
    """Return {lds_version, dg_tags} — tag list tells which DGs the chip holds."""
    tag, content, _, _ = _read_tlv(ef_com)  # application tag 0x60 or plain SEQ
    if tag not in (0x60, 0x30):
        raise _DerError("EF.COM must start with tag 0x60 or SEQUENCE")
    fields = _children(content)
    dg_tags: list[int] = []
    tag_list = _first(fields, 0x5C)
    if tag_list is not None:
        dg_tags = list(tag_list)
    lds_raw = _first(fields, 0x5F01) or b""
    return {"lds_version": lds_raw.decode("ascii", "replace"), "dg_tags": dg_tags}


# --------------------------------------------------------------------------- #
# EF.SOD — CMS SignedData + LDS security object
# --------------------------------------------------------------------------- #
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"


@dataclass
class Sod:
    econtent: bytes
    dg_hashes: dict[int, bytes]
    dg_hash_oid: str
    signer_cert_der: bytes
    signed_attrs_der: bytes  # re-encoded as SET OF for signature verification
    message_digest: bytes | None  # signed attribute committing to eContent
    signature: bytes
    signature_alg_oid: str
    digest_oid: str


def parse_sod(ef_sod: bytes) -> Sod:
    tag, content, _, _ = _read_tlv(ef_sod)
    if tag == 0x77:  # EF.SOD wraps the ContentInfo in application tag 23
        inner = _children(content)
        content = _first(inner, 0x30) or content
    elif tag != 0x30:
        raise _DerError("EF.SOD must be tag 0x77 or a SEQUENCE")
    content_info = _children(content)
    if len(content_info) < 2 or _oid(content_info[0][1]) != _OID_SIGNED_DATA:
        raise _DerError("not a SignedData content type")
    if content_info[1][0] != 0xA0:
        raise _DerError("SignedData must be [0] EXPLICIT")
    # [0] EXPLICIT wraps the SignedData SEQUENCE.
    signed_data_seq = _children(content_info[1][1])
    sd = _children(signed_data_seq[0][1])

    # SignedData ::= { version, digestAlgorithms, encapContentInfo, certs?, signerInfos }
    encap = _children(sd[2][1])
    econtent_raw = _first(encap, 0xA0)
    if econtent_raw is None:
        raise _DerError("missing encapsulated content")
    econtent = _children(econtent_raw)[0][1]  # OCTET STRING content

    certs_der: list[bytes] = []
    signer_infos: list[tuple[int, bytes, bytes]] = []
    for item in sd[3:]:
        if item[0] == 0xA0:  # [0] IMPLICIT certificates
            certs_der = [full for _, _, full in _children(item[1])]
        elif item[0] == 0x31:  # SET OF SignerInfo
            signer_infos = _children(item[1])
    if not certs_der or not signer_infos:
        raise _DerError("missing DSC certificate or signerInfo")

    si = _children(signer_infos[0][1])
    # SignerInfo ::= { version, sid, digestAlgorithm, signedAttrs?[0], sigAlg, signature }
    signed_attrs_raw = None
    signature_alg_oid = ""
    signature = b""
    digest_oid = ""
    for item in si:
        if item[0] == 0x30:
            # AlgorithmIdentifier sequences start with an OID — the
            # issuerAndSerialNumber SEQ does not, so it is skipped safely.
            alg = _children(item[1])
            if not alg or alg[0][0] != 0x06:
                continue
            oid = _oid(alg[0][1])
            if oid in _HASHES and not digest_oid:
                digest_oid = oid
            elif oid not in _HASHES:
                signature_alg_oid = oid
        elif item[0] == 0xA0:
            signed_attrs_raw = item[1]
        elif item[0] == 0x04:
            signature = item[1]
    if signed_attrs_raw is None or not signature or not signature_alg_oid:
        raise _DerError("incomplete SignerInfo")
    # The signature covers the DER encoding of the attributes as a SET OF.
    signed_attrs_der = b"\x31" + _der_length(len(signed_attrs_raw)) + signed_attrs_raw

    # Extract the messageDigest signed attribute — it binds the signature to
    # this exact eContent (defends against a swapped LDS security object).
    message_digest: bytes | None = None
    for attr in _children(signed_attrs_raw):
        parts = _children(attr[1])
        if parts and _oid(parts[0][1]) == _OID_MESSAGE_DIGEST:
            values = _children(parts[1][1])
            if values:
                message_digest = values[0][1]

    dg_hashes, dg_oid = _parse_lds_security_object(econtent)
    return Sod(
        econtent=econtent,
        dg_hashes=dg_hashes,
        dg_hash_oid=dg_oid,
        signer_cert_der=certs_der[0],
        signed_attrs_der=signed_attrs_der,
        message_digest=message_digest,
        signature=signature,
        signature_alg_oid=signature_alg_oid,
        digest_oid=digest_oid or "2.16.840.1.101.3.4.2.1",
    )


def _der_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _parse_lds_security_object(econtent: bytes) -> tuple[dict[int, bytes], str]:
    tag, seq, _, _ = _read_tlv(econtent)
    if tag != 0x30:
        raise _DerError("LDS security object must be a SEQUENCE")
    items = _children(seq)
    if len(items) < 3:
        raise _DerError("incomplete LDS security object")
    hash_alg = _oid(_children(items[1][1])[0][1])
    hashes: dict[int, bytes] = {}
    for entry in _children(items[2][1]):
        parts = _children(entry[1])
        dg = int.from_bytes(parts[0][1], "big")
        hashes[dg] = parts[1][1]
    return hashes, hash_alg


# --------------------------------------------------------------------------- #
# Verification steps
# --------------------------------------------------------------------------- #
def _verify_dg_hashes(sod: Sod, groups: dict[int, bytes]) -> tuple[bool, list[str]]:
    digest = _digest_factory(sod.dg_hash_oid)
    if digest is None:
        raise _DerError(f"unsupported DG hash algorithm {sod.dg_hash_oid}")
    mismatched: list[str] = []
    for number, data in groups.items():
        expected = sod.dg_hashes.get(number)
        if expected is None:
            mismatched.append(f"DG{number}:UNDECLARED")
        elif digest(data).digest() != expected:
            mismatched.append(f"DG{number}:HASH_MISMATCH")
    return not mismatched, mismatched


_OID_RSA_GENERIC = "1.2.840.113549.1.1.1"  # rsaEncryption: hash lives in digestAlgorithm


def _verify_cms_signature(sod: Sod) -> bool:
    cert = x509.load_der_x509_certificate(sod.signer_cert_der)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        sig_oid = sod.signature_alg_oid
        if sig_oid in _SIG_RSA:
            pad, hash_alg = padding.PKCS1v15(), _SIG_RSA[sig_oid]()
        elif sig_oid in (_OID_RSA_GENERIC, _OID_RSA_PSS):
            # Generic RSA/PSS identifiers defer the digest to digestAlgorithm.
            hash_alg = _hash_algorithm(sod.digest_oid)
            if hash_alg is None:
                raise _DerError(f"unsupported digest OID {sod.digest_oid}")
            pad = (
                padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size)
                if sig_oid == _OID_RSA_PSS
                else padding.PKCS1v15()
            )
        else:
            raise _DerError(f"unsupported RSA signature OID {sig_oid}")
        key.verify(sod.signature, sod.signed_attrs_der, pad, hash_alg)
        return True
    if isinstance(key, ec.EllipticCurvePublicKey):
        hash_cls = _SIG_ECDSA.get(sod.signature_alg_oid)
        if hash_cls is None:
            raise _DerError(f"unsupported ECDSA signature OID {sod.signature_alg_oid}")
        key.verify(sod.signature, sod.signed_attrs_der, ec.ECDSA(hash_cls()))
        return True
    raise _DerError("unsupported DSC public key type")


def _load_csca_store() -> list[x509.Certificate]:
    """Load every certificate under ``EKYC_CSCA_DIR`` (PEM files may hold a
    concatenated master list). An unreadable file is skipped, not fatal."""
    path = Path(settings.csca_dir).expanduser()
    if not path.is_dir():
        return []
    certs: list[x509.Certificate] = []
    for file in sorted(path.iterdir()):
        if file.suffix.lower() not in {".pem", ".der", ".cer", ".crt"}:
            continue
        blob = file.read_bytes()
        if b"-----BEGIN CERTIFICATE-----" in blob:
            for chunk in blob.split(b"-----END CERTIFICATE-----"):
                if b"-----BEGIN CERTIFICATE-----" not in chunk:
                    continue
                try:
                    certs.append(
                        x509.load_pem_x509_certificate(chunk + b"-----END CERTIFICATE-----")
                    )
                except Exception:
                    continue
        else:
            try:
                certs.append(x509.load_der_x509_certificate(blob))
            except Exception:
                continue
    return certs


def _crl_dir() -> Path:
    if settings.crl_dir:
        return Path(settings.crl_dir).expanduser()
    return Path(settings.csca_dir).expanduser() / "crls"


def _load_crl_store() -> list[x509.CertificateRevocationList]:
    """Load every CRL under the crl dir (.crl/.der binary, .pem armored)."""
    path = _crl_dir()
    if not path.is_dir():
        return []
    crls: list[x509.CertificateRevocationList] = []
    for file in sorted(path.iterdir()):
        if file.suffix.lower() not in {".crl", ".der", ".pem"}:
            continue
        blob = file.read_bytes()
        try:
            if b"-----BEGIN X509 CRL-----" in blob:
                crls.append(x509.load_pem_x509_crl(blob))
            else:
                crls.append(x509.load_der_x509_crl(blob))
        except Exception:
            continue
    return crls


def _verify_crl_signature(
    crl: x509.CertificateRevocationList, csca: x509.Certificate
) -> bool:
    """The CRL must be signed by the issuing CSCA — an unverifiable CRL
    carries no weight either way."""
    key = csca.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm,
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                ec.ECDSA(crl.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except Exception:
        return False


def _aware(dt):
    from datetime import timezone

    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _crl_time(crl: x509.CertificateRevocationList, attr: str):
    """cryptography <42 uses naive last_update/next_update; newer exposes
    *_utc variants. Normalise to aware datetimes."""
    aware = getattr(crl, f"{attr}_utc", None)
    if aware is not None:
        return aware
    naive = getattr(crl, attr, None)
    return _aware(naive) if naive is not None else None


def _check_revocation(
    dsc: x509.Certificate, csca: x509.Certificate
) -> tuple[str, dict]:
    """DSC revocation check against CRLs issued by its CSCA.

    Outcomes — absence or staleness is NEVER treated as revocation:
      REVOKED       — serial listed in a signature-verified CRL (hard evidence,
                      even from a stale list: revocation is affirmative)
      NOT_REVOKED   — fresh verified CRL does not list the serial
      STALE         — verified CRL exists but nextUpdate has lapsed beyond
                      the grace window: revocation state is unknown
      NO_CRL        — issuer publishes no CRL we hold
      UNVERIFIABLE  — a CRL candidate's signature cannot be verified
    """
    from app.db.base import utcnow

    now = utcnow()
    candidates = [
        c for c in _load_crl_store() if c.issuer.rfc4514_string() == csca.subject.rfc4514_string()
    ]
    if not candidates:
        return "NO_CRL", {}
    crl = max(candidates, key=lambda c: _crl_time(c, "last_update"))
    if not _verify_crl_signature(crl, csca):
        return "UNVERIFIABLE", {"crl_issuer": crl.issuer.rfc4514_string()}

    next_update = _crl_time(crl, "next_update")
    details = {
        "crl_issuer": crl.issuer.rfc4514_string(),
        "crl_this_update": _crl_time(crl, "last_update").isoformat(),
        "crl_next_update": next_update.isoformat() if next_update else None,
    }
    entry = crl.get_revoked_certificate_by_serial_number(dsc.serial_number)
    if entry is not None:
        rev_date = getattr(entry, "revocation_date_utc", None) or _aware(entry.revocation_date)
        details["revocation_date"] = rev_date.isoformat()
        return "REVOKED", details
    if next_update is not None:
        stale_after = next_update + timedelta(days=settings.crl_staleness_days)
        if now > stale_after:
            details["stale_since"] = stale_after.isoformat()
            return "STALE", details
    return "NOT_REVOKED", details


def _chain_to_csca(
    dsc: x509.Certificate,
) -> tuple[PkiStatus, str, dict, x509.Certificate | None]:
    from app.db.base import utcnow

    now = utcnow()
    details = {"dsc_subject": dsc.subject.rfc4514_string(), "csca_store": settings.csca_dir}
    if now < dsc.not_valid_before_utc or now > dsc.not_valid_after_utc:
        return "INVALID", "DSC_EXPIRED", details, None
    cscas = _load_csca_store()
    if not cscas:
        return "INDETERMINATE", "CSCA_STORE_EMPTY", details, None
    for csca in cscas:
        if csca.subject != dsc.issuer:
            continue
        key = csca.public_key()
        try:
            if isinstance(key, rsa.RSAPublicKey):
                key.verify(
                    dsc.signature,
                    dsc.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    dsc.signature_hash_algorithm,
                )
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(
                    dsc.signature,
                    dsc.tbs_certificate_bytes,
                    ec.ECDSA(dsc.signature_hash_algorithm),
                )
            else:
                continue
        except InvalidSignature:
            return "INVALID", "DSC_SIGNATURE_BAD", details, None
        except Exception:
            continue
        details["csca_subject"] = csca.subject.rfc4514_string()
        return "VALID", "CHAINED", details, csca
    return "INDETERMINATE", "CSCA_UNKNOWN", details, None


def verify_passport(
    *,
    ef_com: bytes,
    ef_sod: bytes,
    dg1: bytes | None = None,
    dg2: bytes | None = None,
) -> PkiResult:
    """Passive authentication of an eMRTD NFC read.

    dg1/dg2 are the raw EF.DG bytes exactly as read from the chip — their
    hashes must match the values signed inside the SOD.
    """
    try:
        com = parse_ef_com(ef_com)
        sod = parse_sod(ef_sod)
    except _DerError as exc:
        # Malformed upload: cannot even parse — not cryptographic proof of
        # forgery, so indeterminate rather than invalid.
        return PkiResult("INDETERMINATE", f"MALFORMED:{exc}", {})

    groups = {1: dg1, 2: dg2}
    provided = {n: d for n, d in groups.items() if d}
    details: dict = {"lds_version": com["lds_version"], "provided_dgs": sorted(provided)}

    # EF.COM lists DG *tags* (0x61 = DG1, 0x75 = DG2, …); map to DG numbers.
    declared = (
        {_DG_TAG_TO_NUMBER.get(tag, tag - 0x60) for tag in com["dg_tags"]}
        if com["dg_tags"]
        else set(provided)
    )
    missing = [n for n in provided if n not in declared]
    if missing:
        return PkiResult("INVALID", f"DG_NOT_IN_EF_COM:{missing}", details)

    try:
        # The signed messageDigest attribute must commit to this eContent —
        # otherwise the LDS object could be swapped without breaking the CMS
        # signature.
        digest = _digest_factory(sod.digest_oid)
        if digest is None:
            return PkiResult("INDETERMINATE", f"unsupported digest {sod.digest_oid}", details)
        if sod.message_digest is not None and digest(sod.econtent).digest() != sod.message_digest:
            return PkiResult("INVALID", "MESSAGE_DIGEST_MISMATCH", details)
        hashes_ok, mismatched = _verify_dg_hashes(sod, provided)
    except _DerError as exc:
        return PkiResult("INDETERMINATE", str(exc), details)
    if not hashes_ok:
        # A hash mismatch is hard evidence the chip data was altered.
        return PkiResult("INVALID", f"DG_HASH_MISMATCH:{mismatched}", details)

    try:
        _verify_cms_signature(sod)
    except InvalidSignature:
        return PkiResult("INVALID", "SOD_SIGNATURE_BAD", details)
    except _DerError as exc:
        return PkiResult("INDETERMINATE", str(exc), details)
    except Exception:
        return PkiResult("INDETERMINATE", "SOD_SIGNATURE_UNVERIFIABLE", details)

    dsc = x509.load_der_x509_certificate(sod.signer_cert_der)
    chain_status, reason, chain_details, csca = _chain_to_csca(dsc)
    details.update(chain_details)
    if chain_status != "VALID":
        # DG hashes + SOD signature are valid; only the trust anchor is unknown.
        return PkiResult(chain_status, reason, details)

    # Revocation layer — a confirmed revocation invalidates; an absent or
    # stale CRL is recorded honestly, never treated as proof of revocation
    # nor silently as proof of non-revocation.
    rev_status, rev_details = _check_revocation(dsc, csca)  # type: ignore[arg-type]
    details["dsc_revocation"] = rev_status
    details.update(rev_details)
    if rev_status == "REVOKED":
        return PkiResult("INVALID", "DSC_REVOKED", details)
    if rev_status != "NOT_REVOKED":
        details["revocation_unchecked"] = True
    return PkiResult("VALID", "PASSIVE_AUTH_OK", details)
