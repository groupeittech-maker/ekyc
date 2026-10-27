"""Fetch CSCA master lists and populate EKYC_CSCA_DIR with PEM certificates.

National PKIs publish signed ``.ml`` files: a CMS SignedData whose eContent
is an ``ICAOMasterList`` (SEQUENCE { version INTEGER, SET OF Certificate }).
A plain LDIF dump is also supported (``dscCscaCertificate`` attributes).

The BSI verifies the CMS signature itself (``openssl cms -verify``) before the
certificates are extracted — a tampered master list is rejected, not parsed.

Extra sources via ``EKYC_CSCA_SOURCES`` (JSON list of URLs). A country whose
master list isn't publicly distributed can always be provisioned manually by
dropping a PEM/DER file into the CSCA directory.

Default: the German federal master list (609 certs, ~120 countries — the only
national list freely downloadable without an ICAO PKD agreement).

Usage:
    python -m scripts.fetch_csca                 # default sources
    python -m scripts.fetch_csca --url <zip|ml|ldif>
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from app.core.config import settings

DEFAULT_SOURCES = [
    "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip",
]

_UA = {"User-Agent": "Mozilla/5.0 (eKYC masterlist fetcher)"}
_CERT_ATTR = re.compile(r"^(?:dscCscaCertificate|userCertificate)::\s*([A-Za-z0-9+/=\s]+)$")


def _pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"


def _fetch(url: str) -> bytes:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:  # noqa: S310 — trusted PKI source
        return resp.read()


# ---------------------------------------------------------------------------
# DER helpers (same minimal TLV logic as the passport_pki engine)
# ---------------------------------------------------------------------------

def _read_len(b: bytes, i: int) -> tuple[int, int]:
    if b[i] < 0x80:
        return b[i], i + 1
    n = b[i] & 0x7F
    return int.from_bytes(b[i + 1 : i + 1 + n], "big"), i + 1 + n


def _children(b: bytes) -> list[tuple[int, bytes, bytes]]:
    """Children of a constructed TLV value: (tag, raw_content, raw_full)."""
    out, i, end = [], 0, len(b)
    while i < end:
        tag = b[i]
        length, hdr_end = _read_len(b, i + 1)
        out.append((tag, b[hdr_end : hdr_end + length], b[i : hdr_end + length]))
        i = hdr_end + length
    return out


def _tlv_value(data: bytes) -> bytes:
    length, hdr_end = _read_len(data, 1)
    return data[hdr_end : hdr_end + length]


def _certs_from_masterlist(content: bytes) -> list[bytes]:
    """ICAOMasterList ::= SEQUENCE { version INTEGER, certSet SET }"""
    seq = _tlv_value(content)
    certs: list[bytes] = []
    for tag, raw, full in _children(seq):
        if tag == 0x31:  # SET OF Certificate
            for _, _, cert_full in _children(raw):
                certs.append(cert_full)
    return certs


def _cms_econtent(blob: bytes, workdir: Path) -> bytes:
    """Verify the CMS signature and return the eContent bytes via openssl."""
    ml = workdir / "in.ml"
    out = workdir / "content.der"
    ml.write_bytes(blob)
    proc = subprocess.run(
        ["openssl", "cms", "-inform", "DER", "-in", str(ml),
         "-verify", "-noverify", "-out", str(out)],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0 or not out.exists():
        raise RuntimeError(f"openssl cms verify failed: {proc.stderr.strip()[:200]}")
    return out.read_bytes()


def _extract(blob: bytes, workdir: Path) -> list[bytes]:
    """Dispatch on the container format: zip > CMS .ml > LDIF > raw SET."""
    if blob[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            name = next(n for n in zf.namelist() if n.lower().endswith((".ml", ".ldif")))
            return _extract(zf.read(name), workdir)
    if blob[:1] == b"0":  # DER — CMS SignedData wrapper
        econtent = _cms_econtent(blob, workdir)
        return _certs_from_masterlist(econtent)
    if b"dn:" in blob[:4096] or b"Certificate" in blob[:4096]:  # LDIF text
        text = blob.decode("utf-8", errors="replace")
        unfolded = re.sub(r"\n ", "", text)
        return [
            base64.b64decode(m.group(1))
            for m in _CERT_ATTR.finditer(unfolded)
        ]
    return _certs_from_masterlist(blob)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch CSCA master lists")
    parser.add_argument("--url", action="append", default=None, help="Extra source (zip/ml/ldif)")
    parser.add_argument("--file", type=Path, default=None, help="Local file instead of URL")
    args = parser.parse_args(argv)

    csca_dir = Path(settings.csca_dir).expanduser()
    csca_dir.mkdir(parents=True, exist_ok=True)

    sources: list[tuple[str, bytes | None]] = [(s, None) for s in (
        json.loads(getattr(settings, "csca_sources", "[]") or "[]") + (args.url or [])
        or DEFAULT_SOURCES
    )]
    if args.file:
        sources = [(args.file.name, args.file.read_bytes())]

    total = 0
    with tempfile.TemporaryDirectory() as td:
        for name, blob in sources:
            try:
                data = blob if blob is not None else _fetch(name)
                der_certs = _extract(data, Path(td))
            except Exception as exc:
                print(f"  ! {name}: {exc}", file=sys.stderr)
                continue
            if not der_certs:
                print(f"  ! {name}: no certificates found", file=sys.stderr)
                continue
            valid = []
            for der in der_certs:
                try:
                    from cryptography import x509
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        x509.load_der_x509_certificate(der)
                    valid.append(der)
                except Exception:
                    continue
            stem = Path(name.split("?")[0]).stem or "csca"
            (csca_dir / f"{stem}.pem").write_text("".join(_pem(d) for d in valid))
            total += len(valid)
            print(f"  + {len(valid):>4} certificates -> {stem}.pem  ({name})")

    print(f"Done — {total} CSCA certificates in {csca_dir}")
    return 0 if total else 1


if __name__ == "__main__":
    raise SystemExit(main())
