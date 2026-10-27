"""Fetch CSCA master lists and populate EKYC_CSCA_DIR with PEM certificates.

Public sources are LDIF dumps (LDAP-style) published by national PKIs; each
``dscCscaCertificate::`` attribute holds a base64-encoded DER certificate.
Extra sources are configured via ``EKYC_CSCA_SOURCES`` (JSON list of URLs);
a country whose master list isn't publicly distributed must be provisioned
manually by dropping the PEM/DER file into the CSCA directory.

Default: the German federal PKD master list (covers DE passports — and is
the only national list freely downloadable without an ICAO PKD agreement).

Usage:
    python -m scripts.fetch_csca                 # default sources
    python -m scripts.fetch_csca --url <ldif>    # extra source
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import ssl
import sys
import urllib.request
from pathlib import Path

from app.core.config import settings

DEFAULT_SOURCES = [
    "https://pkd-download.bsi.bund.de/PKD/Masterlists/ml_de.ldif",
]

# LDIF continuation lines start with a single space.
_CERT_ATTR = re.compile(r"^dscCscaCertificate::\s*([A-Za-z0-9+/=\s]+)$")


def _pem(der: bytes, name: str) -> str:
    b64 = base64.b64encode(der).decode()
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"# source: {name}\n-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"


def _fetch(url: str) -> str:
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(url, context=ctx, timeout=60) as resp:  # noqa: S310 — trusted PKD source
        return resp.read().decode("utf-8", errors="replace")


def _parse_ldif(text: str) -> list[bytes]:
    """Extract every base64 DSC/CSCA certificate from an LDIF dump.

    Attribute values may span continuation lines (leading space).
    """
    unfolded = re.sub(r"\n ", "", text)
    certs = []
    for match in _CERT_ATTR.finditer(unfolded):
        try:
            certs.append(base64.b64decode(match.group(1)))
        except Exception:
            continue
    return certs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch CSCA master lists")
    parser.add_argument("--url", action="append", default=None, help="Extra LDIF URL")
    args = parser.parse_args(argv)

    csca_dir = Path(settings.csca_dir).expanduser()
    csca_dir.mkdir(parents=True, exist_ok=True)

    sources = json.loads(getattr(settings, "csca_sources", "[]") or "[]")
    sources += args.url or []
    if not sources:
        sources = list(DEFAULT_SOURCES)

    total = 0
    for url in sources:
        name = url.rstrip("/").split("/")[-1] or "csca"
        try:
            text = _fetch(url)
        except Exception as exc:
            print(f"  ! {url}: fetch failed ({exc})", file=sys.stderr)
            continue
        certs = _parse_ldif(text)
        if not certs:
            print(f"  ! {url}: no certificates found", file=sys.stderr)
            continue
        out = csca_dir / f"{Path(name).stem}.pem"
        out.write_text("".join(_pem(c, f"{url}") for c in certs))
        total += len(certs)
        print(f"  + {len(certs):>4} certificates -> {out.name}  ({url})")

    print(f"Done — {total} CSCA certificates in {csca_dir}")
    return 0 if total else 1


if __name__ == "__main__":
    raise SystemExit(main())
