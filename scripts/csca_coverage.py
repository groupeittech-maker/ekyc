"""CSCA trust-store coverage inventory.

Reports, per country code present in the store:
  - how many CSCA certificates are held,
  - the soonest expiry (attention needed before chain breakage),
  - provenance (which source file they came from).

Three-level truth per country (as required by ops policy):
  L1 CSCA available        — certs present in the store (this report)
  L2 DSC chain verifiable  — a real SOD signature verifies end-to-end
                             (measured on live NFC reads — manual test)
  L3 Real passport tested  — a physical document was read + validated
                             (manual test, recorded separately)

Usage: python -m scripts.csca_coverage [--json] [--expiring-days 180]
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

from app.core.config import settings


def _load_store(csca_dir: Path) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    for pem in sorted(csca_dir.glob("*.pem")):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                certs.extend(x509.load_pem_x509_certificates(pem.read_bytes()))
            except Exception:
                continue
    return certs


def _country(cert: x509.Certificate) -> str:
    for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME):
        return attr.value.upper()
    return "??"


def _source(csca_dir: Path, fingerprint: str) -> str:
    prov = csca_dir / "provenance.json"
    if not prov.exists():
        return "unknown"
    for src in json.loads(prov.read_text()).get("sources", []):
        if fingerprint in src.get("sha256", []):
            return src["source"].split("/")[-1][:40]
    return "unknown"


def report(csca_dir: Path, expiring_days: int) -> dict:
    now = datetime.now(timezone.utc)
    by_country: dict[str, list] = defaultdict(list)
    for cert in _load_store(csca_dir):
        by_country[_country(cert)].append(cert)

    countries = []
    for cc in sorted(by_country):
        certs = by_country[cc]
        expiries = sorted(
            c.not_valid_after_utc if hasattr(c, "not_valid_after_utc")
            else c.not_valid_after.replace(tzinfo=timezone.utc)
            for c in certs
        )
        # A country remains trustable while ANY of its CSCAs is valid —
        # earliest expiry is shown for renewal tracking only.
        latest = expiries[-1]
        usable = latest > now
        countries.append(
            {
                "country": cc,
                "csca_count": len(certs),
                "earliest_expiry": expiries[0].isoformat()[:10],
                "latest_expiry": latest.isoformat()[:10],
                "days_to_expiry": (latest - now).days,
                "status": "csca-available" if usable else "all-csca-expired",
            }
        )
    return {
        "generated_at": now.isoformat(),
        "store": str(csca_dir),
        "total_certificates": sum(len(v) for v in by_country.values()),
        "total_countries": len(countries),
        "countries": countries,
        "expiring_soon": [
            c["country"]
            for c in countries
            if c["days_to_expiry"] < expiring_days
        ],
        "levels": {
            "L1": "csca-available (this report)",
            "L2": "dsc-chain-verified (measured on NFC reads)",
            "L3": "real-passport-tested (manual)",
        },
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--json", action="store_true")
    p.add_argument("--expiring-days", type=int, default=180)
    p.add_argument("--dir", default=None)
    args = p.parse_args(argv)

    csca_dir = Path(args.dir or settings.csca_dir).expanduser()
    r = report(csca_dir, args.expiring_days)

    if args.json:
        print(json.dumps(r, indent=2))
        return 0

    print(f"CSCA coverage — {r['total_certificates']} certs, "
          f"{r['total_countries']} countries")
    print(f"{'CC':>4} {'certs':>5} {'latest exp':>12} {'days':>6}  status")
    for c in r["countries"]:
        flag = " !" if c["days_to_expiry"] < args.expiring_days else ""
        print(f"{c['country']:>4} {c['csca_count']:>5} "
              f"{c['latest_expiry']:>12} {c['days_to_expiry']:>6}  "
              f"{c['status']}{flag}")
    if r["expiring_soon"]:
        print(f"\n! expiring <{args.expiring_days}d: {', '.join(r['expiring_soon'])}")
    print("\nL2/L3 require live NFC reads — not inferable from the store.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
