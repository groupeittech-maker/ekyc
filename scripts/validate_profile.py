"""Validate a country profile file against the strict schema.

Usage: python -m scripts.validate_profile country-profiles/CI.json [--strict]

--strict additionally requires all activation flags true and a signature-
verifiable attestation (needs EKYC_CENTRAL_PUBLIC_KEY set or --pubkey).
"""

from __future__ import annotations

import argparse
import sys

from app.core.country_profile import (
    ActivationAttestation,
    _verify_attestation,
    load_profile,
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("profile")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--pubkey", default=None, help="Central public key (b64/hex/PEM)")
    args = p.parse_args(argv)

    try:
        profile = load_profile(args.profile)
    except Exception as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"schema OK — {profile.country_code} ({profile.deployment_mode})")

    act = profile.activation
    flags = [act.legal_review, act.hosting_approved, act.trust_services_validated]
    if not all(flags):
        print("  ! activation flags not all true — instance will NOT boot in production")
        if args.strict:
            return 1
    if profile.activation_attestation is None:
        print("  ! no Central attestation embedded")
        return 1 if args.strict else 0
    if args.pubkey:
        from app.core.config import settings

        settings.central_public_key = args.pubkey
    reason = _verify_attestation(ActivationAttestation(**profile.activation_attestation.model_dump()))
    if reason:
        print(f"  ! attestation: {reason}")
        return 1
    print("  + attestation valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
