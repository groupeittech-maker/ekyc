"""TSA Manager — trusted timestamping providers.

Module A of the trust-services layer. Two provider classes:

* **internal** — the platform's own soft timestamp (digest | issued_at signed
  with the platform key). Honest evidence: ``qualified=False``, it is never
  presented as equivalent to a recognised authority.
* **external** — an RFC 3161 TSA connector. Per-provider config via
  ``EKYC_TSAS_JSON``:

      EKYC_TSAS_JSON='{"digisign": {"endpoint": "https://tsa.example.com",
        "timeout_s": 10, "qualified": true, "auth_header": "Bearer …",
        "trusted_ca_path": "/srv/ekyc/tsa-ca.pem"}}'

  Plus the legacy ``EKYC_TSA_URL`` which registers the provider ``external``.

``session.tsa_policy`` selects the provider: ``"internal"``, ``"qualified"``
(first provider configured as qualified, falling back honestly to internal)
or a configured provider name — jurisdictions can pin a specific TSA.

``verify_token`` validates what a token contains: RFC 3161 replies are
structurally parsed (status, messageImprint digest match, genTime); chain
validation is reported but requires the TSA's trusted CA bundle.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from app.core.config import settings
from app.db.base import utcnow


class UnknownTsaProviderError(ValueError):
    pass


@dataclass(frozen=True)
class TsaProvider:
    name: str
    mode: str  # "internal" | "external"
    endpoint: str | None = None
    timeout_s: float = 15.0
    qualified: bool = False
    auth_header: str | None = None
    trusted_ca_path: str | None = None


@dataclass
class TimestampToken:
    token: bytes
    authority: str
    issued_at: str
    qualified: bool
    provider: str = "internal"
    details: dict[str, Any] = field(default_factory=dict)


_INTERNAL = TsaProvider(name="internal", mode="internal")


def providers() -> dict[str, TsaProvider]:
    """Effective TSA registry: internal + env-configured externals."""
    registry: dict[str, TsaProvider] = {"internal": _INTERNAL}
    if settings.tsa_url:
        registry["external"] = TsaProvider(
            name="external",
            mode="external",
            endpoint=settings.tsa_url,
            qualified=True,
        )
    if settings.tsas_json:
        for name, cfg in json.loads(settings.tsas_json).items():
            registry[name] = TsaProvider(
                name=name,
                mode="external",
                endpoint=cfg["endpoint"],
                timeout_s=float(cfg.get("timeout_s", 15.0)),
                qualified=bool(cfg.get("qualified", False)),
                auth_header=cfg.get("auth_header"),
                trusted_ca_path=cfg.get("trusted_ca_path"),
            )
    return registry


def resolve_policy(policy: str) -> TsaProvider:
    """Map a session's tsa_policy to a provider.

    ``qualified`` selects the first qualified external provider; when none is
    configured it degrades honestly to the internal provider (the token keeps
    ``qualified=False`` — the *requirement* is recorded, never fabricated).
    """
    registry = providers()
    if policy == "internal":
        return _INTERNAL
    if policy == "qualified":
        for provider in registry.values():
            if provider.mode == "external" and provider.qualified:
                return provider
        return _INTERNAL
    named = registry.get(policy)
    if named is None:
        raise UnknownTsaProviderError(
            f"Unknown TSA provider: {policy} (configured: {', '.join(sorted(registry))})"
        )
    return named


def _external_timestamp(digest_hex: str, provider: TsaProvider) -> TimestampToken:
    from app.engines.asn1 import build_timestamp_request

    headers = {"Content-Type": "application/timestamp-query"}
    if provider.auth_header:
        headers["Authorization"] = provider.auth_header
    response = httpx.post(
        provider.endpoint or "",
        content=build_timestamp_request(bytes.fromhex(digest_hex)),
        headers=headers,
        timeout=provider.timeout_s,
    )
    response.raise_for_status()
    verification = _verify_rfc3161(response.content, digest_hex)
    return TimestampToken(
        token=response.content,
        authority=provider.endpoint or provider.name,
        issued_at=utcnow().isoformat(),
        qualified=provider.qualified,
        provider=provider.name,
        details={
            "content_type": response.headers.get("content-type", ""),
            "verification": verification,
        },
    )


def _internal_timestamp(digest_hex: str) -> TimestampToken:
    from app.engines.signature import sign_digest

    issued_at = utcnow().isoformat()
    signature = sign_digest(f"{digest_hex}|{issued_at}".encode())
    return TimestampToken(
        token=base64.b64encode(signature.value),
        authority="local-soft-timestamp",
        issued_at=issued_at,
        qualified=False,
        provider="internal",
        details={"algorithm": signature.algorithm, "warning": "NOT_A_QUALIFIED_TSA_TOKEN"},
    )


def timestamp(digest_hex: str, policy: str = "internal") -> TimestampToken:
    provider = resolve_policy(policy)
    if provider.mode == "external" and provider.endpoint:
        try:
            return _external_timestamp(digest_hex, provider)
        except Exception:
            # A failing external TSA must not drop the evidence: fall back to
            # the honest internal token instead of fabricating a qualified one.
            return _internal_timestamp(digest_hex)
    return _internal_timestamp(digest_hex)


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def verify_token(
    token_bytes: bytes,
    digest_hex: str,
    *,
    issued_at: str | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    """Verify a stored timestamp token against the digest it covers.

    Internal tokens are cryptographically verified with the platform key —
    this requires ``issued_at`` (stored in the TIMESTAMPED audit event and the
    sealed PDF metadata) since the signed payload is ``"<digest>|<issued_at>"``.
    RFC 3161 replies are structurally verified (status + imprint digest);
    signature/chain validation needs the TSA's trusted CA — reported as
    ``signature_verified: None`` when no trust anchor is configured.
    """
    try:
        decoded = base64.b64decode(token_bytes, validate=True)
        # internal tokens are base64(RSA signature) — never DER
        if not decoded.startswith(b"\x30"):
            return _verify_internal(decoded, digest_hex, issued_at)
    except ValueError:
        pass
    return _verify_rfc3161(token_bytes, digest_hex, provider=provider)


def _verify_internal(signature: bytes, digest_hex: str, issued_at: str | None) -> dict[str, Any]:
    from app.engines.signature import get_signer

    verified = None
    if issued_at is not None:
        verified = get_signer().verify(f"{digest_hex}|{issued_at}".encode(), signature)
    return {
        "type": "internal-soft-timestamp",
        "signature_verified": verified,
        "imprint_matches": True if verified else None,
        "structural_ok": True,
        "qualified": False,
    }


def _verify_rfc3161(blob: bytes, digest_hex: str, provider: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "rfc3161",
        "structural_ok": False,
        "granted": None,
        "imprint_matches": None,
        "gen_time": None,
        "signature_verified": None,
    }
    try:
        tag, resp, _ = _read_tlv(blob, 0)
        if tag != 0x30:
            return result
        elems = list(_children(resp))
        status_seq = elems[0][1]
        status_int = int.from_bytes(list(_children(status_seq))[0][1], "big")
        result["granted"] = status_int in (0, 1)
        if not result["granted"] or len(elems) < 2:
            result["structural_ok"] = True
            return result

        ci_children = list(_children(elems[1][1]))
        expl = next((c for t, c in ci_children if t == 0xA0), None)
        if expl is None:
            return result
        tag, signed_data, _ = _read_tlv(expl, 0)
        if tag != 0x30:
            return result
        sd_children = list(_children(signed_data))
        eci = sd_children[2][1]  # encapContentInfo
        eci_children = list(_children(eci))
        exp2 = next((c for t, c in eci_children if t == 0xA0), None)
        if exp2 is None:
            return result
        tag, tst_der, _ = _read_tlv(exp2, 0)
        if tag != 0x04:
            return result
        # The eContent OCTET STRING wraps the DER-encoded TSTInfo SEQUENCE.
        tag, tst_seq, _ = _read_tlv(tst_der, 0)
        if tag != 0x30:
            return result
        tst_children = list(_children(tst_seq))
        imprint_seq = tst_children[2][1]  # messageImprint
        imprint = list(_children(imprint_seq))[-1][1]
        result["imprint_matches"] = imprint == bytes.fromhex(digest_hex)
        result["imprint"] = imprint.hex()
        result["gen_time"] = tst_children[4][1].decode(errors="replace")
        result["structural_ok"] = True
        if provider:
            cfg = providers().get(provider)
            if cfg and cfg.trusted_ca_path:
                result["trusted_ca_present"] = Path(cfg.trusted_ca_path).exists()
    except Exception:
        result["structural_ok"] = False
    return result


# --------------------------------------------------------------------------- #
# Minimal DER reader — just enough to walk TimeStampResp → TSTInfo.
# --------------------------------------------------------------------------- #
def _read_tlv(buf: bytes, off: int) -> tuple[int, bytes, int]:
    tag = buf[off]
    off += 1
    length = buf[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[off : off + n], "big")
        off += n
    return tag, buf[off : off + length], off + length


def _children(buf: bytes):
    off = 0
    while off < len(buf):
        tag, content, off = _read_tlv(buf, off)
        yield tag, content


@lru_cache
def list_providers() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "mode": p.mode,
            "qualified": p.qualified,
            "endpoint": p.endpoint,
        }
        for name, p in providers().items()
    }
