from __future__ import annotations

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from apps.control_plane.crypto import load_instance_public_key
from apps.control_plane.db import session_scope
from apps.control_plane.models import Instance

_bearer = HTTPBearer(auto_error=True)
_seen_jti: set[str] = set()  # lightweight replay guard


def current_instance(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> Instance:
    """Authenticate a national instance via its EdDSA-signed JWT
    (``typ: instance``, ``sub: instance_id``, ``exp`` ≤ 5 min, ``jti``)."""
    token = creds.credentials
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        raise HTTPException(401, "malformed instance token") from None
    if unverified.get("typ") != "instance":
        raise HTTPException(401, "token type must be 'instance'")
    sub = unverified.get("sub", "")
    with session_scope() as s:
        inst = s.get(Instance, sub)
        if inst is None:
            raise HTTPException(401, "unknown instance")
        try:
            key = load_instance_public_key(inst.instance_public_key)
            claims = jwt.decode(token, key, algorithms=["EdDSA"])
        except jwt.PyJWTError:
            raise HTTPException(401, "invalid instance token") from None
        jti = claims.get("jti")
        if not jti or jti in _seen_jti:
            raise HTTPException(401, "missing or replayed jti")
        _seen_jti.add(jti)
        return inst
