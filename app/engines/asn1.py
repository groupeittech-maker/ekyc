"""Minimal DER encoder for RFC 3161 timestamp requests.

Only the small subset needed to build a ``TimeStampReq`` is implemented, which
avoids pulling a full ASN.1 stack into the runtime image.
"""

from __future__ import annotations

import secrets

SHA256_OID = (2, 16, 840, 1, 101, 3, 4, 2, 1)


def _length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def encode_integer(value: int) -> bytes:
    if value == 0:
        return _tlv(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return _tlv(0x02, raw.lstrip(b"\x00") or b"\x00")


def encode_octet_string(value: bytes) -> bytes:
    return _tlv(0x04, value)


def encode_boolean(value: bool) -> bytes:
    return _tlv(0x01, b"\xff" if value else b"\x00")


def encode_null() -> bytes:
    return _tlv(0x05, b"")


def encode_oid(oid: tuple[int, ...]) -> bytes:
    body = bytearray([oid[0] * 40 + oid[1]])
    for component in oid[2:]:
        chunks = [component & 0x7F]
        component >>= 7
        while component:
            chunks.append((component & 0x7F) | 0x80)
            component >>= 7
        body.extend(reversed(chunks))
    return _tlv(0x06, bytes(body))


def encode_sequence(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def build_timestamp_request(digest: bytes, *, cert_req: bool = True) -> bytes:
    """TimeStampReq with a SHA-256 message imprint and a random nonce."""
    algorithm = encode_sequence(encode_oid(SHA256_OID), encode_null())
    message_imprint = encode_sequence(algorithm, encode_octet_string(digest))
    nonce = encode_integer(secrets.randbits(64))
    return encode_sequence(
        encode_integer(1),
        message_imprint,
        nonce,
        encode_boolean(cert_req),
    )
