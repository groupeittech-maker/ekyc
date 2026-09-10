"""ICAO 9303 machine readable zone parsing and check-digit validation."""

from __future__ import annotations

import re
from datetime import date
from typing import Any

_WEIGHTS = (7, 3, 1)
_FILLER = "<"
_MRZ_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<")


def _char_value(char: str) -> int:
    if char == _FILLER:
        return 0
    if char.isdigit():
        return int(char)
    return ord(char.upper()) - 55


def check_digit(value: str) -> str:
    total = sum(_char_value(char) * _WEIGHTS[index % 3] for index, char in enumerate(value))
    return str(total % 10)


def _parse_date(value: str, pivot: int = 30) -> str | None:
    if not re.fullmatch(r"\d{6}", value):
        return None
    year, month, day = int(value[0:2]), int(value[2:4]), int(value[4:6])
    century = 2000 if year <= pivot else 1900
    try:
        return date(century + year, month, day).isoformat()
    except ValueError:
        return None


def parse_td3(line1: str, line2: str) -> dict[str, Any]:
    """Parse a 2x44 characters TD3 MRZ (passport)."""
    line1 = line1.ljust(44, _FILLER)[:44]
    line2 = line2.ljust(44, _FILLER)[:44]

    names = line1[5:44].split("<<", 1)
    surname = names[0].replace(_FILLER, " ").strip()
    given = names[1].replace(_FILLER, " ").strip() if len(names) > 1 else ""

    document_number = line2[0:9].replace(_FILLER, "").strip()
    birth_date_raw = line2[13:19]
    expiry_raw = line2[21:27]

    checks = {
        "document_number": check_digit(line2[0:9]) == line2[9],
        "birth_date": check_digit(birth_date_raw) == line2[19],
        "expiry_date": check_digit(expiry_raw) == line2[27],
        "composite": check_digit(line2[0:10] + line2[13:20] + line2[21:43]) == line2[43],
    }

    return {
        "document_type": "PASSPORT",
        "issuing_country": line1[2:5].replace(_FILLER, ""),
        "last_name": surname,
        "first_name": given,
        "document_number": document_number,
        "nationality": line2[10:13].replace(_FILLER, ""),
        "date_of_birth": _parse_date(birth_date_raw),
        "sex": line2[20].replace(_FILLER, ""),
        "expiry_date": _parse_date(expiry_raw, pivot=99),
        "checks": checks,
        "checks_passed": all(checks.values()),
    }


MRZ_LINE_RE = re.compile(r"^[A-Z0-9<]{30,44}$")


def _normalize(line: str) -> str:
    """Keep only MRZ-legal characters and trim to the standard 44-char width."""
    return "".join(char for char in line.upper() if char in _MRZ_ALPHABET)[:44]


def find_mrz(text: str) -> tuple[str, str] | None:
    lines = [_normalize(line) for line in text.splitlines() if _normalize(line)]
    candidates = [line for line in lines if MRZ_LINE_RE.match(line)]
    for first, second in zip(candidates, candidates[1:], strict=False):
        if len(first) >= 44 or first.startswith(("P<", "I<")):
            return first, second
    return None
