"""ICAO 9303 machine readable zone parsing and check-digit validation.

Supports TD3 (passports, 2×44), TD1 (ID cards, 3×30 — e.g. ``IDCIV``) and
TD2 (2×36) formats.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Any

_WEIGHTS = (7, 3, 1)
_FILLER = "<"
_MRZ_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<")


@dataclass
class MrzResult:
    format: str  # "TD1" | "TD2" | "TD3"
    lines: tuple[str, ...]


def _char_value(char: str) -> int:
    if char == _FILLER:
        return 0
    if char.isdigit():
        return int(char)
    return ord(char.upper()) - 55


def check_digit(value: str) -> str:
    total = sum(_char_value(char) * _WEIGHTS[index % 3] for index, char in enumerate(value))
    return str(total % 10)


# Confusions OCR les plus fréquentes dans la zone MRZ (police OCR-B sur carte
# plastifiée : reflets, compression). Ordre pertinent pour la correction.
_OCR_CONFUSABLES: dict[str, str] = {
    "0": "ODQ", "O": "0DQ", "D": "0O", "Q": "0O",
    "1": "IL", "I": "1L", "L": "1I",
    "5": "S", "S": "5",
    "8": "B", "B": "8",
    "2": "Z", "Z": "2",
    "6": "G", "G": "6",
}


def tolerant_check(field: str, digit: str) -> str:
    """Validate a check digit with OCR-error correction.

    ICAO 9303 check digits protect against transcription noise — but the
    noise here comes from the OCR itself: a single misread character inside
    the protected field (or the digit) fails the checksum of a perfectly
    genuine document. Industry practice is single-error correction before
    declaring failure.

    Returns ``"pass"`` (clean), ``"corrected"`` (valid after fixing one
    OCR-confusable character) or ``"fail"``. A corrected pass is still real
    evidence — a forger gains nothing: their data must be one OCR-confusable
    character away from check-valid either way.
    """
    if check_digit(field) == digit:
        return "pass"
    # One confusable character inside the protected field. Correcting the
    # digit itself would be vacuous — exactly one digit is valid for any
    # field, so every mismatch would pass as « corrected » and the check
    # would certify nothing. Field correction is meaningful in coding-theory
    # terms: most single-error neighbourhoods are invalid, so a successful
    # correction is real evidence of a near-clean read.
    for index, char in enumerate(field):
        for replacement in _OCR_CONFUSABLES.get(char, ""):
            if check_digit(field[:index] + replacement + field[index + 1 :]) == digit:
                return "corrected"
    return "fail"


def _parse_date(value: str, pivot: int = 30) -> str | None:
    if not re.fullmatch(r"\d{6}", value):
        return None
    year, month, day = int(value[0:2]), int(value[2:4]), int(value[4:6])
    century = 2000 if year <= pivot else 1900
    try:
        return date(century + year, month, day).isoformat()
    except ValueError:
        return None


def _parse_names(zone: str) -> tuple[str, str]:
    parts = zone.split("<<", 1)
    surname = parts[0].replace(_FILLER, " ").strip()
    given = parts[1].replace(_FILLER, " ").strip() if len(parts) > 1 else ""
    return surname, given


def _check_details(field_digits: dict[str, tuple[str, str]]) -> dict[str, Any]:
    """Evaluate every check with OCR tolerance and derive aggregate scores.

    ``field_digits`` maps check name -> (protected field, check digit).
    """
    detail = {name: tolerant_check(field, digit) for name, (field, digit) in field_digits.items()}
    strict = {name: verdict == "pass" for name, verdict in detail.items()}
    # pass = 1.0, corrected = 0.7 (real evidence, slightly discounted), fail = 0
    score = sum({"pass": 1.0, "corrected": 0.7, "fail": 0.0}[v] for v in detail.values()) / max(
        len(detail), 1
    )
    return {
        "checks": strict,
        "checks_passed": all(strict.values()),
        "checks_detail": detail,
        "checks_lenient": all(v != "fail" for v in detail.values()),
        "checks_score": round(score, 4),
    }


def _fields(
    *,
    mrz_format: str,
    issuing_country: str,
    last_name: str,
    first_name: str,
    document_number: str,
    nationality: str,
    date_of_birth: str | None,
    sex: str,
    expiry_date: str | None,
    checks: dict[str, bool],
    check_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "mrz_format": mrz_format,
        "issuing_country": issuing_country,
        "last_name": last_name,
        "first_name": first_name,
        "document_number": document_number,
        "nationality": nationality,
        "date_of_birth": date_of_birth,
        "sex": sex,
        "expiry_date": expiry_date,
        "checks": checks,
        "checks_passed": all(checks.values()),
        **(check_meta or {}),
    }


def parse_td3(line1: str, line2: str) -> dict[str, Any]:
    """Parse a 2x44 characters TD3 MRZ (passport)."""
    line1 = line1.ljust(44, _FILLER)[:44]
    line2 = line2.ljust(44, _FILLER)[:44]

    surname, given = _parse_names(line1[5:44])
    birth_date_raw = line2[13:19]
    expiry_raw = line2[21:27]

    meta = _check_details({
        "document_number": (line2[0:9], line2[9]),
        "birth_date": (birth_date_raw, line2[19]),
        "expiry_date": (expiry_raw, line2[27]),
        "composite": (line2[0:10] + line2[13:20] + line2[21:43], line2[43]),
    })
    checks = meta.pop("checks")
    meta.pop("checks_passed")

    return _fields(
        mrz_format="TD3",
        issuing_country=line1[2:5].replace(_FILLER, ""),
        last_name=surname,
        first_name=given,
        document_number=line2[0:9].replace(_FILLER, "").strip(),
        nationality=line2[10:13].replace(_FILLER, ""),
        date_of_birth=_parse_date(birth_date_raw),
        sex=line2[20].replace(_FILLER, ""),
        expiry_date=_parse_date(expiry_raw, pivot=99),
        checks=checks,
        check_meta=meta,
    )


def parse_td1(line1: str, line2: str, line3: str) -> dict[str, Any]:
    """Parse a 3x30 characters TD1 MRZ (national ID card, e.g. ``IDCIV``)."""
    line1 = line1.ljust(30, _FILLER)[:30]
    line2 = line2.ljust(30, _FILLER)[:30]
    line3 = line3.ljust(30, _FILLER)[:30]

    surname, given = _parse_names(line3)
    birth_date_raw = line2[0:6]
    expiry_raw = line2[8:14]

    meta = _check_details({
        "document_number": (line1[5:14], line1[14]),
        "birth_date": (birth_date_raw, line2[6]),
        "expiry_date": (expiry_raw, line2[14]),
        "composite": (line1[5:30] + line2[0:7] + line2[8:15] + line2[18:29], line2[29]),
    })
    checks = meta.pop("checks")
    meta.pop("checks_passed")

    return _fields(
        mrz_format="TD1",
        issuing_country=line1[2:5].replace(_FILLER, ""),
        last_name=surname,
        first_name=given,
        document_number=line1[5:14].replace(_FILLER, "").strip(),
        nationality=line2[15:18].replace(_FILLER, ""),
        date_of_birth=_parse_date(birth_date_raw),
        sex=line2[7].replace(_FILLER, ""),
        expiry_date=_parse_date(expiry_raw, pivot=99),
        checks=checks,
        check_meta=meta,
    )


def parse_td2(line1: str, line2: str) -> dict[str, Any]:
    """Parse a 2x36 characters TD2 MRZ (visas, some ID cards)."""
    line1 = line1.ljust(36, _FILLER)[:36]
    line2 = line2.ljust(36, _FILLER)[:36]

    surname, given = _parse_names(line1[5:36])
    birth_date_raw = line2[13:19]
    expiry_raw = line2[21:27]

    meta = _check_details({
        "document_number": (line2[0:9], line2[9]),
        "birth_date": (birth_date_raw, line2[19]),
        "expiry_date": (expiry_raw, line2[27]),
        "composite": (line2[0:10] + line2[13:20] + line2[21:35], line2[35]),
    })
    checks = meta.pop("checks")
    meta.pop("checks_passed")

    return _fields(
        mrz_format="TD2",
        issuing_country=line1[2:5].replace(_FILLER, ""),
        last_name=surname,
        first_name=given,
        document_number=line2[0:9].replace(_FILLER, "").strip(),
        nationality=line2[10:13].replace(_FILLER, ""),
        date_of_birth=_parse_date(birth_date_raw),
        sex=line2[20].replace(_FILLER, ""),
        expiry_date=_parse_date(expiry_raw, pivot=99),
        checks=checks,
        check_meta=meta,
    )


def parse_mrz(mrz: MrzResult) -> dict[str, Any]:
    if mrz.format == "TD1":
        return parse_td1(*mrz.lines)
    if mrz.format == "TD2":
        return parse_td2(*mrz.lines)
    return parse_td3(*mrz.lines)


MRZ_LINE_RE = re.compile(r"^[A-Z0-9<]{28,44}$")


def _normalize(line: str) -> str:
    """Keep only MRZ-legal characters and trim to the standard 44-char width."""
    return "".join(char for char in line.upper() if char in _MRZ_ALPHABET)[:44]


def find_mrz(text: str) -> MrzResult | None:
    """Locate an MRZ in OCR text and identify its ICAO format."""
    lines = [_normalize(line) for line in text.splitlines()]
    candidates = [line for line in lines if MRZ_LINE_RE.match(line)]
    for index, first in enumerate(candidates):
        rest = candidates[index + 1 :]
        if len(first) >= 40 or first.startswith("P<"):
            if rest:
                return MrzResult("TD3", (first, rest[0]))
        elif 33 <= len(first) <= 38 and first[0] in "IAV":
            if rest:
                return MrzResult("TD2", (first, rest[0]))
        elif first.startswith("I") and len(first) <= 32:
            if len(rest) >= 2:
                return MrzResult("TD1", (first, rest[0], rest[1]))
    return None
