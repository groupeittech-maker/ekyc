from __future__ import annotations

from app.engines.providers.mrz import check_digit, parse_td1, parse_td3, tolerant_check


def _td3_lines():
    """Build a structurally valid TD3 MRZ pair."""
    line1 = "P<CIVKOUASSI<<JEAN<MARIE<<<<<<<<<<<<<<<<<<<".ljust(44, "<")[:44]
    docnum = "12AB34567"
    dn = check_digit(docnum)
    birth = "800101"
    b = check_digit(birth)
    expiry = "301231"
    e = check_digit(expiry)
    composite_field = (docnum + dn) + (birth + b) + (expiry + e + "<<<<<<<<<<<<<<".ljust(22, "<")[:22])
    comp = check_digit(composite_field)
    line2 = (docnum + dn + "CIV" + birth + b + "M" + expiry + e + "<<<<<<<<<<<<<<").ljust(43, "<") + comp
    return line1, line2[:44]


def test_tolerant_check_clean_pass() -> None:
    field = "800101"
    assert tolerant_check(field, check_digit(field)) == "pass"


def test_tolerant_check_corrects_confusable_character() -> None:
    # Genuine field contains digit 0; OCR reads letter O — a classic OCR-B confusion.
    field = "800101"
    digit = check_digit(field)
    noisy = "8O0101"
    assert tolerant_check(noisy, digit) == "corrected"


def test_tolerant_check_two_errors_fail() -> None:
    # Two independent OCR errors cannot be a single slip — no single
    # substitution restores validity, the check must fail.
    field = "800101"
    digit = check_digit(field)
    noisy = "8OO101"
    assert tolerant_check(noisy, digit) == "fail"


def test_tolerant_check_unconfusable_error_fails() -> None:
    # An error outside the confusable set (e.g. 8 misread as 3) is not corrected.
    field = "800101"
    digit = check_digit(field)
    noisy = "300101"
    assert tolerant_check(noisy, digit) == "fail"


def test_parse_td3_exposes_lenient_checks() -> None:
    line1, line2 = _td3_lines()
    result = parse_td3(line1, line2)
    assert result["checks_passed"] is True
    assert result["checks_lenient"] is True
    assert result["checks_score"] == 1.0
    assert set(result["checks_detail"]) >= {"document_number", "birth_date", "expiry_date", "composite"}


def test_parse_td3_single_ocr_error_stays_lenient() -> None:
    line1, line2 = _td3_lines()
    # OCR reads the leading 1 of the document number as letter I.
    noisy_line2 = "I" + line2[1:]
    result = parse_td3(line1, noisy_line2)
    assert result["checks_passed"] is False  # strict view still fails
    assert result["checks_lenient"] is True  # but correction rescues the evidence
    assert 0.0 < result["checks_score"] < 1.0


def test_parse_td1_lenient_fields_present() -> None:
    # Minimal TD1 structure check — mostly ensuring metadata keys exist.
    line1 = "IDCIV1234567890<<<<<<<<<<<<<<".ljust(30, "<")[:30]
    docnum_field = line1[5:14]
    dn = check_digit(docnum_field)
    line1 = line1[:14] + dn + line1[15:]
    birth = "800101"
    b = check_digit(birth)
    expiry = "301231"
    e = check_digit(expiry)
    comp_field = line1[5:30] + (birth + b)[:7] + (expiry + e)[:7] + "<" * 11
    comp = check_digit(comp_field[:29])
    line2 = (birth + b + "M" + expiry + e + "CIV" + "<" * 11 + comp)[:30]
    line3 = "KOUASSI<<JEAN<MARIE<<<<<<<<<<<<<"[:30]
    result = parse_td1(line1, line2, line3)
    assert "checks_lenient" in result
    assert "checks_score" in result
    assert "checks_detail" in result
