"""PDF generation: KYC certificate and default contract rendering."""

from __future__ import annotations

import io
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


def _header(pdf: canvas.Canvas, title: str, subtitle: str) -> float:
    width, height = A4
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(20 * mm, height - 25 * mm, title)
    pdf.setFont("Helvetica", 9)
    pdf.drawString(20 * mm, height - 32 * mm, subtitle)
    pdf.line(20 * mm, height - 35 * mm, width - 20 * mm, height - 35 * mm)
    return height - 45 * mm


def _rows(pdf: canvas.Canvas, y: float, rows: list[tuple[str, Any]]) -> float:
    for label, value in rows:
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(20 * mm, y, f"{label}")
        pdf.setFont("Helvetica", 10)
        pdf.drawString(80 * mm, y, str(value if value is not None else "-"))
        y -= 7 * mm
    return y


def render_kyc_certificate(
    *,
    session_id: str,
    tenant_name: str,
    flow: str,
    status: str,
    identity: dict[str, Any],
    checks: dict[str, str],
    audit_head_hash: str | None,
    issued_at: str,
) -> bytes:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    y = _header(
        pdf, "CERTIFICAT DE VERIFICATION D'IDENTITE", "IT-TECH eKYC - Digital Trust Platform"
    )

    y = _rows(
        pdf,
        y,
        [
            ("KYC ID", session_id),
            ("Client", tenant_name),
            ("Parcours", flow),
            ("Statut global", status),
            ("Emis le", issued_at),
        ],
    )
    y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(20 * mm, y, "Identite")
    y -= 8 * mm
    y = _rows(pdf, y, [(key.replace("_", " ").title(), value) for key, value in identity.items()])

    y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(20 * mm, y, "Controles")
    y -= 8 * mm
    y = _rows(pdf, y, list(checks.items()))

    y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(20 * mm, y, "Piste d'audit")
    y -= 8 * mm
    _rows(pdf, y, [("Empreinte de chaine", audit_head_hash or "-")])

    pdf.showPage()
    pdf.save()
    return buffer.getvalue()


def render_contract(
    *, title: str, session_id: str, tenant_name: str, body: list[tuple[str, Any]], issued_at: str
) -> bytes:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    y = _header(pdf, title, f"{tenant_name} - genere via IT-TECH eKYC le {issued_at}")
    y = _rows(pdf, y, body)
    y -= 6 * mm
    pdf.setFont("Helvetica-Oblique", 9)
    pdf.drawString(20 * mm, y, f"KYC ID: {session_id}")
    pdf.showPage()
    pdf.save()
    return buffer.getvalue()
