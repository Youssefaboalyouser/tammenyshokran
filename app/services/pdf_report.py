"""
pdf_report.py
-------------
Generates a detailed PDF report for an EmailAnalysis record.
Uses ReportLab for PDF generation.
"""

import io
from datetime import datetime
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER


# ── Colors ───────────────────────────────────────────────────────────────────
DARK_BG = colors.HexColor("#060b10")
CYAN = colors.HexColor("#00d4ff")
RED = colors.HexColor("#ff4060")
GREEN = colors.HexColor("#00ff8c")
YELLOW = colors.HexColor("#ffd050")
GRAY = colors.HexColor("#4d7a90")
LIGHT_TEXT = colors.HexColor("#b8d4e4")
WHITE = colors.white


def _verdict_color(verdict: Optional[str]):
    if not verdict:
        return GRAY
    v = verdict.upper()
    if "HIGH" in v:
        return RED
    if "SUSPICIOUS" in v:
        return YELLOW
    return GREEN


def _score_color(score: Optional[float]):
    if score is None:
        return GRAY
    if score >= 60:
        return RED
    if score >= 30:
        return YELLOW
    return GREEN


def generate_pdf(analysis: dict) -> bytes:
    """
    Generate a PDF report bytes for an email analysis.

    `analysis` is expected to match EmailAnalysis model fields as a dict.
    """
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=22,
        textColor=CYAN,
        spaceAfter=6,
        fontName="Helvetica-Bold",
        alignment=TA_LEFT,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=GRAY,
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=CYAN,
        spaceBefore=16,
        spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#c8d8e8"),
        leading=16,
    )
    flag_style = ParagraphStyle(
        "Flag",
        parent=styles["Normal"],
        fontSize=9,
        textColor=LIGHT_TEXT,
        leftIndent=10,
        leading=14,
    )

    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("TAMENNY", title_style))
    story.append(Paragraph("Scam &amp; Phishing Detection Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN, spaceAfter=12))

    # ── Verdict banner ────────────────────────────────────────────────────────
    verdict = analysis.get("verdict", "UNKNOWN")
    score = analysis.get("risk_score", 0.0)
    v_color = _verdict_color(verdict)
    s_color = _score_color(score)

    verdict_data = [
        [
            Paragraph(f"<b>VERDICT: {verdict}</b>", ParagraphStyle(
                "V", fontSize=14, textColor=v_color, fontName="Helvetica-Bold"
            )),
            Paragraph(f"<b>RISK SCORE: {score}/100</b>", ParagraphStyle(
                "S", fontSize=14, textColor=s_color, fontName="Helvetica-Bold",
                alignment=TA_CENTER,
            )),
            Paragraph(
                f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                ParagraphStyle("D", fontSize=9, textColor=GRAY),
            ),
        ]
    ]
    verdict_table = Table(verdict_data, colWidths=["40%", "35%", "25%"])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0c1520")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#0c1520")]),
        ("BOX", (0, 0), (-1, -1), 1, CYAN),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, GRAY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 16))

    # ── Email metadata ────────────────────────────────────────────────────────
    story.append(Paragraph("Email Metadata", section_style))

    meta = [
        ["Field", "Value"],
        ["File", analysis.get("filename", "—")],
        ["Subject", analysis.get("subject", "—") or "—"],
        ["Sender", analysis.get("sender_email", "—") or "—"],
        ["Sender Domain", analysis.get("sender_domain", "—") or "—"],
        ["Recipient", analysis.get("recipient", "—") or "—"],
        ["Email Timestamp", analysis.get("email_timestamp", "—") or "—"],
        ["Analysis ID", str(analysis.get("id", "—"))],
    ]
    meta_table = Table(meta, colWidths=["35%", "65%"])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b3348")),
        ("TEXTCOLOR", (0, 0), (-1, 0), CYAN),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.HexColor("#0c1520"), colors.HexColor("#101d2a")
        ]),
        ("TEXTCOLOR", (0, 1), (-1, -1), LIGHT_TEXT),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOX", (0, 0), (-1, -1), 0.5, GRAY),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#1b3348")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)

    # ── Phishing flags ────────────────────────────────────────────────────────
    story.append(Paragraph("Phishing Detection Flags", section_style))
    flags: list = analysis.get("phishing_flags") or []
    if flags:
        for i, flag in enumerate(flags, 1):
            story.append(Paragraph(f"⚠  {i}. {flag}", flag_style))
    else:
        story.append(Paragraph("✓  No phishing flags detected.", flag_style))

    story.append(Spacer(1, 8))

    # ── NLP result ────────────────────────────────────────────────────────────
    story.append(Paragraph("NLP Spam Classification", section_style))
    nlp: dict = analysis.get("nlp_result") or {}
    nlp_data = [
        ["Property", "Value"],
        ["Classification", nlp.get("label", "—")],
        ["Confidence Score", f"{round(nlp.get('score', 0) * 100, 1)}%"],
        ["Is Spam", "YES" if nlp.get("is_spam") else "NO"],
    ]
    nlp_table = Table(nlp_data, colWidths=["40%", "60%"])
    nlp_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b3348")),
        ("TEXTCOLOR", (0, 0), (-1, 0), CYAN),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.HexColor("#0c1520"), colors.HexColor("#101d2a")
        ]),
        ("TEXTCOLOR", (0, 1), (-1, -1), LIGHT_TEXT),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOX", (0, 0), (-1, -1), 0.5, GRAY),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#1b3348")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(nlp_table)

    # ── VirusTotal summary ────────────────────────────────────────────────────
    vt_data_raw: dict = analysis.get("virustotal_data") or {}
    vt = vt_data_raw.get("virustotal", {})
    vt_links = vt.get("links", [])
    vt_atts = vt.get("attachments", [])

    if vt_links or vt_atts:
        story.append(Paragraph("VirusTotal Results", section_style))

        if vt_links:
            story.append(Paragraph("<b>Links</b>", body_style))
            link_rows = [["URL", "Malicious Votes", "Verdict"]]
            for entry in vt_links:
                url = entry.get("url", "—")
                if len(url) > 60:
                    url = url[:57] + "..."
                link_rows.append([
                    url,
                    str(entry.get("malicious_votes", 0)),
                    entry.get("verdict", "—").upper(),
                ])
            lt = Table(link_rows, colWidths=["60%", "20%", "20%"])
            lt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b3348")),
                ("TEXTCOLOR", (0, 0), (-1, 0), CYAN),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.HexColor("#0c1520"), colors.HexColor("#101d2a")
                ]),
                ("TEXTCOLOR", (0, 1), (-1, -1), LIGHT_TEXT),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.5, GRAY),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#1b3348")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("WORDWRAP", (0, 0), (-1, -1), True),
            ]))
            story.append(lt)
            story.append(Spacer(1, 8))

        if vt_atts:
            story.append(Paragraph("<b>Attachments</b>", body_style))
            att_rows = [["Filename", "SHA256 (partial)", "Verdict"]]
            for entry in vt_atts:
                sha = entry.get("hash_sha256", "—")
                att_rows.append([
                    entry.get("filename", "—"),
                    sha[:16] + "..." if len(sha) > 16 else sha,
                    entry.get("verdict", "—").upper(),
                ])
            at = Table(att_rows, colWidths=["40%", "35%", "25%"])
            at.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b3348")),
                ("TEXTCOLOR", (0, 0), (-1, 0), CYAN),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.HexColor("#0c1520"), colors.HexColor("#101d2a")
                ]),
                ("TEXTCOLOR", (0, 1), (-1, -1), LIGHT_TEXT),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.5, GRAY),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#1b3348")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(at)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY, spaceAfter=8))
    story.append(Paragraph(
        "Generated by Tamenny — Scam &amp; Phishing Detection Platform",
        ParagraphStyle("Footer", fontSize=8, textColor=GRAY, alignment=TA_CENTER),
    ))

    doc.build(story)
    return buffer.getvalue()
