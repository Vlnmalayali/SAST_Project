"""PDF report generation using ReportLab."""

import io
import logging
from collections import Counter
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.compliance_mapping import get_compliance_mapping
from app.reporting.charts import (
    generate_risk_gauge,
    generate_severity_pie_chart,
    generate_type_bar_chart,
)

logger = logging.getLogger(__name__)

WIDTH, HEIGHT = A4

SEVERITY_COLORS_MAP = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#CA8A04"),
    "low": colors.HexColor("#16A34A"),
    "info": colors.HexColor("#6B7280"),
}


def generate_pdf_report(file_path: str, scan, vulnerabilities: list) -> str:
    """Generate a professional PDF security report."""
    doc = SimpleDocTemplate(
        file_path,
        pagesize=A4,
        leftMargin=50,
        rightMargin=50,
        topMargin=60,
        bottomMargin=60,
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="CoverTitle",
            fontSize=28,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.HexColor("#1E3A5F"),
            fontName="Helvetica-Bold",
        )
    )
    styles.add(
        ParagraphStyle(
            name="CoverSubtitle",
            fontSize=14,
            alignment=TA_CENTER,
            spaceAfter=10,
            textColor=colors.HexColor("#4B5563"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor("#1E3A5F"),
            fontName="Helvetica-Bold",
        )
    )
    styles.add(
        ParagraphStyle(
            name="SubSection", fontSize=12, spaceAfter=8, spaceBefore=12, fontName="Helvetica-Bold"
        )
    )
    styles.add(ParagraphStyle(name="BodyText2", fontSize=10, spaceAfter=6, leading=14))
    styles.add(
        ParagraphStyle(
            name="CodeBlock",
            fontSize=8,
            fontName="Courier",
            backColor=colors.HexColor("#F3F4F6"),
            leftIndent=10,
            spaceAfter=8,
            leading=11,
        )
    )

    elements = []

    # — Cover Page —
    elements.append(Spacer(1, 2 * inch))
    elements.append(Paragraph("🔒 Security Analysis Report", styles["CoverTitle"]))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(f"Scan ID: {scan.id[:8]}...", styles["CoverSubtitle"]))
    elements.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", styles["CoverSubtitle"]
        )
    )
    elements.append(
        Paragraph(f"Risk Score: {scan.overall_risk_score}/10.0", styles["CoverSubtitle"])
    )
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(
        Paragraph("AI-Powered Static Application Security Testing", styles["CoverSubtitle"])
    )
    elements.append(PageBreak())

    # — Executive Summary —
    elements.append(Paragraph("Executive Summary", styles["SectionTitle"]))

    severity_counts = Counter(v.severity for v in vulnerabilities)
    total_vulns = len(vulnerabilities)

    summary_text = (
        f"This report presents the findings of an automated security scan. "
        f"A total of <b>{scan.total_files_scanned}</b> files and "
        f"<b>{scan.total_lines_scanned:,}</b> lines of code were analyzed. "
        f"The scan identified <b>{total_vulns}</b> potential security vulnerabilities "
        f"with an overall risk score of <b>{scan.overall_risk_score}/10.0</b>."
    )
    elements.append(Paragraph(summary_text, styles["BodyText2"]))
    elements.append(Spacer(1, 0.2 * inch))

    # Summary table
    summary_data = [
        ["Metric", "Value"],
        ["Total Vulnerabilities", str(total_vulns)],
        ["Critical", str(severity_counts.get("critical", 0))],
        ["High", str(severity_counts.get("high", 0))],
        ["Medium", str(severity_counts.get("medium", 0))],
        ["Low", str(severity_counts.get("low", 0))],
        ["Files Scanned", str(scan.total_files_scanned)],
        ["Lines Scanned", f"{scan.total_lines_scanned:,}"],
        ["Scan Duration", f"{scan.scan_duration_seconds or 0}s"],
    ]

    summary_table = Table(summary_data, colWidths=[200, 200])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 0.3 * inch))

    # — Charts —
    elements.append(Paragraph("Risk Overview", styles["SectionTitle"]))

    try:
        gauge_bytes = generate_risk_gauge(scan.overall_risk_score)
        elements.append(Image(io.BytesIO(gauge_bytes), width=4 * inch, height=3 * inch))
        elements.append(Spacer(1, 0.2 * inch))
    except Exception as e:
        logger.warning(f"Failed to generate risk gauge: {e}")

    try:
        pie_bytes = generate_severity_pie_chart(dict(severity_counts))
        elements.append(Image(io.BytesIO(pie_bytes), width=5 * inch, height=3.5 * inch))
    except Exception as e:
        logger.warning(f"Failed to generate pie chart: {e}")

    type_counts = Counter(v.vulnerability_type for v in vulnerabilities)
    try:
        bar_bytes = generate_type_bar_chart(dict(type_counts))
        elements.append(Image(io.BytesIO(bar_bytes), width=6 * inch, height=3.5 * inch))
    except Exception as e:
        logger.warning(f"Failed to generate bar chart: {e}")

    elements.append(PageBreak())

    # — Vulnerability Details —
    elements.append(Paragraph("Vulnerability Details", styles["SectionTitle"]))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.severity, 5))

    for idx, vuln in enumerate(sorted_vulns, 1):
        sev_color = SEVERITY_COLORS_MAP.get(vuln.severity, colors.gray)

        elements.append(
            Paragraph(
                f"<b>#{idx}. {vuln.vulnerability_type.replace('_', ' ').title()}</b> "
                f"in <font color='#3B82F6'>{vuln.file_path}:{vuln.line_number}</font>",
                styles["SubSection"],
            )
        )

        detail_data = [
            ["Severity", vuln.severity.upper()],
            ["CVSS Score", f"{vuln.cvss_score}/10.0"],
            ["Confidence", f"{vuln.confidence * 100:.0f}%"],
        ]
        if vuln.cwe_id:
            detail_data.append(["CWE", vuln.cwe_id])

        compliance = get_compliance_mapping(
            vulnerability_type=vuln.vulnerability_type,
            cwe_id=vuln.cwe_id,
        )
        if compliance.get("owasp_top10"):
            detail_data.append(["OWASP Top 10", compliance["owasp_top10"]])
        if compliance.get("pci_dss"):
            detail_data.append(["PCI-DSS", "; ".join(compliance["pci_dss"])])
        if compliance.get("gdpr"):
            detail_data.append(["GDPR", "; ".join(compliance["gdpr"])])

        detail_table = Table(detail_data, colWidths=[100, 300])
        detail_table.setStyle(
            TableStyle(
                [
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("TEXTCOLOR", (1, 0), (1, 0), sev_color),
                    ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        elements.append(detail_table)
        elements.append(Spacer(1, 0.1 * inch))

        # Code snippet
        if vuln.code_snippet:
            elements.append(Paragraph("<b>Vulnerable Code:</b>", styles["BodyText2"]))
            safe_code = (
                vuln.code_snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            )
            elements.append(Paragraph(safe_code, styles["CodeBlock"]))

        # AI explanation
        if vuln.ai_explanation:
            elements.append(Paragraph("<b>Analysis:</b>", styles["BodyText2"]))
            elements.append(Paragraph(vuln.ai_explanation, styles["BodyText2"]))

        # Fix
        if vuln.ai_fixed_code:
            elements.append(Paragraph("<b>Suggested Fix:</b>", styles["BodyText2"]))
            safe_fix = (
                vuln.ai_fixed_code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            )
            elements.append(Paragraph(safe_fix, styles["CodeBlock"]))

        if vuln.remediation_steps and isinstance(vuln.remediation_steps, dict):
            steps = vuln.remediation_steps.get("remediation_steps", [])
            if steps:
                elements.append(Paragraph("<b>Remediation Steps:</b>", styles["BodyText2"]))
                for step_idx, step in enumerate(steps, 1):
                    elements.append(Paragraph(f"  {step_idx}. {step}", styles["BodyText2"]))

        elements.append(Spacer(1, 0.3 * inch))

        # Page break every 3 vulnerabilities
        if idx % 3 == 0 and idx < len(sorted_vulns):
            elements.append(PageBreak())

    # — Footer —
    elements.append(PageBreak())
    elements.append(Paragraph("Appendix", styles["SectionTitle"]))
    elements.append(
        Paragraph(
            "This report was generated automatically by the AI-Powered SAST tool. "
            "Static analysis may produce false positives and does not guarantee the absence "
            "of vulnerabilities. Manual code review is recommended for critical findings.",
            styles["BodyText2"],
        )
    )

    # Build PDF
    doc.build(elements)
    return file_path
