"""PDF export for SmartScan scan reports.

Renders a host or web scan report into the HostedScan/ZAP "Vulnerability Scan
Report" structure (cover -> executive summary -> vulnerabilities by target ->
vulnerability details -> glossary), branded for DEWEBNET Solution.

Pure-Python via reportlab (no native deps -- Windows-friendly).
`build_pdf(report, scan_type)` returns the PDF as bytes.
"""
import os
from io import BytesIO
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak,
)

# --- DEWEBNET brand palette ---
NAVY = colors.HexColor("#11178C")
GREEN = colors.HexColor("#8CC63F")
GREEN_DARK = colors.HexColor("#6fa72c")
MUTED = colors.HexColor("#6b7185")
BORDER = colors.HexColor("#e3e7f1")
LIGHT = colors.HexColor("#f6f8fc")

# Severity palette aligned with the web console (HostedScan-style 5 states)
SEV_COLORS = {
    "critical": colors.HexColor("#7c3aed"),  # purple
    "high": colors.HexColor("#e5484d"),      # red
    "medium": colors.HexColor("#f76808"),    # orange
    "low": colors.HexColor("#e0b400"),       # yellow
    "accepted": colors.HexColor("#30a46c"),  # green
    "unknown": colors.HexColor("#8b91a3"),
}
SEV_ORDER = ["critical", "high", "medium", "low"]
CARD_ORDER = ["critical", "high", "medium", "low", "accepted"]
ZERO_GRAY = colors.HexColor("#c2c7d6")

LOGO_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "logo.png")

GLOSSARY = [
    ("Critical", "Most severe. Easily exploitable with severe impact (full compromise, data breach). Evaluate and remediate first."),
    ("High", "Serious weakness that is exploitable and can lead to significant compromise or data exposure."),
    ("Medium", "Moderate risk. Often requires specific conditions or chaining with other issues to be exploited."),
    ("Low", "Minor risk or hardening gap. Limited direct impact but should be addressed as good practice."),
    ("Accepted", "A vulnerability that has been manually reviewed and classified as acceptable — e.g. a false positive or an intentional part of the system's architecture."),
    ("FQDN", "Fully Qualified Domain Name — the complete domain address of a host, such as app.example.com."),
    ("CVE", "Common Vulnerabilities and Exposures — a public identifier for a known software vulnerability."),
    ("CVSS", "Common Vulnerability Scoring System — a 0–10 numeric severity score for a vulnerability."),
]


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("Cover", parent=s["Title"], fontSize=30, textColor=NAVY, leading=36, spaceAfter=6))
    s.add(ParagraphStyle("CoverSub", parent=s["Normal"], fontSize=11, textColor=MUTED, leading=16))
    s.add(ParagraphStyle("H1", parent=s["Heading1"], fontSize=17, textColor=NAVY, spaceBefore=14, spaceAfter=8))
    s.add(ParagraphStyle("H2", parent=s["Heading2"], fontSize=12.5, textColor=colors.HexColor("#1c2230"), spaceBefore=10, spaceAfter=5))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9.5, leading=14, textColor=colors.HexColor("#1c2230")))
    s.add(ParagraphStyle("Small", parent=s["Normal"], fontSize=8.5, leading=12, textColor=MUTED))
    s.add(ParagraphStyle("Cell", parent=s["Normal"], fontSize=8.5, leading=11))
    s.add(ParagraphStyle("CellBold", parent=s["Normal"], fontSize=8.5, leading=11, fontName="Helvetica-Bold"))
    s.add(ParagraphStyle("Label", parent=s["Normal"], fontSize=7.5, textColor=MUTED, fontName="Helvetica-Bold"))
    s.add(ParagraphStyle("Eyebrow", parent=s["Normal"], fontSize=8, textColor=GREEN_DARK, fontName="Helvetica-Bold", leading=12))
    s.add(ParagraphStyle("TOC", parent=s["Title"], fontSize=28, textColor=colors.HexColor("#9aa0b4"), leading=32, alignment=0))
    s.add(ParagraphStyle("TOCItem", parent=s["Normal"], fontSize=12.5, textColor=colors.HexColor("#1c2230"), fontName="Helvetica-Bold", leading=16))
    s.add(ParagraphStyle("TOCNum", parent=s["Normal"], fontSize=12.5, textColor=GREEN_DARK, fontName="Helvetica-Bold", leading=16))
    return s


def _brand_rule(width: float = 46 * mm) -> Table:
    """A thin two-tone rule (navy trace -> green via) echoing the logo's circuitry."""
    t = Table([["", ""]], colWidths=[width * 0.78, width * 0.22], rowHeights=[1.6 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), NAVY),
        ("BACKGROUND", (1, 0), (1, 0), GREEN),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def _h1(story: List[Any], styles, text: str) -> None:
    """Numbered section heading followed by the trace-node brand rule."""
    story.append(Paragraph(text, styles["H1"]))
    story.append(_brand_rule(30 * mm))
    story.append(Spacer(1, 3 * mm))


def _watermark(canvas) -> None:
    """Faint, tiled DEWEBNET wordmark behind page content.

    Reproduces the logo's two-tone split (DEWEB navy / NET green) so the
    watermark reads as the brand rather than generic boilerplate.
    """
    w, h = A4
    canvas.saveState()
    canvas.translate(w / 2.0, h / 2.0)
    canvas.rotate(30)
    canvas.setFont("Helvetica-Bold", 38)
    deweb_w = canvas.stringWidth("DEWEB", "Helvetica-Bold", 38)
    for gy in range(-6, 7):
        for gx in range(-3, 4):
            x = gx * 200 - deweb_w / 2.0
            y = gy * 86
            canvas.setFillColorRGB(NAVY.red, NAVY.green, NAVY.blue, alpha=0.03)
            canvas.drawString(x, y, "DEWEB")
            canvas.setFillColorRGB(GREEN.red, GREEN.green, GREEN.blue, alpha=0.045)
            canvas.drawString(x + deweb_w, y, "NET")
    canvas.restoreState()


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {k: 0 for k in CARD_ORDER}
    for f in findings:
        if str(f.get("status", "open")).lower() == "accepted":
            counts["accepted"] += 1
            continue
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _severity_badge(sev: str) -> Table:
    key = sev.lower() if sev.lower() in SEV_COLORS else "unknown"
    t = Table([[sev.capitalize()]], colWidths=[20 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEV_COLORS[key]),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _severity_cards(counts: Dict[str, int]) -> Table:
    """Five white severity cards (Critical/High/Medium/Low/Accepted) with a colored
    top rule and a big number in the severity color (gray when zero), per the reference."""
    nums = [str(counts.get(s, 0)) for s in CARD_ORDER]
    labels = [s.capitalize() for s in CARD_ORDER]
    t = Table([nums, labels], colWidths=[32 * mm] * 5, rowHeights=[15 * mm, 8 * mm])
    style = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 26),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 8.5),
        ("TEXTCOLOR", (0, 1), (-1, 1), MUTED),
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 7),
    ]
    for i, sev in enumerate(CARD_ORDER):
        c = counts.get(sev, 0)
        style.append(("LINEABOVE", (i, 0), (i, 0), 2.4, SEV_COLORS[sev]))
        style.append(("TEXTCOLOR", (i, 0), (i, 0), SEV_COLORS[sev] if c > 0 else ZERO_GRAY))
    t.setStyle(TableStyle(style))
    return t


def _percent_bar(counts: Dict[str, int], width: float = 164 * mm) -> Table:
    """A stacked horizontal proportion bar across severities (with % labels)."""
    total = sum(counts.get(s, 0) for s in SEV_ORDER)
    if total == 0:
        t = Table([[""]], colWidths=[width], rowHeights=[6.5 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), LIGHT), ("BOX", (0, 0), (-1, -1), 0.5, BORDER)]))
        return t
    nz = [s for s in SEV_ORDER if counts.get(s, 0) > 0]
    cells, widths, style = [], [], [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
    ]
    for i, s in enumerate(nz):
        frac = counts[s] / total
        widths.append(width * frac)
        cells.append(f"{round(frac * 100)}%" if frac > 0.08 else "")
        style.append(("BACKGROUND", (i, 0), (i, 0), SEV_COLORS[s]))
    t = Table([cells], colWidths=widths, rowHeights=[6.5 * mm])
    t.setStyle(TableStyle(style))
    return t


def _coverage_stats(n_targets: int, n_vulns: int) -> Table:
    """Two large coverage numbers (Total Targets / Total Vulnerabilities)."""
    num = ParagraphStyle("covnum", fontName="Helvetica-Bold", fontSize=24, textColor=NAVY, leading=26)
    lab = ParagraphStyle("covlab", fontName="Helvetica", fontSize=8.5, textColor=MUTED, leading=12)
    cell1 = [Paragraph(str(n_targets), num), Spacer(1, 1.5 * mm), Paragraph("Total Targets", lab)]
    cell2 = [Paragraph(str(n_vulns), num), Spacer(1, 1.5 * mm), Paragraph("Total Vulnerabilities", lab)]
    t = Table([[cell1, cell2]], colWidths=[82 * mm, 82 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER), ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _toc(styles, section_title: str) -> List[Any]:
    """Table of Contents page flowables."""
    flow: List[Any] = [Paragraph("Table of Contents", styles["TOC"]), Spacer(1, 3 * mm),
                       _brand_rule(54 * mm), Spacer(1, 8 * mm)]
    entries = [("1", "Executive Summary"), ("2", "Vulnerabilities By Target"),
               ("3", section_title), ("4", "Glossary")]
    rows = [[Paragraph(n, styles["TOCNum"]), Paragraph(title, styles["TOCItem"])] for n, title in entries]
    t = Table(rows, colWidths=[14 * mm, 150 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 11), ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, BORDER),
        ("LINEABOVE", (0, 0), (-1, 0), 0.5, BORDER),
    ]))
    flow.append(t)
    return flow


def _header_footer(canvas, doc):
    _watermark(canvas)
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "DEWEBNET Solution  ·  SmartScan Vulnerability Scan Report")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(BORDER)
    canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
    canvas.restoreState()


def _meta(report: Dict[str, Any], scan_type: str) -> Dict[str, str]:
    if scan_type == "web":
        return {
            "target": report.get("url", "Unknown"),
            "subtitle": f"Server: {report.get('server', 'Unknown')}  |  Powered by: {report.get('powered_by', 'n/a')}",
            "scans_run": "Passive Web Application Scan (ZAP-style: headers, cookies, TLS) + Local CVE Match",
            "section_title": "Passive Web Application Vulnerabilities",
        }
    return {
        "target": report.get("host", "Unknown"),
        "subtitle": f"OS: {report.get('os', 'Unknown')}  |  Open ports: {', '.join(str(p) for p in report.get('open_ports', [])) or 'n/a'}",
        "scans_run": "Nmap Service/OS Detection + Local CVE Match",
        "section_title": "Host Vulnerabilities",
    }


def build_pdf(report: Dict[str, Any], scan_type: str = "web") -> bytes:
    """Render a scan report dict to a branded PDF. Returns bytes."""
    styles = _styles()
    findings = report.get("findings", [])
    counts = _severity_counts(findings)
    meta = _meta(report, scan_type)
    today = datetime.now()
    date_long = today.strftime("%B %d, %Y")
    date_short = today.strftime("%m/%d/%Y")

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"SmartScan Report {report.get('scan_id', '')}",
        author="DEWEBNET Solution",
    )
    story: List[Any] = []

    # ---------- Cover ----------
    if os.path.exists(LOGO_PATH):
        try:
            img = Image(LOGO_PATH)
            ratio = img.imageHeight / float(img.imageWidth)
            img.drawWidth = 60 * mm
            img.drawHeight = 60 * mm * ratio
            story.append(img)
        except Exception:
            pass
    story.append(Spacer(1, 16 * mm))
    story.append(Paragraph("DEWEBNET SOLUTION &nbsp;·&nbsp; SECURITY OPERATIONS", styles["Eyebrow"]))
    story.append(Paragraph("Vulnerability<br/>Scan Report", styles["Cover"]))
    story.append(Spacer(1, 3 * mm))
    story.append(_brand_rule(54 * mm))
    story.append(Spacer(1, 11 * mm))

    cover_rows = [
        ("TARGET", f"<b>{meta['target']}</b>"),
        ("DETAILS", meta["subtitle"]),
        ("ASSESSMENT", meta["scans_run"]),
        ("DATE", date_long),
        ("REPORT ID", str(report.get("scan_id", "n/a"))),
        ("PREPARED BY", "DEWEBNET Solution &nbsp;·&nbsp; dewebnetsolution.com"),
    ]
    cov = [[Paragraph(k, styles["Label"]), Paragraph(v, styles["Body"])] for k, v in cover_rows]
    covt = Table(cov, colWidths=[34 * mm, 130 * mm])
    covt.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, BORDER),
        ("LINEBEFORE", (0, 0), (0, -1), 2, GREEN),
        ("LEFTPADDING", (0, 0), (0, -1), 9),
    ]))
    story.append(covt)
    story.append(PageBreak())

    # ---------- Table of Contents ----------
    story.extend(_toc(styles, meta["section_title"]))
    story.append(PageBreak())

    # ---------- 1. Executive Summary ----------
    _h1(story, styles, "1  Executive Summary")
    story.append(Paragraph(
        "A vulnerability scan was conducted on the target below. This report contains the discovered "
        "potential vulnerabilities, classified by severity. Higher severity indicates a greater risk to "
        "the confidentiality, integrity, or availability of the target.", styles["Body"]))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("1.1  Total Vulnerabilities", styles["H2"]))
    story.append(Paragraph(
        "Below are the total number of vulnerabilities found by severity. Critical vulnerabilities are the "
        "most severe and should be evaluated first.", styles["Small"]))
    story.append(Spacer(1, 3 * mm))
    story.append(_severity_cards(counts))
    story.append(Spacer(1, 3 * mm))
    story.append(_percent_bar(counts))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("1.2  Report Coverage", styles["H2"]))
    story.append(Paragraph(
        f"This report includes findings for the target below. Scans run: {meta['scans_run']}.", styles["Small"]))
    story.append(Spacer(1, 3 * mm))
    story.append(_coverage_stats(1, len(findings)))
    story.append(Spacer(1, 4 * mm))
    if scan_type == "web":
        story.append(Paragraph(
            f"Config issues flagged: {report.get('checks_flagged', 0)}  |  "
            f"CVEs matched (local DB): {report.get('cves_found', 0)}  |  "
            f"HTTPS: {'Yes' if report.get('https') else 'No'}  |  "
            f"TLS issuer: {report.get('tls_issuer', 'Unknown')}", styles["Small"]))
    else:
        story.append(Paragraph(
            f"CVEs matched (local DB): {report.get('cves_found', 0)}  |  "
            f"Services detected: {len(report.get('services', []))}", styles["Small"]))
    story.append(PageBreak())

    # ---------- 2. Vulnerabilities By Target ----------
    _h1(story, styles, "2  Vulnerabilities By Target")
    story.append(Paragraph("2.1  Targets Summary", styles["H2"]))
    story.append(Paragraph("The number of potential vulnerabilities found for the target by severity.", styles["Small"]))
    story.append(Spacer(1, 2 * mm))

    def _dot_head(label, sev):
        hexv = SEV_COLORS[sev].hexval()[2:]
        return Paragraph(f'<font color="#{hexv}">●</font> {label}', styles["CellBold"])

    header = [Paragraph("Target", styles["CellBold"])] + [
        _dot_head(s.capitalize(), s) for s in CARD_ORDER]
    row = [Paragraph(meta["target"], styles["Cell"])] + [str(counts.get(s, 0)) for s in CARD_ORDER]
    tbl = Table([header, row], colWidths=[62 * mm, 22 * mm, 18 * mm, 22 * mm, 18 * mm, 22 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
        ("TEXTCOLOR", (0, 0), (-1, 0), NAVY),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("2.2  Target Breakdown", styles["H2"]))
    story.append(Paragraph(f"<b>{meta['target']}</b> &mdash; Scans run: {meta['scans_run']}", styles["Body"]))
    story.append(Spacer(1, 2 * mm))

    # Breakdown list: Title | Severity | Detected
    bd = [["Finding", "Severity", "Detected"]]
    for f in findings:
        title = f.get("description") or f.get("cve_id") or "Finding"
        accepted = str(f.get("status", "open")).lower() == "accepted"
        sev_label = "Accepted" if accepted else str(f.get("severity", "")).capitalize()
        bd.append([
            Paragraph(str(title), styles["Cell"]),
            Paragraph(sev_label, styles["CellBold"]),
            date_short,
        ])
    if len(bd) == 1:
        bd.append([Paragraph("No findings.", styles["Cell"]), "", ""])
    bt = Table(bd, colWidths=[110 * mm, 24 * mm, 30 * mm], repeatRows=1)
    bt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
        ("TEXTCOLOR", (0, 0), (-1, 0), NAVY),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(bt)
    story.append(PageBreak())

    # ---------- 3. Vulnerability Details ----------
    _h1(story, styles, f"3  {meta['section_title']}")
    story.append(Paragraph("Detailed information about each potential vulnerability found by the scan.", styles["Body"]))
    story.append(Spacer(1, 2 * mm))

    if not findings:
        story.append(Paragraph("No vulnerabilities were identified.", styles["Body"]))
    for idx, f in enumerate(findings, 1):
        fid = f.get("cve_id", "Finding")
        accepted = str(f.get("status", "open")).lower() == "accepted"
        sev = "accepted" if accepted else str(f.get("severity", "unknown"))
        title = f.get("description") or fid
        story.append(Paragraph(f"3.{idx}  {title}", styles["H2"]))

        info = Table([[
            _severity_badge(sev),
            Paragraph(f"<font color='#6b7185'>IDENTIFIER</font><br/><b>{fid}</b>", styles["Cell"]),
            Paragraph(f"<font color='#6b7185'>CVSS</font><br/><b>{f.get('cvss', 'N/A')}</b>", styles["Cell"]),
            Paragraph(f"<font color='#6b7185'>LAST DETECTED</font><br/><b>{date_short}</b>", styles["Cell"]),
        ]], colWidths=[26 * mm, 60 * mm, 30 * mm, 40 * mm])
        info.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(info)
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph("<b>Description</b>", styles["Body"]))
        story.append(Paragraph(str(f.get("risk_explanation", "No description available.")), styles["Body"]))
        story.append(Spacer(1, 1.5 * mm))
        story.append(Paragraph("<b>Recommendation</b>", styles["Body"]))
        story.append(Paragraph(str(f.get("fix", "Review and remediate.")), styles["Body"]))

        if str(fid).upper().startswith("CVE-"):
            story.append(Spacer(1, 1.5 * mm))
            story.append(Paragraph("<b>References</b>", styles["Body"]))
            story.append(Paragraph(f"https://nvd.nist.gov/vuln/detail/{fid}", styles["Small"]))

        story.append(Spacer(1, 4 * mm))

    story.append(PageBreak())

    # ---------- 4. Glossary ----------
    _h1(story, styles, "4  Glossary")
    gdata = [["Term", "Definition"]]
    for term, definition in GLOSSARY:
        gdata.append([Paragraph(f"<b>{term}</b>", styles["Cell"]), Paragraph(definition, styles["Cell"])])
    gt = Table(gdata, colWidths=[28 * mm, 136 * mm], repeatRows=1)
    gt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
        ("TEXTCOLOR", (0, 0), (-1, 0), NAVY),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(gt)

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
