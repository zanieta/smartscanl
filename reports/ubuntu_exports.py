"""Finding-only derivatives. Do not export host identifiers, package lists or raw payloads."""
import csv
from io import BytesIO, StringIO
import json
from uuid import UUID

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


TYPES = {"csv": "text/csv", "json": "application/json", "pdf": "application/pdf",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
FIELDS = ("control", "observed", "expected", "recommendation")
RECOMMENDATION = "Review workload compatibility, apply the approved kernel policy and retest."


def findings_export(review, fmt):
    # Only normalized, allowlisted controls can reach here. No arbitrary cell text or formulas.
    rows = [(c["id"], c["observed"], c["expected"], RECOMMENDATION)
            for c in review["checks"] if c["state"] == "open"]
    try:
        reference = str(UUID(review["scan_id"]))
    except (ValueError, TypeError, AttributeError):
        reference = None
    if fmt == "json":
        return json.dumps({"scan_id": reference, "findings": [dict(zip(FIELDS, r)) for r in rows]}).encode()
    if fmt == "csv":
        text = StringIO(newline="")
        writer = csv.writer(text)
        writer.writerow(("scan_id", *FIELDS))
        writer.writerows((reference, *r) for r in rows)
        return text.getvalue().encode()
    buf = BytesIO()
    if fmt == "pdf":
        doc = canvas.Canvas(buf, pagesize=A4)
        doc.setTitle("Ubuntu baseline findings | DE-Webnet Security360")
        doc.setFillColorRGB(.08, .18, .28)
        doc.setFont("Helvetica-Bold", 13)
        doc.drawString(48, 778, "DE-Webnet Security360")
        doc.setFont("Helvetica-Bold", 22)
        doc.drawString(48, 735, "Ubuntu baseline findings")
        doc.setFont("Helvetica", 11)
        doc.drawString(48, 708, f"Measured configuration deviations: {len(rows)}")
        if reference:
            doc.setFont("Helvetica", 9)
            doc.drawString(48, 690, "Evidence reference: " + reference)
        for i, (control, observed, expected, fix) in enumerate(rows):
            y = 650 - i * 100
            doc.setFont("Helvetica-Bold", 13)
            doc.drawString(48, y, control)
            doc.setFont("Helvetica", 10)
            doc.drawString(48, y-21, f"Observed: {observed}     Expected: {expected}")
            doc.drawString(48, y-40, fix)
        doc.showPage()
        doc.save()
    elif fmt == "xlsx":
        import xlsxwriter
        with xlsxwriter.Workbook(buf, {"in_memory": True}) as book:
            if reference:
                book.set_properties({"subject": "Evidence reference: " + reference})
            sheet = book.add_worksheet("Ubuntu findings")
            heading = book.add_format({"bold": True, "bg_color": "#17334A", "font_color": "#FFFFFF"})
            sheet.freeze_panes(1, 0)
            for col, width in enumerate((28, 14, 14, 84)):
                sheet.set_column(col, col, width)
                sheet.write_string(0, col, FIELDS[col], heading)
            for index, row in enumerate(rows, 1):
                for col, value in enumerate(row):
                    sheet.write_string(index, col, value)
    else:
        raise ValueError("Unsupported export format.")
    return buf.getvalue()
