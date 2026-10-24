import json
import re
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from pypdf import PdfReader
from pypdf.errors import PdfReadError
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from werkzeug.utils import secure_filename
from xml.sax.saxutils import escape


MAX_REVIEW_TEXT_CHARS = 1_000_000
MAX_DOCX_XML_BYTES = 5 * 1024 * 1024
MAX_PDF_PAGES = 200

RULES = (
    ("private_key", "Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I), 80),
    ("credential", "Possible credential or API key", re.compile(
        r"\b(?:api[_ -]?key|access[_ -]?token|client[_ -]?secret|password)\b\s*[:=]\s*[\"']?([^\s\"']{8,})",
        re.I,
    ), 65),
    ("payment_card", "Possible payment card number", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), 35),
    ("government_id", "Possible government identification number", re.compile(
        r"\b(?:\d{3}-\d{2}-\d{4}|\d{12})\b"
    ), 35),
    ("email", "Email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), 12),
    ("phone", "Possible phone number", re.compile(r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)"), 12),
)


class ReviewInputError(ValueError):
    pass


def extract_text(path: Path, original_filename: str) -> str:
    extension = secure_filename(original_filename).rsplit(".", 1)[-1].lower()
    if extension == "txt":
        try:
            return path.read_text(encoding="utf-8")[:MAX_REVIEW_TEXT_CHARS]
        except UnicodeDecodeError as error:
            raise ReviewInputError("This text file is not valid UTF-8.") from error
    if extension == "docx":
        try:
            with zipfile.ZipFile(path) as archive:
                info = archive.getinfo("word/document.xml")
                if info.file_size > MAX_DOCX_XML_BYTES:
                    raise ReviewInputError("The DOCX document body is too large to review safely.")
                xml = archive.read(info)
            root = ElementTree.fromstring(xml)
        except (KeyError, OSError, RuntimeError, zipfile.BadZipFile, ElementTree.ParseError) as error:
            raise ReviewInputError("The DOCX document could not be read.") from error
        return " ".join(text for text in root.itertext() if text)[:MAX_REVIEW_TEXT_CHARS]
    if extension == "pdf":
        try:
            reader = PdfReader(path, strict=True)
            if reader.is_encrypted:
                raise ReviewInputError("Password-protected PDFs cannot be reviewed.")
            if len(reader.pages) > MAX_PDF_PAGES:
                raise ReviewInputError(f"PDFs are limited to {MAX_PDF_PAGES} pages for review.")
            extracted = []
            remaining = MAX_REVIEW_TEXT_CHARS
            for page in reader.pages:
                page_text = page.extract_text() or ""
                extracted.append(page_text[:remaining])
                remaining -= len(page_text)
                if remaining <= 0:
                    break
            return "\n".join(extracted)
        except ReviewInputError:
            raise
        except (KeyError, OSError, PdfReadError, ValueError) as error:
            raise ReviewInputError("The PDF could not be safely parsed.") from error
    if extension in {"png", "jpg", "jpeg"}:
        raise ReviewInputError("Image OCR is not enabled. This local review supports PDF, DOCX, and TXT.")
    raise ReviewInputError("This file type is not supported for document review.")


def _has_luhn_checksum(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _redact(value: str) -> str:
    if "@" in value:
        local, separator, domain = value.partition("@")
        return f"{local[:1]}***{separator}{domain}"
    digits = "".join(char for char in value if char.isdigit())
    if len(digits) >= 8:
        return f"***{digits[-4:]}"
    return "[redacted]"


def build_review(text: str, document: dict, reviewer: dict) -> dict:
    findings = []
    deductions = 0
    for code, label, pattern, deduction in RULES:
        matches = list(pattern.finditer(text))
        if code == "payment_card":
            matches = [match for match in matches if _has_luhn_checksum(match.group())]
        if not matches:
            continue
        count = len(matches)
        deductions += deduction * min(count, 3)
        findings.append({
            "code": code,
            "label": label,
            "count": count,
            "examples": [_redact(match.group()) for match in matches[:3]],
            "severity": "high" if deduction >= 35 else "medium" if deduction >= 12 else "low",
        })

    score = max(0, 100 - deductions)
    level = "low" if score >= 80 else "moderate" if score >= 50 else "high"
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "id": str(uuid.uuid4()),
        "document_id": document["id"],
        "document_name": document["name"],
        "document_category": document["category"],
        "reviewed_by": reviewer["display_name"],
        "created_at": created_at,
        "privacy_score": score,
        "risk_level": level,
        "findings": findings,
        "summary": (
            f"Found {sum(item['count'] for item in findings)} potential sensitive-data matches "
            f"across {len(findings)} categories."
            if findings else "No supported sensitive-data patterns were detected."
        ),
        "methodology": (
            "Local deterministic pattern scan for possible credentials, private-key markers, "
            "government ID numbers, payment-card numbers (Luhn check), email addresses, and phone numbers. "
            "Matches are heuristic and can be false positives or miss sensitive content. "
            "No file text is sent to an external service or included in this report."
        ),
    }


def render_pdf_report(report: dict, output):
    styles = getSampleStyleSheet()
    body = ParagraphStyle("ReviewBody", parent=styles["BodyText"], leading=15, alignment=TA_LEFT)
    title = ParagraphStyle("ReviewTitle", parent=styles["Title"], textColor=colors.HexColor("#142d46"))
    heading = ParagraphStyle("ReviewHeading", parent=styles["Heading2"], textColor=colors.HexColor("#098b83"))
    story = [
        Paragraph("TrustVault Document Risk Review", title),
        Spacer(1, 4 * mm),
        Paragraph(f"Document: {escape(report['document_name'])}", body),
        Paragraph(f"Category: {escape(report['document_category'])}", body),
        Paragraph(f"Reviewed by: {escape(report['reviewed_by'])}", body),
        Paragraph(f"Date: {escape(report['created_at'])}", body),
        Spacer(1, 5 * mm),
        Paragraph(f"Privacy score: {report['privacy_score']}/100 ({escape(report['risk_level'].title())} risk)", heading),
        Paragraph(escape(report["summary"]), body),
        Spacer(1, 4 * mm),
        Paragraph("Potential findings", heading),
    ]
    if report["findings"]:
        rows = [["Category", "Severity", "Count", "Redacted examples"]]
        for item in report["findings"]:
            rows.append([
                escape(item["label"]),
                escape(item["severity"].title()),
                str(item["count"]),
                escape(", ".join(item["examples"])),
            ])
        table = Table(rows, colWidths=[48 * mm, 24 * mm, 16 * mm, 74 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#142d46")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dce4eb")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fb")]),
        ]))
        story.extend([table, Spacer(1, 5 * mm)])
    else:
        story.extend([Paragraph("No supported patterns detected.", body), Spacer(1, 5 * mm)])
    story.extend([
        Paragraph("Method and limitations", heading),
        Paragraph(escape(report["methodology"]), body),
        Spacer(1, 3 * mm),
        Paragraph(
            "This is a heuristic privacy review, not a factual accuracy, legal, or compliance certification.",
            styles["Italic"],
        ),
    ])
    SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="TrustVault Document Risk Review",
    ).build(story)
    return output


def serialize_review(report: dict) -> str:
    return json.dumps(report, sort_keys=True, separators=(",", ":"))
