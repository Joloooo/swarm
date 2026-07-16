"""Generate a flowing, branded SwarmAttacker penetration-test PDF.

The PDF is a complete client deliverable rather than a fixed-page executive
excerpt.  Platypus owns pagination, so evidence, URLs, tables, and remediation
can grow without colliding with headings or being clipped.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.colors import HexColor, white
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    HRFlowable,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .content import ReportContent, ReportFinding, build_report_content


PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

INK = HexColor("#111318")
MUTED = HexColor("#667085")
SOFT = HexColor("#98A2B3")
PAPER = HexColor("#F7F8FA")
LINE = HexColor("#E4E7EC")
RED = HexColor("#E22935")
RED_DARK = HexColor("#9F1722")
CHARCOAL = HexColor("#090A0D")
CARD = HexColor("#17191F")
BLUE = HexColor("#175CD3")
GREEN = HexColor("#067647")

SEVERITY_COLOURS = {
    "critical": HexColor("#9B1C1C"),
    "high": HexColor("#D92D20"),
    "medium": HexColor("#F79009"),
    "low": HexColor("#1570EF"),
    "info": HexColor("#667085"),
}

LOGO_PATH = Path(__file__).with_name("assets") / "swarm-logo.png"
REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports"


def _register_fonts() -> tuple[str, str, str]:
    """Use bundled workspace fonts when available, otherwise core PDF fonts."""
    candidates = [
        ("/System/Library/Fonts/Supplemental/Arial.ttf", "SwarmSans"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "SwarmSans"),
    ]
    bold_candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ]
    mono_candidates = [
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    regular = "Helvetica"
    bold = "Helvetica-Bold"
    mono = "Courier"
    for path, name in candidates:
        if Path(path).exists():
            try:
                pdfmetrics.registerFont(TTFont(name, path))
                regular = name
                break
            except Exception:  # noqa: BLE001
                pass
    for path in bold_candidates:
        if Path(path).exists():
            try:
                pdfmetrics.registerFont(TTFont("SwarmSans-Bold", path))
                bold = "SwarmSans-Bold"
                break
            except Exception:  # noqa: BLE001
                pass
    for path in mono_candidates:
        if Path(path).exists():
            try:
                pdfmetrics.registerFont(TTFont("SwarmMono", path))
                mono = "SwarmMono"
                break
            except Exception:  # noqa: BLE001
                pass
    if regular == "SwarmSans" and bold == "SwarmSans-Bold":
        pdfmetrics.registerFontFamily("SwarmSans", normal=regular, bold=bold)
    return regular, bold, mono


FONT, FONT_BOLD, FONT_MONO = _register_fonts()


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "SwarmTitle", parent=base["Title"], fontName=FONT_BOLD,
            fontSize=23, leading=27, textColor=INK, spaceAfter=5,
        ),
        "subtitle": ParagraphStyle(
            "SwarmSubtitle", parent=base["BodyText"], fontName=FONT,
            fontSize=9.5, leading=13, textColor=MUTED, spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "SwarmH2", parent=base["Heading2"], fontName=FONT_BOLD,
            fontSize=14, leading=17, textColor=INK, spaceBefore=12, spaceAfter=7,
        ),
        "h3": ParagraphStyle(
            "SwarmH3", parent=base["Heading3"], fontName=FONT_BOLD,
            fontSize=10.5, leading=13, textColor=INK, spaceBefore=9, spaceAfter=5,
        ),
        "body": ParagraphStyle(
            "SwarmBody", parent=base["BodyText"], fontName=FONT,
            fontSize=9, leading=12.5, textColor=INK, spaceAfter=6,
        ),
        "small": ParagraphStyle(
            "SwarmSmall", parent=base["BodyText"], fontName=FONT,
            fontSize=7.7, leading=10.5, textColor=MUTED,
        ),
        "tiny": ParagraphStyle(
            "SwarmTiny", parent=base["BodyText"], fontName=FONT,
            fontSize=6.7, leading=8.5, textColor=MUTED,
        ),
        "bullet": ParagraphStyle(
            "SwarmBullet", parent=base["BodyText"], fontName=FONT,
            fontSize=8.8, leading=12, textColor=INK, leftIndent=11,
            firstLineIndent=-7, bulletIndent=0, spaceAfter=4,
        ),
        "number": ParagraphStyle(
            "SwarmNumber", parent=base["BodyText"], fontName=FONT,
            fontSize=8.8, leading=12, textColor=INK, leftIndent=18,
            firstLineIndent=-14, spaceAfter=4,
        ),
        "url": ParagraphStyle(
            "SwarmURL", parent=base["BodyText"], fontName=FONT,
            fontSize=7.3, leading=9.5, textColor=BLUE, wordWrap="CJK",
        ),
        "evidence": ParagraphStyle(
            "SwarmEvidence", parent=base["Code"], fontName=FONT_MONO,
            fontSize=6.6, leading=8.7, textColor=INK, wordWrap="CJK",
            backColor=HexColor("#F2F4F7"), borderColor=LINE,
            borderWidth=0.5, borderPadding=8, spaceAfter=8,
        ),
        "impact": ParagraphStyle(
            "SwarmImpact", parent=base["BodyText"], fontName=FONT,
            fontSize=9.4, leading=13, textColor=INK,
        ),
        "table_header": ParagraphStyle(
            "SwarmTableHeader", parent=base["BodyText"], fontName=FONT_BOLD,
            fontSize=7, leading=9, textColor=white,
        ),
        "table": ParagraphStyle(
            "SwarmTable", parent=base["BodyText"], fontName=FONT,
            fontSize=7.3, leading=9.5, textColor=INK, wordWrap="CJK",
        ),
        "table_bold": ParagraphStyle(
            "SwarmTableBold", parent=base["BodyText"], fontName=FONT_BOLD,
            fontSize=7.3, leading=9.5, textColor=INK, wordWrap="CJK",
        ),
        "table_compact": ParagraphStyle(
            "SwarmTableCompact", parent=base["BodyText"], fontName=FONT,
            fontSize=6.25, leading=7.6, textColor=INK, wordWrap="CJK",
        ),
        "table_compact_bold": ParagraphStyle(
            "SwarmTableCompactBold", parent=base["BodyText"], fontName=FONT_BOLD,
            fontSize=6.25, leading=7.6, textColor=INK, wordWrap="CJK",
        ),
        "center_white": ParagraphStyle(
            "SwarmCenterWhite", parent=base["BodyText"], fontName=FONT_BOLD,
            fontSize=8, leading=10, textColor=white, alignment=TA_CENTER,
        ),
        "metric_value": ParagraphStyle(
            "SwarmMetricValue", parent=base["BodyText"], fontName=FONT_BOLD,
            fontSize=17, leading=20, textColor=INK, alignment=TA_CENTER,
        ),
        "metric_label": ParagraphStyle(
            "SwarmMetricLabel", parent=base["BodyText"], fontName=FONT_BOLD,
            fontSize=6.5, leading=8, textColor=MUTED, alignment=TA_CENTER,
        ),
        "right": ParagraphStyle(
            "SwarmRight", parent=base["BodyText"], fontName=FONT,
            fontSize=7.5, leading=9, textColor=MUTED, alignment=TA_RIGHT,
        ),
    }


STYLES = _styles()


def _p(text: str, style: str = "body") -> Paragraph:
    return Paragraph(escape(str(text or "")), STYLES[style])


def _rich(text: str, style: str = "body") -> Paragraph:
    return Paragraph(text, STYLES[style])


def _bullets(items: list[str], *, bold_labels: bool = False) -> list[Flowable]:
    result: list[Flowable] = []
    for item in items:
        value = escape(item)
        if bold_labels and ":" in value:
            label, rest = value.split(":", 1)
            value = f"<b>{label}:</b>{rest}"
        result.append(Paragraph(f"<font color='#E22935'>•</font> {value}", STYLES["bullet"]))
    return result


def _section_heading(title: str, kicker: str = "") -> list[Flowable]:
    items: list[Flowable] = []
    if kicker:
        items.append(_rich(f"<font color='#E22935'><b>{escape(kicker.upper())}</b></font>", "small"))
        items.append(Spacer(1, 2))
    items.append(_p(title, "h2"))
    items.append(HRFlowable(width="100%", thickness=0.7, color=LINE, spaceAfter=6))
    return items


class CoverPage(Flowable):
    def __init__(self, report: ReportContent, generated: datetime):
        super().__init__()
        self.report = report
        self.generated = generated
        self.width = PAGE_W
        self.height = PAGE_H

    def wrap(self, avail_width: float, avail_height: float) -> tuple[float, float]:
        return PAGE_W, PAGE_H

    def draw(self) -> None:
        pdf = self.canv
        pdf.setFillColor(CHARCOAL)
        pdf.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        pdf.setFillColor(RED)
        pdf.rect(0, 0, 8, PAGE_H, fill=1, stroke=0)
        if LOGO_PATH.exists():
            pdf.drawImage(
                ImageReader(LOGO_PATH), PAGE_W - MARGIN - 64 * mm,
                PAGE_H - 95 * mm, 64 * mm, 64 * mm,
                preserveAspectRatio=True, mask="auto",
            )
        pdf.setFont(FONT_BOLD, 9)
        pdf.setFillColor(RED)
        pdf.drawString(MARGIN, PAGE_H - 28 * mm, "SWARMATTACKER / SECURITY ASSESSMENT")
        pdf.setFillColor(white)
        pdf.setFont(FONT_BOLD, 29)
        pdf.drawString(MARGIN, PAGE_H - 48 * mm, "PENETRATION")
        pdf.drawString(MARGIN, PAGE_H - 61 * mm, "TEST REPORT")
        pdf.setFillColor(HexColor("#AEB4BF"))
        pdf.setFont(FONT, 10)
        pdf.drawString(MARGIN, PAGE_H - 70 * mm, "Autonomous black-box web application assessment")

        y = PAGE_H - 145 * mm
        pdf.setFillColor(HexColor("#8B919C"))
        pdf.setFont(FONT_BOLD, 7.5)
        pdf.drawString(MARGIN, y, "TARGET")
        pdf.setFillColor(white)
        pdf.setFont(FONT_BOLD, 13)
        target = self.report.target
        while len(target) > 70:
            pdf.drawString(MARGIN, y - 9 * mm, target[:70])
            target = target[70:]
            y -= 6 * mm
        pdf.drawString(MARGIN, y - 9 * mm, target)
        y -= 23 * mm
        pdf.setFillColor(HexColor("#8B919C"))
        pdf.setFont(FONT_BOLD, 7.5)
        pdf.drawString(MARGIN, y, "AUTHORIZED SCOPE")
        pdf.setFillColor(HexColor("#D0D4DA"))
        pdf.setFont(FONT, 8.5)
        scope = self.report.scope[:180]
        pdf.drawString(MARGIN, y - 8 * mm, scope)

        counts = self.report.severity_counts
        card_y = 38 * mm
        card_w = (CONTENT_W - 9 * mm) / 4
        for index, severity in enumerate(("critical", "high", "medium", "low")):
            x = MARGIN + index * (card_w + 3 * mm)
            pdf.setFillColor(CARD)
            pdf.roundRect(x, card_y, card_w, 25 * mm, 6, fill=1, stroke=0)
            pdf.setFillColor(SEVERITY_COLOURS[severity])
            pdf.rect(x, card_y + 23.5 * mm, card_w, 1.5 * mm, fill=1, stroke=0)
            pdf.setFillColor(white)
            pdf.setFont(FONT_BOLD, 20)
            pdf.drawCentredString(x + card_w / 2, card_y + 13 * mm, str(counts[severity]))
            pdf.setFillColor(HexColor("#AEB4BF"))
            pdf.setFont(FONT_BOLD, 6.5)
            pdf.drawCentredString(x + card_w / 2, card_y + 6 * mm, severity.upper())

        pdf.setFillColor(HexColor("#8B919C"))
        pdf.setFont(FONT, 7.5)
        pdf.drawString(MARGIN, 22 * mm, self.generated.strftime("Generated %d %B %Y, %H:%M %Z"))
        pdf.drawRightString(PAGE_W - MARGIN, 22 * mm, "CONFIDENTIAL")


def _body_page(pdf, doc) -> None:  # noqa: ANN001
    pdf.saveState()
    pdf.setFillColor(CHARCOAL)
    pdf.rect(0, PAGE_H - 19 * mm, PAGE_W, 19 * mm, fill=1, stroke=0)
    if LOGO_PATH.exists():
        pdf.drawImage(
            ImageReader(LOGO_PATH), MARGIN, PAGE_H - 16.5 * mm, 12 * mm, 12 * mm,
            preserveAspectRatio=True, mask="auto",
        )
    pdf.setFillColor(white)
    pdf.setFont(FONT_BOLD, 10.5)
    pdf.drawString(MARGIN + 15 * mm, PAGE_H - 11 * mm, "SWARMATTACKER")
    pdf.setFillColor(HexColor("#B8BDC7"))
    pdf.setFont(FONT, 7.5)
    pdf.drawRightString(PAGE_W - MARGIN, PAGE_H - 11 * mm, "SECURITY ASSESSMENT")
    pdf.setStrokeColor(LINE)
    pdf.line(MARGIN, 12 * mm, PAGE_W - MARGIN, 12 * mm)
    pdf.setFillColor(MUTED)
    pdf.setFont(FONT, 6.8)
    pdf.drawString(MARGIN, 7 * mm, "CONFIDENTIAL - AUTHORIZED SECURITY TESTING")
    pdf.drawRightString(PAGE_W - MARGIN, 7 * mm, f"PAGE {pdf.getPageNumber()}")
    pdf.restoreState()


def _metric_cards(report: ReportContent) -> Table:
    confirmed = sum(1 for finding in report.findings if finding.validation == "Confirmed")
    data = [[
        [
            _p(str(len(report.findings)), "metric_value"),
            _p("ACTIONABLE FINDINGS", "metric_label"),
        ],
        [
            _p(f"{report.average_confidence}%", "metric_value"),
            _p("AVG. EVIDENCE CONFIDENCE", "metric_label"),
        ],
        [
            _p(str(confirmed), "metric_value"),
            _p("INDEPENDENTLY CONFIRMED", "metric_label"),
        ],
        [
            _p(str(len(report.unverified)), "metric_value"),
            _p("MANUAL REVIEW", "metric_label"),
        ],
    ]]
    table = Table(data, colWidths=[CONTENT_W / 4 - 3] * 4, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), white),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    return table


def _risk_panel(report: ReportContent) -> Table:
    colour = SEVERITY_COLOURS.get(report.overall_risk.lower(), MUTED)
    left = Table(
        [[_rich(f"<font size='7'>OVERALL RISK</font>", "center_white")],
         [_rich(f"<font size='22'><b>{escape(report.overall_risk.upper())}</b></font>", "center_white")],
         [_rich(f"<font size='7'>{escape(report.overall_risk_band)}</font>", "center_white")]],
        colWidths=[38 * mm],
    )
    left.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colour),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    rationale = Table(
        [[_rich("<b>What matters</b>", "h3")], [_p(report.risk_rationale, "impact")]],
        colWidths=[CONTENT_W - 40 * mm],
    )
    rationale.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#FFF7F7")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    panel = Table([[left, rationale]], colWidths=[38 * mm, CONTENT_W - 38 * mm])
    panel.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.7, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return panel


def _two_column_bullets(report: ReportContent) -> Table:
    outcomes = [_rich("<font color='#E22935'><b>WHAT AN ATTACKER COULD ACHIEVE</b></font>", "small")]
    outcomes += _bullets(report.attacker_outcomes, bold_labels=True)
    assets = [_rich("<font color='#E22935'><b>SYSTEMS AND DATA AT RISK</b></font>", "small")]
    assets += _bullets(report.assets_at_risk)
    table = Table([[outcomes, assets]], colWidths=[CONTENT_W / 2 - 4, CONTENT_W / 2 - 4])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), white),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 11),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    return table


def _severity_distribution(report: ReportContent) -> Table:
    counts = report.severity_counts
    levels = ("critical", "high", "medium", "low", "info")
    cells = []
    for severity in levels:
        cells.append(_rich(
            f"<font size='13'><b>{counts[severity]}</b></font><br/>"
            f"<font size='6'>{severity.upper()}</font>",
            "center_white",
        ))
    table = Table([cells], colWidths=[CONTENT_W / 5] * 5, rowHeights=[16 * mm])
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]
    for index, severity in enumerate(levels):
        commands.append(("BACKGROUND", (index, 0), (index, 0), SEVERITY_COLOURS[severity]))
    table.setStyle(TableStyle(commands))
    return table


def _summary_table(report: ReportContent) -> Table:
    data = [[
        _p("ID", "table_header"), _p("SEVERITY", "table_header"),
        _p("CONFIDENCE", "table_header"), _p("VALIDATION", "table_header"),
        _p("FINDING", "table_header"),
    ]]
    for index, finding in enumerate(report.findings, 1):
        data.append([
            _p(f"F-{index:03d}", "table_bold"),
            _rich(
                f"<font color='{SEVERITY_COLOURS[finding.severity].hexval()}'><b>"
                f"{escape(finding.severity.upper())}</b></font>", "table",
            ),
            _p(f"{finding.confidence}%", "table"),
            _p(finding.validation, "table"),
            _p(finding.title, "table"),
        ])
    table = Table(
        data,
        colWidths=[15 * mm, 22 * mm, 23 * mm, 25 * mm, CONTENT_W - 85 * mm],
        repeatRows=1,
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), CHARCOAL),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.45, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _finding_banner(finding: ReportFinding, index: int) -> Table:
    colour = SEVERITY_COLOURS[finding.severity]
    title = _rich(
        f"<font size='7' color='#667085'>F-{index:03d}</font><br/>"
        f"<font size='15'><b>{escape(finding.title)}</b></font>", "body",
    )
    severity = _rich(
        f"<font size='7'>SEVERITY</font><br/><font size='13'><b>"
        f"{escape(finding.severity.upper())}</b></font><br/>"
        f"<font size='6'>{escape(finding.severity_band)}</font>",
        "center_white",
    )
    table = Table([[severity, title]], colWidths=[34 * mm, CONTENT_W - 34 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colour),
        ("BACKGROUND", (1, 0), (1, 0), white),
        ("BOX", (0, 0), (-1, -1), 0.8, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 4),
        ("RIGHTPADDING", (0, 0), (0, 0), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (1, 0), (1, 0), 12),
    ]))
    return table


def _finding_metadata(finding: ReportFinding) -> Table:
    rows = [
        [
            _rich("<b>EVIDENCE CONFIDENCE</b>", "tiny"),
            _rich("<b>VALIDATION STATUS</b>", "tiny"),
            _rich("<b>CATEGORY / CWE</b>", "tiny"),
        ],
        [
            _rich(f"<font size='12'><b>{finding.confidence}%</b></font><br/>"
                  f"<font size='7'>{escape(finding.confidence_label)}</font>", "body"),
            _rich(f"<font size='10'><b>{escape(finding.validation)}</b></font>", "body"),
            _rich(f"<font size='9'><b>{escape(finding.category)}</b></font><br/>"
                  f"<font size='7'>{escape(finding.cwe or 'Not mapped')}</font>", "body"),
        ],
    ]
    table = Table(rows, colWidths=[CONTENT_W / 3] * 3)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _impact_box(finding: ReportFinding) -> Table:
    content = [
        _rich("<font color='#9F1722'><b>WHAT AN ATTACKER COULD ACHIEVE</b></font>", "small"),
        Spacer(1, 3),
        _p(finding.business_impact, "impact"),
        Spacer(1, 4),
        _rich("<b>Systems and data at risk</b>", "small"),
        *_bullets(finding.assets_at_risk),
    ]
    table = Table([[content]], colWidths=[CONTENT_W])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#FFF7F7")),
        ("BOX", (0, 0), (-1, -1), 0.8, HexColor("#F4B8BD")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def _attempt_table(finding: ReportFinding) -> Table | None:
    if not finding.attempts:
        return None
    data = [[
        _p("STEP", "table_header"), _p("METHOD", "table_header"),
        _p("RESULT", "table_header"), _p("OBSERVATION", "table_header"),
    ]]
    for index, attempt in enumerate(finding.attempts, 1):
        data.append([
            _p(str(index), "table"),
            _p(attempt.get("method") or "Not recorded", "table"),
            _p(attempt.get("result") or "Not recorded", "table"),
            _p(attempt.get("note") or "", "table"),
        ])
    table = Table(
        data,
        colWidths=[12 * mm, 43 * mm, 27 * mm, CONTENT_W - 82 * mm],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), CHARCOAL),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.45, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _evidence_paragraph(evidence: str) -> Paragraph:
    # Paragraph's CJK wrapping safely breaks long cookies, URLs, and tokens.
    clean = str(evidence or "").replace("\x00", "")
    rendered = escape(clean).replace("\n", "<br/>")
    return Paragraph(rendered, STYLES["evidence"])


def _remediation_box(finding: ReportFinding) -> Table:
    content = [
        _rich("<font color='#067647'><b>RECOMMENDED REMEDIATION</b></font>", "small"),
        Spacer(1, 3),
        *_bullets(finding.remediation),
        Spacer(1, 3),
        _rich(f"<b>How to verify the fix:</b> {escape(finding.validation_guidance)}", "body"),
    ]
    table = Table([[content]], colWidths=[CONTENT_W])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#F3FAF7")),
        ("BOX", (0, 0), (-1, -1), 0.8, HexColor("#A6D8C4")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def _finding_story(finding: ReportFinding, index: int) -> list[Flowable]:
    story: list[Flowable] = [
        CondPageBreak(105 * mm),
        _finding_banner(finding, index),
        Spacer(1, 7),
        _finding_metadata(finding),
        Spacer(1, 7),
    ]
    if finding.url:
        story.extend([
            _rich("<b>Affected target</b>", "small"),
            _p(finding.url, "url"),
            Spacer(1, 5),
        ])
    story.extend([
        _impact_box(finding),
        *_section_heading("Technical description", "Technical detail"),
        _p(finding.description or "No additional technical description was recorded."),
        _rich(f"<b>Root cause:</b> {escape(finding.root_cause)}", "body"),
        *_section_heading("Attack narrative", "Demonstration"),
    ])
    for step, text in enumerate(finding.attack_narrative, 1):
        story.append(_rich(f"<b>{step}.</b> {escape(text)}", "number"))
    attempts = _attempt_table(finding)
    if attempts is not None:
        story.extend([_p("Recorded testing steps", "h3"), attempts, Spacer(1, 7)])
    if finding.evidence:
        story.append(KeepTogether([
            _p("Raw evidence", "h3"),
            _p("The excerpt below is captured technical evidence, not an AI summary.", "small"),
            Spacer(1, 3),
            _evidence_paragraph(finding.evidence),
        ]))
    story.extend([Spacer(1, 5), _remediation_box(finding)])
    return story


def _remediation_table(report: ReportContent) -> Table:
    data = [[
        _p("PRIORITY", "table_header"), _p("FINDING", "table_header"),
        _p("FIRST ACTION", "table_header"), _p("CONFIDENCE", "table_header"),
    ]]
    for index, finding in enumerate(report.findings, 1):
        priority = "P0" if finding.severity in {"critical", "high"} else "P1" if finding.severity == "medium" else "P2"
        action = finding.remediation[0] if finding.remediation else "Review the finding."
        short_title = finding.title if len(finding.title) <= 92 else finding.title[:89].rstrip() + "..."
        short_action = action if len(action) <= 145 else action[:142].rstrip() + "..."
        data.append([
            _p(priority, "table_compact_bold"),
            _rich(f"<b>F-{index:03d}</b><br/>{escape(short_title)}", "table_compact"),
            _p(short_action, "table_compact"),
            _p(f"{finding.confidence}%", "table_compact"),
        ])
    table = Table(
        data,
        colWidths=[18 * mm, 57 * mm, CONTENT_W - 98 * mm, 23 * mm],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), CHARCOAL),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.45, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


def _story(report: ReportContent, generated: datetime) -> list[Flowable]:
    story: list[Flowable] = [
        NextPageTemplate("body"),
        CoverPage(report, generated),
        PageBreak(),
        _p("Executive summary", "title"),
        _p("Business risk, demonstrated attacker outcomes, and immediate priorities", "subtitle"),
        _risk_panel(report),
        Spacer(1, 10),
        _metric_cards(report),
        Spacer(1, 10),
        _two_column_bullets(report),
        *_section_heading("Priority actions", "What should be fixed first"),
        *_bullets(report.priority_actions, bold_labels=True),
        Spacer(1, 4),
        _rich(f"<b>Assessment limitation:</b> {escape(report.limitations)}", "small"),
        *_section_heading("Risk distribution", "Actionable findings"),
        _severity_distribution(report),
        PageBreak(),
        _p("Engagement overview", "title"),
        _p("Scope, assessment model, evidence interpretation, and coverage", "subtitle"),
    ]

    details = [
        [_rich("<b>Target</b>", "table"), _p(report.target, "url")],
        [_rich("<b>Authorized scope</b>", "table"), _p(report.scope, "table")],
        [_rich("<b>Testing model</b>", "table"), _p("Autonomous black-box web application testing", "table")],
        [_rich("<b>Traffic profile</b>", "table"), _p(report.traffic_profile, "table")],
        [_rich("<b>Raw observations</b>", "table"), _p(str(report.raw_observation_count), "table")],
        [_rich("<b>Consolidated findings</b>", "table"), _p(str(len(report.findings)), "table")],
    ]
    detail_table = Table(details, colWidths=[40 * mm, CONTENT_W - 40 * mm])
    detail_table.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [white, HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.45, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([
        detail_table,
        *_section_heading("Methodology", "How the assessment was performed"),
        _p(
            "SwarmAttacker mapped reachable functionality, formed evidence-backed hypotheses, "
            "dispatched specialist testing capabilities, and consolidated repeated observations by "
            "root cause. The assessment was limited to the supplied scope, credentials, runtime, "
            "target availability, and non-destructive authorization constraints."
        ),
        *_section_heading("Severity and evidence confidence", "How to read the scores"),
        _p(
            "Severity describes potential damage if a vulnerability is exploited. The qualitative "
            "bands are Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9, and "
            "Informational. A band is shown rather than an invented exact CVSS score when no full "
            "CVSS vector was calculated."
        ),
        _p(
            "Confidence is not model self-confidence. It is calculated from raw evidence quality "
            "(0-40 points), validation status (0-35), successful supporting attempts (0-15), and "
            "traceability metadata (0-10). Unverified observations are capped below 70%."
        ),
    ])
    if report.testing_areas:
        story.extend([*_section_heading("Testing areas exercised", "Coverage"), *_bullets(report.testing_areas)])
    story.extend([
        PageBreak(),
        _p("Findings summary", "title"),
        _p("Consolidated root-cause findings ordered by severity", "subtitle"),
        _summary_table(report),
    ])
    if report.findings:
        story.extend([*_section_heading("Key attack paths", "Demonstrated behavior")])
        for index, finding in enumerate(report.findings[:4], 1):
            outcome = finding.business_impact
            story.append(_rich(
                f"<b>F-{index:03d} — {escape(finding.title)}:</b> {escape(outcome)}",
                "bullet",
            ))
    for index, finding in enumerate(report.findings, 1):
        story.extend(_finding_story(finding, index))

    story.extend([
        PageBreak(),
        _p("Remediation roadmap", "title"),
        _p("Prioritized actions grouped by demonstrated risk and evidence confidence", "subtitle"),
        _p(
            "P0 items should be addressed immediately, P1 items in the next planned remediation "
            "cycle, and P2 items as hardening work. Application owners should adjust timing where "
            "business context or compensating controls materially change exposure."
        ),
        _remediation_table(report),
    ])
    if report.unverified:
        story.extend([
            PageBreak(),
            _p("Unverified observations", "title"),
            _p("Items requiring manual review; excluded from actionable risk totals", "subtitle"),
            _p(
                "These observations did not meet the report's demonstrated-evidence threshold. "
                "They are retained for follow-up without being presented as confirmed vulnerabilities."
            ),
        ])
        rows = [[
            _p("ID", "table_header"), _p("SEVERITY", "table_header"),
            _p("CONFIDENCE", "table_header"), _p("OBSERVATION", "table_header"),
        ]]
        for index, finding in enumerate(report.unverified, 1):
            rows.append([
                _p(f"U-{index:03d}", "table_bold"),
                _p(finding.severity.title(), "table"),
                _p(f"{finding.confidence}%", "table"),
                _p(finding.title, "table"),
            ])
        unverified_table = Table(
            rows,
            colWidths=[16 * mm, 25 * mm, 24 * mm, CONTENT_W - 65 * mm],
            repeatRows=1,
        )
        unverified_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), CHARCOAL),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#F8FAFC")]),
            ("GRID", (0, 0), (-1, -1), 0.45, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(unverified_table)
    return story


def generate_pentest_pdf(
    state: dict,
    output_path: Path | None = None,
    *,
    report: ReportContent | None = None,
) -> Path:
    """Create the complete branded PDF and return its filesystem path."""
    content = report or build_report_content(state)
    if output_path is None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S")
        output_path = REPORTS_DIR / f"pentest-{stamp}.pdf"
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    generated = datetime.now().astimezone()
    doc = BaseDocTemplate(
        str(output_path), pagesize=A4,
        title="SwarmAttacker Penetration Test Report",
        author="SwarmAttacker",
        subject=content.target,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=28 * mm, bottomMargin=18 * mm,
    )
    cover_frame = Frame(0, 0, PAGE_W, PAGE_H, leftPadding=0, rightPadding=0,
                        topPadding=0, bottomPadding=0, id="cover-frame")
    body_frame = Frame(
        MARGIN, 15 * mm, CONTENT_W, PAGE_H - 40 * mm,
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
        id="body-frame",
    )
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame]),
        PageTemplate(id="body", frames=[body_frame], onPage=_body_page),
    ])
    doc.build(_story(content, generated))
    return output_path


__all__ = ["generate_pentest_pdf"]
