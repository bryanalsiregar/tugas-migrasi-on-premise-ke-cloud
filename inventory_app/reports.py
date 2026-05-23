import html
import io
import textwrap

from .config import EXPORT_CONFIG, utc_now

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except ImportError:
    colors = None
    letter = None
    landscape = None
    ParagraphStyle = None
    getSampleStyleSheet = None
    inch = None
    Paragraph = None
    SimpleDocTemplate = None
    Table = None
    TableStyle = None

def pdf_escape(text):
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def format_export_value(key, value):
    if key == "is_active":
        return "Yes" if value else "No"
    if value is None:
        return ""
    return str(value)


def get_export_definition(entity):
    return EXPORT_CONFIG[entity]


def get_export_columns(entity):
    return get_export_definition(entity)["columns"]


def normalize_csv_row(entity, row):
    normalized = {}
    columns = get_export_columns(entity)
    for column in columns:
        key = column["key"]
        label = column["label"]
        value = row.get(key)
        if value is None:
            value = row.get(label)
        if value is None:
            value = row.get(label.lower())
        normalized[key] = value if value is not None else ""
    return normalized


def sync_asset_assignment_state(conn, asset_id):
    active_assignment = conn.execute(
        """
        SELECT ass.person_id, p.location
        FROM assignments ass
        JOIN people p ON p.id = ass.person_id
        WHERE ass.asset_id = ? AND ass.returned_at IS NULL
        ORDER BY ass.assigned_at DESC, ass.id DESC
        LIMIT 1
        """,
        (asset_id,),
    ).fetchone()

    asset = conn.execute(
        "SELECT status FROM assets WHERE id = ?",
        (asset_id,),
    ).fetchone()
    if not asset:
        return

    if active_assignment:
        conn.execute(
            """
            UPDATE assets
            SET status = 'Assigned', current_holder_id = ?, location = ?, updated_at = ?
            WHERE id = ?
            """,
            (active_assignment["person_id"], active_assignment["location"], utc_now(), asset_id),
        )
        return

    if asset["status"] == "Assigned":
        conn.execute(
            """
            UPDATE assets
            SET status = 'Available', current_holder_id = NULL, updated_at = ?
            WHERE id = ?
            """,
            (utc_now(), asset_id),
        )
    else:
        conn.execute(
            "UPDATE assets SET current_holder_id = NULL, updated_at = ? WHERE id = ?",
            (utc_now(), asset_id),
        )


def build_pretty_pdf(entity, title, columns, rows):
    if not SimpleDocTemplate:
        headers = [column["label"] for column in columns]
        simple_rows = []
        for row in rows:
            if isinstance(row, dict):
                simple_rows.append(
                    [
                        format_export_value(column["key"], row.get(column["key"], ""))
                        for column in columns
                    ]
                )
            else:
                simple_rows.append(row)
        return build_simple_pdf(title, headers, simple_rows)

    page_size = landscape(letter) if get_export_definition(entity)["landscape"] else letter
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=page_size,
        leftMargin=0.45 * inch,
        rightMargin=0.45 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = styles["Heading1"]
    title_style.textColor = colors.HexColor("#17324d")
    title_style.fontName = "Helvetica-Bold"
    title_style.fontSize = 18
    title_style.spaceAfter = 6

    meta_style = ParagraphStyle(
        "ReportMeta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#5b667a"),
        leading=12,
        spaceAfter=4,
    )

    cell_style = ParagraphStyle(
        "ReportCell",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#14213d"),
        wordWrap="CJK",
    )

    header_style = ParagraphStyle(
        "ReportHeader",
        parent=cell_style,
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )

    table_data = [[Paragraph(html.escape(column["label"]), header_style) for column in columns]]
    for row in rows:
        table_data.append(
            [
                Paragraph(html.escape(format_export_value(column["key"], row.get(column["key"], ""))), cell_style)
                for column in columns
            ]
        )

    if len(table_data) == 1:
        table_data.append([Paragraph("No records found.", cell_style)] + [""] * (len(columns) - 1))

    usable_width = document.width
    total_weight = sum(column.get("weight", 1) for column in columns) or 1
    col_widths = [(usable_width * column.get("weight", 1) / total_weight) for column in columns]

    table = Table(table_data, repeatRows=1, colWidths=col_widths)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e79")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d2dae6")),
                ("LINEBELOW", (0, 0), (-1, 0), 0.9, colors.HexColor("#17324d")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f5f8fc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story = [
        Paragraph(html.escape(title), title_style),
        Paragraph(html.escape(f"Generated {utc_now()}"), meta_style),
        Paragraph(html.escape(f"Total records: {len(rows)}"), meta_style),
        Spacer(1, 0.18 * inch),
        table,
    ]
    document.build(story)
    return output.getvalue()


def build_simple_pdf(title, headers, rows):
    max_widths = [18] * len(headers)
    for idx, header in enumerate(headers):
        max_widths[idx] = max(max_widths[idx], min(len(str(header)), 22))
    for row in rows:
        for idx, value in enumerate(row):
            max_widths[idx] = min(max(max_widths[idx], len(str(value or ""))), 22)

    def row_to_line(values):
        cells = []
        for idx, value in enumerate(values):
            text = str(value or "")
            text = textwrap.shorten(text, width=max_widths[idx], placeholder="...")
            cells.append(text.ljust(max_widths[idx]))
        return " | ".join(cells).rstrip()

    lines = [title, f"Generated {utc_now()}", ""]
    header_line = row_to_line(headers)
    separator = "-" * min(len(header_line), 110)
    lines.extend([header_line, separator])
    for row in rows:
        base = row_to_line(row)
        wrapped = textwrap.wrap(base, width=110, break_long_words=True, replace_whitespace=False) or [""]
        lines.extend(wrapped)
    lines_per_page = 48
    pages = [lines[i:i + lines_per_page] for i in range(0, len(lines), lines_per_page)] or [["No data"]]

    objects = []
    font_obj = 1
    pages_obj = 2
    next_obj = 3
    page_refs = []

    for page_lines in pages:
        commands = ["BT", "/F1 10 Tf", "14 TL", "40 800 Td"]
        for line in page_lines:
            commands.append(f"({pdf_escape(line)}) Tj")
            commands.append("T*")
        commands.append("ET")
        content = "\n".join(commands).encode("latin-1", errors="replace")
        content_obj = next_obj
        page_obj = next_obj + 1
        next_obj += 2
        objects.append((content_obj, f"<< /Length {len(content)} >>\nstream\n".encode("latin-1") + content + b"\nendstream"))
        objects.append((page_obj, f"<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 {font_obj} 0 R >> >> /Contents {content_obj} 0 R >>".encode("latin-1")))
        page_refs.append(f"{page_obj} 0 R")

    objects.insert(0, (font_obj, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))
    objects.insert(1, (pages_obj, f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>".encode("latin-1")))
    catalog_obj = next_obj
    objects.append((catalog_obj, f"<< /Type /Catalog /Pages {pages_obj} 0 R >>".encode("latin-1")))

    output = bytearray(b"%PDF-1.4\n")
    offsets = {0: 0}
    for obj_id, body in objects:
        offsets[obj_id] = len(output)
        output.extend(f"{obj_id} 0 obj\n".encode("latin-1"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {catalog_obj + 1}\n".encode("latin-1"))
    output.extend(b"0000000000 65535 f \n")
    for obj_id in range(1, catalog_obj + 1):
        output.extend(f"{offsets[obj_id]:010d} 00000 n \n".encode("latin-1"))
    output.extend(f"trailer\n<< /Size {catalog_obj + 1} /Root {catalog_obj} 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("latin-1"))
    return bytes(output)
