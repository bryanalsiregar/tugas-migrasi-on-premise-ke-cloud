import csv
import hashlib
import html
import hmac
import io
import json
import os
import secrets
import threading
import webbrowser
from email.message import Message
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

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

load_dotenv()

# Konfigurasi aplikasi dan global state
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:HIflocODzS4DeIk7@db.okqzgdwapqscptokeqnu.supabase.co:5432/postgres?sslmode=require",
)
HOST = os.environ.get("APP_HOST", "127.0.0.1")
PORT = int(os.environ.get("APP_PORT", "8000"))
APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

SESSIONS: dict = {}
SESSION_LOCK = threading.Lock()
BROWSER_OPENED = False
BROWSER_LOCK = threading.Lock()
_DB_READY = False
_DB_LOCK = threading.Lock()

LOOKUP_FIELD_MAP = {
    "category":        ("assets", "category"),
    "device_name":     ("assets", "device_name"),
    "brand":           ("assets", "brand"),
    "model":           ("assets", "model"),
    "location":        ("assets", "location"),
    "status":          ("assets", "status"),
    "condition":       ("assets", "condition"),
    "department":      ("people", "department"),
    "person_location": ("people", "location"),
    "role":            ("admin_users", "role"),
}

EXPORT_CONFIG = {
    "assets": {
        "title": "Assets Report", "landscape": True,
        "columns": [
            {"key": "asset_tag",     "label": "Asset Tag",    "weight": 1.0},
            {"key": "device_name",   "label": "Device",       "weight": 1.4},
            {"key": "category",      "label": "Category",     "weight": 1.0},
            {"key": "brand",         "label": "Brand",        "weight": 0.9},
            {"key": "model",         "label": "Model",        "weight": 1.1},
            {"key": "serial_number", "label": "Serial No.",   "weight": 1.2},
            {"key": "status",        "label": "Status",       "weight": 0.9},
            {"key": "condition",     "label": "Condition",    "weight": 0.9},
            {"key": "location",      "label": "Location",     "weight": 1.0},
            {"key": "visibility",    "label": "Visibility",   "weight": 0.8},
            {"key": "holder_name",   "label": "Assigned To",  "weight": 1.2},
        ],
    },
    "people": {
        "title": "Users Report", "landscape": False,
        "columns": [
            {"key": "full_name",  "label": "Full Name",   "weight": 1.3},
            {"key": "department", "label": "Department",  "weight": 1.0},
            {"key": "email",      "label": "Email",       "weight": 1.4},
            {"key": "phone",      "label": "Phone",       "weight": 0.9},
            {"key": "location",   "label": "Location",    "weight": 1.0},
            {"key": "notes",      "label": "Notes",       "weight": 1.4},
        ],
    },
    "admins": {
        "title": "Admin Users Report", "landscape": False,
        "columns": [
            {"key": "full_name",  "label": "Full Name",  "weight": 1.3},
            {"key": "username",   "label": "Username",   "weight": 1.0},
            {"key": "role",       "label": "Role",       "weight": 1.0},
            {"key": "is_active",  "label": "Active",     "weight": 0.7},
        ],
    },
    "assignments": {
        "title": "Assignments Report", "landscape": True,
        "columns": [
            {"key": "asset_tag",    "label": "Asset Tag",       "weight": 1.0},
            {"key": "person_name",  "label": "Assigned To",     "weight": 1.2},
            {"key": "admin_name",   "label": "Assigned By",     "weight": 1.1},
            {"key": "assigned_at",  "label": "Assigned At",     "weight": 1.0},
            {"key": "returned_at",  "label": "Returned At",     "weight": 1.0},
            {"key": "notes",        "label": "Check-out Notes", "weight": 1.4},
            {"key": "return_notes", "label": "Check-in Notes",  "weight": 1.4},
        ],
    },
}


# Helper Functions
def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    """Buka koneksi PostgreSQL dengan RealDictCursor agar kolom bisa diakses via nama."""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn


def hash_password(password: str, salt: str = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 120000
    ).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, digest = stored.split("$", 1)
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 120000
    ).hex()
    return hmac.compare_digest(candidate, digest)


def json_response(handler, payload: dict, status=HTTPStatus.OK):
    body = json.dumps(payload, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def error_response(handler, message: str, status=HTTPStatus.BAD_REQUEST):
    json_response(handler, {"error": message}, status=status)


def parse_json(handler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    return json.loads(raw.decode("utf-8")) if raw else {}


def require_fields(data: dict, fields: list):
    missing = [f for f in fields if not str(data.get(f, "")).strip()]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")


def admin_dict(row) -> dict | None:
    if not row:
        return None
    data = dict(row)
    data.pop("password_hash", None)
    data["is_active"] = bool(data.get("is_active"))
    return data


def role_name(user) -> str:
    if not user:
        return ""
    return str(user.get("role") or "").strip()


def is_admin_role(user) -> bool:
    return role_name(user) in {"Super Admin", "Admin"}


def require_admin_role(handler, user) -> bool:
    if not is_admin_role(user):
        error_response(handler, "Admin access required", HTTPStatus.FORBIDDEN)
        return False
    return True


def get_export_definition(entity: str) -> dict:
    return EXPORT_CONFIG[entity]


def get_export_columns(entity: str) -> list:
    return get_export_definition(entity)["columns"]


def format_export_value(key: str, value) -> str:
    if key == "is_active":
        return "Yes" if value else "No"
    if value is None:
        return ""
    return str(value)


def normalize_csv_row(entity: str, row: dict) -> dict:
    normalized = {}
    for col in get_export_columns(entity):
        key, label = col["key"], col["label"]
        val = row.get(key) or row.get(label) or row.get(label.lower()) or ""
        normalized[key] = val
    return normalized


def app_url() -> str:
    return f"http://{HOST}:{PORT}"


def open_browser_once():
    global BROWSER_OPENED
    with BROWSER_LOCK:
        if BROWSER_OPENED:
            return
        BROWSER_OPENED = True
    threading.Timer(1.0, lambda: webbrowser.open(app_url())).start()


def ensure_db_ready():
    global _DB_READY
    if _DB_READY:
        return
    with _DB_LOCK:
        if _DB_READY:
            return
        init_db()
        _DB_READY = True


# Sync Lookup with PostgreSQL
def sync_lookup(conn, kind: str, value):
    value = str(value or "").strip()
    if not value:
        return
    now = utc_now()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO lookup_values (kind, value, created_at, updated_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (kind, value) DO UPDATE
                SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
            """,
            (kind, value, now, now),
        )


def lookup_usage_count(conn, kind: str, value: str) -> int:
    table, field = LOOKUP_FIELD_MAP[kind]
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {field} = %s", (value,))
        row = cur.fetchone()
        return list(row.values())[0] if row else 0


def sync_asset_assignment_state(conn, asset_id):
    """Update status & current_holder_id aset berdasarkan assignment aktif."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT ass.person_id, p.location
            FROM assignments ass
            JOIN people p ON p.id = ass.person_id
            WHERE ass.asset_id = %s AND ass.returned_at IS NULL
            ORDER BY ass.assigned_at DESC, ass.id DESC
            LIMIT 1
            """,
            (asset_id,),
        )
        active_assignment = cur.fetchone()

        cur.execute("SELECT status FROM assets WHERE id = %s", (asset_id,))
        asset = cur.fetchone()
        if not asset:
            return

        if active_assignment:
            cur.execute(
                """
                UPDATE assets
                SET status = 'Assigned', current_holder_id = %s, location = %s, updated_at = %s
                WHERE id = %s
                """,
                (active_assignment["person_id"], active_assignment["location"], utc_now(), asset_id),
            )
        elif asset["status"] == "Assigned":
            cur.execute(
                """
                UPDATE assets
                SET status = 'Available', current_holder_id = NULL, updated_at = %s
                WHERE id = %s
                """,
                (utc_now(), asset_id),
            )
        else:
            cur.execute(
                "UPDATE assets SET current_holder_id = NULL, updated_at = %s WHERE id = %s",
                (utc_now(), asset_id),
            )


# PDF Helpers
def build_pretty_pdf(entity, title, columns, rows):
    if not SimpleDocTemplate:
        return build_simple_pdf(title, [c["label"] for c in columns], rows)

    page_size = landscape(letter) if get_export_definition(entity)["landscape"] else letter
    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output, pagesize=page_size,
        leftMargin=0.45 * inch, rightMargin=0.45 * inch,
        topMargin=0.5 * inch, bottomMargin=0.5 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = styles["Heading1"]
    title_style.textColor = colors.HexColor("#17324d")
    title_style.fontName = "Helvetica-Bold"
    title_style.fontSize = 18
    title_style.spaceAfter = 6

    meta_style = ParagraphStyle(
        "ReportMeta", parent=styles["Normal"],
        fontName="Helvetica", fontSize=9,
        textColor=colors.HexColor("#5b667a"), leading=12, spaceAfter=4,
    )
    cell_style = ParagraphStyle(
        "ReportCell", parent=styles["BodyText"],
        fontName="Helvetica", fontSize=8, leading=10,
        textColor=colors.HexColor("#14213d"), wordWrap="CJK",
    )
    header_style = ParagraphStyle(
        "ReportHeader", parent=cell_style,
        fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white,
    )

    table_data = [[Paragraph(html.escape(c["label"]), header_style) for c in columns]]
    for row in rows:
        table_data.append([
            Paragraph(html.escape(format_export_value(c["key"], row.get(c["key"], ""))), cell_style)
            for c in columns
        ])
    if len(table_data) == 1:
        table_data.append([Paragraph("No records found.", cell_style)] + [""] * (len(columns) - 1))

    usable_width = doc.width
    total_weight = sum(c.get("weight", 1) for c in columns) or 1
    col_widths = [(usable_width * c.get("weight", 1) / total_weight) for c in columns]

    tbl = Table(table_data, repeatRows=1, colWidths=col_widths)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e79")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d2dae6")),
        ("LINEBELOW", (0, 0), (-1, 0), 0.9, colors.HexColor("#17324d")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f5f8fc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    doc.build([
        Paragraph(html.escape(title), title_style),
        Paragraph(html.escape(f"Generated {utc_now()}"), meta_style),
        Paragraph(html.escape(f"Total records: {len(rows)}"), meta_style),
        Spacer(1, 0.18 * inch), tbl,
    ])
    return output.getvalue()


def build_simple_pdf(title, headers, rows):
    lines = [f"--- {title} ---", f"Generated: {utc_now()}", ""]
    lines.append("  ".join(h[:18].ljust(18) for h in headers))
    lines.append("-" * (20 * len(headers)))
    for row in rows:
        lines.append("  ".join(str(row.get(h, ""))[:18].ljust(18) for h in headers))
    text = "\n".join(lines)
    return text.encode("utf-8")


# Database Initialization
def init_db():
    """Pastikan tabel sudah ada dan ada minimal 1 Super Admin."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Tabel assignments (tidak ada di migration_rev.sql, tapi dibutuhkan app)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS assignments (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    person_id UUID NOT NULL REFERENCES people(id) ON DELETE CASCADE,
                    assigned_by_admin_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
                    assigned_at TIMESTAMPTZ DEFAULT NOW(),
                    returned_at TIMESTAMPTZ,
                    return_notes TEXT,
                    notes TEXT
                )
            """)

            # Seed Super Admin jika belum ada
            cur.execute("SELECT COUNT(*) FROM admin_users")
            count = list(cur.fetchone().values())[0]
            if count == 0:
                now = utc_now()
                cur.execute(
                    """
                    INSERT INTO admin_users (full_name, username, password_hash, role, is_active, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, true, %s, %s)
                    """,
                    ("System Administrator", "admin", hash_password("admin"), "Super Admin", now, now),
                )

        conn.commit()
    finally:
        conn.close()


# HTTP Handler
class InventoryHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path

        if p == "/api/session":
            return self.handle_session()
        if p == "/api/dashboard":
            return self.authenticated(self.handle_dashboard)
        if p == "/api/assets":
            return self.authenticated(self.handle_assets_list)
        if p == "/api/people":
            return self.authenticated(self.handle_people_list)
        if p == "/api/admin-users":
            return self.authenticated(self.handle_admin_list)
        if p == "/api/assignments":
            return self.authenticated(self.handle_assignments_list)
        if p == "/api/lookups":
            return self.authenticated(self.handle_lookup_list)
        if p == "/api/export/csv":
            return self.authenticated(self.handle_export_csv)
        if p == "/api/export/pdf":
            return self.authenticated(self.handle_export_pdf)
        if p == "/api/report":
            return self.authenticated(self.handle_report_page)
        return self.serve_static(p)

    def do_POST(self):
        parsed = urlparse(self.path)
        p = parsed.path

        if p == "/api/login":
            return self.handle_login()
        if p == "/api/logout":
            return self.handle_logout()
        if p == "/api/assets":
            return self.authenticated(self.handle_asset_create)
        if p == "/api/people":
            return self.authenticated(self.handle_person_create)
        if p == "/api/admin-users":
            return self.authenticated(self.handle_admin_create)
        if p == "/api/assignments/assign":
            return self.authenticated(self.handle_assign_asset)
        if p == "/api/assignments/return":
            return self.authenticated(self.handle_return_asset)
        if p == "/api/lookups":
            return self.authenticated(self.handle_lookup_create)
        if p == "/api/import/csv":
            return self.authenticated(self.handle_import_csv)
        if p == "/api/change-password":
            return self.authenticated(self.handle_change_own_password)
        return error_response(self, "Route not found", HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        parsed = urlparse(self.path)
        p = parsed.path

        if p.startswith("/api/assets/"):
            return self.authenticated(self.handle_asset_update)
        if p.startswith("/api/people/"):
            return self.authenticated(self.handle_person_update)
        if p.startswith("/api/admin-users/"):
            return self.authenticated(self.handle_admin_update)
        if p.startswith("/api/lookups/"):
            return self.authenticated(self.handle_lookup_update)
        return error_response(self, "Route not found", HTTPStatus.NOT_FOUND)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        p = parsed.path

        if p.startswith("/api/assets/"):
            return self.authenticated(self.handle_asset_delete)
        if p.startswith("/api/people/"):
            return self.authenticated(self.handle_person_delete)
        if p.startswith("/api/admin-users/"):
            return self.authenticated(self.handle_admin_delete)
        if p.startswith("/api/lookups/"):
            return self.authenticated(self.handle_lookup_delete)
        return error_response(self, "Route not found", HTTPStatus.NOT_FOUND)

    def log_message(self, format, *args):
        return  # suppress request logs

    # Auth helpers
    def authenticated(self, callback):
        user = self.current_user()
        if not user:
            return error_response(self, "Authentication required", HTTPStatus.UNAUTHORIZED)
        return callback(user)

    def current_user(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get("session_id")
        if not morsel:
            return None
        with SESSION_LOCK:
            user_id = SESSIONS.get(morsel.value)
        if not user_id:
            return None
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM admin_users WHERE id = %s AND is_active = true", (user_id,)
                )
                user = cur.fetchone()
        finally:
            conn.close()
        return dict(user) if user else None

    def set_session(self, user_id):
        session_id = secrets.token_urlsafe(32)
        with SESSION_LOCK:
            SESSIONS[session_id] = str(user_id)
        self.send_header(
            "Set-Cookie",
            f"session_id={session_id}; HttpOnly; Path=/; SameSite=Lax",
        )

    def clear_session(self):
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            morsel = cookie.get("session_id")
            if morsel:
                with SESSION_LOCK:
                    SESSIONS.pop(morsel.value, None)
        self.send_header("Set-Cookie", "session_id=; Max-Age=0; Path=/; SameSite=Lax")

    # Auth handlers
    def handle_login(self):
        try:
            data = parse_json(self)
            require_fields(data, ["username", "password"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM admin_users WHERE username = %s AND is_active = true",
                    (data["username"].strip(),),
                )
                user = cur.fetchone()
        finally:
            conn.close()

        if not user or not verify_password(data["password"], user["password_hash"]):
            return error_response(self, "Invalid username or password", HTTPStatus.UNAUTHORIZED)

        body = json.dumps({"user": admin_dict(user)}, default=str).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.set_session(user["id"])
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_logout(self):
        body = json.dumps({"success": True}).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.clear_session()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_session(self):
        json_response(self, {"user": admin_dict(self.current_user())})

    # Dashboard 
    def handle_dashboard(self, user):
        conn = get_db()
        try:
            with conn.cursor() as cur:
                def count(sql, *args):
                    cur.execute(sql, args)
                    return list(cur.fetchone().values())[0]

                stats = {
                    "assets_total":       count("SELECT COUNT(*) FROM assets"),
                    "assets_assigned":    count("SELECT COUNT(*) FROM assets WHERE status = 'Assigned'"),
                    "assets_available":   count("SELECT COUNT(*) FROM assets WHERE status = 'Available'"),
                    "assets_maintenance": count("SELECT COUNT(*) FROM assets WHERE status = 'Maintenance'"),
                    "people_total":       count("SELECT COUNT(*) FROM people"),
                    "admins_total":       count("SELECT COUNT(*) FROM admin_users WHERE is_active = true"),
                }

                cur.execute("""
                    SELECT a.id, a.asset_tag, a.device_name, a.status, p.full_name AS holder_name
                    FROM assets a
                    LEFT JOIN people p ON p.id = a.current_holder_id
                    ORDER BY a.updated_at DESC
                    LIMIT 5
                """)
                recent_assets = [dict(r) for r in cur.fetchall()]

                cur.execute("""
                    SELECT ass.id, a.asset_tag, p.full_name, ass.assigned_at, ass.returned_at
                    FROM assignments ass
                    JOIN assets a ON a.id = ass.asset_id
                    JOIN people p ON p.id = ass.person_id
                    ORDER BY COALESCE(ass.returned_at, ass.assigned_at) DESC
                    LIMIT 8
                """)
                recent_activity = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        json_response(self, {
            "stats": stats,
            "recent_assets": recent_assets,
            "recent_activity": recent_activity,
            "user": admin_dict(user),
        })

    # Assets
    def handle_assets_list(self, user):
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT a.*, p.full_name AS holder_name
                    FROM assets a
                    LEFT JOIN people p ON p.id = a.current_holder_id
                    ORDER BY a.updated_at DESC, a.id DESC
                """)
                rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
        json_response(self, {"items": rows})

    def handle_asset_create(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["asset_tag", "device_name", "category", "status", "condition"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        now = utc_now()
        visibility = data.get("visibility", "public").strip() or "public"
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO assets (
                        asset_tag, device_name, category, brand, model, serial_number,
                        status, condition, location, visibility, current_holder_id,
                        added_by_id, created_at, updated_at
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                    """,
                    (
                        data["asset_tag"].strip(),
                        data["device_name"].strip(),
                        data["category"].strip(),
                        data.get("brand", "").strip() or None,
                        data.get("model", "").strip() or None,
                        data.get("serial_number", "").strip() or None,
                        data["status"].strip(),
                        data["condition"].strip(),
                        data.get("location", "").strip() or None,
                        visibility,
                        data.get("current_holder_id") or None,
                        str(user["id"]),
                        now, now,
                    ),
                )
                new_id = cur.fetchone()["id"]
                for kind in ["category", "device_name", "brand", "model", "location", "status", "condition"]:
                    sync_lookup(conn, kind, data.get(kind) or data.get(kind.replace("_", ""), ""))

                cur.execute("""
                    SELECT a.*, p.full_name AS holder_name
                    FROM assets a LEFT JOIN people p ON p.id = a.current_holder_id
                    WHERE a.id = %s
                """, (new_id,))
                row = dict(cur.fetchone())
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            conn.close()
            return error_response(self, "Asset tag must be unique")
        finally:
            conn.close()
        json_response(self, {"item": row}, HTTPStatus.CREATED)

    def handle_asset_update(self, user):
        asset_id = self.path.rsplit("/", 1)[-1]
        try:
            data = parse_json(self)
            require_fields(data, ["asset_tag", "device_name", "category", "status", "condition"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        visibility = data.get("visibility", "public").strip() or "public"
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE assets
                    SET asset_tag=%s, device_name=%s, category=%s, brand=%s, model=%s,
                        serial_number=%s, status=%s, condition=%s, location=%s,
                        visibility=%s, current_holder_id=%s, updated_at=%s
                    WHERE id=%s
                    """,
                    (
                        data["asset_tag"].strip(),
                        data["device_name"].strip(),
                        data["category"].strip(),
                        data.get("brand", "").strip() or None,
                        data.get("model", "").strip() or None,
                        data.get("serial_number", "").strip() or None,
                        data["status"].strip(),
                        data["condition"].strip(),
                        data.get("location", "").strip() or None,
                        visibility,
                        data.get("current_holder_id") or None,
                        utc_now(),
                        asset_id,
                    ),
                )
                if cur.rowcount == 0:
                    conn.rollback()
                    conn.close()
                    return error_response(self, "Asset not found", HTTPStatus.NOT_FOUND)

                for kind in ["category", "device_name", "brand", "model", "location", "status", "condition"]:
                    sync_lookup(conn, kind, data.get(kind) or "")

                cur.execute("""
                    SELECT a.*, p.full_name AS holder_name
                    FROM assets a LEFT JOIN people p ON p.id = a.current_holder_id
                    WHERE a.id = %s
                """, (asset_id,))
                row = dict(cur.fetchone())
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            conn.close()
            return error_response(self, "Asset tag must be unique")
        finally:
            conn.close()
        json_response(self, {"item": row})

    def handle_asset_delete(self, user):
        asset_id = self.path.rsplit("/", 1)[-1]
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM assignments WHERE asset_id = %s AND returned_at IS NULL", (asset_id,)
                )
                if cur.fetchone():
                    conn.close()
                    return error_response(self, "Return the asset before deleting it")
                cur.execute("DELETE FROM assets WHERE id = %s", (asset_id,))
                if cur.rowcount == 0:
                    conn.close()
                    return error_response(self, "Asset not found", HTTPStatus.NOT_FOUND)
            conn.commit()
        finally:
            conn.close()
        json_response(self, {"success": True})

    # People
    def handle_people_list(self, user):
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT p.*,
                        (SELECT COUNT(*) FROM assets a WHERE a.current_holder_id = p.id) AS assigned_assets
                    FROM people p
                    ORDER BY p.updated_at DESC, p.id DESC
                """)
                rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
        json_response(self, {"items": rows})

    def handle_person_create(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["full_name", "department"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        now = utc_now()
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO people (full_name, department, email, phone, location, notes, created_at, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                    """,
                    (
                        data["full_name"].strip(),
                        data["department"].strip(),
                        data.get("email", "").strip() or None,
                        data.get("phone", "").strip() or None,
                        data.get("location", "").strip() or None,
                        data.get("notes", "").strip() or None,
                        now, now,
                    ),
                )
                new_id = cur.fetchone()["id"]
                sync_lookup(conn, "department", data["department"])
                sync_lookup(conn, "person_location", data.get("location"))

                cur.execute("""
                    SELECT p.*, (SELECT COUNT(*) FROM assets a WHERE a.current_holder_id = p.id) AS assigned_assets
                    FROM people p WHERE p.id = %s
                """, (new_id,))
                row = dict(cur.fetchone())
            conn.commit()
        finally:
            conn.close()
        json_response(self, {"item": row}, HTTPStatus.CREATED)

    def handle_person_update(self, user):
        person_id = self.path.rsplit("/", 1)[-1]
        try:
            data = parse_json(self)
            require_fields(data, ["full_name", "department"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE people
                    SET full_name=%s, department=%s, email=%s, phone=%s, location=%s, notes=%s, updated_at=%s
                    WHERE id=%s
                    """,
                    (
                        data["full_name"].strip(),
                        data["department"].strip(),
                        data.get("email", "").strip() or None,
                        data.get("phone", "").strip() or None,
                        data.get("location", "").strip() or None,
                        data.get("notes", "").strip() or None,
                        utc_now(), person_id,
                    ),
                )
                if cur.rowcount == 0:
                    conn.close()
                    return error_response(self, "Person not found", HTTPStatus.NOT_FOUND)

                sync_lookup(conn, "department", data["department"])
                sync_lookup(conn, "person_location", data.get("location"))

                cur.execute("""
                    SELECT p.*, (SELECT COUNT(*) FROM assets a WHERE a.current_holder_id = p.id) AS assigned_assets
                    FROM people p WHERE p.id = %s
                """, (person_id,))
                row = dict(cur.fetchone())
            conn.commit()
        finally:
            conn.close()
        json_response(self, {"item": row})

    def handle_person_delete(self, user):
        person_id = self.path.rsplit("/", 1)[-1]
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM assets WHERE current_holder_id = %s", (person_id,))
                if cur.fetchone():
                    conn.close()
                    return error_response(self, "Reassign or return assets before deleting this profile")
                cur.execute("DELETE FROM people WHERE id = %s", (person_id,))
                if cur.rowcount == 0:
                    conn.close()
                    return error_response(self, "Person not found", HTTPStatus.NOT_FOUND)
            conn.commit()
        finally:
            conn.close()
        json_response(self, {"success": True})

    # Admin Users 
    def handle_admin_list(self, user):
        if not require_admin_role(self, user):
            return
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM admin_users ORDER BY updated_at DESC, id DESC")
                rows = [admin_dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
        json_response(self, {"items": rows})

    def handle_admin_create(self, user):
        if not require_admin_role(self, user):
            return
        try:
            data = parse_json(self)
            require_fields(data, ["full_name", "username", "password"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        now = utc_now()
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO admin_users (full_name, username, password_hash, role, is_active, created_at, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                    """,
                    (
                        data["full_name"].strip(),
                        data["username"].strip(),
                        hash_password(data["password"]),
                        data.get("role", "Admin").strip() or "Admin",
                        bool(data.get("is_active", True)),
                        now, now,
                    ),
                )
                new_id = cur.fetchone()["id"]
                sync_lookup(conn, "role", data.get("role", "Admin"))

                cur.execute("SELECT * FROM admin_users WHERE id = %s", (new_id,))
                row = admin_dict(cur.fetchone())
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            conn.close()
            return error_response(self, "Username already exists")
        finally:
            conn.close()
        json_response(self, {"item": row}, HTTPStatus.CREATED)

    def handle_admin_update(self, user):
        admin_id = self.path.rsplit("/", 1)[-1]
        if not require_admin_role(self, user):
            return
        try:
            data = parse_json(self)
            require_fields(data, ["full_name", "username"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM admin_users WHERE id = %s", (admin_id,))
                existing = cur.fetchone()
                if not existing:
                    conn.close()
                    return error_response(self, "Admin user not found", HTTPStatus.NOT_FOUND)

                password_hash = existing["password_hash"]
                if str(data.get("password", "")).strip():
                    password_hash = hash_password(data["password"])

                cur.execute(
                    """
                    UPDATE admin_users
                    SET full_name=%s, username=%s, password_hash=%s, role=%s, is_active=%s, updated_at=%s
                    WHERE id=%s
                    """,
                    (
                        data["full_name"].strip(),
                        data["username"].strip(),
                        password_hash,
                        data.get("role", "Admin").strip() or "Admin",
                        bool(data.get("is_active", True)),
                        utc_now(), admin_id,
                    ),
                )
                sync_lookup(conn, "role", data.get("role", "Admin"))

                cur.execute("SELECT * FROM admin_users WHERE id = %s", (admin_id,))
                row = admin_dict(cur.fetchone())
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            conn.close()
            return error_response(self, "Username already exists")
        finally:
            conn.close()
        json_response(self, {"item": row})

    def handle_admin_delete(self, user):
        if not require_admin_role(self, user):
            return
        admin_id = self.path.rsplit("/", 1)[-1]
        if str(admin_id) == str(user["id"]):
            return error_response(self, "You cannot delete your own logged-in account")

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM admin_users WHERE id = %s", (admin_id,))
                if cur.rowcount == 0:
                    conn.close()
                    return error_response(self, "Admin user not found", HTTPStatus.NOT_FOUND)
            conn.commit()
        finally:
            conn.close()
        json_response(self, {"success": True})

    def handle_change_own_password(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["current_password", "new_password"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        if len(str(data["new_password"])) < 6:
            return error_response(self, "New password must be at least 6 characters long")
        if not verify_password(data["current_password"], user["password_hash"]):
            return error_response(self, "Current password is incorrect", HTTPStatus.UNAUTHORIZED)

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE admin_users SET password_hash=%s, updated_at=%s WHERE id=%s",
                    (hash_password(data["new_password"]), utc_now(), user["id"]),
                )
                cur.execute("SELECT * FROM admin_users WHERE id = %s", (user["id"],))
                row = admin_dict(cur.fetchone())
            conn.commit()
        finally:
            conn.close()
        json_response(self, {"success": True, "user": row})

    # Assignments 
    def handle_assignments_list(self, user):
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT ass.id, ass.asset_id, ass.person_id, ass.assigned_at, ass.returned_at,
                           ass.notes, ass.return_notes,
                           a.asset_tag, a.device_name, p.full_name AS person_name, ad.full_name AS admin_name
                    FROM assignments ass
                    JOIN assets a ON a.id = ass.asset_id
                    JOIN people p ON p.id = ass.person_id
                    JOIN admin_users ad ON ad.id = ass.assigned_by_admin_id
                    ORDER BY ass.assigned_at DESC
                """)
                rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
        json_response(self, {"items": rows})

    def handle_assign_asset(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["asset_id", "person_id"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM assets WHERE id = %s", (data["asset_id"],))
                asset = cur.fetchone()
                if not asset:
                    conn.close()
                    return error_response(self, "Asset not found", HTTPStatus.NOT_FOUND)
                if asset["status"] == "Assigned":
                    conn.close()
                    return error_response(self, "Asset is already assigned")

                cur.execute("SELECT * FROM people WHERE id = %s", (data["person_id"],))
                person = cur.fetchone()
                if not person:
                    conn.close()
                    return error_response(self, "Person not found", HTTPStatus.NOT_FOUND)

                now = utc_now()
                cur.execute(
                    """
                    INSERT INTO assignments (asset_id, person_id, assigned_by_admin_id, assigned_at, notes)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (data["asset_id"], data["person_id"], str(user["id"]), now, data.get("notes", "").strip() or None),
                )
                cur.execute(
                    """
                    UPDATE assets
                    SET status = 'Assigned', current_holder_id = %s, location = %s, updated_at = %s
                    WHERE id = %s
                    """,
                    (data["person_id"], person["location"], now, data["asset_id"]),
                )
            conn.commit()
        finally:
            conn.close()
        json_response(self, {"success": True})

    def handle_return_asset(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["asset_id"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT * FROM assignments
                    WHERE asset_id = %s AND returned_at IS NULL
                    ORDER BY assigned_at DESC LIMIT 1
                    """,
                    (data["asset_id"],),
                )
                assignment = cur.fetchone()
                if not assignment:
                    conn.close()
                    return error_response(self, "No active assignment found for this asset")

                now = utc_now()
                cur.execute(
                    "UPDATE assignments SET returned_at=%s, return_notes=%s WHERE id=%s",
                    (now, data.get("return_notes", "").strip() or None, assignment["id"]),
                )
                cur.execute(
                    "UPDATE assets SET status='Available', current_holder_id=NULL, updated_at=%s WHERE id=%s",
                    (now, data["asset_id"]),
                )
            conn.commit()
        finally:
            conn.close()
        json_response(self, {"success": True})

    # Lookups
    def handle_lookup_list(self, user):
        parsed = urlparse(self.path)
        requested_kind = parse_qs(parsed.query).get("kind", [None])[0]

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, kind, value, created_at, updated_at
                    FROM lookup_values
                    ORDER BY kind, value
                """)
                items = []
                for row in cur.fetchall():
                    item = dict(row)
                    item["usage_count"] = lookup_usage_count(conn, item["kind"], item["value"])
                    if not requested_kind or item["kind"] == requested_kind:
                        items.append(item)
        finally:
            conn.close()
        json_response(self, {"items": items})

    def handle_lookup_create(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["kind", "value"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        if data["kind"] not in LOOKUP_FIELD_MAP:
            return error_response(self, "Unsupported lookup type")

        conn = get_db()
        try:
            with conn.cursor() as cur:
                sync_lookup(conn, data["kind"], data["value"])
                cur.execute(
                    """
                    SELECT id, kind, value, created_at, updated_at
                    FROM lookup_values
                    WHERE kind = %s AND lower(value) = lower(%s)
                    """,
                    (data["kind"], data["value"].strip()),
                )
                item = dict(cur.fetchone())
                item["usage_count"] = lookup_usage_count(conn, item["kind"], item["value"])
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            conn.close()
            return error_response(self, "Keyword already exists")
        finally:
            conn.close()
        json_response(self, {"item": item}, HTTPStatus.CREATED)

    def handle_lookup_update(self, user):
        lookup_id = self.path.rsplit("/", 1)[-1]
        try:
            data = parse_json(self)
            require_fields(data, ["value"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM lookup_values WHERE id = %s", (lookup_id,))
                existing = cur.fetchone()
                if not existing:
                    conn.close()
                    return error_response(self, "Keyword not found", HTTPStatus.NOT_FOUND)

                table, field = LOOKUP_FIELD_MAP[existing["kind"]]
                cur.execute(
                    f"UPDATE {table} SET {field} = %s, updated_at = %s WHERE {field} = %s",
                    (data["value"].strip(), utc_now(), existing["value"]),
                )
                cur.execute(
                    "UPDATE lookup_values SET value = %s, updated_at = %s WHERE id = %s",
                    (data["value"].strip(), utc_now(), lookup_id),
                )
                cur.execute("SELECT id, kind, value, created_at, updated_at FROM lookup_values WHERE id = %s", (lookup_id,))
                item = dict(cur.fetchone())
                item["usage_count"] = lookup_usage_count(conn, item["kind"], item["value"])
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            conn.close()
            return error_response(self, "Keyword already exists")
        finally:
            conn.close()
        json_response(self, {"item": item})

    def handle_lookup_delete(self, user):
        lookup_id = self.path.rsplit("/", 1)[-1]
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM lookup_values WHERE id = %s", (lookup_id,))
                existing = cur.fetchone()
                if not existing:
                    conn.close()
                    return error_response(self, "Keyword not found", HTTPStatus.NOT_FOUND)

                usage_count = lookup_usage_count(conn, existing["kind"], existing["value"])
                if usage_count:
                    conn.close()
                    return error_response(self, "Update matching assets before deleting this keyword")

                cur.execute("DELETE FROM lookup_values WHERE id = %s", (lookup_id,))
            conn.commit()
        finally:
            conn.close()
        json_response(self, {"success": True})

    # Export Import
    def get_export_rows(self, entity):
        conn = get_db()
        try:
            with conn.cursor() as cur:
                if entity == "assets":
                    cur.execute("""
                        SELECT a.*, p.full_name AS holder_name
                        FROM assets a
                        LEFT JOIN people p ON p.id = a.current_holder_id
                        ORDER BY a.id
                    """)
                elif entity == "people":
                    cur.execute("SELECT * FROM people ORDER BY id")
                elif entity == "admins":
                    cur.execute("SELECT * FROM admin_users ORDER BY id")
                    return [admin_dict(r) for r in cur.fetchall()]
                else:
                    cur.execute("""
                        SELECT a.asset_tag, p.full_name AS person_name, ad.full_name AS admin_name,
                               ass.assigned_at, ass.returned_at, ass.notes, ass.return_notes
                        FROM assignments ass
                        JOIN assets a ON a.id = ass.asset_id
                        JOIN people p ON p.id = ass.person_id
                        JOIN admin_users ad ON ad.id = ass.assigned_by_admin_id
                        ORDER BY ass.assigned_at
                    """)
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def get_report_definition(self, entity):
        rows = self.get_export_rows(entity)
        definition = get_export_definition(entity)
        return definition["title"], definition["columns"], rows

    def handle_export_csv(self, user):
        entity = parse_qs(urlparse(self.path).query).get("entity", ["assets"])[0]
        if entity not in {"assets", "people", "admins", "assignments"}:
            return error_response(self, "Unsupported export type")

        rows = self.get_export_rows(entity)
        columns = get_export_columns(entity)
        headers = [c["label"] for c in columns]

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                c["label"]: format_export_value(c["key"], row.get(c["key"], ""))
                for c in columns
            })
        body = output.getvalue().encode("utf-8-sig")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{entity}.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_export_pdf(self, user):
        entity = parse_qs(urlparse(self.path).query).get("entity", ["assets"])[0]
        if entity not in {"assets", "people", "admins", "assignments"}:
            return error_response(self, "Unsupported export type")
        title, columns, report_rows = self.get_report_definition(entity)
        pdf_bytes = build_pretty_pdf(entity, title, columns, report_rows)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{entity}.pdf"')
        self.send_header("Content-Length", str(len(pdf_bytes)))
        self.end_headers()
        self.wfile.write(pdf_bytes)

    def handle_report_page(self, user):
        entity = parse_qs(urlparse(self.path).query).get("entity", ["assets"])[0]
        if entity not in {"assets", "people", "admins", "assignments"}:
            return error_response(self, "Unsupported report type")
        title, columns, report_rows = self.get_report_definition(entity)
        table_html = "".join(
            "<tr>" + "".join(
                f"<td>{html.escape(format_export_value(c['key'], row.get(c['key'], '')))}</td>"
                for c in columns
            ) + "</tr>"
            for row in report_rows
        )
        body = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>
body{{font-family:Segoe UI,sans-serif;padding:28px;color:#14213d;background:#f4f7fb}}
.sheet{{background:#fff;border:1px solid #d7deea;border-radius:18px;padding:28px;box-shadow:0 12px 30px rgba(20,33,61,.08)}}
h1{{margin:0 0 6px;font-size:28px}} p{{color:#5c677d;margin:4px 0}}
table{{width:100%;border-collapse:collapse;margin-top:22px;font-size:14px}}
th,td{{border:1px solid #d4d9e2;padding:10px 12px;text-align:left;vertical-align:top;word-break:break-word}}
th{{background:#1f4e79;color:#fff}} tbody tr:nth-child(even){{background:#f5f8fc}}
@media print{{body{{padding:0;background:#fff}} .sheet{{border:none;box-shadow:none;padding:0}}}}
</style></head><body>
<div class="sheet">
<h1>{html.escape(title)}</h1>
<p>Generated {html.escape(utc_now())}</p>
<p>Total records: {len(report_rows)}</p>
<table><thead><tr>{"".join(f"<th>{html.escape(c['label'])}</th>" for c in columns)}</tr></thead>
<tbody>{table_html}</tbody></table>
</div></body></html>"""
        payload = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def handle_import_csv(self, user):
        entity = parse_qs(urlparse(self.path).query).get("entity", ["assets"])[0]
        if entity not in {"assets", "people", "admins", "assignments"}:
            return error_response(self, "Unsupported import type")
        try:
            data = parse_json(self)
            require_fields(data, ["csv_text"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))
        try:
            imported = self.import_rows(entity, data["csv_text"])
        except ValueError as exc:
            return error_response(self, str(exc))
        json_response(self, {"success": True, "imported": imported})

    def import_rows(self, entity, csv_text):
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = [normalize_csv_row(entity, row) for row in reader]
        if not rows:
            raise ValueError("CSV file is empty")

        conn = get_db()
        imported = 0
        now = utc_now()
        try:
            with conn.cursor() as cur:
                if entity == "assets":
                    for row in rows:
                        require_fields(row, ["asset_tag", "device_name", "category", "status", "condition"])
                        holder_name = str(row.get("holder_name", "")).strip()
                        holder_id = None
                        if holder_name:
                            cur.execute("SELECT id FROM people WHERE full_name = %s", (holder_name,))
                            h = cur.fetchone()
                            holder_id = h["id"] if h else None
                        cur.execute(
                            """
                            INSERT INTO assets (asset_tag, device_name, category, brand, model, serial_number,
                                status, condition, location, visibility, current_holder_id, created_at, updated_at)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (asset_tag) DO UPDATE
                                SET device_name=EXCLUDED.device_name, category=EXCLUDED.category,
                                    brand=EXCLUDED.brand, model=EXCLUDED.model,
                                    serial_number=EXCLUDED.serial_number, status=EXCLUDED.status,
                                    condition=EXCLUDED.condition, location=EXCLUDED.location,
                                    visibility=EXCLUDED.visibility, current_holder_id=EXCLUDED.current_holder_id,
                                    updated_at=EXCLUDED.updated_at
                            """,
                            (
                                row["asset_tag"].strip(), row["device_name"].strip(),
                                row["category"].strip(),
                                row.get("brand", "").strip() or None,
                                row.get("model", "").strip() or None,
                                row.get("serial_number", "").strip() or None,
                                row["status"].strip(), row["condition"].strip(),
                                row.get("location", "").strip() or None,
                                row.get("visibility", "public").strip() or "public",
                                holder_id, now, now,
                            ),
                        )
                        for kind in ["device_name", "category", "brand", "model", "location", "status", "condition"]:
                            sync_lookup(conn, kind, row.get(kind) or "")
                        imported += 1

                elif entity == "people":
                    for row in rows:
                        require_fields(row, ["full_name", "department"])
                        cur.execute(
                            """
                            INSERT INTO people (full_name, department, email, phone, location, notes, created_at, updated_at)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT DO NOTHING
                            """,
                            (
                                row["full_name"].strip(), row["department"].strip(),
                                row.get("email", "").strip() or None,
                                row.get("phone", "").strip() or None,
                                row.get("location", "").strip() or None,
                                row.get("notes", "").strip() or None,
                                now, now,
                            ),
                        )
                        sync_lookup(conn, "department", row["department"])
                        sync_lookup(conn, "person_location", row.get("location"))
                        imported += 1

                elif entity == "admins":
                    for row in rows:
                        require_fields(row, ["full_name", "username", "role"])
                        cur.execute("SELECT id, password_hash FROM admin_users WHERE username = %s", (row["username"].strip(),))
                        existing = cur.fetchone()
                        password_hash = existing["password_hash"] if existing else hash_password("admin")
                        cur.execute(
                            """
                            INSERT INTO admin_users (full_name, username, password_hash, role, is_active, created_at, updated_at)
                            VALUES (%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (username) DO UPDATE
                                SET full_name=EXCLUDED.full_name, role=EXCLUDED.role,
                                    is_active=EXCLUDED.is_active, updated_at=EXCLUDED.updated_at
                            """,
                            (
                                row["full_name"].strip(), row["username"].strip(),
                                password_hash, row["role"].strip(),
                                str(row.get("is_active", "true")).strip().lower() in {"1", "true", "yes", "active"},
                                now, now,
                            ),
                        )
                        sync_lookup(conn, "role", row["role"])
                        imported += 1

                else:  # assignments
                    for idx, row in enumerate(rows, start=2):
                        require_fields(row, ["asset_tag", "person_name", "admin_name"])
                        cur.execute("SELECT id FROM assets WHERE asset_tag = %s", (row["asset_tag"].strip(),))
                        asset = cur.fetchone()
                        if not asset:
                            raise ValueError(f"Row {idx}: asset tag '{row['asset_tag']}' not found")

                        cur.execute("SELECT id FROM people WHERE full_name = %s", (row["person_name"].strip(),))
                        person = cur.fetchone()
                        if not person:
                            raise ValueError(f"Row {idx}: user '{row['person_name']}' not found")

                        cur.execute(
                            """
                            SELECT id FROM admin_users
                            WHERE full_name = %s OR username = %s
                            ORDER BY CASE WHEN full_name = %s THEN 0 ELSE 1 END, id
                            LIMIT 1
                            """,
                            (row["admin_name"].strip(),) * 3,
                        )
                        admin = cur.fetchone()
                        if not admin:
                            raise ValueError(f"Row {idx}: admin '{row['admin_name']}' not found")

                        assigned_at = row.get("assigned_at") or now
                        returned_at = row.get("returned_at") or None
                        cur.execute(
                            """
                            INSERT INTO assignments (asset_id, person_id, assigned_by_admin_id, assigned_at, returned_at, notes, return_notes)
                            VALUES (%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT DO NOTHING
                            """,
                            (
                                asset["id"], person["id"], admin["id"], assigned_at, returned_at,
                                row.get("notes", "").strip() or None,
                                row.get("return_notes", "").strip() or None,
                            ),
                        )
                        sync_asset_assignment_state(conn, asset["id"])
                        imported += 1

            conn.commit()
        except (psycopg2.Error, ValueError) as exc:
            conn.rollback()
            conn.close()
            raise ValueError(f"Import failed: {exc}") from exc
        finally:
            conn.close()
        return imported

    # Static files 
    def serve_static(self, path):
        target = "index.html" if path in ("/", "") else path.lstrip("/")
        file_path = STATIC_DIR / target
        if not file_path.exists() or not file_path.is_file():
            if path.startswith("/api/"):
                return error_response(self, "Route not found", HTTPStatus.NOT_FOUND)
            file_path = STATIC_DIR / "index.html"
        if not file_path.exists():
            body = b"<h1>IT Inventory</h1><p>Static files not found. Place your frontend in the <code>static/</code> folder.</p>"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        ext = file_path.suffix
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css":  "text/css; charset=utf-8",
            ".js":   "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".png":  "image/png",
            ".ico":  "image/x-icon",
            ".svg":  "image/svg+xml",
        }.get(ext, "text/plain; charset=utf-8")
        body = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _build_wsgi_path(environ):
    path = environ.get("PATH_INFO", "/") or "/"
    query = environ.get("QUERY_STRING")
    if query:
        return f"{path}?{query}"
    return path


def _build_wsgi_headers(environ):
    headers = Message()
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            name = key[5:].replace("_", "-").title()
            headers[name] = value
    content_type = environ.get("CONTENT_TYPE")
    if content_type:
        headers["Content-Type"] = content_type
    content_length = environ.get("CONTENT_LENGTH")
    if content_length:
        headers["Content-Length"] = content_length
    return headers


class WSGIInventoryHandler(InventoryHandler):
    def __init__(self, environ, body):
        self.environ = environ
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.headers = _build_wsgi_headers(environ)
        self.command = environ.get("REQUEST_METHOD", "GET").upper()
        self.path = _build_wsgi_path(environ)
        self.client_address = (environ.get("REMOTE_ADDR", "127.0.0.1"), 0)
        self.response_status = HTTPStatus.OK
        self.response_reason = None
        self.response_headers = []

    def send_response(self, code, message=None):
        self.response_status = HTTPStatus(code)
        if message:
            self.response_reason = message

    def send_header(self, keyword, value):
        self.response_headers.append((keyword, value))

    def end_headers(self):
        return


# SERVER
def main(environ=None, start_response=None):
    if environ is None or start_response is None:
        run_server(open_browser=True)
        return None
    ensure_db_ready()
    body = b""
    wsgi_input = environ.get("wsgi.input")
    if wsgi_input:
        body = wsgi_input.read() or b""

    handler = WSGIInventoryHandler(environ, body)
    try:
        if handler.command == "GET":
            handler.do_GET()
        elif handler.command == "POST":
            handler.do_POST()
        elif handler.command == "PUT":
            handler.do_PUT()
        elif handler.command == "DELETE":
            handler.do_DELETE()
        else:
            error_response(handler, "Method not allowed", HTTPStatus.METHOD_NOT_ALLOWED)
    except Exception:
        error_response(handler, "Internal server error", HTTPStatus.INTERNAL_SERVER_ERROR)

    status_code = int(handler.response_status)
    reason = handler.response_reason or HTTPStatus(status_code).phrase
    response_body = handler.wfile.getvalue()
    headers = handler.response_headers
    if not any(name.lower() == "content-length" for name, _ in headers):
        headers.append(("Content-Length", str(len(response_body))))
    start_response(f"{status_code} {reason}", headers)
    return [response_body]


def create_server():
    init_db()
    return ThreadingHTTPServer((HOST, PORT), InventoryHandler)


def run_server(open_browser=True):
    server = create_server()
    print(f"IT Inventory (PostgreSQL) running at {app_url()}")
    print("Default login: admin / admin")
    if open_browser:
        open_browser_once()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.server_close()


def cli():
    run_server(open_browser=True)

if __name__ == "__main__":
    cli()