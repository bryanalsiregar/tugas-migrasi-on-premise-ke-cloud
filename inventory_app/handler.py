import csv
import html
import io
import json
import secrets
import sqlite3
import threading
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from .auth import admin_dict, hash_password, require_admin_role, verify_password
from .config import LOOKUP_FIELD_MAP, STATIC_DIR, utc_now
from .db import get_db, lookup_usage_count, sync_asset_assignment_state, sync_lookup
from .reports import build_pretty_pdf, format_export_value, get_export_columns, get_export_definition, normalize_csv_row
from .responses import error_response, json_response, parse_json, require_fields
from .sync_service import get_sync_status, start_sync_job

SESSIONS = {}
SESSION_LOCK = threading.Lock()

class InventoryHandler(BaseHTTPRequestHandler):
    server_version = "PortableInventory/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/session":
            return self.handle_session()
        if parsed.path == "/api/dashboard":
            return self.authenticated(self.handle_dashboard)
        if parsed.path == "/api/assets":
            return self.authenticated(self.handle_assets_list)
        if parsed.path == "/api/people":
            return self.authenticated(self.handle_people_list)
        if parsed.path == "/api/admin-users":
            return self.authenticated(self.handle_admin_list)
        if parsed.path == "/api/assignments":
            return self.authenticated(self.handle_assignments_list)
        if parsed.path == "/api/lookups":
            return self.authenticated(self.handle_lookup_list)
        if parsed.path == "/api/sync/status":
            return self.authenticated(self.handle_sync_status)
        if parsed.path == "/api/export":
            return self.authenticated(self.handle_export_csv)
        if parsed.path == "/api/export-pdf":
            return self.authenticated(self.handle_export_pdf)
        if parsed.path == "/api/report":
            return self.authenticated(self.handle_report_page)
        return self.serve_static(parsed.path)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            return self.handle_login()
        if parsed.path == "/api/logout":
            return self.handle_logout()
        if parsed.path == "/api/assets":
            return self.authenticated(self.handle_asset_create)
        if parsed.path == "/api/people":
            return self.authenticated(self.handle_person_create)
        if parsed.path == "/api/admin-users":
            return self.authenticated(self.handle_admin_create)
        if parsed.path == "/api/lookups":
            return self.authenticated(self.handle_lookup_create)
        if parsed.path == "/api/import":
            return self.authenticated(self.handle_import_csv)
        if parsed.path == "/api/account/password":
            return self.authenticated(self.handle_change_own_password)
        if parsed.path == "/api/sync/start":
            return self.authenticated(self.handle_sync_start)
        if parsed.path == "/api/assignments/assign":
            return self.authenticated(self.handle_assign_asset)
        if parsed.path == "/api/assignments/return":
            return self.authenticated(self.handle_return_asset)
        return error_response(self, "Route not found", HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/assets/"):
            return self.authenticated(self.handle_asset_update)
        if parsed.path.startswith("/api/people/"):
            return self.authenticated(self.handle_person_update)
        if parsed.path.startswith("/api/admin-users/"):
            return self.authenticated(self.handle_admin_update)
        if parsed.path.startswith("/api/lookups/"):
            return self.authenticated(self.handle_lookup_update)
        return error_response(self, "Route not found", HTTPStatus.NOT_FOUND)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/assets/"):
            return self.authenticated(self.handle_asset_delete)
        if parsed.path.startswith("/api/people/"):
            return self.authenticated(self.handle_person_delete)
        if parsed.path.startswith("/api/admin-users/"):
            return self.authenticated(self.handle_admin_delete)
        if parsed.path.startswith("/api/lookups/"):
            return self.authenticated(self.handle_lookup_delete)
        return error_response(self, "Route not found", HTTPStatus.NOT_FOUND)

    def log_message(self, format, *args):
        return

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
        user = conn.execute(
            "SELECT * FROM admin_users WHERE id = ? AND is_active = 1", (user_id,)
        ).fetchone()
        conn.close()
        return user

    def set_session(self, user_id):
        session_id = secrets.token_urlsafe(32)
        with SESSION_LOCK:
            SESSIONS[session_id] = user_id
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

    def handle_login(self):
        try:
            data = parse_json(self)
            require_fields(data, ["username", "password"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM admin_users WHERE username = ? AND is_active = 1",
            (data["username"].strip(),),
        ).fetchone()
        conn.close()
        if not user or not verify_password(data["password"], user["password_hash"]):
            return error_response(self, "Invalid username or password", HTTPStatus.UNAUTHORIZED)

        body = json.dumps({"user": admin_dict(user)}).encode("utf-8")
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

    def handle_sync_start(self, user):
        if not require_admin_role(self, user):
            return
        try:
            job = start_sync_job()
        except RuntimeError as exc:
            return error_response(self, str(exc), HTTPStatus.CONFLICT)
        json_response(self, job, HTTPStatus.ACCEPTED)

    def handle_sync_status(self, user):
        if not require_admin_role(self, user):
            return
        parsed = urlparse(self.path)
        job_id = parse_qs(parsed.query).get("job_id", [""])[0].strip()
        if not job_id:
            return error_response(self, "job_id is required")
        status = get_sync_status(job_id)
        if not status:
            return error_response(self, "Sync job not found", HTTPStatus.NOT_FOUND)
        json_response(self, status)

    def handle_dashboard(self, user):
        conn = get_db()
        stats = {
            "assets_total": conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0],
            "assets_assigned": conn.execute("SELECT COUNT(*) FROM assets WHERE status = 'Assigned'").fetchone()[0],
            "assets_available": conn.execute("SELECT COUNT(*) FROM assets WHERE status = 'Available'").fetchone()[0],
            "assets_maintenance": conn.execute("SELECT COUNT(*) FROM assets WHERE status = 'Maintenance'").fetchone()[0],
            "people_total": conn.execute("SELECT COUNT(*) FROM people").fetchone()[0],
            "admins_total": conn.execute("SELECT COUNT(*) FROM admin_users WHERE is_active = 1").fetchone()[0],
        }
        recent_assets = [dict(row) for row in conn.execute(
            """
            SELECT a.id, a.asset_tag, a.device_name, a.status, p.full_name AS holder_name
            FROM assets a
            LEFT JOIN people p ON p.id = a.current_holder_id
            ORDER BY a.updated_at DESC
            LIMIT 5
            """
        ).fetchall()]
        recent_activity = [dict(row) for row in conn.execute(
            """
            SELECT ass.id, a.asset_tag, p.full_name, ass.assigned_at, ass.returned_at
            FROM assignments ass
            JOIN assets a ON a.id = ass.asset_id
            JOIN people p ON p.id = ass.person_id
            ORDER BY COALESCE(ass.returned_at, ass.assigned_at) DESC
            LIMIT 8
            """
        ).fetchall()]
        conn.close()
        json_response(self, {"stats": stats, "recent_assets": recent_assets, "recent_activity": recent_activity, "user": admin_dict(user)})

    def handle_assets_list(self, user):
        conn = get_db()
        rows = conn.execute(
            """
            SELECT a.*, p.full_name AS holder_name
            FROM assets a
            LEFT JOIN people p ON p.id = a.current_holder_id
            ORDER BY a.updated_at DESC, a.id DESC
            """
        ).fetchall()
        conn.close()
        json_response(self, {"items": [dict(row) for row in rows]})

    def handle_people_list(self, user):
        conn = get_db()
        rows = conn.execute(
            """
            SELECT p.*,
                (SELECT COUNT(*) FROM assets a WHERE a.current_holder_id = p.id) AS assigned_assets
            FROM people p
            ORDER BY p.updated_at DESC, p.id DESC
            """
        ).fetchall()
        conn.close()
        json_response(self, {"items": [dict(row) for row in rows]})

    def handle_admin_list(self, user):
        if not require_admin_role(self, user):
            return
        conn = get_db()
        rows = conn.execute("SELECT * FROM admin_users ORDER BY updated_at DESC, id DESC").fetchall()
        conn.close()
        json_response(self, {"items": [admin_dict(row) for row in rows]})

    def handle_assignments_list(self, user):
        conn = get_db()
        rows = conn.execute(
            """
            SELECT ass.id, ass.asset_id, ass.person_id, ass.assigned_at, ass.returned_at, ass.notes, ass.return_notes,
                   a.asset_tag, a.device_name, p.full_name AS person_name, ad.full_name AS admin_name
            FROM assignments ass
            JOIN assets a ON a.id = ass.asset_id
            JOIN people p ON p.id = ass.person_id
            JOIN admin_users ad ON ad.id = ass.assigned_by_admin_id
            ORDER BY ass.id DESC
            """
        ).fetchall()
        conn.close()
        json_response(self, {"items": [dict(row) for row in rows]})

    def handle_lookup_list(self, user):
        parsed = urlparse(self.path)
        requested_kind = parse_qs(parsed.query).get("kind", [None])[0]
        conn = get_db()
        rows = conn.execute(
            """
            SELECT id, kind, value, created_at, updated_at
            FROM lookup_values
            ORDER BY kind, value COLLATE NOCASE
            """
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["usage_count"] = lookup_usage_count(conn, item["kind"], item["value"])
            if not requested_kind or item["kind"] == requested_kind:
                items.append(item)
        conn.close()
        json_response(self, {"items": items})

    def handle_export_csv(self, user):
        entity = parse_qs(urlparse(self.path).query).get("entity", ["assets"])[0]
        if entity not in {"assets", "people", "admins", "assignments"}:
            return error_response(self, "Unsupported export type")

        rows = self.get_export_rows(entity)
        columns = get_export_columns(entity)
        headers = [column["label"] for column in columns]

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    column["label"]: format_export_value(column["key"], row.get(column["key"], ""))
                    for column in columns
                }
            )
        body = output.getvalue().encode("utf-8-sig")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{entity}.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
            "<tr>"
            + "".join(
                f"<td>{html.escape(format_export_value(column['key'], row.get(column['key'], '')))}</td>"
                for column in columns
            )
            + "</tr>"
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
<h1>{title}</h1>
<p>Generated {html.escape(utc_now())}</p>
<p>Total records: {len(report_rows)}</p>
<table><thead><tr>{"".join(f"<th>{html.escape(column['label'])}</th>" for column in columns)}</tr></thead><tbody>{table_html}</tbody></table>
</div></body></html>"""
        payload = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def handle_asset_create(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["asset_tag", "device_name", "category", "status", "condition"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))
        now = utc_now()
        conn = get_db()
        try:
            cursor = conn.execute(
                """
                INSERT INTO assets (
                    asset_tag, device_name, category, brand, model, serial_number, status, condition,
                    purchase_date, warranty_end, location, notes, current_holder_id, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["asset_tag"].strip(),
                    data["device_name"].strip(),
                    data["category"].strip(),
                    data.get("brand", "").strip(),
                    data.get("model", "").strip(),
                    data.get("serial_number", "").strip(),
                    data["status"].strip(),
                    data["condition"].strip(),
                    data.get("purchase_date") or None,
                    data.get("warranty_end") or None,
                    data.get("location", "").strip(),
                    data.get("notes", "").strip(),
                    data.get("current_holder_id") or None,
                    now,
                    now,
                ),
            )
            sync_lookup(conn, "category", data["category"])
            sync_lookup(conn, "device_name", data["device_name"])
            sync_lookup(conn, "brand", data.get("brand"))
            sync_lookup(conn, "model", data.get("model"))
            sync_lookup(conn, "location", data.get("location"))
            sync_lookup(conn, "status", data["status"])
            sync_lookup(conn, "condition", data["condition"])
            conn.commit()
            row = conn.execute(
                """
                SELECT a.*, p.full_name AS holder_name
                FROM assets a LEFT JOIN people p ON p.id = a.current_holder_id
                WHERE a.id = ?
                """,
                (cursor.lastrowid,),
            ).fetchone()
        except sqlite3.IntegrityError:
            conn.close()
            return error_response(self, "Asset tag must be unique")
        conn.close()
        json_response(self, {"item": dict(row)}, HTTPStatus.CREATED)

    def handle_asset_update(self, user):
        asset_id = self.path.rsplit("/", 1)[-1]
        try:
            data = parse_json(self)
            require_fields(data, ["asset_tag", "device_name", "category", "status", "condition"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))
        conn = get_db()
        try:
            cursor = conn.execute(
                """
                UPDATE assets
                SET asset_tag = ?, device_name = ?, category = ?, brand = ?, model = ?, serial_number = ?,
                    status = ?, condition = ?, purchase_date = ?, warranty_end = ?, location = ?, notes = ?,
                    current_holder_id = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    data["asset_tag"].strip(),
                    data["device_name"].strip(),
                    data["category"].strip(),
                    data.get("brand", "").strip(),
                    data.get("model", "").strip(),
                    data.get("serial_number", "").strip(),
                    data["status"].strip(),
                    data["condition"].strip(),
                    data.get("purchase_date") or None,
                    data.get("warranty_end") or None,
                    data.get("location", "").strip(),
                    data.get("notes", "").strip(),
                    data.get("current_holder_id") or None,
                    utc_now(),
                    asset_id,
                ),
            )
            if cursor.rowcount == 0:
                conn.close()
                return error_response(self, "Asset not found", HTTPStatus.NOT_FOUND)
            sync_lookup(conn, "category", data["category"])
            sync_lookup(conn, "device_name", data["device_name"])
            sync_lookup(conn, "brand", data.get("brand"))
            sync_lookup(conn, "model", data.get("model"))
            sync_lookup(conn, "location", data.get("location"))
            sync_lookup(conn, "status", data["status"])
            sync_lookup(conn, "condition", data["condition"])
            conn.commit()
            row = conn.execute(
                """
                SELECT a.*, p.full_name AS holder_name
                FROM assets a LEFT JOIN people p ON p.id = a.current_holder_id
                WHERE a.id = ?
                """,
                (asset_id,),
            ).fetchone()
        except sqlite3.IntegrityError:
            conn.close()
            return error_response(self, "Asset tag must be unique")
        conn.close()
        json_response(self, {"item": dict(row)})

    def handle_asset_delete(self, user):
        asset_id = self.path.rsplit("/", 1)[-1]
        conn = get_db()
        active_assignment = conn.execute(
            "SELECT 1 FROM assignments WHERE asset_id = ? AND returned_at IS NULL", (asset_id,)
        ).fetchone()
        if active_assignment:
            conn.close()
            return error_response(self, "Return the asset before deleting it")
        cursor = conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()
        conn.close()
        if cursor.rowcount == 0:
            return error_response(self, "Asset not found", HTTPStatus.NOT_FOUND)
        json_response(self, {"success": True})

    def handle_person_create(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["full_name", "department"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))
        now = utc_now()
        conn = get_db()
        cursor = conn.execute(
            """
            INSERT INTO people (full_name, department, email, phone, location, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["full_name"].strip(),
                data["department"].strip(),
                data.get("email", "").strip(),
                data.get("phone", "").strip(),
                data.get("location", "").strip(),
                data.get("notes", "").strip(),
                now,
                now,
            ),
        )
        sync_lookup(conn, "department", data["department"])
        sync_lookup(conn, "person_location", data.get("location"))
        conn.commit()
        row = conn.execute(
            """
            SELECT p.*, (SELECT COUNT(*) FROM assets a WHERE a.current_holder_id = p.id) AS assigned_assets
            FROM people p WHERE p.id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
        conn.close()
        json_response(self, {"item": dict(row)}, HTTPStatus.CREATED)

    def handle_person_update(self, user):
        person_id = self.path.rsplit("/", 1)[-1]
        try:
            data = parse_json(self)
            require_fields(data, ["full_name", "department"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))
        conn = get_db()
        cursor = conn.execute(
            """
            UPDATE people
            SET full_name = ?, department = ?, email = ?, phone = ?, location = ?, notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                data["full_name"].strip(),
                data["department"].strip(),
                data.get("email", "").strip(),
                data.get("phone", "").strip(),
                data.get("location", "").strip(),
                data.get("notes", "").strip(),
                utc_now(),
                person_id,
            ),
        )
        if cursor.rowcount == 0:
            conn.close()
            return error_response(self, "Person not found", HTTPStatus.NOT_FOUND)
        sync_lookup(conn, "department", data["department"])
        sync_lookup(conn, "person_location", data.get("location"))
        conn.commit()
        row = conn.execute(
            """
            SELECT p.*, (SELECT COUNT(*) FROM assets a WHERE a.current_holder_id = p.id) AS assigned_assets
            FROM people p WHERE p.id = ?
            """,
            (person_id,),
        ).fetchone()
        conn.close()
        json_response(self, {"item": dict(row)})

    def handle_person_delete(self, user):
        person_id = self.path.rsplit("/", 1)[-1]
        conn = get_db()
        assigned = conn.execute("SELECT 1 FROM assets WHERE current_holder_id = ?", (person_id,)).fetchone()
        if assigned:
            conn.close()
            return error_response(self, "Reassign or return assets before deleting this profile")
        cursor = conn.execute("DELETE FROM people WHERE id = ?", (person_id,))
        conn.commit()
        conn.close()
        if cursor.rowcount == 0:
            return error_response(self, "Person not found", HTTPStatus.NOT_FOUND)
        json_response(self, {"success": True})

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
            cursor = conn.execute(
                """
                INSERT INTO admin_users (full_name, username, password_hash, role, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["full_name"].strip(),
                    data["username"].strip(),
                    hash_password(data["password"]),
                    data.get("role", "Admin").strip() or "Admin",
                    1 if data.get("is_active", True) else 0,
                    now,
                    now,
                ),
            )
            sync_lookup(conn, "role", data.get("role", "Admin"))
            conn.commit()
            row = conn.execute("SELECT * FROM admin_users WHERE id = ?", (cursor.lastrowid,)).fetchone()
        except sqlite3.IntegrityError:
            conn.close()
            return error_response(self, "Username already exists")
        conn.close()
        json_response(self, {"item": admin_dict(row)}, HTTPStatus.CREATED)

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
        existing = conn.execute("SELECT * FROM admin_users WHERE id = ?", (admin_id,)).fetchone()
        if not existing:
            conn.close()
            return error_response(self, "Admin user not found", HTTPStatus.NOT_FOUND)
        password_hash = existing["password_hash"]
        if str(data.get("password", "")).strip():
            password_hash = hash_password(data["password"])
        try:
            conn.execute(
                """
                UPDATE admin_users
                SET full_name = ?, username = ?, password_hash = ?, role = ?, is_active = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    data["full_name"].strip(),
                    data["username"].strip(),
                    password_hash,
                    data.get("role", "Admin").strip() or "Admin",
                    1 if data.get("is_active", True) else 0,
                    utc_now(),
                    admin_id,
                ),
            )
            sync_lookup(conn, "role", data.get("role", "Admin"))
            conn.commit()
            row = conn.execute("SELECT * FROM admin_users WHERE id = ?", (admin_id,)).fetchone()
        except sqlite3.IntegrityError:
            conn.close()
            return error_response(self, "Username already exists")
        conn.close()
        json_response(self, {"item": admin_dict(row)})

    def handle_admin_delete(self, user):
        if not require_admin_role(self, user):
            return
        admin_id = int(self.path.rsplit("/", 1)[-1])
        if admin_id == user["id"]:
            return error_response(self, "You cannot delete your own logged-in account")
        conn = get_db()
        cursor = conn.execute("DELETE FROM admin_users WHERE id = ?", (admin_id,))
        conn.commit()
        conn.close()
        if cursor.rowcount == 0:
            return error_response(self, "Admin user not found", HTTPStatus.NOT_FOUND)
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
        conn.execute(
            "UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (hash_password(data["new_password"]), utc_now(), user["id"]),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM admin_users WHERE id = ?", (user["id"],)).fetchone()
        conn.close()
        json_response(self, {"success": True, "user": admin_dict(row)})

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
            sync_lookup(conn, data["kind"], data["value"])
            conn.commit()
            row = conn.execute(
                """
                SELECT id, kind, value, created_at, updated_at
                FROM lookup_values
                WHERE kind = ? AND lower(value) = lower(?)
                """,
                (data["kind"], data["value"].strip()),
            ).fetchone()
            item = dict(row)
            item["usage_count"] = lookup_usage_count(conn, item["kind"], item["value"])
        except sqlite3.IntegrityError:
            conn.close()
            return error_response(self, "Keyword already exists")
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
        existing = conn.execute(
            "SELECT * FROM lookup_values WHERE id = ?",
            (lookup_id,),
        ).fetchone()
        if not existing:
            conn.close()
            return error_response(self, "Keyword not found", HTTPStatus.NOT_FOUND)
        try:
            conn.execute(
                "UPDATE lookup_values SET value = ?, updated_at = ? WHERE id = ?",
                (data["value"].strip(), utc_now(), lookup_id),
            )
            table, field = LOOKUP_FIELD_MAP[existing["kind"]]
            conn.execute(
                f"UPDATE {table} SET {field} = ?, updated_at = ? WHERE {field} = ?",
                (data["value"].strip(), utc_now(), existing["value"]),
            )
            conn.commit()
            row = conn.execute(
                "SELECT id, kind, value, created_at, updated_at FROM lookup_values WHERE id = ?",
                (lookup_id,),
            ).fetchone()
            item = dict(row)
            item["usage_count"] = lookup_usage_count(conn, item["kind"], item["value"])
        except sqlite3.IntegrityError:
            conn.close()
            return error_response(self, "Keyword already exists")
        conn.close()
        json_response(self, {"item": item})

    def handle_lookup_delete(self, user):
        lookup_id = self.path.rsplit("/", 1)[-1]
        conn = get_db()
        existing = conn.execute(
            "SELECT * FROM lookup_values WHERE id = ?",
            (lookup_id,),
        ).fetchone()
        if not existing:
            conn.close()
            return error_response(self, "Keyword not found", HTTPStatus.NOT_FOUND)
        usage_count = lookup_usage_count(conn, existing["kind"], existing["value"])
        if usage_count:
            conn.close()
            return error_response(self, "Update matching assets before deleting this keyword")
        conn.execute("DELETE FROM lookup_values WHERE id = ?", (lookup_id,))
        conn.commit()
        conn.close()
        json_response(self, {"success": True})

    def handle_assign_asset(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["asset_id", "person_id"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))
        conn = get_db()
        asset = conn.execute("SELECT * FROM assets WHERE id = ?", (data["asset_id"],)).fetchone()
        if not asset:
            conn.close()
            return error_response(self, "Asset not found", HTTPStatus.NOT_FOUND)
        if asset["status"] == "Assigned":
            conn.close()
            return error_response(self, "Asset is already assigned")
        person = conn.execute("SELECT * FROM people WHERE id = ?", (data["person_id"],)).fetchone()
        if not person:
            conn.close()
            return error_response(self, "Person not found", HTTPStatus.NOT_FOUND)
        now = utc_now()
        conn.execute(
            """
            INSERT INTO assignments (asset_id, person_id, assigned_by_admin_id, assigned_at, notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (data["asset_id"], data["person_id"], user["id"], now, data.get("notes", "").strip()),
        )
        conn.execute(
            """
            UPDATE assets
            SET status = 'Assigned', current_holder_id = ?, location = ?, updated_at = ?
            WHERE id = ?
            """,
            (data["person_id"], person["location"], now, data["asset_id"]),
        )
        conn.commit()
        conn.close()
        json_response(self, {"success": True})

    def handle_return_asset(self, user):
        try:
            data = parse_json(self)
            require_fields(data, ["asset_id"])
        except (json.JSONDecodeError, ValueError) as exc:
            return error_response(self, str(exc))
        conn = get_db()
        assignment = conn.execute(
            """
            SELECT * FROM assignments
            WHERE asset_id = ? AND returned_at IS NULL
            ORDER BY assigned_at DESC LIMIT 1
            """,
            (data["asset_id"],),
        ).fetchone()
        if not assignment:
            conn.close()
            return error_response(self, "No active assignment found for this asset")
        now = utc_now()
        conn.execute(
            """
            UPDATE assignments
            SET returned_at = ?, return_notes = ?
            WHERE id = ?
            """,
            (now, data.get("return_notes", "").strip(), assignment["id"]),
        )
        conn.execute(
            """
            UPDATE assets
            SET status = 'Available', current_holder_id = NULL, updated_at = ?
            WHERE id = ?
            """,
            (now, data["asset_id"]),
        )
        conn.commit()
        conn.close()
        json_response(self, {"success": True})

    def get_export_rows(self, entity):
        conn = get_db()
        if entity == "assets":
            rows = [dict(row) for row in conn.execute(
                """
                SELECT a.*, p.full_name AS holder_name
                FROM assets a
                LEFT JOIN people p ON p.id = a.current_holder_id
                ORDER BY a.id
                """
            ).fetchall()]
        elif entity == "people":
            rows = [dict(row) for row in conn.execute("SELECT * FROM people ORDER BY id").fetchall()]
        elif entity == "admins":
            rows = [admin_dict(row) for row in conn.execute("SELECT * FROM admin_users ORDER BY id").fetchall()]
        else:
            rows = [dict(row) for row in conn.execute(
                """
                SELECT a.asset_tag, p.full_name AS person_name, ad.full_name AS admin_name,
                       ass.assigned_at, ass.returned_at, ass.notes, ass.return_notes
                FROM assignments ass
                JOIN assets a ON a.id = ass.asset_id
                JOIN people p ON p.id = ass.person_id
                JOIN admin_users ad ON ad.id = ass.assigned_by_admin_id
                ORDER BY ass.id
                """
            ).fetchall()]
        conn.close()
        return rows

    def get_report_definition(self, entity):
        rows = self.get_export_rows(entity)
        definition = get_export_definition(entity)
        return definition["title"], definition["columns"], rows

    def import_rows(self, entity, csv_text):
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = [normalize_csv_row(entity, row) for row in reader]
        if not rows:
            raise ValueError("CSV file is empty")
        conn = get_db()
        imported = 0
        now = utc_now()
        try:
            if entity == "assets":
                for row in rows:
                    require_fields(row, ["asset_tag", "device_name", "category", "status", "condition"])
                    holder_name = str(row.get("holder_name", "")).strip()
                    holder_id = None
                    if holder_name:
                        holder = conn.execute("SELECT id FROM people WHERE full_name = ?", (holder_name,)).fetchone()
                        holder_id = holder["id"] if holder else None
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO assets (
                            id, asset_tag, device_name, category, brand, model, serial_number, status, condition,
                            purchase_date, warranty_end, location, notes, current_holder_id, created_at, updated_at
                        )
                        VALUES (
                            COALESCE((SELECT id FROM assets WHERE asset_tag = ?), NULL), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            COALESCE((SELECT created_at FROM assets WHERE asset_tag = ?), ?), ?
                        )
                        """,
                        (
                            row["asset_tag"].strip(),
                            row["asset_tag"].strip(),
                            row["device_name"].strip(),
                            row["category"].strip(),
                            row.get("brand", "").strip(),
                            row.get("model", "").strip(),
                            row.get("serial_number", "").strip(),
                            row["status"].strip(),
                            row["condition"].strip(),
                            row.get("purchase_date") or None,
                            row.get("warranty_end") or None,
                            row.get("location", "").strip(),
                            row.get("notes", "").strip(),
                            holder_id,
                            row["asset_tag"].strip(),
                            now,
                            now,
                        ),
                    )
                    sync_lookup(conn, "device_name", row["device_name"])
                    sync_lookup(conn, "category", row["category"])
                    sync_lookup(conn, "brand", row.get("brand"))
                    sync_lookup(conn, "model", row.get("model"))
                    sync_lookup(conn, "location", row.get("location"))
                    sync_lookup(conn, "status", row["status"])
                    sync_lookup(conn, "condition", row["condition"])
                    imported += 1
            elif entity == "people":
                for row in rows:
                    require_fields(row, ["full_name", "department"])
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO people (
                            id, full_name, department, email, phone, location, notes, created_at, updated_at
                        )
                        VALUES (
                            COALESCE((SELECT id FROM people WHERE full_name = ?), NULL), ?, ?, ?, ?, ?, ?,
                            COALESCE((SELECT created_at FROM people WHERE full_name = ?), ?), ?
                        )
                        """,
                        (
                            row["full_name"].strip(),
                            row["full_name"].strip(),
                            row["department"].strip(),
                            row.get("email", "").strip(),
                            row.get("phone", "").strip(),
                            row.get("location", "").strip(),
                            row.get("notes", "").strip(),
                            row["full_name"].strip(),
                            now,
                            now,
                        ),
                    )
                    sync_lookup(conn, "department", row["department"])
                    sync_lookup(conn, "person_location", row.get("location"))
                    imported += 1
            elif entity == "admins":
                for row in rows:
                    require_fields(row, ["full_name", "username", "role"])
                    existing = conn.execute("SELECT id, password_hash, created_at FROM admin_users WHERE username = ?", (row["username"].strip(),)).fetchone()
                    password_hash = existing["password_hash"] if existing else hash_password("admin")
                    created_at = existing["created_at"] if existing else now
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO admin_users (
                            id, full_name, username, password_hash, role, is_active, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            existing["id"] if existing else None,
                            row["full_name"].strip(),
                            row["username"].strip(),
                            password_hash,
                            row["role"].strip(),
                            1 if str(row.get("is_active", "true")).strip().lower() in {"1", "true", "yes", "active"} else 0,
                            created_at,
                            now,
                        ),
                    )
                    sync_lookup(conn, "role", row["role"])
                    imported += 1
            else:
                for index, row in enumerate(rows, start=2):
                    require_fields(row, ["asset_tag", "person_name", "admin_name"])
                    asset = conn.execute(
                        "SELECT id FROM assets WHERE asset_tag = ?",
                        (row["asset_tag"].strip(),),
                    ).fetchone()
                    if not asset:
                        raise ValueError(f"Assignments import row {index}: asset tag '{row['asset_tag']}' was not found")

                    person = conn.execute(
                        "SELECT id, location FROM people WHERE full_name = ?",
                        (row["person_name"].strip(),),
                    ).fetchone()
                    if not person:
                        raise ValueError(f"Assignments import row {index}: user '{row['person_name']}' was not found")

                    admin = conn.execute(
                        """
                        SELECT id FROM admin_users
                        WHERE full_name = ? OR username = ?
                        ORDER BY CASE WHEN full_name = ? THEN 0 ELSE 1 END, id
                        LIMIT 1
                        """,
                        (row["admin_name"].strip(), row["admin_name"].strip(), row["admin_name"].strip()),
                    ).fetchone()
                    if not admin:
                        raise ValueError(f"Assignments import row {index}: admin '{row['admin_name']}' was not found")

                    assigned_at = row.get("assigned_at") or now
                    returned_at = row.get("returned_at") or None
                    notes = row.get("notes", "").strip()
                    return_notes = row.get("return_notes", "").strip()

                    existing = conn.execute(
                        """
                        SELECT id FROM assignments
                        WHERE asset_id = ? AND person_id = ? AND assigned_by_admin_id = ? AND assigned_at = ?
                        """,
                        (asset["id"], person["id"], admin["id"], assigned_at),
                    ).fetchone()

                    if existing:
                        conn.execute(
                            """
                            UPDATE assignments
                            SET returned_at = ?, notes = ?, return_notes = ?
                            WHERE id = ?
                            """,
                            (returned_at, notes, return_notes, existing["id"]),
                        )
                    else:
                        conn.execute(
                            """
                            INSERT INTO assignments (
                                asset_id, person_id, assigned_by_admin_id, assigned_at, returned_at, notes, return_notes
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (asset["id"], person["id"], admin["id"], assigned_at, returned_at, notes, return_notes),
                        )

                    sync_asset_assignment_state(conn, asset["id"])
                    imported += 1
            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            conn.close()
            raise ValueError(f"Import failed: {exc}") from exc
        conn.close()
        return imported

    def serve_static(self, path):
        target = "index.html" if path in ("/", "") else path.lstrip("/")
        file_path = STATIC_DIR / target
        if not file_path.exists() or not file_path.is_file():
            if path.startswith("/api/"):
                return error_response(self, "Route not found", HTTPStatus.NOT_FOUND)
            file_path = STATIC_DIR / "index.html"
        content_type = "text/plain; charset=utf-8"
        if file_path.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        elif file_path.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif file_path.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        body = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
