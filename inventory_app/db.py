import sqlite3

from .auth import hash_password
from .config import DB_PATH, LOOKUP_FIELD_MAP, ensure_dirs, utc_now

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def sync_lookup(conn, kind, value):
    value = str(value or "").strip()
    if not value:
        return
    now = utc_now()
    existing = conn.execute(
        "SELECT id FROM lookup_values WHERE kind = ? AND lower(value) = lower(?)",
        (kind, value),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE lookup_values SET value = ?, updated_at = ? WHERE id = ?",
            (value, now, existing["id"]),
        )
    else:
        conn.execute(
            "INSERT INTO lookup_values (kind, value, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (kind, value, now, now),
        )


def lookup_usage_count(conn, kind, value):
    table, field = LOOKUP_FIELD_MAP[kind]
    return conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE {field} = ?",
        (value,),
    ).fetchone()[0]

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


def init_db():
    ensure_dirs()
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Admin',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS people (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            department TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            location TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_tag TEXT NOT NULL UNIQUE,
            device_name TEXT NOT NULL,
            category TEXT NOT NULL,
            brand TEXT,
            model TEXT,
            serial_number TEXT,
            status TEXT NOT NULL DEFAULT 'Available',
            condition TEXT NOT NULL DEFAULT 'Good',
            purchase_date TEXT,
            warranty_end TEXT,
            location TEXT,
            notes TEXT,
            current_holder_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(current_holder_id) REFERENCES people(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS lookup_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(kind, value)
        );

        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            person_id INTEGER NOT NULL,
            assigned_by_admin_id INTEGER NOT NULL,
            assigned_at TEXT NOT NULL,
            returned_at TEXT,
            return_notes TEXT,
            notes TEXT,
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            FOREIGN KEY(person_id) REFERENCES people(id) ON DELETE CASCADE,
            FOREIGN KEY(assigned_by_admin_id) REFERENCES admin_users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sync_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )

    count = conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
    if count == 0:
        now = utc_now()
        conn.execute(
            """
            INSERT INTO admin_users (full_name, username, password_hash, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            ("System Administrator", "admin", hash_password("admin"), "Super Admin", now, now),
        )
    assets_for_lookup = conn.execute(
        "SELECT DISTINCT category, device_name, brand, model, location, status, condition FROM assets"
    ).fetchall()
    for row in assets_for_lookup:
        sync_lookup(conn, "category", row["category"])
        sync_lookup(conn, "device_name", row["device_name"])
        sync_lookup(conn, "brand", row["brand"])
        sync_lookup(conn, "model", row["model"])
        sync_lookup(conn, "location", row["location"])
        sync_lookup(conn, "status", row["status"])
        sync_lookup(conn, "condition", row["condition"])
    people_for_lookup = conn.execute(
        "SELECT DISTINCT department, location FROM people"
    ).fetchall()
    for row in people_for_lookup:
        sync_lookup(conn, "department", row["department"])
        sync_lookup(conn, "person_location", row["location"])
    admin_roles = conn.execute("SELECT DISTINCT role FROM admin_users").fetchall()
    for row in admin_roles:
        sync_lookup(conn, "role", row["role"])
    conn.commit()
    conn.close()
