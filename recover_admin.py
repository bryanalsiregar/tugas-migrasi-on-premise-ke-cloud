import getpass
import sqlite3

import app


def main():
    app.ensure_dirs()
    app.init_db()

    username = input("Username to recover [admin]: ").strip() or "admin"
    new_password = getpass.getpass("New password [admin]: ").strip() or "admin"
    full_name = input("Display name [System Administrator]: ").strip() or "System Administrator"
    role = input("Role [Super Admin]: ").strip() or "Super Admin"

    conn = app.get_db()
    existing = conn.execute(
        "SELECT id FROM admin_users WHERE username = ?",
        (username,),
    ).fetchone()

    if existing:
        conn.execute(
            """
            UPDATE admin_users
            SET full_name = ?, password_hash = ?, role = ?, is_active = 1, updated_at = ?
            WHERE id = ?
            """,
            (full_name, app.hash_password(new_password), role, app.utc_now(), existing["id"]),
        )
        action = "updated"
    else:
        now = app.utc_now()
        conn.execute(
            """
            INSERT INTO admin_users (full_name, username, password_hash, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (full_name, username, app.hash_password(new_password), role, now, now),
        )
        action = "created"

    app.sync_lookup(conn, "role", role)
    conn.commit()
    conn.close()
    print(f"Recovery account {action}: {username}")


if __name__ == "__main__":
    main()
