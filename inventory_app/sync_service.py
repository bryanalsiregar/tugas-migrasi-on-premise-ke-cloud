import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone

from .config import IT_INVENTORY_PG_URL, SYNC_CONNECT_TIMEOUT, SYNC_JOB_KEEP_SECONDS, utc_now
from .db import get_db

SYNC_LOCK = threading.Lock()
SYNC_JOBS = {}
ACTIVE_SYNC_JOB_ID = None

TABLE_SPECS = [
    {
        "name": "analytics_people",
        "label": "people",
        "source_table": "people",
        "select_sql": """
            SELECT
                id,
                full_name,
                department,
                email,
                phone,
                location,
                notes,
                created_at AS source_created_at,
                updated_at AS source_updated_at
            FROM people
            ORDER BY id
        """,
        "data_columns": [
            "full_name",
            "department",
            "email",
            "phone",
            "location",
            "notes",
            "source_created_at",
            "source_updated_at",
        ],
        "ddl_columns": [
            "full_name TEXT NOT NULL",
            "department TEXT NOT NULL",
            "email TEXT",
            "phone TEXT",
            "location TEXT",
            "notes TEXT",
            "source_created_at TEXT",
            "source_updated_at TEXT",
        ],
    },
    {
        "name": "analytics_assets",
        "label": "assets",
        "source_table": "assets",
        "select_sql": """
            SELECT
                id,
                asset_tag,
                device_name,
                category,
                brand,
                model,
                serial_number,
                status,
                condition,
                purchase_date,
                warranty_end,
                location,
                notes,
                current_holder_id AS current_holder_local_id,
                created_at AS source_created_at,
                updated_at AS source_updated_at
            FROM assets
            ORDER BY id
        """,
        "data_columns": [
            "asset_tag",
            "device_name",
            "category",
            "brand",
            "model",
            "serial_number",
            "status",
            "condition",
            "purchase_date",
            "warranty_end",
            "location",
            "notes",
            "current_holder_local_id",
            "source_created_at",
            "source_updated_at",
        ],
        "ddl_columns": [
            "asset_tag TEXT NOT NULL",
            "device_name TEXT NOT NULL",
            "category TEXT NOT NULL",
            "brand TEXT",
            "model TEXT",
            "serial_number TEXT",
            "status TEXT NOT NULL",
            "condition TEXT NOT NULL",
            "purchase_date TEXT",
            "warranty_end TEXT",
            "location TEXT",
            "notes TEXT",
            "current_holder_local_id BIGINT",
            "source_created_at TEXT",
            "source_updated_at TEXT",
        ],
    },
    {
        "name": "analytics_assignments",
        "label": "assignments",
        "source_table": "assignments",
        "select_sql": """
            SELECT
                id,
                asset_id AS asset_local_id,
                person_id AS person_local_id,
                assigned_by_admin_id AS assigned_by_admin_local_id,
                assigned_at,
                returned_at,
                notes,
                return_notes
            FROM assignments
            ORDER BY id
        """,
        "data_columns": [
            "asset_local_id",
            "person_local_id",
            "assigned_by_admin_local_id",
            "assigned_at",
            "returned_at",
            "notes",
            "return_notes",
        ],
        "ddl_columns": [
            "asset_local_id BIGINT NOT NULL",
            "person_local_id BIGINT NOT NULL",
            "assigned_by_admin_local_id BIGINT NOT NULL",
            "assigned_at TEXT NOT NULL",
            "returned_at TEXT",
            "notes TEXT",
            "return_notes TEXT",
        ],
    },
    {
        "name": "analytics_lookup_values",
        "label": "lookup values",
        "source_table": "lookup_values",
        "select_sql": """
            SELECT
                id,
                kind,
                value,
                created_at AS source_created_at,
                updated_at AS source_updated_at
            FROM lookup_values
            ORDER BY id
        """,
        "data_columns": [
            "kind",
            "value",
            "source_created_at",
            "source_updated_at",
        ],
        "ddl_columns": [
            "kind TEXT NOT NULL",
            "value TEXT NOT NULL",
            "source_created_at TEXT",
            "source_updated_at TEXT",
        ],
    },
]


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def start_sync_job():
    _cleanup_old_jobs()
    with SYNC_LOCK:
        global ACTIVE_SYNC_JOB_ID
        if ACTIVE_SYNC_JOB_ID:
            active_job = SYNC_JOBS.get(ACTIVE_SYNC_JOB_ID)
            if active_job and active_job["state"] in {"queued", "running"}:
                raise RuntimeError("A sync job is already running")
        job_id = uuid.uuid4().hex
        started_at = utc_now()
        SYNC_JOBS[job_id] = {
            "job_id": job_id,
            "state": "queued",
            "percent": 0,
            "step": "Queued",
            "processed_rows": 0,
            "total_rows": 0,
            "message": "Sync job queued",
            "error": None,
            "started_at": started_at,
            "finished_at": None,
            "_updated_epoch": time.time(),
        }
        ACTIVE_SYNC_JOB_ID = job_id
    worker = threading.Thread(target=_run_sync_job, args=(job_id,), daemon=True)
    worker.start()
    return {"job_id": job_id, "started_at": started_at}


def get_sync_status(job_id):
    _cleanup_old_jobs()
    with SYNC_LOCK:
        job = SYNC_JOBS.get(job_id)
        if not job:
            return None
        return _public_status(job)


def _public_status(job):
    return {
        "job_id": job["job_id"],
        "state": job["state"],
        "percent": int(job.get("percent", 0)),
        "step": job.get("step", ""),
        "processed_rows": int(job.get("processed_rows", 0)),
        "total_rows": int(job.get("total_rows", 0)),
        "message": job.get("message", ""),
        "error": job.get("error"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
    }


def _cleanup_old_jobs():
    with SYNC_LOCK:
        now = time.time()
        expired = []
        for job_id, job in SYNC_JOBS.items():
            if job["state"] in {"queued", "running"}:
                continue
            if now - job.get("_updated_epoch", now) > SYNC_JOB_KEEP_SECONDS:
                expired.append(job_id)
        for job_id in expired:
            SYNC_JOBS.pop(job_id, None)


def _update_job(job_id, **updates):
    with SYNC_LOCK:
        job = SYNC_JOBS.get(job_id)
        if not job:
            return
        job.update(updates)
        total_rows = int(job.get("total_rows") or 0)
        processed_rows = int(job.get("processed_rows") or 0)
        if total_rows > 0:
            progress = int((processed_rows * 100) / total_rows)
            job["percent"] = min(100, max(job.get("percent", 0), progress))
        elif job.get("state") == "success":
            job["percent"] = 100
        job["_updated_epoch"] = time.time()


def _set_active_job_done(job_id):
    with SYNC_LOCK:
        global ACTIVE_SYNC_JOB_ID
        if ACTIVE_SYNC_JOB_ID == job_id:
            ACTIVE_SYNC_JOB_ID = None


def _run_sync_job(job_id):
    pg_conn = None
    run_row_created = False
    run_id = job_id
    try:
        _update_job(job_id, state="running", step="Preparing local data", message="Preparing local snapshot")
        pg_url = IT_INVENTORY_PG_URL or os.environ.get("IT_INVENTORY_PG_URL", "").strip()
        if not pg_url:
            raise RuntimeError("IT_INVENTORY_PG_URL is not configured")

        with get_db() as sqlite_conn:
            sqlite_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sync_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            device_id, hostname = _ensure_device_identity(sqlite_conn)
            table_counts = _collect_table_counts(sqlite_conn)

        total_rows = sum(table_counts.values())
        _update_job(
            job_id,
            total_rows=total_rows,
            processed_rows=0,
            percent=0,
            step="Connecting to PostgreSQL",
            message=f"Device {hostname}",
        )

        try:
            import psycopg
        except Exception as exc:
            raise RuntimeError(
                "Missing PostgreSQL dependency. Install requirements to enable sync."
            ) from exc

        pg_conn = psycopg.connect(pg_url, connect_timeout=SYNC_CONNECT_TIMEOUT)
        with pg_conn.cursor() as cursor:
            _ensure_postgres_schema(cursor)
            cursor.execute(
                """
                INSERT INTO sync_devices (device_id, hostname, first_seen_at, last_seen_at)
                VALUES (%s, %s, NOW(), NOW())
                ON CONFLICT (device_id) DO UPDATE
                SET hostname = EXCLUDED.hostname,
                    last_seen_at = NOW()
                """,
                (device_id, hostname),
            )
            cursor.execute(
                """
                INSERT INTO sync_runs (run_id, device_id, started_at, status, message, stats_json)
                VALUES (%s, %s, NOW(), %s, %s, %s::jsonb)
                """,
                (run_id, device_id, "running", "Sync in progress", json.dumps({})),
            )
            run_row_created = True
        pg_conn.commit()

        processed_rows = 0
        stats = {"device_id": device_id, "hostname": hostname, "tables": {}}
        with get_db() as sqlite_conn:
            for spec in TABLE_SPECS:
                _update_job(
                    job_id,
                    step=f"Syncing {spec['label']}",
                    message=f"Uploading {spec['label']}",
                )
                rows = [dict(row) for row in sqlite_conn.execute(spec["select_sql"]).fetchall()]
                table_stats = _sync_table(pg_conn, spec, rows, device_id, run_id)
                stats["tables"][spec["name"]] = table_stats
                processed_rows += table_stats["upserted"]
                _update_job(job_id, processed_rows=processed_rows)

        with pg_conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE sync_runs
                SET finished_at = NOW(),
                    status = %s,
                    message = %s,
                    stats_json = %s::jsonb
                WHERE run_id = %s
                """,
                ("success", "Sync completed", json.dumps(stats), run_id),
            )
        pg_conn.commit()
        _update_job(
            job_id,
            state="success",
            step="Completed",
            processed_rows=total_rows,
            percent=100,
            message="Sync completed successfully",
            error=None,
            finished_at=utc_now(),
        )
    except Exception as exc:
        error_message = str(exc)
        if pg_conn is not None and run_row_created:
            try:
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE sync_runs
                        SET finished_at = NOW(),
                            status = %s,
                            message = %s,
                            stats_json = %s::jsonb
                        WHERE run_id = %s
                        """,
                        ("failed", error_message, json.dumps({"error": error_message}), run_id),
                    )
                pg_conn.commit()
            except Exception:
                pass
        _update_job(
            job_id,
            state="failed",
            step="Failed",
            message="Sync failed",
            error=error_message,
            finished_at=utc_now(),
        )
    finally:
        if pg_conn is not None:
            pg_conn.close()
        _set_active_job_done(job_id)


def _ensure_device_identity(conn):
    device_id_row = conn.execute(
        "SELECT value FROM sync_metadata WHERE key = ?",
        ("device_id",),
    ).fetchone()
    hostname = socket.gethostname() or "unknown-host"
    if device_id_row:
        device_id = str(device_id_row["value"]).strip()
    else:
        device_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO sync_metadata (key, value, updated_at) VALUES (?, ?, ?)",
            ("device_id", device_id, utc_now()),
        )
    conn.execute(
        """
        INSERT INTO sync_metadata (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        """,
        ("device_hostname", hostname, utc_now()),
    )
    conn.commit()
    return device_id, hostname


def _collect_table_counts(conn):
    counts = {}
    for spec in TABLE_SPECS:
        row = conn.execute(
            f"SELECT COUNT(*) AS total FROM {spec['source_table']}"
        ).fetchone()
        counts[spec["name"]] = int(row["total"])
    return counts


def _ensure_postgres_schema(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_devices (
            device_id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_runs (
            run_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL REFERENCES sync_devices(device_id) ON DELETE CASCADE,
            started_at TIMESTAMPTZ NOT NULL,
            finished_at TIMESTAMPTZ,
            status TEXT NOT NULL,
            message TEXT,
            stats_json JSONB NOT NULL DEFAULT '{}'::jsonb
        )
        """
    )

    for spec in TABLE_SPECS:
        columns = [
            "source_device_id TEXT NOT NULL",
            "source_local_id BIGINT NOT NULL",
            *spec["ddl_columns"],
            "first_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
            "last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
            "last_sync_run_id TEXT NOT NULL",
            "is_deleted BOOLEAN NOT NULL DEFAULT FALSE",
            "deleted_at TIMESTAMPTZ",
            "PRIMARY KEY (source_device_id, source_local_id)",
        ]
        cursor.execute(
            f"CREATE TABLE IF NOT EXISTS {spec['name']} ({', '.join(columns)})"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{spec['name']}_device_deleted "
            f"ON {spec['name']} (source_device_id, is_deleted)"
        )


def _build_upsert_sql(spec):
    insert_columns = [
        "source_device_id",
        "source_local_id",
        *spec["data_columns"],
        "last_sync_run_id",
        "last_synced_at",
        "first_synced_at",
        "is_deleted",
        "deleted_at",
    ]
    placeholders = ", ".join(["%s"] * len(insert_columns))
    update_columns = [
        *[f"{column} = EXCLUDED.{column}" for column in spec["data_columns"]],
        "last_sync_run_id = EXCLUDED.last_sync_run_id",
        "last_synced_at = EXCLUDED.last_synced_at",
        "is_deleted = FALSE",
        "deleted_at = NULL",
    ]
    return (
        f"INSERT INTO {spec['name']} ({', '.join(insert_columns)}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT (source_device_id, source_local_id) DO UPDATE SET "
        + ", ".join(update_columns)
    )


def _sync_table(pg_conn, spec, rows, device_id, run_id):
    synced_at = _utc_now_iso()
    local_ids = []
    values = []
    for row in rows:
        source_local_id = int(row["id"])
        local_ids.append(source_local_id)
        values.append(
            (
                device_id,
                source_local_id,
                *[row.get(column) for column in spec["data_columns"]],
                run_id,
                synced_at,
                synced_at,
                False,
                None,
            )
        )

    with pg_conn.cursor() as cursor:
        if values:
            cursor.executemany(_build_upsert_sql(spec), values)

        if local_ids:
            cursor.execute(
                f"""
                UPDATE {spec['name']}
                SET is_deleted = TRUE,
                    deleted_at = %s,
                    last_synced_at = %s,
                    last_sync_run_id = %s
                WHERE source_device_id = %s
                  AND NOT (source_local_id = ANY(%s::bigint[]))
                  AND is_deleted = FALSE
                """,
                (synced_at, synced_at, run_id, device_id, local_ids),
            )
        else:
            cursor.execute(
                f"""
                UPDATE {spec['name']}
                SET is_deleted = TRUE,
                    deleted_at = %s,
                    last_synced_at = %s,
                    last_sync_run_id = %s
                WHERE source_device_id = %s
                  AND is_deleted = FALSE
                """,
                (synced_at, synced_at, run_id, device_id),
            )
        soft_deleted = max(cursor.rowcount, 0)
    pg_conn.commit()
    return {"upserted": len(values), "soft_deleted": soft_deleted}
