import os
import sys
from datetime import datetime
from pathlib import Path

APP_DIR = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent.parent
)
RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))


def _load_env_file(path):
    if not path.exists() or not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if value and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


# Load local env files before reading runtime config values.
_load_env_file(APP_DIR / ".env")
if Path.cwd() != APP_DIR:
    _load_env_file(Path.cwd() / ".env")

STATIC_DIR = RESOURCE_DIR / "static"
DATA_DIR = Path(os.environ.get("IT_INVENTORY_DATA_DIR", str(APP_DIR / "data")))
DB_PATH = DATA_DIR / "inventory.db"
HOST = "127.0.0.1"
PORT = int(os.environ.get("IT_INVENTORY_PORT", "8000"))
IT_INVENTORY_PG_URL = os.environ.get("IT_INVENTORY_PG_URL", "").strip()
SYNC_CONNECT_TIMEOUT = int(os.environ.get("IT_INVENTORY_SYNC_CONNECT_TIMEOUT", "10"))
SYNC_JOB_KEEP_SECONDS = int(os.environ.get("IT_INVENTORY_SYNC_JOB_KEEP_SECONDS", "86400"))

LOOKUP_FIELD_MAP = {
    "category": ("assets", "category"),
    "device_name": ("assets", "device_name"),
    "brand": ("assets", "brand"),
    "model": ("assets", "model"),
    "location": ("assets", "location"),
    "status": ("assets", "status"),
    "condition": ("assets", "condition"),
    "department": ("people", "department"),
    "person_location": ("people", "location"),
    "role": ("admin_users", "role"),
}

EXPORT_CONFIG = {
    "assets": {
        "title": "Assets Report",
        "landscape": True,
        "columns": [
            {"key": "asset_tag", "label": "Asset Tag", "weight": 1.0},
            {"key": "device_name", "label": "Device", "weight": 1.4},
            {"key": "category", "label": "Category", "weight": 1.0},
            {"key": "brand", "label": "Brand", "weight": 0.9},
            {"key": "model", "label": "Model", "weight": 1.1},
            {"key": "serial_number", "label": "Serial Number", "weight": 1.2},
            {"key": "status", "label": "Status", "weight": 0.9},
            {"key": "condition", "label": "Condition", "weight": 0.9},
            {"key": "location", "label": "Location", "weight": 1.0},
            {"key": "holder_name", "label": "Assigned To", "weight": 1.2},
        ],
    },
    "people": {
        "title": "Users Report",
        "landscape": False,
        "columns": [
            {"key": "full_name", "label": "Full Name", "weight": 1.3},
            {"key": "department", "label": "Department", "weight": 1.0},
            {"key": "email", "label": "Email", "weight": 1.4},
            {"key": "phone", "label": "Phone", "weight": 0.9},
            {"key": "location", "label": "Location", "weight": 1.0},
            {"key": "notes", "label": "Notes", "weight": 1.4},
        ],
    },
    "admins": {
        "title": "Admin Users Report",
        "landscape": False,
        "columns": [
            {"key": "full_name", "label": "Full Name", "weight": 1.3},
            {"key": "username", "label": "Username", "weight": 1.0},
            {"key": "role", "label": "Role", "weight": 1.0},
            {"key": "is_active", "label": "Active", "weight": 0.7},
        ],
    },
    "assignments": {
        "title": "Assignments Report",
        "landscape": True,
        "columns": [
            {"key": "asset_tag", "label": "Asset Tag", "weight": 1.0},
            {"key": "person_name", "label": "Assigned To", "weight": 1.2},
            {"key": "admin_name", "label": "Assigned By", "weight": 1.1},
            {"key": "assigned_at", "label": "Assigned At", "weight": 1.0},
            {"key": "returned_at", "label": "Returned At", "weight": 1.0},
            {"key": "notes", "label": "Check-out Notes", "weight": 1.4},
            {"key": "return_notes", "label": "Check-in Notes", "weight": 1.4},
        ],
    },
}

def utc_now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def ensure_dirs():
    DATA_DIR.mkdir(exist_ok=True)
    STATIC_DIR.mkdir(exist_ok=True)


def app_url():
    return f"http://{HOST}:{PORT}"
