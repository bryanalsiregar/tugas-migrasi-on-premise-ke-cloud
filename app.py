from inventory_app.auth import hash_password
from inventory_app.config import app_url, ensure_dirs, utc_now
from inventory_app.db import get_db, init_db, sync_lookup
from inventory_app.handler import InventoryHandler
from inventory_app.server import create_server, main, run_server

__all__ = [
    "InventoryHandler",
    "app_url",
    "create_server",
    "ensure_dirs",
    "get_db",
    "hash_password",
    "init_db",
    "main",
    "run_server",
    "sync_lookup",
    "utc_now",
]


if __name__ == "__main__":
    main()
