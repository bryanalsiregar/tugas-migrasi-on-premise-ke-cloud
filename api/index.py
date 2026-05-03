import threading

from app import InventoryHandler, init_db

_DB_READY = False
_DB_LOCK = threading.Lock()


def ensure_db_ready():
    global _DB_READY
    if _DB_READY:
        return
    with _DB_LOCK:
        if _DB_READY:
            return
        init_db()
        _DB_READY = True


class handler(InventoryHandler):
    def do_GET(self):
        ensure_db_ready()
        super().do_GET()

    def do_POST(self):
        ensure_db_ready()
        super().do_POST()

    def do_PUT(self):
        ensure_db_ready()
        super().do_PUT()

    def do_DELETE(self):
        ensure_db_ready()
        super().do_DELETE()
