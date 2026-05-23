import threading
import webbrowser
from http.server import ThreadingHTTPServer

from .config import HOST, PORT, app_url
from .db import init_db
from .handler import InventoryHandler

BROWSER_OPENED = False
BROWSER_LOCK = threading.Lock()


def open_browser_once():
    global BROWSER_OPENED
    with BROWSER_LOCK:
        if BROWSER_OPENED:
            return
        BROWSER_OPENED = True
    threading.Timer(1.0, lambda: webbrowser.open(app_url())).start()


def create_server():
    init_db()
    return ThreadingHTTPServer((HOST, PORT), InventoryHandler)


def run_server(open_browser=True):
    server = create_server()
    print(f"Portable IT Inventory running at {app_url()}")
    print("Default login: admin / admin")
    if open_browser:
        open_browser_once()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.server_close()


def main():
    run_server(open_browser=True)
