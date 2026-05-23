import base64
import ctypes
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

import app

try:
    import webview
except ImportError:
    webview = None


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class NativeDialogs:
    def __init__(self):
        self.window = None

    def attach(self, window):
        self.window = window

    def open_csv_file(self):
        if not self.window:
            return None
        result = self.window.create_file_dialog(
            webview.FileDialog.OPEN,
            allow_multiple=False,
            file_types=("CSV files (*.csv)",),
        )
        if not result:
            return None
        path = Path(result[0])
        return {"name": path.name, "text": path.read_text(encoding="utf-8-sig")}

    def save_file(self, suggested_name, content_b64):
        if not self.window:
            return None
        suffix = Path(suggested_name).suffix.lower()
        label = "CSV files (*.csv)" if suffix == ".csv" else "PDF files (*.pdf)" if suffix == ".pdf" else "All files (*.*)"
        result = self.window.create_file_dialog(
            webview.FileDialog.SAVE,
            save_filename=suggested_name,
            file_types=(label,),
        )
        if not result:
            return None
        path = Path(result[0])
        path.write_bytes(base64.b64decode(content_b64))
        return str(path)


def wait_for_server(timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(app.app_url(), timeout=1):
                return True
        except Exception:
            time.sleep(0.2)
    return False


def initial_window_size():
    # Use the Windows work area so the app does not sit under the taskbar.
    try:
        rect = RECT()
        if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0):
            work_width = rect.right - rect.left
            work_height = rect.bottom - rect.top
            width = max(1100, min(1360, work_width - 80))
            height = max(720, min(860, work_height - 80))
            return width, height
    except Exception:
        pass
    return 1280, 780


def main():
    server = app.create_server()
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    if not wait_for_server():
        server.shutdown()
        server.server_close()
        raise RuntimeError("The local server did not start in time.")

    try:
        if webview:
            bridge = NativeDialogs()
            width, height = initial_window_size()
            window = webview.create_window(
                "IT Inventory Manager",
                app.app_url(),
                js_api=bridge,
                width=width,
                height=height,
                min_size=(1100, 720),
            )
            bridge.attach(window)
            webview.start()
        else:
            webbrowser.open(app.app_url())
            while True:
                time.sleep(1)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
