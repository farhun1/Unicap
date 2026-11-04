import json
import secrets
import shutil
import tempfile
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .capture import summarise

WEB = Path(__file__).parent / "web"
KEEPALIVE = 3.0


def _scrub(msg: str, paths: tuple[Path, ...], name: str | None) -> str:
    """Drop staging paths from text shown to the browser.

    OSError renders the offending filename through repr(), so on Windows its message
    spells every backslash twice; replacing only the plain spelling would leak it."""
    for path in paths:
        for spelling in (str(path), str(path).replace("\\", "\\\\")):
            msg = msg.replace(spelling, name or "")
    return msg


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # windowed exe has no stderr


def _handler(server: "Server"):
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(WEB), **kw)

        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/ping":
                return self._send(204)
            rel = self._relative()
            if rel is None:
                return self._send(403)
            if rel == "events":
                return self._events()
            self.path = "/" + rel.lstrip("/")
            super().do_GET()

        def do_HEAD(self):
            rel = self._relative()
            if rel is None:
                return self._send(403)
            self.path = "/" + rel.lstrip("/")
            super().do_HEAD()

        def do_POST(self):
            if self._relative() != "analyze":
                return self._send(403)
            self._analyze()

        def _relative(self):
            prefix = f"/t/{server.token}/"
            return self.path[len(prefix):] if self.path.startswith(prefix) else None

        def _send(self, code, body=b"", headers=()):
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            if code != 204:  # RFC 7230 forbids Content-Length on 204
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _events(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with server._lock:
                server._viewers += 1
                server._ever = True
            try:
                while True:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    time.sleep(KEEPALIVE)
            except OSError:
                pass
            finally:
                with server._lock:
                    server._viewers -= 1

        def _analyze(self):
            tmp = dst = name = None
            with server._lock:
                server._active += 1
            try:
                n = int(self.headers.get("Content-Length") or 0)
                name = Path(unquote(self.headers.get("X-Filename") or "")).name or "upload.pcap"
                if name in (".", ".."):  # Path.name keeps both, but neither can name an uploaded file
                    name = "upload.pcap"
                tmp = Path(tempfile.mkdtemp(prefix="unipcap-upload-"))
                dst = tmp / name
                with dst.open("wb") as f:
                    left = n
                    while left > 0:
                        chunk = self.rfile.read(min(left, 1 << 20))
                        if not chunk:
                            break
                        f.write(chunk)
                        left -= len(chunk)
                summary = summarise(dst)
                # the browser never needs the staging path: report the name the user chose
                summary["file"]["path"] = name
                for i, warn in enumerate(summary["warnings"]):
                    summary["warnings"][i] = _scrub(warn, (dst, tmp), name)
                body = {"ok": True, "summary": summary}
            except Exception as e:
                msg = str(e) or type(e).__name__
                if tmp is not None:  # never show the staging path, only the name the user chose
                    msg = _scrub(msg, tuple(p for p in (dst, tmp) if p is not None), name)
                body = {"ok": False, "error": msg}
            finally:
                if tmp is not None:
                    shutil.rmtree(tmp, ignore_errors=True)
                with server._lock:
                    server._active -= 1
            self._send(200, json.dumps(body).encode("utf-8"),
                       [("Content-Type", "application/json"), ("Cache-Control", "no-store")])

    return Handler


class Server:
    def __init__(self, port: int = 0) -> None:
        self.token = secrets.token_urlsafe(16)
        self._lock = threading.Lock()
        self._viewers = 0
        self._active = 0  # in-flight analyze requests; their temp copy must outlive the last viewer
        self._ever = False
        self.httpd = _Server(("127.0.0.1", port), _handler(self))

    @property
    def port(self) -> int:
        return self.httpd.server_port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/t/{self.token}/"

    @property
    def viewers(self) -> int:
        with self._lock:
            return self._viewers

    def start(self) -> None:
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def wait(self, startup_timeout: float = 120.0, grace: float = 3.0) -> None:
        end = time.monotonic() + startup_timeout
        while not self._ever:
            if time.monotonic() >= end:
                return
            time.sleep(0.1)
        empty_since = time.monotonic()
        while True:
            with self._lock:
                busy = self._viewers > 0 or self._active > 0
            if busy:
                empty_since = time.monotonic()
            elif time.monotonic() - empty_since >= grace:
                return
            time.sleep(0.1)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
