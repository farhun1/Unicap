# Portable Browser Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the same portable one-folder app without bundling Wireshark and without pywebview: it requires an installed Wireshark for tshark, serves its UI from a loopback HTTP server, and opens it in the user's default browser.

**Architecture:** `unipcap.exe` starts a stdlib `ThreadingHTTPServer` on `127.0.0.1` with an ephemeral port and a random token path, then `webbrowser.open`s that URL. The existing `web/` assets are served from it. The page POSTs the chosen capture as a raw request body; the server streams it to a `%TEMP%` folder, runs the unchanged `summarise()` pipeline over it, deletes the copy, and answers with the same `{ok, summary|error}` JSON the pywebview API used. The page holds an SSE connection; the process exits `grace` seconds after the last page closes. `find_tshark()` now locates the user's installed Wireshark.

**Tech Stack:** Python 3.12 via `uv`, stdlib `http.server` / `webbrowser` / `secrets`, PyInstaller ≥6 one-folder, pytest, installed Wireshark 4.x, vanilla HTML/JS.

**Spec:** `docs/superpowers/specs/2026-10-29-unipcap-vision.md` (roadmap item 1; this plan revises its *Decoder* and *App shell* decisions)

## Global Constraints

- Python 3.12 (`>=3.12,<3.13`). Runtime code uses only the stdlib; `pywebview` is removed from `pyproject.toml` and `uv.lock`.
- Windows x64 target; keep the code cross-platform (`sys.platform == "win32"` guards only where unavoidable).
- Portable: no installer, nothing written outside the app folder except `%TEMP%`. The app never edits the input capture; the uploaded temp copy is deleted in a `finally`.
- Wireshark is a prerequisite, not a bundled payload: `UNIPCAP_TSHARK` → `PATH` → `%ProgramFiles%\Wireshark`, then `%ProgramFiles(x86)%\Wireshark`.
- The HTTP server binds `127.0.0.1` only, and every data path (static files, analyze, SSE) requires the per-run token; only `GET /ping` is token-free.
- The windowed exe has `sys.stderr is None`: no handler may log or print. HTTP request logging and server error printing are suppressed.
- pytest config has `filterwarnings = ["error::ResourceWarning"]`: every server, socket, connection and thread in tests is closed or joined.
- tshark invocation rules are unchanged: `-n`, list args (no shell), isolated `WIRESHARK_CONFIG_DIR`.

## Review Focus

1. **Wireshark installed to its default location but not on `PATH`** (the normal install): still found and analysis works. → Task 1 `test_finds_wireshark_in_program_files`.
2. **Wireshark missing entirely**: the UI says to install Wireshark and links wireshark.org; no traceback, no silent empty dashboard. → Task 2 `test_analyze_without_tshark_reports_install_hint`, Task 3 `test_main_refuses_to_start_without_tshark`.
3. **A large capture's copy in `%TEMP%` is removed after every request, including failed ones** (a 1 GB trace must not leave 1 GB behind). → Task 2 `test_analyze_upload_returns_summary`, `test_analyze_unicode_filename_and_cleanup`.
4. **Closing the last tab (or never opening one) ends the process**; no orphan `unipcap.exe`. → Task 2 `test_events_counts_viewers`, `test_wait_returns_after_the_last_viewer_leaves`, `test_wait_gives_up_when_no_browser_opens`.
5. **Another local process or web page reaches the server**: a wrong token is 403, `..` traversal is blocked, the socket is loopback-only. → Task 2 `test_wrong_token_forbidden`, `test_traversal_blocked`, `test_bound_to_loopback`.

---

## File Structure

```
src/unipcap/tshark.py        find_tshark(): installed Wireshark; bundle_root() deleted in Task 3
src/unipcap/capture.py       + summarise(): Path -> dashboard dict, raises on bad input
src/unipcap/serve.py         NEW: loopback server (static UI, /ping, /events SSE, /analyze upload), Server
src/unipcap/app.py           main(): CLI + startup checks + server + default browser; Api/pywebview deleted
src/unipcap/web/index.html   hidden <input type="file">
src/unipcap/web/app.js       file input -> fetch upload; EventSource keepalive
tests/test_tshark.py         discovery tests
tests/test_capture.py        summarise tests
tests/test_serve.py          NEW: routing, upload, token, traversal, SSE, wait()
tests/test_app.py            main() wiring tests; pywebview tests deleted
scripts/build.ps1            no vendor data
scripts/smoke.ps1            installed tshark + /ping check
scripts/vendor_*.ps1         DELETED
pyproject.toml, uv.lock      pywebview removed
THIRD_PARTY.md               no redistributed binaries
docs/.../specs/...vision.md  Decoder / App shell decisions updated
```

---

### Task 1: Resolve tshark from the installed Wireshark

**Files:**
- Modify: `src/unipcap/tshark.py:24-33` (`find_tshark`)
- Test: `tests/test_tshark.py:7-24`

**Interfaces:**
- Consumes: nothing new.
- Produces: `find_tshark() -> pathlib.Path`. Lookup order: `UNIPCAP_TSHARK` (must be an existing file) → `shutil.which("tshark")` → `Path(programfiles)/"Wireshark"/"tshark.exe"` for `ProgramFiles` then `ProgramFiles(x86)`. On failure raises `TsharkNotFound(INSTALL_HINT)` where `INSTALL_HINT` starts `"tshark not found."` and contains `"https://www.wireshark.org/download.html"`.
- `bundle_root()` stays until Task 3 (still used by `app.py`).

- [ ] **Step 1: Write the failing tests**

Replace `tests/test_tshark.py` lines 7-24 (the three lookup tests) with:

```python
def test_env_override_wins(tmp_path, monkeypatch):
    exe = tmp_path / "tshark.exe"; exe.write_bytes(b"")
    monkeypatch.setenv("UNIPCAP_TSHARK", str(exe))
    assert find_tshark() == exe


def test_found_on_path(tmp_path, monkeypatch):
    monkeypatch.delenv("UNIPCAP_TSHARK", raising=False)
    monkeypatch.setattr("unipcap.tshark.shutil.which", lambda _: str(tmp_path / "tshark.exe"))
    assert find_tshark() == tmp_path / "tshark.exe"


def test_finds_wireshark_in_program_files(tmp_path, monkeypatch):
    exe = tmp_path / "Wireshark" / "tshark.exe"
    exe.parent.mkdir(parents=True); exe.write_bytes(b"")
    monkeypatch.delenv("UNIPCAP_TSHARK", raising=False)
    monkeypatch.setattr("unipcap.tshark.shutil.which", lambda _: None)
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    assert find_tshark() == exe


def test_not_found_names_the_install_fix(tmp_path, monkeypatch):
    monkeypatch.delenv("UNIPCAP_TSHARK", raising=False)
    monkeypatch.setattr("unipcap.tshark.shutil.which", lambda _: None)
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    with pytest.raises(TsharkNotFound, match="wireshark.org"):
        find_tshark()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_tshark.py -q -k "lookup or env or path or program or not_found"`
Expected: `test_finds_wireshark_in_program_files` and `test_not_found_names_the_install_fix` FAIL (bundled path is gone and the message does not mention wireshark.org).

- [ ] **Step 3: Rewrite `find_tshark` in `src/unipcap/tshark.py`**

Delete the bundled-lookup lines and the vendor path in the error message; keep `bundle_root` for now.

```python
INSTALL_HINT = ("tshark not found. Install Wireshark from "
                "https://www.wireshark.org/download.html, or set UNIPCAP_TSHARK "
                "to the full path of tshark.exe")


def find_tshark() -> Path:
    env = os.environ.get("UNIPCAP_TSHARK")
    if env and Path(env).is_file():
        return Path(env)
    if found := shutil.which("tshark"):
        return Path(found)
    for var in ("ProgramFiles", "ProgramFiles(x86)"):
        if d := os.environ.get(var):
            p = Path(d) / "Wireshark" / "tshark.exe"
            if p.is_file():
                return p
    raise TsharkNotFound(INSTALL_HINT)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_tshark.py -q`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/unipcap/tshark.py tests/test_tshark.py
git commit -m "feat: resolve tshark from an installed Wireshark

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `summarise()` in `capture.py` and the loopback server

**Files:**
- Modify: `src/unipcap/capture.py` (add `summarise` after `to_dict`; import `Path` already present)
- Modify: `src/unipcap/app.py` (`Api.analyze` calls `summarise`; `_summarise` deleted)
- Create: `src/unipcap/serve.py`
- Test: `tests/test_capture.py`, `tests/test_serve.py`

**Interfaces:**
- Produces: `capture.summarise(path: Path) -> dict` — `to_dict(analyze(path))`; raises `FileNotFoundError("File not found: <path>")` when missing, `ValueError("Not a packet capture: <name>")` when tshark returns frames with no timestamps.
- Produces: `serve.Server(port: int = 0)`:
  - `httpd: ThreadingHTTPServer` (already bound), `port: int` (property → `httpd.server_port`), `url: str` (property → `"http://127.0.0.1:<port>/t/<token>/"`), `viewers: int` (property, lock-guarded),
  - `start() -> None` (daemon thread running `serve_forever`), `wait(startup_timeout: float = 120.0, grace: float = 3.0) -> None`, `close() -> None` (`shutdown()` then `server_close()`).
- HTTP contract (token = `server.token`, 16+ random URL-safe chars):
  | Request | Body | Response |
  |---|---|---|
  | `GET /ping` | – | 204, empty (token not required; used by the packaged smoke test) |
  | `GET {url}<file>` | – | static file from `src/unipcap/web`; `/` serves `index.html` |
  | `GET {url}events` | – | 200 `text/event-stream`; writes `": keepalive\n\n"` every 3 s until the client disconnects |
  | `POST {url}analyze` | raw capture bytes | 200 `application/json`, `Cache-Control: no-store`: `{"ok": true, "summary": …}` or `{"ok": false, "error": "…"}` |
  | anything under `{url}` with a wrong/missing token | – | 403 |
- `POST analyze` reads `X-Filename` (percent-encoded original name), streams the body to `%TEMP%\unipcap-upload-<rand>\<basename>`, calls `summarise`, deletes the folder in `finally`. `log_message` and the server's `handle_error` are no-ops (windowed exe has no stderr).

- [ ] **Step 1: Write the failing `summarise` tests**

Append to `tests/test_capture.py` (add `import pytest` and `summarise` to its imports):

```python
def test_summarise_returns_the_dashboard_dict():
    d = summarise(FIXTURE)
    assert d["file"]["frames"] == 1 and d["file"]["name"] == "gtpv2_csr.pcap"


def test_summarise_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="File not found"):
        summarise(tmp_path / "gone.pcap")


def test_summarise_rejects_timestamp_less_frames(tmp_path):
    p = tmp_path / "x.txt"; p.write_text("nope")
    with pytest.raises(ValueError, match="Not a packet capture: x.txt"):
        summarise(p)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_capture.py -q -k summarise`
Expected: FAIL with `ImportError: cannot import name 'summarise'`.

- [ ] **Step 3: Add `summarise` to `src/unipcap/capture.py`**

```python
def summarise(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    d = to_dict(analyze(path))
    # tshark "reads" some non-captures (e.g. text sniffed as MP4) as timestamp-less frames
    if d["file"]["frames"] and d["file"]["start"] is None:
        raise ValueError(f"Not a packet capture: {path.name}")
    return d
```

In `src/unipcap/app.py`, delete `_summarise`, import `summarise` from `.capture`, and make `Api.analyze` call `summarise(Path(path))`.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/test_capture.py tests/test_app.py -q`
Expected: all PASS.

- [ ] **Step 5: Write the failing server tests**

Create `tests/test_serve.py`:

```python
import http.client
import json
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import pytest

from unipcap.serve import Server

FIXTURE = Path(__file__).parent / "fixtures" / "gtpv2_csr.pcap"


@pytest.fixture
def server():
    s = Server()
    s.start()
    try:
        yield s
    finally:
        s.close()


def call(s, method, suffix, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", s.port, timeout=30)
    try:
        conn.request(method, urlsplit(s.url).path + suffix, body=body, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def wait_for(predicate, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def upload_dirs():
    return set(Path(tempfile.gettempdir()).glob("unipcap-upload-*"))


def test_bound_to_loopback(server):
    assert server.httpd.server_address[0] == "127.0.0.1"


def test_index_served_under_the_token(server):
    status, body = call(server, "GET", "")
    assert status == 200 and b"UniPCAP" in body


def test_wrong_token_forbidden(server):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    try:
        conn.request("GET", "/t/not-the-token/")
        assert conn.getresponse().status == 403
    finally:
        conn.close()


def test_traversal_blocked(server):
    status, body = call(server, "GET", "%2e%2e/%2e%2e/pyproject.toml")
    assert status in (403, 404) and b"hatchling" not in body


def test_ping_is_204(server):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    try:
        conn.request("GET", "/ping")
        assert conn.getresponse().status == 204
    finally:
        conn.close()


def test_analyze_upload_returns_summary(server):
    before = upload_dirs()
    status, body = call(server, "POST", "analyze", FIXTURE.read_bytes(),
                        {"X-Filename": "gtpv2_csr.pcap"})
    assert status == 200
    d = json.loads(body)
    assert d["ok"] and d["summary"]["file"]["frames"] == 1
    assert any(n["ip"] == "10.5.0.1" and n["roles"] == ["PGW"] for n in d["summary"]["nodes"])
    assert upload_dirs() == before


def test_analyze_unicode_filename_and_cleanup(server):
    before = upload_dirs()
    status, body = call(server, "POST", "analyze", b"nope",
                        {"X-Filename": quote("ক রহিম.txt")})
    d = json.loads(body)
    assert status == 200 and d["ok"] is False
    assert "Not a packet capture: ক রহিম.txt" in d["error"]
    assert upload_dirs() == before


def test_analyze_without_tshark_reports_install_hint(server, monkeypatch):
    from unipcap.tshark import TsharkNotFound

    def missing():
        raise TsharkNotFound("tshark not found. Install Wireshark from "
                             "https://www.wireshark.org/download.html")

    monkeypatch.setattr("unipcap.tshark.find_tshark", missing)
    status, body = call(server, "POST", "analyze", FIXTURE.read_bytes(),
                        {"X-Filename": "a.pcap"})
    d = json.loads(body)
    assert d["ok"] is False and "wireshark.org" in d["error"]


def open_events(server):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=30)
    conn.request("GET", urlsplit(server.url).path + "events")
    return conn, conn.getresponse()


def test_events_counts_viewers(server):
    conn, r = open_events(server)
    assert r.status == 200 and r.getheader("Content-Type") == "text/event-stream"
    assert r.readline() == b": keepalive\n"
    assert wait_for(lambda: server.viewers == 1)
    conn.close()
    assert wait_for(lambda: server.viewers == 0, 10)


def test_wait_gives_up_when_no_browser_opens(server):
    t0 = time.monotonic()
    server.wait(startup_timeout=0.3)
    assert time.monotonic() - t0 < 3


def test_wait_returns_after_the_last_viewer_leaves(server):
    conn, r = open_events(server)
    r.readline()
    done = threading.Event()
    t = threading.Thread(target=lambda: (server.wait(startup_timeout=5, grace=0.3), done.set()),
                         daemon=True)
    t.start()
    try:
        time.sleep(1)
        assert not done.is_set()
    finally:
        conn.close()
    assert done.wait(10)
```

- [ ] **Step 6: Run to verify they fail**

Run: `uv run pytest tests/test_serve.py -q`
Expected: collection error, `ModuleNotFoundError: No module named 'unipcap.serve'`.

- [ ] **Step 7: Implement `src/unipcap/serve.py`**

```python
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
            rel = self._relative()          # None when the token is missing/wrong
            if rel is None:
                return self._send(403)
            if rel == "events":
                return self._events()
            self.path = "/" + rel.lstrip("/")   # "" -> "/"
            super().do_GET()

        def do_HEAD(self):
            if self._relative() is None:
                return self._send(403)
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
            n = int(self.headers.get("Content-Length") or 0)
            name = Path(unquote(self.headers.get("X-Filename") or "")).name or "upload.pcap"
            tmp = Path(tempfile.mkdtemp(prefix="unipcap-upload-"))
            try:
                dst = tmp / name
                with dst.open("wb") as f:
                    left = n
                    while left > 0:
                        chunk = self.rfile.read(min(left, 1 << 20))
                        if not chunk:
                            break
                        f.write(chunk)
                        left -= len(chunk)
                body = {"ok": True, "summary": summarise(dst)}
            except Exception as e:
                body = {"ok": False, "error": str(e) or type(e).__name__}
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            self._send(200, json.dumps(body).encode("utf-8"),
                       [("Content-Type", "application/json"), ("Cache-Control", "no-store")])

    return Handler


class Server:
    def __init__(self, port: int = 0) -> None:
        self.token = secrets.token_urlsafe(16)
        self._lock = threading.Lock()
        self._viewers = 0
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
            if self.viewers:
                empty_since = time.monotonic()
            elif time.monotonic() - empty_since >= grace:
                return
            time.sleep(0.1)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
```

- [ ] **Step 8: Run the server tests to verify they pass**

Run: `uv run pytest tests/test_serve.py -q`
Expected: all PASS.

- [ ] **Step 9: Run the full suite**

Run: `uv run pytest -q`
Expected: all PASS.

- [ ] **Step 10: Commit**

```bash
git add src/unipcap/capture.py src/unipcap/serve.py src/unipcap/app.py tests/test_capture.py tests/test_serve.py
git commit -m "feat: loopback UI server with upload-to-temp analysis

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Browser shell replaces pywebview

**Files:**
- Modify: `src/unipcap/app.py` (rewrite `main`; delete `Api`, `WEB`, `FILE_TYPES`, `_use_bundled_webview2`)
- Modify: `src/unipcap/tshark.py` (delete `bundle_root`)
- Modify: `src/unipcap/web/index.html`, `src/unipcap/web/app.js`
- Modify: `tests/test_app.py` (delete `Api` and webview tests; add wiring tests)

**Interfaces:**
- Consumes: `serve.Server(port)`, `.url`, `.start()`, `.wait()`, `.close()`; `capture.summarise(Path)`; `tshark.find_tshark()`, `TsharkNotFound`.
- Produces: `app.main(argv: list[str] | None = None) -> int` with flags `--analyze`, `--out`, `--port` (int, default 0), `--no-browser`. Returns 1 and calls `app._notify(msg)` when tshark is missing (`msg` contains "wireshark.org") or when the server cannot start.
- The page keeps the existing `render`/`showError`/`renderSections` functions unchanged; only the open-capture plumbing changes.

- [ ] **Step 1: Write the failing `main()` tests**

Replace `tests/test_app.py` with:

```python
import json
from pathlib import Path

from unipcap import app

FIXTURE = Path(__file__).parent / "fixtures" / "gtpv2_csr.pcap"
WEB = Path(__file__).parents[1] / "src" / "unipcap" / "web"


class FakeServer:
    url = "http://127.0.0.1:1/t/tok/"

    def __init__(self, port):
        self.port = port
        self.closed = False

    def start(self): pass
    def wait(self): pass
    def close(self): self.closed = True


def test_cli_analyze_writes_json(tmp_path):
    out = tmp_path / "s.json"
    assert app.main(["--analyze", str(FIXTURE), "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["file"]["frames"] == 1


def test_cli_analyze_error_goes_to_out_file(tmp_path):
    out = tmp_path / "s.json"
    assert app.main(["--analyze", str(tmp_path / "gone.pcap"), "--out", str(out)]) == 1
    assert json.loads(out.read_text(encoding="utf-8"))["error"]


def test_cli_analyze_text_file_not_a_capture(tmp_path):
    p = tmp_path / "x.txt"; p.write_text("nope")
    out = tmp_path / "s.json"
    assert app.main(["--analyze", str(p), "--out", str(out)]) == 1
    assert "Not a packet capture" in json.loads(out.read_text(encoding="utf-8"))["error"]


def test_main_opens_the_default_browser(monkeypatch):
    opened = []
    monkeypatch.setattr(app, "find_tshark", lambda: FIXTURE)
    monkeypatch.setattr(app, "Server", FakeServer)
    monkeypatch.setattr(app.webbrowser, "open", lambda url: opened.append(url) or True)
    assert app.main([]) == 0
    assert opened == [FakeServer.url]


def test_main_no_browser_skips_open(monkeypatch):
    opened = []
    monkeypatch.setattr(app, "find_tshark", lambda: FIXTURE)
    monkeypatch.setattr(app, "Server", FakeServer)
    monkeypatch.setattr(app.webbrowser, "open", lambda url: opened.append(url) or True)
    assert app.main(["--no-browser"]) == 0
    assert opened == []


def test_main_falls_back_to_a_notice_when_the_browser_fails(monkeypatch):
    seen = []
    monkeypatch.setattr(app, "find_tshark", lambda: FIXTURE)
    monkeypatch.setattr(app, "Server", FakeServer)
    monkeypatch.setattr(app.webbrowser, "open", lambda url: False)
    monkeypatch.setattr(app, "_notify", seen.append)
    assert app.main([]) == 0
    assert seen and FakeServer.url in seen[0]


def test_main_refuses_to_start_without_tshark(monkeypatch):
    from unipcap.tshark import TsharkNotFound
    seen = []
    monkeypatch.setattr(app, "find_tshark", lambda: (_ for _ in ()).throw(
        TsharkNotFound("tshark not found. Install Wireshark from "
                       "https://www.wireshark.org/download.html")))
    monkeypatch.setattr(app, "_notify", seen.append)
    assert app.main([]) == 1
    assert seen and "wireshark.org" in seen[0]


def test_main_reports_startup_failure(monkeypatch):
    def boom(port):
        raise OSError("in use")
    seen = []
    monkeypatch.setattr(app, "find_tshark", lambda: FIXTURE)
    monkeypatch.setattr(app, "Server", boom)
    monkeypatch.setattr(app, "_notify", seen.append)
    assert app.main(["--no-browser"]) == 1
    assert seen and "Cannot start UniPCAP" in seen[0]


def test_web_assets_use_the_browser_api():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert "pywebview" not in js and 'fetch("analyze"' in js and 'new EventSource("events")' in js
    assert 'type="file"' in html
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_app.py -q`
Expected: FAIL (`_notify`/`find_tshark` missing, `main` still launches pywebview).

- [ ] **Step 3: Rewrite `src/unipcap/app.py`**

```python
import argparse
import json
import sys
import webbrowser
from pathlib import Path

from .capture import summarise
from .serve import Server
from .tshark import TsharkNotFound, find_tshark


def _notify(msg: str) -> None:
    """Windowed exe has no console; a message box is the only way to show a fatal error."""
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, msg, "UniPCAP", 0x10)
    elif sys.stderr:
        print(msg, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="unipcap")
    ap.add_argument("--analyze", metavar="PCAP")
    ap.add_argument("--out", metavar="JSON")
    ap.add_argument("--port", type=int, default=0, help="local UI port (0 = pick a free one)")
    ap.add_argument("--no-browser", action="store_true", help="serve the UI without opening a browser")
    a = ap.parse_args(argv)
    if a.analyze:
        # windowed exe has no stdout, so results (and errors) go to a file
        if not a.out:
            ap.error("--analyze requires --out")
        try:
            data, rc = summarise(Path(a.analyze)), 0
        except Exception as e:
            data, rc = {"error": str(e) or type(e).__name__}, 1
        Path(a.out).write_text(json.dumps(data), encoding="utf-8")
        return rc
    try:
        find_tshark()
    except TsharkNotFound as e:
        _notify(str(e))
        return 1
    try:
        server = Server(port=a.port)
    except OSError as e:
        _notify(f"Cannot start UniPCAP on port {a.port}: {e}")
        return 1
    server.start()
    if not a.no_browser and not webbrowser.open(server.url):
        _notify(f"Open this URL in your browser:\n{server.url}")
    try:
        server.wait()
    finally:
        server.close()
    return 0
```

Delete `Api`, `_use_bundled_webview2`, `WEB`, `FILE_TYPES`, and the `webview` import. In `src/unipcap/tshark.py`, delete `bundle_root` (no users remain).

- [ ] **Step 4: Update the web assets**

`src/unipcap/web/index.html`: add after the button:

```html
  <input id="picker" type="file" accept=".pcap,.pcapng,.cap,.gz" hidden>
```

`src/unipcap/web/app.js`: replace everything from `async function openCapture()` (line 105) to the end with:

```js
async function analyzeFile(file) {
  const btn = document.getElementById("open");
  const status = document.getElementById("status");
  btn.disabled = true;
  status.textContent = "Analyzing… large captures can take minutes";
  try {
    const r = await fetch("analyze", {
      method: "POST",
      body: file,
      headers: { "X-Filename": encodeURIComponent(file.name) },
    });
    const d = await r.json();
    if (d.ok) render(d.summary);
    else showError(d.error);
  } catch (e) {
    showError(String(e));
  } finally {
    btn.disabled = false;
    status.textContent = "";
  }
}

const picker = document.getElementById("picker");
document.getElementById("open").addEventListener("click", () => picker.click());
picker.addEventListener("change", () => {
  const f = picker.files[0];
  picker.value = "";
  if (f) analyzeFile(f);
});

// Holds the local server open while this page is open; it exits `grace` seconds after the last page closes.
new EventSource("events");
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest -q`
Expected: all tests PASS, including `test_web_assets_use_the_browser_api`.

- [ ] **Step 6: Verify in a real browser**

Run: `uv run python -m unipcap`
Expected: the default browser opens `http://127.0.0.1:<port>/t/<token>/` showing "Open capture"; choosing `tests/fixtures/gtpv2_csr.pcap` shows 1 frame, 1 GTPv2 protocol chip and a Packet core section with `10.5.0.1 PGW`; closing the tab ends the Python process within ~10 s (the console prompt returns).

- [ ] **Step 7: Commit**

```bash
git add src/unipcap/app.py src/unipcap/tshark.py src/unipcap/web/index.html src/unipcap/web/app.js tests/test_app.py
git commit -m "feat: serve the UI to the default browser instead of pywebview

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Packaging, smoke test and docs

**Files:**
- Modify: `pyproject.toml`, `uv.lock` (regenerated), `scripts/build.ps1`, `scripts/smoke.ps1`, `THIRD_PARTY.md`, `docs/superpowers/specs/2026-10-29-unipcap-vision.md`
- Delete: `scripts/vendor_wireshark.ps1`, `scripts/vendor_webview2.ps1`

**Interfaces:**
- Consumes: `--no-browser`, `--port`, `GET /ping` from Task 3.
- Produces: a `dist/unipcap/` folder containing no `vendor/` directory; `scripts/smoke.ps1` exits 0 printing `SMOKE PASS`.

- [ ] **Step 1: Drop pywebview from the package**

`pyproject.toml`: `dependencies = []`. Then regenerate the lock:

Run: `uv lock && uv sync`
Expected: `uv.lock` no longer lists `pywebview`/`pythonnet`/`clr-loader`.

- [ ] **Step 2: Delete the vendor scripts**

```bash
git rm scripts/vendor_wireshark.ps1 scripts/vendor_webview2.ps1
```

- [ ] **Step 3: Rewrite `scripts/build.ps1`**

```powershell
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$pa = @("--noconfirm", "--windowed", "--name", "unipcap",
    "--add-data", "src/unipcap/web;unipcap/web")
uv run pyinstaller @pa --paths src scripts/launch.py
if ($LASTEXITCODE) { throw "pyinstaller failed" }
Copy-Item THIRD_PARTY.md dist\unipcap\ -Force
```

- [ ] **Step 4: Rewrite `THIRD_PARTY.md`**

```markdown
# Third-party components

UniPCAP redistributes no third-party binaries. It requires **Wireshark / tshark**
(GPL-2.0-or-later, https://www.wireshark.org/download.html) to be installed on
the machine; all protocol decoding is done by that tshark.
```

- [ ] **Step 5: Rewrite `scripts/smoke.ps1`**

```powershell
Set-Location (Join-Path $PSScriptRoot "..")
function Fail($m) { Write-Host "SMOKE FAIL: $m"; throw $m }
$dir = Join-Path $env:TEMP "unipcap smoke রহিম"
$out = Join-Path $env:TEMP "smoke.json"
$port = Get-Random -Minimum 20000 -Maximum 60000
$gui = $null
$oldPath = $env:PATH
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item dist\unipcap $dir -Recurse
try {
    if (-not (Test-Path (Join-Path $dir "THIRD_PARTY.md"))) { Fail "missing THIRD_PARTY.md" }
    if (Test-Path (Join-Path $dir "_internal\vendor")) { Fail "vendor folder still bundled" }
    Remove-Item $out -ErrorAction SilentlyContinue
    # minimal PATH and no override: proves the installed Wireshark is found without a bundled copy
    $env:PATH = "C:\Windows\System32"
    Remove-Item Env:UNIPCAP_TSHARK -ErrorAction SilentlyContinue
    $p = Start-Process (Join-Path $dir unipcap.exe) -ArgumentList "--analyze", (Resolve-Path tests\fixtures\gtpv2_csr.pcap), "--out", $out -PassThru
    if (-not $p.WaitForExit(120000)) { Stop-Process $p -Force; Fail "headless run timed out" }
    if ($p.ExitCode -ne 0) { Fail "exit code $($p.ExitCode)" }
    $j = Get-Content $out -Raw -Encoding UTF8 | ConvertFrom-Json
    $n = $j.nodes | Where-Object { $_.ip -eq "10.5.0.1" }
    if (-not $n -or $n.roles -notcontains "PGW") { Fail "10.5.0.1 PGW missing" }
    Write-Host "headless OK"

    # browser UI: the loopback server must answer /ping
    $gui = Start-Process (Join-Path $dir unipcap.exe) -ArgumentList "--no-browser", "--port", $port -PassThru
    $r = $null
    $deadline = (Get-Date).AddSeconds(20)
    while (-not $r -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        try { $r = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/ping" -TimeoutSec 2 } catch { }
    }
    if (-not $r -or $r.StatusCode -ne 204) { Fail "UI server did not answer /ping within 20 s" }
    Write-Host "GUI server OK"
    Write-Host "SMOKE PASS"
} catch {
    Write-Host "SMOKE FAIL: $_"
    exit 1
} finally {
    $env:PATH = $oldPath
    if ($gui) { & taskkill.exe /F /T /PID $gui.Id *> $null }
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
```

- [ ] **Step 6: Update the vision spec's decisions**

In `docs/superpowers/specs/2026-10-29-unipcap-vision.md`, change the table rows:

- `Decoder` → `Require an installed Wireshark: find tshark via UNIPCAP_TSHARK, then PATH, then C:\Program Files\Wireshark. Nothing third-party is bundled.`
- `App shell` → `Python stdlib http.server on 127.0.0.1 (random token path) opened in the user's default browser; PyInstaller one-folder build.`
- Roadmap item 1: `portable shell, installed tshark, …` (remove "bundled tshark").

- [ ] **Step 7: Build and smoke-test the portable bundle**

Run: `powershell -ExecutionPolicy Bypass -File scripts/build.ps1`
Expected: build succeeds and `dist\unipcap\` has no `vendor` folder.

Run: `powershell -ExecutionPolicy Bypass -File scripts/smoke.ps1`
Expected: `headless OK`, `GUI server OK`, `SMOKE PASS`.

- [ ] **Step 8: Run the full suite once more**

Run: `uv run pytest -q`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml uv.lock scripts/build.ps1 scripts/smoke.ps1 THIRD_PARTY.md docs/superpowers/specs/2026-10-29-unipcap-vision.md
git commit -m "build: portable bundle with system tshark and browser UI

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Out of scope (named, not built)

- Drag-and-drop of a capture onto the page (F6 polish; the file input covers it).
- Opening a capture from `argv`/"Open with" without the temp copy.
- Any progress bar for the upload; the status line already carries the "can take minutes" hint.
