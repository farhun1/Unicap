import json
import subprocess
import sys
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


def test_cli_analyze_without_out_shows_a_notice(monkeypatch):
    # ap.error writes the usage to stderr, which the windowed exe does not have
    seen = []
    monkeypatch.setattr(app, "_notify", seen.append)
    assert app.main(["--analyze", str(FIXTURE)]) == 2
    assert seen and "--analyze requires --out" in seen[0]


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


def test_main_reports_an_out_of_range_port(monkeypatch):
    seen = []
    monkeypatch.setattr(app, "find_tshark", lambda: FIXTURE)
    monkeypatch.setattr(app, "_notify", seen.append)
    assert app.main(["--port", "70000", "--no-browser"]) == 1
    assert seen and "Cannot start UniPCAP" in seen[0]


def test_module_entry_point_runs(tmp_path):
    out = tmp_path / "m.json"
    r = subprocess.run([sys.executable, "-m", "unipcap.app", "--analyze", str(FIXTURE),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0 and out.is_file()
    assert json.loads(out.read_text(encoding="utf-8"))["file"]["frames"] == 1


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
