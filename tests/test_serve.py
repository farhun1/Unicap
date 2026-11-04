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
        r = conn.getresponse()
        assert r.status == 204
        assert r.getheader("Content-Length") is None  # RFC 7230 forbids it on 204
    finally:
        conn.close()


def test_head_serves_the_ui_paths_like_get(server):
    for path in ("", "app.js"):
        status, body = call(server, "HEAD", path)
        assert status == 200 and body == b""


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


def test_analyze_error_hides_the_staging_path(server):
    before = upload_dirs()
    status, body = call(server, "POST", "analyze", bytes(range(256)) * 4,
                        {"X-Filename": "junk.bin"})
    d = json.loads(body)
    assert status == 200 and d["ok"] is False
    assert "unipcap-upload-" not in d["error"] and "junk.bin" in d["error"]
    assert upload_dirs() == before


def test_analyze_success_hides_the_staging_path(server):
    status, body = call(server, "POST", "analyze", FIXTURE.read_bytes(),
                        {"X-Filename": "gtpv2_csr.pcap"})
    d = json.loads(body)
    assert d["ok"] and d["summary"]["file"]["path"] == "gtpv2_csr.pcap"
    assert b"unipcap-upload-" not in body  # the browser only ever sees the chosen name


def test_analyze_oserror_hides_the_staging_path(server):
    # OSError embeds the filename through repr(), so Windows paths arrive with doubled
    # backslashes; a single-spelling replace misses them and leaks the temp directory
    status, body = call(server, "POST", "analyze", FIXTURE.read_bytes(),
                        {"X-Filename": "x" * 300 + ".pcap"})
    d = json.loads(body)
    assert d["ok"] is False
    assert b"unipcap-upload-" not in body


def test_analyze_dotdot_filename_is_not_treated_as_a_directory(server):
    status, body = call(server, "POST", "analyze", FIXTURE.read_bytes(),
                        {"X-Filename": quote("..")})
    d = json.loads(body)
    assert d["ok"] and d["summary"]["file"]["path"] == "upload.pcap"


def test_analyze_warnings_hide_the_staging_path(server, monkeypatch):
    def fake(path):
        return {"file": {"path": str(path), "name": path.name},
                "warnings": [f'tshark: The file "{path}" appears to have been cut short']}

    monkeypatch.setattr("unipcap.serve.summarise", fake)
    status, body = call(server, "POST", "analyze", b"x", {"X-Filename": "cut.pcap"})
    d = json.loads(body)
    assert d["ok"] is True
    assert b"unipcap-upload-" not in body
    assert d["summary"]["warnings"] == [
        'tshark: The file "cut.pcap" appears to have been cut short']


def test_analyze_cut_short_upload_still_returns_a_summary(server, tmp_path):
    import pcapgen  # tests dir is on sys.path (see tests/test_capture.py)

    p = pcapgen.write(tmp_path / "t.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x")] * 5)
    p.write_bytes(p.read_bytes()[:-50])
    status, body = call(server, "POST", "analyze", p.read_bytes(), {"X-Filename": "t.pcap"})
    d = json.loads(body)
    assert d["ok"] and d["summary"]["file"]["frames"] == 4
    assert d["summary"]["file"]["path"] == "t.pcap"
    assert len(d["summary"]["warnings"]) == 1 and "cut short" in d["summary"]["warnings"][0]
    assert b"unipcap-upload-" not in body


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
    r.close()  # HTTPConnection.close() keeps the fd open while the response's fp lives
    conn.close()
    assert wait_for(lambda: server.viewers == 0, 10)


def test_wait_gives_up_when_no_browser_opens(server):
    t0 = time.monotonic()
    server.wait(startup_timeout=0.3)
    assert time.monotonic() - t0 < 3


def test_wait_waits_for_an_in_flight_analysis(server, monkeypatch):
    monkeypatch.setattr("unipcap.serve.KEEPALIVE", 0.05)
    release = threading.Event()

    def slow(path):
        release.wait(15)
        raise ValueError("boom")

    monkeypatch.setattr("unipcap.serve.summarise", slow)
    conn, r = open_events(server)
    r.readline()
    before = upload_dirs()
    poster = threading.Thread(target=call, args=(server, "POST", "analyze", b"x"),
                              kwargs={"headers": {"X-Filename": "big.pcap"}}, daemon=True)
    poster.start()
    assert wait_for(lambda: upload_dirs() != before)  # the copy exists, analysis still running
    r.close()
    conn.close()
    assert wait_for(lambda: server.viewers == 0)
    done = threading.Event()
    threading.Thread(target=lambda: (server.wait(startup_timeout=5, grace=0.2), done.set()),
                     daemon=True).start()
    try:
        assert not done.wait(1)  # the handler still owns a temp copy; the process must not exit
    finally:
        release.set()
    assert done.wait(10)
    poster.join(10)
    assert upload_dirs() == before


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
        r.close()
        conn.close()
    assert done.wait(10)


def test_app_js_serves_ladder_tabs(server):
    status, body = call(server, "GET", "app.js")
    assert status == 200 and b"ladder-tabs" in body and b"ladder-empty" in body
    # empty-tab notice must stay inside the panel: body keeps at least one row's height
    assert b"Math.max(tabRows.length, 1)" in body
    # tab bar stays pinned while scrolling: tabs + node header share a sticky wrapper
    assert b"ladder-stick" in body
    status, css = call(server, "GET", "style.css")
    assert status == 200 and b".ladder-stick" in css


def test_css_node_boxes_anchor_inside_ladder_head(server):
    # .ladder-node boxes are absolute with top: 4px; without a positioned
    # .ladder-head they anchor to the sticky wrapper and overlay the tab row
    status, css = call(server, "GET", "style.css")
    assert status == 200 and b".ladder-head { position: relative; height: 44px" in css


def test_app_js_serves_overview_tab(server):
    status, body = call(server, "GET", "app.js")
    assert status == 200 and b"Overview" in body and b"renderOverview" in body
    assert b"Negative responses" in body
    assert b"!ld && !ov" in body  # DNS-only capture must still show the panel
    status, css = call(server, "GET", "style.css")
    assert status == 200 and b".ov-card" in css


def test_app_js_renders_absent_quota_as_dash(server):
    status, body = call(server, "GET", "app.js")
    assert status == 200 and b'const quota = (x) => (x ? humanBytes(x) : "\xe2\x80\x94")' in body


def test_app_js_detail_rows_pass_kids_in_kids_slot(server):
    # kv() must pass its spans as kids; in the text slot they coerce to "[object HTMLSpanElement]"
    status, body = call(server, "GET", "app.js")
    assert status == 200
    assert b'h("div", "ld-row", null, [h("span", "ld-k", k), h("span", "ld-v", v)])' in body
