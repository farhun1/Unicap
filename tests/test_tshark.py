import os
import subprocess
import sys
from pathlib import Path

import pytest

import pcapgen
from unipcap.tshark import TsharkError, TsharkNotFound, find_tshark, iter_fields, vals


def test_scratch_profile_directory_is_removed_at_exit():
    # created at import; without cleanup every run leaves an unipcap-ws-* dir in %TEMP%
    code = "import unipcap.tshark as t; print(t._EMPTY_PROFILE)"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    path = Path(r.stdout.strip())
    assert path.name.startswith("unipcap-ws-")
    assert not path.exists()


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


FIELDS = ["frame.number", "ip.src", "udp.dstport", "_ws.col.protocol"]

def test_rows_stream(tmp_path):
    p = pcapgen.write(tmp_path / "a.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1000, 9999, b"x")] * 3)
    rows = list(iter_fields(p, FIELDS))
    assert len(rows) == 3
    assert rows[0] == {"frame.number": "1", "ip.src": "10.0.0.1", "udp.dstport": "9999", "_ws.col.protocol": "UDP"}

def test_display_filter(tmp_path):
    p = pcapgen.write(tmp_path / "a.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 53, b"x"),
                                            pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 9999, b"x")])
    assert len(list(iter_fields(p, FIELDS, "udp.dstport==53"))) == 1

def test_truncated_capture_yields_rows_and_warning(tmp_path):
    p = pcapgen.write(tmp_path / "t.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x" * 100)] * 5)
    p.write_bytes(p.read_bytes()[:-50])
    warnings = []
    rows = list(iter_fields(p, FIELDS, warnings=warnings))
    assert len(rows) == 4 and warnings and "cut short" in warnings[0]

def test_unicode_path_with_spaces(tmp_path):
    d = tmp_path / "My Traces রহিম"; d.mkdir()
    p = pcapgen.write(d / "ক.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x")])
    assert len(list(iter_fields(p, FIELDS))) == 1

def test_non_capture_raises_tsharkerror(tmp_path):
    p = tmp_path / "notes.txt"; p.write_bytes(bytes(range(256)) * 16)  # tshark 4.6 sniffs short plain text as MP4
    with pytest.raises(TsharkError, match="(?i)file format|isn't a capture"):
        list(iter_fields(p, FIELDS))

def test_vals():
    assert vals({"a": "1|2"}, "a") == ["1", "2"] and vals({"a": ""}, "a") == []

def test_early_close_terminates_tshark(tmp_path):
    p = pcapgen.write(tmp_path / "a.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x")] * 50)
    g = iter_fields(p, FIELDS)
    assert next(g)["frame.number"] == "1"
    g.close()


def test_ignores_user_wireshark_profile(tmp_path, monkeypatch):
    prof = tmp_path / "prof"; prof.mkdir()
    (prof / "disabled_protos").write_text("udp"+chr(10))
    monkeypatch.setenv("WIRESHARK_CONFIG_DIR", str(prof))
    p = pcapgen.write(tmp_path / "a.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1000, 9999, b"x")])
    assert next(iter_fields(p, FIELDS))["_ws.col.protocol"] == "UDP"
