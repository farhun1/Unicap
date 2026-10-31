import json
import subprocess
import tracemalloc
from pathlib import Path

import pcapgen
import pytest

from unipcap import roles
from unipcap.capture import (FIELDS, analyze, sctp_diameter_ports, sctp_retrans_proto, summarise,
                             to_dict, undecoded_sctp)
from unipcap.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "gtpv2_csr.pcap"


def test_fields_exist_in_bundled_tshark():
    out = subprocess.run([find_tshark(), "-G", "fields"], capture_output=True, text=True, encoding="utf-8").stdout
    known = {l.split("\t")[2] for l in out.splitlines() if l.startswith("F\t")}
    missing = [f for f in ["frame.time_epoch", *roles.FIELDS] if not f.startswith("_ws.col.") and f not in known]
    assert missing == []


def test_gtpv2_csr_end_to_end():
    s = analyze(FIXTURE)
    nodes = {n.ip: n for n in s.nodes}
    assert nodes["10.3.0.1"].roles == {"MME"} and nodes["10.5.0.1"].roles == {"PGW"}
    assert s.protocols["GTPv2"] == 1


def test_to_dict_is_json_serialisable():
    d = json.loads(json.dumps(to_dict(analyze(FIXTURE))))
    assert d["file"]["frames"] == 1 and d["file"]["name"] == "gtpv2_csr.pcap"
    assert d["protocols"] == [["GTPv2", 1]]


def test_empty_capture(tmp_path):
    s = analyze(pcapgen.write(tmp_path / "e.pcap", []))
    assert s.frames == 0 and s.nodes == [] and s.first_epoch is None
    assert to_dict(s)["file"]["start"] is None


def test_out_of_order_timestamps_span(tmp_path):
    f = pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x")
    s = analyze(pcapgen.write(tmp_path / "o.pcap", [f] * 3, times=[10, 5, 7]))
    assert (s.first_epoch, s.last_epoch) == (1_700_000_005, 1_700_000_010)


def test_undecoded_sctp_warning(tmp_path):
    f = pcapgen.sctp_data("10.0.0.1", "10.0.0.2", 2641, 2641, ppid=0, payload=b"x" * 20)
    s = analyze(pcapgen.write(tmp_path / "s.pcap", [f]))
    assert any("SCTP DATA frames not decoded" in w and "2641" in w for w in s.warnings)


def test_analyze_decodes_sctp_ppid0_diameter(tmp_path):
    f = pcapgen.sctp_data("10.0.0.1", "10.0.0.2", 13201, 2660, 0, pcapgen.diameter_ccr())
    s = analyze(pcapgen.write(tmp_path / "ccr.pcap", [f]))
    assert s.protocols["DIAMETER"] == 1
    assert to_dict(s)["overview"]["gy"]["reported_octets"] == 1024
    assert not any("SCTP DATA frames not decoded" in w for w in s.warnings)


def test_sctp_diameter_ports_skips_natively_decoded(monkeypatch, tmp_path):
    # PPID 0 on 29118 decodes natively as SGsAP (port fallback); forcing diameter would hide it
    rows = [{"sctp.srcport": "29118", "sctp.dstport": "29118", "sctp.data_payload_proto_id": "0",
             "frame.protocols": "eth:ethertype:ip:sctp:sgsap"},
            {"sctp.srcport": "2660", "sctp.dstport": "2660", "sctp.data_payload_proto_id": "0",
             "frame.protocols": "eth:ethertype:ip:sctp:data"}]
    monkeypatch.setattr("unipcap.capture.iter_fields", lambda *a, **k: iter(rows))
    assert sctp_diameter_ports(tmp_path / "x.pcap") == ["2660"]


def test_analyze_memory_bounded(tmp_path):
    p = pcapgen.write(tmp_path / "big.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x" * 64)] * 200_000)
    tracemalloc.start()
    analyze(p)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 30_000_000


def test_undecoded_sctp_ignores_retransmissions():
    base = {"sctp.data_payload_proto_id": "18", "frame.protocols": "eth:ethertype:ip:sctp"}
    assert "sctp.retransmission" in FIELDS
    assert undecoded_sctp(base)
    assert not undecoded_sctp(base | {"sctp.retransmission": "1"})


def test_sctp_retrans_proto_table_and_learned():
    row = {"sctp.data_payload_proto_id": "18", "sctp.srcport": "36412", "sctp.dstport": "36412"}
    assert sctp_retrans_proto(row, {}) == "S1AP"
    learned = {("18", frozenset(("36412", "36412"))): "Diameter"}  # operator runs Diameter on PPID 18
    assert sctp_retrans_proto(row, learned) == "Diameter"
    assert sctp_retrans_proto(row | {"sctp.data_payload_proto_id": "9"}, {}) is None


def test_analyze_decodes_sctp_retransmissions_as_payload_protocol(tmp_path):
    f = pcapgen.sctp_data("10.0.0.1", "10.0.0.2", 2641, 2641, ppid=46, payload=b"x" * 20, tsn=7)
    s = analyze(pcapgen.write(tmp_path / "d.pcap", [f, f]))
    assert s.protocols["Diameter"] == 1 and s.protocols["SCTP"] == 1
    nodes = {n.ip: n for n in s.nodes}
    assert nodes["10.0.0.1"].protocols["Diameter"] == 1
    # garbage payload: retrans appears via the PPID table, but nothing dissects it
    assert [m.proto for m in s.ladder.messages] == ["DIAMETER"]
    assert s.ladder.messages[0].decode is None


def test_fractional_times(tmp_path):
    f = pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x")
    s = analyze(pcapgen.write(tmp_path / "f.pcap", [f, f], times=[0.25, 1.5]))
    assert round(s.last_epoch - s.first_epoch, 3) == 1.25


def test_analyze_skips_sctp_retransmissions(tmp_path):
    f = pcapgen.sctp_data("10.0.0.1", "10.0.0.2", 2641, 2641, ppid=0, payload=b"x" * 20, tsn=7)
    s = analyze(pcapgen.write(tmp_path / "r.pcap", [f, f]))
    assert any(w.startswith("1 SCTP DATA frames not decoded") for w in s.warnings)
    assert s.ladder.messages == []  # PPID 0 is not signalling: never a ladder message


def test_analyze_retransmitted_diameter_in_ladder_with_decode(tmp_path):
    f = pcapgen.sctp_data("10.0.0.1", "10.0.0.2", 2641, 2641, 46, pcapgen.diameter_ccr(), tsn=7)
    s = analyze(pcapgen.write(tmp_path / "ccr2.pcap", [f, f]))
    assert [m.proto for m in s.ladder.messages] == ["DIAMETER", "DIAMETER"]
    retrans = next(m for m in s.ladder.messages if "retransmission" in m.name)
    assert retrans.decode is not None and "Command Code: Credit-Control (272)" in retrans.decode
    assert s.protocols["DIAMETER"] == 2


def test_analyze_collects_ladder_messages_and_bursts(tmp_path):
    s = analyze(pcapgen.write(tmp_path / "l.pcap",
        [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x"),
         pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"y")]))
    assert len(s.ladder.bursts) == 1 and s.ladder.bursts[0].n == 2
    assert s.ladder.messages == []


def test_analyze_gtpv2_fixture_ladder_has_message_and_decode():
    s = analyze(FIXTURE)
    assert [m.proto for m in s.ladder.messages] == ["GTPv2"]
    assert "Create Session Request" in s.ladder.messages[0].name
    assert s.ladder.messages[0].decode is not None


def test_to_dict_includes_ladder():
    d = json.loads(json.dumps(to_dict(analyze(FIXTURE))))
    assert d["ladder"]["messages"][0]["proto"] == "GTPv2"
    assert "decode" in d["ladder"]["messages"][0]


def test_to_dict_includes_overview():
    d = json.loads(json.dumps(to_dict(analyze(FIXTURE))))
    assert "dns" in d["overview"] and "gtpu" in d["overview"]
    assert d["overview"]["dns"]["answer_rate_pct"] is None  # FIXTURE has no DNS


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


def test_fields_have_no_duplicates():
    # roles.FIELDS and overview.FIELDS overlap; tshark must not get a field twice
    assert len(FIELDS) == len(set(FIELDS))
