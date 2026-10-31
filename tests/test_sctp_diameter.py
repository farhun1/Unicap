from pathlib import Path

import pytest

from unipcap.capture import analyze, sctp_diameter_ports, to_dict

CAP = Path(__file__).parents[1] / "samples" / "CGW_2.pcap"
SGS = Path(__file__).parents[1] / "samples" / "150_20261029222428444_115014.pcap"


@pytest.mark.skipif(not CAP.exists(), reason="capture not in checkout")
def test_cgw2_ppid0_sctp_carries_gy():
    # Ground truth: tshark -d sctp.port==2660-2663,diameter -> 27 CCR + 27 CCA, app 4
    d = to_dict(analyze(CAP))
    assert "DIAMETER" in dict(d["protocols"])
    assert d["overview"]["gy"]["given_octets"] == 614400000    # 6 CCA x 102400000
    assert d["overview"]["gy"]["reported_octets"] == 6865503256
    assert d["overview"]["negative"]["Diameter"] == [["4010", 21]]
    assert not any("SCTP DATA frames not decoded" in w for w in d["warnings"])


@pytest.mark.skipif(not SGS.exists(), reason="capture not in checkout")
def test_sgsap_port_29118_not_hijacked_for_diameter():
    # 29118's PPID-0 chunks are SGsAP (tshark decodes them natively by port); forcing diameter
    # would turn them into undecoded SCTP DATA instead of matching raw tshark
    assert sctp_diameter_ports(SGS) == []
