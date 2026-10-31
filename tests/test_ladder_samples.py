import subprocess
from collections import Counter
from pathlib import Path

import pytest

from unipcap.capture import analyze
from unipcap.ladder import clean_info
from unipcap.tshark import find_tshark

SAMPLES = Path(__file__).parents[1] / "samples"


@pytest.mark.skipif(not (SAMPLES / "merged.pcap").exists(), reason="capture not in checkout")
def test_merged_ladder():
    s = analyze(SAMPLES / "merged.pcap")
    msgs = s.ladder.messages
    assert msgs and any(m.decode for m in msgs)
    assert any(p in {m.proto for m in msgs} for p in ("DIAMETER", "GTPv2", "S1AP"))
    assert s.ladder.pairs and s.ladder.bursts
    # Diameter req/ans pairing must survive real tshark Boolean spellings ("True"/"False")
    assert any(msgs[a].proto == "DIAMETER" for a, _ in s.ladder.pairs), \
        "expected Diameter request/response pairs in merged.pcap"


@pytest.mark.skipif(not (SAMPLES / "Testing_With_Dedicated_Bearer.pcap").exists(),
                    reason="capture not in checkout")
def test_dedicated_bearer_gtpv2_matches_raw_tshark():
    # Update Bearer (97/98) lives here; ladder names and pairs must equal raw tshark exactly
    cap = SAMPLES / "Testing_With_Dedicated_Bearer.pcap"
    s = analyze(cap)
    names = Counter(m.name for m in s.ladder.messages if m.proto == "GTPv2")
    rows = subprocess.run([str(find_tshark()), "-n", "-r", str(cap), "-Y", "gtpv2",
                           "-T", "fields", "-e", "_ws.col.info", "-e", "gtpv2.response_to"],
                          capture_output=True, text=True).stdout.splitlines()
    raw_names, linked = Counter(), 0
    for r in rows:
        info, rt = r.split("\t")
        raw_names[clean_info(info)] += 1
        linked += bool(rt)
    assert names == raw_names
    pairs = sum(1 for i, j in s.ladder.pairs
                if s.ladder.messages[i].proto == "GTPv2" and s.ladder.messages[j].proto == "GTPv2")
    assert pairs == linked
    for n in ("Create Session Request", "Create Session Response", "Modify Bearer Request",
              "Modify Bearer Response", "Update Bearer Request", "Update Bearer Response"):
        assert names[n] > 0


@pytest.mark.skipif(not SAMPLES.exists(), reason="samples not in checkout")
def test_sample_sm_ladder_sip_camel():
    for p in SAMPLES.glob("Sample_SM/RecordQueryFlowChart_*/pcap/export_*.pcap"):
        protos = {m.proto for m in analyze(p).ladder.messages}
        if protos & {"SIP", "CAMEL"}:
            return  # one hit is enough; don't analyze all 16 reference exports
    pytest.fail("no SIP/CAMEL messages in any Sample_SM capture")
