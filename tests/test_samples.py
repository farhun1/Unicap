import json
from pathlib import Path

import pytest

from unipcap.capture import analyze

SAMPLES = Path(__file__).parents[1] / "samples"


def collect_cases(root=SAMPLES):
    """Expected.json cases; CI has no captures, so missing ones are skipped."""
    for exp in sorted(root.glob("*.expected.json")):
        cap = exp.with_name(exp.name.removesuffix(".expected.json") + ".pcap")
        yield pytest.param(exp, cap, id=exp.name,
                           marks=[pytest.mark.skipif(not cap.exists(),
                                                     reason="capture not in checkout")])


CASES = list(collect_cases())


@pytest.mark.skipif(not CASES, reason="no samples/*.expected.json")
@pytest.mark.parametrize("exp, cap", CASES)
def test_sample_roles(exp, cap):
    want = json.loads(exp.read_text(encoding="utf-8"))
    nodes = analyze(cap).nodes
    for role, ips in want.items():
        if role != "not":
            assert set(ips) <= {n.ip for n in nodes if role in n.roles}, role
    for role, ips in want.get("not", {}).items():
        assert not set(ips) & {n.ip for n in nodes if role in n.roles}, f"not {role}"


def test_collection_skips_expectations_whose_capture_is_absent(tmp_path):
    (tmp_path / "a.expected.json").write_text("{}")
    (tmp_path / "b.expected.json").write_text("{}")
    (tmp_path / "b.pcap").write_bytes(b"")
    cases = {c.id: c for c in collect_cases(tmp_path)}
    a, b = cases["a.expected.json"], cases["b.expected.json"]
    assert a.marks[0].args[0] is True
    assert a.marks[0].kwargs["reason"] == "capture not in checkout"
    assert b.marks[0].args[0] is False
