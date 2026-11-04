from pathlib import Path

import pcapgen

from unipcap.roles import Node, RoleInference

# The shared capture fixture is generated, not committed: every capture file type
# is gitignored (see tests/test_user_data_guard.py), so a fresh checkout builds it
# before any test module reads tests/fixtures/gtpv2_csr.pcap.
FIXTURE = pcapgen.ensure_gtpv2_csr_fixture(
    Path(__file__).parent / "fixtures" / pcapgen.FIXTURE_NAME)


def row(n=1, src="10.0.0.1", dst="10.0.0.2", protocols="eth:ethertype:ip:udp",
        fields: dict[str, str] | None = None) -> dict[str, str]:
    r = {"frame.number": str(n), "frame.protocols": protocols, "ip.src": src, "ip.dst": dst}
    return r | (fields or {})


def infer(*rows) -> tuple[dict[str, Node], list[str]]:
    ri = RoleInference()
    for r in rows:
        ri.add(r)
    return {n.ip: n for n in ri.nodes()}, ri.warnings
