from unipcap.roles import Node, RoleInference


def row(n=1, src="10.0.0.1", dst="10.0.0.2", protocols="eth:ethertype:ip:udp",
        fields: dict[str, str] | None = None) -> dict[str, str]:
    r = {"frame.number": str(n), "frame.protocols": protocols, "ip.src": src, "ip.dst": dst}
    return r | (fields or {})


def infer(*rows) -> tuple[dict[str, Node], list[str]]:
    ri = RoleInference()
    for r in rows:
        ri.add(r)
    return {n.ip: n for n in ri.nodes()}, ri.warnings
