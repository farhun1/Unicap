from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from unipcap import ladder, overview, roles
from unipcap.tshark import TsharkError, iter_fields, iter_verbose, vals


@dataclass
class Summary:
    path: str
    frames: int = 0
    first_epoch: float | None = None
    last_epoch: float | None = None
    protocols: Counter[str] = field(default_factory=Counter)
    nodes: list[roles.Node] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # string annotation: in class scope the field name shadows the module (CPython stores the
    # value before evaluating the annotation, so `ladder.Ladder` would see None)
    ladder: "ladder.Ladder | None" = None
    overview: "overview.Overview" = field(default_factory=overview.Overview)


FIELDS = ["frame.time_epoch", "sctp.data_payload_proto_id", "sctp.retransmission",
          "frame.len", "diameter.hopbyhopid", "diameter.endtoendid", "pfcp.seqno",
          "gtpv2.seq", "gtpv2.response_to", "s1ap.procedureCode", "ngap.procedureCode",
          *roles.FIELDS, *overview.FIELDS]
FIELDS = list(dict.fromkeys(FIELDS))  # roles and overview overlap; tshark gets each field once


def undecoded_sctp(row: dict[str, str]) -> bool:
    # retransmissions are never dissected, so they would be false positives
    return bool(row.get("sctp.data_payload_proto_id") and not row.get("sctp.retransmission")
                and row["frame.protocols"].rsplit(":", 1)[-1] in ("sctp", "data"))


def sctp_retrans_proto(row: dict[str, str], learned: dict) -> str | None:
    """Payload protocol of a retransmitted chunk: what its association decodes to elsewhere."""
    ppid = (vals(row, "sctp.data_payload_proto_id") or [""])[0]
    sp, dp = (vals(row, "sctp.srcport") or ["0"])[0], (vals(row, "sctp.dstport") or ["0"])[0]
    return learned.get((ppid, frozenset((sp, dp)))) or ladder.SCTP_PPID_PROTO.get(ppid)


def sctp_diameter_ports(pcap: Path, warnings: list[str] | None = None) -> list[str]:
    """SCTP ports whose DATA chunks are all PPID 0: UGW Gx/Gy rides PPID 0, not 46.
    Only all-PPID-0 ports get a Diameter decode-as rule; a mixed port would hijack its other PPIDs,
    and a port tshark decodes natively despite PPID 0 (SGsAP's 29118 via port fallback) is left alone."""
    ppids: dict[str, set[str]] = {}
    native: set[str] = set()
    for row in iter_fields(pcap, ["sctp.srcport", "sctp.dstport", "sctp.data_payload_proto_id",
                                  "frame.protocols"], display_filter="sctp", warnings=warnings):
        for f in ("sctp.srcport", "sctp.dstport"):
            for p in vals(row, f):
                if p:
                    ppids.setdefault(p, set()).update(
                        v for v in vals(row, "sctp.data_payload_proto_id") if v)
        if row["frame.protocols"].rsplit(":", 1)[-1] not in ("sctp", "data"):
            for f in ("sctp.srcport", "sctp.dstport"):
                native.update(p for p in vals(row, f) if p)
    return sorted((p for p, seen in ppids.items() if seen == {"0"} and p not in native), key=int)


def analyze(pcap: Path) -> Summary:
    s = Summary(str(pcap))
    ri = roles.RoleInference()
    ports: Counter[str] = Counter()
    ppids: set[str] = set()
    undecoded = 0
    retrans: list[dict[str, str]] = []
    learned: dict[tuple[str, frozenset[str]], str] = {}
    l = ladder.Ladder([], [], [], {})
    try:
        decode_as = [f"sctp.port=={p},diameter" for p in sctp_diameter_ports(pcap, s.warnings)]
    except TsharkError as e:
        # a cut-short capture can fail this pre-pass outright when tshark emits no SCTP rows
        # at all; the main pass still yields the frames it could read, so degrade to no decode-as
        s.warnings.append(str(e))
        decode_as = []
    for row in iter_fields(pcap, FIELDS, warnings=s.warnings, decode_as=decode_as):
        s.frames += 1
        if t := row["frame.time_epoch"]:
            t = float(t)
            s.first_epoch = t if s.first_epoch is None else min(s.first_epoch, t)
            s.last_epoch = t if s.last_epoch is None else max(s.last_epoch, t)
        ppid = (vals(row, "sctp.data_payload_proto_id") or [""])[0]
        if ppid and row.get("sctp.retransmission"):
            # tshark skips dissecting retransmitted chunks; classify after the pass
            retrans.append(row)
        else:
            ladder.add_row(l, row, {})
            s.overview.add_row(row)
            s.protocols[row["_ws.col.protocol"]] += 1
            if ppid and row["frame.protocols"].rsplit(":", 1)[-1] not in ("sctp", "data"):
                sp, dp = (vals(row, "sctp.srcport") or ["0"])[0], (vals(row, "sctp.dstport") or ["0"])[0]
                learned[ppid, frozenset((sp, dp))] = row["_ws.col.protocol"]
        if undecoded_sctp(row):
            undecoded += 1
            ppids.update(vals(row, "sctp.data_payload_proto_id"))
            sp, dp = (vals(row, "sctp.srcport") or ["0"])[0], (vals(row, "sctp.dstport") or ["0"])[0]
            ports[min(sp, dp, key=int)] += 1
        ri.add(row)
    for row in retrans:  # signalling retransmissions count for the payload protocol, not SCTP
        proto = sctp_retrans_proto(row, learned) or "SCTP"
        s.protocols[proto] += 1
        ladder.add_row(l, row, learned)  # retrans chunks append out of timestamp order
        src, dst, _, _ = roles.outer_inner(row)
        for ip in (src, dst):
            if ip and ip not in roles.UNSPECIFIED:
                ri.node(ip).protocols[proto] += 1
    l.messages.sort(key=lambda m: m.t)
    l.by_frame = {m.frame: i for i, m in enumerate(l.messages)}
    try:
        # tsn_analysis off: dissect retransmitted chunks too; the main pass keeps it on to defer them
        ladder.attach_decode(l, iter_verbose(pcap, ladder.SIGNALING_FILTER, warnings=s.warnings,
                                             decode_as=decode_as,
                                             options=["sctp.tsn_analysis:FALSE"]))
    except Exception as e:
        if str(e) not in s.warnings:  # an earlier pass may already report the same tshark complaint
            s.warnings.append(f"ladder decode pass failed: {e}")
    ladder.pair(l)
    if l.omitted_messages:
        s.warnings.append(f"{l.omitted_messages} signaling messages omitted from ladder")
    if l.decode_omitted:
        s.warnings.append(f"{l.decode_omitted} message decodes omitted (size budget)")
    s.ladder = l
    s.nodes = ri.nodes()  # resolve first: it rebuilds ri.warnings
    s.warnings += ri.warnings
    if undecoded:
        top = ", ".join(p for p, _ in ports.most_common(5))
        s.warnings.append(f"{undecoded} SCTP DATA frames not decoded (ports {top}; PPID {', '.join(sorted(ppids))})")
    # each tshark pass reports the same complaint (e.g. a cut-short file); keep one banner each
    s.warnings = list(dict.fromkeys(s.warnings))
    return s


def _iso(t: float | None) -> str | None:
    return datetime.fromtimestamp(t, timezone.utc).isoformat() if t is not None else None


def to_dict(s: Summary) -> dict:
    span = None if s.first_epoch is None else round(s.last_epoch - s.first_epoch, 3)
    return {
        "file": {"path": s.path, "name": Path(s.path).name, "frames": s.frames,
                 "start": _iso(s.first_epoch), "end": _iso(s.last_epoch), "duration_s": span},
        "warnings": s.warnings,
        "protocols": [list(p) for p in s.protocols.most_common()],
        "nodes": [{"ip": n.ip, "roles": sorted(n.roles), "interfaces": sorted(n.interfaces),
                   "hostnames": sorted(n.hostnames), "evidence": n.evidence,
                   "protocols": [list(p) for p in n.protocols.most_common()], "frames": n.frames}
                  for n in s.nodes],
        "ladder": ladder.ladder_dict(s.ladder, {n.ip: n for n in s.nodes}),
        "overview": overview.to_dict(s.overview),
    }


def summarise(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    d = to_dict(analyze(path))
    # tshark "reads" some non-captures (e.g. text sniffed as MP4) as timestamp-less frames
    if d["file"]["frames"] and d["file"]["start"] is None:
        raise ValueError(f"Not a packet capture: {path.name}")
    return d
