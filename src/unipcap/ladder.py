from collections.abc import Iterator
from dataclasses import dataclass, field

from unipcap import roles
from unipcap.tshark import vals

SIGNALING_TOKENS = {"s1ap", "ngap", "gtpv2", "pfcp", "diameter", "sip", "camel", "sgsap"}
PROTO_NAMES = {"s1ap": "S1AP", "ngap": "NGAP", "gtpv2": "GTPv2", "pfcp": "PFCP",
               "diameter": "DIAMETER", "sip": "SIP", "camel": "CAMEL", "sgsap": "SGSAP"}
# IANA / 3GPP PPIDs for signalling on retransmitted chunks, undissected in the main pass
SCTP_PPID_PROTO = {"1": "IUA", "2": "M2UA", "3": "M3UA", "4": "SUA", "5": "M2PA",
                   "18": "S1AP", "27": "X2AP", "46": "Diameter", "60": "NGAP"}
SIGNALING_FILTER = "s1ap or ngap or gtpv2 or pfcp or diameter or sip or camel or sgsap"
MESSAGE_CAP = 30_000
DECODE_LIMIT = 12_000  # chars per attached decode
DECODE_BUDGET = 12_000_000  # chars across all decodes
BURST_GAP = 1.0  # seconds; larger gap between two frames of a key starts a new burst


@dataclass
class Message:
    t: float
    frame: int
    src: str
    dst: str
    name: str
    proto: str
    keys: dict
    decode: str | None = None


@dataclass
class Burst:
    t0: float
    t1: float
    src: str
    dst: str
    proto: str
    n: int
    bytes: int


@dataclass
class Ladder:
    messages: list
    bursts: list
    pairs: list
    by_frame: dict
    omitted_messages: int = 0
    decode_omitted: int = 0
    # key -> the one open burst per key; the object also sits in `bursts`
    open_bursts: dict = field(default_factory=dict, repr=False)


def signaling_proto(row: dict[str, str]) -> str | None:
    for tok in row.get("frame.protocols", "").split(":"):
        if tok in SIGNALING_TOKENS:
            return PROTO_NAMES[tok]
    return None


def clean_info(info: str) -> str:
    return info.rstrip().removesuffix(" |")


def message_keys(row: dict[str, str]) -> dict:
    if r := (vals(row, "diameter.hopbyhopid") or [""])[0]:
        req = (vals(row, "diameter.flags.request") or [""])[0]
        return {"hbhid": r, "code": (vals(row, "diameter.cmd.code") or [""])[0],
                "req": {"True": "1", "False": "0"}.get(req, req)}  # tshark prints Booleans as words
    if r := (vals(row, "pfcp.seqno") or [""])[0]:
        return {"seqno": r, "msg": (vals(row, "pfcp.msg_type") or [""])[0]}
    if r := (vals(row, "gtpv2.seq") or [""])[0]:
        # resp_to lets pair() replicate tshark's own request/response linkage exactly
        return {"seq": r, "msg": (vals(row, "gtpv2.message_type") or [""])[0],
                "resp_to": row.get("gtpv2.response_to") or ""}
    if r := (vals(row, "s1ap.procedureCode") or [""])[0]:
        return {"proc": r}
    if r := (vals(row, "ngap.procedureCode") or [""])[0]:
        return {"proc": r}
    return {}


def _message(l: Ladder, row: dict[str, str], src: str, dst: str, proto: str) -> bool:
    if len(l.messages) >= MESSAGE_CAP:
        l.omitted_messages += 1
        return False
    i = len(l.messages)
    m = Message(float(row.get("frame.time_epoch") or 0), int(row.get("frame.number") or 0),
                src, dst, clean_info(row.get("_ws.col.info", "")), proto, message_keys(row))
    l.messages.append(m)
    l.by_frame[m.frame] = i
    return True


def add_row(l: Ladder, row: dict[str, str], learned: dict) -> bool:
    if row.get("sctp.retransmission"):
        # tshark skips dissecting retransmitted chunks; the caller feeds these only once the
        # learned (ppid, ports) -> protocol map is complete. Fall back to the PPID table for
        # unlearned associations (table-only protos carry no decode). No hit: not a message,
        # and never a burst (it is signalling).
        ppid = (vals(row, "sctp.data_payload_proto_id") or [""])[0]
        sp, dp = (vals(row, "sctp.srcport") or ["0"])[0], (vals(row, "sctp.dstport") or ["0"])[0]
        proto = learned.get((ppid, frozenset((sp, dp)))) or SCTP_PPID_PROTO.get(ppid)
        if not proto:
            return False
        # learned stores _ws.col.protocol names, often compound ("S1AP/NAS-EPS", "Camel-v2")
        proto = next((n for n in PROTO_NAMES.values() if n.lower() in proto.lower()), proto)
        src, dst, _, _ = roles.outer_inner(row)
        if not src or not dst or src in roles.UNSPECIFIED or dst in roles.UNSPECIFIED:
            return False
        return _message(l, row, src, dst, proto)
    src, dst, _, _ = roles.outer_inner(row)
    if not src or not dst or src in roles.UNSPECIFIED or dst in roles.UNSPECIFIED:
        return False
    if proto := signaling_proto(row):
        return _message(l, row, src, dst, proto)
    t = float(row.get("frame.time_epoch") or 0)
    key = (src, dst, row.get("_ws.col.protocol", ""))
    if (b := l.open_bursts.get(key)) and t - b.t1 > BURST_GAP:
        b = None
    if b:
        b.t1 = max(b.t1, t)
        b.n += 1
        b.bytes += int(row.get("frame.len") or 0)
    else:
        b = Burst(t, t, src, dst, key[2], 1, int(row.get("frame.len") or 0))
        l.bursts.append(b)
        l.open_bursts[key] = b
    return False


def _int(x: str) -> int | None:
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _type_step(a: str, b: str) -> bool:
    x, y = _int(a), _int(b)
    return x is not None and y is not None and abs(x - y) == 1


def _pairing_match(a: Message, b: Message) -> bool:
    if a.proto != b.proto:
        return False
    ka, kb = a.keys, b.keys
    if "hbhid" in ka and "hbhid" in kb:
        return (ka.get("hbhid") == kb.get("hbhid") and ka.get("code") == kb.get("code")
                and {ka.get("req"), kb.get("req")} == {"1", "0"})
    if "seqno" in ka and "seqno" in kb:
        return (ka.get("seqno") == kb.get("seqno") and _type_step(ka.get("msg"), kb.get("msg"))
                and a.src == b.dst and a.dst == b.src)
    if "proc" in ka and "proc" in kb:
        pa, pb = _int(ka.get("proc")), _int(kb.get("proc"))
        if pa is None or pb is None:
            return False
        return (pb == pa + (1 if pa % 2 else -1)
                and a.src == b.dst and a.dst == b.src and abs(a.t - b.t) <= 30.0)
    return False


def pair(l: Ladder) -> None:
    used: set[int] = set()
    for i, m in enumerate(l.messages):
        if i in used:
            continue
        if "resp_to" in m.keys:  # GTPv2: tshark links each response to its request frame
            if m.keys["resp_to"] and (t := l.by_frame.get(int(m.keys["resp_to"]))) is not None \
                    and t != i and l.messages[t].proto == m.proto:
                used.add(i)
                l.pairs.append((t, i))  # a request may pair with retransmitted responses too
            continue
        cands = [(abs(m.t - o.t), j) for j, o in enumerate(l.messages)
                 if j != i and j not in used and _pairing_match(m, o)]
        if not cands:
            continue
        j = min(cands)[1]
        used.add(i)
        used.add(j)
        l.pairs.append((i, j))


def attach_decode(l: Ladder, blocks: Iterator[tuple[int, str]]) -> None:
    used = 0
    for frame, text in blocks:
        i = l.by_frame.get(frame)
        if i is None:
            continue
        body = text if len(text) <= DECODE_LIMIT else text[:DECODE_LIMIT] + "… (decode truncated)"
        if used + len(body) > DECODE_BUDGET:
            l.decode_omitted += 1
            continue
        used += len(body)
        l.messages[i].decode = body


def ladder_dict(l: Ladder, nodes_by_ip: dict[str, roles.Node]) -> dict:
    order: list[str] = []
    for m in sorted(l.messages, key=lambda m: m.t):
        for ip in (m.src, m.dst):
            if ip not in order:
                order.append(ip)
    for b in sorted(l.bursts, key=lambda b: b.t0):
        for ip in (b.src, b.dst):
            if ip not in order:
                order.append(ip)
    index = {ip: i for i, ip in enumerate(order)}
    nodes = []
    for ip in order:
        n = nodes_by_ip.get(ip)
        name, typ = ip, ""
        if n:
            if n.hostnames:
                name = sorted(n.hostnames)[0]
            if n.roles:
                typ = sorted(n.roles)[0]
        nodes.append({"ip": ip, "name": name, "type": typ})
    return {
        "nodes": nodes,
        "messages": [{"t": m.t, "frame": m.frame, "src": index[m.src], "dst": index[m.dst],
                      "name": m.name, "proto": m.proto,
                      **({"decode": m.decode} if m.decode else {})}
                     for m in sorted(l.messages, key=lambda m: m.t)],
        "bursts": [{"t0": b.t0, "t1": b.t1, "src": index[b.src], "dst": index[b.dst],
                    "proto": b.proto, "n": b.n, "bytes": b.bytes}
                   for b in sorted(l.bursts, key=lambda b: b.t0)],
        "pairs": list(l.pairs),
    }
