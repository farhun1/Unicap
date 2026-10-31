import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field

from unipcap.tshark import vals

FIELDS = ["frame.number", "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
          "sctp.srcport", "sctp.dstport", "udp.srcport", "udp.dstport",
          "_ws.col.protocol", "_ws.col.info",
          "gtpv2.message_type", "gtpv2.f_teid_interface_type", "gtpv2.f_teid_ipv4",
          "gtpv2.pdn_addr_and_prefix.ipv4", "pfcp.msg_type", "pfcp.node_id_fqdn",
          "pfcp.ue_ip_addr_ipv4", "gtp.teid",
          "diameter.cmd.code", "diameter.flags.request", "diameter.applicationId",
          "diameter.Session-Id", "diameter.Origin-Host", "diameter.Origin-Realm",
          "diameter.Destination-Realm", "m3ua.protocol_data_opc", "m3ua.protocol_data_dpc"]

# TS 29.274 Table 8.22-1: F-TEID interface type -> (role, interface)
FTEID_TYPES = {0: ("eNodeB", "S1-U"), 1: ("SGW", "S1-U"), 4: ("SGW", "S5/S8-U"),
               5: ("PGW", "S5/S8-U"), 6: ("SGW", "S5/S8-C"), 7: ("PGW", "S5/S8-C"),
               10: ("MME", "S11"), 11: ("SGW", "S11")}
PFCP_REQUESTS = {"50", "52", "54"}

# application id -> (client role, server role)
DIAMETER_APPS: dict[int, tuple[str | None, str]] = {
    16777251: ("MME", "HSS"), 16777238: ("PGW", "PCRF"), 4: (None, "OCS"),
    16777236: ("P-CSCF", "PCRF"), 16777252: ("MME", "EIR"), 16777272: ("PGW", "AAA"),
    16777216: (None, "HSS")}
DIAMETER_HOP = {"257", "280"}  # CER/CEA, DWR/DWA: hop-by-hop, so Origin-Host is the sender's

EVIDENCE_CAP = 3

S1_UP = {"S1SetupRequest", "InitialUEMessage", "UplinkNASTransport", "UEContextReleaseRequest",
         "PathSwitchRequest", "HandoverRequired"}
S1_DOWN = {"S1SetupResponse", "DownlinkNASTransport", "InitialContextSetupRequest",
           "UEContextReleaseCommand", "Paging"}
NG_UP = {"NGSetupRequest", "InitialUEMessage", "UplinkNASTransport", "UEContextReleaseRequest",
         "PathSwitchRequest", "HandoverRequired"}
NG_DOWN = {"NGSetupResponse", "DownlinkNASTransport", "InitialContextSetupRequest",
           "UEContextReleaseCommand", "Paging", "PDUSessionResourceSetupRequest"}
UNSPECIFIED = {"0.0.0.0", "::"}
# Server-initiated commands: RAR, ASR, CLR, IDR, DSR, Reset. The request sender is the server.
SERVER_INITIATED = {"258", "274", "317", "319", "320", "322"}

# Ordered: first match wins, so saegw/spgw must precede sgw/pgw.
HOSTNAME_HINTS = [
    (("saegw", "spgw"), {"SGW", "PGW"}), (("mme",), {"MME"}), (("sgw",), {"SGW"}),
    (("pgw", "ggsn"), {"PGW"}), (("amf",), {"AMF"}), (("smf",), {"SMF/PGW-C"}),
    (("upf",), {"UPF"}), (("hss",), {"HSS"}), (("pcrf",), {"PCRF"}), (("ocs",), {"OCS"}),
    (("dra",), {"DRA"}), (("dea",), {"DEA"}), (("stp",), {"STP"}), (("pcscf",), {"P-CSCF"}),
    (("enb",), {"eNodeB"}), (("gnb",), {"gNB"}),
]


@dataclass
class Node:
    ip: str
    roles: set[str] = field(default_factory=set)
    interfaces: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)
    protocols: Counter[str] = field(default_factory=Counter)
    frames: int = 0


def outer_inner(row: dict[str, str]) -> tuple[str | None, str | None, str | None, str | None]:
    lists = {"ip": (vals(row, "ip.src"), vals(row, "ip.dst")),
             "ipv6": (vals(row, "ipv6.src"), vals(row, "ipv6.dst"))}
    used = {"ip": 0, "ipv6": 0}
    layers = []
    for tok in row.get("frame.protocols", "").split(":"):
        if tok not in used:
            continue
        # tshark 4.x labels a GTP-U inner IPv6 layer "ip": fall back to the other family
        for fam in (tok, "ipv6" if tok == "ip" else "ip"):
            i = used[fam]
            if i < len(lists[fam][0]) or i < len(lists[fam][1]):
                used[fam] += 1
                layers.append((lists[fam][0][i] if i < len(lists[fam][0]) else None,
                               lists[fam][1][i] if i < len(lists[fam][1]) else None))
                break
        else:
            layers.append((None, None))
    if not layers:
        return None, None, None, None
    inner = layers[-1] if len(layers) > 1 else (None, None)
    return layers[0] + inner


class RoleInference:
    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._ev: Counter[tuple[str, str]] = Counter()
        self.warnings: list[str] = []
        self.ues: set[str] = set()  # UE IPs seen in PAA / PFCP
        self.fteid_skipped = 0
        # (outer src, outer dst, teid) -> [frames, inner IP counts]; bounded by bearers, not frames
        self.bearers: dict[tuple[str, str, str], list] = {}
        self._derived: list[str] = []  # warnings owned by _resolve, rebuilt on each run
        self.plain: set[tuple[str, str]] = set()  # (src, dst) of frames with no inner IP
        self._resolved = False
        self.dia_skipped = 0
        # (Session-Id, cmd) -> {(src, dst, app, origin realm, dest realm, server-initiated)} of requests
        # open sessions only: popped into the aggregates below on the first answer, so memory stays flat
        self.dia_open: dict[tuple[str, str], set[tuple[str, str, int, str, str, bool]]] = {}
        self.dia_agents: dict[str, bool] = {}  # relaying IP -> saw Origin-Realm != Destination-Realm
        self.dia_clients: set[tuple[str, str, str]] = set()  # (ip, role, evidence)
        self.dia_servers: set[tuple[str, str, str]] = set()
        self._base: dict[str, set[str]] = {}  # roles from per-row rules; never revoked
        self._dmarks: list[tuple[str, str, str]] = []  # marks made by _resolve, revoked on each run
        self._in_resolve = False
        self.m3ua: dict[str, set[tuple[str, str]]] = {}  # OPC -> {(src, dst)}

    def node(self, ip: str) -> Node:
        if ip not in self._nodes:
            self._nodes[ip] = Node(ip)
        return self._nodes[ip]

    def mark(self, ip: str, role: str, evidence: str) -> None:
        if ip in UNSPECIFIED:
            return
        n = self.node(ip)
        if self._in_resolve:
            self._dmarks.append((ip, role, evidence))
        else:
            self._base.setdefault(ip, set()).add(role)
        n.roles.add(role)
        if self._ev[ip, role] < EVIDENCE_CAP and evidence not in n.evidence:
            self._ev[ip, role] += 1
            n.evidence.append(evidence)

    def add(self, row: dict[str, str]) -> None:
        src, dst, _, _ = outer_inner(row)
        if not src or not dst:
            return
        self._resolved = False
        proto = row.get("_ws.col.protocol", "")
        for ip in (src, dst):
            if ip in UNSPECIFIED:
                continue
            n = self.node(ip)
            n.frames += 1
            if proto:
                n.protocols[proto] += 1
        for rule in RULES:
            rule(self, row, src, dst)

    def _resolve(self) -> None:
        for w in self._derived:
            self.warnings.remove(w)
        self._derived = []
        self._in_resolve = True
        for ip, role, ev in self._dmarks:
            n = self.node(ip)
            if role not in self._base.get(ip, ()):
                n.roles.discard(role)
            if ev in n.evidence:
                n.evidence.remove(ev)
                self._ev[ip, role] -= 1
        self._dmarks = []
        if self.fteid_skipped:
            self._derived.append(
                f"{self.fteid_skipped} GTPv2 frames with IPv6-only/misaligned F-TEIDs skipped")
        if self.dia_skipped:
            self._derived.append(
                f"{self.dia_skipped} Diameter frames with misaligned bundled fields skipped")
        agents, clients, servers = dict(self.dia_agents), set(self.dia_clients), set(self.dia_servers)
        for edges in self.dia_open.values():
            _dia_fold(edges, agents, clients, servers)
        for ip, mismatch in agents.items():
            dea = mismatch or any(re.search(r"(^|[-.])dea\d*([-.]|$)", h.lower()) for h in self.node(ip).hostnames)
            self.mark(ip, "DEA" if dea else "DRA", "Diameter request relayed")
        for ip, role, ev in clients | servers:
            if ip not in agents:
                self.mark(ip, role, ev)
        sent: dict[str, set[str]] = {}
        for opc, edges in self.m3ua.items():
            for a, b in edges:
                sent.setdefault(a, set()).add(opc)
                if a != b and any(s == b for s, _ in edges):  # b receives OPC from another IP and sends it on
                    self.mark(b, "STP", f"M3UA OPC {opc} relayed")
        for ip, opcs in sent.items():
            if len(opcs) > 1:
                self.mark(ip, "STP", f"M3UA sends {len(opcs)} distinct OPCs")
        cands = {k: {ip for ip, c in inner.items() if c == frames}
                 for k, (frames, inner) in self.bearers.items()}
        ues = set(self.ues)
        pairs: dict[frozenset, set[str]] = {}  # single-subscriber traces: IP common to the whole pair
        for (a, b, _), c in cands.items():
            pairs[frozenset((a, b))] = pairs.get(frozenset((a, b)), c) & c
        for pair, c in pairs.items():
            if len(c) == 1:
                self._ue(next(iter(c)), f"GTP-U tunnel {'↔'.join(sorted(pair))}: inner IP in every frame", ues)
        for (a, b, teid), c in cands.items():
            if len(c) == 1:
                self._ue(next(iter(c)), f"GTP-U bearer {a}→{b} TEID {teid}: inner IP in every frame", ues)
        ambiguous = 0
        for (a, b, teid), (_, inner) in self.bearers.items():
            if not cands[a, b, teid] & ues:
                ambiguous += 1
                continue
            for ip in inner.keys() - ues:
                self.mark(ip, "Server", f"GTP-U inner peer of UE on {a}→{b} TEID {teid}")
        if ambiguous:
            self._derived.append(f"{ambiguous} GTP-U bearers: UE address ambiguous")
        for a, b in self.plain:
            for ue, peer in ((a, b), (b, a)):
                if ue in ues:
                    self.mark(peer, "Server", f"plain traffic with UE {ue}")
        self.warnings += self._derived
        self._in_resolve = False

    def _ue(self, ip: str, evidence: str, ues: set[str]) -> None:
        ues.add(ip)
        self.mark(ip, "UE", evidence)

    def nodes(self) -> list[Node]:
        if not self._resolved:
            self._resolved = True
            self._resolve()
        for n in self._nodes.values():
            if n.roles:
                continue
            for name in sorted(n.hostnames):
                low = name.lower()
                hit = next((r for keys, r in HOSTNAME_HINTS if any(k in low for k in keys)), None)
                if hit:
                    n.roles |= hit
                    n.evidence.append(f"hostname hint: {name}")
                    break
        return sorted(self._nodes.values(), key=lambda n: _ip_key(n.ip))


def _ip_key(ip: str):
    try:
        a = ipaddress.ip_address(ip)
        return 0, a.version, int(a), ""
    except ValueError:  # non-IP labels only occur in synthetic tests
        return 1, 0, 0, ip


def _ran(ri: RoleInference, row: dict[str, str], src: str, dst: str, proto: str,
         up: set[str], down: set[str], port: str, ran: str, core: str) -> None:
    if proto not in row.get("frame.protocols", "").split(":"):
        return
    msgs = set(re.findall(r"[A-Za-z0-9]+", row.get("_ws.col.info", "")))
    sp, dp = (vals(row, "sctp.srcport") or [""])[0], (vals(row, "sctp.dstport") or [""])[0]
    if hit := msgs & up:
        a, b, msg = src, dst, sorted(hit)[0]
    elif hit := msgs & down:
        a, b, msg = dst, src, sorted(hit)[0]
    elif (sp == port) != (dp == port):  # standard port is only a fallback when unambiguous
        a, b = (src, dst) if dp == port else (dst, src)
        msg = row.get("_ws.col.info", "").split(",")[0]
    else:
        return
    ev = f"frame {row.get('frame.number', '?')}: {proto.upper()} {msg} ({src}→{dst})"
    ri.mark(a, ran, ev)
    ri.mark(b, core, ev)


def _s1ap(ri, row, src, dst):
    _ran(ri, row, src, dst, "s1ap", S1_UP, S1_DOWN, "36412", "eNodeB", "MME")


def _ngap(ri, row, src, dst):
    _ran(ri, row, src, dst, "ngap", NG_UP, NG_DOWN, "38412", "gNB", "AMF")


def _gtpv2(ri, row, src, dst):
    if "gtpv2" not in row.get("frame.protocols", "").split(":"):
        return
    types, ips = vals(row, "gtpv2.f_teid_interface_type"), vals(row, "gtpv2.f_teid_ipv4")
    if len(types) != len(ips):
        # shortcut: field lists only; parse per-IE via -T json if this warning shows up on real traces
        ri.fteid_skipped += 1
    else:
        for t, ip in zip(types, ips):
            if (rl := FTEID_TYPES.get(int(t))):
                ri.mark(ip, rl[0], f"frame {row.get('frame.number', '?')}: F-TEID {rl[1]}")
                ri.node(ip).interfaces.add(rl[1])
    # a Create Session Request carries 0.0.0.0 (dynamic allocation); the PAA is real only in later messages
    if (vals(row, "gtpv2.message_type") or [""])[0] == "32":
        return
    for ip in vals(row, "gtpv2.pdn_addr_and_prefix.ipv4"):
        ri.ues.add(ip)
        ri.mark(ip, "UE", f"frame {row.get('frame.number', '?')}: PAA")


def _pfcp(ri, row, src, dst):
    if "pfcp" not in row.get("frame.protocols", "").split(":"):
        return
    ev = f"frame {row.get('frame.number', '?')}: PFCP ({src}→{dst})"
    if (vals(row, "pfcp.msg_type") or [""])[0] in PFCP_REQUESTS:
        ri.mark(src, "SMF/PGW-C", ev)
        ri.mark(dst, "UPF", ev)
        ri.node(src).hostnames.update(vals(row, "pfcp.node_id_fqdn"))
    for ip in vals(row, "pfcp.ue_ip_addr_ipv4"):
        ri.ues.add(ip)
        ri.mark(ip, "UE", ev)


def _local(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_link_local or a.is_multicast


def _gtpu(ri, row, src, dst):
    _, _, isrc, idst = outer_inner(row)
    if not (isrc and idst and ":gtp:" in f":{row.get('frame.protocols', '')}:"):
        ri.plain.add((src, dst))
        return
    if any(_local(ip) for ip in (isrc, idst)):  # RS/RA etc. make the UE absent from some frames
        return
    b = ri.bearers.setdefault((src, dst, (vals(row, "gtp.teid") or [""])[0]), [0, Counter()])
    b[0] += 1
    inner = b[1]
    for ip in (isrc, idst):
        inner[ip] += 1
        ri.node(ip).frames += 1


def _dia_fold(edges, agents, clients, servers) -> None:
    srcs, dsts = {e[0] for e in edges}, {e[1] for e in edges}
    for ip in srcs & dsts:
        agents[ip] = agents.get(ip, False) or any(e[3] and e[4] and e[3] != e[4] for e in edges if e[1] == ip)
    for src, dst, app, _, _, srv_init in edges:
        client, server = DIAMETER_APPS.get(app, (None, None))
        if srv_init:  # request flows server -> client
            if server and src not in dsts:
                servers.add((src, server, f"Diameter app {app} request"))
            if client and dst not in srcs:
                clients.add((dst, client, f"Diameter app {app} request"))
            continue
        if client and src not in dsts:
            clients.add((src, client, f"Diameter app {app} request"))
        if server and dst not in srcs:
            servers.add((dst, server, f"Diameter app {app} request"))


def _diameter(ri, row, src, dst):
    if "diameter" not in row.get("frame.protocols", "").split(":"):
        return
    cmds, reqs, apps, sids = (vals(row, "diameter." + f) for f in
                              ("cmd.code", "flags.request", "applicationId", "Session-Id"))
    n = len(cmds)
    if not (len(reqs) == len(apps) == n and (len(sids) == n or (not sids and set(cmds) <= DIAMETER_HOP))):
        ri.dia_skipped += 1
        return
    orig, dest = vals(row, "diameter.Origin-Realm"), vals(row, "diameter.Destination-Realm")
    for i, (cmd, req, app) in enumerate(zip(cmds, reqs, apps)):
        if cmd in DIAMETER_HOP:
            hosts = vals(row, "diameter.Origin-Host")
            if len(hosts) == 1 and set(cmds) <= DIAMETER_HOP:
                ri.node(src).hostnames.add(hosts[0])
        elif req not in ("1", "True"):
            if edges := ri.dia_open.pop((sids[i], cmd), None):
                _dia_fold(edges, ri.dia_agents, ri.dia_clients, ri.dia_servers)
        elif app.isdigit():
            realms = tuple(v[i] if len(v) == n else "" for v in (orig, dest))
            ri.dia_open.setdefault((sids[i], cmd), set()).add((src, dst, int(app), *realms, cmd in SERVER_INITIATED))


def _m3ua(ri, row, src, dst):
    for opc in vals(row, "m3ua.protocol_data_opc"):
        ri.m3ua.setdefault(opc, set()).add((src, dst))


# Task 5 appends rules here: each is f(ri, row, outer_src, outer_dst).
RULES = [_s1ap, _ngap, _gtpv2, _pfcp, _gtpu, _diameter, _m3ua]
