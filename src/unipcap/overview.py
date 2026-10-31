"""Overview tab metrics, accumulated in one pass over the streaming rows.

DNS rates, GTP-U volume and quality, Gx/Gy quotas and rules, negative
signaling responses, and subscriber identities.
"""
from collections import Counter

from unipcap.tshark import vals

# Ordered fallback chains: per frame, the first field that yields a value wins.
IMSI_FIELDS = ["e212.imsi", "s1ap.iMSI", "pfcp.user_id.supi", "camel.iMSI",
               "gsm_map.imsi", "gsm_old.imsi", "ranap.imsi", "lte-rrc.imsi",
               "bssap.imsi_ie", "diameter.3GPP-IMSI"]
MSISDN_FIELDS = ["e164.msisdn", "pfcp.user_id.gpsi", "camel.mSISDN",
                 "gsm_map.msisdn", "gsm_old.msisdn", "ranap.MSISDN",
                 "diameter.MSISDN", "diameter.A-MSISDN"]

FIELDS = ["dns.id", "dns.flags.response", "dns.flags.rcode",
          "dns.count.answers", "gtp.message", "gtp.seq_number", "gtp.flags.s",
          "tcp.analysis.retransmission", "tcp.analysis.lost_segment",
          "diameter.flags.request", "diameter.Auth-Application-Id",
          "diameter.CC-Total-Octets", "diameter.Rating-Group",
          "diameter.Service-Identifier", "diameter.Charging-Rule-Name",
          "diameter.Charging-Rule-Base-Name", "diameter.Result-Code",
          "gtpv2.cause", "s1ap.unsuccessfulOutcome_element",
          "ngap.unsuccessfulOutcome_element", *IMSI_FIELDS, *MSISDN_FIELDS]

GX_APP = "16777238"
GY_APP = "4"


def _endpoints(row: dict[str, str]) -> tuple[str, str]:
    return (row.get("ip.src") or row.get("ipv6.src"),
            row.get("ip.dst") or row.get("ipv6.dst"))


def _instances(row: dict[str, str], field: str) -> list[str]:
    # one | occurrence is one comma-joined instance list; flatten and drop empties
    return [x for el in vals(row, field) for x in el.split(",") if x]


class Overview:
    def __init__(self):
        self.queries = 0
        self.answered = 0
        self.responses = 0
        self.rcode0 = 0
        self.pending_dns: set[tuple[str, str, str]] = set()  # (src, dst, dns.id)
        self.gtpu_frames = 0
        self.gtpu_bytes = 0
        self.loss: dict[tuple[str, str], list] = {}  # (src,dst) -> [received, missing, last_sn]
        self.inner_tcp = 0
        self.inner_retrans = 0
        self.inner_lost = 0
        self.pending_echo: set[tuple[str, str, str]] = set()  # (src, dst, sn)
        self.gx = {"given": 0, "reported": 0, "rules": Counter(), "rule_bases": Counter()}
        self.gy = {"given": 0, "reported": 0,
                   "by_rg": {}, "by_sid": {}}  # key -> [given, reported]
        self.negative = {p: Counter() for p in ("Diameter", "GTPv2", "S1AP", "NGAP")}
        self.imsis: Counter[str] = Counter()
        self.msisdns: Counter[str] = Counter()

    def add_row(self, row: dict[str, str]) -> None:
        # DNS: a response answers a query when it carries the same id back.
        qid = row.get("dns.id")
        if row.get("dns.flags.response") == "True":
            self.responses += 1
            if row.get("dns.flags.rcode") == "0":
                self.rcode0 += 1
            src, dst = _endpoints(row)
            if (dst, src, qid) in self.pending_dns:
                self.pending_dns.remove((dst, src, qid))
                self.answered += 1
        elif qid:
            self.queries += 1
            self.pending_dns.add(_endpoints(row) + (qid,))
        # GTP-U volume: G-PDU frames only.
        if row.get("gtp.message") == "0xff":
            self.gtpu_frames += 1
            self.gtpu_bytes += int(row.get("frame.len") or 0)
        # GTP-U loss: SN gaps per direction; the first SN starts a stream.
        sn = row.get("gtp.seq_number")
        if row.get("gtp.message") == "0xff" and row.get("gtp.flags.s") == "True" and sn:
            state = self.loss.setdefault(_endpoints(row), [0, 0, None])
            sn_i = int(sn, 0)  # tshark renders seq numbers hex; base 0 parses both
            if state[2] is None:
                state[0], state[2] = 1, sn_i
            else:
                gap = (sn_i - state[2] - 1) % 65536  # wrap-safe; duplicate gives 65535
                # shortcut: out-of-order SNs read as loss; no reorder guard until real captures show it
                if gap != 65535:
                    state[0] += 1
                    state[1] += gap
                    state[2] = sn_i
        # Inner-TCP quality: only frames whose protocol chain has gtp + tcp.
        segs = row.get("frame.protocols", "").split(":")
        if "gtp" in segs and "tcp" in segs:
            self.inner_tcp += 1
            self.inner_retrans += row.get("tcp.analysis.retransmission") == "1"
            self.inner_lost += row.get("tcp.analysis.lost_segment") == "1"
        # Echo request/response pairing; unanswered requests stay pending.
        if row.get("gtp.message") == "0x01" and sn:
            self.pending_echo.add(_endpoints(row) + (sn,))
        elif row.get("gtp.message") == "0x02" and sn:
            src, dst = _endpoints(row)
            self.pending_echo.discard((dst, src, sn))
        # Diameter CC: Gx vs Gy by Application-Id; CCA gives, CCR reports.
        aid = row.get("diameter.Auth-Application-Id")
        if aid in (GX_APP, GY_APP):
            self._add_cc(row, aid == GX_APP)
        # Negative responses: failures only, per protocol.
        for code in _instances(row, "diameter.Result-Code"):
            if int(code) >= 3000:
                self.negative["Diameter"][code] += 1
        for cause in _instances(row, "gtpv2.cause"):
            if cause != "16":  # 16 = Request accepted
                self.negative["GTPv2"][cause] += 1
        # FT_NONE outcome elements render "1" when present, "" when absent.
        if row.get("s1ap.unsuccessfulOutcome_element") == "1":
            self.negative["S1AP"][row.get("s1ap.procedureCode") or "?"] += 1
        if row.get("ngap.unsuccessfulOutcome_element") == "1":
            self.negative["NGAP"][row.get("ngap.procedureCode") or "?"] += 1
        # Subscriber identities: per chain, the first field that yields a value wins.
        for chain, counter in ((IMSI_FIELDS, self.imsis), (MSISDN_FIELDS, self.msisdns)):
            for f in chain:
                if vs := [v for v in vals(row, f) if v]:
                    counter.update(vs)
                    break

    def _add_cc(self, row: dict[str, str], gx: bool) -> None:
        acc = self.gx if gx else self.gy
        reported = row.get("diameter.flags.request") == "True"
        octets = sum(int(x) for x in _instances(row, "diameter.CC-Total-Octets"))
        acc["reported" if reported else "given"] += octets
        if not gx:  # per-RG / per-SID pairing is a Gy concept; Gx carries rules instead
            octs = _instances(row, "diameter.CC-Total-Octets")
            for field, table in (("diameter.Rating-Group", acc["by_rg"]),
                                 ("diameter.Service-Identifier", acc["by_sid"])):
                for i, key in enumerate(_instances(row, field)):
                    slot = table.setdefault(key, [0, 0])
                    slot[reported] += int(octs[i]) if i < len(octs) else 0
        if gx and not reported:
            acc["rules"].update(_instances(row, "diameter.Charging-Rule-Name"))
            acc["rule_bases"].update(_instances(row, "diameter.Charging-Rule-Base-Name"))

    def to_dict(self) -> dict:
        def pairs(counts: Counter) -> list[list]:
            return [[k, v] for k, v in sorted(counts.items(), key=lambda p: (-p[1], p[0]))]

        def quota_table(table: dict) -> list[list]:
            return [[k, {"given": v[0], "reported": v[1]}]
                    for k, v in sorted(table.items(), key=lambda kv: int(kv[0]))]

        negative = {}
        for proto, counts in self.negative.items():
            if counts:  # protocols with no negatives are omitted
                negative[proto] = [[k, v] for k, v in sorted(
                    counts.items(), key=lambda kv: (-kv[1], int(kv[0]) if kv[0].isdigit() else 0))]

        loss = [{"src": s, "dst": d, "received": st[0], "missing": st[1],
                 "pct": round(st[1] / (st[0] + st[1]) * 100, 1) if (st[0] + st[1]) else 0.0}
                for (s, d), st in sorted(
                    self.loss.items(), key=lambda kv: (-kv[1][0], kv[0][0]))]

        return {
            "dns": {
                "queries": self.queries, "answered": self.answered,
                "responses": self.responses, "rcode0": self.rcode0,
                "answer_rate_pct": round(self.answered / self.queries * 100, 1)
                                   if self.queries else None,
                "success_rate_pct": round(self.rcode0 / self.responses * 100, 1)
                                    if self.responses else None,
            },
            "gtpu": {"volume": {"frames": self.gtpu_frames, "bytes": self.gtpu_bytes},
                     "loss": loss,
                     "retrans_pct": round(self.inner_retrans / self.inner_tcp * 100, 1)
                                    if self.inner_tcp else None,
                     "drop_pct": round(self.inner_lost / self.inner_tcp * 100, 1)
                                 if self.inner_tcp else None,
                     "no_response": len(self.pending_echo)},
            "gx": {"given_octets": self.gx["given"], "reported_octets": self.gx["reported"],
                   "rules": pairs(self.gx["rules"]), "rule_bases": pairs(self.gx["rule_bases"])},
            "gy": {"given_octets": self.gy["given"], "reported_octets": self.gy["reported"],
                   "by_rg": quota_table(self.gy["by_rg"]), "by_sid": quota_table(self.gy["by_sid"])},
            "subscribers": {"imsi": pairs(self.imsis), "msisdn": pairs(self.msisdns)},
            "negative": negative,
        }


def to_dict(ov: Overview) -> dict:
    return ov.to_dict()
