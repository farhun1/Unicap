import pcapgen

from unipcap.ladder import (DECODE_BUDGET, DECODE_LIMIT, MESSAGE_CAP, Burst, Ladder, Message,
                            add_row, attach_decode, clean_info, ladder_dict, message_keys, pair,
                            signaling_proto)
from unipcap.tshark import iter_verbose


def test_iter_verbose_yields_one_block_per_frame(tmp_path):
    p = pcapgen.write(tmp_path / "v.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x")] * 2)
    blocks = list(iter_verbose(p, "udp"))
    assert [(n, "User Datagram Protocol" in text, text.startswith("Frame ")) for n, text in blocks] \
        == [(1, True, True), (2, True, True)]


def test_signaling_proto_variants():
    assert signaling_proto({"frame.protocols": "eth:ethertype:ip:sctp:s1ap:nas-eps"}) == "S1AP"
    assert signaling_proto({"frame.protocols": "eth:ethertype:ip:tcp:diameter"}) == "DIAMETER"
    assert signaling_proto({"frame.protocols": "eth:ethertype:ip:sctp:m3ua:sccp:camel"}) == "CAMEL"
    assert signaling_proto({"frame.protocols": "eth:ethertype:ip:sctp:sgsap"}) == "SGSAP"
    assert signaling_proto({"frame.protocols": "eth:ethertype:ip:udp:gtp:ip:tcp"}) is None


def test_clean_info_strips_trailing_pipe():
    assert clean_info("Credit-Control Request | ") == "Credit-Control Request"
    assert clean_info("UplinkNASTransport, PDN disconnect request") == "UplinkNASTransport, PDN disconnect request"


def test_message_keys_field_names():
    assert message_keys({"diameter.hopbyhopid": "0x1", "diameter.cmd.code": "272",
                         "diameter.flags.request": "1"}) == {"hbhid": "0x1", "code": "272", "req": "1"}
    # tshark 4.6.9 prints Boolean fields as "True"/"False"
    assert message_keys({"diameter.hopbyhopid": "0x1", "diameter.cmd.code": "272",
                         "diameter.flags.request": "True"}) == {"hbhid": "0x1", "code": "272", "req": "1"}
    assert message_keys({"diameter.hopbyhopid": "0x1", "diameter.cmd.code": "272",
                         "diameter.flags.request": "False"}) == {"hbhid": "0x1", "code": "272", "req": "0"}
    assert message_keys({"pfcp.seqno": "5", "pfcp.msg_type": "50"}) == {"seqno": "5", "msg": "50"}
    assert message_keys({"gtpv2.seq": "0x1", "gtpv2.message_type": "32"}) == \
        {"seq": "0x1", "msg": "32", "resp_to": ""}
    assert message_keys({"gtpv2.seq": "0x1", "gtpv2.message_type": "33",
                         "gtpv2.response_to": "7"}) == {"seq": "0x1", "msg": "33", "resp_to": "7"}
    assert message_keys({"s1ap.procedureCode": "13"}) == {"proc": "13"}
    assert message_keys({"ngap.procedureCode": "13"}) == {"proc": "13"}


def test_add_row_messages_and_burst_merge():
    l = Ladder([], [], [], {})
    r = lambda t, pl: {"frame.time_epoch": str(t), "frame.protocols": pl,
                        "ip.src": "1.1.1.1", "ip.dst": "2.2.2.2", "_ws.col.protocol": "GTP-U",
                        "_ws.col.info": "", "frame.len": "100", "frame.number": "1"}
    add_row(l, r(1700000000.0, "eth:ethertype:ip:udp:gtp:ip"), {})   # burst 1 opens
    add_row(l, r(1700000000.5, "eth:ethertype:ip:udp:gtp:ip"), {})   # merges (gap <= 1s)
    add_row(l, r(1700000002.0, "eth:ethertype:ip:udp:gtp:ip"), {})   # splits (gap > 1s)
    add_row(l, r(1700000003.0, "eth:ethertype:ip:sctp:s1ap"), {})    # message
    assert len(l.bursts) == 2 and l.bursts[0].n == 2 and l.bursts[0].bytes == 200
    assert [m.proto for m in l.messages] == ["S1AP"]


def test_add_row_retransmission_learned():
    row = {"frame.time_epoch": "1700000000.0", "frame.protocols": "eth:ethertype:ip:sctp",
           "ip.src": "1.1.1.1", "ip.dst": "2.2.2.2", "_ws.col.protocol": "SCTP",
           "_ws.col.info": "DATA (TSN=0) (retransmission)", "sctp.data_payload_proto_id": "18",
           "sctp.retransmission": "1", "sctp.srcport": "36412", "sctp.dstport": "36412",
           "frame.number": "9", "frame.len": "200"}
    l = Ladder([], [], [], {})
    assert add_row(l, row, {}) is True                       # PPID table fallback, not a burst
    assert l.messages[0].proto == "S1AP"
    assert add_row(l, row, {("18", frozenset(("36412", "36412"))): "S1AP"}) is True
    assert l.messages[1].proto == "S1AP"
    # capture's learned map stores _ws.col.protocol names; canonicalize to PROTO_NAMES values
    assert add_row(l, row, {("18", frozenset(("36412", "36412"))): "Diameter"}) is True
    assert l.messages[2].proto == "DIAMETER"
    # real tshark col protocol is compound when NAS rides on top: "S1AP/NAS-EPS", "Camel-v2"
    assert add_row(l, row, {("18", frozenset(("36412", "36412"))): "S1AP/NAS-EPS"}) is True
    assert l.messages[3].proto == "S1AP"


def test_add_row_retransmission_table_fallback():
    row = {"frame.time_epoch": "1700000000.0", "frame.protocols": "eth:ethertype:ip:sctp",
           "ip.src": "1.1.1.1", "ip.dst": "2.2.2.2", "_ws.col.protocol": "SCTP",
           "_ws.col.info": "DATA (TSN=0) (retransmission)", "sctp.retransmission": "1",
           "sctp.srcport": "36412", "sctp.dstport": "36412", "frame.number": "9", "frame.len": "200"}
    l = Ladder([], [], [], {})
    for ppid, proto in (("3", "M3UA"), ("27", "X2AP"), ("46", "DIAMETER")):
        assert add_row(l, row | {"sctp.data_payload_proto_id": ppid}, {}) is True
        assert l.messages[-1].proto == proto
    assert add_row(l, row | {"sctp.data_payload_proto_id": "0"}, {}) is False
    assert l.bursts == []


def test_add_row_skips_unspecified():
    l = Ladder([], [], [], {})
    r = {"frame.time_epoch": "1700000000.0", "frame.protocols": "eth:ethertype:ip:udp",
         "ip.src": "0.0.0.0", "ip.dst": "2.2.2.2", "_ws.col.protocol": "UDP",
         "_ws.col.info": "", "frame.len": "50", "frame.number": "1"}
    add_row(l, r, {})
    assert l.bursts == []


def test_message_cap():
    l = Ladder([], [], [], {})
    r = {"frame.time_epoch": "1700000000.0", "frame.protocols": "eth:ethertype:ip:sctp:s1ap",
         "ip.src": "1.1.1.1", "ip.dst": "2.2.2.2", "_ws.col.protocol": "S1AP",
         "_ws.col.info": "x", "frame.number": "1", "frame.len": "50"}
    for i in range(MESSAGE_CAP + 10):
        add_row(l, r | {"frame.number": str(i)}, {})
    assert len(l.messages) == MESSAGE_CAP and l.omitted_messages == 10


def test_attach_decode_truncates():
    l = Ladder([], [], [], {})
    l.messages = [Message(0.0, 1, "a", "b", "n", "S1AP", {})]
    l.by_frame = {1: 0}
    attach_decode(l, iter([(1, "x" * (DECODE_LIMIT + 10))]))
    assert l.messages[0].decode.endswith("… (decode truncated)")
    assert len(l.messages[0].decode) <= DECODE_LIMIT + len("… (decode truncated)")


def test_attach_decode_budget(monkeypatch):
    monkeypatch.setattr("unipcap.ladder.DECODE_BUDGET", 1000)
    l = Ladder([], [], [], {})
    l.messages = [Message(0.0, i, "a", "b", "n", "S1AP", {}) for i in (1, 2, 3)]
    l.by_frame = {1: 0, 2: 1, 3: 2}
    attach_decode(l, iter([(1, "short decode"), (2, "y" * 2000), (3, "z" * 2000)]))
    assert l.messages[0].decode == "short decode"
    assert l.messages[1].decode is None and l.messages[2].decode is None
    assert l.decode_omitted == 2


def test_ladder_dict_shape():
    from unipcap.roles import Node
    l = Ladder([], [], [], {})
    l.messages = [Message(0.0, 1, "1.1.1.1", "2.2.2.2", "hello", "S1AP", {})]
    l.bursts = [Burst(0.0, 0.5, "1.1.1.1", "2.2.2.2", "GTP-U", 3, 300)]
    l.pairs = []
    d = ladder_dict(l, {"1.1.1.1": Node("1.1.1.1"), "2.2.2.2": Node("2.2.2.2")})
    assert d["nodes"] == [{"ip": "1.1.1.1", "name": "1.1.1.1", "type": ""},
                          {"ip": "2.2.2.2", "name": "2.2.2.2", "type": ""}]
    assert d["messages"][0]["src"] == 0 and d["messages"][0]["dst"] == 1
    assert "decode" not in d["messages"][0]


def _msg(i, t, src, dst, proto, keys):
    return Message(t, i, src, dst, f"m{i}", proto, keys)


def test_pair_diameter_hbhid():
    # end-to-end: real rows carry tshark 4.6.9 Boolean spellings "True"/"False"
    l = Ladder([], [], [], {})
    def row(t, n, src, dst, req):
        return {"frame.time_epoch": str(t), "frame.number": str(n),
                "frame.protocols": "eth:ethertype:ip:tcp:diameter",
                "ip.src": src, "ip.dst": dst,
                "_ws.col.protocol": "Diameter", "_ws.col.info": "x", "frame.len": "100",
                "diameter.hopbyhopid": "0x1", "diameter.cmd.code": "272",
                "diameter.flags.request": req}
    add_row(l, row(0.0, 1, "a", "b", "True"), {})
    add_row(l, row(0.1, 2, "b", "a", "False"), {})
    pair(l)
    assert l.pairs == [(0, 1)]


def test_pair_pfcp_seqno_parity():
    l = Ladder([], [], [], {})
    l.messages = [_msg(1, 0.0, "a", "b", "PFCP", {"seqno": "100", "msg": "50"}),
                  _msg(2, 0.1, "b", "a", "PFCP", {"seqno": "100", "msg": "51"}),
                  _msg(3, 0.2, "a", "b", "PFCP", {"seqno": "100", "msg": "50"})]  # retrans req
    pair(l)
    assert l.pairs == [(0, 1)] and 3 not in {j for _, j in l.pairs}


def test_pair_gtpv2_replicates_tshark_linkage():
    l = Ladder([], [], [], {})
    l.messages = [_msg(1, 0.0, "a", "b", "GTPv2", {"seq": "0x1", "msg": "32", "resp_to": ""}),
                  _msg(2, 0.1, "b", "a", "GTPv2", {"seq": "0x1", "msg": "33", "resp_to": "1"}),
                  # retransmitted response links to the same request frame
                  _msg(3, 0.2, "b", "a", "GTPv2", {"seq": "0x1", "msg": "33", "resp_to": "1"}),
                  # request tshark did not link stays unpaired
                  _msg(4, 0.3, "a", "b", "GTPv2", {"seq": "0x2", "msg": "32", "resp_to": ""})]
    l.by_frame = {1: 0, 2: 1, 3: 2, 4: 3}
    pair(l)
    assert l.pairs == [(0, 1), (0, 2)]


def test_pair_s1ap_window_best_effort():
    l = Ladder([], [], [], {})
    l.messages = [_msg(1, 0.0, "a", "b", "S1AP", {"proc": "13"}),   # initiating
                  _msg(2, 0.5, "b", "a", "S1AP", {"proc": "14"}),   # successful outcome
                  _msg(3, 40.0, "b", "a", "S1AP", {"proc": "14"})]  # outside 30s window
    pair(l)
    assert l.pairs == [(0, 1)]


def test_pair_one_partner_only():
    l = Ladder([], [], [], {})
    l.messages = [_msg(1, 0.0, "a", "b", "DIAMETER", {"hbhid": "0x1", "code": "272", "req": "1"}),
                  _msg(2, 0.1, "b", "a", "DIAMETER", {"hbhid": "0x1", "code": "272", "req": "0"}),
                  _msg(3, 0.2, "b", "a", "DIAMETER", {"hbhid": "0x1", "code": "272", "req": "0"})]
    pair(l)
    assert l.pairs == [(0, 1)]  # nearest-in-time answer wins; the other stays unpaired
