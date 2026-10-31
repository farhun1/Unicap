import json

import pytest

from unipcap.capture import analyze, to_dict as capture_to_dict
from unipcap.overview import Overview, to_dict


# Build a tshark -T fields row: every overview field defaults to "" so a
# missing key never masks the code path under test. Param names map to field keys.
def row(**kw):
    m = {"ip_src": "ip.src", "ip_dst": "ip.dst", "ipv6_src": "ipv6.src",
         "ipv6_dst": "ipv6.dst", "dns_id": "dns.id",
         "dns_response": "dns.flags.response", "dns_rcode": "dns.flags.rcode",
         "dns_answers": "dns.count.answers", "gtp_message": "gtp.message",
         "frame_len": "frame.len", "protocols": "frame.protocols",
         "sn": "gtp.seq_number", "sn_flag": "gtp.flags.s",
         "retrans": "tcp.analysis.retransmission", "lost": "tcp.analysis.lost_segment",
         "app_id": "diameter.Auth-Application-Id", "req": "diameter.flags.request",
         "rg": "diameter.Rating-Group", "sid": "diameter.Service-Identifier",
         "octets": "diameter.CC-Total-Octets", "rule_name": "diameter.Charging-Rule-Name",
         "rule_base": "diameter.Charging-Rule-Base-Name",
         "result_code": "diameter.Result-Code", "gtpv2_cause": "gtpv2.cause",
         "s1ap_outcome": "s1ap.unsuccessfulOutcome_element",
         "ngap_outcome": "ngap.unsuccessfulOutcome_element",
         "s1ap_proc": "s1ap.procedureCode", "ngap_proc": "ngap.procedureCode",
         "imsi": "e212.imsi", "s1ap_imsi": "s1ap.iMSI", "supi": "pfcp.user_id.supi",
         "msisdn": "e164.msisdn", "camel_msisdn": "camel.mSISDN",
         "gpsi": "pfcp.user_id.gpsi"}
    d = {k: "" for k in m.values()}
    d["ip.src"] = "1.1.1.1"
    d["ip.dst"] = "2.2.2.2"
    for k, v in kw.items():
        d[m[k]] = v
    return d


def test_dns_rates_and_answered_queries():
    ov = Overview()
    ov.add_row(row(dns_id="0x0064", dns_response="False"))                    # query 1
    ov.add_row(row(dns_id="0x00c8", dns_response="False"))                    # query 2
    ov.add_row(row(ip_src="2.2.2.2", ip_dst="1.1.1.1", dns_id="0x0064",
                   dns_response="True", dns_rcode="0", dns_answers="1"))      # answers query 1
    d = to_dict(ov)
    assert d["dns"]["queries"] == 2 and d["dns"]["answered"] == 1
    assert d["dns"]["responses"] == 1 and d["dns"]["rcode0"] == 1
    assert d["dns"]["answer_rate_pct"] == 50.0 and d["dns"]["success_rate_pct"] == 100.0


def test_dns_only_capture_rates_and_nulls():
    ov = Overview()
    ov.add_row(row(dns_id="0x0064", dns_response="False"))
    d = to_dict(ov)
    assert d["dns"]["answer_rate_pct"] == 0.0    # 1 query, 0 answered
    assert d["dns"]["success_rate_pct"] is None  # 0 responses: denominator 0 → null
    assert d["gtpu"]["volume"] == {"frames": 0, "bytes": 0}


def test_gtpu_volume_sums_gpdu_frame_len():
    ov = Overview()
    ov.add_row(row(gtp_message="0xff", frame_len="100"))
    ov.add_row(row(gtp_message="0xff", frame_len="150"))
    ov.add_row(row(gtp_message="0x02", frame_len="60"))   # echo is not a G-PDU
    assert to_dict(ov)["gtpu"]["volume"] == {"frames": 2, "bytes": 250}


def test_gy_given_and_reported_from_parallel_avps():
    ov = Overview()
    ov.add_row(row(app_id="4", req="False", rg="90,1054", sid="90,1000",
                   octets="102400000,358400000"))     # CCA: given
    ov.add_row(row(app_id="4", req="True", rg="1035", sid="1035",
                   octets="1024,0"))                   # CCR: reported
    d = to_dict(ov)["gy"]
    assert d["given_octets"] == 460800000 and d["reported_octets"] == 1024
    assert d["by_rg"] == [["90", {"given": 102400000, "reported": 0}],
                          ["1035", {"given": 0, "reported": 1024}],
                          ["1054", {"given": 358400000, "reported": 0}]]
    assert d["by_sid"] == [["90", {"given": 102400000, "reported": 0}],
                           ["1000", {"given": 358400000, "reported": 0}],
                           ["1035", {"given": 0, "reported": 1024}]]


def test_mismatched_parallel_lists_tail_is_zero():
    ov = Overview()
    ov.add_row(row(app_id="4", req="False", rg="90,1054", sid="90", octets="102400000"))
    assert to_dict(ov)["gy"]["by_rg"][1] == ["1054", {"given": 0, "reported": 0}]


def test_gx_rules_and_rule_bases():
    ov = Overview()
    ov.add_row(row(app_id="16777238", req="False", octets="102400000",
                   rule_name="rule_IMS_5,rule_IMS_6", rule_base="R_IMS_DEFAULT"))
    d = to_dict(ov)["gx"]
    assert d["given_octets"] == 102400000 and d["reported_octets"] == 0
    assert d["rule_bases"] == [["R_IMS_DEFAULT", 1]]
    assert d["rules"] == [["rule_IMS_5", 1], ["rule_IMS_6", 1]]


def test_cc_with_neither_app_id_is_skipped():
    ov = Overview()
    ov.add_row(row(app_id="3", req="False", octets="999"))
    assert to_dict(ov)["gx"] == {"given_octets": 0, "reported_octets": 0,
                                 "rules": [], "rule_bases": []}
    assert to_dict(ov)["gy"]["given_octets"] == 0


def test_result_code_mixed_instances():
    ov = Overview()
    ov.add_row(row(result_code="2001,4010"))     # one failure instance among successes
    ov.add_row(row(result_code="4010"))          # pure failure
    ov.add_row(row(result_code="5031|4010"))     # two occurrences, both failures
    assert to_dict(ov)["negative"] == {"Diameter": [["4010", 3], ["5031", 1]]}


def test_result_code_all_success_is_not_negative():
    ov = Overview()
    ov.add_row(row(result_code="2001"))
    assert "Diameter" not in to_dict(ov)["negative"]


def test_gtpv2_cause_other_than_accepted():
    ov = Overview()
    ov.add_row(row(gtpv2_cause="16"))            # accepted: ignored
    ov.add_row(row(gtpv2_cause="73"))            # no resources available
    ov.add_row(row(gtpv2_cause=""))              # request frame: no cause
    assert to_dict(ov)["negative"]["GTPv2"] == [["73", 1]]


def test_gtpv2_cause_multiple_occurrences_per_row():
    ov = Overview()
    ov.add_row(row(gtpv2_cause="16|16"))         # both accepted: ignored
    ov.add_row(row(gtpv2_cause="18|18"))         # both failures: one count per instance
    assert to_dict(ov)["negative"]["GTPv2"] == [["18", 2]]


def test_s1ap_ngap_unsuccessful_outcome():
    ov = Overview()
    ov.add_row(row(s1ap_outcome="1", s1ap_proc="9"))
    ov.add_row(row(s1ap_outcome="", s1ap_proc="9"))     # successful: ignored
    ov.add_row(row(ngap_outcome="1", ngap_proc="0"))
    assert to_dict(ov)["negative"] == {"S1AP": [["9", 1]], "NGAP": [["0", 1]]}


def test_loss_sn_gap_per_direction():
    ov = Overview()
    for sn in ("1", "3"):
        ov.add_row(row(gtp_message="0xff", sn_flag="True", sn=sn, frame_len="100"))
    ov.add_row(row(ip_src="2.2.2.2", ip_dst="1.1.1.1", gtp_message="0xff",
                   sn_flag="True", sn="1", frame_len="100"))   # other direction
    loss = to_dict(ov)["gtpu"]["loss"]
    assert loss == [{"src": "1.1.1.1", "dst": "2.2.2.2", "received": 2, "missing": 1, "pct": 33.3},
                    {"src": "2.2.2.2", "dst": "1.1.1.1", "received": 1, "missing": 0, "pct": 0.0}]


def test_sn_wraparound_gap():
    ov = Overview()
    for sn in ("65535", "1"):
        ov.add_row(row(gtp_message="0xff", sn_flag="True", sn=sn, frame_len="100"))
    assert to_dict(ov)["gtpu"]["loss"][0]["missing"] == 1


def test_duplicate_sn_is_ignored():
    ov = Overview()
    for sn in ("1", "1"):
        ov.add_row(row(gtp_message="0xff", sn_flag="True", sn=sn, frame_len="100"))
    assert to_dict(ov)["gtpu"]["loss"][0] == {"src": "1.1.1.1", "dst": "2.2.2.2",
                                              "received": 1, "missing": 0, "pct": 0.0}


def test_retrans_drop_rates_count_inner_tcp_only():
    ov = Overview()
    chain = "eth:ip:udp:gtp:ip:tcp"
    ov.add_row(row(protocols=chain, retrans="1"))
    ov.add_row(row(protocols=chain, lost="1"))
    ov.add_row(row(protocols=chain))
    d = to_dict(ov)["gtpu"]
    assert d["retrans_pct"] == 33.3 and d["drop_pct"] == 33.3


def test_gtpv2_is_not_inner_tcp():
    ov = Overview()
    ov.add_row(row(protocols="eth:ip:udp:gtpv2:tcp", retrans="1"))
    assert to_dict(ov)["gtpu"]["retrans_pct"] is None


def test_echo_no_response_counts_unanswered():
    ov = Overview()
    ov.add_row(row(gtp_message="0x01", sn="7"))
    ov.add_row(row(ip_src="2.2.2.2", ip_dst="1.1.1.1", gtp_message="0x02", sn="7"))
    ov.add_row(row(gtp_message="0x01", sn="9"))
    assert to_dict(ov)["gtpu"]["no_response"] == 1


def test_subscriber_imsi_fallback_and_counting():
    ov = Overview()
    ov.add_row(row(imsi="405123456789012", s1ap_imsi="999"))        # e212 wins over s1ap
    ov.add_row(row(s1ap_imsi="310150123456789"))                    # e212 empty: s1ap used
    ov.add_row(row(supi="imsi-405999000000001"))                    # pfcp used when earlier empty
    ov.add_row(row(imsi="405123456789012"))                         # same IMSI again
    d = to_dict(ov)["subscribers"]
    assert d["imsi"] == [["405123456789012", 2], ["310150123456789", 1],
                         ["imsi-405999000000001", 1]]  # most-common-first
    assert d["msisdn"] == []


def test_subscriber_msisdn_fallback_and_empty_rows():
    ov = Overview()
    ov.add_row(row(msisdn="8801712345678", camel_msisdn="999"))     # e164 wins over camel
    ov.add_row(row(camel_msisdn="8801111111111"))
    ov.add_row(row(gpsi="msisdn-8802222222222"))
    ov.add_row(row())                                                # no identity: adds nothing
    assert to_dict(ov)["subscribers"]["msisdn"] == [["8801111111111", 1],
                                                    ["8801712345678", 1],
                                                    ["msisdn-8802222222222", 1]]  # ties sort by value


def test_analyze_gtpv2_identities_end_to_end(tmp_path):
    from pcapgen import gtpv2_csr, write  # tests dir is on sys.path (see tests/test_capture.py:6)

    f = gtpv2_csr("10.3.0.1", "10.4.0.1", [(10, "10.3.0.1"), (7, "10.5.0.1")],
                  imsi="405123456789012", msisdn="8801712345678")
    pcap = write(tmp_path / "ids.pcap", [f])
    sub = json.loads(json.dumps(capture_to_dict(analyze(pcap))))["overview"]["subscribers"]
    assert sub["imsi"] == [["405123456789012", 1]]
    assert sub["msisdn"] == [["8801712345678", 1]]


def test_analyze_end_to_end_overview(tmp_path):
    from pcapgen import dns, gtpu_echo, gtpu_gpdu, ip, tcp, write  # tests dir is on sys.path (see tests/test_capture.py:6)

    a, b = "10.1.0.1", "10.2.0.1"
    frames = [
        dns(a, b, 0x100), dns(a, b, 0x200),                 # two queries
        dns(b, a, 0x100, resp=True, rcode=0, answers=1),    # one answered
        gtpu_gpdu(a, b, 1, 1), gtpu_gpdu(a, b, 1, 3),       # SN gap: 2 missing
        gtpu_echo(a, b, 2, 7), gtpu_echo(b, a, 2, 7, resp=True),
        gtpu_echo(a, b, 2, 9),                              # never answered
        # inner TCP retransmission: seg, ack, seg retransmitted
        gtpu_gpdu(a, b, 1, 0, ip(a, b, 6, tcp(a, b, 40000, 80, 100, b"x" * 10)), sn=False),
        gtpu_gpdu(b, a, 1, 0, ip(b, a, 6, tcp(b, a, 80, 40000, 1, b"", ack=110)), sn=False),
        gtpu_gpdu(a, b, 1, 0, ip(a, b, 6, tcp(a, b, 40000, 80, 100, b"x" * 10)), sn=False),
    ]
    pcap = write(tmp_path / "overview.pcap", frames)
    d = json.loads(json.dumps(capture_to_dict(analyze(pcap))))["overview"]
    assert d["dns"] == {"queries": 2, "answered": 1, "responses": 1, "rcode0": 1,
                        "answer_rate_pct": 50.0, "success_rate_pct": 100.0}
    assert d["gtpu"]["volume"]["frames"] == 5
    assert d["gtpu"]["loss"][0]["received"] == 2 and d["gtpu"]["loss"][0]["missing"] == 1
    assert d["gtpu"]["no_response"] == 1
    assert d["gtpu"]["retrans_pct"] == 33.3
    assert d["negative"] == {}
