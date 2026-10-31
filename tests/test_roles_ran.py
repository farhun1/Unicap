from conftest import infer, row
from unipcap.roles import RoleInference, outer_inner

S1 = "eth:ethertype:ip:sctp:s1ap:nas-eps"
NG = "eth:ethertype:ip:sctp:ngap:nas-5gs"


def s1(info, src="10.1.1.1", dst="10.2.2.2", sp="4000", dp="4000", protocols=S1, n=1):
    return row(n, src, dst, protocols, {"_ws.col.info": info, "sctp.srcport": sp, "sctp.dstport": dp})


def test_outer_inner_gtpu():
    r = row(protocols="eth:ethertype:ip:udp:gtp:ip:tcp",
            fields={"ip.src": "1.1.1.1|100.64.0.5", "ip.dst": "2.2.2.2|142.250.1.1"})
    assert outer_inner(r) == ("1.1.1.1", "2.2.2.2", "100.64.0.5", "142.250.1.1")


def test_outer_inner_v6_outer_v4_inner():
    r = {"frame.protocols": "eth:ethertype:ipv6:udp:gtp:ip:tcp", "ipv6.src": "fd00::1",
         "ipv6.dst": "fd00::2", "ip.src": "100.64.0.5", "ip.dst": "8.8.8.8"}
    assert outer_inner(r) == ("fd00::1", "fd00::2", "100.64.0.5", "8.8.8.8")


def test_s1ap_initial_ue_marks_enb_and_mme():
    nodes, _ = infer(s1("InitialUEMessage, Attach request"))
    assert nodes["10.1.1.1"].roles == {"eNodeB"}
    assert nodes["10.2.2.2"].roles == {"MME"}
    ev = nodes["10.1.1.1"].evidence[0]
    assert "frame 1" in ev and "InitialUEMessage" in ev


def test_s1ap_downlink_direction():
    nodes, _ = infer(s1("DownlinkNASTransport, Attach accept", src="10.2.2.2", dst="10.1.1.1"))
    assert nodes["10.1.1.1"].roles == {"eNodeB"} and nodes["10.2.2.2"].roles == {"MME"}


def test_s1ap_nonstandard_port():
    nodes, _ = infer(s1("UplinkNASTransport, TAU complete"))
    assert nodes["10.1.1.1"].roles == {"eNodeB"} and nodes["10.2.2.2"].roles == {"MME"}


def test_s1ap_port_fallback():
    nodes, _ = infer(s1("Reset", sp="40000", dp="36412"))
    assert nodes["10.2.2.2"].roles == {"MME"} and nodes["10.1.1.1"].roles == {"eNodeB"}


def test_s1ap_both_ports_36412_unknown_msg_no_role():
    nodes, _ = infer(s1("Reset", sp="36412", dp="36412"))
    assert all(not n.roles for n in nodes.values())


def test_ngap_gnb_amf():
    nodes, _ = infer(s1("NGSetupRequest", protocols=NG))
    assert nodes["10.1.1.1"].roles == {"gNB"} and nodes["10.2.2.2"].roles == {"AMF"}


def test_hostname_hint_only_without_protocol_role():
    ri = RoleInference()
    ri.node("10.9.9.9").hostnames.add("dhk-saegw01.epc.example")
    ri.node("10.2.2.2").hostnames.add("dhk-saegw01.epc.example")
    ri.add(s1("InitialUEMessage, Attach request"))
    nodes = {n.ip: n for n in ri.nodes()}
    assert nodes["10.9.9.9"].roles == {"SGW", "PGW"}
    assert any("hostname hint" in e for e in nodes["10.9.9.9"].evidence)
    assert nodes["10.2.2.2"].roles == {"MME"}


def test_evidence_capped_per_role():
    nodes, _ = infer(*[s1("UplinkNASTransport", n=i) for i in range(1, 7)])
    assert len(nodes["10.1.1.1"].evidence) == 3


def test_frames_and_protocol_counts():
    f = lambda p: {"_ws.col.protocol": p}
    nodes, _ = infer(row(1, fields=f("S1AP/NAS-EPS")), row(2, fields=f("S1AP/NAS-EPS")), row(3, fields=f("SCTP")))
    n = nodes["10.0.0.1"]
    assert n.frames == 3 and n.protocols["S1AP/NAS-EPS"] == 2


def test_outer_inner_gtp_inner_v6_labelled_ip():
    r = {"frame.protocols": "eth:ethertype:vlan:ethertype:ip:udp:gtp:ip:tcp",
         "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2",
         "ipv6.src": "2001:db8::5", "ipv6.dst": "64:ff9b::1"}
    assert outer_inner(r) == ("10.0.0.1", "10.0.0.2", "2001:db8::5", "64:ff9b::1")


def test_ngap_uplink_nonstandard_port():
    nodes, _ = infer(s1("UplinkNASTransport", sp="5000", dp="5000", protocols=NG))
    assert nodes["10.1.1.1"].roles == {"gNB"} and nodes["10.2.2.2"].roles == {"AMF"}


def test_ngap_downlink_direction():
    nodes, _ = infer(s1("DownlinkNASTransport", src="10.2.2.2", dst="10.1.1.1", protocols=NG))
    assert nodes["10.1.1.1"].roles == {"gNB"} and nodes["10.2.2.2"].roles == {"AMF"}


def test_ngap_port_fallback():
    nodes, _ = infer(s1("Reset", sp="40000", dp="38412", protocols=NG))
    assert nodes["10.2.2.2"].roles == {"AMF"} and nodes["10.1.1.1"].roles == {"gNB"}


def test_unspecified_address_never_labelled():
    nodes, _ = infer(s1("InitialUEMessage", src="0.0.0.0", dst="0.0.0.0"))
    assert nodes == {}
