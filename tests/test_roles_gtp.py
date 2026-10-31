from conftest import infer, row

GTPV2 = "eth:ethertype:ip:udp:gtpv2"
PFCP = "eth:ethertype:ip:udp:pfcp"
GTPU = "eth:ethertype:ip:udp:gtp:ip:tcp"


def gtpv2(types, ips, msg="32", **kw):
    return row(protocols=GTPV2, fields={"gtpv2.message_type": msg, "gtpv2.f_teid_interface_type": types,
                                        "gtpv2.f_teid_ipv4": ips} | kw)


def tun(n, isrc, idst, a="10.1.0.1", b="10.1.0.2"):
    return row(n, a, b, GTPU, {"ip.src": f"{a}|{isrc}", "ip.dst": f"{b}|{idst}"})


def test_fteid_roles_from_csr():
    nodes, _ = infer(gtpv2("10|7", "10.3.0.1|10.5.0.1"))
    assert nodes["10.3.0.1"].roles == {"MME"} and nodes["10.3.0.1"].interfaces == {"S11"}
    assert nodes["10.5.0.1"].roles == {"PGW"} and nodes["10.5.0.1"].interfaces == {"S5/S8-C"}


def test_fteid_misaligned_skipped():
    nodes, warnings = infer(gtpv2("10|7", "10.3.0.1"))
    assert not nodes["10.0.0.1"].roles and "10.3.0.1" not in nodes
    assert len(warnings) == 1 and "F-TEID" in warnings[0]


def test_saegw_dual_role():
    nodes, _ = infer(gtpv2("1|5", "10.3.0.1|10.3.0.1"))
    assert nodes["10.3.0.1"].roles == {"SGW", "PGW"}


def test_paa_marks_ue():
    nodes, _ = infer(row(protocols=GTPV2, fields={"gtpv2.message_type": "33",
                                                  "gtpv2.pdn_addr_and_prefix.ipv4": "100.64.0.5"}))
    assert nodes["100.64.0.5"].roles == {"UE"}


def test_pfcp_cp_up():
    nodes, _ = infer(row(src="10.8.0.1", dst="10.9.0.1", protocols=PFCP, fields={
        "pfcp.msg_type": "50", "pfcp.node_id_fqdn": "smf01.5gc.mnc001.mcc470.3gppnetwork.org"}))
    assert nodes["10.8.0.1"].roles == {"SMF/PGW-C"}
    assert nodes["10.8.0.1"].hostnames == {"smf01.5gc.mnc001.mcc470.3gppnetwork.org"}
    assert nodes["10.9.0.1"].roles == {"UPF"}


def test_pfcp_ue_ip():
    nodes, _ = infer(row(protocols=PFCP, fields={"pfcp.msg_type": "50", "pfcp.ue_ip_addr_ipv4": "100.65.0.9"}))
    assert nodes["100.65.0.9"].roles == {"UE"}


def test_gtpu_inner_ue_inference():
    nodes, _ = infer(tun(1, "100.64.0.1", "8.8.8.1"), tun(2, "8.8.8.2", "100.64.0.1"),
                     tun(3, "100.64.0.1", "8.8.8.1"))
    assert nodes["100.64.0.1"].roles == {"UE"} and nodes["100.64.0.1"].frames == 3
    assert nodes["8.8.8.1"].roles == nodes["8.8.8.2"].roles == {"Server"}
    assert not nodes["10.1.0.1"].roles and not nodes["10.1.0.2"].roles


def tie_rows():
    return [tun(1, "9.9.9.1", "9.9.9.2"), tun(2, "9.9.9.2", "9.9.9.1")]


def test_gtpu_tie_unresolved():
    nodes, warnings = infer(*tie_rows())
    assert not nodes["9.9.9.1"].roles and not nodes["9.9.9.2"].roles
    assert any("UE address ambiguous" in w for w in warnings)


def test_known_ue_overrides_inference():
    paa = row(protocols=GTPV2, fields={"gtpv2.message_type": "33", "gtpv2.pdn_addr_and_prefix.ipv4": "9.9.9.2"})
    nodes, _ = infer(paa, *tie_rows())
    assert nodes["9.9.9.2"].roles == {"UE"} and nodes["9.9.9.1"].roles == {"Server"}


def test_plain_ip_peer_of_ue_is_server():
    paa = row(protocols=GTPV2, fields={"gtpv2.message_type": "33", "gtpv2.pdn_addr_and_prefix.ipv4": "100.64.0.5"})
    nodes, _ = infer(paa, row(2, "100.64.0.5", "8.8.8.8"))
    assert nodes["8.8.8.8"].roles == {"Server"}


def bearer(n, teid, isrc, idst):
    return tun(n, isrc, idst) | {"gtp.teid": teid}


def multi_ue_rows():
    return [bearer(1, "1", "100.64.0.1", "8.8.8.1"), bearer(2, "1", "100.64.0.1", "8.8.8.2"),
            bearer(3, "2", "100.64.0.2", "8.8.8.3"), bearer(4, "2", "100.64.0.2", "8.8.8.1")]


def test_multi_ue_tunnel_by_teid():
    nodes, _ = infer(*multi_ue_rows())
    assert nodes["100.64.0.1"].roles == nodes["100.64.0.2"].roles == {"UE"}
    assert all(nodes[f"8.8.8.{i}"].roles == {"Server"} for i in (1, 2, 3))


def test_known_ue_does_not_make_tunnel_mates_servers():
    paa = row(protocols=GTPV2, fields={"gtpv2.message_type": "33", "gtpv2.pdn_addr_and_prefix.ipv4": "100.64.0.1"})
    nodes, _ = infer(paa, *multi_ue_rows())
    assert nodes["100.64.0.2"].roles == {"UE"}


def test_plain_peer_of_inferred_ue_is_server():
    nodes, _ = infer(tun(1, "100.64.0.1", "8.8.8.1"), tun(3, "100.64.0.1", "8.8.8.2"), row(2, "100.64.0.1", "7.7.7.7"))
    assert nodes["7.7.7.7"].roles == {"Server"}


def test_nodes_idempotent_after_more_rows():
    from unipcap.roles import RoleInference
    ri = RoleInference()
    ri.add(gtpv2("10|7", "10.3.0.1"))
    for r in tie_rows():
        ri.add(r)
    ri.nodes()
    ri.add(row(9, "10.0.0.7", "10.0.0.8"))
    ri.nodes()
    nodes = {n.ip: n for n in ri.nodes()}
    assert len(ri.warnings) == 2 and len(set(ri.warnings)) == 2
    assert all(len(set(n.evidence)) == len(n.evidence) for n in nodes.values())


def test_link_local_frames_ignored_in_bearer():
    rs = [tun(1, "10.9.0.1", "8.8.8.1"), tun(2, "10.9.0.1", "8.8.8.2"),
          row(3, "10.1.0.1", "10.1.0.2", "eth:ethertype:ip:udp:gtp:ipv6:icmpv6",
              {"ip.src": "10.1.0.1", "ip.dst": "10.1.0.2", "ipv6.src": "fe80::1", "ipv6.dst": "ff02::2"})]
    nodes, _ = infer(*rs)
    assert nodes["10.9.0.1"].roles == {"UE"}
    assert not any(nodes[ip].roles for ip in ("fe80::1", "ff02::2") if ip in nodes)


def test_paa_in_csr_ignored():
    nodes, _ = infer(row(protocols=GTPV2, fields={"gtpv2.message_type": "32",
                                                  "gtpv2.pdn_addr_and_prefix.ipv4": "0.0.0.0"}))
    assert all("UE" not in n.roles for n in nodes.values())
