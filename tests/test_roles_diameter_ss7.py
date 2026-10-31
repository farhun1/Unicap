from conftest import infer, row, RoleInference

ORH = "epc.mnc001.mcc470.3gppnetwork.org"
DRH = "epc.mnc003.mcc404.3gppnetwork.org"


def dia(n, src, dst, cmd="316", req="1", app="16777251", sid="s1", **kw):
    f = {"diameter.cmd.code": cmd, "diameter.flags.request": req,
         "diameter.applicationId": app, "diameter.Session-Id": sid}
    f |= {"diameter." + k.replace("_", "-"): v for k, v in kw.items()}
    return row(n, src, dst, "eth:ethertype:ip:sctp:diameter", f)


def roles(nodes):
    return {ip: n.roles for ip, n in nodes.items()}


def test_diameter_s6a_direct():
    r = roles(infer(dia(1, "A", "B"))[0])
    assert r["A"] == {"MME"} and r["B"] == {"HSS"}


def test_diameter_via_dra():
    r = roles(infer(dia(1, "A", "X"), dia(2, "X", "B"))[0])
    assert r == {"A": {"MME"}, "X": {"DRA"}, "B": {"HSS"}}


def test_diameter_dea_by_realm():
    r = roles(infer(dia(1, "A", "X", Origin_Realm=ORH, Destination_Realm=DRH), dia(2, "X", "B"))[0])
    assert r["X"] == {"DEA"}


def test_diameter_cer_binds_hostname():
    nodes, _ = infer(dia(1, "X", "Y", cmd="257", Origin_Host="dra1." + ORH),
                     dia(2, "A", "X", Origin_Host="mme1." + ORH), dia(3, "X", "B", Origin_Host="mme1." + ORH))
    assert "dra1." + ORH in nodes["X"].hostnames
    assert not any("mme1" in h for n in nodes.values() for h in n.hostnames)


def test_diameter_answers_ignored_for_roles():
    assert not any(roles(infer(dia(1, "B", "A", req="0"))[0]).values())


def test_diameter_bundled_mismatch_skipped():
    nodes, warns = infer(dia(1, "A", "B", cmd="257|316", req="1|1"))
    assert not any(roles(nodes).values())
    assert any("Diameter" in w for w in warns)


def test_gx_pgw_pcrf():
    r = roles(infer(dia(1, "A", "B", cmd="272", app="16777238"))[0])
    assert r["A"] == {"PGW"} and r["B"] == {"PCRF"}


def test_diameter_idempotent_when_add_follows_nodes():
    ri = RoleInference()
    ri.add(dia(1, "A", "X"))
    ri.nodes()
    ri.add(dia(2, "X", "B"))
    ri.nodes()
    assert {n.ip: n.roles for n in ri.nodes()} == {"A": {"MME"}, "X": {"DRA"}, "B": {"HSS"}}
    assert ri.warnings == []


def m3(n, src, dst, opc):
    return row(n, src, dst, "eth:ethertype:ip:sctp:m3ua", {"m3ua.protocol_data_opc": opc})


def test_m3ua_stp_relay():
    r = roles(infer(m3(1, "A", "X", "100"), m3(2, "X", "B", "100"))[0])
    assert r["X"] == {"STP"} and not r["A"] and not r["B"]


def test_m3ua_multi_opc_sender_is_stp():
    assert roles(infer(m3(1, "X", "B", "100"), m3(2, "X", "B", "200"))[0])["X"] == {"STP"}


def test_diameter_sessions_evicted_on_answer():
    ri = RoleInference()
    for i in range(1000):
        ri.add(dia(2 * i, "A", "B", sid=f"s{i}"))
        ri.add(dia(2 * i + 1, "B", "A", req="0", sid=f"s{i}"))
    assert not ri.dia_open
    assert {n.ip: n.roles for n in ri.nodes()} == {"A": {"MME"}, "B": {"HSS"}}


def test_agent_never_gets_server_role_across_sessions():
    r = roles(infer(dia(1, "A", "X"), dia(2, "X", "B"), dia(3, "C", "X", sid="s2"))[0])
    assert r["X"] == {"DRA"}


def test_per_row_role_survives_resolve_revocation():
    ri = RoleInference()
    ri.add(dia(1, "A", "B"))
    ri.nodes()
    ri.add(row(2, "E", "A", "eth:ethertype:ip:sctp:s1ap", {"_ws.col.info": "InitialUEMessage"}))
    ri.nodes()
    ri.add(dia(3, "Z", "A"))  # A becomes a relay: its derived MME role is retracted, the S1AP one stays
    assert {n.ip: n.roles for n in ri.nodes()}["A"] == {"MME", "DRA"}


def test_dea_by_hostname():
    nodes, _ = infer(dia(1, "X", "Y", cmd="280", Origin_Host="dea1.example.org"),
                     dia(2, "A", "X"), dia(3, "X", "B"))
    assert nodes["X"].roles == {"DEA"}


def test_diameter_clr_hss_to_mme():
    r = roles(infer(dia(1, "B", "A", cmd="317"))[0])
    assert r["B"] == {"HSS"} and r["A"] == {"MME"}


def test_gx_rar_pcrf_to_pgw():
    r = roles(infer(dia(1, "P", "G", cmd="258", app="16777238"))[0])
    assert r["P"] == {"PCRF"} and r["G"] == {"PGW"}


def test_ulr_and_clr_same_pair():
    r = roles(infer(dia(1, "A", "B", sid="s1"), dia(2, "B", "A", cmd="317", sid="s2"))[0])
    assert r["A"] == {"MME"} and r["B"] == {"HSS"}
