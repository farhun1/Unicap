# Sample captures

Put sanitized captures (`.pcap`, `.pcapng`, `.cap`, `.gz`) in this folder.
Everything here except this README stays out of git, because captures carry
subscriber data.

Next to each capture, add a `<name>.expected.json` that lists the node IPs you
know are correct, grouped by role:

```
lte_attach.pcap
lte_attach.expected.json
```

```json
{
  "eNodeB": ["10.1.1.1"],
  "MME": ["10.2.2.2"],
  "SGW": ["10.3.3.3"],
  "PGW": ["10.4.4.4"],
  "DRA": ["10.7.7.7"],
  "HSS": ["10.8.8.8"]
}
```

Role names: `eNodeB gNB MME AMF SGW PGW SMF/PGW-C UPF HSS PCRF OCS EIR AAA
P-CSCF DRA DEA STP UE Server`.

The test `tests/test_samples.py` checks that the app finds at least these IPs
for each role. List only what you are sure of. Leaving a role out means it
isn't checked; it does not mean the role should be absent.

To assert a role must be absent, add an optional `"not"` key mapping roles to
IPs that must NOT carry that role:

```json
{ "not": { "UE": ["10.9.9.9"], "HSS": ["10.2.2.2"] } }
```

Useful captures to have:
- an LTE attach (S1AP/NAS + GTPv2 S11/S5 + Diameter S6a);
- Diameter going through a DRA or DEA;
- a user-plane trace (GTP-U on S1-U and/or S5/S8);
- a 5G trace (NGAP + PFCP), if you have one;
- SS7/SIGTRAN through an STP, if you have one.
