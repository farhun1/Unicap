# UniPCAP — Vision and Feature Roadmap

## Purpose

A portable desktop app that makes telco PCAP troubleshooting easy. Open a
.pcap/.pcapng and get, without knowing Wireshark filters:

- automatic decoding of DIAMETER, SIP, S1AP, NAS, NGAP, GTPv2-C, GTP-U, PFCP,
  SCTP/M3UA/MAP and other protocols;
- a dashboard that names the network nodes found in the trace: eNodeB, gNB, MME,
  AMF, SGW, PGW, SMF, UPF, HSS, PCRF, OCS, DRA, DEA, STP, UE, internet servers;
- for each node, the signaling flow (end-to-end ladder / stick diagram between
  auto-labelled nodes, labelled from the trace's own hostnames and IPs) and the
  data flow;
- data flows classified by service/destination (Google, Facebook, …), each
  service with its own colour;
- every user-plane leg that the capture contains: UE↔eNodeB, eNodeB↔SGW (S1-U),
  SGW↔PGW (S5/S8), PGW↔server (SGi/N6), UE↔server;
- the analysis method of the author's `telco-pcap-analyze` skill (cause-code
  gate, tunnel map, in-vs-out test, policy-discard gate, loss by size, MTU
  arithmetic, vendor DataTrace handling), surfaced as automatic checks.

## Decisions (2026-10-29)

| Topic | Decision |
|---|---|
| Decoder | Require an installed Wireshark: find tshark via `UNIPCAP_TSHARK`, then `PATH`, then `C:\Program Files\Wireshark`. Nothing third-party is bundled. |
| App shell | Python stdlib `http.server` on `127.0.0.1` (random token path) opened in the user's default browser; PyInstaller one-folder build. |
| Portability | No install. Unzip the folder and run `unipcap.exe`. Nothing is written outside the folder except temp files. |
| Target OS | Windows x64 only for now. Keep the code cross-platform. |
| Test data | The user provides sanitized captures in `samples/`, which is git-ignored. Each capture gets a `<name>.expected.json` listing the node IPs the user knows are correct. |

## Feature roadmap (one plan per feature, in order)

1. **Foundation + node dashboard**: portable shell, installed tshark, a one-pass
   analysis, node-role inference with evidence, and a dashboard grouped by role.
2. **Signaling flow**: a ladder diagram between auto-labelled nodes, filterable
   per node or per subscriber (IMSI/UE IP), with click-through to the decoded
   message.
3. **Data flow by service**: classify flows by DNS/SNI/HTTP host into services,
   each service with its own colour.
4. **User-plane leg map**: all legs present, the same packet correlated across
   legs.
5. **Fault checks from the skill**: the cause gate, in-vs-out per transit node,
   the policy gate, loss by size, MTU, vendor DataTrace mapping.
6. **Polish**: drag & drop, report export, Decode-As for non-standard ports, a
   smaller bundle.
