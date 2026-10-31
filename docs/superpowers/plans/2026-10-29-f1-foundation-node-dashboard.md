# F1 — Foundation + Node Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Open a capture in a portable Windows app and see a dashboard that names every eNodeB, gNB, MME, AMF, SGW, PGW, SMF, UPF, HSS, PCRF, OCS, DRA, DEA, STP, UE and server IP in it, with the evidence for each label.

**Architecture:** A bundled `tshark.exe` reads the capture once (`-T fields`) and streams rows (`dict[str, str]`) into `RoleInference`. It assigns roles from protocol evidence (S1AP/NGAP direction, GTPv2 F-TEID interface types, PFCP requests, Diameter application + relay detection, M3UA relay detection, GTP-U inner addresses) and falls back to hostname hints. `capture.analyze()` returns a `Summary`. A pywebview window shows it as JSON-driven vanilla HTML/JS.

**Tech Stack:** Python 3.12 (via `uv`), pywebview ≥5 (WebView2 on Windows), PyInstaller ≥6 one-folder, pytest, Wireshark 4.4+ `tshark` (vendored). No JS framework.

**Spec:** `docs/superpowers/specs/2026-10-29-unipcap-vision.md` (roadmap item 1)

## Global Constraints

- Windows x64 only. Portable: unzip and run `unipcap.exe`. No installer, no registry, nothing written outside the app folder except `%TEMP%`.
- All decoding comes from the bundled tshark. Do not hand-write protocol parsers. Vendor-record byte parsing is F5, not F1.
- Wireshark's `COPYING.txt` ships inside `vendor/wireshark/` and is never deleted.
- Python 3.12, not the system 3.15 (pythonnet/PyInstaller support). Create the env with `uv venv --python 3.12`.
- tshark is always run with `-n` (no name resolution) and with list args (no shell).
- Multi-occurrence fields are joined with `|` (`-E aggregator=|`). For tunnelled frames, the first value is the outer header and the last is the inner one.
- Captures under `samples/` contain subscriber data. `samples/*` is git-ignored, except `samples/README.md`.
- The app never edits the input capture.

## Review Focus

1. **Truncated capture** (tshark: "cut short in the middle of a packet", exit 2), which is common with live-copied traces: show results for the packets read, plus a warning. Never fail with no output. → Task 2 `test_truncated_capture_yields_rows_and_warning`.
2. **Path with spaces / non-ASCII** (e.g. `C:\Users\রহিম\My Traces\a.pcap`): opens normally. → Task 2 `test_unicode_path_with_spaces`.
3. **Non-capture file chosen** (a .txt or .zip): the UI shows tshark's message. No crash, no empty dashboard. → Task 2 `test_non_capture_raises_tsharkerror`, Task 7 `test_api_analyze_reports_error`.
4. **Large capture (≥1 GB)**: memory stays flat. Rows are streamed, never collected, and tshark's stderr goes to a temp file so a full pipe cannot deadlock. → Task 6 `test_analyze_memory_bounded`.
5. **Multiple Diameter messages bundled in one SCTP frame** misalign the `|` lists (CER has no Session-Id). Skip that frame and count a warning. Never assign a role from misaligned lists. → Task 5 `test_diameter_bundled_mismatch_skipped`.

## Sample corpus facts (profiled 2026-10-29, `samples/`, 134 files, 4.8 GB)

- Every file is classic pcap, mostly Ethernet. Some are SLL2 (276) or raw IP (101, PCAPdroid handset captures). One file is header-only (0 frames). 3 `DataTrace_Upf_4_20260429*` files are truncated. `DGW_2.pcap` is 1.0 GB / 886k frames.
- Real traces use **non-standard SCTP ports**: S1AP on 4000; Diameter on 3869, 43201, 5008; M3UA on 2930, 3648, 20301. tshark decodes these by PPID (18/46/3), so role rules must never depend on the standard ports. Some SCTP DATA carries PPID 0 or 9 on ports 2641, 2520–2663, 9863 and does **not** decode. F1 reports these, and Decode-As is F6.
- Out-of-order timestamps (`export_ETHERNET_*`, `PCAP-bangladesh`): last frame < first frame. The capture span must use min/max, not first/last.
- Huawei UGW user traces (`*UGW*_User_Trace*`) and ZTE `DataTrace_Upf_*` carry each user packet twice (GTP-U copy + plain-IP copy) on several VLAN trace points.
- 12 sets of byte-identical duplicates (`_1`, `(1)` copies).

---

## File Structure

```
pyproject.toml                    package + deps; pytest config
.gitignore
scripts/vendor_wireshark.ps1      copies an installed Wireshark into vendor/wireshark (+ VC++ runtime DLLs)
scripts/build.ps1                 PyInstaller one-folder build
scripts/smoke.ps1                 runs the frozen exe headless against a fixture, with tshark absent from PATH
src/unipcap/__init__.py
src/unipcap/__main__.py           -> app.main()
src/unipcap/tshark.py             locate tshark; stream -T fields rows
src/unipcap/roles.py              Node, RoleInference: all role rules
src/unipcap/capture.py            analyze(): one pass -> Summary; to_dict()
src/unipcap/app.py                Api (js_api) + main() (window or --analyze headless)
src/unipcap/web/index.html, app.js, style.css
tests/pcapgen.py                  writes tiny classic pcaps (UDP, GTPv2 CSR)
tests/test_tshark.py, test_roles_ran.py, test_roles_gtp.py, test_roles_diameter_ss7.py,
tests/test_capture.py, test_app.py, test_samples.py
tests/fixtures/gtpv2_csr.pcap     generated, committed
samples/README.md                 how to add a sample + expected.json
```

---

### Task 1: Scaffold, vendored tshark, `find_tshark`

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `scripts/vendor_wireshark.ps1`, `src/unipcap/__init__.py`, `src/unipcap/tshark.py`, `samples/README.md`
- Test: `tests/test_tshark.py`

**Interfaces:**
- Produces: `find_tshark() -> pathlib.Path`, `class TsharkNotFound(RuntimeError)`, `bundle_root() -> Path` (`Path(sys._MEIPASS)` when frozen, else the repo root).

- [ ] **Step 1: Initialise.** `git init`. Write `.gitignore` (`.venv/ build/ dist/ vendor/ __pycache__/ samples/*` and `!samples/README.md`). Write `pyproject.toml`: name `unipcap`, `requires-python = ">=3.12,<3.13"`, deps `pywebview>=5`, optional `dev = ["pytest", "pyinstaller>=6"]`, src layout, `[tool.pytest.ini_options] testpaths=["tests"]`. Then run `uv venv --python 3.12 && uv pip install -e .[dev]`.
- [ ] **Step 2: Vendor Wireshark.** Install Wireshark on the dev machine only (`winget install WiresharkFoundation.Wireshark`). `scripts/vendor_wireshark.ps1 [-Source "C:\Program Files\Wireshark"]` does a robocopy `/E` of the folder into `vendor/wireshark/`. It copies `vcruntime140.dll`, `vcruntime140_1.dll` and `msvcp140.dll` from `System32` into the same folder, because a clean machine may lack the VC++ runtime. It writes `vendor/wireshark/VERSION` from `tshark --version` line 1. `# shortcut: copies the whole Wireshark folder (~250 MB incl. Qt GUI DLLs); prune to tshark's deps in F6.`
  Run it. Expected: `vendor\wireshark\tshark.exe -v` prints `TShark (Wireshark) 4.x`.
- [ ] **Step 3: Write failing tests**

```python
def test_env_override_wins(tmp_path, monkeypatch):
    exe = tmp_path / "tshark.exe"; exe.write_bytes(b"")
    monkeypatch.setenv("UNIPCAP_TSHARK", str(exe))
    assert find_tshark() == exe

def test_bundled_used_when_no_env(monkeypatch):
    monkeypatch.delenv("UNIPCAP_TSHARK", raising=False)
    assert find_tshark() == bundle_root() / "vendor" / "wireshark" / "tshark.exe"

def test_not_found(tmp_path, monkeypatch):
    monkeypatch.delenv("UNIPCAP_TSHARK", raising=False)
    monkeypatch.setattr("unipcap.tshark.bundle_root", lambda: tmp_path)
    monkeypatch.setenv("PATH", "")
    with pytest.raises(TsharkNotFound):
        find_tshark()
```

- [ ] **Step 4:** Run `uv run pytest tests/test_tshark.py -v`. Expected: FAIL (ImportError).
- [ ] **Step 5: Implement `find_tshark()`.** Lookup order: env `UNIPCAP_TSHARK` (if the file exists), then `bundle_root()/vendor/wireshark/tshark.exe`, then `shutil.which("tshark")`. Otherwise raise `TsharkNotFound` with a message naming the bundled path.
- [ ] **Step 6:** Run the tests. Expected: 3 passed.
- [ ] **Step 7:** Write `samples/README.md`: put sanitized captures here, and next to each one a `<name>.expected.json` such as `{"eNodeB": ["10.1.1.1"], "MME": ["10.2.2.2"]}` (role → IPs you know are right). Then commit: `git add -A && git commit -m "chore: scaffold unipcap, vendor tshark, find_tshark"`.

---

### Task 2: `iter_fields` — stream tshark rows

**Files:**
- Modify: `src/unipcap/tshark.py`
- Create: `tests/pcapgen.py`
- Test: `tests/test_tshark.py`

**Interfaces:**
- Consumes: `find_tshark()`.
- Produces: `iter_fields(pcap: Path, fields: list[str], display_filter: str = "", warnings: list[str] | None = None) -> Iterator[dict[str, str]]`, `class TsharkError(RuntimeError)`, `vals(row: dict[str, str], field: str) -> list[str]` (split on `|`, `[]` when empty).
- Produces (tests): `pcapgen.udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes` (Ethernet+IPv4+UDP frame, checksums 0) and `pcapgen.write(path: Path, frames: list[bytes]) -> Path` (classic little-endian pcap, linktype 1, timestamps 1 s apart starting at 1_700_000_000).

- [ ] **Step 1: Write failing tests**

```python
FIELDS = ["frame.number", "ip.src", "udp.dstport", "_ws.col.protocol"]

def test_rows_stream(tmp_path):
    p = pcapgen.write(tmp_path / "a.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1000, 9999, b"x")] * 3)
    rows = list(iter_fields(p, FIELDS))
    assert len(rows) == 3
    assert rows[0] == {"frame.number": "1", "ip.src": "10.0.0.1", "udp.dstport": "9999", "_ws.col.protocol": "UDP"}

def test_display_filter(tmp_path): ...   # 2 frames, dport 53 and 9999; -Y "udp.dstport==53" -> 1 row

def test_truncated_capture_yields_rows_and_warning(tmp_path):
    p = pcapgen.write(tmp_path / "t.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x" * 100)] * 5)
    p.write_bytes(p.read_bytes()[:-50])
    warnings = []
    rows = list(iter_fields(p, FIELDS, warnings=warnings))
    assert len(rows) == 4 and warnings and "cut short" in warnings[0]

def test_unicode_path_with_spaces(tmp_path):
    d = tmp_path / "My Traces রহিম"; d.mkdir()
    p = pcapgen.write(d / "ক.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x")])
    assert len(list(iter_fields(p, FIELDS))) == 1

def test_non_capture_raises_tsharkerror(tmp_path):
    p = tmp_path / "notes.txt"; p.write_text("hello")
    with pytest.raises(TsharkError, match="(?i)file format|isn't a capture"):
        list(iter_fields(p, FIELDS))
```

- [ ] **Step 2:** Run `uv run pytest tests/test_tshark.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.** Command: `[tshark, "-n", "-r", str(pcap), "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=|", *("-Y", f) if f, *("-e", x) for x in fields]`. Use `Popen` with `stdout=PIPE`, `encoding="utf-8", errors="replace"`, `stderr` set to a `tempfile.TemporaryFile`, and `creationflags=CREATE_NO_WINDOW` on Windows. Yield `dict(zip(fields, line.rstrip("\n").split("\t")))` per line. After EOF, `wait()`. On non-zero exit: no rows yielded → raise `TsharkError(stderr)`; rows yielded → append the stderr text to `warnings`. If the consumer stops early, terminate the process in `finally`.
- [ ] **Step 4:** Run the tests. Expected: all pass.
- [ ] **Step 5:** Commit: `git commit -am "feat: stream tshark field rows"` (plus `git add tests/pcapgen.py`).

---

### Task 3: `RoleInference` core + RAN rules + hostname hints

**Files:**
- Create: `src/unipcap/roles.py`, `tests/conftest.py`
- Test: `tests/test_roles_ran.py`

**Interfaces:**
- Consumes: `vals()` from `unipcap.tshark`.
- Produces:
  - `FIELDS: list[str]`: every tshark field `roles.py` reads. Start with `frame.number, frame.protocols, ip.src, ip.dst, ipv6.src, ipv6.dst, sctp.srcport, sctp.dstport, udp.srcport, udp.dstport, _ws.col.protocol, _ws.col.info`. Tasks 4–5 append to it.
  - `@dataclass Node: ip: str; roles: set[str]; interfaces: set[str]; hostnames: set[str]; evidence: list[str]; protocols: Counter[str]; frames: int`
  - `class RoleInference: add(row: dict[str,str]) -> None; nodes() -> list[Node]` (sorted by IP, only IPs seen); `warnings: list[str]`
  - `outer_inner(row) -> tuple[str|None, str|None, str|None, str|None]`: (outer src, outer dst, inner src, inner dst). Walk `frame.protocols` tokens. Each `ip`/`ipv6` token consumes the next value from `ip.src`/`ipv6.src` (and dst) lists, in order. Outer = first IP layer. Inner = last IP layer, or `None` when there is only one.
  - Role names used everywhere: `eNodeB gNB MME AMF SGW PGW SMF/PGW-C UPF HSS PCRF OCS EIR AAA P-CSCF DRA DEA STP UE Server`.
- Test helpers in `tests/conftest.py` (Tasks 4–5 reuse them): `row(n=1, src="10.0.0.1", dst="10.0.0.2", protocols="eth:ethertype:ip:udp", fields: dict[str, str] | None = None) -> dict[str, str]`, and `infer(*rows) -> tuple[dict[str, Node], list[str]]` (nodes by IP, warnings).

- [ ] **Step 1: Write failing tests**

| test | rows | assert |
|---|---|---|
| `test_outer_inner_gtpu` | protocols `eth:ethertype:ip:udp:gtp:ip:tcp`, `ip.src="1.1.1.1\|100.64.0.5"`, `ip.dst="2.2.2.2\|142.250.1.1"` | `("1.1.1.1","2.2.2.2","100.64.0.5","142.250.1.1")` |
| `test_outer_inner_v6_outer_v4_inner` | `eth:ethertype:ipv6:udp:gtp:ip:tcp`, ipv6 src/dst `fd00::1`/`fd00::2`, ip `100.64.0.5`/`8.8.8.8` | outer is v6, inner is v4 |
| `test_s1ap_initial_ue_marks_enb_and_mme` | src `10.1.1.1`, dst `10.2.2.2`, protocols `…:sctp:s1ap:nas-eps`, info `InitialUEMessage, Attach request` | `10.1.1.1.roles=={"eNodeB"}`, `10.2.2.2.roles=={"MME"}`, evidence[0] contains `"frame 1"` and `"InitialUEMessage"` |
| `test_s1ap_downlink_direction` | info `DownlinkNASTransport, …` src `10.2.2.2` dst `10.1.1.1` | same two roles |
| `test_s1ap_nonstandard_port` | info `UplinkNASTransport, …`, sctp `4000→4000` | src eNodeB, dst MME (message rule, port ignored) |
| `test_s1ap_port_fallback` | info `Reset`, sctp `40000→36412` | dst MME, src eNodeB |
| `test_s1ap_both_ports_36412_unknown_msg_no_role` | info `Reset`, sctp `36412→36412` | no roles |
| `test_ngap_gnb_amf` | `…:ngap:nas-5gs`, info `NGSetupRequest` | gNB / AMF |
| `test_hostname_hint_only_without_protocol_role` | Node with hostname `dhk-saegw01.epc…` and no evidence | roles `{"SGW","PGW"}`, evidence contains `"hostname hint"`. Same hostname on an IP already marked MME by S1AP → stays `{"MME"}` |
| `test_frames_and_protocol_counts` | 3 rows, same src, `_ws.col.protocol` `S1AP/NAS-EPS` ×2, `SCTP` ×1 | `frames==3`, `protocols["S1AP/NAS-EPS"]==2` |

- [ ] **Step 2:** Run `uv run pytest tests/test_roles_ran.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** in `roles.py`. Rules:
  - S1AP: tokenise `_ws.col.info` with `re.findall(r"[A-Za-z0-9]+", info)`. If any token is in `S1_UP = {S1SetupRequest, InitialUEMessage, UplinkNASTransport, UEContextReleaseRequest, PathSwitchRequest, HandoverRequired}`, then src=eNodeB and dst=MME. If any is in `S1_DOWN = {S1SetupResponse, DownlinkNASTransport, InitialContextSetupRequest, UEContextReleaseCommand, Paging}`, the reverse. Otherwise, if exactly one SCTP port is 36412, that side is MME.
  - NGAP: the same, with `NGSetupRequest/NGSetupResponse` and port 38412, giving gNB/AMF.
  - Evidence string format: `f"frame {n}: {proto} {msg} ({src}→{dst})"`. Cap it at 3 per (node, role).
  - Hostname hints, applied in `nodes()` only to nodes with no roles. Ordered substring table on the lower-cased hostname: `saegw|spgw→{SGW,PGW}, mme, sgw, pgw, ggsn→PGW, amf, smf→SMF/PGW-C, upf, hss, pcrf, ocs, dra, dea, stp, pcscf→P-CSCF, enb→eNodeB, gnb`. Evidence: `"hostname hint: <name>"`.
- [ ] **Step 4:** Run the tests. Expected: pass.
- [ ] **Step 5:** Commit: `git commit -m "feat: role inference core with S1AP/NGAP rules"`.

---

### Task 4: GTPv2-C, PFCP, GTP-U → SGW/PGW/SMF/UPF/UE/Server

**Files:**
- Modify: `src/unipcap/roles.py`
- Test: `tests/test_roles_gtp.py`

**Interfaces:**
- Consumes: Task 3 `RoleInference`, `outer_inner`, test helpers.
- Produces: `FIELDS += gtpv2.message_type, gtpv2.f_teid_interface_type, gtpv2.f_teid_ipv4, gtpv2.pdn_addr_and_prefix.ipv4, pfcp.msg_type, pfcp.node_id_fqdn, pfcp.ue_ip_addr_ipv4`. Constant `FTEID_TYPES: dict[int, tuple[str, str]]` (role, interface), per TS 29.274 Table 8.22-1: `0:(eNodeB,S1-U) 1:(SGW,S1-U) 4:(SGW,S5/S8-U) 5:(PGW,S5/S8-U) 6:(SGW,S5/S8-C) 7:(PGW,S5/S8-C) 10:(MME,S11) 11:(SGW,S11)`.

- [ ] **Step 1: Write failing tests**

| test | input | assert |
|---|---|---|
| `test_fteid_roles_from_csr` | protocols `…:udp:gtpv2`, msg type `32`, types `10\|7`, ipv4 `10.3.0.1\|10.5.0.1` | `10.3.0.1`: roles `{"MME"}`, interfaces `{"S11"}`; `10.5.0.1`: `{"PGW"}`, `{"S5/S8-C"}` (these IPs need not be the frame's src/dst) |
| `test_fteid_misaligned_skipped` | types `10\|7`, ipv4 `10.3.0.1` | neither IP gets a role; `warnings` has 1 entry mentioning `F-TEID` |
| `test_saegw_dual_role` | types `1\|5`, same IP twice | roles `{"SGW","PGW"}` |
| `test_paa_marks_ue` | msg `33`, `gtpv2.pdn_addr_and_prefix.ipv4=100.64.0.5` | `100.64.0.5` roles `{"UE"}` |
| `test_pfcp_cp_up` | `pfcp.msg_type=50`, src `10.8.0.1`, dst `10.9.0.1`, fqdn `smf01.5gc.mnc001.mcc470.3gppnetwork.org` | src `{"SMF/PGW-C"}` with that hostname, dst `{"UPF"}` |
| `test_pfcp_ue_ip` | `pfcp.ue_ip_addr_ipv4=100.65.0.9` | UE |
| `test_gtpu_inner_ue_inference` | 3 GTP-U rows on the outer pair A↔B, inner `U→S1`, `S2→U`, `U→S1` | `U` is UE; `S1`, `S2` are Server; A and B get no role from this rule |
| `test_gtpu_tie_unresolved` | 2 rows, inner `X→Y`, `Y→X` | no UE, no Server; warning `"UE address ambiguous"` |
| `test_known_ue_overrides_inference` | PAA row for `Y`, then the tie rows | `Y` UE, `X` Server |
| `test_plain_ip_peer_of_ue_is_server` | PAA `100.64.0.5`, then a non-tunnelled row `100.64.0.5→8.8.8.8` | `8.8.8.8` Server |

- [ ] **Step 2:** Run `uv run pytest tests/test_roles_gtp.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - F-TEID: if `len(types) != len(ipv4s)`, skip the frame and bump one counter that becomes the warning `"N GTPv2 frames with IPv6-only/misaligned F-TEIDs skipped"` (`# shortcut: field lists only; parse per-IE via -T json if this warning shows up on real traces`). Otherwise map through `FTEID_TYPES`, ignoring unknown types.
  - PFCP: request types `50, 52, 54` mean src=SMF/PGW-C and dst=UPF. `node_id_fqdn` → hostname of src.
  - GTP-U is a frame whose protocols contain `:gtp:` and that has an inner IP. Per unordered outer pair, count frames and a `Counter` of inner IPs. In `nodes()`, UEs = PAA/PFCP UEs. If there are none for a tunnel, the UE is the single inner IP whose count == the tunnel's frame count; with more than one such IP, the tunnel is ambiguous and gets the warning. Servers = inner IPs that are not UEs, plus outer peers of known UEs in frames with no inner IP. UE/Server counts come from inner appearances. Outer node counts stay as in Task 3.
- [ ] **Step 4:** Run the tests. Expected: pass.
- [ ] **Step 5:** Commit: `git commit -am "feat: GTPv2/PFCP/GTP-U role rules"`.

---

### Task 5: Diameter (HSS/PCRF/OCS/…, DRA/DEA) and M3UA STP

**Files:**
- Modify: `src/unipcap/roles.py`
- Test: `tests/test_roles_diameter_ss7.py`

**Interfaces:**
- Produces: `FIELDS += diameter.cmd.code, diameter.flags.request, diameter.applicationId, diameter.Session-Id, diameter.Origin-Host, diameter.Origin-Realm, diameter.Destination-Realm, m3ua.protocol_data_opc, m3ua.protocol_data_dpc`. `DIAMETER_APPS: dict[int, tuple[str|None, str]]` (client role, server role): `16777251:(MME,HSS) 16777238:(PGW,PCRF) 4:(None,OCS) 16777236:(P-CSCF,PCRF) 16777252:(MME,EIR) 16777272:(PGW,AAA) 16777216:(None,HSS)`.

- [ ] **Step 1: Write failing tests**

| test | input | assert |
|---|---|---|
| `test_diameter_s6a_direct` | ULR: cmd `316`, request `1`, app `16777251`, sid `s1`, A→B | A MME, B HSS |
| `test_diameter_via_dra` | same sid/cmd: A→X, then X→B | X `{"DRA"}`, A MME, B HSS; X does **not** get HSS/MME |
| `test_diameter_dea_by_realm` | A→X with Origin-Realm `epc.mnc001.mcc470.3gppnetwork.org`, Destination-Realm `epc.mnc003.mcc404.3gppnetwork.org`, then X→B | X `{"DEA"}` |
| `test_diameter_cer_binds_hostname` | cmd `257`, request `1`, Origin-Host `dra1.epc.mnc001.mcc470.3gppnetwork.org`, src X | X hostnames contain it. A relayed ULR's Origin-Host (`mme1…`) is **not** bound to X |
| `test_diameter_answers_ignored_for_roles` | ULA (request `0`) B→A only | no roles |
| `test_diameter_bundled_mismatch_skipped` | cmd `257\|316`, request `1\|1`, sid `s1` (1 value) | no roles; warning mentions `Diameter` |
| `test_gx_pgw_pcrf` | app `16777238` CCR, cmd `272` | PGW / PCRF |
| `test_m3ua_stp_relay` | DATA A→X with OPC `100`, then X→B with OPC `100` | X `{"STP"}`, A and B no STP role |
| `test_m3ua_multi_opc_sender_is_stp` | X sends OPC `100` and OPC `200` | X STP |

- [ ] **Step 2:** Run `uv run pytest tests/test_roles_diameter_ss7.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Per Diameter frame, all of `cmd.code`, `flags.request` and `applicationId` must have the same length. Session-Id must have that length too, or be empty when every message is 257/280. Otherwise skip the frame and count it (Review Focus 5). Accept `"1"` or `"True"` as true.
  - CER/CEA/DWR/DWA (257, 280): bind Origin-Host → src IP. These are hop-by-hop, so it is safe.
  - Other requests: record the edge `(src, dst)` under the key `(Session-Id, cmd.code)` together with the app and realms. In `nodes()`, for each key, an IP that is both a dst and a src is an agent. It is a DEA if its hostname contains `dea` or any forwarded request's Origin-Realm ≠ Destination-Realm; otherwise a DRA. A src that is never a dst gets the client role and a dst that is never a src gets the server role, both from `DIAMETER_APPS`. A `None` client means no role.
  - M3UA DATA: track `opc → [(src, dst)]`. X is an STP if X is a src for OPC p and also a dst of OPC p from a different IP, or if X sends ≥2 distinct OPCs.
- [ ] **Step 4:** Run the tests. Expected: pass.
- [ ] **Step 5:** Commit: `git commit -am "feat: Diameter agent and M3UA STP role rules"`.

---

### Task 6: `capture.analyze` + headless CLI + real-tshark checks

**Files:**
- Create: `src/unipcap/capture.py`, `tests/fixtures/gtpv2_csr.pcap`
- Modify: `tests/pcapgen.py`
- Test: `tests/test_capture.py`, `tests/test_samples.py`

**Interfaces:**
- Consumes: `iter_fields`, `vals`, `roles.FIELDS`, `RoleInference`.
- Produces:
  - `@dataclass Summary: path: str; frames: int; first_epoch: float|None; last_epoch: float|None; protocols: Counter[str]; nodes: list[Node]; warnings: list[str]`
  - `analyze(pcap: Path) -> Summary`: one `iter_fields` pass with `["frame.time_epoch", "sctp.data_payload_proto_id", *roles.FIELDS]`. `protocols` counts `_ws.col.protocol`. `first_epoch`/`last_epoch` are the **min/max** timestamps (timestamps can be out of order). Warnings = tshark's plus the inference's, plus one for undecoded SCTP: frames with a PPID value whose last `frame.protocols` token is `sctp` or `data` give `"N SCTP DATA frames not decoded (ports a, b, c; PPID x)"`, listing the top 5 lower ports.
  - `to_dict(s: Summary) -> dict`: `{"file": {"path","name","frames","start","end","duration_s"}, "warnings": [...], "protocols": [[name, n], …] sorted by count desc, "nodes": [{"ip","roles","interfaces","hostnames","evidence","protocols":[[name,n]…],"frames"}]}`. Sets are sorted lists; start/end are ISO-8601 UTC strings.
  - `pcapgen.write` gains `times: list[float] | None = None` (per-frame epoch offsets). `pcapgen.sctp_data(src, dst, sport, dport, ppid, payload) -> bytes` builds an SCTP common header (checksum 0; tshark doesn't verify it by default) plus one DATA chunk.
  - `pcapgen.gtpv2_csr(src, dst, fteids: list[tuple[int, str]]) -> bytes`: a UDP/2123 frame carrying a GTPv2 Create Session Request (header `0x48`, type 32, TEID 0, seq 1) with one F-TEID IE (type 87, the V4 flag `0x80 | iface`, TEID, IPv4) per tuple. Instance = index.

- [ ] **Step 1: Write failing tests**

```python
def test_fields_exist_in_bundled_tshark():
    out = subprocess.run([find_tshark(), "-G", "fields"], capture_output=True, text=True, encoding="utf-8").stdout
    known = {l.split("\t")[2] for l in out.splitlines() if l.startswith("F\t")}
    missing = [f for f in ["frame.time_epoch", *roles.FIELDS] if not f.startswith("_ws.col.") and f not in known]
    assert missing == []

def test_gtpv2_csr_end_to_end():
    s = analyze(Path("tests/fixtures/gtpv2_csr.pcap"))   # fteids [(10,"10.3.0.1"), (7,"10.5.0.1")], frame 10.3.0.1->10.4.0.1
    nodes = {n.ip: n for n in s.nodes}
    assert nodes["10.3.0.1"].roles == {"MME"} and nodes["10.5.0.1"].roles == {"PGW"}
    assert s.protocols["GTPv2"] == 1

def test_to_dict_is_json_serialisable(): ...   # json.dumps(to_dict(analyze(fixture))) works; file.frames == 1

def test_empty_capture(tmp_path):                # header-only file, as in samples/6443948e-….pcap
    s = analyze(pcapgen.write(tmp_path / "e.pcap", []))
    assert s.frames == 0 and s.nodes == [] and s.first_epoch is None

def test_out_of_order_timestamps_span(tmp_path): # pcapgen.write(..., times=[10, 5, 7]) -> first 5, last 10
    ...

def test_undecoded_sctp_warning(tmp_path):       # pcapgen.sctp_data("10.0.0.1","10.0.0.2",2641,2641,ppid=0,payload=b"x"*20)
    s = analyze(...)
    assert any("SCTP DATA frames not decoded" in w and "2641" in w for w in s.warnings)

def test_analyze_memory_bounded(tmp_path):
    p = pcapgen.write(tmp_path / "big.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x" * 64)] * 200_000)
    tracemalloc.start(); analyze(p); peak = tracemalloc.get_traced_memory()[1]; tracemalloc.stop()
    assert peak < 30_000_000
```

`tests/test_samples.py`: parametrise over `samples/*.expected.json` (skip when none). For each role → IPs in the JSON, assert `set(ips) <= {n.ip for n in nodes if role in n.roles}`.

- [ ] **Step 2:** Generate the fixture with a `if __name__ == "__main__"` block in `pcapgen.py` (`uv run python tests/pcapgen.py`). Run `uv run pytest tests/test_capture.py -v`. Expected: FAIL (no `capture` module). If `test_fields_exist_in_bundled_tshark` lists missing names, fix them in `roles.py` using `tshark -G fields | findstr <proto>` before going on.
- [ ] **Step 3:** Implement `analyze` and `to_dict`.
- [ ] **Step 4:** Run `uv run pytest -v`. Expected: all pass. `test_samples` is skipped until the user adds samples.
- [ ] **Step 5:** Commit: `git add -A && git commit -m "feat: one-pass capture analysis summary"`.

---

### Task 7: Desktop window + dashboard UI

**Files:**
- Create: `src/unipcap/app.py`, `src/unipcap/__main__.py`, `src/unipcap/web/index.html`, `web/app.js`, `web/style.css`
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `analyze`, `to_dict`, `TsharkError`, `TsharkNotFound`.
- Produces:
  - `class Api` (pywebview `js_api`): `analyze(path: str) -> dict` returns `{"ok": True, "summary": to_dict(...)}` or `{"ok": False, "error": str}`. It never raises. `pick_and_analyze() -> dict | None` opens `create_file_dialog(OPEN_DIALOG, file_types=("Captures (*.pcap;*.pcapng;*.cap;*.gz)", "All files (*.*)"))` and returns `None` on cancel.
  - `main(argv: list[str] | None = None) -> int`: `--analyze PCAP --out JSON` writes `to_dict` JSON and exits 0, or 1 with the error written to the out file as `{"error": …}`. The windowed exe has no stdout. With no args it opens `webview.create_window("UniPCAP", str(web/index.html), js_api=Api(), width=1400, height=900)`.

- [ ] **Step 1: Write failing tests**

```python
def test_api_analyze_ok():
    r = Api().analyze("tests/fixtures/gtpv2_csr.pcap")
    assert r["ok"] and r["summary"]["file"]["frames"] == 1

def test_api_analyze_reports_error(tmp_path):
    p = tmp_path / "x.txt"; p.write_text("nope")
    r = Api().analyze(str(p))
    assert r == {"ok": False, "error": ANY} and r["error"]

def test_cli_analyze_writes_json(tmp_path):
    out = tmp_path / "s.json"
    assert main(["--analyze", "tests/fixtures/gtpv2_csr.pcap", "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["file"]["frames"] == 1
```

- [ ] **Step 2:** Run `uv run pytest tests/test_app.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement `app.py`.** Then the UI, in vanilla JS with no build step:
  - Toolbar with an **Open capture** button that calls `pywebview.api.pick_and_analyze()`. While it waits, show "Analyzing… large captures can take minutes".
  - File strip: name, frames, start, end, duration. Warnings shown in an amber banner. Errors shown in a red banner.
  - Protocol chips: top 15 by count.
  - Sections, in this order: Radio (eNodeB, gNB), Packet core (MME, AMF, SGW, PGW, SMF/PGW-C, UPF), Diameter (HSS, PCRF, OCS, EIR, AAA, DRA, DEA), SS7 (STP), IMS (P-CSCF), Subscribers (UE), Internet (Server, top 20 by frames then "+N more"), Unclassified (no role, collapsed, top 50). A node with two roles appears under both.
  - Each node row shows the IP (monospace), hostname, interfaces as tags, and frames. Clicking it expands the evidence lines and the protocol breakdown.
  - Colours are tokens on `:root` with a `prefers-color-scheme: dark` variant.
- [ ] **Step 4:** Run `uv run pytest -v`. Expected: all pass. Then a manual check: `uv run python -m unipcap`, open `tests/fixtures/gtpv2_csr.pcap`, and confirm MME `10.3.0.1 (S11)` and PGW `10.5.0.1 (S5/S8-C)` are shown. Open a `.txt` file and confirm the red banner.
- [ ] **Step 5:** Commit: `git add -A && git commit -m "feat: desktop window with node dashboard"`.

---

### Task 8: Portable build + smoke test

**Files:**
- Create: `scripts/build.ps1`, `scripts/smoke.ps1`

**Interfaces:**
- Consumes: `main()`, `find_tshark()` (bundled path `_MEIPASS/vendor/wireshark/tshark.exe`).
- Produces: `dist/unipcap/unipcap.exe`, a self-contained folder.

- [ ] **Step 1:** `build.ps1`: `uv run pyinstaller --noconfirm --windowed --name unipcap --add-data "src/unipcap/web;unipcap/web" --add-data "vendor/wireshark;vendor/wireshark" src/unipcap/__main__.py`. Before running, it fails if `vendor/wireshark/tshark.exe` is missing.
- [ ] **Step 2:** `smoke.ps1`: copy `dist/unipcap` to `$env:TEMP\unipcap smoke রহিম\`. Set `PATH` to `C:\Windows\System32` only and clear `UNIPCAP_TSHARK`. Run `unipcap.exe --analyze tests\fixtures\gtpv2_csr.pcap --out $env:TEMP\smoke.json` with `Start-Process -Wait -PassThru`. Exit code 0 and `nodes` containing `10.5.0.1` with role `PGW` mean PASS; print `SMOKE PASS` / `SMOKE FAIL: <reason>`.
- [ ] **Step 3:** Run `scripts/build.ps1; scripts/smoke.ps1`. Expected: `SMOKE PASS`.
- [ ] **Step 4:** Manual check (for the user): copy `dist/unipcap` to a machine or Windows Sandbox without Wireshark, run `unipcap.exe`, and open a sample. This confirms WebView2 and the VC++ DLLs are found.
- [ ] **Step 5:** Commit: `git add scripts && git commit -m "build: portable one-folder bundle with smoke test"`.
