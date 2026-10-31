# Ladder Diagram (Signaling Flow) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show a capture's signaling flow as a ladder diagram — one row per signaling message between auto-labelled nodes, user-plane burst arrows, click-through to the full per-message decode, and automatic request→response pairing.

**Architecture:** The existing single `analyze()` pass collects messages and aggregates data bursts (bounded by caps); a second `tshark -V` invocation filtered to signaling frames attaches decode text; pairing runs as a pure post-pass. The UI renders reference-faithful fixed-height rows with absolutely-positioned divs (no SVG, no JS deps).

**Tech Stack:** Python 3 (stdlib only, existing), tshark 4.6.9 bundled fields, vanilla HTML/CSS/JS.

**Spec:** `docs/superpowers/specs/2026-10-31-ladder-design.md` — the plan argues from the spec; executors read both.

## Global Constraints

- No new dependencies (Python or JS); no JS build step; DOM built with `textContent` only (capture data is untrusted).
- tshark field names verified for 4.6.9: `diameter.hopbyhopid`, `diameter.endtoendid`, `pfcp.seqno`, `gtpv2.seq`, `s1ap.procedureCode`, `ngap.procedureCode`, `frame.len` (never `pfcp.sequence_number`/`gtpv2.sequence_number` — always empty).
- Signaling display filter: `s1ap or ngap or gtpv2 or pfcp or diameter or sip or camel` (token is `camel`, not `cap`).
- `sctp.retransmission` is presence-checked only (`==1` matches nothing).
- `tests/test_capture.py::test_analyze_memory_bounded` must keep passing (200k frames, tracemalloc peak < 30 MB) with ladder collection active.
- `filterwarnings = ["error::ResourceWarning"]` — every Popen pipe closed explicitly; stderr never PIPE.
- Samples live in git-ignored `samples/`; sample-dependent tests use the `skipif` pattern of `tests/test_samples.py`.
- Run tests with `uv run pytest`. Every commit message ends with:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`

## Review Focus

1. **Variant protocol columns** — signaling appears as `S1AP/NAS-EPS`, `Camel-v2`, etc.; classification must use `frame.protocols` tokens, never `_ws.col.protocol`. → Task 2 `test_signaling_proto_variants`.
2. **Undissected SCTP retransmissions** — no protocol dissection, no decode in `-V`; must classify via the learned map and render without a decode, with the UI fallback note. → Task 2 `test_add_row_retransmission_learned`, Task 6 fallback branch.
3. **200 k-frame capture** — a naive per-frame list breaks the memory bound; bursts must aggregate on the fly and messages must cap. → Task 4 reruns `test_analyze_memory_bounded`.
4. **Signaling-heavy capture** (merged.pcap is 44.7% signaling) — decode budget exhausts; must truncate per message, warn with counts, and never fail the analysis. → Task 2 `test_attach_decode_budget`, Task 5 `test_merged_ladder`.
5. **UNSPECIFIED / self messages** — `0.0.0.0`/`::` endpoints and `src == dst` must not produce bad lifeline indexes or arrows; skip or stub. → Task 2 `test_add_row_skips_unspecified`.

---

### Task 1: `iter_verbose` — streaming `-V` block generator

**Files:**
- Modify: `src/unipcap/tshark.py` (add after `iter_fields`, ~line 70)
- Test: `tests/test_ladder.py` (created here)

**Interfaces:**
- Consumes: `find_tshark()` (tshark.py:23), the `iter_fields` Popen pattern (tshark.py:48-63).
- Produces: `iter_verbose(pcap: Path, display_filter: str, warnings: list[str] | None = None) -> Iterator[tuple[int, str]]` — yields `(frame_number, block_text)` per `-V` frame block.

- [ ] **Step 1: Write the failing test**

In `tests/test_ladder.py`:

```python
def test_iter_verbose_yields_one_block_per_frame(tmp_path):
    p = pcapgen.write(tmp_path / "v.pcap", [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x")] * 2)
    blocks = list(iter_verbose(p, "udp"))
    assert [(n, "User Datagram Protocol" in text, text.startswith("Frame ")) for n, text in blocks] \
        == [(1, True, True), (2, True, True)]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_ladder.py -v`
Expected: FAIL with ImportError (no `iter_verbose`).

- [ ] **Step 3: Implement `iter_verbose` in `src/unipcap/tshark.py`**

Clone the `iter_fields` Popen pattern exactly (stderr `TemporaryFile`, `CREATE_NO_WINDOW` on win32,
empty `WIRESHARK_CONFIG_DIR` profile, `encoding="utf-8"`, `errors="replace"`, explicit pipe close,
`terminate()` on early close, same returncode policy — nonzero with zero rows raises `TsharkError`,
nonzero after rows appends stderr to `warnings`). Command: `tshark -n -r <pcap> -Y <filter> -V`.
Stream stdout line by line; start a block at a line matching `^Frame (\d+): ` and yield the
accumulated block (joined lines, trailing blank line stripped) at the next header or EOF.
Never buffer the whole output.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_ladder.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/unipcap/tshark.py tests/test_ladder.py
git commit -m "feat: add iter_verbose streaming -V tshark reader"
```

### Task 2: `ladder.py` core — classification, messages, bursts, decode attach

**Files:**
- Create: `src/unipcap/ladder.py`
- Test: `tests/test_ladder.py` (extend)

**Interfaces:**
- Consumes: `roles.outer_inner`, `roles.UNSPECIFIED`, `tshark.vals`, `capture.SCTP_PPID_PROTO`.
- Produces:
  - Constants: `SIGNALING_TOKENS = {"s1ap","ngap","gtpv2","pfcp","diameter","sip","camel"}`,
    `PROTO_NAMES = {"s1ap":"S1AP","ngap":"NGAP","gtpv2":"GTPv2","pfcp":"PFCP","diameter":"DIAMETER","sip":"SIP","camel":"CAMEL"}`,
    `SIGNALING_FILTER = "s1ap or ngap or gtpv2 or pfcp or diameter or sip or camel"`,
    `MESSAGE_CAP = 5000`, `DECODE_LIMIT = 12_000`, `DECODE_BUDGET = 4_000_000`, `BURST_GAP = 1.0`.
  - `@dataclass Message: t: float; frame: int; src: str; dst: str; name: str; proto: str; keys: dict; decode: str | None = None`
  - `@dataclass Burst: t0: float; t1: float; src: str; dst: str; proto: str; n: int; bytes: int`
  - `@dataclass Ladder: messages: list; bursts: list; pairs: list; by_frame: dict; omitted_messages: int = 0; decode_omitted: int = 0`
  - `signaling_proto(row: dict[str, str]) -> str | None` — token ∩ `SIGNALING_TOKENS` → `PROTO_NAMES` name (first token by `frame.protocols` order), else None.
  - `clean_info(info: str) -> str` — strip trailing `" |"` and whitespace.
  - `message_keys(row: dict[str, str]) -> dict` — `{"hbhid","code","req"}` from `diameter.hopbyhopid` / `diameter.cmd.code` / `diameter.flags.request`; `{"seqno","msg"}` from `pfcp.seqno` / `pfcp.msg_type`; `{"seq","msg"}` from `gtpv2.seq` / `gtpv2.message_type`; `{"proc"}` from `s1ap.procedureCode` / `ngap.procedureCode`; empty dict otherwise (raw string values via `vals()`).
  - `add_row(l: Ladder, row: dict[str, str], learned: dict) -> bool` — True if a message was added (retransmission rows return False — caller feeds them after the learned map is complete; see Task 4).
  - `attach_decode(l: Ladder, blocks: Iterator[tuple[int, str]]) -> None` — per message: if the truncated text would exceed the remaining budget, skip (no decode, count `decode_omitted`); else truncate to `DECODE_LIMIT` with a `… (decode truncated)` footer and attach.
  - `ladder_dict(l: Ladder, nodes_by_ip: dict[str, roles.Node]) -> dict` — the spec's JSON shape. Builds the participant node list itself from messages+bursts in first-appearance order (messages sorted by `t`, then bursts); each node's `name` = first hostname else the ip, `type` = first sorted role else `""`, looked up from `nodes_by_ip` (unknown IPs become ip-only placeholder nodes); `src`/`dst` become indexes into that list; `decode` present only when attached; pairs serialized as-is.

- [ ] **Step 1: Write the failing tests**

```python
def test_signaling_proto_variants():
    assert signaling_proto({"frame.protocols": "eth:ethertype:ip:sctp:s1ap:nas-eps"}) == "S1AP"
    assert signaling_proto({"frame.protocols": "eth:ethertype:ip:tcp:diameter"}) == "DIAMETER"
    assert signaling_proto({"frame.protocols": "eth:ethertype:ip:sctp:m3ua:sccp:camel"}) == "CAMEL"
    assert signaling_proto({"frame.protocols": "eth:ethertype:ip:udp:gtp:ip:tcp"}) is None

def test_clean_info_strips_trailing_pipe():
    assert clean_info("Credit-Control Request | ") == "Credit-Control Request"
    assert clean_info("UplinkNASTransport, PDN disconnect request") == "UplinkNASTransport, PDN disconnect request"

def test_message_keys_field_names():
    assert message_keys({"diameter.hopbyhopid": "0x1", "diameter.cmd.code": "272",
                         "diameter.flags.request": "1"}) == {"hbhid": "0x1", "code": "272", "req": "1"}
    assert message_keys({"pfcp.seqno": "5", "pfcp.msg_type": "50"}) == {"seqno": "5", "msg": "50"}
    assert message_keys({"gtpv2.seq": "0x1", "gtpv2.message_type": "32"}) == {"seq": "0x1", "msg": "32"}
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
    assert add_row(l, row, {}) is False                      # deferred, not a burst
    assert add_row(l, row, {("18", frozenset(("36412", "36412"))): "S1AP"}) is True
    assert l.messages[0].proto == "S1AP"

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_ladder.py -v`
Expected: FAIL (no `unipcap.ladder` module).

- [ ] **Step 3: Implement `src/unipcap/ladder.py`**

One module, pure functions + dataclasses above (imports: `unipcap.roles`, `unipcap.tshark.vals`
only — no cycle with `capture.py`). The constants live here, not in `capture.py` as the spec's
section title suggests: `tests/test_ladder.py` imports them without pulling in the analysis pass.
`add_row`: classify via `signaling_proto`; if a message, append up to `MESSAGE_CAP` (count
`omitted_messages`, record `by_frame[frame] = index`, fill `keys` via `message_keys`); if a
retransmission (`sctp.retransmission` present) return False without touching bursts; else
accumulate the open burst for `(src, dst, _ws.col.protocol)` — close when `t - t1 > BURST_GAP`
(and set `t1 = max(t1, t)`); skip rows whose src or dst is in `UNSPECIFIED` for messages and
bursts alike. `src`/`dst` for signaling use the outer addresses via `roles.outer_inner` (skip
`UNSPECIFIED`; if both usable pairs differ, use outer). `ladder_dict`: node order = first
appearance across sorted messages then bursts; `name`/`type` looked up in `nodes_by_ip`;
unknown IPs get a placeholder node (ip-only, no type).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_ladder.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/unipcap/ladder.py tests/test_ladder.py
git commit -m "feat: add ladder collection, burst aggregation, and decode attach"
```

### Task 3: Pairing

**Files:**
- Modify: `src/unipcap/ladder.py` (add `pair` to the module)
- Test: `tests/test_ladder.py` (extend)

**Interfaces:**
- Consumes: `Message.keys` from Task 2.
- Produces: `pair(l: Ladder) -> None` — fills `l.pairs` with `(i, j)` message indexes; each message pairs at most once.

- [ ] **Step 1: Write the failing tests**

```python
def _msg(i, t, src, dst, proto, keys):
    return Message(t, i, src, dst, f"m{i}", proto, keys)

def test_pair_diameter_hbhid():
    l = Ladder([], [], [], {})
    l.messages = [_msg(1, 0.0, "a", "b", "DIAMETER", {"hbhid": "0x1", "code": "272", "req": "1"}),
                  _msg(2, 0.1, "b", "a", "DIAMETER", {"hbhid": "0x1", "code": "272", "req": "0"})]
    pair(l)
    assert l.pairs == [(0, 1)]

def test_pair_pfcp_seqno_parity():
    l = Ladder([], [], [], {})
    l.messages = [_msg(1, 0.0, "a", "b", "PFCP", {"seqno": "100", "msg": "50"}),
                  _msg(2, 0.1, "b", "a", "PFCP", {"seqno": "100", "msg": "51"}),
                  _msg(3, 0.2, "a", "b", "PFCP", {"seqno": "100", "msg": "50"})]  # retrans req
    pair(l)
    assert l.pairs == [(0, 1)] and 3 not in {j for _, j in l.pairs}

def test_pair_gtpv2_seq_dedupe():
    l = Ladder([], [], [], {})
    l.messages = [_msg(1, 0.0, "a", "b", "GTPv2", {"seq": "0x19e4c3", "msg": "32"}),
                  _msg(2, 0.1, "a", "b", "GTPv2", {"seq": "0x19e4c3", "msg": "32"}),  # retrans req
                  _msg(3, 0.2, "b", "a", "GTPv2", {"seq": "0x19e4c3", "msg": "33"})]
    pair(l)
    assert l.pairs == [(0, 2)] and 1 not in {i for i, _ in l.pairs}

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_ladder.py::test_pair_diameter_hbhid -v`
Expected: FAIL (no `pair`).

- [ ] **Step 3: Implement `pair(l)` in `src/unipcap/ladder.py`**

Group messages by protocol and key: Diameter by `(hbhid, code)` — requests (`req == "1"`) pair
with the nearest-in-time answer; PFCP by `seqno` — pair type N with N+1 (the request/response
type pair, e.g. 3→4, 50→51) on the reversed IP pair; GTPv2 by `seq` as a hint — dedupe identical
`(seq, msg, src, dst)` taking the first, pair type N with N+1 on the reversed pair within 30 s;
S1AP/NGAP — odd `proc` pairs with even `proc+1` on the reversed pair, nearest within 30 s. Track
used indexes in one `used` set so each message pairs at most once.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_ladder.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/unipcap/ladder.py tests/test_ladder.py
git commit -m "feat: add signaling request-response pairing"
```

### Task 4: `capture.py` integration

**Files:**
- Modify: `src/unipcap/capture.py` — `FIELDS` (:21), `analyze()` (:42-83), `to_dict()` (:90-101)
- Test: `tests/test_capture.py` (extend)

**Interfaces:**
- Consumes: Task 1 `iter_verbose`, Task 2 `ladder.*`, Task 3 `pair`.
- Produces: `Summary.ladder: ladder.Ladder | None = None` (analyze always assigns one, even for zero frames); `to_dict()` key `"ladder"` = `ladder_dict(s.ladder, {n.ip: n for n in s.nodes})`.

- [ ] **Step 1: Write the failing tests**

```python
def test_analyze_collects_ladder_messages_and_bursts(tmp_path):
    s = analyze(pcapgen.write(tmp_path / "l.pcap",
        [pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"x"),
         pcapgen.udp("10.0.0.1", "10.0.0.2", 1, 2, b"y")]))
    assert len(s.ladder.bursts) == 1 and s.ladder.bursts[0].n == 2
    assert s.ladder.messages == []

def test_analyze_gtpv2_fixture_ladder_has_message_and_decode():
    s = analyze(FIXTURE)
    assert [m.proto for m in s.ladder.messages] == ["GTPv2"]
    assert "Create Session Request" in s.ladder.messages[0].name
    assert s.ladder.messages[0].decode is not None

def test_to_dict_includes_ladder():
    d = json.loads(json.dumps(to_dict(analyze(FIXTURE))))
    assert d["ladder"]["messages"][0]["proto"] == "GTPv2"
    assert "decode" in d["ladder"]["messages"][0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_capture.py::test_analyze_collects_ladder_messages_and_bursts -v`
Expected: FAIL (no `s.ladder`).

- [ ] **Step 3: Implement integration in `src/unipcap/capture.py`**

- `FIELDS` gains: `"frame.len", "diameter.hopbyhopid", "diameter.endtoendid", "pfcp.seqno",
  "gtpv2.seq", "s1ap.procedureCode", "ngap.procedureCode"` (note `diameter.flags.request`,
  `diameter.cmd.code`, `pfcp.msg_type`, `gtpv2.message_type` are already in `roles.FIELDS`).
- `Summary` gains `ladder: ladder.Ladder | None = None`.
- In `analyze()`: build `l = ladder.Ladder([], [], [], {})`; inside the loop's non-retransmission
  branch call `ladder.add_row(l, row, {})` (before `ri.add(row)`); after the existing
  retransmission post-pass, feed the existing `retrans` list to `add_row` with the completed
  `learned` map — retransmission rows are signaling, never bursts. Retrans messages append out
  of timestamp order, so then: `l.messages.sort(key=lambda m: m.t)`,
  `l.by_frame = {m.frame: i for i, m in enumerate(l.messages)}`, then
  `ladder.attach_decode(l, iter_verbose(pcap, SIGNALING_FILTER, warnings=s.warnings))` wrapped in
  `try/except Exception` (on failure append `"ladder decode pass failed: …"` to `s.warnings`),
  then `ladder.pair(l)`; append cap/budget warnings (`"N signaling messages omitted from
  ladder"`, `"M message decodes omitted (size budget)"`) when the counters are nonzero;
  `s.ladder = l` unconditionally (zero frames → empty ladder).
- `to_dict()`: `"ladder": ladder_dict(s.ladder, {n.ip: n for n in s.nodes})` (no None branch —
  `analyze` always assigns; an empty ladder serializes to the empty shape).
- Re-run `test_analyze_memory_bounded` unchanged — it must still pass.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_capture.py tests/test_ladder.py -v`
Expected: PASS (including `test_analyze_memory_bounded`).

- [ ] **Step 5: Commit**

```bash
git add src/unipcap/capture.py tests/test_capture.py
git commit -m "feat: wire ladder collection, decode pass, and pairing into analyze"
```

### Task 5: Sample-based integration tests

**Files:**
- Create: `tests/test_ladder_samples.py`

**Interfaces:**
- Consumes: Task 4's `analyze()`.

- [ ] **Step 1: Write the failing tests**

```python
SAMPLES = Path(__file__).parents[1] / "samples"

@pytest.mark.skipif(not (SAMPLES / "merged.pcap").exists(), reason="capture not in checkout")
def test_merged_ladder():
    s = analyze(SAMPLES / "merged.pcap")
    msgs = s.ladder.messages
    assert msgs and any(m.decode for m in msgs)
    assert any(p in {m.proto for m in msgs} for p in ("DIAMETER", "GTPv2", "S1AP"))
    assert s.ladder.pairs and s.ladder.bursts

@pytest.mark.skipif(not SAMPLES.exists(), reason="samples not in checkout")
def test_sample_sm_ladder_sip_camel():
    for p in SAMPLES.glob("Sample_SM/RecordQueryFlowChart_*/pcap/export_*.pcap"):
        protos = {m.proto for m in analyze(p).ladder.messages}
        if protos & {"SIP", "CAMEL"}:
            return  # one hit is enough; don't analyze all 16 reference exports
    pytest.fail("no SIP/CAMEL messages in any Sample_SM capture")
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `uv run pytest tests/test_ladder_samples.py -v`
Expected: PASS locally (samples present); skips in CI.

- [ ] **Step 3: Commit**

```bash
git add tests/test_ladder_samples.py
git commit -m "test: add sample-based ladder integration tests"
```

### Task 6: UI — ladder rendering, detail pane, node focus

**Files:**
- Modify: `src/unipcap/web/index.html` (insert `<div id="ladder" class="ladder" hidden></div>` between `#chips` and `#sections`), `src/unipcap/web/app.js`, `src/unipcap/web/style.css`

**Interfaces:**
- Consumes: summary JSON `"ladder"` shape from Task 4.

- [ ] **Step 1: Implement `renderLadder(summary.ladder)` in `src/unipcap/web/app.js`**

Pure DOM building via the existing `h()` helper (textContent only — decode text is untrusted).
Layout per spec: sticky header of node boxes (name + type, `#369cda`, ellipsis, title tooltip)
with 3 px `#7b8dac` lifelines; scrollable body (max-height ~70 vh, `overflow: auto`), fixed 35 px
rows, column step 171 px; 210 px right-aligned time column (local `HH:MM:SS.mmm` + seconds-since-
first, computed from `t`); message rows = 3 px protocol-colored arrow line + CSS triangle
arrowhead at the destination + centered label (name, protocol color, `title` tooltip);
`src == dst` renders a short right-pointing stub on its own lifeline; burst rows = gray thin
arrow, italic `PROTO ×N · 1.2 MB` label (humanized bytes). Protocol colors: S1AP/NGAP `#1099A2`,
DIAMETER `#90CC19`, GTPv2 `#7C3AC1`, SIP `#F2A14E`, CAMEL `#00C90D`, PFCP `#369CD8`, bursts
`#909090`. Messages and bursts merge into one row list sorted by `t` (bursts by `t0`).

Interactions:
- Click a message row → highlight it and its paired counterpart (from `pairs`, scroll into
  view) with `#2A90FF` label background; show the detail pane below the ladder: table rows
  Message Name / Time Stamp / Link (`src → dst` node names) / IP SRC / IP DST + the decode in a
  monospace `<pre>` (escape nothing — `textContent`). No decode → fallback text
  `Retransmitted chunk — tshark does not dissect retransmissions` or
  `Decode omitted (size budget)`.
- Click a node header box → toggle focus: only rows touching that node render; click again to
  clear.

Call `renderLadder` from `render()` (hide the section when the ladder is empty/missing); clear
it in `showError()`.

- [ ] **Step 2: Add ladder styles to `src/unipcap/web/style.css`**

Use the existing light/dark token pattern; fixed row height 35 px, arrow geometry, time column,
detail pane, focus states. No external assets.

- [ ] **Step 3: Verify by running the app on real captures**

Start the server (existing run pattern: `Server(port=0)` + browser), POST `samples/merged.pcap`
and one `Sample_SM` pcap, and confirm in the browser: ladder section renders with lifelines,
colored arrows, correct labels; clicking an arrow shows the decode and highlights its pair;
clicking a node box filters rows; the dashboard sections still render. Check the response JSON
carries `ladder` with decodes and pairs.

- [ ] **Step 4: Commit**

```bash
git add src/unipcap/web/index.html src/unipcap/web/app.js src/unipcap/web/style.css
git commit -m "feat: render ladder diagram with decode detail and node focus"
```

### Task 7: Whole-feature verification

- [ ] **Step 1: Run the full suite**

Run: `uv run pytest`
Expected: all pass (sample tests skip in CI; pass locally).

- [ ] **Step 2: Lint/compile sanity**

Run: `uv run python -m compileall -q src tests`
Expected: no errors.

- [ ] **Step 3: Commit any stragglers and summarize**

Confirm `git status` clean; summarize what was built, what was skipped (per spec "Skipped"
section), and risks.
