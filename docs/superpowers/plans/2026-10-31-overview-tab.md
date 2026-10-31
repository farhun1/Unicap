# Overview Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an Overview tab to the ladder panel summarizing DNS success, GTP-U volume/quality, Gx/Gy quotas and rules, and negative signaling responses.

**Architecture:** One new module, `src/unipcap/overview.py`, exposes `FIELDS` and an `Overview` accumulator whose `add_row(row)` consumes the same streaming rows as `ladder.add_row`. `capture.py` appends `overview.FIELDS` to the shared field list, instantiates one `Overview` per analysis, and emits it under `to_dict()["overview"]`. `app.js` gains a third tab in the existing ladder tab bar rendering the summary with `textContent`-only DOM.

**Tech Stack:** Python 3 stdlib + tshark `-T fields` streaming (existing `iter_fields`), vanilla JS/CSS, pytest.

**Spec:** [docs/superpowers/specs/2026-10-31-overview-tab-design.md](../specs/2026-10-31-overview-tab-design.md)

## Global Constraints

- One tshark streaming pass: new fields are appended to the shared `FIELDS` list, never a second pass.
- FT_NONE fields render `"1"` when present, `""` when absent — presence is `row.get(field) == "1"`.
- Percentages rounded to 1 decimal; a zero denominator yields `null` (UI renders `—`).
- Vanilla JS, zero dependencies; DOM built with `textContent` only (capture data is untrusted).
- Copy is fixed: tab label `Overview`; missing metric renders `—`.
- `tests/test_samples.py` compares node roles only — the `to_dict` shape change must not require regenerating `*.expected.json`.
- Tests run with `uv run pytest`; never modify `.gitignore`.

## Review Focus

Input classes the spec implies but no task's tests would otherwise exercise:

1. **DNS-only capture (no ladder rows, no Diameter, no GTP-U)** — the ladder panel must not hide when the ladder is empty but an overview exists, and every metric renders without NaN. Test: Task 1 `test_dns_only_capture_rates_and_nulls` + Task 6 serve assertion `b"!ld && !ov"`.
2. **Parallel AVPs with mismatched lengths** (real merged.pcap has 10 RGs but 9 octets in one CCA) — tail contributes 0, no crash. Test: Task 2 `test_mismatched_parallel_lists_tail_is_zero`.
3. **SN wrap-around at 65535** — gap arithmetic is mod 65536, so 65535 → 1 is a gap of 1, not a huge one. Test: Task 4 `test_sn_wraparound_gap`.
4. **`gtpv2` must not count as inner TCP** — the protocol check matches whole segments of `frame.protocols`, so `gtpv2` never matches `gtp`. Test: Task 4 `test_gtpv2_is_not_inner_tcp`.
5. **Result-Code rows mixing success and failure instances** (`"2001,4010"` — 26 such messages in merged.pcap) — each instance ≥ 3000 counts; success instances do not. Test: Task 3 `test_result_code_mixed_instances`.

---

### Task 1: Overview module — DNS + GTP-U volume + capture wiring

**Files:**
- Create: `src/unipcap/overview.py`
- Modify: `src/unipcap/capture.py` (FIELDS ~line 24, `Summary` ~line 21, `analyze` loop ~line 67, `to_dict` ~line 110)
- Test: `tests/test_overview.py` (create), `tests/test_capture.py` (extend)

**Interfaces:**
- Produces:
  - `overview.FIELDS: list[str]` — starts as `["dns.id", "dns.flags.response", "dns.flags.rcode", "dns.count.answers", "gtp.message"]`; Tasks 2–4 append their fields to this constant.
  - `class Overview` with `add_row(self, row: dict[str, str]) -> None` and `to_dict(self) -> dict`.
  - `overview.to_dict(ov: Overview) -> dict` — module function used by `capture.to_dict`.
  - `capture.Summary.overview` — dataclass field, `field(default_factory=overview.Overview)`.
  - `capture.to_dict` gains `"overview": overview.to_dict(s.overview)`.
- Consumes: the shared streaming rows from `iter_fields` (every key may be `""`).

- [ ] **Step 1: Write the failing tests**

`tests/test_overview.py`:

```python
import pytest
from unipcap.overview import Overview, to_dict

def row(**kw):
    d = {"ip.src": "1.1.1.1", "ip.dst": "2.2.2.2", "ipv6.src": "", "ipv6.dst": "",
         "dns.id": "", "dns.flags.response": "", "dns.flags.rcode": "",
         "dns.count.answers": "", "gtp.message": "", "frame.len": "",
         "frame.protocols": ""}
    d.update(kw)
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
    assert d["dns"]["answer_rate_pct"] is None and d["dns"]["success_rate_pct"] is None
    assert d["gtpu"]["volume"] == {"frames": 0, "bytes": 0}

def test_gtpu_volume_sums_gpdu_frame_len():
    ov = Overview()
    ov.add_row(row(gtp_message="0xff", frame_len="100"))
    ov.add_row(row(gtp_message="0xff", frame_len="150"))
    ov.add_row(row(gtp_message="0x02", frame_len="60"))   # echo is not a G-PDU
    assert to_dict(ov)["gtpu"]["volume"] == {"frames": 2, "bytes": 250}
```

Note the `row` helper's parameter names differ from the dict keys (`dns_id` → `"dns.id"`); implement the helper with an explicit mapping. Helper code may grow in later tasks — extend, never rewrite.

`tests/test_capture.py` — add to the existing file:

```python
def test_to_dict_includes_overview():
    d = json.loads(json.dumps(to_dict(analyze(FIXTURE))))
    assert "dns" in d["overview"] and "gtpu" in d["overview"]
    assert d["overview"]["dns"]["answer_rate_pct"] is None  # FIXTURE has no DNS
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_overview.py tests/test_capture.py::test_to_dict_includes_overview -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'unipcap.overview'`

- [ ] **Step 3: Implement `src/unipcap/overview.py` and wire `capture.py`**

Signatures: `FIELDS: list[str]`, `class Overview` with `add_row(self, row: dict[str, str]) -> None`, module-level `to_dict(ov: Overview) -> dict`; `_endpoints(row) -> tuple[str, str]` helper returning `(row.get("ip.src") or row.get("ipv6.src"), row.get("ip.dst") or row.get("ipv6.dst"))` — Task 4 reuses it.

Semantics (from the spec):
- query: `dns.flags.response == "False"` and a `dns.id` — track `(src, dst, id)` in a pending set.
- response: `"True"` — if `dns.flags.rcode == "0"` count rcode0; if `(dst, src, id)` is pending, pop it and count answered.
- volume: `gtp.message == "0xff"` → frames += 1, bytes += `int(row["frame.len"] or 0)`.
- `to_dict` returns `{"dns": {...}, "gtpu": {"volume": {"frames": n, "bytes": n}}}` with rates `round(x, 1)` or `None` when the denominator is 0.

In `capture.py`: `from unipcap import ladder, overview, roles`; `FIELDS = [...] + overview.FIELDS`; `Summary.overview` field; in `analyze()` create `ov = overview.Overview()` before the loop and call `ov.add_row(row)` next to `ladder.add_row(l, row, {})` (main loop only, not the retrans loop); `to_dict` gains `"overview": overview.to_dict(s.overview)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_overview.py tests/test_capture.py -v`
Expected: PASS (all new tests + the existing capture tests)

- [ ] **Step 5: Run the full suite and commit**

Run: `uv run pytest` — Expected: all green (134 + new).
Commit:

```bash
git add src/unipcap/overview.py src/unipcap/capture.py tests/test_overview.py tests/test_capture.py
git commit -m "feat: add overview module with DNS and GTP-U volume metrics"
```

---

### Task 2: Gx / Gy reporting

**Files:**
- Modify: `src/unipcap/overview.py` (append to `FIELDS`; extend `add_row`, `to_dict`)
- Test: `tests/test_overview.py` (extend)

**Interfaces:**
- Produces: `to_dict(ov)` gains `"gx"` and `"gy"` keys (shapes per spec §14); `FIELDS` appends `diameter.flags.request`, `diameter.Auth-Application-Id`, `diameter.CC-Total-Octets`, `diameter.Rating-Group`, `diameter.Service-Identifier`, `diameter.Charging-Rule-Name`, `diameter.Charging-Rule-Base-Name`.
- Consumes: `unipcap.tshark.vals(row, field) -> list[str]` (splits `|`-aggregated occurrences, each element one comma-joined instance list); `Overview` from Task 1.

- [ ] **Step 1: Write the failing tests**

```python
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
```

Extend the `row` helper with `app_id` → `"diameter.Auth-Application-Id"`, `req` → `"diameter.flags.request"`, `rg` → `"diameter.Rating-Group"`, `sid` → `"diameter.Service-Identifier"`, `octets` → `"diameter.CC-Total-Octets"`, `rule_name` → `"diameter.Charging-Rule-Name"`, `rule_base` → `"diameter.Charging-Rule-Base-Name"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_overview.py -v`
Expected: FAIL — the four new tests (KeyError/assertion on the missing `gx`/`gy` keys)

- [ ] **Step 3: Implement in `overview.py`**

Add a private `_instances(row, field) -> list[str]` helper: for each element of `vals(row, field)`, split on `,` and flatten (one `|` occurrence is one comma-joined list).

Semantics:
- Interface: `aid = row.get("diameter.Auth-Application-Id")`; Gx when `"16777238"`, Gy when `"4"`, else return. Request when `row.get("diameter.flags.request") == "True"`.
- Octets: `sum(int(x) for x in _instances(row, "diameter.CC-Total-Octets") if x)` — added to given on answers, reported on requests.
- Parallel pairing for by_rg/by_sid: `rgs`, `sids`, `octs = [_instances(...) for the three fields]`; for each index `i` in `rgs`, add `octs[i]` (0 when `i >= len(octs)`) to `by_rg[rgs[i]]`; for each `i` in `sids`, same into `by_sid[sids[i]]`. Track given/reported per key.
- Rules (Gx answer rows only): count each `_instances` value of the two rule-name fields.
- `to_dict`: `gx = {"given_octets", "reported_octets", "rules": [[name, count]…], "rule_bases": …}`, pairs sorted by `(-count, name)`; `gy = {"given_octets", "reported_octets", "by_rg": [[key, {"given": g, "reported": r}]…], "by_sid": …}` sorted by `int(key)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_overview.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite and commit**

Run: `uv run pytest` — Expected: all green.
Commit:

```bash
git add src/unipcap/overview.py tests/test_overview.py
git commit -m "feat: add Gx/Gy quota and rule reporting to overview"
```

---

### Task 3: Negative signaling responses

**Files:**
- Modify: `src/unipcap/overview.py` (append to `FIELDS`; extend `add_row`, `to_dict`)
- Test: `tests/test_overview.py` (extend)

**Interfaces:**
- Produces: `to_dict(ov)` gains `"negative"` (`{"Diameter": [["4010", 26]], "GTPv2": [["73", 2]], "S1AP": [["9", 1]], "NGAP": []}`; protocols with no entries omitted). `FIELDS` appends `diameter.Result-Code`, `gtpv2.cause`, `s1ap.unsuccessfulOutcome_element`, `ngap.unsuccessfulOutcome_element`.
- Consumes: `row["s1ap.procedureCode"]` / `row["ngap.procedureCode"]` — already in `capture.FIELDS`.

- [ ] **Step 1: Write the failing tests**

```python
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

def test_s1ap_ngap_unsuccessful_outcome():
    ov = Overview()
    ov.add_row(row(s1ap_outcome="1", s1ap_proc="9"))
    ov.add_row(row(s1ap_outcome="", s1ap_proc="9"))     # successful: ignored
    ov.add_row(row(ngap_outcome="1", ngap_proc="0"))
    assert to_dict(ov)["negative"] == {"S1AP": [["9", 1]], "NGAP": [["0", 1]]}
```

Extend `row` with `result_code` → `"diameter.Result-Code"`, `gtpv2_cause` → `"gtpv2.cause"`, `s1ap_outcome` → `"s1ap.unsuccessfulOutcome_element"`, `ngap_outcome` → `"ngap.unsuccessfulOutcome_element"`, `s1ap_proc` → `"s1ap.procedureCode"`, `ngap_proc` → `"ngap.procedureCode"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_overview.py -v`
Expected: FAIL — no `negative` key

- [ ] **Step 3: Implement in `overview.py`**

- Diameter: for each `x` in `_instances(row, "diameter.Result-Code")` where `x` is non-empty and `int(x) >= 3000`: `negative["Diameter"][x] += 1`.
- GTPv2: `cause = row.get("gtpv2.cause")`; if `cause` and `cause != "16"`: count under `cause`.
- S1AP: `row.get("s1ap.unsuccessfulOutcome_element") == "1"` → count under `row.get("s1ap.procedureCode") or "?"`; NGAP the same with its two fields.
- `to_dict`: omit empty protocols; sort each protocol's rows by `(-count, int(key))` (all real keys are numeric; a `"?"` key sorts as 0).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_overview.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite and commit**

Run: `uv run pytest` — Expected: all green.
Commit:

```bash
git add src/unipcap/overview.py tests/test_overview.py
git commit -m "feat: add negative signaling response counts to overview"
```

---

### Task 4: GTP-U quality metrics

**Files:**
- Modify: `src/unipcap/overview.py` (append to `FIELDS`; extend `add_row`, `to_dict`)
- Test: `tests/test_overview.py` (extend)

**Interfaces:**
- Produces: `to_dict(ov)` gains, inside `"gtpu"`: `"loss": [{"src", "dst", "received", "missing", "pct"}…]` (sorted by received desc, then src), `"retrans_pct"`, `"drop_pct"`, `"no_response"`. `FIELDS` appends `gtp.seq_number`, `gtp.flags.s`, `tcp.analysis.retransmission`, `tcp.analysis.lost_segment`.
- Consumes: `_endpoints` and the `gtpu.volume` state from Task 1.

- [ ] **Step 1: Write the failing tests**

```python
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
```

Extend `row` with `sn` → `"gtp.seq_number"`, `sn_flag` → `"gtp.flags.s"`, `retrans` → `"tcp.analysis.retransmission"`, `lost` → `"tcp.analysis.lost_segment"`, `protocols` → `"frame.protocols"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_overview.py -v`
Expected: FAIL — missing `loss`/`retrans_pct`/`no_response` keys

- [ ] **Step 3: Implement in `overview.py`**

- Loss: per direction key `(src, dst)` from `_endpoints`, state `[received, missing, last_sn]`. On a G-PDU row with `gtp.flags.s == "True"` and a non-empty `gtp.seq_number`:

```python
sn = int(row["gtp.seq_number"])
gap = (sn - last - 1) % 65536          # wrap-safe; duplicate gives 65535
if gap == 65535: return                # duplicate: ignore
state[0] += 1; state[1] += gap; state[2] = sn
```

`pct = round(missing / (received + missing) * 100, 1)`.
- Inner TCP: `segs = row.get("frame.protocols", "").split(":")`; inner when `"gtp" in segs and "tcp" in segs`. Inner frames increment the denominator; `tcp.analysis.retransmission == "1"` / `tcp.analysis.lost_segment == "1"` increment the numerators. Rates `round(x, 1)`; denominator 0 → `None`.
- Echo: pending set of `(src, dst, sn)`; `gtp.message == "0x01"` adds, `"0x02"` pops `(dst, src, sn)`; `no_response = len(pending)` at `to_dict` time.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_overview.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite and commit**

Run: `uv run pytest` — Expected: all green.
Commit:

```bash
git add src/unipcap/overview.py tests/test_overview.py
git commit -m "feat: add GTP-U loss, retransmission, drop and echo metrics to overview"
```

---

### Task 5: Synthesized fixtures + end-to-end analysis

**Files:**
- Modify: `tests/pcapgen.py` (add builders)
- Test: `tests/test_overview.py` (extend)

**Interfaces:**
- Produces (pcapgen): `dns(src, dst, qid, resp=False, rcode=0, answers=0) -> bytes` (UDP/53: query flags `0x0100`; response flags `0x8180 | rcode` with `answers` answer RRs, question `example.com` type A echoed via pointer `0xc00c`); `gtpu_gpdu(src, dst, teid, seq, payload=b"", sn=True) -> bytes` (UDP/2152, GTP v1 flags `0x30` + `0x02` when `sn`, type `0xff`, length `8 + (4 if sn else 0) + len(payload)`, TEID, then seq + 2 zero bytes when `sn`); `gtpu_echo(src, dst, teid, seq, resp=False) -> bytes` (flags `0x32`, type `0x01`/`0x02`, TEID, seq + 2 zero bytes); `ip(src, dst, proto, body) -> bytes` (existing `_ip` without the ETH prefix); `tcp(src, dst, sport, dport, seq, payload=b"", ack=0) -> bytes` (IP proto 6, 20-byte TCP header, flags `0x18`, ack number `ack`).
- Consumes: `analyze`, `to_dict` from `unipcap.capture`; existing `udp`, `write` from pcapgen.

- [ ] **Step 1: Write the failing test**

```python
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
    d = json.loads(json.dumps(to_dict(analyze(pcap))))["overview"]
    assert d["dns"] == {"queries": 2, "answered": 1, "responses": 1, "rcode0": 1,
                        "answer_rate_pct": 50.0, "success_rate_pct": 100.0}
    assert d["gtpu"]["volume"]["frames"] == 5
    assert d["gtpu"]["loss"][0]["received"] == 2 and d["gtpu"]["loss"][0]["missing"] == 1
    assert d["gtpu"]["no_response"] == 1
    assert d["gtpu"]["retrans_pct"] == 33.3
    assert d["negative"] == {}
```

(Top of file: `import json`, `from pathlib import Path`, `from unipcap.capture import analyze, to_dict`. The ACK segment uses seq `1` for a fresh inner connection; its own seq numbering is irrelevant to the test.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_overview.py::test_analyze_end_to_end_overview -v`
Expected: FAIL — `ImportError: cannot import name 'dns' from 'pcapgen'`

- [ ] **Step 3: Implement the pcapgen builders**

DNS payload: header `struct.pack("!HHHHHH", qid, flags, 1, ans, 0, 0)`; question `b"\x07example\x03com\x00"` + `struct.pack("!HH", 1, 1)`; each answer RR: `struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + b"\x01\x02\x03\x04"`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_overview.py::test_analyze_end_to_end_overview -v`
Expected: PASS. If tshark does not flag the third TCP segment as a retransmission (`retrans_pct` not 33.3), add a fourth G-PDU segment from b→a with ACK 110 after the first data segment, and adjust the expected `retrans_pct` to 25.0 and `volume.frames` to 6 — then rerun until PASS.

- [ ] **Step 5: Verify against the real Gx/Gy sample (not CI) and commit**

Run: `uv run python -c "import json; from unipcap.capture import analyze, to_dict; ov = to_dict(analyze('samples/merged.pcap'))['overview']; print(json.dumps({k: ov[k] for k in ('dns', 'gx', 'gy', 'negative')}, indent=1))"`
Expected, in the printed JSON: `gy.given_octets` > 0, `gy.by_rg` contains a `"90"` row, `gx.rule_bases` contains `["R_IMS_DEFAULT", 1]`, `negative.Diameter` contains a `"4010"` row, and `dns.queries == 0`.

Run: `uv run pytest` — Expected: all green.
Commit:

```bash
git add tests/pcapgen.py tests/test_overview.py
git commit -m "test: synthesize DNS and GTP-U fixtures for overview end-to-end"
```

---

### Task 6: Overview tab in the UI

**Files:**
- Modify: `src/unipcap/web/app.js` (`renderLadder` ~line 50, `render` ~line 287)
- Modify: `src/unipcap/web/style.css`
- Test: `tests/test_serve.py` (extend)

**Interfaces:**
- Consumes: the `overview` object from `to_dict` (spec §14) via `summary.overview`.
- Produces: `renderLadder(ld, ov)` — second parameter, null-tolerant; `renderOverview(ov) -> HTMLElement`.

- [ ] **Step 1: Write the failing test**

`tests/test_serve.py`:

```python
def test_app_js_serves_overview_tab(server):
    status, body = call(server, "GET", "app.js")
    assert status == 200 and b"Overview" in body and b"renderOverview" in body
    assert b"Negative responses" in body
    assert b"!ld && !ov" in body  # DNS-only capture must still show the panel
    status, css = call(server, "GET", "style.css")
    assert status == 200 and b".ov-card" in css
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_serve.py::test_app_js_serves_overview_tab -v`
Expected: FAIL — `b"Overview" not found` etc.

- [ ] **Step 3: Implement the UI**

`renderLadder(ld, ov)`:
- Panel hidden only when `!ld && !ov` (ladder empty but overview present must render).
- `tabEls` gains the first entry `["overview", "Overview", null]` (no count suffix) and the default tab becomes `"overview"`.
- `buildBody()` branches first: when `tab === "overview"`, hide `head`, `body`, `detail` and show the overview element (built once by `buildOverview()`); otherwise re-show `head`/`body` and keep the existing ladder-row behavior. The click handler stays as it is — it resets `sel`/`detail` and calls `buildBody()`, which handles the tab.
- `buildOverview()`: a `div.overview` holding `div.ov-cards` with one `div.ov-card` per section, each built by a `card(title, rows)` helper (h3 + row divs) and `ov-table` tables for the Gx rules, Gy by_rg/by_sid, negatives and loss sections. Card titles exactly: `DNS`, `GTP-U volume`, `Gx reporting`, `Gy reporting`, `Negative responses`, `GTP-U quality`.
- Values: rates via `pct(x) = x == null ? "—" : x.toFixed(1) + " %"`; octets via the existing `humanBytes`; missing values `—`. Loss rows show `src → dst`; the negatives and loss sections show the `—` line when empty.
- All nodes via the existing `h()` helper (textContent only).
- `render(summary)`: `renderLadder(summary.ladder, summary.overview || null)`.

`style.css` — add classes: `.overview` (padding), `.ov-cards` (responsive grid, `repeat(auto-fill, minmax(260px, 1fr))`, 8px gap), `.ov-card` (panel border/radius/padding matching the existing cards), `.ov-card h3` (small caps label styled like `.grp h3`), `.ov-row` (flex, space-between), `.ov-table` (full-width, `var(--mono)`, right-aligned last column), `.ov-empty` (muted). Use only the existing tokens.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_serve.py -v`
Expected: PASS

- [ ] **Step 5: Verify in a real browser (headless Brave) and commit**

Build a harness HTML in the system Temp dir (pattern from the tabs feature): real `style.css`/`app.js` via `file://` links, embedded summary JSON with `ladder.messages.length == 0`, no bursts, and an `overview` object whose `dns.answer_rate_pct` is `50.0` and `gtpu.retrans_pct` is `null`; escape `<` as `\u003c`. Script it to click `Overview` (already default), measure `.ov-cards` bounding box, click `GTPC`, then `Overview` again; report via a `<pre id="result">`.
Run with `--headless --dump-dom` (Brave path `C:\Users\xero\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe`).
Expected: `RESULT` lines show the overview card box wider than 200px on both Overview activations, and the empty GTPC tab shows its notice while the overview was reachable.

Run: `uv run pytest` — Expected: all green.
Commit:

```bash
git add src/unipcap/web/app.js src/unipcap/web/style.css tests/test_serve.py
git commit -m "feat: add Overview tab with metric cards to the ladder panel"
```
