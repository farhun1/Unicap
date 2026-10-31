# Overview Tab — Design

**Goal:** A third ladder-panel tab, **Overview**, that summarizes a capture at a glance: DNS success, GTP-U volume and quality, Gx and Gy reporting (quotas, rules, per-RG/per-SID), negative signaling responses, and GTP-U packet-loss / retransmission / drop / no-response metrics.

## Decisions

These were answered by the user and are binding:

| Topic | Decision |
|---|---|
| Gx / Gy split | By Diameter Application-Id AVP (`diameter.Auth-Application-Id`): `16777238` = Gx, `4` = Gy. A CC message with neither is skipped. |
| Given vs reported quota | Given = CCA `CC-Total-Octets` (answer rows); reported/consumed = CCR `CC-Total-Octets` (request rows). Two numbers per interface. |
| Gy SID | `Service-Identifier` AVP (`diameter.Service-Identifier`, 439). Gy tables group by `Rating-Group` (432) and by `Service-Identifier`. |
| Negative responses | Failures only: Diameter `Result-Code >= 3000`, GTPv2 `Cause` ≠ accepted (16), S1AP/NGAP `unsuccessfulOutcome` — summarized per protocol as count by code/cause/procedure. |
| DNS success rate | Both rates: rcode-0 responses ÷ total responses, AND answered queries ÷ total queries. |
| GTP-U metrics | Loss = GTP-U sequence-number gaps per direction; Retransmission = inner-TCP retransmissions ÷ tunneled TCP frames; Drop = inner-TCP lost segments ÷ tunneled TCP frames; No-response = GTP-U echo requests with no echo response. |

## Requirements

### UI

1. **Third tab.** The ladder panel's tab bar becomes `[Overview] [GTPC (n)] [GTPU (n)]`. Overview is first and is the default tab on load (the GTPC/GTPU fallback rule still applies when the user switches to them).
2. **Overview content.** Selecting Overview swaps the ladder body (rows, head, detail pane) for the overview section rendered from the summary's `overview` object; the sticky tab strip stays. The node header renders only on the GTPC/GTPU tabs.
3. **Overview cards, in order:**
   - **DNS** — two rates: answered % and rcode-0 (success) %.
   - **GTP-U volume** — G-PDU frame count and total bytes (human-readable).
   - **Gx reporting** — Given quota, Reported quota, and a rule summary: per name count of `Charging-Rule-Name` and `Charging-Rule-Base-Name`.
   - **Gy reporting** — Given quota, Reported quota, and two tables: per-RG (RG, Given, Reported) and per-SID (SID, Given, Reported).
   - **Negative responses** — per protocol (Diameter, GTPv2, S1AP, NGAP), a count table by code/cause/procedure.
   - **GTP-U quality** — per-direction loss rows (src → dst, received, missing, loss %), retransmission %, drop %, and the no-response count.
4. **Missing data renders as "—"**, never as 0: a rate whose denominator is zero, an absent quota, an empty table.
5. **Untrusted-data rule holds.** Everything is built with `textContent`, no innerHTML; new CSS uses the existing tokens.

### Extraction mechanics

6. **One tshark pass.** All new metrics are extracted inside the existing `iter_fields` pass: `FIELDS` gains an `overview.FIELDS` extension and `analyze()` streams every row through `overview.add_row(row)` beside `ladder.add_row`.
7. **New fields** (all verified against the installed tshark):

   ```
   dns.id, dns.flags.response, dns.flags.rcode, dns.count.answers,
   diameter.flags.request, diameter.Auth-Application-Id, diameter.Result-Code,
   diameter.CC-Total-Octets, diameter.Rating-Group, diameter.Service-Identifier,
   diameter.Charging-Rule-Name, diameter.Charging-Rule-Base-Name,
   gtp.message, gtp.seq_number, gtp.flags.s,
   gtpv2.cause, tcp.analysis.retransmission, tcp.analysis.lost_segment,
   s1ap.unsuccessfulOutcome_element, ngap.unsuccessfulOutcome_element
   ```

   `frame.len`, `frame.protocols`, `ip.src`/`ip.dst` (and v6), `s1ap.procedureCode` and `ngap.procedureCode` are already in FIELDS via `roles.FIELDS` / `capture.FIELDS`.
8. **Presence of flag fields.** FT_NONE fields (`tcp.analysis.*`, the outcome elements) render as the string `"1"` when present and `""` when absent in `-T fields` rows — verified against `DataTrace_Upf_2_*` and an S1AP capture. Detection is therefore `row.get(field) == "1"`; no decode-text parsing and no changes to `attach_decode`.

### Metric definitions

9. **DNS.**
   - query = `dns.flags.response == "False"`; response = `"True"` (boolean fields render as the strings `True`/`False`).
   - answered query = query whose `dns.id` later appears in a response in the reverse direction (dst → src) between the same two endpoints.
   - `answer_rate_pct = answered / queries * 100`, `success_rate_pct = rcode0 / responses * 100`, both rounded to 1 decimal; denominator 0 → null.
10. **GTP-U volume.** G-PDU frames = `gtp.message == "0xff"`. `volume = {frames, bytes}` where bytes = Σ `frame.len` over G-PDU frames.
11. **Gx / Gy.** A CC frame is Gx when `diameter.Auth-Application-Id == "16777238"`, Gy when `"4"`; otherwise skipped. Request rows (`diameter.flags.request == "True"`) are CCR → reported; answer rows are CCA → given. `diameter.CC-Total-Octets` values are summed per instance; multi-instance rows are comma-joined within one `|`-separated occurrence, so each `vals()` element splits on `,` and every instance is summed. Absent → contributes 0.
    - Gx rules: `Charging-Rule-Name` and `Charging-Rule-Base-Name` counted per name from Gx answer rows only.
    - Gy per-RG / per-SID: `Rating-Group`, `Service-Identifier` and `CC-Total-Octets` are parallel per-instance lists; pair by index and sum each instance's octets into `by_rg[rg]` / `by_sid[sid]` (given on answers, reported on requests). A shorter octets list leaves the tail at 0. Sorted by RG/SID value (numeric).
12. **Negative responses.** Per protocol:
    - **Diameter**: each `Result-Code` instance ≥ 3000 counts toward that code (multi-instance rows count each instance).
    - **GTPv2**: frames where `gtpv2.cause` is present and ≠ `16`, counted by cause value.
    - **S1AP / NGAP**: frames where `s1ap.unsuccessfulOutcome_element == "1"` / `ngap.unsuccessfulOutcome_element == "1"`; counted by the frame's `s1ap.procedureCode` / `ngap.procedureCode` value (numeric code).
13. **GTP-U quality.**
    - **Loss**: per outer direction (outer `ip.src` → `ip.dst`), over G-PDU frames with `gtp.flags.s == "True"` and a `gtp.seq_number`: sequential gaps `(sn − last − 1) mod 65536` accumulate into `missing`; duplicates (gap 65535) are ignored. `pct = missing / (received + missing) * 100`, 1 decimal. Rows sorted by received desc; no SN frames → empty list.
    - **Retransmission / drop**: numerator = frames with `tcp.analysis.retransmission` / `tcp.analysis.lost_segment` present; denominator = inner-TCP frames, i.e. the `frame.protocols` segment list contains both `gtp` and `tcp` (`gtpv2` is a different segment and must not match). Percent, 1 decimal; denominator 0 → null.
    - **No-response**: echo request frames (`gtp.message == "0x01"`) matched to an echo response (`"0x02"`) in the reverse direction with the same `gtp.seq_number`; count of requests never answered.

### Summary JSON

14. **`to_dict` gains one key**, `"overview"`:

    ```json
    {
      "dns":  {"queries": 0, "answered": 0, "responses": 0, "rcode0": 0,
               "answer_rate_pct": null, "success_rate_pct": null},
      "gtpu": {"volume": {"frames": 0, "bytes": 0},
               "loss": [{"src": "1.2.3.4", "dst": "5.6.7.8", "received": 10, "missing": 1, "pct": 9.1}],
               "retrans_pct": null, "drop_pct": null, "no_response": 0},
      "gx":   {"given_octets": 0, "reported_octets": 0,
               "rules": [["R_IMS_DEFAULT", 1]], "rule_bases": [["name", 1]]},
      "gy":   {"given_octets": 0, "reported_octets": 0,
               "by_rg": [["90", {"given": 0, "reported": 0}]],
               "by_sid": [["1000", {"given": 0, "reported": 0}]]},
      "negative": {"Diameter": [["4010", 26]], "GTPv2": [["73", 2]],
                   "S1AP": [["9", 1]], "NGAP": []}
    }
    ```

    `rules`/`rule_bases` sorted by count desc then name; `by_rg`/`by_sid` sorted by RG/SID value (numeric). Protocols with no negatives are omitted from `negative`.

## Data realities (verified against the samples)

- **`8801326713132_Gx_Gy_QP_Traffic_7D.pcap` is misnamed** — it contains no Diameter at all (GTP/TCP + TLS user-plane). The only real Gx/Gy capture is **`merged.pcap`**: 274 Gy CC frames (RGs {90, 1033, 1035, 1042, 1051, 1054, 1055, 1070, 110}, SIDs {90, 1000, 1033, 1035}, Request-Type mix 9 INITIAL / 256 UPDATE / 13 TERMINATION), 4 Gx CCA frames (one carrying `Charging-Rule-Base-Name: R_IMS_DEFAULT`), and multi-instance Result-Code rows (2001+4010, 2001+5031).
- **No sample has GTP-U sequence numbers or echo** (`gtp.seq_number` = 0 and no `gtp.message 0x01/0x02` anywhere); `DataTrace_Upf_2_*.pcap` supplies real DNS (336) and inner-TCP retransmissions (3290) for spot checks. Loss/echo fixtures must therefore be **synthesized by extending `tests/pcapgen.py`** (GTP-U v1 G-PDU with SN, echo request/response, DNS over UDP).
- **Golden files are unaffected**: `test_samples.py` compares node roles only, not the `to_dict` shape; `test_to_dict_is_json_serialisable` automatically exercises the new section.

## Non-goals

- No second tshark pass for metrics (the single streaming pass carries everything).
- No changes to node sections, chips, file info, or the GTPC/GTPU tab behavior.
- No rate limiting of tables (RG/SID/rule counts are small); no export.
- No cause-code name mapping: codes are shown as numbers.

## Constraints

- Vanilla JS, zero dependencies; textContent-only DOM (capture data is untrusted).
- Single tshark streaming pass is preserved; new fields must not break `iter_fields` positional zipping (they are appended to the shared FIELDS list).
- Copy is fixed: tab label `Overview`; missing metric renders as `—`.
