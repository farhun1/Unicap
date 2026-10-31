# Ladder Diagram (Signaling Flow) — Design

Roadmap item 2 of `2026-10-29-unipcap-vision.md`: "a ladder diagram between auto-labelled nodes,
filterable per node or per subscriber (IMSI/UE IP), with click-through to the decoded message."

## Purpose and intent

Open a capture and see the signaling call flow as a ladder diagram — one row per signaling
message, lifelines per network element labelled with type + name + IP — plus coarse arrows for
user-plane bursts, click-through to the full per-message decode, and automatic request→response
pairing. Behavior modeled on the Huawei RecordQuery flow-chart exports the user provided in
`samples/Sample_SM/` (16 reference folders), reimplemented in unipcap's own vanilla-DOM style.

What "feels the same" as the reference (from the reference behavior spec):

1. One fixed 35 px row per message in message order (not time-proportional).
2. Lifelines: node-name boxes on a header row, 3 px vertical lines at box centers.
3. Arrow = colored line from source column to destination column, arrowhead at the destination.
4. Message name centered over the arrow, colored per protocol.
5. Time column (right-aligned) showing message time + seconds since first message.
6. Click a message → highlight + detail view with the full decode.
7. Per-protocol colors; errors in red.
8. Large flows stay usable via a scrollable viewport (the reference pages with a slider; we use
   native scroll — see Skipped).

Beyond the reference: automatic request→response pairing (the reference has none), user-plane
burst arrows (the reference has a separate user-plane mode), and per-node focusing.

## Decisions

| Topic | Decision |
|---|---|
| Data source | Same analysis request. First pass (existing `iter_fields`) collects messages and bursts; a second tshark invocation (`-V`, signaling filter only) attaches decode text. No file retention, no new endpoint. |
| Message = signaling | `frame.protocols` tokens intersect `{s1ap, ngap, gtpv2, pfcp, diameter, sip, camel}`. |
| Row layout | Fixed row height (35 px), message order. Rendered with absolutely-positioned divs (reference technique), not SVG. |
| Pairing | Reliable where the protocol echoes an ID (Diameter `hopbyhopid`, PFCP `seqno`, GTPv2 `seq`); heuristic for S1AP/NGAP (procedure-code parity + reversed IP pair + 30 s window). |
| Node labels | Hostname when role inference found one, else IP; type = primary role. |
| Memory | On-the-fly aggregation: burst keyed accumulation, 5000-message cap, decode size budget. The 200 k-frame memory-bound test must still pass. |

## Architecture

### Server — collection (first pass, `capture.py`)

New constants in `capture.py`:

- `SIGNALING_TOKENS = {"s1ap", "ngap", "gtpv2", "pfcp", "diameter", "sip", "camel"}`
- `PROTO_NAMES = {"s1ap": "S1AP", "ngap": "NGAP", "gtpv2": "GTPv2", "pfcp": "PFCP",
  "diameter": "DIAMETER", "sip": "SIP", "camel": "CAMEL"}` (canonical display names for coloring)
- `PROTO_COLORS` lives client-side (see UI).
- `MESSAGE_CAP = 5000`, `DECODE_LIMIT = 12_000` (bytes per message), `DECODE_BUDGET = 4_000_000`
  (bytes total), `BURST_GAP = 1.0` (seconds).

`FIELDS` in `capture.py` gains (all verified against the bundled tshark 4.6.9):

- `frame.len` — burst byte counts
- `diameter.hopbyhopid`, `diameter.endtoendid` — pairing keys (note: no underscores)
- `pfcp.seqno` — pairing key (`pfcp.sequence_number` exists but is always empty — do not use)
- `gtpv2.seq` — pairing hint (`gtpv2.sequence_number` is always empty)
- `s1ap.procedureCode`, `ngap.procedureCode` — S1AP/NGAP pairing (no message-name field exists;
  names come from `_ws.col.info`)

`test_fields_exist_in_bundled_tshark` validates all of these automatically.

Inside the `analyze()` loop, per row:

- If signaling (`frame.protocols` tokens ∩ `SIGNALING_TOKENS`): append a message
  `{t, frame, src, dst, name, proto, key}` up to `MESSAGE_CAP` (overflow counted, not stored).
  `name` = `_ws.col.info` with any trailing `" |"` stripped. `src`/`dst` from `outer_inner()`
  outer pair (skipping `UNSPECIFIED`). `key` = the protocol's pairing key values (see Pairing).
  Retransmitted SCTP chunks are not dissected in the main pass: classify them via the existing
  learned map / `SCTP_PPID_PROTO` (proto = learned name or table name, name = info string).
  Retransmissions of filter protocols get decodes in the decode pass (which runs with TSN
  analysis off); table-only protos (M3UA family) carry no decode (see Decode).
- Else if it has a usable `(src, dst)` and is not in `UNSPECIFIED`: accumulate a data burst
  keyed `(src, dst, _ws.col.protocol)`; a gap > `BURST_GAP` since that key's last frame starts a
  new burst. Only the open burst per key is retained (bounded by number of pair×protocol keys).

`analyze()` returns a `Ladder` dataclass on `Summary` (default empty for zero frames):
`messages: list[Message]`, `bursts: list[Burst]`, `pairs: list[tuple[int, int]]`.

### Server — decode (second pass, `tshark.py` + `capture.py`)

New generator in `tshark.py`, `iter_verbose(pcap, display_filter, warnings)`:

- Command: `tshark -n -r <pcap> -Y "<filter>" -V`.
- Clones the `iter_fields` Popen pattern exactly: `stderr=TemporaryFile()` (never PIPE),
  `CREATE_NO_WINDOW` on win32, `WIRESHARK_CONFIG_DIR` empty profile, `encoding="utf-8"`,
  `errors="replace"`, explicit pipe close, `terminate()` on early close, same returncode policy.
- Streams stdout line by line; a block starts at a line matching `^Frame (\d+): ` and ends at
  the next such line or EOF. Yields `(frame_number, text)` per block. Never buffers whole output.

Called from `analyze()` after the first pass with
`-Y "s1ap or ngap or gtpv2 or pfcp or diameter or sip or camel"` while the learned map is still
in scope. Each block's frame number looks up its message (first pass kept a
`frame → message index` map for signaling frames); the decode attaches there, truncated to
`DECODE_LIMIT` with a `… (decode truncated)` footer, until `DECODE_BUDGET` is exhausted
(remaining messages get no decode; a warning names the totals).

Failure policy: the ladder pass never fails the analysis. Any exception from the second pass
degrades to a warning (`s.warnings`) and a ladder without decodes. The decode pass runs with
`-o sctp.tsn_analysis:FALSE`, so SCTP retransmissions of filter protocols match the filter and
get decodes (verified); retransmissions of table-only protos (M3UA family) still show a fallback
note instead.

### Server — pairing (`capture.py`, post-pass on messages)

Pairs are `(i, j)` message indexes. One message pairs at most once.

- **Diameter**: group by `(hopbyhopid, cmd.code)`; a request (`diameter.flags.request` = "1")
  pairs with the nearest-in-time answer (flag "0").
- **PFCP**: group by `pfcp.seqno`; message-type parity pairs N with N+1 (request/response).
- **GTPv2**: `gtpv2.seq` is a hint, not unique (retransmissions repeat it — dedupe by
  `(seq, message_type, src, dst)` taking the first occurrence); pair type N with N+1 on the
  reversed IP pair within a 30 s window.
- **S1AP / NGAP**: `procedureCode` odd = initiating, even = its successful outcome; pair odd N
  with even N+1 on the reversed IP pair, nearest within 30 s. Best-effort: S1AP has no
  transaction ID, so unpaired messages simply render as normal arrows.

### JSON (`capture.py to_dict()`)

```json
"ladder": {
  "nodes":  [{"ip": "...", "name": "...", "type": ""}],
  "messages": [{"t": 1792152037.69, "frame": 58, "src": 0, "dst": 1,
                "name": "UplinkNASTransport, PDN disconnect request",
                "proto": "S1AP", "decode": "Frame 58: ..."}],
  "bursts": [{"t0": ..., "t1": ..., "src": 0, "dst": 1, "proto": "GTP-U", "n": 128, "bytes": 1234567}],
  "pairs": [[0, 3], [2, 5]]
}
```

- `nodes`: one per ladder participant (has a message or burst), ordered by first appearance.
  `name` = first hostname from role inference else the IP; `type` = primary role else `""`.
- `src`/`dst` are indexes into `nodes` (resolved after nodes are built).
- `decode` present only when attached (see budget).
- Messages and bursts are separate arrays; the UI interleaves them by `t` and computes the
  relative-times column itself from `t` minus the first message's `t`.
- Collection-internal fields (pairing keys, the frame→message index map) are never serialized.

### UI (`web/`)

New `#ladder` section between `#chips` and `#sections` in `index.html`; `renderLadder()` in
`app.js` called from `render()` and cleared in `showError()`. Pure functions, `textContent`-only
DOM (capture data is untrusted — the decode text is rendered via `textContent` inside a `<pre>`).

Layout (reference-faithful, divs not SVG):

- Sticky header row: one box per node (hostname/IP + type), color `#369cda`, ellipsis; lifeline
  = 3 px `#7b8dac` vertical bar at each box center, full height.
- Body: scrollable (`max-height` ~70 vh, `overflow: auto`), fixed row height 35 px.
- Time column (210 px, right-aligned, `#EEEEEE` bg): per-row local time `HH:MM:SS.mmm` plus
  seconds-since-first.
- Message row: arrow line (3 px, protocol color) from src column to dst column with a CSS
  triangle arrowhead at the destination; centered label = message name (protocol color), title
  tooltip with the full name. Column step 171 px. A message where src == dst (loopback) renders
  as a short right-pointing stub on its own lifeline.
- Burst row: thin gray arrow, italic label `GTP-U ×128 · 1.2 MB` (humanized bytes).
- Protocol colors: S1AP/NGAP `#1099A2`, DIAMETER `#90CC19`, GTPv2 `#7C3AC1`, SIP `#F2A14E`,
  CAMEL `#00C90D`, PFCP `#369CD8`, bursts `#909090`. Dark mode: same hues, lightened via the
  existing token system.
- Interaction:
  - Click a message row → highlight it (`#2A90FF` label bg) and its paired counterpart
    (scrolls into view); show the detail pane below the ladder.
  - Detail pane: table rows Message Name / Time Stamp / Link (`src → dst`) / IP SRC / IP DST
    (from the outer addresses), then the decode in a monospace `<pre>`. Fallbacks: no decode →
    "Retransmitted chunk — decode not collected" or "Decode omitted (size budget)".
  - Click a node box → focus filter (toggle): only rows touching that node render; click again
    to clear. Satisfies the vision's "filterable per node".

### Error handling

- Message cap exceeded → warning "… more signaling messages omitted from ladder".
- Decode budget exhausted / messages without decode → warning with counts.
- Second pass failure → warning; ladder renders without decodes.
- Empty capture / no signaling → ladder section hidden (existing empty state).

### Testing

- Pure logic factored to take rows/dicts so `tests/conftest.py` `row()` can drive it:
  signaling classification (S1AP/NAS-EPS variants, camel, retransmitted SCTP via learned map),
  info cleaning, burst merging (gap ≤ 1 s merges, > 1 s splits), pairing for all four protocols
  (including the GTPv2 duplicate-seq dedupe and the S1AP window), decode attach/truncate/budget.
- `iter_verbose`: block splitting (headers, blank lines, UTF-8 glyphs `·`/`…`), on a sample
  capture; Popen hygiene is covered by the existing ResourceWarning-as-error config.
- End-to-end with pcapgen: UDP bursts (1 s default pacing → one burst; `times=[0, 5]` → two),
  200 k frames → `test_analyze_memory_bounded` still passes with ladder collection active.
- Sample-based (`skipif` capture absent, like `test_samples.py`): on `merged.pcap` — signaling
  message count > 0, decodes attached, Diameter pairs found; on a `Sample_SM` pcap — SIP/CAMEL
  messages present.
- UI verified by running the app against real samples (existing run pattern); no JS test infra.

## Skipped in this feature (named, not forgotten)

- **Paging/slider** for very large flows (reference behavior): native scroll renders up to the
  5000-message cap; revisit if big captures feel slow.
- **Per-subscriber filter** (IMSI/UE IP) from the vision: needs IMSI extraction from decodes —
  separate follow-up.
- **Session Info table** (procedure metadata: IMSI/APN/status): requires the vendor-style
  correlation engine; our pairing + decode is the honest equivalent.
- **Navigator (First/Previous/Following/Last)**: clicking arrows covers navigation in v1.
- **Collapsible decode tree** (reference's SignalingTree): flat monospace decode first.
- **`cap` as a filter token**: tshark's token is `camel`; no alias needed.
