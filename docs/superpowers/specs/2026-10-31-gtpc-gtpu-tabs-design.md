# GTPC / GTPU Ladder Tabs — Design

**Goal:** The ladder diagram splits into two tabs — **GTPC** (signalling) and **GTPU** (data) — so control-plane and user-plane traffic are shown separately, never combined. Uploading a capture segregates them automatically.

## Requirements

1. **Two tabs replace the combined ladder.** The ladder panel renders a tab bar with two tabs:
   - **GTPC** — all signalling messages the ladder collects: S1AP, NGAP, DIAMETER, GTPv2, SIP, CAMEL, PFCP (the `messages` array).
   - **GTPU** — all data-plane burst arrows (the `bursts` array).
   - Each tab label shows its row count, e.g. `GTPC (428)` / `GTPU (339)`.
2. **Auto-segregation on upload.** Nothing new to compute: the summary JSON already separates the two (`ladder.messages` holds only signalling messages, `ladder.bursts` only data bursts — `add_row` classifies every frame into exactly one). Uploading any pcap/pcapng therefore lands segregated in the tabs with zero server-side change.
3. **Default tab.** GTPC, falling back to GTPU when the capture has no signalling messages (a pure-data capture must not open on an empty tab).
4. **Empty tab.** A tab with no rows shows one line: `No signalling messages in this capture.` / `No data traffic in this capture.`
5. **Switching tabs clears the selection.** The selected message, its pair highlight, and the decode pane reset; the decode pane hides while the GTPU tab is active.
6. **Everything else is preserved.** Sticky node header (shared by both tabs), node-focus filter, 35px fixed rows, time column, message→decode detail pane, and the existing behavior that the whole panel hides when there are no messages and no bursts.

## Non-goals

- No server or Python changes: the data model already segregates; this is a render-only change.
- No third "Combined" tab.
- No changes to node sections, chips, or file info.

## Constraints

- Vanilla JS, zero dependencies; build DOM with textContent only (capture data is untrusted).
- Copy is fixed: tab labels `GTPC`, `GTPU`; empty-state lines above.
