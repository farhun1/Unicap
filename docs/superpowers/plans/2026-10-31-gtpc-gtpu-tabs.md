# GTPC/GTPU Ladder Tabs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the ladder diagram into two tabs — GTPC (signalling messages) and GTPU (data bursts) — with automatic segregation on upload.

**Architecture:** Render-only change in `app.js`/`style.css`. The summary JSON already separates signalling (`ladder.messages`) from data (`ladder.bursts`) — `add_row` classifies every frame into exactly one — so the tabs are built by filtering the already-merged row list by `kind` and rendering one tab's rows at a time. No server or Python changes.

**Tech Stack:** Vanilla JS + CSS (existing `h()` textContent-only DOM builder), pytest for the serve-level tripwire.

**Spec:** docs/superpowers/specs/2026-10-31-gtpc-gtpu-tabs-design.md

## Global Constraints

- No new dependencies; vanilla JS; DOM built with textContent only (capture data is untrusted).
- Zero server-side or Python changes — `tests/` Python tests all keep passing unchanged.
- Tab labels exactly `GTPC` and `GTPU`, each with its row count (`GTPC (428)`).
- Empty-state copy exactly: `No signalling messages in this capture.` / `No data traffic in this capture.`
- Default tab: GTPC, falling back to GTPU when `messages` is empty and `bursts` is not.
- Switching tabs resets the selection (`sel = -1`), clears and hides the decode pane.
- Ladder panel stays hidden entirely when there are no messages and no bursts (existing guard).
- The repo has no JS test runner; JS behavior is verified with `node --check` plus a serve-level tripwire test plus a browser confirm (Brave is installed).

## Review Focus

The spec implies these inputs no pytest can exercise (no JS runner); each is verified by the task's browser-confirm step, with the tripwire test guarding that the shipped bundle at least carries the feature:

1. Pure-data capture (messages empty, bursts present) must open on the GTPU tab, not an empty GTPC tab.
2. Switching tabs while a message is selected must hide the decode pane and clear the pair highlight.
3. Node-focus filter must apply inside both tabs.
4. Tab counts must equal `messages.length` / `bursts.length` (spec requirement 1).
5. A capture with no messages and no bursts must still hide the whole panel (existing behavior).

---

### Task 1: Split the ladder into GTPC/GTPU tabs

**Files:**
- Modify: `src/unipcap/web/app.js` — `renderLadder` only
- Modify: `src/unipcap/web/style.css` — append tab + empty-state styles
- Test: `tests/test_serve.py`

**Interfaces:**
- Consumes: `renderLadder(summary.ladder)` — the existing `ld` shape (`nodes`, `messages`, `bursts`, `pairs`); `h(tag, cls, text, kids)`; `Server`/`call()` helpers in `tests/test_serve.py`.
- Produces: no new interfaces; the rendered ladder gains a tab bar (`div.ladder-tabs`) with two `div.ladder-tab` buttons, ids `gtpc`/`gtpu` as a `data-tab` attribute value.

- [ ] **Step 1: Write the failing tripwire test**

```python
def test_app_js_serves_ladder_tabs(server):
    status, body = call(server, "GET", "app.js")
    assert status == 200 and b"ladder-tabs" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_serve.py::test_app_js_serves_ladder_tabs -v`
Expected: FAIL — `assert 200 == 200 and b'ladder-tabs' in body` fails (the served bundle lacks the class).

- [ ] **Step 3: Implement the tabs in `renderLadder` in `src/unipcap/web/app.js`**

Keep the existing merged `rows` array and `t0` exactly as built (the first row's time stays the time origin). Then:

1. `const msgRows = rows.filter((r) => r.kind === "msg");` and `const burstRows = rows.filter((r) => r.kind === "burst");`
2. Tab state: `let tab = msgRows.length ? "gtpc" : burstRows.length ? "gtpu" : "gtpc";` (pure-data fallback).
3. Build the tab bar before the header: `h("div", "ladder-tabs", null, ...)` containing two buttons `h("button", "ladder-tab", ...)` with text `"GTPC (" + msgRows.length + ")"` and `"GTPU (" + burstRows.length + ")"`; the active one gets class `on`; the click handler sets `tab`, clears `sel = -1`, clears and hides `detail`, toggles `.on` between the two, and calls `buildBody()`. (`detail` and `sel` are declared later in `renderLadder`; the handler body may reference them — clicks run after the render completes — but the tab-bar construction itself must not.)
4. `const tabRows = tab === "gtpc" ? msgRows : burstRows;` and use `tabRows` everywhere `buildBody` used `rows`: the `forEach`, the empty guard, and the body height.
5. Move the `body.style.height` assignment from creation time into `buildBody` (before the loop), sized `tabRows.length * LADDER_ROW_H + "px"`. `body.style.width` stays as-is.
6. Empty tab: when `!tabRows.length`, append `h("div", "ladder-empty", tab === "gtpc" ? "No signalling messages in this capture." : "No data traffic in this capture.")` to `layer` and skip the row loop and the `sel`/detail block.
7. Row positioning: `row.style.top = ri * LADDER_ROW_H + "px"` now uses the tab-local `ri` (rows pack without gaps); pairing and focus logic keep using the global `r.i`/`r.m.src` values unchanged.
8. Append the tab bar: `el.appendChild(tabs)` before `el.appendChild(head)`.

- [ ] **Step 4: Add the tab styles in `src/unipcap/web/style.css`**

Append after the `.ladder` block, matching the existing token style: `.ladder-tabs` (flex, gap 4px, padding 6px 8px 0), `.ladder-tab` (font inherit, 12px, `--bg` background, `--muted` text, 1px `--line` border, bottom border 0, radius 5px 5px 0 0, padding 4px 12px, cursor pointer), `.ladder-tab.on` (`--panel` background, `--accent` text, weight 600), `.ladder-empty` (`--muted`, padding 12px).

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/test_serve.py::test_app_js_serves_ladder_tabs -v`
Expected: PASS.

- [ ] **Step 6: Syntax and full suite**

Run: `node --check src/unipcap/web/app.js`
Expected: no output, exit 0.

Run: `uv run pytest -q`
Expected: 134 passed (133 existing + the new tripwire).

- [ ] **Step 7: Browser confirm**

Start the server against `samples/merged.pcap` (the session has a running instance pattern: `Server(port=8765)` + `brave.exe <url>`), open the UI, and check the Review Focus list: default GTPC tab with counts, GTPU tab shows bursts, clicking a message shows the decode pane, switching tabs clears it, node focus works in both tabs, a no-message capture would fall back (spot-check with a data-only pcap if one exists in `samples/`).

- [ ] **Step 8: Commit**

```bash
git add tests/test_serve.py src/unipcap/web/app.js src/unipcap/web/style.css
git commit -m "feat: split ladder into GTPC signalling and GTPU data tabs"
```
