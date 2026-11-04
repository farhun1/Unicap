"use strict";
// Display order; a node with several roles shows under each. Third item caps rows.
const SECTIONS = [
  ["Radio", ["eNodeB", "gNB"]],
  ["Packet core", ["MME", "AMF", "SGW", "PGW", "SMF/PGW-C", "UPF"]],
  ["Diameter", ["HSS", "PCRF", "OCS", "EIR", "AAA", "DRA", "DEA"]],
  ["SS7", ["STP"]],
  ["IMS", ["P-CSCF"]],
  ["Subscribers", ["UE"]],
  ["Internet", ["Server"], 20],
];
const UNCLASSIFIED_CAP = 50;
const ROLE_CAP = 200;

// Ladders up to this many rows render eagerly; larger ones are virtualised (a
// scroll window is built from the same data, so nothing is dropped).
const LADDER_ROW_LIMIT = 600;
const ROW_OVERSCAN = 8;          // extra rows rendered above/below the viewport
const OV_TABLE_CAP = 40;         // rows per overview table before "… more rows"
const OV_ID_CAP = 8;             // subscriber ids shown per card before "+N more"
const MAX_PROTO_CHIPS = 15;      // protocol chips before "+N more"

// Build DOM with textContent only: capture data is untrusted.
function h(tag, cls, text, kids) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  (kids || []).forEach((k) => e.appendChild(k));
  return e;
}

function attrs(e, map) {
  for (const k in map) if (map[k] != null) e.setAttribute(k, map[k]);
  return e;
}

function button(cls, text, aria) {
  const b = h("button", cls, text);
  b.type = "button";
  if (aria) b.setAttribute("aria-label", aria);
  return b;
}

const fmt = (n) => Number(n).toLocaleString();

// Ladder diagram (signaling flow): protocol-colored arrows, req→rsp pairing, per-message decode.
const LADDER_COLORS = { S1AP: "#1099A2", NGAP: "#1099A2", DIAMETER: "#90CC19", GTPv2: "#7C3AC1",
                        SIP: "#F2A14E", CAMEL: "#00C90D", PFCP: "#369CD8" };
const LADDER_BURST = "#909090";
const LADDER_COL = 171;      // px per node column; lifeline at +85
const LADDER_ROW_H = 35;     // fixed row height, not time-proportional
const LADDER_TIME_W = 210;   // right-aligned time column
let ladderFocus = -1;        // focused node index, -1 = all
let ladderQuery = "";        // case-insensitive ladder filter text
let protoFilter = null;      // protocol-chip filter: {label, key, tab}
let chipHandler = null;      // renderChips -> renderLadder bridge (set per render)

// Signalling is normalised into ladder messages. A protocol chip can spell it with a
// payload suffix ("S1AP/NAS-EPS") or a variant ("GTPv2-C"), so match the base name.
const SIGNALLING_PROTOS = ["S1AP", "NGAP", "GTPv2", "PFCP", "DIAMETER", "SIP", "CAMEL", "SGSAP"];
function signallingFor(chipProto) {
  const up = String(chipProto || "").toUpperCase();
  return SIGNALLING_PROTOS.find((n) => {
    const u = n.toUpperCase();
    return up === u || up.startsWith(u + "/") || up.startsWith(u + "-");
  }) || null;
}

// Hooks the global keyboard handler uses against the current ladder instance.
let relayoutLadder = null;       // recompute the scroll window after a resize
let closeLadderSelection = null; // Escape: close the message detail
let clearLadderFocusHook = null; // Escape: clear the focused node
let clearLadderFilterHook = null;// Escape: clear the ladder filter
let clearProtoFilterHook = null; // Escape: clear the protocol (chip) filter
let sectionModel = null;         // data behind the role (node) sections
let sectionQuery = "";           // case-insensitive node filter text

function humanBytes(n) {
  if (n < 1024) return n + " B";
  for (const u of ["KB", "MB", "GB", "TB"]) {
    n /= 1024;
    if (n < 1024) return n.toFixed(1) + " " + u;
  }
  return n.toFixed(1) + " PB";
}

function fmtTime(t, t0) {
  const d = new Date(t * 1000);
  const p = (x, w) => String(x).padStart(w, "0");
  return `${p(d.getHours(), 2)}:${p(d.getMinutes(), 2)}:${p(d.getSeconds(), 2)}.${p(d.getMilliseconds(), 3)}  +${(t - t0).toFixed(3)}s`;
}

// Server timestamps are ISO-8601 UTC; show them in the viewer's local time.
function fmtStamp(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (!d || isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit",
                                       hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function fmtDuration(s) {
  if (s == null) return "—";
  if (s < 1) return Math.round(s * 1000) + " ms";
  if (s < 60) return (Math.round(s * 10) / 10) + " s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + " min " + Math.round(s % 60) + " s";
  return Math.floor(m / 60) + " h " + (m % 60) + " min";
}

const pct = (x) => (x == null ? "—" : x.toFixed(1) + " %");
const quota = (x) => (x ? humanBytes(x) : "—"); // absent quota renders "—", never 0 (spec §4)

// Overview tab: metric cards built with textContent only — capture data is untrusted.
function renderOverview(ov) {
  const row = (k, v) => h("div", "ov-row", null, [h("span", null, k), h("span", null, v)]);
  const card = (title, rows, kids) => h("div", "ov-card", null,
    [h("h3", null, title), ...rows.map(([k, v]) => row(k, v)), ...(kids || [])]);
  const empty = () => h("div", "ov-empty", "—");
  // Cap long tables: a capture with thousands of rules must not build a huge DOM.
  const table = (heads, rows) => {
    if (!rows.length) return empty();
    const shown = rows.slice(0, OV_TABLE_CAP);
    const t = h("table", "ov-table", null, [
      h("thead", null, null, [h("tr", null, null, heads.map((c) => h("th", null, c)))]),
      h("tbody", null, null, shown.map((r) => h("tr", null, null, r.map((c) => h("td", null, c))))),
    ]);
    if (rows.length <= OV_TABLE_CAP) return t;
    return h("div", "ov-table-wrap", null,
      [t, h("div", "ov-more", "… " + fmt(rows.length - OV_TABLE_CAP) + " more rows")]);
  };

  const d = ov.dns, g = ov.gtpu, gx = ov.gx, gy = ov.gy, sub = ov.subscribers;
  const ids = (pairs) => {
    if (!pairs.length) return "—";
    const shown = pairs.slice(0, OV_ID_CAP).map(([v, n]) => (n > 1 ? v + " ×" + n : v)).join(", ");
    return pairs.length > OV_ID_CAP ? shown + " +" + fmt(pairs.length - OV_ID_CAP) + " more" : shown;
  };
  const negRows = Object.entries(ov.negative)
    .flatMap(([proto, codes]) => codes.map(([code, n]) => [proto + " " + code, fmt(n)]));
  const lossRows = g.loss.map((l) => [`${l.src} → ${l.dst}`, fmt(l.received), fmt(l.missing), pct(l.pct)]);
  return h("div", "overview", null, [h("div", "ov-cards", null, [
    card("Subscribers", [
      ["IMSI", ids(sub.imsi)],
      ["MSISDN", ids(sub.msisdn)],
    ]),
    card("DNS", [
      ["Queries", fmt(d.queries)],
      ["Responses", fmt(d.responses)],
      ["Answered", pct(d.answer_rate_pct)],
      ["Success (rcode 0)", pct(d.success_rate_pct)],
    ]),
    card("GTP-U volume", [
      ["G-PDU frames", fmt(g.volume.frames)],
      ["Bytes", humanBytes(g.volume.bytes)],
    ]),
    card("Gx reporting", [
      ["Given quota", quota(gx.given_octets)],
      ["Reported quota", quota(gx.reported_octets)],
    ], [
      table(["Rule base", "Count"], gx.rule_bases.map(([n, c]) => [n, fmt(c)])),
      table(["Rule name", "Count"], gx.rules.map(([n, c]) => [n, fmt(c)])),
    ]),
    card("Gy reporting", [
      ["Given quota", quota(gy.given_octets)],
      ["Reported quota", quota(gy.reported_octets)],
    ], [
      table(["RG", "Given", "Reported"],
        gy.by_rg.map(([k, v]) => [k, humanBytes(v.given), humanBytes(v.reported)])),
      table(["SID", "Given", "Reported"],
        gy.by_sid.map(([k, v]) => [k, humanBytes(v.given), humanBytes(v.reported)])),
    ]),
    card("Negative responses", [], [table(["Code", "Count"], negRows)]),
    card("GTP-U quality", [
      ["Retransmissions", pct(g.retrans_pct)],
      ["Dropped (lost segments)", pct(g.drop_pct)],
      ["No response", fmt(g.no_response)],
    ], [table(["Loss per direction", "Received", "Missing", "Rate"], lossRows)]),
  ])]);
}

// ── Ladder ──────────────────────────────────────────────────────────────────

function renderLadder(ld, ov) {
  const el = document.getElementById("ladder");
  ladderFocus = -1;
  ladderQuery = "";
  protoFilter = null;
  chipHandler = null;
  relayoutLadder = null;
  closeLadderSelection = null;
  clearLadderFocusHook = null;
  clearLadderFilterHook = null;
  clearProtoFilterHook = null;
  // an empty ladder counts as absent
  if (ld && !ld.messages.length && !ld.bursts.length) ld = null;
  el.hidden = !ld && !ov;
  el.replaceChildren();
  if (el.hidden) return;
  ld = ld || { messages: [], bursts: [], nodes: [], pairs: [] };

  const rows = [];
  ld.messages.forEach((m, i) => rows.push({ t: m.t, kind: "msg", i, m }));
  ld.bursts.forEach((b, i) => rows.push({ t: b.t0, kind: "burst", i, b }));
  rows.sort((a, b) => a.t - b.t);
  const t0 = rows.length ? rows[0].t : 0;
  const msgRows = rows.filter((r) => r.kind === "msg");
  const burstRows = rows.filter((r) => r.kind === "burst");
  const nodes = ld.nodes || [];
  const nodeText = (i) => {
    const n = nodes[i];
    return n ? [n.name, n.ip, n.type].filter(Boolean).join(" ") : "";
  };
  // One lowercase haystack per row, so filtering a 30k-message ladder stays cheap.
  for (const r of rows) {
    r.hay = (r.kind === "msg"
      ? ["frame " + r.m.frame, r.m.name, r.m.proto, nodeText(r.m.src), nodeText(r.m.dst)]
      : ["burst", r.b.proto, nodeText(r.b.src), nodeText(r.b.dst), "frames " + r.b.n, r.b.bytes + " bytes"])
      .join(" ").toLowerCase();
  }
  const pairMap = new Map();
  (ld.pairs || []).forEach(([a, b]) => {
    if (a != null && b != null) { pairMap.set(a, b); pairMap.set(b, a); }
  });

  const n = nodes.length;
  const contentW = n * LADDER_COL + LADDER_TIME_W;
  const labelRight = contentW - LADDER_TIME_W; // labels stay left of the time column
  const x = (i) => i * LADDER_COL + LADDER_COL / 2;
  const protoColor = (p) => LADDER_COLORS[p] || LADDER_BURST;

  // Tabs
  const tabDefs = [];
  if (ov) tabDefs.push(["overview", "Overview", null]);
  tabDefs.push(["gtpc", "GTPC", msgRows.length], ["gtpu", "GTPU", burstRows.length]);
  let tab = ov ? "overview" : msgRows.length ? "gtpc" : "gtpu";

  // Search box + live counts; only meaningful on the message tabs.
  const qInput = h("input", "ladder-input");
  attrs(qInput, { type: "search", placeholder: "Filter messages — name, protocol, node, frame",
                  "aria-label": "Filter ladder messages", autocomplete: "off", spellcheck: "false" });
  const qClear = button("search-clear", "×", "Clear ladder filter");
  qClear.hidden = true;
  const countEl = h("span", "ladder-count", "");
  attrs(countEl, { role: "status", "aria-live": "polite" });
  const focusPill = button("focus-pill", "", "Clear node focus");
  focusPill.hidden = true;
  const protoPill = button("focus-pill proto-pill", "", "Clear protocol filter");
  protoPill.hidden = true;
  const winNote = h("span", "ladder-window", "");
  const tools = h("div", "ladder-tools", null,
    [h("div", "search", null, [qInput, qClear]), countEl, protoPill, focusPill, winNote]);

  const tabEls = tabDefs.map(([id, label, count]) => {
    const b = button("ladder-tab", count == null ? label : label + " (" + count + ")");
    b.setAttribute("role", "tab");
    b.setAttribute("aria-selected", String(tab === id));
    b.tabIndex = tab === id ? 0 : -1;
    b.addEventListener("click", () => selectTab(id));
    return b;
  });
  const tabs = h("div", "ladder-tabs", null, tabEls);
  tabs.setAttribute("role", "tablist");
  tabs.setAttribute("aria-label", "Ladder views");
  tabs.addEventListener("keydown", (e) => {
    const i = tabDefs.findIndex(([id]) => id === tab);
    let j = -1;
    if (e.key === "ArrowRight") j = (i + 1) % tabDefs.length;
    else if (e.key === "ArrowLeft") j = (i - 1 + tabDefs.length) % tabDefs.length;
    else if (e.key === "Home") j = 0;
    else if (e.key === "End") j = tabDefs.length - 1;
    if (j < 0) return;
    e.preventDefault();
    selectTab(tabDefs[j][0]);
    tabEls[j].focus();
  });

  // Sticky node header boxes + lifelines.
  const head = h("div", "ladder-head");
  const boxes = [];
  nodes.forEach((node, i) => {
    const box = h("div", "ladder-node", null, [
      h("div", "nm", node.name),
      h("div", "tp", node.type),
    ]);
    box.style.left = x(i) - 70 + "px";
    box.title = [node.name, node.type, node.ip].filter(Boolean).join("\n");
    attrs(box, { role: "button", tabindex: "0", "aria-pressed": "false",
                 "aria-label": "Focus flows for " + node.name + (node.type ? " (" + node.type + ")" : "") });
    box.addEventListener("click", () => setFocus(i));
    box.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setFocus(i); }
    });
    boxes.push(box);
    head.appendChild(box);
  });

  const stick = h("div", "ladder-stick", null, [tools, tabs, head]);
  stick.style.width = contentW + "px"; // CSS min-width:100% stretches it when the panel is wider

  const mainEl = h("div", "ladder-main");
  const body = h("div", "ladder-body");
  body.style.width = contentW + "px";
  const lines = h("div", "ladder-lines", null,
    nodes.map((_, i) => {
      const line = h("div", "ladder-line");
      line.style.left = x(i) - 1.5 + "px";
      return line;
    }));
  const layer = h("div", "ladder-rows");
  attrs(layer, { role: "listbox", "aria-label": "Ladder messages" });

  // Detail panel: a sibling of the scroller, so selecting a row near the top of a
  // 30k-row ladder does not put its decode thousands of pixels below the fold.
  const detail = h("aside", "ladder-detail");
  attrs(detail, { role: "region", "aria-label": "Message detail", "aria-live": "polite" });
  detail.hidden = true;
  const detailTitle = h("h3", null, "Message detail");
  const detailClose = button("ghost-btn icon-btn", "×", "Close message detail");
  const detailBody = h("div", "ld-body");
  detail.append(h("div", "ld-head", null, [detailTitle, detailClose]), detailBody);

  body.append(lines, layer);
  mainEl.append(stick, body);

  let sel = null;              // {kind, i} — selected ladder item
  let kbd = 0;                 // roving keyboard focus, index into `view`
  let view = [];               // rows for the active tab after focus + filter
  let winStart = 0;
  let winEnd = 0;
  const rendered = [];         // [{ row, r, k }] currently in the DOM (a window)
  let msgEls = new Map();      // message index -> row element
  let burstEls = new Map();    // burst index -> row element

  const kv = (k, v) => h("div", "ld-row", null, [h("span", "ld-k", k), h("span", "ld-v", v)]);

  function baseRows() { return tab === "gtpc" ? msgRows : burstRows; }

  function currentView() {
    let list = baseRows().filter((r) => ladderFocus < 0
      || (r.kind === "msg" && (r.m.src === ladderFocus || r.m.dst === ladderFocus))
      || (r.kind === "burst" && (r.b.src === ladderFocus || r.b.dst === ladderFocus)));
    if (protoFilter) {  // exact protocol: a "DNS" chip must not also match "GTP/DNS"
      const key = protoFilter.key.toUpperCase();
      list = list.filter((r) => ((r.kind === "msg" ? r.m.proto : r.b.proto) || "").toUpperCase() === key);
    }
    const terms = ladderQuery.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (terms.length) list = list.filter((r) => terms.every((t) => r.hay.includes(t)));
    return list;
  }

  function viewHeight() {
    const vh = mainEl.clientHeight;
    return vh > 40 ? vh : 620; // jsdom and pre-layout have no height
  }
  function rowsFit() {
    return Math.max(24, Math.ceil(viewHeight() / LADDER_ROW_H) + 2 * ROW_OVERSCAN);
  }
  function windowBounds(total) {
    const fit = rowsFit();
    if (total <= Math.max(LADDER_ROW_LIMIT, fit)) return [0, total];
    const top = Math.max(0, (mainEl.scrollTop || 0) - (stick.offsetHeight || 0));
    const first = Math.floor(top / LADDER_ROW_H) - ROW_OVERSCAN;
    const start = Math.max(0, Math.min(first, total - fit));
    return [start, Math.min(total, start + fit)];
  }

  // Clamp centred labels so they never slide under the time column or off the
  // left edge (self-calls on the first node used to be cut off).
  function labelMax(cx) {
    const space = Math.min(cx - 8, labelRight - cx - 8);
    return Math.max(56, Math.min(280, space * 2));
  }

  function arrow(parent, x1, x2, color, thin) {
    const line = h("div", "ladder-arrow" + (thin ? " thin" : ""));
    line.style.left = Math.min(x1, x2) + "px";
    line.style.width = Math.abs(x2 - x1) + "px";
    line.style.setProperty("--ld-color", color);
    const tri = h("div", "ladder-headtri" + (thin ? " thin" : "") + (x2 > x1 ? " r" : " l"));
    tri.style.left = (x2 > x1 ? x2 - 8 : x2) + "px";
    tri.style.setProperty("--ld-color", color);
    parent.append(line, tri);
  }

  function paintBoxes() {
    for (let j = 0; j < boxes.length; j++) {
      const on = j === ladderFocus;
      boxes[j].classList.toggle("focus", on);
      boxes[j].setAttribute("aria-pressed", on ? "true" : "false");
    }
  }

  function paintTabs() {
    tabEls.forEach((b, i) => {
      const on = tabDefs[i][0] === tab;
      b.classList.toggle("on", on);
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
    });
  }

  function updateCounts(tabRows) {
    if (tab === "overview") return;
    const noun = tab === "gtpc" ? "messages" : "flows";
    const total = baseRows().length;
    const filtering = !!ladderQuery.trim() || ladderFocus >= 0 || !!protoFilter;
    const scope = protoFilter ? protoFilter.label + " · " : "";
    countEl.textContent = filtering
      ? scope + fmt(tabRows.length) + " of " + fmt(total) + " " + noun
      : fmt(total) + " " + noun;
    protoPill.hidden = !protoFilter;
    if (protoFilter) protoPill.textContent = "Protocol: " + protoFilter.label + "  ×";
    const showPill = ladderFocus >= 0 && nodes[ladderFocus];
    focusPill.hidden = !showPill;
    if (showPill) focusPill.textContent = "Focus: " + nodes[ladderFocus].name + "  ×";
  }

  function updateWindowNote(start, end, total) {
    winNote.textContent = end - start < total
      ? "Rows " + fmt(start + 1) + "–" + fmt(end) + " of " + fmt(total) + " · scroll to explore"
      : "";
  }

  function emptyNotice() {
    const noun = tab === "gtpc" ? "messages" : "flows";
    const q = ladderQuery.trim();
    const box = h("div", "ladder-empty");
    if (q) {
      box.appendChild(h("span", null, "No " + noun + " match “" + q + "”."));
      const clear = button("ghost-btn", "Clear filter");
      clear.addEventListener("click", () => { qInput.value = ""; applyLadderFilter(); });
      box.appendChild(clear);
    } else if (protoFilter) {
      box.appendChild(h("span", null,
        "No " + noun + " for protocol " + protoFilter.label + " in this tab."));
      const clear = button("ghost-btn", "Clear protocol filter");
      clear.addEventListener("click", () => applyProtocolFilter(protoFilter.label));
      box.appendChild(clear);
    } else if (ladderFocus >= 0) {
      const name = nodes[ladderFocus] ? nodes[ladderFocus].name : "this node";
      box.appendChild(h("span", null, "No " + noun + " for " + name + " in this tab."));
      const clear = button("ghost-btn", "Clear node focus");
      clear.addEventListener("click", () => setFocus(ladderFocus));
      box.appendChild(clear);
    } else {
      box.appendChild(h("span", null,
        tab === "gtpc" ? "No signalling messages in this capture." : "No data traffic in this capture."));
    }
    return box;
  }

  function buildRow(r, k) {
    const row = h("div", "ladder-row");
    row.style.top = k * LADDER_ROW_H + "px";
    attrs(row, { role: "option", "aria-selected": "false", tabindex: k === kbd ? "0" : "-1" });
    const time = h("div", "ladder-time", fmtTime(r.t, t0));
    row.appendChild(time);
    if (r.kind === "burst") {
      const x1 = x(r.b.src), x2 = x(r.b.dst);
      arrow(row, x1, x2, LADDER_BURST, true);
      const cx = (x1 + x2) / 2;
      const label = h("div", "ladder-blabel",
        `${r.b.proto} ×${fmt(r.b.n)} · ${humanBytes(r.b.bytes)}`);
      label.style.left = cx + "px";
      label.style.maxWidth = labelMax(cx) + "px";
      label.style.setProperty("--ld-color", LADDER_BURST);
      label.title = label.textContent;
      row.appendChild(label);
    } else {
      const m = r.m;
      const x1 = x(m.src), x2 = m.src === m.dst ? x1 + 40 : x(m.dst);
      const color = protoColor(m.proto);
      arrow(row, x1, x2, color, false);
      const cx = (x1 + x2) / 2;
      const label = h("div", "ladder-label", m.name);
      label.style.left = cx + "px";
      label.style.maxWidth = labelMax(cx) + "px";
      label.style.setProperty("--ld-color", color);
      label.title = m.name + (m.proto ? " · " + m.proto : "") + " (frame " + fmt(m.frame) + ")";
      row.appendChild(label);
    }
    row.addEventListener("click", () => { selectRow(r, k); });
    return row;
  }

  function showDetail(r) {
    const srcN = nodes[r.kind === "msg" ? r.m.src : r.b.src] || { name: "?", ip: "?" };
    const dstN = nodes[r.kind === "msg" ? r.m.dst : r.b.dst] || { name: "?", ip: "?" };
    const kids = [];
    if (r.kind === "msg") {
      const m = r.m;
      const fallback = m.name.includes("retransmission")
        ? "Retransmitted chunk — decode not collected"
        : "Decode omitted (size budget)";
      kids.push(
        kv("Message Name", m.name),
        kv("Protocol", m.proto),
        kv("Frame", fmt(m.frame)),
        kv("Time Stamp", fmtTime(m.t, t0)),
        kv("Link", srcN.name + " → " + dstN.name),
        kv("IP SRC", srcN.ip),
        kv("IP DST", dstN.ip),
      );
      const pair = pairMap.get(r.i);
      if (pair != null && ld.messages[pair]) {
        const p = ld.messages[pair];
        const jump = button("ghost-btn pair-jump",
          "Paired: " + p.name + " (" + fmtTime(p.t, t0) + ") →");
        jump.addEventListener("click", () => selectAndReveal("msg", pair));
        kids.push(jump);
      }
      kids.push(h("pre", "ld-pre", m.decode || fallback));
    } else {
      const b = r.b;
      kids.push(
        kv("Traffic", b.proto + " burst"),
        kv("Link", srcN.name + " → " + dstN.name),
        kv("IP SRC", srcN.ip),
        kv("IP DST", dstN.ip),
        kv("Packets", fmt(b.n)),
        kv("Bytes", humanBytes(b.bytes) + " (" + fmt(b.bytes) + ")"),
        kv("Time Span", fmtTime(b.t0, t0) + " → " + fmtTime(b.t1, t0)),
        kv("Duration", fmtDuration(Math.max(0, b.t1 - b.t0))),
      );
    }
    detailTitle.textContent = r.kind === "msg" ? "Message detail" : "Traffic detail";
    detailBody.replaceChildren(...kids);
    detail.hidden = false;
    detail.scrollTop = 0;
  }

  function applyRowState() {
    for (const { row, r, k } of rendered) {
      const isSel = !!sel && sel.kind === r.kind && sel.i === r.i;
      const isPair = !!sel && sel.kind === "msg" && r.kind === "msg" && pairMap.get(sel.i) === r.i;
      row.classList.toggle("sel", isSel);
      row.classList.toggle("pair", isPair);
      row.setAttribute("aria-selected", String(isSel));
      row.tabIndex = k === kbd ? 0 : -1;
    }
  }

  function clearSelection(repaint) {
    sel = null;
    detail.hidden = true;
    detailBody.replaceChildren();
    if (repaint !== false) applyRowState();
  }

  function viewHasSelection(list) {
    return !!sel && list.some((r) => r.kind === sel.kind && r.i === sel.i);
  }

  function renderRows() {
    const tabRows = currentView();
    view = tabRows;
    body.style.height = Math.max(tabRows.length, 1) * LADDER_ROW_H + "px";
    layer.replaceChildren();
    msgEls = new Map();
    burstEls = new Map();
    rendered.length = 0;
    if (!viewHasSelection(tabRows)) clearSelection(false);
    if (tabRows.length && kbd >= tabRows.length) kbd = tabRows.length - 1;
    if (!tabRows.length) {
      kbd = 0;
      layer.appendChild(emptyNotice());
      updateCounts(tabRows);
      winNote.textContent = "";
      return;
    }
    const [start, end] = windowBounds(tabRows.length);
    winStart = start;
    winEnd = end;
    for (let k = start; k < end; k++) {
      const r = tabRows[k];
      const row = buildRow(r, k);
      layer.appendChild(row);
      rendered.push({ row, r, k });
      if (r.kind === "msg") msgEls.set(r.i, row);
      else burstEls.set(r.i, row);
    }
    applyRowState();
    updateCounts(tabRows);
    updateWindowNote(start, end, tabRows.length);
  }

  function setFocus(i) {
    ladderFocus = ladderFocus === i ? -1 : i;
    paintBoxes();
    kbd = 0;
    mainEl.scrollTop = 0;
    renderRows();
  }

  function selectRow(r, k) {
    if (k != null) kbd = k;
    sel = { kind: r.kind, i: r.i };
    showDetail(r);
    applyRowState();
  }

  // Move the roving focus, re-windowing the ladder when the target is outside it.
  function moveTo(k) {
    if (!view.length) return;
    kbd = Math.max(0, Math.min(view.length - 1, k));
    let item = rendered.find((x) => x.k === kbd);
    if (!item) {
      const top = kbd * LADDER_ROW_H;
      mainEl.scrollTop = Math.max(0, top - Math.floor(viewHeight() / 3));
      renderRows();
      item = rendered.find((x) => x.k === kbd);
    }
    if (item) item.row.focus({ preventScroll: true });
    applyRowState();
  }

  function selectAndReveal(kind, i) {
    const k = view.findIndex((r) => r.kind === kind && r.i === i);
    if (k < 0) return;
    kbd = k;
    const target = view[k];
    selectRow(target, k);
    moveTo(k);
    showDetail(target);
  }

  function applyLadderFilter() {
    ladderQuery = qInput.value;
    qClear.hidden = !ladderQuery;
    kbd = 0;
    mainEl.scrollTop = 0;
    renderRows();
  }

  function selectTab(id) {
    if (tab === id) return;
    tab = id;
    kbd = 0;
    clearSelection(false);
    paintTabs();
    buildBody();
  }

  function buildBody() {
    // The overview is a child of the scroller (below the sticky tab strip), so
    // switching to it must hide the row body only. Hiding `mainEl` here would hide
    // the tabs themselves and make GTPC/GTPU unreachable.
    const overview = tab === "overview";
    head.hidden = overview;
    body.hidden = overview;
    tools.hidden = overview;
    if (overview) detail.hidden = true;
    if (ovEl) ovEl.hidden = !overview;
    // Only the tab strip remains in overview: give it the panel's width instead of
    // the ladder's content width (which can be thousands of pixels).
    stick.style.width = overview ? "" : contentW + "px";
    mainEl.scrollTop = 0;
    if (overview) return;
    renderRows();
  }

  // A protocol chip is a direct jump: switch to the tab that holds those rows and
  // keep only frames whose protocol matches exactly ("DNS" must not show "GTP/DNS").
  function applyProtocolFilter(chipProto) {
    const sign = signallingFor(chipProto);
    const targetTab = sign ? "gtpc" : "gtpu";
    const clearing = !!protoFilter && protoFilter.label === chipProto;
    protoFilter = clearing ? null : { label: chipProto, key: sign || chipProto };
    if (!clearing) {  // a protocol jump starts from an unfiltered view
      ladderQuery = "";
      qInput.value = "";
      qClear.hidden = true;
      ladderFocus = -1;
      paintBoxes();
    }
    if (tab !== targetTab) {
      tab = targetTab;
      paintTabs();
    }
    kbd = 0;
    clearSelection(false);
    buildBody();
    paintChips();
    if (!el.scrollIntoView) return;
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
  }

  // Highlight the chip whose packets are showing.
  function paintChips() {
    document.querySelectorAll("#chips .chip.link").forEach((c) => {
      const on = !!protoFilter && c.dataset.proto === protoFilter.label;
      c.classList.toggle("on", on);
      c.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }

  // Tab / search / focus wiring
  qInput.addEventListener("input", applyLadderFilter);
  qClear.addEventListener("click", () => { qInput.value = ""; applyLadderFilter(); qInput.focus(); });
  focusPill.addEventListener("click", () => { if (ladderFocus >= 0) setFocus(ladderFocus); });
  protoPill.addEventListener("click", () => { if (protoFilter) applyProtocolFilter(protoFilter.label); });
  detailClose.addEventListener("click", () => clearSelection());

  // Roving keyboard navigation over the rendered message rows.
  layer.addEventListener("keydown", (e) => {
    if (!view.length) return;
    const page = Math.max(5, Math.floor(viewHeight() / LADDER_ROW_H) - 1);
    let next;
    if (e.key === "ArrowDown") next = kbd + 1;
    else if (e.key === "ArrowUp") next = kbd - 1;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = view.length - 1;
    else if (e.key === "PageDown") next = kbd + page;
    else if (e.key === "PageUp") next = kbd - page;
    else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      selectRow(view[kbd], kbd);
      return;
    } else return;
    e.preventDefault();
    moveTo(next);
  });

  // Re-window as the user scrolls. Only rebuilds when the row window changes.
  let scrollQueued = false;
  mainEl.addEventListener("scroll", () => {
    if (scrollQueued) return;
    scrollQueued = true;
    const run = () => {
      scrollQueued = false;
      if (el.hidden || tab === "overview") return;
      const total = view.length;
      if (total <= LADDER_ROW_LIMIT) return;
      const [s, e] = windowBounds(total);
      if (s === winStart && e === winEnd) { updateWindowNote(s, e, total); return; }
      renderRows();
    };
    if (window.requestAnimationFrame) window.requestAnimationFrame(run);
    else setTimeout(run, 16);
  }, { passive: true });

  const ovEl = ov ? renderOverview(ov) : null; // built once; tab switching only toggles visibility
  el.appendChild(mainEl);
  el.appendChild(detail);
  if (ovEl) mainEl.appendChild(ovEl); // inside the scroller, under the sticky tabs
  buildBody();

  // Exposed to the document-level keyboard handler.
  closeLadderSelection = () => {
    if (!sel && detail.hidden) return false;
    clearSelection();
    return true;
  };
  clearLadderFocusHook = () => {
    if (ladderFocus < 0) return false;
    setFocus(ladderFocus);
    return true;
  };
  clearLadderFilterHook = () => {
    if (!qInput.value) return false;
    qInput.value = "";
    applyLadderFilter();
    return true;
  };
  clearProtoFilterHook = () => {
    if (!protoFilter) return false;
    applyProtocolFilter(protoFilter.label);
    return true;
  };
  const relayout = () => {
    if (el.hidden || tab === "overview") return;
    renderRows();
  };
  relayoutLadder = relayout;
  chipHandler = applyProtocolFilter;  // protocol chips navigate into the ladder
  // Re-measure once real layout exists (the first build happens before/at attach).
  if (window.requestAnimationFrame) {
    window.requestAnimationFrame(() => { if (relayoutLadder === relayout) relayout(); });
  }
}

// ── Node sections (roles) ───────────────────────────────────────────────────

function nodeRow(n) {
  const sum = h("summary", null, null, [
    h("span", "ip", n.ip),
    h("span", "host", (n.hostnames || []).join(", ")),
    h("span", "tags", null, (n.interfaces || []).map((i) => h("span", "tag", i))),
    h("span", "frames", fmt(n.frames)),
  ]);
  const ev = h("ul", null, null, (n.evidence || []).map((e) => h("li", null, e)));
  const pr = h("div", null, (n.protocols || []).map(([p, c]) => p + " " + fmt(c)).join("  ·  "));
  return h("details", "node", null, [sum, h("div", "detail", null, [ev, pr])]);
}

const nodeSearchCache = new WeakMap();
function nodeSearchText(n) {
  let text = nodeSearchCache.get(n);
  if (text != null) return text;
  text = [n.ip, (n.hostnames || []).join(" "), (n.roles || []).join(" "),
          (n.interfaces || []).join(" "), (n.evidence || []).join(" "),
          (n.protocols || []).map((p) => p[0]).join(" ")]
    .join(" ").toLowerCase();
  nodeSearchCache.set(n, text);
  return text;
}

// Pure: summary dict -> the section model the filter renders from.
function buildSectionModel(summary) {
  const byRole = {};
  const none = [];
  for (const n of summary.nodes) {
    if (!n.roles.length) none.push(n);
    n.roles.forEach((r) => (byRole[r] = byRole[r] || []).push(n));
  }
  const model = [];
  for (const [title, roles, cap] of SECTIONS) {
    const groups = roles.filter((r) => byRole[r]).map((r) => ({ label: r, nodes: byRole[r] }));
    for (const g of groups) g.nodes = [...g.nodes].sort((a, b) => b.frames - a.frames);
    if (groups.length) model.push({ title, groups, cap: cap || ROLE_CAP, open: true });
  }
  none.sort((a, b) => b.frames - a.frames);
  if (none.length) model.push({ title: "Unclassified", groups: [{ label: "", nodes: none }],
                                cap: UNCLASSIFIED_CAP, open: false });
  return model;
}

function filteredSections() {
  const terms = sectionQuery.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const match = (text) => terms.every((t) => text.includes(t));
  const out = [];
  for (const sec of sectionModel || []) {
    const titleHit = terms.length > 0 && match(sec.title.toLowerCase());
    const groups = [];
    for (const g of sec.groups) {
      const labelHit = terms.length > 0 && !!g.label && match(g.label.toLowerCase());
      const nodes = terms.length === 0 || titleHit || labelHit
        ? g.nodes
        : g.nodes.filter((nd) => match(nodeSearchText(nd)));
      if (nodes.length) groups.push({ label: g.label, nodes, total: g.nodes.length });
    }
    if (groups.length) out.push({ sec, groups });
  }
  return out;
}

function moreButton(remaining, cap) {
  const total = remaining.length;
  let shown = 0;
  const b = button("ghost-btn more-btn", "");
  const paint = () => {
    b.textContent = "Show " + fmt(Math.min(cap, total - shown)) + " more" + (shown ? "" : " of " + fmt(total));
  };
  paint();
  b.addEventListener("click", () => {
    const chunk = remaining.splice(0, cap);
    shown += chunk.length;
    const parent = b.parentNode;
    chunk.forEach((node) => parent.insertBefore(nodeRow(node), b));
    if (!remaining.length) b.remove();
    else paint();
  });
  return b;
}

function sectionEl(sec, groups, shownSec, totalSec) {
  const q = sectionQuery.trim();
  const d = h("details", "sec", null, [
    h("summary", null, sec.title, [
      h("span", "n", q ? fmt(shownSec) + " of " + fmt(totalSec) : "(" + fmt(totalSec) + ")"),
    ]),
  ]);
  d.open = q ? true : sec.open;
  d.addEventListener("toggle", () => { if (!sectionQuery.trim()) sec.open = d.open; });
  const bodyEl = h("div", "grp");
  for (const g of groups) {
    if (g.label) {
      bodyEl.appendChild(h("h3", null, q
        ? g.label + " (" + fmt(g.nodes.length) + " of " + fmt(g.total) + ")"
        : g.label + " (" + fmt(g.total) + ")"));
    }
    const cap = sec.cap;
    for (const node of g.nodes.slice(0, cap)) bodyEl.appendChild(nodeRow(node));
    if (g.nodes.length > cap) bodyEl.appendChild(moreButton(g.nodes.slice(cap), cap));
  }
  d.appendChild(bodyEl);
  return d;
}

// Render the current section model under the current filter.
function renderSections() {
  const filtered = filteredSections();
  const els = [];
  let shown = 0;
  for (const { sec, groups } of filtered) {
    const shownSec = groups.reduce((a, g) => a + g.nodes.length, 0);
    const totalSec = sec.groups.reduce((a, g) => a + g.nodes.length, 0);
    shown += shownSec;
    els.push(sectionEl(sec, groups, shownSec, totalSec));
  }
  const total = (sectionModel || []).reduce((a, s) => a + s.groups.reduce((b, g) => b + g.nodes.length, 0), 0);
  return { els, shown, total };
}

// ── Page rendering ──────────────────────────────────────────────────────────

function renderFile(f) {
  const item = (k, v, title) => {
    const e = h("span", null, k + " ", [h("em", null, v == null ? "-" : v)]);
    if (title) e.title = title;
    return e;
  };
  return [
    h("b", null, f.name),
    item("frames", fmt(f.frames)),
    item("start", fmtStamp(f.start), f.start || ""),
    item("end", fmtStamp(f.end), f.end || ""),
    item("duration", fmtDuration(f.duration_s)),
  ];
}

function renderChips(protocols) {
  // Each chip is a jump link: clicking it opens the ladder filtered to exactly
  // that protocol (signalling protocols open the GTPC tab, the rest the GTPU tab).
  const makeChip = ([p, c]) => {
    const chip = h("span", "chip link", p, [h("i", null, fmt(c))]);
    chip.title = p + " · " + fmt(c) + " frames — click to show only these";
    chip.dataset.proto = p;
    attrs(chip, { role: "button", tabindex: "0", "aria-pressed": "false" });
    const go = () => { if (chipHandler) chipHandler(p); };
    chip.addEventListener("click", go);
    chip.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); }
    });
    return chip;
  };
  const chips = protocols.slice(0, MAX_PROTO_CHIPS).map(makeChip);
  if (protocols.length > MAX_PROTO_CHIPS) {
    const rest = protocols.slice(MAX_PROTO_CHIPS);
    const more = button("chips-more", "+" + fmt(rest.length) + " more");
    more.title = rest.map(([p, c]) => p + " " + fmt(c)).join("\n");
    more.addEventListener("click", () => { more.replaceWith(...rest.map(makeChip)); });
    chips.push(more);
  }
  return chips;
}

function render(summary) {
  const $ = (id) => document.getElementById(id);
  chipHandler = null;  // chips are rebuilt below; the ladder re-registers the handler
  document.title = (summary.file && summary.file.name ? summary.file.name + " — " : "") + "UniPCAP";
  $("banners").replaceChildren(...summary.warnings.map((w) => h("div", "banner warn", w)));
  $("file").replaceChildren(...renderFile(summary.file));
  $("file").hidden = false;
  $("chips").replaceChildren(...renderChips(summary.protocols || []));
  renderLadder(summary.ladder, summary.overview || null);
  sectionModel = buildSectionModel(summary);
  sectionQuery = "";
  if (secFilterEl) secFilterEl.value = "";
  const res = renderSections();
  $("sections").replaceChildren(...res.els);
  updateSecTools(res.shown, res.total);
  $("empty").hidden = summary.nodes.length > 0;
  if (!$("empty").hidden) showEmpty("no-nodes");
}

function showEmpty(kind) {
  const el = document.getElementById("empty");
  if (!el) return;
  el.replaceChildren();
  const add = (tag, cls, text, kids) => el.appendChild(h(tag, cls, text, kids));
  if (kind === "no-nodes") {
    add("p", "empty-title", "No nodes identified");
    add("p", null, "The capture was analyzed, but no network nodes could be identified from its frames.");
    add("p", "empty-types", "Try a capture that contains signalling, user-plane, or IP traffic.");
    return;
  }
  if (kind === "error") {
    add("p", "empty-title", "Couldn't analyze that file");
    add("p", null, "See the banner above for details, then try another capture.");
  } else {
    add("p", "empty-title", "No capture loaded");
    add("p", null, "Open a packet capture to see every node grouped by role, the signalling ladder, and summary metrics.");
    add("p", "empty-hint", "Drop a file anywhere · ", [
      h("kbd", null, "Ctrl"), document.createTextNode(" + "), h("kbd", null, "O"),
      document.createTextNode(" to browse"),
    ]);
    add("p", "empty-types", ".pcap · .pcapng · .cap · .gz");
  }
  const open = button("ghost-btn strong", "Open a capture");
  open.dataset.action = "open";
  el.appendChild(open);
}

function showError(msg) {
  const $ = (id) => document.getElementById(id);
  $("banners").replaceChildren(h("div", "banner err", msg));
  $("file").replaceChildren();
  $("file").hidden = true;
  $("chips").replaceChildren();
  const ladder = $("ladder");
  ladder.replaceChildren();
  ladder.hidden = true;
  relayoutLadder = null;
  chipHandler = null;
  protoFilter = null;
  closeLadderSelection = null;
  clearLadderFocusHook = null;
  clearLadderFilterHook = null;
  clearProtoFilterHook = null;
  $("sections").replaceChildren();
  sectionModel = [];
  sectionQuery = "";
  if (secFilterEl) secFilterEl.value = "";
  updateSecTools(0, 0);
  $("empty").hidden = false;
  showEmpty("error");
  document.title = "UniPCAP";
  const status = document.getElementById("status");
  if (status) status.replaceChildren();
}

// ── Loading ─────────────────────────────────────────────────────────────────

let runSeq = 0;
let runController = null;

async function analyzeFile(file) {
  const seq = ++runSeq;
  if (runController) runController.abort();
  runController = new AbortController();
  const btn = document.getElementById("open");
  const status = document.getElementById("status");
  const main = document.getElementById("main");
  btn.disabled = true;
  if (main) main.setAttribute("aria-busy", "true");
  status.replaceChildren(h("span", "spinner"),
    document.createTextNode("Analyzing " + file.name + "… large captures can take minutes"));
  const started = window.performance && performance.now ? performance.now() : Date.now();
  try {
    const r = await fetch("analyze", {
      method: "POST",
      body: file,
      headers: { "X-Filename": encodeURIComponent(file.name) },
      signal: runController.signal,
    });
    if (seq !== runSeq) return;
    if (!r.ok) throw new Error("The local server returned " + r.status + " " + (r.statusText || ""));
    const d = await r.json();
    if (seq !== runSeq) return;
    if (d.ok) {
      render(d.summary);
      const elapsed = (window.performance && performance.now ? performance.now() : Date.now()) - started;
      status.replaceChildren(document.createTextNode(
        "Loaded " + d.summary.file.name + " in " + (elapsed / 1000).toFixed(1) + " s"));
      const keep = status.firstChild;
      window.setTimeout(() => {
        const s = document.getElementById("status");
        if (s && s.firstChild === keep) s.replaceChildren();
      }, 8000);
    } else {
      showError(d.error);
    }
  } catch (e) {
    if (seq !== runSeq || (e && e.name === "AbortError")) return;
    showError((e && e.message) ? e.message : String(e));
  } finally {
    if (seq === runSeq) {
      btn.disabled = false;
      if (main) main.removeAttribute("aria-busy");
    }
  }
}

// ── Wiring ──────────────────────────────────────────────────────────────────

const picker = document.getElementById("picker");
const secFilterEl = document.getElementById("sec-filter");

document.getElementById("open").addEventListener("click", () => picker.click());
picker.addEventListener("change", () => {
  const f = picker.files[0];
  picker.value = "";
  if (f) analyzeFile(f);
});

function updateSecTools(shown, total) {
  const tools = document.getElementById("sec-tools");
  const count = document.getElementById("sec-count");
  const clear = document.getElementById("sec-clear");
  const empty = document.getElementById("sec-empty");
  const q = sectionQuery.trim();
  if (tools) tools.hidden = total === 0;
  if (clear) clear.hidden = !q;
  if (count) count.textContent = total === 0 ? "" : q ? fmt(shown) + " of " + fmt(total) + " nodes" : fmt(total) + " nodes";
  if (empty) {
    empty.hidden = !(q && shown === 0);
    if (!empty.hidden) empty.textContent = "No nodes match “" + q + "”.";
  }
}

function applySectionFilter() {
  const res = renderSections();
  document.getElementById("sections").replaceChildren(...res.els);
  updateSecTools(res.shown, res.total);
}

function clearSectionFilter() {
  sectionQuery = "";
  if (secFilterEl) secFilterEl.value = "";
  applySectionFilter();
}

if (secFilterEl) {
  secFilterEl.addEventListener("input", () => {
    sectionQuery = secFilterEl.value;
    applySectionFilter();
  });
}
const secClear = document.getElementById("sec-clear");
if (secClear) secClear.addEventListener("click", () => { clearSectionFilter(); secFilterEl.focus(); });

// Drag and drop capture files anywhere on the window. A plain depth counter can
// leave the overlay stuck open (dragleave is not guaranteed when the drag leaves
// the window), so definitive exits reset it immediately and ambiguous ones are
// re-checked on the next dragenter/dragover tick.
const dropzone = document.getElementById("dropzone");
let dragDepth = 0;
let dragHideTimer = 0;

function cancelDragHide() {
  if (dragHideTimer) { clearTimeout(dragHideTimer); dragHideTimer = 0; }
}
function showDrop(on) {
  cancelDragHide();
  if (dropzone) dropzone.hidden = !on;
}
function resetDrag() {
  dragDepth = 0;
  showDrop(false);
}
function hideDropSoon() {
  cancelDragHide();
  dragHideTimer = setTimeout(resetDrag, 180);
}
function hasFiles(dt) {
  if (!dt || !dt.types) return false;
  if (typeof dt.types.contains === "function") return dt.types.contains("Files");
  return Array.prototype.indexOf.call(dt.types, "Files") !== -1;
}
function insidePage(node) {
  return !!(node && node.nodeType === 1 && document.documentElement.contains(node));
}

window.addEventListener("dragenter", (e) => {
  if (!hasFiles(e.dataTransfer)) return;
  e.preventDefault();
  dragDepth += 1;
  showDrop(true);
});
window.addEventListener("dragover", (e) => {
  if (!hasFiles(e.dataTransfer)) return;
  e.preventDefault();
  cancelDragHide(); // still over the page: never hide mid-drag
  if (dropzone && dropzone.hidden) showDrop(true);
  if (e.dataTransfer) {
    try { e.dataTransfer.dropEffect = "copy"; } catch (_) { /* some browsers refuse */ }
  }
});
window.addEventListener("dragleave", (e) => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (!insidePage(e.relatedTarget)) resetDrag();      // pointer really left the page
  else if (dragDepth === 0) hideDropSoon();           // transient imbalance, re-checked by dragover
});
window.addEventListener("dragend", resetDrag);
window.addEventListener("blur", resetDrag);
window.addEventListener("drop", (e) => {
  e.preventDefault();
  resetDrag();
  const files = e.dataTransfer && e.dataTransfer.files;
  if (files && files.length) analyzeFile(files[0]);
});

// Keyboard shortcuts: Ctrl/Cmd+O opens, "/" focuses the filter, Escape backs out.
function handleEscape() {
  const dz = document.getElementById("dropzone");
  if (dz && !dz.hidden) { resetDrag(); return; }
  const active = document.activeElement;
  if (active && active.classList && active.classList.contains("ladder-input")) {
    if (active.value && clearLadderFilterHook) clearLadderFilterHook();
    active.blur();
    return;
  }
  if (active === secFilterEl) {
    if (secFilterEl.value) clearSectionFilter();
    secFilterEl.blur();
    return;
  }
  if (closeLadderSelection && closeLadderSelection()) return;
  if (clearLadderFocusHook && clearLadderFocusHook()) return;
  if (clearProtoFilterHook && clearProtoFilterHook()) return;
  if (secFilterEl && secFilterEl.value) { clearSectionFilter(); return; }
  if (clearLadderFilterHook && clearLadderFilterHook()) return;
}

document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && !e.shiftKey && !e.altKey && (e.key === "o" || e.key === "O")) {
    e.preventDefault();
    picker.click();
    return;
  }
  if (e.key === "Escape") { handleEscape(); return; }
  const active = document.activeElement;
  const typing = !!active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA"
    || active.tagName === "SELECT" || active.isContentEditable);
  if (e.key === "/" && !typing && !mod) {
    const ladder = document.getElementById("ladder");
    const ladderInput = document.querySelector(".ladder-input");
    let target = null;
    if (ladder && !ladder.hidden && ladderInput && !ladderInput.closest("[hidden]")) target = ladderInput;
    else if (secFilterEl && !secFilterEl.closest("[hidden]")) target = secFilterEl;
    if (target) {
      e.preventDefault();
      target.focus();
      if (target.select) target.select();
    }
  }
});

document.getElementById("empty").addEventListener("click", (e) => {
  const t = e.target;
  if (t && t.closest && t.closest("[data-action='open']")) picker.click();
});

// Keep the ladder's virtual window in step with the viewport size.
window.addEventListener("resize", () => {
  if (!relayoutLadder) return;
  if (window.requestAnimationFrame) window.requestAnimationFrame(() => { if (relayoutLadder) relayoutLadder(); });
  else setTimeout(() => { if (relayoutLadder) relayoutLadder(); }, 100);
});

// Holds the local server open while this page is open; it exits `grace` seconds
// after the last page closes. Close it on pagehide so the server exits promptly.
const events = new EventSource("events");
events.onerror = () => {
  const banners = document.getElementById("banners");
  if (!banners || banners.querySelector(".banner.lost")) return;
  banners.appendChild(h("div", "banner warn lost",
    "Lost the connection to the UniPCAP server — restart UniPCAP and reload this page."));
};
events.onopen = () => {
  const lost = document.querySelector(".banner.lost");
  if (lost) lost.remove();
};
window.addEventListener("pagehide", () => {
  try { events.close(); } catch (_) { /* already closed */ }
});
