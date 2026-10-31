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

// Build DOM with textContent only: capture data is untrusted.
function h(tag, cls, text, kids) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  (kids || []).forEach((k) => e.appendChild(k));
  return e;
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

const pct = (x) => (x == null ? "—" : x.toFixed(1) + " %");
const quota = (x) => (x ? humanBytes(x) : "—"); // absent quota renders "—", never 0 (spec §4)

// Overview tab: metric cards built with textContent only — capture data is untrusted.
function renderOverview(ov) {
  const row = (k, v) => h("div", "ov-row", null, [h("span", null, k), h("span", null, v)]);
  const card = (title, rows, kids) => h("div", "ov-card", null,
    [h("h3", null, title), ...rows.map(([k, v]) => row(k, v)), ...(kids || [])]);
  const empty = () => h("div", "ov-empty", "—");
  const table = (heads, rows) => rows.length
    ? h("table", "ov-table", null, [
        h("thead", null, null, [h("tr", null, null, heads.map((c) => h("th", null, c)))]),
        h("tbody", null, null, rows.map((r) => h("tr", null, null, r.map((c) => h("td", null, c))))),
      ])
    : empty();

  const d = ov.dns, g = ov.gtpu, gx = ov.gx, gy = ov.gy, sub = ov.subscribers;
  const ids = (pairs) => pairs.map(([v, n]) => (n > 1 ? v + " ×" + n : v)).join(", ") || "—";
  const negRows = Object.entries(ov.negative)
    .flatMap(([proto, codes]) => codes.map(([code, n]) => [proto + " " + code, fmt(n)]));
  const lossRows = g.loss.map((l) => [`${l.src} → ${l.dst}`, fmt(l.received), fmt(l.missing), pct(l.pct)]);
  return h("div", "overview", null, [h("div", "ov-cards", null, [
    card("Subscribers", [
      ["IMSI", ids(sub.imsi)],
      ["MSISDN", ids(sub.msisdn)],
    ]),
    card("DNS", [
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

function renderLadder(ld, ov) {
  const el = document.getElementById("ladder");
  ladderFocus = -1;
  if (ld && !ld.messages.length && !ld.bursts.length) ld = null; // an empty ladder counts as absent
  el.hidden = !ld && !ov;
  el.replaceChildren();
  if (el.hidden) return;
  ld = ld || { messages: [], bursts: [], nodes: [], pairs: [] };

  const rows = [];
  ld.messages.forEach((m, i) => rows.push({ t: m.t, kind: "msg", i, m }));
  ld.bursts.forEach((b) => rows.push({ t: b.t0, kind: "burst", b }));
  rows.sort((a, b) => a.t - b.t);
  const t0 = rows.length ? rows[0].t : 0;
  const msgRows = rows.filter((r) => r.kind === "msg");
  const burstRows = rows.filter((r) => r.kind === "burst");
  let tab = ov ? "overview" : msgRows.length ? "gtpc" : burstRows.length ? "gtpu" : "gtpc";
  const tabEls = [["overview", "Overview", null], ["gtpc", "GTPC", msgRows.length],
                  ["gtpu", "GTPU", burstRows.length]]
    .map(([id, label, count]) => {
      const b = h("button", "ladder-tab", count == null ? label : label + " (" + count + ")");
      b.classList.toggle("on", tab === id);
      b.addEventListener("click", () => {
        if (tab === id) return;
        tab = id;
        sel = -1;               // sel/detail resolve at click time, after renderLadder sets them up
        detail.replaceChildren();
        detail.hidden = true;
        tabEls.forEach((t) => t.classList.toggle("on", t === b));
        buildBody();
      });
      return b;
    });
  const tabs = h("div", "ladder-tabs", null, tabEls);
  const n = ld.nodes.length;
  const x = (i) => i * LADDER_COL + LADDER_COL / 2;
  const pairOf = (i) => (ld.pairs || []).find(([a, b]) => a === i || b === i);
  const protoColor = (p) => LADDER_COLORS[p] || LADDER_BURST;

  // sticky node header boxes + lifelines
  const head = h("div", "ladder-head");
  const boxes = [];
  ld.nodes.forEach((node, i) => {
    const box = h("div", "ladder-node", null, [
      h("div", "nm", node.name),
      h("div", "tp", node.type),
    ]);
    box.style.left = x(i) - 70 + "px";
    box.title = [node.name, node.type, node.ip].filter(Boolean).join("\n");
    box.addEventListener("click", () => {
      ladderFocus = ladderFocus === i ? -1 : i;
      boxes.forEach((b, j) => b.classList.toggle("focus", j === ladderFocus));
      buildBody();
    });
    boxes.push(box);
    head.appendChild(box);
  });

  const stick = h("div", "ladder-stick", null, [tabs, head]);

  const body = h("div", "ladder-body");
  body.style.width = n * LADDER_COL + LADDER_TIME_W + "px";
  const lines = h("div", "ladder-lines", null,
    ld.nodes.map((_, i) => {
      const l = h("div", "ladder-line");
      l.style.left = x(i) - 1.5 + "px";
      return l;
    }));
  const layer = h("div", "ladder-rows");
  const detail = h("div", "ladder-detail");
  detail.hidden = true;
  body.appendChild(lines);
  body.appendChild(layer);

  let sel = -1;
  const rowEls = []; // message index -> row element, for pair highlighting

  function arrow(parent, x1, x2, color, thin) {
    const line = h("div", "ladder-arrow" + (thin ? " thin" : ""));
    line.style.left = Math.min(x1, x2) + "px";
    line.style.width = Math.abs(x2 - x1) + "px";
    line.style.background = color;
    const tri = h("div", "ladder-headtri" + (thin ? " thin" : "") + (x2 > x1 ? " r" : " l"));
    tri.style.left = (x2 > x1 ? x2 - 8 : x2) + "px";
    tri.style[x2 > x1 ? "borderLeftColor" : "borderRightColor"] = color;
    parent.appendChild(line);
    parent.appendChild(tri);
  }

  function visible(r) {
    return ladderFocus < 0
      || (r.kind === "msg" && (r.m.src === ladderFocus || r.m.dst === ladderFocus))
      || (r.kind === "burst" && (r.b.src === ladderFocus || r.b.dst === ladderFocus));
  }

  function showDetail(m) {
    const srcN = ld.nodes[m.src], dstN = ld.nodes[m.dst];
    const kv = (k, v) => h("div", "ld-row", null, [h("span", "ld-k", k), h("span", "ld-v", v)]);
    const fallback = m.name.includes("retransmission")
      ? "Retransmitted chunk — decode not collected"
      : "Decode omitted (size budget)";
    detail.hidden = false;
    detail.replaceChildren(
      kv("Message Name", m.name),
      kv("Time Stamp", fmtTime(m.t, t0)),
      kv("Link", srcN.name + " → " + dstN.name),
      kv("IP SRC", srcN.ip),
      kv("IP DST", dstN.ip),
      h("pre", "ld-pre", m.decode || fallback)
    );
  }

  function buildBody() {
    if (tab === "overview") {
      head.hidden = true;
      body.hidden = true;
      detail.hidden = true;
      if (ovEl) ovEl.hidden = false;
      return;
    }
    head.hidden = false;
    body.hidden = false;
    if (ovEl) ovEl.hidden = true;
    const tabRows = tab === "gtpc" ? msgRows : burstRows;
    layer.replaceChildren();
    rowEls.length = 0;
    // keep one row's height on an empty tab so the notice stays inside the panel
    body.style.height = Math.max(tabRows.length, 1) * LADDER_ROW_H + "px";
    if (!tabRows.length) {
      layer.appendChild(h("div", "ladder-empty",
        tab === "gtpc" ? "No signalling messages in this capture." : "No data traffic in this capture."));
      return;
    }
    let selVisible = false;
    tabRows.forEach((r, ri) => {
      if (!visible(r)) return;
      const row = h("div", "ladder-row");
      row.style.top = ri * LADDER_ROW_H + "px";
      const time = h("div", "ladder-time", fmtTime(r.t, t0));
      time.style.left = n * LADDER_COL + "px";
      row.appendChild(time);
      if (r.kind === "burst") {
        const x1 = x(r.b.src), x2 = x(r.b.dst);
        arrow(row, x1, x2, LADDER_BURST, true);
        const label = h("div", "ladder-blabel",
          `${r.b.proto} ×${r.b.n} · ${humanBytes(r.b.bytes)}`);
        label.style.left = (x1 + x2) / 2 + "px";
        label.title = label.textContent;
        row.appendChild(label);
      } else {
        const m = r.m;
        const x1 = x(m.src), x2 = m.src === m.dst ? x1 + 40 : x(m.dst);
        const color = protoColor(m.proto);
        arrow(row, x1, x2, color, false);
        const label = h("div", "ladder-label", m.name);
        label.style.left = (x1 + x2) / 2 + "px";
        label.style.color = color;
        label.style.maxWidth = m.src === m.dst ? "" : "280px";
        label.title = m.name;
        row.appendChild(label);
        rowEls[r.i] = row;
        if (r.i === sel) selVisible = true;
        row.addEventListener("click", () => {
          sel = r.i;
          buildBody();
          const pair = pairOf(r.i);
          if (pair) {
            const other = pair[0] === r.i ? pair[1] : pair[0];
            if (rowEls[other]) rowEls[other].scrollIntoView({ block: "nearest", behavior: "smooth" });
          }
        });
      }
      layer.appendChild(row);
    });
    if (selVisible && ld.messages[sel]) showDetail(ld.messages[sel]);
    else { sel = -1; detail.replaceChildren(); detail.hidden = true; }
    // highlight the selected message and its paired counterpart (freshly built rows)
    if (sel >= 0) {
      if (rowEls[sel]) rowEls[sel].classList.add("sel");
      const pair = pairOf(sel);
      if (pair) {
        const other = pair[0] === sel ? pair[1] : pair[0];
        if (rowEls[other]) rowEls[other].classList.add("sel");
      }
    }
  }

  const ovEl = ov ? renderOverview(ov) : null; // built once; tab switching only toggles visibility
  if (ovEl) ovEl.hidden = tab !== "overview";
  buildBody();
  el.appendChild(stick);
  el.appendChild(body);
  el.appendChild(detail);
  if (ovEl) el.appendChild(ovEl);
}

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

function section(title, groups, cap, open) {
  const total = groups.reduce((a, g) => a + g.nodes.length, 0);
  const d = h("details", "sec", null, [h("summary", null, title, [h("span", "n", "(" + total + ")")])]);
  d.open = open;
  const body = h("div", "grp");
  for (const g of groups) {
    if (g.label) body.appendChild(h("h3", null, g.label + " (" + g.nodes.length + ")"));
    g.nodes.slice(0, cap).forEach((n) => body.appendChild(nodeRow(n)));
    if (g.nodes.length > cap) body.appendChild(h("div", "more", "+" + (g.nodes.length - cap) + " more"));
  }
  d.appendChild(body);
  return d;
}

// Pure: summary dict -> section elements.
function renderSections(summary) {
  const byRole = {};
  const none = [];
  for (const n of summary.nodes) {
    if (!n.roles.length) none.push(n);
    n.roles.forEach((r) => (byRole[r] = byRole[r] || []).push(n));
  }
  const out = [];
  for (const [title, roles, cap] of SECTIONS) {
    const groups = roles.filter((r) => byRole[r]).map((r) => ({ label: r, nodes: byRole[r] }));
    for (const g of groups) g.nodes = [...g.nodes].sort((a, b) => b.frames - a.frames);
    if (groups.length) out.push(section(title, groups, cap || ROLE_CAP, true));
  }
  none.sort((a, b) => b.frames - a.frames);
  if (none.length) out.push(section("Unclassified", [{ label: "", nodes: none }], UNCLASSIFIED_CAP, false));
  return out;
}

function renderFile(f) {
  const item = (k, v) => h("span", null, k + " ", [h("em", null, v == null ? "-" : v)]);
  return [
    h("b", null, f.name),
    item("frames", fmt(f.frames)),
    item("start", f.start),
    item("end", f.end),
    item("duration", f.duration_s == null ? null : f.duration_s + " s"),
  ];
}

function render(summary) {
  const $ = (id) => document.getElementById(id);
  $("banners").replaceChildren(...summary.warnings.map((w) => h("div", "banner warn", w)));
  $("file").replaceChildren(...renderFile(summary.file));
  $("file").hidden = false;
  $("chips").replaceChildren(
    ...summary.protocols.slice(0, 15).map(([p, c]) => h("span", "chip", p, [h("i", null, fmt(c))]))
  );
  renderLadder(summary.ladder, summary.overview || null);
  $("sections").replaceChildren(...renderSections(summary));
  $("empty").hidden = summary.nodes.length > 0;
  $("empty").textContent = "No nodes identified in this capture.";
}

function showError(msg) {
  const $ = (id) => document.getElementById(id);
  $("banners").replaceChildren(h("div", "banner err", msg));
  $("file").replaceChildren();
  $("file").hidden = true;
  $("chips").replaceChildren();
  $("ladder").replaceChildren();
  $("ladder").hidden = true;
  $("sections").replaceChildren();
  $("empty").hidden = true;
}

async function analyzeFile(file) {
  const btn = document.getElementById("open");
  const status = document.getElementById("status");
  btn.disabled = true;
  status.replaceChildren(h("span", "spinner"), document.createTextNode("Analyzing… large captures can take minutes"));
  try {
    const r = await fetch("analyze", {
      method: "POST",
      body: file,
      headers: { "X-Filename": encodeURIComponent(file.name) },
    });
    const d = await r.json();
    if (d.ok) render(d.summary);
    else showError(d.error);
  } catch (e) {
    showError(String(e));
  } finally {
    btn.disabled = false;
    status.replaceChildren();
  }
}

const picker = document.getElementById("picker");
document.getElementById("open").addEventListener("click", () => picker.click());
picker.addEventListener("change", () => {
  const f = picker.files[0];
  picker.value = "";
  if (f) analyzeFile(f);
});

// Holds the local server open while this page is open; it exits `grace` seconds after the last page closes.

// Drag and drop capture files anywhere on window
const dropzone = document.getElementById("dropzone");
let dragDepth = 0;

window.addEventListener("dragenter", (e) => {
  e.preventDefault();
  dragDepth++;
  if (dropzone) dropzone.hidden = false;
});

window.addEventListener("dragover", (e) => {
  e.preventDefault();
  if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
});

window.addEventListener("dragleave", (e) => {
  e.preventDefault();
  dragDepth--;
  if (dragDepth <= 0) {
    dragDepth = 0;
    if (dropzone) dropzone.hidden = true;
  }
});

window.addEventListener("drop", (e) => {
  e.preventDefault();
  dragDepth = 0;
  if (dropzone) dropzone.hidden = true;
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) analyzeFile(f);
});

new EventSource("events");
