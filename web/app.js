"use strict";
// Core console controller: SSE → state mirror → views. Renders are throttled to
// the server's ~2 Hz delta cadence; the Geo view manages its own canvas.

const STATE = {
  mode: "starting", msg: "", home: null, online: false, view: "overview",
  flows: new Map(), devices: new Map(), names: new Map(), geo: new Map(),
  packets: [], http: [], alerts: [], stats: {},
  selected: null, flowFilter: "", dnsFilter: "",
};
const FLOW_CAP = 1500, PKT_CAP = 600, LOG_CAP = 300;
let pendingRender = false;

// ---- state merge ----
function mergeNames(arr) {
  for (const n of arr || []) STATE.names.set(n.ip, { name: n.name, src: n.src, cat: n.cat || "" });
}
function mergeGeo(arr) {
  for (const g of arr || []) {
    STATE.geo.set(g.ip, g);
    const n = STATE.names.get(g.ip);
    GeoView.addDest(g, n ? n.cat : "");
  }
}
function mergeFlows(arr) {
  for (const f of arr || []) STATE.flows.set(f.key, f);
  if (STATE.flows.size > FLOW_CAP) {
    const old = [...STATE.flows.values()].sort((a, b) => a.last - b.last).slice(0, STATE.flows.size - FLOW_CAP);
    for (const f of old) STATE.flows.delete(f.key);
  }
}
function mergeDevices(arr) { for (const d of arr || []) STATE.devices.set(d.ip, d); }
function pushCapped(target, arr, cap) {
  if (arr && arr.length) { target.push(...arr); if (target.length > cap) target.splice(0, target.length - cap); }
}

function applySnapshot(s) {
  STATE.flows.clear(); STATE.devices.clear(); STATE.names.clear(); STATE.geo.clear();
  STATE.packets = []; STATE.http = []; STATE.alerts = [];
  mergeNames(s.names); mergeFlows(s.flows); mergeDevices(s.devices);
  pushCapped(STATE.packets, s.packets, PKT_CAP);
  pushCapped(STATE.http, s.http, LOG_CAP);
  pushCapped(STATE.alerts, s.alerts, LOG_CAP);
  mergeGeo(s.geo);
  STATE.stats = s.stats || {};
  pendingRender = true;
}
function applyDelta(d) {
  mergeNames(d.names); mergeFlows(d.flows); mergeDevices(d.devices);
  pushCapped(STATE.packets, d.packets, PKT_CAP);
  pushCapped(STATE.http, d.http, LOG_CAP);
  pushCapped(STATE.alerts, d.alerts, LOG_CAP);
  mergeGeo(d.geo);
  if (d.stats) STATE.stats = d.stats;
  pendingRender = true;
}
function applyMeta(m) {
  STATE.mode = m.mode; STATE.msg = m.msg || "";
  STATE.online = ["live", "replay"].includes(m.mode);
  if (m.home) { STATE.home = m.home; GeoView.setHome(m.home); }
  if (m.mode === "error") { STATE.devices.clear(); STATE.flows.clear(); pendingRender = true; }
  updateBadge();
}

// ---- header ----
function updateBadge() {
  const map = { live: ["LIVE", "live"], replay: ["REPLAY", "demo"],
    error: ["CAPTURE ERROR", "error"], offline: ["OFFLINE", "off"], starting: ["CONNECTING", "off"] };
  const [text, cls] = map[STATE.mode] || ["?", "off"];
  const b = document.getElementById("mode-badge");
  b.textContent = "● " + text; b.className = "mode " + cls;
  document.getElementById("mode-msg").textContent = STATE.msg || "";
}
function updateHeader() {
  const st = STATE.stats || {};
  setText("s-devices", st.devices || 0);
  setText("s-flows", st.flows || 0);
  setText("s-domains", st.domains || 0);
  setText("s-alerts", st.alerts || 0);
  const s = st.bw_global || [];
  const last = s.length ? s[s.length - 1] : [0, 0, 0];
  setText("s-rate", fmtRate((last[1] || 0) + (last[2] || 0)));
}
function setText(id, v) { const e = document.getElementById(id); if (e) e.textContent = v; }

// ---- routing / render ----
function setView(v) {
  STATE.view = v;
  for (const btn of document.querySelectorAll("#rail button"))
    btn.classList.toggle("active", btn.dataset.view === v);
  renderView(true);
}
function renderView(force) {
  const root = document.getElementById("view");
  if (STATE.view === "geo") {
    GeoView.mount(root);
    GeoView.syncAll([...STATE.geo.values()], STATE.names);  // back-fill prior dests
    return;
  }
  // Don't yank focus from a filter box mid-type unless forced (view switch).
  const ae = document.activeElement;
  if (!force && ae && ae.tagName === "INPUT" && root.contains(ae)) return;
  const fn = VIEWS[STATE.view];
  if (fn) fn(root, STATE);
}
function periodicRender() {
  updateHeader();
  if (pendingRender && STATE.view !== "geo") { renderView(false); pendingRender = false; }
}

// ---- packet inspector modal ----
async function openPacket(ds) {
  const modal = document.getElementById("modal");
  const body = document.getElementById("modal-body");
  document.getElementById("modal-title").textContent =
    `${ds.src || ""} → ${ds.dst || ""}`;
  body.innerHTML = '<div class="muted">Dissecting…</div>';
  modal.hidden = false;
  try {
    const q = new URLSearchParams({ ts: ds.ts, src: ds.src, dst: ds.dst, sport: ds.sport || "" });
    const r = await fetch("/api/packet?" + q.toString());
    if (!r.ok) { body.innerHTML = '<div class="muted">Frame not found in the recording (it may have rotated out).</div>'; return; }
    const obj = await r.json();
    body.innerHTML = renderPacketDetail(obj);
  } catch (e) {
    body.innerHTML = '<div class="muted">Could not load packet.</div>';
  }
}
function closeModal() { document.getElementById("modal").hidden = true; }

function renderPacketDetail(obj) {
  const layers = obj && obj._source && obj._source.layers ? obj._source.layers : obj;
  let hexHtml = "";
  const raw = layers.frame_raw;
  if (raw && raw[0]) hexHtml = `<div class="hexdump">${hexDump(raw[0])}</div>`;
  const tree = treeNode(layers, 0);
  return `<div class="pkt-detail"><div class="pkt-tree">${tree}</div>${hexHtml}</div>`;
}
function treeNode(node, depth) {
  if (node == null) return "";
  if (typeof node !== "object") return `<span class="v">${esc(node)}</span>`;
  let html = "";
  for (const k of Object.keys(node)) {
    if (k.endsWith("_raw")) continue;
    const v = node[k];
    if (Array.isArray(v)) {
      html += `<div class="tnode" style="padding-left:${depth * 12}px"><span class="k">${esc(k)}</span><span class="v">${esc(v.join(" "))}</span></div>`;
    } else if (v && typeof v === "object") {
      html += `<div class="tnode grp" style="padding-left:${depth * 12}px"><span class="k">${esc(k)}</span></div>` + treeNode(v, depth + 1);
    } else {
      html += `<div class="tnode" style="padding-left:${depth * 12}px"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`;
    }
  }
  return html;
}
function hexDump(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
  let out = "";
  for (let off = 0; off < bytes.length; off += 16) {
    const slice = bytes.slice(off, off + 16);
    const h = slice.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const a = slice.map((b) => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
    out += `<div><span class="off">${off.toString(16).padStart(4, "0")}</span> <span class="hx">${h}</span> <span class="as">${esc(a)}</span></div>`;
  }
  return out;
}

// ---- selection ----
function selectDevice(ip) {
  STATE.selected = (STATE.selected === ip) ? null : ip;
  setText("sel-foot", STATE.selected ? "▼ " + STATE.selected : "");
  renderView(true);
}

// ---- events ----
function wireEvents() {
  document.getElementById("rail").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-view]");
    if (btn) setView(btn.dataset.view);
  });
  const view = document.getElementById("view");
  view.addEventListener("click", (e) => {
    const pkt = e.target.closest(".pkt");
    if (pkt) return openPacket(pkt.dataset);
    if (e.target.closest("[data-clear]")) { STATE.selected = null; setText("sel-foot", ""); return renderView(true); }
    const ipEl = e.target.closest("[data-ip]");
    if (ipEl) return selectDevice(ipEl.dataset.ip);
  });
  view.addEventListener("input", (e) => {
    if (e.target.id === "flow-filter") { STATE.flowFilter = e.target.value; renderView(false); refocus("flow-filter"); }
    if (e.target.id === "dns-filter") { STATE.dnsFilter = e.target.value; renderView(false); refocus("dns-filter"); }
  });
  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.getElementById("modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
}
function refocus(id) {
  const el = document.getElementById(id);
  if (el) { el.focus(); const v = el.value; el.value = ""; el.value = v; }
}

// ---- connection ----
function connect() {
  const es = new EventSource("/stream");
  es.onmessage = (m) => {
    let ev; try { ev = JSON.parse(m.data); } catch (e) { return; }
    if (ev.type === "meta") applyMeta(ev);
    else if (ev.type === "snapshot") applySnapshot(ev);
    else if (ev.type === "delta") applyDelta(ev);
    else if (ev.type === "tick") { STATE.stats = ev.stats || STATE.stats; }
  };
  es.onerror = () => { STATE.mode = "offline"; STATE.online = false; updateBadge(); };
}
async function bootstrap() {
  try {
    const r = await fetch("/api/snapshot");
    if (r.ok) applySnapshot(await r.json());
  } catch (e) {}
  connect();
}

setInterval(() => {
  document.getElementById("clock").textContent = new Date().toTimeString().slice(0, 8);
}, 1000);
setInterval(periodicRender, 500);

window._loadGlobe(function () {
  wireEvents();
  setView("overview");
  bootstrap();
});
