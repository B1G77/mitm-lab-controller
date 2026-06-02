"use strict";

const CAT_COLOR = {
  auth: "#ff4d6d", tracking: "#ffd166", media: "#00ff95",
  cdn: "#8ea0bd", other: "#38bdf8",
};
const STALE_MS = 90000;
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const state = {
  domains: new Set(), countries: new Set(), authCount: 0,
  devices: new Map(),   // ip -> {os, apps:Set, logins:Set, domains:Set, last, lastMs}
  meta: new Map(),      // "ip|kind|domain" -> {ip,kind,domain,cat,hits,ts,lastMs,loc}
  arcs: [], rings: [], points: [], labels: [],
  online: false, selected: null,
};
let globe = null;
let home = { lat: 38.7223, lon: -9.1393, label: "ROGUE AP" };
let flewHome = false;

// ---- Globe ----
function initGlobe() {
  const el = document.getElementById("globe");
  if (typeof Globe === "undefined") {
    el.innerHTML = '<div class="globe-missing">3D globe library not loaded.<br>' +
      'Run <code>bash web/fetch_libs.sh</code> once while online.</div>';
    return;
  }
  globe = Globe()(el);
  const cfg = {
    backgroundColor: "rgba(0,0,0,0)", showGlobe: true, showAtmosphere: true,
    atmosphereColor: "#00ff95", atmosphereAltitude: 0.2,
    globeImageUrl: "static/earth-night.jpg",
    arcColor: "color", arcStroke: 0.55, arcDashLength: 0.4, arcDashGap: 0.18,
    arcDashAnimateTime: REDUCED ? 0 : 1500, arcAltitudeAutoScale: 0.45,
    arcsTransitionDuration: 0,
    ringColor: (r) => r.color, ringMaxRadius: 4,
    ringPropagationSpeed: 2.5, ringRepeatPeriod: REDUCED ? 0 : 650,
    pointsData: [], pointColor: "color", pointAltitude: 0.012,
    pointRadius: (d) => d.r, pointsMerge: false,
    labelsData: [], labelLat: "lat", labelLng: "lng", labelText: "text",
    labelColor: (d) => d.color, labelSize: 0.85, labelDotRadius: 0.28, labelResolution: 2,
  };
  for (const k in cfg) { try { if (typeof globe[k] === "function") globe[k](cfg[k]); } catch (e) {} }
  try {
    const m = globe.globeMaterial();
    m.color = new THREE.Color("#0a1a16");
    m.emissive = new THREE.Color("#02140e"); m.emissiveIntensity = 0.4;
  } catch (e) {}
  try {
    globe.controls().autoRotate = !REDUCED;
    globe.controls().autoRotateSpeed = 0.5;
  } catch (e) {}

  const fit = () => { if (el.clientWidth && el.clientHeight) globe.width(el.clientWidth).height(el.clientHeight); };
  fit(); setTimeout(fit, 80); setTimeout(() => { fit(); flyHome(); }, 400);
  if (window.ResizeObserver) new ResizeObserver(fit).observe(el);
  window.addEventListener("resize", fit);
  setHomeMarker();
}

function flyHome() {
  if (globe && !flewHome) { globe.pointOfView({ lat: home.lat, lng: home.lon, altitude: 2.3 }, 1200); flewHome = true; }
}
function clearGeo() { state.arcs = []; state.rings = []; if (globe) { globe.arcsData([]); globe.ringsData([]); } }

function setHomeMarker() {
  if (!globe) return;
  state.points = state.points.filter((p) => !p.home);
  state.points.unshift({ lat: home.lat, lng: home.lon, color: "#00ff95", r: 0.95, home: true });
  state.labels = state.labels.filter((l) => !l.home);
  state.labels.unshift({ lat: home.lat, lng: home.lon, text: home.label || "AP", color: "#00ff95", home: true });
  globe.pointsData(state.points.slice()).labelsData(state.labels.slice());
}

function pushGeo(ev) {
  if (!globe || ev.lat == null) return;
  const color = CAT_COLOR[ev.category] || CAT_COLOR.other;
  state.arcs.push({ startLat: home.lat, startLng: home.lon, endLat: ev.lat, endLng: ev.lon, color });
  if (state.arcs.length > 36) state.arcs.shift();
  globe.arcsData(state.arcs.slice());
  state.rings.push({ lat: ev.lat, lng: ev.lon, color });
  if (state.rings.length > 26) state.rings.shift();
  globe.ringsData(state.rings.slice());
  const key = ev.lat.toFixed(1) + "," + ev.lon.toFixed(1);
  if (!state.points.some((p) => !p.home && p.key === key)) {
    state.points.push({ lat: ev.lat, lng: ev.lon, color, r: 0.45, key });
    const txt = ev.city || ev.country || "";
    if (txt) state.labels.push({ lat: ev.lat, lng: ev.lon, text: txt, color: "#cfe3ff", key });
    if (state.points.length > 80) state.points.splice(1, 1);
    if (state.labels.length > 60) state.labels.splice(1, 1);
    globe.pointsData(state.points.slice()).labelsData(state.labels.slice());
  }
}

// ---- Live metadata table (deduped, with hit counts) ----
function upsertMeta(ev) {
  const key = `${ev.src}|${ev.kind}|${ev.domain}`;
  let m = state.meta.get(key);
  if (m) { m.hits++; m.ts = ev.ts; m.lastMs = Date.now(); }
  else {
    m = { ip: ev.src, kind: ev.kind, domain: ev.domain, cat: ev.category,
          hits: 1, ts: ev.ts, lastMs: Date.now(),
          loc: ev.country ? ev.country : "" };
    state.meta.set(key, m);
  }
  renderMeta();
}

function renderMeta() {
  const wrap = document.getElementById("meta-rows");
  let rows = [...state.meta.values()];
  if (state.selected) rows = rows.filter((r) => r.ip === state.selected);
  rows.sort((a, b) => b.lastMs - a.lastMs);
  rows = rows.slice(0, 80);
  if (!rows.length) { wrap.innerHTML = '<div class="empty">No metadata yet.</div>'; return; }
  wrap.innerHTML = rows.map((r) =>
    `<div class="row ${r.cat}"><span class="t">${r.ts}</span>` +
    `<span class="k">${r.kind}</span><span class="cat">${r.cat}</span>` +
    `<span class="hits">${r.hits}</span>` +
    `<span class="dom" title="${r.domain}">${r.domain}</span>` +
    `<span class="loc">${r.loc}</span></div>`).join("");
}

// ---- Devices ----
function updateDevice(ev) {
  if (!ev.src || ev.src === "?") return;
  let d = state.devices.get(ev.src);
  if (!d) { d = { os: "", apps: new Set(), logins: new Set(), domains: new Set() }; state.devices.set(ev.src, d); }
  if (!d.os && ev.os) d.os = ev.os;
  (ev.apps || []).forEach((a) => d.apps.add(a));
  d.domains.add(ev.domain);
  if (ev.category === "auth") d.logins.add(ev.domain);
  d.last = ev.ts; d.lastMs = Date.now();
  renderDevices();
}

function renderDevices() {
  const wrap = document.getElementById("device-list");
  if (!state.devices.size) { wrap.innerHTML = '<div class="empty">No devices observed yet.</div>'; return; }
  const now = Date.now();
  wrap.innerHTML = "";
  for (const [ip, d] of state.devices) {
    const stale = !state.online || (now - (d.lastMs || 0) > STALE_MS);
    const el = document.createElement("div");
    el.className = "device" + (stale ? " stale" : "") + (state.selected === ip ? " sel" : "");
    el.tabIndex = 0;
    el.setAttribute("role", "button");
    const apps = [...d.apps].map((a) => `<span class="tag">${a}</span>`).join("");
    const logins = [...d.logins].map((l) => `<span class="tag login">↪ ${l}</span>`).join("");
    el.innerHTML =
      `<div class="d-top"><span class="ip">${ip}</span><span class="os">${d.os || "unknown OS"}</span></div>` +
      `<div class="apps">${apps || '<span class="os">no apps yet</span>'}${logins}</div>` +
      `<div class="meta">${d.domains.size} domains · last ${d.last || "—"}</div>`;
    const toggle = () => selectDevice(state.selected === ip ? null : ip);
    el.addEventListener("click", toggle);
    el.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    wrap.appendChild(el);
  }
}

function selectDevice(ip) {
  state.selected = ip;
  const tag = document.getElementById("filter-tag");
  if (ip) { tag.hidden = false; tag.textContent = "▼ " + ip + "  ✕"; tag.onclick = () => selectDevice(null); }
  else { tag.hidden = true; }
  renderDevices(); renderMeta();
}

function updateStats() {
  document.getElementById("s-domains").textContent = state.domains.size;
  document.getElementById("s-devices").textContent = state.devices.size;
  document.getElementById("s-auth").textContent = state.authCount;
  document.getElementById("s-countries").textContent = state.countries.size;
}

// ---- Mode badge ----
function applyMode(mode, msg) {
  const badge = document.getElementById("mode-badge");
  const map = { live: ["LIVE", "live"], demo: ["DEMO", "demo"], replay: ["REPLAY", "demo"],
    error: ["CAPTURE ERROR", "error"], offline: ["OFFLINE", "off"], starting: ["CONNECTING", "off"] };
  const [text, cls] = map[mode] || ["?", "off"];
  badge.textContent = "● " + text; badge.className = "mode " + cls;
  document.getElementById("mode-msg").textContent = msg || "";
  const hint = document.getElementById("dev-hint");
  hint.textContent = mode === "demo" ? "(synthetic)" : (mode === "error" || mode === "offline") ? "(stale)" : "";
  state.online = (mode === "live" || mode === "replay" || mode === "demo");
}

// ---- Events ----
function handle(ev) {
  if (ev._meta) {
    if (ev.home) { home = ev.home; setHomeMarker(); flyHome(); }
    applyMode(ev.mode, ev.msg);
    if (ev.mode === "error") { state.devices.clear(); renderDevices(); clearGeo(); }
    return;
  }
  state.domains.add(ev.domain);
  if (ev.country) state.countries.add(ev.country);
  if (ev.category === "auth") state.authCount++;
  pushGeo(ev); upsertMeta(ev); updateDevice(ev); updateStats();
}

function connect() {
  const es = new EventSource("/stream");
  es.onmessage = (m) => { try { handle(JSON.parse(m.data)); } catch (e) {} };
  es.onerror = () => { applyMode("offline", "server unreachable"); renderDevices(); };
}

setInterval(() => {
  document.getElementById("clock").textContent = new Date().toTimeString().slice(0, 8);
  if (state.devices.size) renderDevices();
}, 1000);

window._loadGlobe(function () { initGlobe(); connect(); });
