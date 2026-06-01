"use strict";

// --- Category colors (match style.css) --------------------------------------
const CAT_COLOR = {
  auth: "#ff4d6d", tracking: "#ffd166", media: "#00ff95",
  cdn: "#7d8aa3", other: "#38bdf8",
};
const STALE_MS = 90000;   // a device with no traffic for this long goes dim

// --- State ------------------------------------------------------------------
const state = {
  domains: new Set(), countries: new Set(), authCount: 0,
  devices: new Map(),   // ip -> {os, apps:Set, logins:Set, domains:Set, last, lastMs}
  arcs: [], rings: [], points: [], labels: [],
  online: false,
};
let globe = null;
let home = { lat: 38.7223, lon: -9.1393, label: "ROGUE AP" };
let flewHome = false;   // only auto-frame the globe once, not on every reconnect

// --- Globe ------------------------------------------------------------------
function initGlobe() {
  const el = document.getElementById("globe");
  if (typeof Globe === "undefined") {
    el.innerHTML = '<div class="globe-missing">3D globe library not loaded.<br>' +
      'Run <code>bash web/fetch_libs.sh</code> once while online.</div>';
    return;
  }
  // Configure defensively: a CDN-fallback globe.gl of a different version may
  // be missing a method, and a fluent chain would throw and blank the globe.
  // Apply each setter independently so one missing method can't kill the rest.
  globe = Globe()(el);
  const cfg = {
    backgroundColor: "rgba(0,0,0,0)", showGlobe: true, showAtmosphere: true,
    atmosphereColor: "#00ff95", atmosphereAltitude: 0.2,
    globeImageUrl: "static/earth-night.jpg",
    arcColor: "color", arcStroke: 0.6, arcDashLength: 0.4, arcDashGap: 0.18,
    arcDashAnimateTime: 1500, arcAltitudeAutoScale: 0.45, arcsTransitionDuration: 0,
    ringColor: (r) => r.color, ringMaxRadius: 4,
    ringPropagationSpeed: 2.5, ringRepeatPeriod: 650,
    pointsData: [], pointColor: "color", pointAltitude: 0.012,
    pointRadius: (d) => d.r, pointsMerge: false,
    labelsData: [], labelLat: "lat", labelLng: "lng", labelText: "text",
    labelColor: (d) => d.color, labelSize: 0.9, labelDotRadius: 0.3, labelResolution: 2,
  };
  for (const k in cfg) {
    try { if (typeof globe[k] === "function") globe[k](cfg[k]); } catch (e) {}
  }

  // dark-teal base so a missing texture still reads as a planet, not a void
  try {
    const mat = globe.globeMaterial();
    mat.color = new THREE.Color("#0a1a16");
    mat.emissive = new THREE.Color("#02140e");
    mat.emissiveIntensity = 0.4;
  } catch (e) {}

  globe.controls().autoRotate = true;
  globe.controls().autoRotateSpeed = 0.55;
  globe.controls().enableZoom = true;

  // The #1 reason the globe "rarely showed": it initialised before the flex
  // panel had a size, rendering 0x0. Size it now, again after a tick, and on
  // every container resize.
  const fit = () => {
    if (el.clientWidth && el.clientHeight)
      globe.width(el.clientWidth).height(el.clientHeight);
  };
  fit();
  setTimeout(fit, 80);
  setTimeout(() => { fit(); flyHome(); }, 400);
  if (window.ResizeObserver) new ResizeObserver(fit).observe(el);
  window.addEventListener("resize", fit);

  setHomeMarker();
}

function clearGeo() {
  state.arcs = []; state.rings = [];
  if (globe) { globe.arcsData([]); globe.ringsData([]); }
}

function flyHome() {
  if (globe && !flewHome) {
    globe.pointOfView({ lat: home.lat, lng: home.lon, altitude: 2.3 }, 1200);
    flewHome = true;
  }
}

function setHomeMarker() {
  if (!globe) return;
  state.points = state.points.filter((p) => !p.home);
  state.points.push({ lat: home.lat, lng: home.lon, color: "#00ff95", r: 0.9, home: true });
  state.labels = state.labels.filter((l) => !l.home);
  state.labels.push({ lat: home.lat, lng: home.lon, text: home.label || "AP",
                      color: "#00ff95", home: true });
  globe.pointsData(state.points.slice()).labelsData(state.labels.slice());
}

function pushGeo(ev) {
  if (!globe || ev.lat == null) return;
  const color = CAT_COLOR[ev.category] || CAT_COLOR.other;
  state.arcs.push({ startLat: home.lat, startLng: home.lon,
                    endLat: ev.lat, endLng: ev.lon, color });
  if (state.arcs.length > 36) state.arcs.shift();
  globe.arcsData(state.arcs.slice());

  state.rings.push({ lat: ev.lat, lng: ev.lon, color });
  if (state.rings.length > 28) state.rings.shift();
  globe.ringsData(state.rings.slice());

  // one persistent dot + label per destination location
  const key = ev.lat.toFixed(1) + "," + ev.lon.toFixed(1);
  if (!state.points.some((p) => !p.home && p.key === key)) {
    state.points.push({ lat: ev.lat, lng: ev.lon, color, r: 0.45, key });
    const txt = ev.city || ev.country || "";
    if (txt) state.labels.push({ lat: ev.lat, lng: ev.lon, text: txt,
                                 color: "#cfe3ff", key });
    if (state.points.length > 80) state.points.splice(1, 1);
    if (state.labels.length > 60) state.labels.splice(1, 1);
    globe.pointsData(state.points.slice()).labelsData(state.labels.slice());
  }
}

// --- Feed -------------------------------------------------------------------
function pushFeed(ev) {
  const list = document.getElementById("feed-list");
  const row = document.createElement("div");
  row.className = "row " + ev.category;
  const cc = ev.country ? `${ev.country}${ev.city ? " · " + ev.city : ""}` : "";
  row.innerHTML = `<span class="t">${ev.ts}</span><span class="k">${ev.kind}</span>` +
    `<span class="d">${ev.domain}</span><span class="cc">${cc}</span>`;
  list.insertBefore(row, list.firstChild);
  while (list.childElementCount > 120) list.removeChild(list.lastChild);
}

// --- Devices ----------------------------------------------------------------
function updateDevice(ev) {
  if (!ev.src || ev.src === "?") return;
  let d = state.devices.get(ev.src);
  if (!d) {
    d = { os: "", apps: new Set(), logins: new Set(), domains: new Set() };
    state.devices.set(ev.src, d);
  }
  if (!d.os && ev.os) d.os = ev.os;
  (ev.apps || []).forEach((a) => d.apps.add(a));
  d.domains.add(ev.domain);
  if (ev.category === "auth") d.logins.add(ev.domain);
  d.last = ev.ts; d.lastMs = Date.now();
  renderDevices();
}

function renderDevices() {
  const wrap = document.getElementById("device-list");
  wrap.innerHTML = "";
  if (!state.devices.size) {
    wrap.innerHTML = '<div class="empty">No devices observed yet.</div>';
    return;
  }
  const now = Date.now();
  for (const [ip, d] of state.devices) {
    const stale = !state.online || (now - (d.lastMs || 0) > STALE_MS);
    const el = document.createElement("div");
    el.className = "device" + (stale ? " stale" : "");
    const apps = [...d.apps].map((a) => `<span class="tag">${a}</span>`).join("");
    const logins = [...d.logins].map((l) => `<span class="tag login">⚷ ${l}</span>`).join("");
    el.innerHTML =
      `<div class="d-top"><span class="ip">${ip}</span>` +
      `<span class="os">${d.os || "unknown OS"}</span></div>` +
      `<div class="apps">${apps || '<span class="os">no apps yet</span>'}${logins}</div>` +
      `<div class="meta">${d.domains.size} domains · last ${d.last || "—"}</div>`;
    wrap.appendChild(el);
  }
}

function updateStats() {
  document.getElementById("s-domains").textContent = state.domains.size;
  document.getElementById("s-devices").textContent = state.devices.size;
  document.getElementById("s-auth").textContent = state.authCount;
  document.getElementById("s-countries").textContent = state.countries.size;
}

// --- Mode badge -------------------------------------------------------------
function applyMode(mode, msg) {
  const badge = document.getElementById("mode-badge");
  const mmsg = document.getElementById("mode-msg");
  const map = {
    live: ["LIVE", "live"], demo: ["DEMO", "demo"],
    replay: ["REPLAY", "demo"], error: ["CAPTURE ERROR", "error"],
    offline: ["OFFLINE", "off"], starting: ["CONNECTING", "off"],
  };
  const [text, cls] = map[mode] || ["?", "off"];
  badge.textContent = "● " + text;
  badge.className = "mode " + cls;
  mmsg.textContent = msg || "";
  const hint = document.getElementById("dev-hint");
  if (mode === "demo") hint.textContent = "(synthetic)";
  else if (mode === "error" || mode === "offline") hint.textContent = "(stale)";
  else hint.textContent = "";
  state.online = (mode === "live" || mode === "replay" || mode === "demo");
}

// --- Event handling ---------------------------------------------------------
function handle(ev) {
  if (ev._meta) {
    if (ev.home) { home = ev.home; setHomeMarker(); flyHome(); }
    applyMode(ev.mode, ev.msg);
    // On a capture error, don't keep animating stale "live" arcs/devices —
    // show a clean stopped state so the dashboard never implies false activity.
    if (ev.mode === "error") { state.devices.clear(); renderDevices(); clearGeo(); }
    return;
  }
  state.domains.add(ev.domain);
  if (ev.country) state.countries.add(ev.country);
  if (ev.category === "auth") state.authCount++;
  pushGeo(ev); pushFeed(ev); updateDevice(ev); updateStats();
}

// --- SSE --------------------------------------------------------------------
function connect() {
  const es = new EventSource("/stream");
  es.onmessage = (m) => { try { handle(JSON.parse(m.data)); } catch (e) {} };
  es.onerror = () => { applyMode("offline", "server unreachable"); renderDevices(); };
}

// --- Clock + staleness sweep ------------------------------------------------
setInterval(() => {
  document.getElementById("clock").textContent = new Date().toTimeString().slice(0, 8);
  if (state.devices.size) renderDevices();
}, 1000);

// --- Boot -------------------------------------------------------------------
window._loadGlobe(function () { initGlobe(); connect(); });
