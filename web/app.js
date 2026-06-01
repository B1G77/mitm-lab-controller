"use strict";

// --- Category colors (match style.css) --------------------------------------
const CAT_COLOR = {
  auth: "#ff4d6d", tracking: "#ffd166", media: "#00ff95",
  cdn: "#7d8aa3", other: "#38bdf8",
};

// --- State ------------------------------------------------------------------
const state = {
  domains: new Set(),
  countries: new Set(),
  authCount: 0,
  devices: new Map(),   // ip -> {os, apps:Set, logins:Set, domains:Set, last}
  arcs: [],
  rings: [],
};
let globe = null;
let home = { lat: 38.7223, lon: -9.1393 };

// --- Globe setup ------------------------------------------------------------
function initGlobe() {
  const el = document.getElementById("globe");
  if (typeof Globe === "undefined") {
    el.innerHTML = '<div style="padding:60px;text-align:center;color:#6b7a99">' +
      '3D globe library not loaded.<br>Run <code>web/fetch_libs.sh</code> ' +
      'or connect to the internet once.</div>';
    return;
  }
  // Texture is bundled locally (web/static/earth-night.jpg via fetch_libs.sh)
  // because the AP being live cuts the host's internet — a CDN URL would 404
  // mid-demo. If the local file is missing the globe falls back to a dark
  // sphere, which still looks on-brand.
  globe = Globe()(el)
    .backgroundColor("rgba(0,0,0,0)")
    .showGlobe(true)
    .showAtmosphere(true)
    .atmosphereColor("#00ff95")
    .atmosphereAltitude(0.18)
    .globeImageUrl("static/earth-night.jpg")
    .arcColor("color")
    .arcStroke(0.5)
    .arcDashLength(0.45)
    .arcDashGap(0.18)
    .arcDashAnimateTime(1600)
    .arcsTransitionDuration(0)
    .ringColor((r) => r.color)
    .ringMaxRadius(4)
    .ringPropagationSpeed(2.2)
    .ringRepeatPeriod(700);

  // Dark teal base so a missing texture reads as an intentional dark planet.
  try {
    const mat = globe.globeMaterial();
    mat.color = new THREE.Color("#0a1a16");
    mat.emissive = new THREE.Color("#021a12");
    mat.emissiveIntensity = 0.35;
  } catch (e) {}

  const resize = () => globe.width(el.clientWidth).height(el.clientHeight);
  resize();
  window.addEventListener("resize", resize);

  // gentle auto-rotation — cinematic
  globe.controls().autoRotate = true;
  globe.controls().autoRotateSpeed = 0.6;
  globe.pointOfView({ lat: 25, lng: 0, altitude: 2.4 });
}

function pushArc(ev) {
  if (!globe || ev.lat == null) return;
  const color = CAT_COLOR[ev.category] || CAT_COLOR.other;
  const arc = {
    startLat: ev.home ? ev.home.lat : home.lat,
    startLng: ev.home ? ev.home.lon : home.lon,
    endLat: ev.lat, endLng: ev.lon, color,
  };
  state.arcs.push(arc);
  if (state.arcs.length > 40) state.arcs.shift();
  globe.arcsData(state.arcs.slice());

  const ring = { lat: ev.lat, lng: ev.lon, color };
  state.rings.push(ring);
  if (state.rings.length > 30) state.rings.shift();
  globe.ringsData(state.rings.slice());
}

// --- Feed -------------------------------------------------------------------
function pushFeed(ev) {
  const list = document.getElementById("feed-list");
  const row = document.createElement("div");
  row.className = "row " + ev.category;
  const cc = ev.country ? `${ev.country}${ev.city ? " · " + ev.city : ""}` : "";
  row.innerHTML =
    `<span class="t">${ev.ts}</span>` +
    `<span class="k">${ev.kind}</span>` +
    `<span class="d">${ev.domain}</span>` +
    `<span class="cc">${cc}</span>`;
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
  d.last = ev.ts;
  renderDevices();
}

function renderDevices() {
  const wrap = document.getElementById("device-list");
  wrap.innerHTML = "";
  for (const [ip, d] of state.devices) {
    const el = document.createElement("div");
    el.className = "device";
    const apps = [...d.apps].map((a) => `<span class="tag">${a}</span>`).join("");
    const logins = [...d.logins]
      .map((l) => `<span class="tag login">⚷ ${l}</span>`).join("");
    el.innerHTML =
      `<div class="d-top"><span class="ip">${ip}</span>` +
      `<span class="os">${d.os || "unknown OS"}</span></div>` +
      `<div class="apps">${apps || '<span class="os">no apps yet</span>'}${logins}</div>` +
      `<div class="meta">${d.domains.size} domains · last ${d.last}</div>`;
    wrap.appendChild(el);
  }
}

// --- Stats ------------------------------------------------------------------
function updateStats() {
  document.getElementById("s-domains").textContent = state.domains.size;
  document.getElementById("s-devices").textContent = state.devices.size;
  document.getElementById("s-auth").textContent = state.authCount;
  document.getElementById("s-countries").textContent = state.countries.size;
}

// --- Event handling ---------------------------------------------------------
function handle(ev) {
  if (ev.home) home = { lat: ev.home.lat, lon: ev.home.lon };
  state.domains.add(ev.domain);
  if (ev.country) state.countries.add(ev.country);
  if (ev.category === "auth") state.authCount++;
  pushArc(ev);
  pushFeed(ev);
  updateDevice(ev);
  updateStats();
}

// --- SSE connection ---------------------------------------------------------
function connect() {
  const dot = document.getElementById("conn-dot");
  const txt = document.getElementById("conn-text");
  const es = new EventSource("/stream");
  es.onopen = () => { dot.classList.add("live"); txt.textContent = "● LIVE"; };
  es.onmessage = (m) => { try { handle(JSON.parse(m.data)); } catch (e) {} };
  es.onerror = () => { dot.classList.remove("live"); txt.textContent = "RECONNECTING…"; };
}

// --- Clock ------------------------------------------------------------------
function tick() {
  const d = new Date();
  document.getElementById("clock").textContent =
    d.toTimeString().slice(0, 8);
}
setInterval(tick, 1000); tick();

// --- Boot -------------------------------------------------------------------
window._loadGlobe(function () {
  initGlobe();
  connect();
});
