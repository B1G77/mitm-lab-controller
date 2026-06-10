"use strict";
// Geo view: a 3D globe with a glowing arc from the rogue AP to every
// destination we could geolocate. Only real, geolocated destinations appear —
// un-geolocated flows simply have no point. globe.gl is optional; if it never
// loads, the view shows a friendly message and the rest of the console works.

const GeoView = (function () {
  let globe = null, host = null, mounted = false, flew = false;
  let home = { lat: 38.7223, lon: -9.1393, label: "ROGUE AP" };
  const arcs = [], rings = [], points = [], labels = [];
  const seenPts = new Set();
  const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function ensureHost() {
    if (!host) { host = document.createElement("div"); host.id = "globe"; }
    return host;
  }

  function mount(container) {
    container.innerHTML = "";
    const wrap = document.createElement("div");
    wrap.className = "globe-panel glass";
    wrap.innerHTML = '<div class="panel-label">LIVE GEO-INTELLIGENCE' +
      '<span class="legend"><i style="background:#ff4d6d"></i>auth ' +
      '<i style="background:#ffd166"></i>tracking <i style="background:#00ff95"></i>media ' +
      '<i style="background:#8ea0bd"></i>cdn <i style="background:#38bdf8"></i>other</span></div>';
    wrap.appendChild(ensureHost());
    container.appendChild(wrap);
    mounted = true;
    if (!globe) init(); else { fit(); flew = false; flyHome(); }
  }

  function unmount() { mounted = false; }

  function init() {
    const el = ensureHost();
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
      arcColor: "color", arcStroke: 0.5, arcDashLength: 0.4, arcDashGap: 0.18,
      arcDashAnimateTime: REDUCED ? 0 : 1500, arcAltitudeAutoScale: 0.45,
      arcsTransitionDuration: 0,
      ringColor: (r) => r.color, ringMaxRadius: 4,
      ringPropagationSpeed: 2.5, ringRepeatPeriod: REDUCED ? 0 : 700,
      pointsData: [], pointColor: "color", pointAltitude: 0.012,
      pointRadius: (d) => d.r, pointsMerge: false,
      labelsData: [], labelLat: "lat", labelLng: "lng", labelText: "text",
      labelColor: (d) => d.color, labelSize: 0.8, labelDotRadius: 0.26, labelResolution: 2,
    };
    for (const k in cfg) { try { if (typeof globe[k] === "function") globe[k](cfg[k]); } catch (e) {} }
    try {
      const m = globe.globeMaterial();
      m.color = new THREE.Color("#0a1a16");
      m.emissive = new THREE.Color("#02140e"); m.emissiveIntensity = 0.4;
    } catch (e) {}
    try { globe.controls().autoRotate = !REDUCED; globe.controls().autoRotateSpeed = 0.45; } catch (e) {}
    fit(); setTimeout(fit, 80); setTimeout(() => { fit(); flyHome(); }, 400);
    if (window.ResizeObserver) new ResizeObserver(fit).observe(el);
    setHomeMarker();
  }

  function fit() {
    if (globe && host && host.clientWidth && host.clientHeight)
      globe.width(host.clientWidth).height(host.clientHeight);
  }
  function flyHome() {
    if (globe && !flew) { globe.pointOfView({ lat: home.lat, lng: home.lon, altitude: 2.3 }, 1200); flew = true; }
  }

  function setHome(h) {
    if (!h) return;
    home = { lat: h.lat, lon: h.lon, label: h.label || "AP" };
    flew = false;
    setHomeMarker(); flyHome();
  }

  function setHomeMarker() {
    if (!globe) return;
    const i = points.findIndex((p) => p.home);
    if (i >= 0) points.splice(i, 1);
    points.unshift({ lat: home.lat, lng: home.lon, color: "#00ff95", r: 0.95, home: true });
    const j = labels.findIndex((l) => l.home);
    if (j >= 0) labels.splice(j, 1);
    labels.unshift({ lat: home.lat, lng: home.lon, text: home.label, color: "#00ff95", home: true });
    globe.pointsData(points.slice()).labelsData(labels.slice());
  }

  // Register a geolocated destination (truthful: only called with real coords).
  function addDest(geo, category) {
    if (!globe || geo.lat == null) return;
    const color = CAT_COLOR[category] || CAT_COLOR.other;
    arcs.push({ startLat: home.lat, startLng: home.lon, endLat: geo.lat, endLng: geo.lon, color });
    if (arcs.length > 40) arcs.shift();
    globe.arcsData(arcs.slice());
    rings.push({ lat: geo.lat, lng: geo.lon, color });
    if (rings.length > 28) rings.shift();
    globe.ringsData(rings.slice());
    const key = geo.lat.toFixed(1) + "," + geo.lon.toFixed(1);
    if (!seenPts.has(key)) {
      seenPts.add(key);
      points.push({ lat: geo.lat, lng: geo.lon, color, r: 0.45, key });
      const txt = geo.city || geo.country || "";
      if (txt) labels.push({ lat: geo.lat, lng: geo.lon, text: txt, color: "#cfe3ff", key });
      if (points.length > 90) points.splice(1, 1);
      if (labels.length > 70) labels.splice(1, 1);
      globe.pointsData(points.slice()).labelsData(labels.slice());
    }
  }

  // Rebuild all points from a snapshot's geo set (used on initial load).
  function syncAll(geoList, namesMap) {
    if (!globe || !geoList) return;
    for (const g of geoList) {
      const name = namesMap && namesMap.get ? namesMap.get(g.ip) : null;
      addDest(g, name ? name.cat : "");
    }
  }

  return { mount, unmount, setHome, addDest, syncAll, fit };
})();
