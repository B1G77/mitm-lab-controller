"use strict";
// Shared constants + tiny dependency-free SVG charts. Loaded first, so every
// other script (views, globe, app) can use these at call time.

const CAT_COLOR = {
  auth: "#ff4d6d", tracking: "#ffd166", media: "#00ff95",
  cdn: "#8ea0bd", other: "#38bdf8", "": "#5b6b86",
};

// Stable colour per protocol label (hashed → hue), so the donut/legend agree.
const _protoCache = {};
function protoColor(name) {
  if (_protoCache[name]) return _protoCache[name];
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
  const c = `hsl(${h}, 70%, 60%)`;
  _protoCache[name] = c;
  return c;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function fmtBytes(n) {
  n = n || 0;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)) + " " + u[i];
}

function fmtRate(bytesPerSec) {
  return fmtBytes(bytesPerSec) + "/s";
}

function fmtAgo(epoch) {
  if (!epoch) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - epoch));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  return Math.floor(s / 3600) + "h";
}

// Single-series filled sparkline.
function sparkArea(values, opts) {
  opts = opts || {};
  const w = opts.w || 140, h = opts.h || 36, color = opts.color || "#00ff95";
  if (!values || !values.length) return `<svg width="${w}" height="${h}"></svg>`;
  const max = Math.max(1, ...values);
  const step = w / Math.max(1, values.length - 1);
  const pts = values.map((v, i) => [i * step, h - (v / max) * (h - 2) - 1]);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const area = `M0 ${h} ` + pts.map((p) => "L" + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ") + ` L${w} ${h} Z`;
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <path d="${area}" fill="${color}" opacity="0.16"/>
    <path d="${line}" fill="none" stroke="${color}" stroke-width="1.4"/></svg>`;
}

// Up/down throughput area chart from [[bucket, up, down], ...].
function dualArea(series, opts) {
  opts = opts || {};
  const w = opts.w || 600, h = opts.h || 120;
  if (!series || !series.length) return `<svg width="100%" height="${h}"></svg>`;
  const ups = series.map((s) => s[1] || 0), downs = series.map((s) => s[2] || 0);
  const max = Math.max(1, ...ups, ...downs);
  const step = w / Math.max(1, series.length - 1);
  const build = (vals) => {
    const pts = vals.map((v, i) => [i * step, h - (v / max) * (h - 4) - 2]);
    const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    const area = `M0 ${h} ` + pts.map((p) => "L" + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ") + ` L${w} ${h} Z`;
    return { line, area };
  };
  const d = build(downs), u = build(ups);
  return `<svg width="100%" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="dual">
    <path d="${d.area}" fill="#38bdf8" opacity="0.12"/>
    <path d="${d.line}" fill="none" stroke="#38bdf8" stroke-width="1.4"/>
    <path d="${u.area}" fill="#00ff95" opacity="0.14"/>
    <path d="${u.line}" fill="none" stroke="#00ff95" stroke-width="1.4"/></svg>`;
}

// Donut from parts [{label, value, color}]. Returns svg + legend wrapper.
function donut(parts, opts) {
  opts = opts || {};
  const size = opts.size || 150, r = size / 2 - 6, cx = size / 2, cy = size / 2;
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  let ang = -Math.PI / 2, segs = "";
  for (const p of parts) {
    const frac = p.value / total, a2 = ang + frac * Math.PI * 2;
    const large = frac > 0.5 ? 1 : 0;
    const x1 = cx + r * Math.cos(ang), y1 = cy + r * Math.sin(ang);
    const x2 = cx + r * Math.cos(a2), y2 = cy + r * Math.sin(a2);
    if (frac > 0.0001)
      segs += `<path d="M${cx} ${cy} L${x1.toFixed(1)} ${y1.toFixed(1)} A${r} ${r} 0 ${large} 1 ${x2.toFixed(1)} ${y2.toFixed(1)} Z" fill="${p.color}" opacity="0.85"/>`;
    ang = a2;
  }
  const hole = `<circle cx="${cx}" cy="${cy}" r="${r * 0.58}" fill="#060c18"/>`;
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${segs}${hole}</svg>`;
}
