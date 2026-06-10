"use strict";
// View renderers. Each takes the main element + the shared STATE and paints a
// focused analysis surface. Interaction is via data-* attributes handled by a
// delegated listener in app.js. Everything shown is real observed data.

function badge(cat) {
  return `<span class="badge ${cat || "none"}">${esc(cat || "—")}</span>`;
}
function serverCell(f) {
  const label = f.name || f.server;
  const sub = f.name ? f.server : (f.src || "");
  const loc = f.geo && f.geo.country ? ` <span class="loc">${esc(f.geo.country)}</span>` : "";
  return `<span class="srv" title="${esc(f.server)}">${esc(label)}</span>` +
    (sub ? `<span class="srv-sub">${esc(sub)}</span>` : "") + loc;
}
function head(title, tools) {
  return `<div class="view-head"><h2>${title}</h2><div class="tools">${tools || ""}</div></div>`;
}

// ---- Overview ----
function renderOverview(root, S) {
  const st = S.stats || {};
  const devs = [...S.devices.values()].sort((a, b) => (b.up + b.down) - (a.up + a.down));
  const maxBw = Math.max(1, ...devs.map((d) => d.up + d.down));
  const protoParts = Object.entries(st.proto_bytes || {}).map(([k, v]) => ({ label: k, value: v, color: protoColor(k) }));
  const cats = st.cat_counts || {};
  const catParts = Object.keys(CAT_COLOR).filter((c) => c && cats[c])
    .map((c) => ({ label: c, value: cats[c], color: CAT_COLOR[c] }));
  const maxCat = Math.max(1, ...catParts.map((p) => p.value));
  const alerts = S.alerts.slice(-8).reverse();

  root.innerHTML = head("Overview") + `<div class="grid-overview">
    <section class="card span2">
      <div class="card-h">Throughput <span class="muted">↑ up · ↓ down · ${BW_LABEL(st)}</span></div>
      ${dualArea(st.bw_global || [], { h: 130 })}
    </section>
    <section class="card">
      <div class="card-h">Protocols</div>
      <div class="donut-row">${donut(protoParts, { size: 130 })}
        <div class="legend-list">${protoParts.slice(0, 7).map((p) =>
          `<div><i style="background:${p.color}"></i>${esc(p.label)} <b>${fmtBytes(p.value)}</b></div>`).join("") || '<div class="muted">no data</div>'}</div></div>
    </section>
    <section class="card">
      <div class="card-h">Categories</div>
      <div class="bars">${catParts.map((p) =>
        `<div class="bar-row"><span>${esc(p.label)}</span><span class="bar"><i style="width:${(p.value / maxCat * 100).toFixed(0)}%;background:${p.color}"></i></span><b>${p.value}</b></div>`).join("") || '<div class="muted">no categorised traffic yet</div>'}</div>
    </section>
    <section class="card span2">
      <div class="card-h">Top talkers</div>
      <div class="talkers">${devs.slice(0, 8).map((d) => {
        const tot = d.up + d.down;
        return `<div class="talk-row" data-ip="${esc(d.ip)}"><span class="ip">${esc(d.ip)}</span>` +
          `<span class="os">${esc(d.os || "")}</span>` +
          `<span class="bar"><i style="width:${(tot / maxBw * 100).toFixed(0)}%"></i></span>` +
          `<b>${fmtBytes(tot)}</b></div>`;
      }).join("") || '<div class="muted">no devices yet</div>'}</div>
    </section>
    <section class="card span2">
      <div class="card-h">Recent alerts</div>
      <div class="alert-list">${alerts.map((a) =>
        `<div class="al ${a.sev}"><span class="al-k">${esc(a.kind)}</span><span class="al-m">${esc(a.msg)}</span><span class="al-t">${esc(a.ts)}</span></div>`).join("") || '<div class="muted">no alerts</div>'}</div>
    </section></div>`;
}
function BW_LABEL(st) {
  const s = st.bw_global || [];
  if (!s.length) return "0/s";
  const last = s[s.length - 1];
  return fmtRate((last[1] || 0) + (last[2] || 0));
}

// ---- Flows ----
function renderFlows(root, S) {
  const tools = `<input id="flow-filter" placeholder="filter host / ip / proto…" value="${esc(S.flowFilter || "")}">` +
    (S.selected ? `<span class="sel-chip" data-clear="1">▼ ${esc(S.selected)} ✕</span>` : "");
  let rows = [...S.flows.values()];
  if (S.selected) rows = rows.filter((f) => f.client === S.selected);
  const q = (S.flowFilter || "").toLowerCase();
  if (q) rows = rows.filter((f) => (f.name + f.server + f.client + f.proto).toLowerCase().includes(q));
  rows.sort((a, b) => b.last - a.last);
  rows = rows.slice(0, 250);
  root.innerHTML = head("Flows", tools) + `<div class="tbl flows">
    <div class="tr th"><span>Client</span><span>Server</span><span>Proto</span><span>Cat</span>
      <span class="num">↑</span><span class="num">↓</span><span class="num">Pkts</span><span class="num">Dur</span></div>
    <div class="tbody">${rows.map((f) =>
      `<div class="tr ${f.cat || "none"}"><span class="mono">${esc(f.client)}</span>` +
      `<span class="srv-c">${serverCell(f)}</span><span class="mono sm">${esc(f.proto)}</span>` +
      `${badge(f.cat)}<span class="num">${fmtBytes(f.up)}</span><span class="num">${fmtBytes(f.down)}</span>` +
      `<span class="num">${f.pkts}</span><span class="num">${f.dur}s</span></div>`).join("") ||
      '<div class="empty">No flows match.</div>'}</div></div>`;
}

// ---- Devices ----
function renderDevices(root, S) {
  const devs = [...S.devices.values()].sort((a, b) => b.last - a.last);
  const now = Date.now() / 1000;
  root.innerHTML = head("Devices") + `<div class="dev-grid">${devs.map((d) => {
    const stale = !S.online || (now - (d.last || 0) > 90);
    const apps = d.apps.map((a) => `<span class="tag">${esc(a)}</span>`).join("");
    const logins = d.logins.map((l) => `<span class="tag login">↪ ${esc(l)}</span>`).join("");
    const bw = (d.bw || []).map((b) => (b[1] || 0) + (b[2] || 0));
    return `<div class="device ${stale ? "stale" : ""} ${S.selected === d.ip ? "sel" : ""}" data-ip="${esc(d.ip)}" tabindex="0" role="button">
      <div class="d-top"><span class="ip">${esc(d.ip)}</span><span class="os">${esc(d.os || "unknown OS")}</span></div>
      <div class="d-mac">${esc(d.mac || "")}</div>
      <div class="apps">${apps || '<span class="os">no apps yet</span>'}${logins}</div>
      <div class="d-bw">${sparkArea(bw, { w: 300, h: 30, color: "#00ff95" })}</div>
      <div class="meta"><span>↑ ${fmtBytes(d.up)} · ↓ ${fmtBytes(d.down)}</span><span>${d.domains} hosts · ${fmtAgo(d.last)} ago</span></div>
    </div>`;
  }).join("") || '<div class="empty">No devices observed yet.</div>'}</div>`;
}

// ---- DNS ----
function renderDNS(root, S) {
  // Group resolved hosts by name → which addresses, how learned.
  const byName = new Map();
  for (const [ip, n] of S.names) {
    let e = byName.get(n.name);
    if (!e) { e = { name: n.name, ips: [], src: n.src, cat: n.cat }; byName.set(n.name, e); }
    e.ips.push(ip);
  }
  let rows = [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
  const q = (S.dnsFilter || "").toLowerCase();
  if (q) rows = rows.filter((r) => r.name.toLowerCase().includes(q));
  root.innerHTML = head("Resolved hosts", `<input id="dns-filter" placeholder="filter host…" value="${esc(S.dnsFilter || "")}">`) +
    `<div class="tbl dns"><div class="tr th"><span>Host</span><span>Addresses</span><span>Learned</span><span>Cat</span></div>
    <div class="tbody">${rows.map((r) =>
      `<div class="tr"><span class="srv">${esc(r.name)}</span>` +
      `<span class="mono sm">${r.ips.map(esc).join(", ")}</span>` +
      `<span class="src-tag ${r.src}">${esc(r.src)}</span>${badge(r.cat)}</div>`).join("") ||
      '<div class="empty">No hosts resolved yet.</div>'}</div></div>`;
}

// ---- TLS ----
function renderTLS(root, S) {
  const fps = [...S.devices.values()].filter((d) => (d.ja3 && d.ja3.length) || (d.ja4 && d.ja4.length));
  const tlsFlows = [...S.flows.values()].filter((f) => /TLS|QUIC/i.test(f.proto) || f.sport === 443 || f.server)
    .filter((f) => f.name && (/TLS|QUIC/i.test(f.proto) || f.cat))
    .sort((a, b) => b.last - a.last).slice(0, 200);
  root.innerHTML = head("TLS intelligence") + `<div class="tls-wrap">
    <section class="card">
      <div class="card-h">Client fingerprints (JA3 / JA4)</div>
      <div class="fp-list">${fps.map((d) =>
        `<div class="fp"><span class="ip">${esc(d.ip)}</span><span class="os">${esc(d.os || "")}</span>` +
        (d.ja4 || []).map((j) => `<code class="ja4">JA4 ${esc(j)}</code>`).join("") +
        (d.ja3 || []).map((j) => `<code class="ja3">JA3 ${esc(j)}</code>`).join("") + `</div>`).join("") ||
        '<div class="muted">No TLS fingerprints captured yet (needs tshark JA3/JA4 fields).</div>'}</div>
    </section>
    <section class="card span2">
      <div class="card-h">TLS connections (SNI)</div>
      <div class="tbl"><div class="tr th"><span>SNI</span><span>Version</span><span>Server</span><span>Cat</span></div>
      <div class="tbody">${tlsFlows.map((f) =>
        `<div class="tr"><span class="srv">${esc(f.name)}</span><span class="mono sm">${esc(f.proto)}</span>` +
        `<span class="mono sm">${esc(f.server)}${f.geo && f.geo.country ? " · " + esc(f.geo.country) : ""}</span>${badge(f.cat)}</div>`).join("") ||
        '<div class="empty">No named TLS connections yet.</div>'}</div></div>
    </section></div>`;
}

// ---- HTTP (cleartext) ----
function renderHTTP(root, S) {
  const rows = S.http.slice().reverse();
  root.innerHTML = head("Cleartext HTTP", '<span class="muted">plaintext requests the AP could read</span>') +
    `<div class="tbl http"><div class="tr th"><span>Time</span><span>Client</span><span>Method</span>
      <span class="grow">Host / URL</span><span>Flags</span></div>
    <div class="tbody">${rows.map((r) => {
      const flags = (r.auth ? '<span class="flag creds">CREDS</span>' : "") + (r.cookie ? '<span class="flag">cookie</span>' : "");
      const url = esc((r.host || "") + (r.uri || ""));
      return `<div class="tr ${r.auth ? "auth" : ""}"><span class="t">${esc(r.ts)}</span>` +
        `<span class="mono">${esc(r.client)}</span><span class="m">${esc(r.method || "")}</span>` +
        `<span class="grow url" title="${url}">${url}</span><span>${flags}</span></div>`;
    }).join("") || '<div class="empty">No cleartext HTTP seen. (Most traffic is HTTPS — that is expected.)</div>'}</div></div>`;
}

// ---- Packets ----
function renderPackets(root, S) {
  const rows = S.packets.slice(-300).reverse();
  root.innerHTML = head("Packets", '<span class="muted">click a row for full dissection + hex</span>') +
    `<div class="tbl packets"><div class="tr th"><span>#</span><span>Time</span><span>Source</span>
      <span>Destination</span><span>Proto</span><span class="num">Len</span><span class="grow">Host</span></div>
    <div class="tbody">${rows.map((p) => {
      const t = new Date((p.ts || 0) * 1000).toTimeString().slice(0, 8);
      return `<div class="tr pkt" data-ts="${p.ts}" data-src="${esc(p.src)}" data-dst="${esc(p.dst)}" data-sport="${p.sport || ""}">` +
        `<span class="mono sm">${p.num || ""}</span><span class="t">${t}</span>` +
        `<span class="mono sm">${esc(p.src)}${p.sport ? ":" + p.sport : ""}</span>` +
        `<span class="mono sm">${esc(p.dst)}${p.dport ? ":" + p.dport : ""}</span>` +
        `<span class="sm">${esc(p.proto)}</span><span class="num">${p.len}</span>` +
        `<span class="grow srv">${esc(p.host || "")}</span></div>`;
    }).join("") || '<div class="empty">No packets captured yet.</div>'}</div></div>`;
}

const VIEWS = {
  overview: renderOverview, flows: renderFlows, devices: renderDevices,
  dns: renderDNS, tls: renderTLS, http: renderHTTP, packets: renderPackets,
};
