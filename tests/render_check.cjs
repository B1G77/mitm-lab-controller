// Dev-only: execute the browser view renderers in Node (shared scope, like
// <script> tags) against realistic state to catch runtime errors. Not shipped.
const fs = require("fs"), vm = require("vm");
const ctx = { Math, Date, Object, Array, String, JSON, parseInt, isNaN,
  window: { matchMedia: () => ({ matches: false }) }, console };
vm.createContext(ctx);

const flows = new Map([
  ["k1", { key: "k1", client: "192.168.50.2", cport: 44512, server: "35.186.224.25", sport: 443, l4: "TCP", proto: "TLSv1.3", name: "api.spotify.com", cat: "media", up: 5830, down: 120400, pkts: 88, dur: 12.3, last: 1700000200, geo: { country: "SE", city: "Stockholm" } }],
  ["k2", { key: "k2", client: "192.168.50.3", cport: 51000, server: "93.184.216.34", sport: 80, l4: "TCP", proto: "HTTP", name: "login.example.com", cat: "auth", up: 300, down: 800, pkts: 6, dur: 1.1, last: 1700000205, geo: null }],
  ["k3", { key: "k3", client: "192.168.50.2", cport: 5, server: "203.0.113.9", sport: 443, l4: "TCP", proto: "TCP", name: "", cat: "", up: 100, down: 0, pkts: 2, dur: 0, last: 1700000180 }],
]);
const devices = new Map([
  ["192.168.50.2", { ip: "192.168.50.2", mac: "aa:bb:cc:dd:ee:ff", os: "Apple", apps: ["Spotify", "Discord"], logins: [], domains: 14, up: 120000, down: 980000, ja3: ["771,4865"], ja4: ["t13d1516h2"], last: 1700000205, bw: [[1700000200, 500, 9000], [1700000201, 300, 12000]] }],
  ["192.168.50.3", { ip: "192.168.50.3", mac: "", os: "Windows", apps: [], logins: ["login.example.com"], domains: 3, up: 1200, down: 3400, ja3: [], ja4: [], last: 1700000205, bw: [] }],
]);
const names = new Map([
  ["35.186.224.25", { name: "api.spotify.com", src: "sni", cat: "media" }],
  ["203.0.113.9", { name: "as13335.cloudflare", src: "rdap", cat: "" }],
]);
const STATE = {
  mode: "live", online: true, view: "overview", flows, devices, names, geo: new Map(),
  packets: [{ num: 42, ts: 1700000205.12, src: "192.168.50.2", dst: "35.186.224.25", sport: 44512, dport: 443, proto: "TLSv1.3", len: 583, host: "api.spotify.com" }],
  http: [{ ts: "10:00:01", client: "192.168.50.3", method: "POST", host: "login.example.com", uri: "/auth", ua: "curl/8", auth: true, cookie: false }],
  alerts: [{ ts: "10:00:01", sev: "high", kind: "cleartext_creds", msg: "Cleartext creds from .50.3", ip: "192.168.50.3" }],
  stats: { devices: 2, flows: 3, domains: 14, countries: 1, alerts: 1, packets: 96, bytes: 1100000, auth: 1, uptime: 42,
    proto_bytes: { "TLSv1.3": 980000, "HTTP": 1100, "QUIC": 50000 }, cat_counts: { media: 40, auth: 2, tracking: 9 },
    bw_global: [[1700000200, 800, 21000], [1700000201, 600, 24000], [1700000202, 1200, 18000]] },
  selected: null, flowFilter: "", dnsFilter: "",
};
ctx.STATE = STATE;

const src = fs.readFileSync("web/charts.js", "utf8") + "\n" +
  fs.readFileSync("web/views.js", "utf8") +
  "\nthis.__run = function(S){ var ok=0; for (var v of Object.keys(VIEWS)){ var root={innerHTML:''}; VIEWS[v](root,S);" +
  " if(!root.innerHTML||root.innerHTML.length<30) throw new Error('empty '+v);" +
  " console.log('ok  '+v+'  ('+root.innerHTML.length+' chars)'); ok++; }" +
  " S.selected='192.168.50.2'; S.flowFilter='spotify'; VIEWS.flows({innerHTML:''},S);" +
  " S.dnsFilter='cloud'; VIEWS.dns({innerHTML:''},S);" +
  " console.log('all '+ok+' views + filter/selection paths rendered, no errors'); };";
vm.runInContext(src, ctx, { filename: "combined.js" });
ctx.__run(STATE);
