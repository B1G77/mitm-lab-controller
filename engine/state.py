"""MonitorState: the live picture built from observed packets.

Owns flows, devices, the IP->name correlation map, bandwidth time-series,
protocol stats, alerts and a recent-packet ring. Thread-safe: the capture
thread calls `ingest`, HTTP threads call `snapshot`/`drain_deltas`.

Honesty rules enforced here:
  * a flow is only *named* from data we actually saw (DNS answer / TLS SNI /
    HTTP Host), or from enrichment (PTR/rdap) supplied later; otherwise it
    stays a raw IP with category "" and is never colour-highlighted.
  * categories/OS/app labels come only from real host names.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from .model import (Packet, classify, match_apps, match_os, SUSPICIOUS_TLDS)

BW_WINDOW = 120          # seconds of bandwidth history kept
FLOW_CAP = 4000          # max flows retained (oldest pruned)
PKT_RING = 600           # recent packets kept for the inspector
ALERT_CAP = 300
SCAN_DISTINCT_PORTS = 15
SCAN_WINDOW = 10.0


@dataclass
class Flow:
    key: str
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None
    l4: str
    proto: str = ""
    bytes_up: int = 0
    bytes_down: int = 0
    pkts_up: int = 0
    pkts_down: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0


@dataclass
class Device:
    ip: str
    mac: str = ""
    os: str = ""
    apps: set = field(default_factory=set)
    logins: set = field(default_factory=set)
    domains: set = field(default_factory=set)
    ja3: set = field(default_factory=set)
    ja4: set = field(default_factory=set)
    bytes_up: int = 0
    bytes_down: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    bw: dict = field(default_factory=dict)   # bucket(int sec) -> [up, down]


def _canon(a_ip, a_port, b_ip, b_port, l4) -> tuple:
    """Order endpoints so both directions hash to one conversation."""
    x, y = (a_ip, a_port), (b_ip, b_port)
    return (x, y, l4) if x <= y else (y, x, l4)


class MonitorState:
    def __init__(self, subnet: str | None = None, ap_ip: str | None = None) -> None:
        self.lock = threading.RLock()
        self.subnet = ipaddress.ip_network(subnet, strict=False) if subnet else None
        self.ap_ip = ap_ip
        self.flows: dict[tuple, Flow] = {}
        self.devices: dict[str, Device] = {}
        self.names: dict[str, str] = {}        # ip -> host name
        self.name_src: dict[str, str] = {}     # ip -> dns|sni|http|ptr|rdap
        self.geo: dict[str, dict] = {}         # ip -> {lat,lon,country,city,org}
        self.packets: deque = deque(maxlen=PKT_RING)
        self.http: deque = deque(maxlen=300)   # cleartext HTTP requests
        self.alerts: deque = deque(maxlen=ALERT_CAP)
        self.bw_global: dict[int, list[int]] = {}
        self.proto_bytes: dict[str, int] = {}  # col_proto -> bytes
        self.cat_counts: dict[str, int] = {}
        self.domains: set = set()
        self.countries: set = set()
        self.total_bytes = 0
        self.total_pkts = 0
        self.started = time.time()
        # scan detection: (client,server) -> {port: ts}
        self._scan: dict[tuple, dict] = {}
        self._alerted_creds: set = set()
        # delta tracking
        self._dirty_flows: set = set()
        self._dirty_devs: set = set()
        self._new_pkts: list = []
        self._new_alerts: list = []
        self._new_names: list = []
        self._new_geo: list = []
        self._new_http: list = []

    # --- classification helpers ---------------------------------------------
    def _is_client(self, ip: str) -> bool:
        if ip == self.ap_ip:
            return False
        if self.subnet:
            try:
                return ipaddress.ip_address(ip) in self.subnet
            except ValueError:
                return False
        return True  # no subnet configured: treat any private src as client

    def display_name(self, ip: str) -> str:
        return self.names.get(ip, "")

    def category_for(self, ip: str) -> str:
        host = self.names.get(ip, "")
        # Only DNS/SNI/HTTP names justify a behavioural category; PTR/rdap
        # owner labels do not (they describe infrastructure, not intent).
        if host and self.name_src.get(ip) in ("dns", "sni", "http"):
            return classify(host)
        return ""

    # --- ingestion -----------------------------------------------------------
    def ingest(self, p: Packet) -> None:
        if not p.src or not p.dst:
            return
        with self.lock:
            self.total_pkts += 1
            self.total_bytes += p.length
            self._record_names(p)
            client, server, up = self._orient(p)
            self._update_flow(p, client, server, up)
            if client:
                self._update_device(p, client, server, up)
            self._update_stats(p)
            self._update_bw(p, client, up)
            self._ring_packet(p)
            self._record_http(p, client)
            self._detect(p, client, server)

    def _orient(self, p: Packet):
        """Return (client_ip, server_ip, up_bool). up = traffic from client."""
        if self._is_client(p.src):
            return p.src, p.dst, True
        if self._is_client(p.dst):
            return p.dst, p.src, False
        return "", p.dst, True  # neither obviously a client (e.g. pcap w/o subnet)

    def _record_names(self, p: Packet) -> None:
        # DNS answers: each returned address belongs to the queried name.
        if p.dns_qry and p.dns_answers:
            for ip in p.dns_answers:
                self._set_name(ip, p.dns_qry, "dns")
        # SNI / HTTP Host name the server IP this packet is heading to.
        if p.sni:
            self._set_name(p.dst, p.sni, "sni")
        elif p.http_host:
            self._set_name(p.dst, p.http_host, "http")
        host = p.hostname()
        if host:
            self.domains.add(host)

    def _set_name(self, ip: str, host: str, src: str) -> None:
        host = (host or "").rstrip(".")
        if not ip or not host:
            return
        rank = {"ptr": 1, "rdap": 1, "http": 2, "dns": 3, "sni": 4}
        cur = self.name_src.get(ip)
        if cur and rank.get(cur, 0) >= rank.get(src, 0) and ip in self.names:
            return  # keep the stronger existing name
        self.names[ip] = host
        self.name_src[ip] = src
        self._new_names.append({"ip": ip, "name": host, "src": src,
                                "cat": classify(host) if src in ("dns", "sni", "http") else ""})

    def set_enrichment(self, ip: str, *, name: str = "", name_src: str = "",
                       geo: dict | None = None) -> None:
        """Called by the async enricher (PTR/rdap/GeoIP)."""
        with self.lock:
            if name:
                self._set_name(ip, name, name_src or "ptr")
            if geo:
                self.geo[ip] = geo
                if geo.get("country"):
                    self.countries.add(geo["country"])
                self._new_geo.append({"ip": ip, **geo})

    # --- flows / devices -----------------------------------------------------
    def _update_flow(self, p: Packet, client, server, up) -> None:
        if up:
            key = _canon(p.src, p.sport, p.dst, p.dport, p.l4)
        else:
            key = _canon(p.dst, p.dport, p.src, p.sport, p.l4)
        f = self.flows.get(key)
        if not f:
            c_ip, c_port = (client or p.src), (p.sport if up else p.dport)
            s_ip = server or p.dst
            s_port = (p.dport if up else p.sport)
            f = Flow(key=str(key), client_ip=c_ip, client_port=c_port,
                     server_ip=s_ip, server_port=s_port, l4=p.l4,
                     first_ts=p.ts, last_ts=p.ts)
            self.flows[key] = f
            if len(self.flows) > FLOW_CAP:
                oldest = min(self.flows, key=lambda k: self.flows[k].last_ts)
                self.flows.pop(oldest, None)
        if p.col_proto:
            f.proto = p.col_proto
        if up:
            f.bytes_up += p.length
            f.pkts_up += 1
        else:
            f.bytes_down += p.length
            f.pkts_down += 1
        f.last_ts = p.ts
        self._dirty_flows.add(key)

    def _update_device(self, p: Packet, client, server, up) -> None:
        d = self.devices.get(client)
        if not d:
            d = Device(ip=client, first_ts=p.ts, last_ts=p.ts)
            self.devices[client] = d
            self._alert("info", "new_device", f"New device joined: {client}", client)
        if up and p.eth_src and not d.mac:
            d.mac = p.eth_src
        if p.ja3:
            d.ja3.add(p.ja3)
        if p.ja4:
            d.ja4.add(p.ja4)
        host = p.hostname()
        if host:
            d.domains.add(host)
            os = match_os(host)
            if os and not d.os:
                d.os = os
            for a in match_apps(host):
                d.apps.add(a)
            if classify(host) == "auth":
                d.logins.add(host)
        if up:
            d.bytes_up += p.length
        else:
            d.bytes_down += p.length
        d.last_ts = p.ts
        self._dirty_devs.add(client)

    def _update_stats(self, p: Packet) -> None:
        proto = p.col_proto or p.l4 or "other"
        self.proto_bytes[proto] = self.proto_bytes.get(proto, 0) + p.length
        cat = self.category_for(p.dst)
        if cat:
            self.cat_counts[cat] = self.cat_counts.get(cat, 0) + 1

    def _update_bw(self, p: Packet, client, up) -> None:
        b = int(p.ts) if p.ts else int(time.time())
        g = self.bw_global.setdefault(b, [0, 0])
        g[0 if up else 1] += p.length
        self._prune_bw(self.bw_global)
        if client:
            d = self.devices.get(client)
            if d is not None:
                db = d.bw.setdefault(b, [0, 0])
                db[0 if up else 1] += p.length
                self._prune_bw(d.bw)

    @staticmethod
    def _prune_bw(bw: dict) -> None:
        if len(bw) > BW_WINDOW + 8:
            cutoff = max(bw) - BW_WINDOW
            for k in [k for k in bw if k < cutoff]:
                bw.pop(k, None)

    def _ring_packet(self, p: Packet) -> None:
        rec = {"num": p.num, "ts": round(p.ts, 6), "src": p.src, "dst": p.dst,
               "sport": p.sport, "dport": p.dport, "proto": p.col_proto or p.l4,
               "len": p.length, "host": p.hostname()}
        self.packets.append(rec)
        self._new_pkts.append(rec)

    def _record_http(self, p: Packet, client) -> None:
        # Only real plaintext HTTP requests (method or host actually present).
        if not (p.http_method or (p.http_host and p.dport == 80)):
            return
        rec = {"ts": time.strftime("%H:%M:%S"), "client": client or p.src,
               "method": p.http_method, "host": p.http_host,
               "uri": p.http_uri, "ua": p.http_ua,
               "auth": bool(p.http_auth), "cookie": bool(p.http_cookie)}
        self.http.append(rec)
        self._new_http.append(rec)

    # --- alerts / detection --------------------------------------------------
    def _detect(self, p: Packet, client, server) -> None:
        host = p.hostname()
        # Cleartext credentials actually present on the wire.
        if p.http_auth:
            sig = (client, p.http_host, "auth-header")
            if sig not in self._alerted_creds:
                self._alerted_creds.add(sig)
                self._alert("high", "cleartext_creds",
                            f"Cleartext HTTP Authorization from {client} → {p.http_host or p.dst}",
                            client)
        # A login page fetched over plaintext HTTP (port 80) = creds at risk.
        if p.http_host and p.dport == 80 and classify(p.http_host) == "auth":
            sig = (client, p.http_host, "http-login")
            if sig not in self._alerted_creds:
                self._alerted_creds.add(sig)
                self._alert("high", "cleartext_login",
                            f"Login page over plaintext HTTP: {p.http_host} from {client}",
                            client)
        if host and host.lower().endswith(SUSPICIOUS_TLDS):
            self._alert("med", "suspicious_tld", f"{client} → {host}", client)
        # Port-scan heuristic: many distinct dest ports on one server, fast.
        if client and server and p.dport:
            k = (client, server)
            seen = self._scan.setdefault(k, {})
            seen[p.dport] = p.ts
            cutoff = p.ts - SCAN_WINDOW
            for port in [pt for pt, t in seen.items() if t < cutoff]:
                seen.pop(port, None)
            if len(seen) >= SCAN_DISTINCT_PORTS:
                self._alert("med", "port_scan",
                            f"Possible port scan: {client} hit {len(seen)} ports on {server}",
                            client)
                seen.clear()

    def _alert(self, sev: str, kind: str, msg: str, ip: str = "") -> None:
        a = {"ts": time.strftime("%H:%M:%S"), "sev": sev, "kind": kind,
             "msg": msg, "ip": ip}
        # De-dupe identical consecutive alerts (e.g. repeated suspicious_tld).
        if self.alerts and self.alerts[-1].get("msg") == msg:
            return
        self.alerts.append(a)
        self._new_alerts.append(a)

    # --- serialization -------------------------------------------------------
    def _flow_dict(self, f: Flow) -> dict:
        name = self.names.get(f.server_ip, "")
        return {
            "key": f.key, "client": f.client_ip, "cport": f.client_port,
            "server": f.server_ip, "sport": f.server_port, "l4": f.l4,
            "proto": f.proto, "name": name, "cat": self.category_for(f.server_ip),
            "up": f.bytes_up, "down": f.bytes_down,
            "pkts": f.pkts_up + f.pkts_down,
            "dur": round(max(0.0, f.last_ts - f.first_ts), 1),
            "last": f.last_ts, "src": self.name_src.get(f.server_ip, ""),
            "geo": self.geo.get(f.server_ip),
        }

    def _device_dict(self, d: Device) -> dict:
        return {
            "ip": d.ip, "mac": d.mac, "os": d.os,
            "apps": sorted(d.apps), "logins": sorted(d.logins),
            "domains": len(d.domains), "up": d.bytes_up, "down": d.bytes_down,
            "ja3": sorted(d.ja3), "ja4": sorted(d.ja4),
            "last": d.last_ts, "bw": self._bw_series(d.bw),
        }

    @staticmethod
    def _bw_series(bw: dict) -> list[list[int]]:
        if not bw:
            return []
        end = max(bw)
        return [[b, *bw.get(b, [0, 0])] for b in range(end - BW_WINDOW + 1, end + 1)
                if b in bw]

    def _stats(self) -> dict:
        up = int(time.time() - self.started)
        return {
            "devices": len(self.devices), "flows": len(self.flows),
            "domains": len(self.domains), "countries": len(self.countries),
            "packets": self.total_pkts, "bytes": self.total_bytes,
            "auth": self.cat_counts.get("auth", 0),
            "alerts": len(self.alerts), "uptime": up,
            "proto_bytes": dict(sorted(self.proto_bytes.items(),
                                       key=lambda kv: -kv[1])[:12]),
            "cat_counts": self.cat_counts,
            "bw_global": self._bw_series(self.bw_global),
        }

    def snapshot(self) -> dict:
        with self.lock:
            flows = sorted(self.flows.values(), key=lambda f: -f.last_ts)[:300]
            return {
                "type": "snapshot",
                "flows": [self._flow_dict(f) for f in flows],
                "devices": [self._device_dict(d) for d in self.devices.values()],
                "packets": list(self.packets),
                "http": list(self.http),
                "alerts": list(self.alerts),
                "names": [{"ip": k, "name": v, "src": self.name_src.get(k, "")}
                          for k, v in self.names.items()],
                "geo": [{"ip": k, **v} for k, v in self.geo.items()],
                "stats": self._stats(),
            }

    def drain_deltas(self) -> dict | None:
        with self.lock:
            if not (self._dirty_flows or self._dirty_devs or self._new_pkts
                    or self._new_alerts or self._new_names or self._new_geo
                    or self._new_http):
                return {"type": "tick", "stats": self._stats()}
            out = {
                "type": "delta",
                "flows": [self._flow_dict(self.flows[k]) for k in self._dirty_flows
                          if k in self.flows],
                "devices": [self._device_dict(self.devices[i]) for i in self._dirty_devs
                            if i in self.devices],
                "packets": self._new_pkts[-200:],
                "http": self._new_http[:],
                "alerts": self._new_alerts[:],
                "names": self._new_names[:],
                "geo": self._new_geo[:],
                "stats": self._stats(),
            }
            self._dirty_flows.clear(); self._dirty_devs.clear()
            self._new_pkts.clear(); self._new_alerts.clear()
            self._new_names.clear(); self._new_geo.clear()
            self._new_http.clear()
            return out

    def unnamed_dsts(self) -> list[str]:
        """Server IPs that have flows but no name yet, to feed the enricher."""
        with self.lock:
            out = []
            for f in self.flows.values():
                ip = f.server_ip
                if ip and ip not in self.names and ip not in self.geo \
                        and not self._is_client(ip):
                    out.append(ip)
            return out
