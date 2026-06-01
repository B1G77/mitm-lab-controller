#!/usr/bin/env python3
"""Ops Dashboard server — streams live network metadata to a browser.

A small stdlib HTTP server (no framework) that:
  * captures metadata on the AP interface (pyshark) OR replays a pcap OR runs
    a built-in demo feed,
  * enriches each destination with GeoIP (DB-IP / GeoLite2 .mmdb via geoip2),
  * categorises + fingerprints the same way the Tkinter Intelligence tab does,
  * pushes every event to the browser over Server-Sent Events (SSE).

Browser side (web/) renders a futuristic command-center: a 3D globe with arcs
from home to each destination, a neon packet feed, and live device cards.

Run:
  python3 ops_server.py --iface wlan0        # live capture (needs pyshark+tshark)
  python3 ops_server.py --pcap capture.pcap  # replay a saved capture
  python3 ops_server.py --demo               # synthetic feed, zero setup

With no working capture source it auto-falls back to --demo so the dashboard
always shows something. Open http://127.0.0.1:8777/ in a browser.
"""

from __future__ import annotations

import argparse
import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEB_DIR = HERE / "web"
GEOIP_DB = HERE / "geoip" / "dbip-city-lite.mmdb"
HOST, PORT = "127.0.0.1", 8777

# Origin point for every arc on the globe ("us" / the rogue AP). Change to your
# own location for a more accurate demo. Default: Lisbon, PT.
HOME = {"lat": 38.7223, "lon": -9.1393, "label": "ROGUE AP"}

# --- Shared intelligence rules (mirrors mitm_lab.py) ------------------------
INTEL_RULES = [
    ("auth", ["login", "signin", "sign-in", "accounts", "oauth", "/auth",
              "auth.", "sso", "logon"]),
    ("tracking", ["analytic", "tracking", "telemetry", "metric", "doubleclick",
                  "adservice", "ads.", "adsystem", "appsflyer", "sentry",
                  "crashlytic", "snplow", "segment", "mixpanel"]),
    ("media", ["spotify", "scdn", "youtube", "googlevideo", "discord", "netflix",
               "twitch", "vimeo", "soundcloud", "tiktok", "instagram"]),
    ("cdn", ["akamai", "akadns", "fastly", "cloudfront", "cloudflare", "edgekey",
             "gstatic", "googleapis", "gvt1", "apple.com", "icloud", "aaplimg"]),
]
OS_FINGERPRINTS = [
    ("Apple", ["apple.com", "icloud", "aaplimg", "itunes", "mzstatic",
               "push.apple", "cdn-apple", "apps.apple"]),
    ("Android", ["android.clients.google", "android.googleapis", "gvt1",
                 "play.googleapis", "googleusercontent", "connectivitycheck"]),
    ("Samsung", ["samsung"]),
    ("Windows", ["windowsupdate", "msftncsi", "msftconnecttest", "microsoft.com"]),
]
APP_FINGERPRINTS = [
    ("Spotify", ["spotify", "scdn"]), ("Discord", ["discord"]),
    ("YouTube", ["youtube", "googlevideo"]), ("Instagram", ["instagram", "cdninstagram"]),
    ("WhatsApp", ["whatsapp"]), ("TikTok", ["tiktok", "musical.ly"]),
    ("Netflix", ["netflix", "nflxvideo"]), ("Snapchat", ["snapchat", "sc-cdn"]),
    ("Facebook", ["facebook", "fbcdn"]), ("Twitch", ["twitch", "ttvnw"]),
]


def categorize(domain: str) -> str:
    d = domain.lower()
    for cat, keys in INTEL_RULES:
        if any(k in d for k in keys):
            return cat
    return "other"


def match_os(domain: str) -> str:
    d = domain.lower()
    for name, keys in OS_FINGERPRINTS:
        if any(k in d for k in keys):
            return name
    return ""


def match_apps(domain: str) -> list[str]:
    d = domain.lower()
    return [n for n, keys in APP_FINGERPRINTS if any(k in d for k in keys)]


# --- GeoIP -------------------------------------------------------------------
class GeoResolver:
    def __init__(self) -> None:
        self.reader = None
        try:
            import geoip2.database
            if GEOIP_DB.exists():
                self.reader = geoip2.database.Reader(str(GEOIP_DB))
                print(f"[geoip] using {GEOIP_DB}")
            else:
                print(f"[geoip] no DB at {GEOIP_DB} — arcs use sample coords only")
        except Exception as e:
            print(f"[geoip] geoip2 unavailable ({e}) — sample coords only")

    def locate(self, ip: str):
        if not self.reader:
            return None
        try:
            r = self.reader.city(ip)
            if r.location.latitude is None:
                return None
            return {"lat": r.location.latitude, "lon": r.location.longitude,
                    "country": r.country.iso_code or "??",
                    "city": r.city.name or ""}
        except Exception:
            return None


# --- SSE event bus -----------------------------------------------------------
class EventBus:
    def __init__(self) -> None:
        self.subs: list[queue.Queue] = []
        self.lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    def publish(self, event: dict) -> None:
        with self.lock:
            dead = []
            for q in self.subs:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self.subs.remove(q)


BUS = EventBus()
GEO = None        # set in main
CAPTURE_FILTER = "udp port 53 or tcp port 443 or tcp port 80"
AP_IP = None      # gateway IP to exclude from the feed

# Dedup: suppress the same (src, domain) seen again within this many seconds, so
# TCP retransmits and repeat lookups don't flood the feed/globe.
DEDUP_TTL = 20.0
_recent: dict = {}


def _is_dup(src: str, domain: str) -> bool:
    now = time.time()
    key = f"{src}|{domain}"
    last = _recent.get(key, 0)
    _recent[key] = now
    if len(_recent) > 4000:   # bound memory
        for k, t in list(_recent.items()):
            if now - t > DEDUP_TTL:
                _recent.pop(k, None)
    return (now - last) < DEDUP_TTL


def build_filter(subnet: str | None, ap_ip: str | None) -> str:
    """BPF: only client-originated DNS/TLS/HTTP in the AP subnet, never the AP
    itself. Keeps the dashboard to victim traffic instead of the whole host."""
    f = f"({CAPTURE_FILTER})"
    if subnet:
        f += f" and src net {subnet}"
    if ap_ip:
        f += f" and not src host {ap_ip}"
    return f


def emit(src: str, kind: str, domain: str) -> None:
    domain = domain.rstrip(".")
    cat = categorize(domain)
    event = {
        "ts": time.strftime("%H:%M:%S"),
        "src": src, "kind": kind, "domain": domain, "category": cat,
        "os": match_os(domain), "apps": match_apps(domain),
        "home": HOME,
    }
    return event


# --- Capture sources ---------------------------------------------------------
def run_live(iface: str) -> bool:
    """Live pyshark capture. Returns False if it can't start (caller falls back)."""
    try:
        import asyncio
        import pyshark
    except Exception as e:
        print(f"[live] pyshark/tshark missing: {e}")
        return False
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
        cap = pyshark.LiveCapture(interface=iface, bpf_filter=CAPTURE_FILTER)
        print(f"[live] capturing on {iface} :: {CAPTURE_FILTER}")
        for pkt in cap.sniff_continuously():
            _handle_pkt(pkt)
    except Exception as e:
        print(f"[live] failed: {e}")
        return False
    return True


def run_replay(pcap: str, pace: float = 0.15) -> bool:
    try:
        import asyncio
        import pyshark
    except Exception as e:
        print(f"[replay] pyshark/tshark missing: {e}")
        return False
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
        cap = pyshark.FileCapture(
            pcap, display_filter="dns or tls.handshake.extensions_server_name or http.host")
        print(f"[replay] reading {pcap}")
        for pkt in cap:
            _handle_pkt(pkt)
            time.sleep(pace)   # pace it so the globe animates like real time
        cap.close()
    except Exception as e:
        print(f"[replay] failed: {e}")
        return False
    return True


def _handle_pkt(pkt) -> None:
    try:
        names = {l.layer_name for l in pkt.layers}
        src = pkt.ip.src if "ip" in names else "?"
        dst = pkt.ip.dst if "ip" in names else None
        domain = kind = None
        if "dns" in names and hasattr(pkt.dns, "qry_name"):
            kind, domain = "DNS", pkt.dns.qry_name
        else:
            for ln in ("tls", "ssl"):
                if ln in names:
                    sni = getattr(getattr(pkt, ln),
                                  "handshake_extensions_server_name", None)
                    if sni:
                        kind, domain = "SNI", sni
                        break
            if not domain and "http" in names and hasattr(pkt.http, "host"):
                kind, domain = "HTTP", pkt.http.host
        if not domain:
            return
        if src == AP_IP or _is_dup(src, domain.rstrip(".")):
            return
        ev = emit(src, kind, domain)
        loc = GEO.locate(dst) if dst else None
        if loc:
            ev.update(loc)
        BUS.publish(ev)
    except Exception:
        pass


# Built-in demo feed — real domains from the project's own iPhone capture, with
# representative coordinates so the globe works with zero GeoIP setup.
DEMO = [
    ("192.168.50.2", "SNI", "api.spotify.com", 59.33, 18.06, "SE", "Stockholm"),
    ("192.168.50.2", "DNS", "gateway.discord.gg", 37.77, -122.42, "US", "San Francisco"),
    ("192.168.50.2", "SNI", "youtubei.googleapis.com", 37.42, -122.08, "US", "Mountain View"),
    ("192.168.50.2", "DNS", "login.dpgmedia.net", 52.37, 4.90, "NL", "Amsterdam"),
    ("192.168.50.2", "SNI", "amp-api-edge.apps.apple.com", 37.33, -122.03, "US", "Cupertino"),
    ("192.168.50.2", "DNS", "googleads.g.doubleclick.net", 37.42, -122.08, "US", "Mountain View"),
    ("192.168.50.2", "SNI", "o64374.ingest.sentry.io", 37.77, -122.42, "US", "San Francisco"),
    ("192.168.50.2", "DNS", "data.buienradar.nl", 52.09, 5.12, "NL", "Utrecht"),
    ("192.168.50.2", "SNI", "cdn.discordapp.com", 51.51, -0.13, "GB", "London"),
    ("192.168.50.3", "DNS", "android.googleapis.com", 37.42, -122.08, "US", "Mountain View"),
    ("192.168.50.3", "SNI", "redirector.googlevideo.com", 50.11, 8.68, "DE", "Frankfurt"),
    ("192.168.50.3", "DNS", "connectivitycheck.gstatic.com", 37.42, -122.08, "US", "Mountain View"),
    ("192.168.50.2", "SNI", "i.scdn.co", 59.33, 18.06, "SE", "Stockholm"),
    ("192.168.50.2", "DNS", "att.launches.appsflyersdk.com", 32.07, 34.78, "IL", "Tel Aviv"),
    ("192.168.50.2", "SNI", "register.appattest.apple.com", 37.33, -122.03, "US", "Cupertino"),
]


def run_demo() -> bool:
    print("[demo] synthetic feed (project's real captured domains)")
    i = 0
    while True:
        src, kind, dom, lat, lon, cc, city = DEMO[i % len(DEMO)]
        ev = emit(src, kind, dom)
        ev.update({"lat": lat, "lon": lon, "country": cc, "city": city})
        BUS.publish(ev)
        i += 1
        time.sleep(1.1)


def start_capture(args) -> None:
    def worker():
        ok = False
        if args.iface:
            ok = run_live(args.iface)
        elif args.pcap:
            ok = run_replay(args.pcap)
        if not ok and not args.demo:
            print("[capture] source unavailable — falling back to demo mode")
        if args.demo or not ok:
            run_demo()
    threading.Thread(target=worker, daemon=True).start()


# --- HTTP / SSE handler ------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        if self.path == "/stream":
            return self._sse()
        path = "index.html" if self.path in ("/", "") else self.path.lstrip("/")
        f = (WEB_DIR / path).resolve()
        if not str(f).startswith(str(WEB_DIR)) or not f.is_file():
            self.send_error(404)
            return
        ctype = ("text/html" if f.suffix == ".html" else
                 "text/css" if f.suffix == ".css" else
                 "application/javascript" if f.suffix == ".js" else
                 "application/octet-stream")
        data = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = BUS.subscribe()
        try:
            while True:
                try:
                    ev = q.get(timeout=15)
                    self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")   # heartbeat
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            BUS.unsubscribe(q)


def main():
    global GEO, CAPTURE_FILTER, AP_IP
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", help="capture live on this interface")
    ap.add_argument("--pcap", help="replay a saved pcap file")
    ap.add_argument("--demo", action="store_true", help="synthetic demo feed")
    ap.add_argument("--subnet", help="AP subnet (e.g. 192.168.50.0/24) — capture clients only")
    ap.add_argument("--ap-ip", dest="ap_ip", help="AP/gateway IP to exclude from the feed")
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()
    CAPTURE_FILTER = build_filter(args.subnet, args.ap_ip)
    AP_IP = args.ap_ip
    GEO = GeoResolver()
    start_capture(args)
    srv = ThreadingHTTPServer((HOST, args.port), Handler)
    print(f"[ops] dashboard at http://{HOST}:{args.port}/  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[ops] stopped")


if __name__ == "__main__":
    main()
