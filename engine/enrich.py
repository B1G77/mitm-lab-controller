"""Enrichment: turn bare destination IPs into truthful labels + coordinates.

Three real, external-but-passive lookups, all cached and rate-limited:
  * GeoIP   — offline DB-IP/GeoLite2 .mmdb (lat/lon/city/country)
  * PTR     — reverse DNS (the host's own claimed name)
  * rdap    — IP registry owner/ASN org (e.g. "Cloudflare, Inc.")

These only ever run for IPs we could NOT name from observed DNS/SNI/HTTP, so a
flow is labelled from the strongest real evidence available and genuinely
unknown IPs are left bare. Nothing is synthesised.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
GEOIP_DB = HERE / "geoip" / "dbip-city-lite.mmdb"

DEFAULT_HOME = {"lat": 38.7223, "lon": -9.1393, "label": "ROGUE AP"}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class GeoResolver:
    def __init__(self) -> None:
        self.reader = None
        try:
            import geoip2.database
            if GEOIP_DB.exists():
                self.reader = geoip2.database.Reader(str(GEOIP_DB))
                log(f"[geoip] using {GEOIP_DB}")
            else:
                log(f"[geoip] no DB at {GEOIP_DB} — destinations have no coords")
        except Exception as e:  # geoip2 missing
            log(f"[geoip] geoip2 unavailable ({e})")

    def locate(self, ip: str) -> dict | None:
        if not self.reader or not ip:
            return None
        try:
            r = self.reader.city(ip)
            if r.location.latitude is None:
                return None
            return {"lat": r.location.latitude, "lon": r.location.longitude,
                    "country": r.country.iso_code or "", "city": r.city.name or ""}
        except Exception:
            return None


def ptr_lookup(ip: str) -> str:
    try:
        socket.setdefaulttimeout(2.5)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


def rdap_org(ip: str) -> str:
    """Registry owner/ASN org for an IP via rdap.org (no key). Best-effort."""
    try:
        with urllib.request.urlopen(f"https://rdap.org/ip/{ip}", timeout=4) as r:
            d = json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return ""
    name = d.get("name") or ""
    for ent in d.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        if "registrant" in roles or "administrative" in roles:
            for item in (ent.get("vcardArray", [None, []])[1] or []):
                if isinstance(item, list) and item and item[0] == "fn" and len(item) > 3:
                    return item[3]
    return name


def detect_home() -> dict:
    """Geolocate the host's own public IP so the globe's AP marker sits at the
    real location. Uses free ip-api.com; eth0 stays online while the AP runs."""
    try:
        url = "http://ip-api.com/json/?fields=status,lat,lon,city,countryCode"
        with urllib.request.urlopen(url, timeout=4) as r:
            d = json.loads(r.read().decode())
        if d.get("status") == "success" and d.get("lat") is not None:
            city = d.get("city") or ""
            log(f"[geo] AP located via public IP: {city} ({d['lat']:.2f},{d['lon']:.2f})")
            return {"lat": d["lat"], "lon": d["lon"],
                    "label": f"AP · {city}" if city else "ROGUE AP",
                    "city": city, "country": d.get("countryCode", "")}
    except Exception as e:
        log(f"[geo] public-IP lookup failed ({e}); using default HOME")
    return dict(DEFAULT_HOME)


class Enricher:
    """Background worker: pulls unnamed destinations from state and enriches
    them with geo + PTR + rdap, then hands results back via set_enrichment."""

    def __init__(self, state, *, do_ptr=True, do_rdap=True, per_cycle=8) -> None:
        self.state = state
        self.geo = GeoResolver()
        self.do_ptr, self.do_rdap = do_ptr, do_rdap
        self.per_cycle = per_cycle
        self.done: set[str] = set()
        self._stop = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                todo = [ip for ip in self.state.unnamed_dsts() if ip not in self.done][:self.per_cycle]
                for ip in todo:
                    self.done.add(ip)
                    self._enrich_one(ip)
            except Exception:
                pass
            self._stop.wait(2.0)

    def _enrich_one(self, ip: str) -> None:
        geo = self.geo.locate(ip)
        name, src = "", ""
        if self.do_ptr:
            name = ptr_lookup(ip)
            src = "ptr"
        if not name and self.do_rdap:
            org = rdap_org(ip)
            if org:
                name, src = org, "rdap"
        if name or geo:
            self.state.set_enrichment(ip, name=name, name_src=src, geo=geo)
