"""Normalised data model + classification rules for the monitor engine.

A `Packet` is the single normalised record every capture source produces, so
the rest of the engine never has to know whether it came from a live `tshark`
stream, a pcap replay, or a test fixture. Everything downstream (flows,
devices, stats, alerts) is built from these.

Nothing in here fabricates data: a field is `None`/empty when the packet did
not actually carry it. Classification only labels what was really observed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# --- Classification rules ----------------------------------------------------
# Each is a (label, substrings) pair matched case-insensitively against a host
# name. These describe observed destinations only; they never invent traffic.
CATEGORY_RULES = [
    ("auth", ["login", "signin", "sign-in", "accounts", "oauth", "/auth",
              "auth.", "sso", "logon", "id.", "identity"]),
    ("tracking", ["analytic", "tracking", "telemetry", "metric", "doubleclick",
                  "adservice", "ads.", "adsystem", "appsflyer", "sentry",
                  "crashlytic", "snplow", "segment", "mixpanel", "amplitude",
                  "googletagmanager", "scorecardresearch", "branch.io"]),
    ("media", ["spotify", "scdn", "youtube", "googlevideo", "discord", "netflix",
               "twitch", "vimeo", "soundcloud", "tiktok", "instagram", "nflxvideo",
               "cdninstagram", "fbcdn"]),
    ("cdn", ["akamai", "akadns", "fastly", "cloudfront", "cloudflare", "edgekey",
             "gstatic", "googleapis", "gvt1", "apple.com", "icloud", "aaplimg",
             "amazonaws", "azureedge", "edgesuite"]),
]
OS_FINGERPRINTS = [
    ("Apple", ["apple.com", "icloud", "aaplimg", "itunes", "mzstatic",
               "push.apple", "cdn-apple", "apps.apple", "appattest"]),
    ("Android", ["android.clients.google", "android.googleapis", "gvt1",
                 "play.googleapis", "googleusercontent", "connectivitycheck",
                 "android.pool.ntp"]),
    ("Samsung", ["samsung"]),
    ("Windows", ["windowsupdate", "msftncsi", "msftconnecttest", "microsoft.com",
                 "windows.com", "live.com"]),
    ("Linux", ["ubuntu.com", "debian.org", "archlinux", "canonical"]),
]
APP_FINGERPRINTS = [
    ("Spotify", ["spotify", "scdn"]), ("Discord", ["discord"]),
    ("YouTube", ["youtube", "googlevideo"]), ("Instagram", ["instagram", "cdninstagram"]),
    ("WhatsApp", ["whatsapp"]), ("TikTok", ["tiktok", "musical.ly"]),
    ("Netflix", ["netflix", "nflxvideo"]), ("Snapchat", ["snapchat", "sc-cdn"]),
    ("Facebook", ["facebook", "fbcdn"]), ("Twitch", ["twitch", "ttvnw"]),
    ("Telegram", ["telegram", "t.me"]), ("Reddit", ["reddit", "redd.it"]),
    ("Gmail", ["mail.google", "gmail"]), ("iMessage", ["imessage", "courier.push.apple"]),
]
# Top-level domains that are disproportionately abused; flagged, not blocked.
SUSPICIOUS_TLDS = (".zip", ".mov", ".tk", ".gq", ".top", ".xyz", ".cam",
                   ".click", ".country", ".kim", ".work", ".party")


def classify(host: str) -> str:
    h = (host or "").lower()
    for cat, keys in CATEGORY_RULES:
        if any(k in h for k in keys):
            return cat
    return "other"


def match_os(host: str) -> str:
    h = (host or "").lower()
    for name, keys in OS_FINGERPRINTS:
        if any(k in h for k in keys):
            return name
    return ""


def match_apps(host: str) -> list[str]:
    h = (host or "").lower()
    return [n for n, keys in APP_FINGERPRINTS if any(k in h for k in keys)]


# --- Normalised packet -------------------------------------------------------
@dataclass
class Packet:
    """One observed frame, normalised. Empty fields mean 'not present'."""
    num: int = 0
    ts: float = 0.0
    length: int = 0
    protocols: str = ""        # frame.protocols, e.g. eth:ethertype:ip:tcp:tls
    col_proto: str = ""        # human label, e.g. "TLSv1.3", "DNS", "QUIC"
    src: str = ""
    dst: str = ""
    sport: Optional[int] = None
    dport: Optional[int] = None
    l4: str = ""               # "TCP" | "UDP" | ""
    eth_src: str = ""          # client MAC when src is a client
    eth_dst: str = ""
    # Application layer (only set when genuinely present on the wire)
    dns_qry: str = ""
    dns_answers: list[str] = field(default_factory=list)
    sni: str = ""
    http_host: str = ""
    http_method: str = ""
    http_uri: str = ""
    http_ua: str = ""
    http_auth: str = ""        # cleartext Authorization header, if any
    http_cookie: str = ""
    ja3: str = ""
    ja4: str = ""

    def hostname(self) -> str:
        """The single most authoritative host this packet names, if any."""
        return self.sni or self.http_host or self.dns_qry or ""
