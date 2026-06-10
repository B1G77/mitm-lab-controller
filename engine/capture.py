"""Capture sources: turn tshark output into normalised `Packet` objects.

Two live-ish sources (a real interface, or a pcap replay) plus the EK-line
parser they share. The parser is pure and unit-tested on any OS; only the
subprocess launchers need tshark + Linux.

We stream tshark's Elasticsearch (`-T ek`) output: one JSON object per line,
two lines per packet (an `index` line we skip and a `layers` line we parse).
This is markedly faster and lighter than per-packet pyshark objects.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Iterator

from .model import Packet

# tshark -e fields we request, in EK these become dot->underscore keys.
EK_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "_ws.col.Protocol",
    "dns.qry.name", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ja3", "tls.handshake.ja4",
    "http.host", "http.request.method", "http.request.uri",
    "http.user_agent", "http.authorization", "http.cookie",
]


class CaptureError(RuntimeError):
    pass


def tshark_path() -> str:
    p = shutil.which("tshark")
    if not p:
        raise CaptureError("tshark not found on PATH (install wireshark/tshark).")
    return p


def _build_cmd(*, iface: str | None, pcap: str | None, bpf: str | None) -> list[str]:
    cmd = [tshark_path(), "-l", "-n", "-T", "ek"]
    if iface:
        cmd += ["-i", iface]
        if bpf:
            cmd += ["-f", bpf]
    elif pcap:
        cmd += ["-r", pcap]
    for f in EK_FIELDS:
        cmd += ["-e", f]
    return cmd


def _first(d: dict, key: str) -> str:
    """EK values are arrays of strings; return the first or ''."""
    v = d.get(key)
    if isinstance(v, list):
        return str(v[0]) if v else ""
    return str(v) if v not in (None, "") else ""


def _all(d: dict, key: str) -> list[str]:
    v = d.get(key)
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)] if v not in (None, "") else []


def _to_int(s: str) -> int | None:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def parse_ek_line(line: str) -> Packet | None:
    """Parse one EK JSON line into a Packet, or None for index/blank lines.

    Tolerant by design: malformed or non-layer lines yield None rather than
    raising, so one bad frame never stops the capture.
    """
    line = line.strip()
    if not line or '"layers"' not in line:
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    layers = obj.get("layers")
    if not isinstance(layers, dict):
        return None
    # Normalise keys to lowercase so case differences (e.g. col_Protocol) match.
    lay = {k.lower(): v for k, v in layers.items()}

    src = _first(lay, "ip_src") or _first(lay, "ipv6_src")
    dst = _first(lay, "ip_dst") or _first(lay, "ipv6_dst")
    sport = _to_int(_first(lay, "tcp_srcport") or _first(lay, "udp_srcport"))
    dport = _to_int(_first(lay, "tcp_dstport") or _first(lay, "udp_dstport"))
    l4 = "TCP" if "tcp_srcport" in lay else "UDP" if "udp_srcport" in lay else ""

    return Packet(
        num=_to_int(_first(lay, "frame_number")) or 0,
        ts=float(_first(lay, "frame_time_epoch") or 0.0),
        length=_to_int(_first(lay, "frame_len")) or 0,
        protocols=_first(lay, "frame_protocols"),
        col_proto=_first(lay, "_ws_col_protocol"),
        src=src, dst=dst, sport=sport, dport=dport, l4=l4,
        eth_src=_first(lay, "eth_src"), eth_dst=_first(lay, "eth_dst"),
        dns_qry=_first(lay, "dns_qry_name"),
        dns_answers=_all(lay, "dns_a") + _all(lay, "dns_aaaa"),
        sni=_first(lay, "tls_handshake_extensions_server_name"),
        http_host=_first(lay, "http_host"),
        http_method=_first(lay, "http_request_method"),
        http_uri=_first(lay, "http_request_uri"),
        http_ua=_first(lay, "http_user_agent"),
        http_auth=_first(lay, "http_authorization"),
        http_cookie=_first(lay, "http_cookie"),
        ja3=_first(lay, "tls_handshake_ja3"),
        ja4=_first(lay, "tls_handshake_ja4"),
    )


def _stream(cmd: list[str], pace: float = 0.0, on_proc=None) -> Iterator[Packet]:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, bufsize=1)
    if on_proc:
        on_proc(proc)
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            pkt = parse_ek_line(line)
            if pkt is not None:
                yield pkt
                if pace:
                    import time
                    time.sleep(pace)
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


def live_packets(iface: str, bpf: str | None = None, on_proc=None) -> Iterator[Packet]:
    """Yield packets captured live on `iface`. Raises CaptureError if tshark
    cannot start at all (caller turns that into an explicit error state)."""
    cmd = _build_cmd(iface=iface, pcap=None, bpf=bpf)
    probe = subprocess.run([tshark_path(), "-D"], capture_output=True, text=True)
    if probe.returncode != 0 and "permission" in (probe.stderr or "").lower():
        raise CaptureError("tshark lacks capture permission — run with sudo or "
                           "add yourself to the 'wireshark' group.")
    yield from _stream(cmd, on_proc=on_proc)


def replay_packets(pcap: str, pace: float = 0.08, on_proc=None) -> Iterator[Packet]:
    """Yield packets from a real saved pcap, paced so the UI animates."""
    if not Path(pcap).is_file():
        raise CaptureError(f"pcap not found: {pcap}")
    yield from _stream(_build_cmd(iface=None, pcap=pcap, bpf=None), pace=pace, on_proc=on_proc)


class Recorder:
    """Background pcap recorder (dumpcap ring buffer) for export + deep packet
    inspection. Independent of the live EK stream; both passively read the same
    interface. No-op if dumpcap is missing."""

    def __init__(self, iface: str, out: Path, bpf: str | None = None,
                 ring_mb: int = 50, ring_files: int = 4) -> None:
        self.iface, self.out, self.bpf = iface, out, bpf
        self.ring_mb, self.ring_files = ring_mb, ring_files
        self.proc: subprocess.Popen | None = None

    def start(self) -> bool:
        exe = shutil.which("dumpcap")
        if not exe:
            return False
        self.out.parent.mkdir(parents=True, exist_ok=True)
        cmd = [exe, "-i", self.iface, "-w", str(self.out), "-n",
               "-b", f"filesize:{self.ring_mb * 1024}", "-b", f"files:{self.ring_files}"]
        if self.bpf:
            cmd += ["-f", self.bpf]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        self.proc = None
