"""HTTP + SSE server and the engine that wires everything together.

Endpoints:
  GET /                     -> web/index.html (+ static assets)
  GET /api/snapshot         -> full current state (initial load / reconnect)
  GET /stream               -> SSE: meta + ~2/s delta frames
  GET /api/packet?...       -> deep dissection (layer tree + hex) of one frame
  GET /api/export/flows.csv -> flows as CSV
  GET /api/export/pcap      -> newest recorded pcap (download)

Capture is live-or-replay only; there is no synthetic feed. On capture failure
the mode becomes "error" and the UI says so — it never shows fake activity.
"""

from __future__ import annotations

import csv
import io
import json
import queue
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import capture, enrich
from .state import MonitorState

HERE = Path(__file__).resolve().parent.parent
WEB_DIR = HERE / "web"
REC_DIR = Path("/tmp/lab_ap_gui")
REC_BASE = REC_DIR / "monitor.pcapng"

CTYPES = {".html": "text/html; charset=utf-8", ".css": "text/css",
          ".js": "application/javascript", ".json": "application/json",
          ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
          ".svg": "image/svg+xml"}


class EventBus:
    def __init__(self) -> None:
        self.subs: list[queue.Queue] = []
        self.lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    def publish(self, ev: dict) -> None:
        with self.lock:
            for q in list(self.subs):
                try:
                    q.put_nowait(ev)
                except queue.Full:
                    self.subs.remove(q)


class Engine:
    def __init__(self, args) -> None:
        self.args = args
        self.bus = EventBus()
        self.state = MonitorState(subnet=args.subnet, ap_ip=args.ap_ip)
        self.enricher = enrich.Enricher(self.state, do_ptr=not args.no_ptr,
                                        do_rdap=not args.no_rdap)
        self.mode = "starting"
        self.mode_msg = ""
        self.home = enrich.DEFAULT_HOME
        self.recorder: capture.Recorder | None = None
        self._live_proc = None

    # --- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        self.home = enrich.detect_home()
        self.enricher.start()
        threading.Thread(target=self._capture_loop, daemon=True).start()
        threading.Thread(target=self._flush_loop, daemon=True).start()

    def set_mode(self, mode: str, msg: str = "") -> None:
        self.mode, self.mode_msg = mode, msg
        enrich.log(f"[mode] {mode}{(' — ' + msg) if msg else ''}")
        self.bus.publish(self.meta())

    def meta(self) -> dict:
        return {"type": "meta", "mode": self.mode, "msg": self.mode_msg,
                "home": self.home}

    def bpf(self) -> str | None:
        # Scope capture to the lab subnet (all protocols/ports, both directions)
        # so we monitor every client conversation without the host's own noise.
        # In pcap-replay mode there's no live filter.
        return f"net {self.args.subnet}" if self.args.subnet else None

    def _capture_loop(self) -> None:
        a = self.args
        try:
            if a.iface:
                bpf = self.bpf()
                self.recorder = capture.Recorder(a.iface, REC_BASE, bpf=bpf)
                if self.recorder.start():
                    enrich.log(f"[rec] recording to {REC_BASE}")
                self.set_mode("live", f"capturing on {a.iface}")
                on_proc = lambda p: setattr(self, "_live_proc", p)
                for pkt in capture.live_packets(a.iface, bpf=bpf, on_proc=on_proc):
                    self.state.ingest(pkt)
            elif a.pcap:
                self.set_mode("replay", f"replaying {Path(a.pcap).name}")
                for pkt in capture.replay_packets(a.pcap):
                    self.state.ingest(pkt)
                self.set_mode("replay", "replay finished")
            else:
                self.set_mode("error", "no --iface or --pcap given")
        except capture.CaptureError as e:
            self.set_mode("error", str(e))
        except Exception as e:  # noqa: BLE001
            self.set_mode("error", f"capture failed: {e}")

    def _flush_loop(self) -> None:
        while True:
            time.sleep(0.5)
            delta = self.state.drain_deltas()
            if delta:
                self.bus.publish(delta)

    def stop(self) -> None:
        self.enricher.stop()
        if self.recorder:
            self.recorder.stop()
        if self._live_proc and self._live_proc.poll() is None:
            try:
                self._live_proc.terminate()
            except Exception:
                pass


def deep_packet(qs: dict) -> dict | None:
    """Dissect one recorded frame matching (ts, src, dst, ports) → tree + hex."""
    if not shutil.which("tshark"):
        return None
    ts = qs.get("ts", [""])[0]
    src = qs.get("src", [""])[0]
    dst = qs.get("dst", [""])[0]
    sport = qs.get("sport", [""])[0]
    try:
        t = float(ts)
    except ValueError:
        return None
    flt = f"frame.time_epoch>={t-0.02} && frame.time_epoch<={t+0.02}"
    if src and dst:
        flt += f" && ip.addr=={src} && ip.addr=={dst}"
    if sport.isdigit():
        flt += f" && (tcp.port=={sport} || udp.port=={sport})"
    files = sorted(REC_DIR.glob("monitor*.pcapng"), key=lambda p: -p.stat().st_mtime)[:2]
    for f in files:
        try:
            out = subprocess.run(
                ["tshark", "-r", str(f), "-Y", flt, "-T", "json", "-x"],
                capture_output=True, text=True, timeout=8)
            data = json.loads(out.stdout or "[]")
            if data:
                return data[0]
        except Exception:
            continue
    return None


class Handler(BaseHTTPRequestHandler):
    engine: Engine = None  # set before serving

    def log_message(self, *a):
        pass

    def _send(self, code: int, ctype: str, body: bytes, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self):
        u = urlparse(self.path)
        path, qs = u.path, parse_qs(u.query)
        if path == "/stream":
            return self._sse()
        if path == "/api/snapshot":
            body = json.dumps(self.engine.state.snapshot()).encode()
            return self._send(200, "application/json", body)
        if path == "/api/meta":
            return self._send(200, "application/json", json.dumps(self.engine.meta()).encode())
        if path == "/api/packet":
            res = deep_packet(qs)
            return self._send(200 if res else 404, "application/json",
                              json.dumps(res or {"error": "not found"}).encode())
        if path == "/api/export/flows.csv":
            return self._export_flows()
        if path == "/api/export/pcap":
            return self._export_pcap()
        return self._static(path)

    def _static(self, path: str):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        f = (WEB_DIR / rel).resolve()
        if not str(f).startswith(str(WEB_DIR)) or not f.is_file():
            return self._send(404, "text/plain", b"404")
        ctype = CTYPES.get(f.suffix, "application/octet-stream")
        self._send(200, ctype, f.read_bytes())

    def _export_flows(self):
        snap = self.engine.state.snapshot()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["client", "cport", "server", "sport", "l4", "proto",
                    "name", "category", "bytes_up", "bytes_down", "pkts", "dur_s"])
        for fl in snap["flows"]:
            w.writerow([fl["client"], fl["cport"], fl["server"], fl["sport"],
                        fl["l4"], fl["proto"], fl["name"], fl["cat"],
                        fl["up"], fl["down"], fl["pkts"], fl["dur"]])
        self._send(200, "text/csv", buf.getvalue().encode(),
                   {"Content-Disposition": "attachment; filename=flows.csv"})

    def _export_pcap(self):
        files = sorted(REC_DIR.glob("monitor*.pcapng"), key=lambda p: -p.stat().st_mtime)
        if not files:
            return self._send(404, "text/plain", b"no recording")
        self._send(200, "application/vnd.tcpdump.pcap", files[0].read_bytes(),
                   {"Content-Disposition": "attachment; filename=capture.pcapng"})

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = self.engine.bus.subscribe()
        try:
            self.wfile.write(f"data: {json.dumps(self.engine.meta())}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    ev = q.get(timeout=15)
                    self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        finally:
            self.engine.bus.unsubscribe(q)


def run(args) -> None:
    import os
    import signal
    engine = Engine(args)
    Handler.engine = engine
    engine.start()

    def _term(*_):
        # Tear down capture children (tshark/dumpcap) before exiting, so the
        # controller stopping us never strands a process on the radio.
        engine.stop()
        os._exit(0)
    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
        if sig is not None:
            try:
                signal.signal(sig, _term)
            except (ValueError, OSError):
                pass

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    enrich.log(f"[ops] monitor at http://{args.host}:{args.port}/")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        engine.stop()
