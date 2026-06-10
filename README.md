# MITM Lab Controller + Monitor

A Tkinter **controller** for running an Evil Twin access point on Linux, paired
with a web **Monitor** — a passive traffic-analysis console. The controller
wires together `hostapd`, `dhcpd`, and `iptables` to stand up a fake Wi-Fi AP,
lease addresses to clients, and NAT their traffic upstream. Because the AP is
the gateway, it sees every client's traffic; the Monitor turns that into a live,
multi-view picture (flows, devices, DNS, TLS, HTTP, packets, a geo globe). It is
for learning and explaining man-in-the-middle attacks on networks you own.

> **Honest by design:** the Monitor only labels what it actually observes. A
> flow is named from a real DNS answer / TLS SNI / HTTP Host (or a reverse-DNS /
> rdap owner lookup); anything it can't trace stays a raw IP, uncategorised and
> un-highlighted. There is no synthetic/demo data anywhere.

---

## Quick start

Linux only (Kali/Debian), on bare metal or a VM with a **real** AP-capable Wi-Fi
adapter passed through (the radio cannot be virtual).

```bash
git clone https://github.com/B1G77/mitm-lab-controller.git
cd mitm-lab-controller
./setup.sh     # auto-elevates with sudo; installs ALL deps + globe + GeoIP DB
./run.sh       # launches the controller (handles sudo + X11 for you)
```

Then in the app: fill in your interfaces → **Start AP** → connect a device →
**📊 Open Monitor**. That's it. `setup.sh` is safe to re-run and installs the
system packages, the Python GeoIP reader, the offline 3D-globe library, and the
GeoIP database, then grants capture rights.

Want to explore without a radio? Replay any real pcap:

```bash
python3 ops_server.py --pcap /path/to/capture.pcap   # then open http://127.0.0.1:8777/
```

---

## What I did

I started from a working prototype and reworked the parts that broke or felt
slow.

I fixed four real bugs. The DHCP pool used to start at the AP's own gateway
address, so a client could be handed the router's IP and collide with it. Now
the pool starts one address above the gateway. Every log line printed twice
because the code both pushed lines to the console and tailed the log file that
already held them. I made the log file the single source of truth and let the
GUI tail it once. The Bettercap launcher hardcoded `192.168.50.0/24` as its ARP
target, so changing the AP subnet pointed the spoof at the wrong network. It now
reads the subnet from whatever I configured. The form accepted any text and
threw raw tracebacks on bad input, so I added validation.

I made the app responsive. Starting the AP runs about seven seconds of interface
bring-up and daemon launches, and the old version ran all of it on the UI
thread, so the window froze the whole time. I moved Start and Stop onto worker
threads. The buttons disable while work runs, and a status LED reports
`STARTING`, `LIVE`, then `OFFLINE`. I replaced the one-second log poll with a
queue that the GUI drains every 100 ms, and I moved the `iw station dump` call
off the UI thread too.

I rebuilt the look. The whole window now uses a dark theme instead of just the
log box. The console color-codes its lines: commands in blue, errors in red,
"LAB LIVE" in green, warnings in yellow. Connected clients used to print as a
monospace text dump. I turned that into a live table that refreshes every four
seconds and shows each station's MAC, leased IP, signal in dBm, a strength bar,
and device name, colored by signal quality. A status strip across the top tracks
AP state, client count, and a running uptime clock.

I verified the pure logic on Windows, then ran the tool on a Kali VM with the
TP-Link adapter described below. hostapd kept dropping `wlan0` right after it
enabled the AP (`INTERFACE-DISABLED`, then `Failed to set beacon parameters`),
because `wpa_supplicant` still held the radio. I made Start kill
`wpa_supplicant`, unblock rfkill, and set the regulatory domain before launching
hostapd. The AP stays up now.

---

## Requirements

- Linux, on bare metal or a VM with USB passthrough. The radio cannot be virtual.
- Root, since the tool reconfigures interfaces, the firewall, and services.
- A Wi-Fi adapter that supports AP mode. I use a TP-Link AC1300; see the exact
  setup below.

### Dependencies

`./setup.sh` installs everything below for you. To do it by hand instead:

```bash
sudo apt update
sudo apt install -y hostapd isc-dhcp-server iw iptables python3-tk \
                    wireshark-common tshark tcpdump curl
pip3 install -r requirements.txt --break-system-packages
```

The MITM Tools buttons also want `bettercap` and the `qterminal` terminal
emulator. The web **Monitor** needs `tshark` and `dumpcap` (both ship with
Wireshark) for live capture and recording, and the offline globe + GeoIP assets
(`bash web/fetch_libs.sh` and `bash download_geoip.sh`).

---

## Setup on Linux with the TP-Link AC1300 adapter

The adapter I use is the **TP-Link AC1300 Mini Wi-Fi MU-MIMO USB 3.0**, sold as
the **Archer T3U**. Its chipset is the **Realtek RTL8812BU**. These steps get it
from plugged-in to running the AP on any Debian or Kali based Linux.

### 1. Pass the adapter to the machine

On a VM, attach the USB device to the guest first (VirtualBox: Devices → USB →
TP-Link; VMware: VM → Removable Devices). Set the VM's USB controller to 3.0
(xHCI). Then confirm Linux sees the Realtek chip:

```bash
lsusb | grep -i realtek
```

You want a line with ID `0bda:b812` (RTL8812BU). A TP-Link `2357:...` ID means
it is still in CD-ROM/modeswitch mode; replug it or run `usb_modeswitch`.

### 2. Confirm the driver loaded

```bash
iw dev
```

If a wireless interface (`wlan0` or similar) appears, the driver is loaded and
you can skip to step 3. Kali's kernel already had it for me. If no wireless
interface shows up, install the RTL8812BU driver via DKMS:

```bash
sudo apt install -y dkms git build-essential bc
git clone https://github.com/morrownr/88x2bu-20210702.git
cd 88x2bu-20210702
sudo ./install-driver.sh
```

Reboot when it prompts, then run `iw dev` again.

To prove which interface is the TP-Link (vs a built-in card), check the driver
behind each one:

```bash
for d in /sys/class/net/wl*; do echo "$(basename $d) -> $(readlink -f $d/device/driver | xargs basename)"; done
```

The TP-Link shows driver `88x2bu`. Note its interface name; use it as the AP
Interface in the GUI.

### 3. Confirm AP mode

```bash
iw list | grep -A 10 "Supported interface modes"
```

The list must include `* AP`. On my adapter it shows `IBSS`, `managed`, `AP`,
`AP/VLAN`, and `monitor`. If `* AP` is missing, the driver will not run hostapd
and the AP will never start.

> You do not need monitor mode for this tool. hostapd uses AP mode and switches
> the interface itself. Leave the adapter in its normal state.

### 4. Free the radio (the tool does this for you)

hostapd fails with `INTERFACE-DISABLED` / `Failed to set beacon parameters` if
NetworkManager or `wpa_supplicant` keep hold of the interface. Start handles this
automatically, and deliberately does NOT stop NetworkManager (that killed eth0's
internet and often needed a reboot to recover). Instead it sets only `wlan0`
unmanaged, stops the `wpa_supplicant` service, unblocks rfkill, and sets the
regulatory domain. eth0 keeps internet the whole time; Stop hands `wlan0` back.

If you ever test hostapd by hand, run the same prep first:

```bash
sudo nmcli device set wlan0 managed no
sudo systemctl stop wpa_supplicant
sudo pkill -9 wpa_supplicant
sudo rfkill unblock all
sudo iw reg set US
sudo ip link set wlan0 up
# when done, return it to NetworkManager:
sudo nmcli device set wlan0 managed yes
```

### 5. Run it

```bash
cd ~/Desktop/MITM
sudo python3 mitm_lab.py
```

Set **AP Interface** to the TP-Link's interface (`wlan0` here) and **Internet
Iface** to the uplink that has real connectivity (`eth0` on my VM). Hit
**Start AP** and watch for `AP-ENABLED` in the log. Connect a phone to the SSID;
it should pull a `192.168.50.x` lease, appear in the client table, and reach the
internet through the uplink.

### Other adapters

Any card with `* AP` in `iw list` works. Built-in Intel cards often do. Known
USB options include the Atheros AR9271 (`ath9k_htc`, in-kernel, also does
monitor), Ralink RT5370, and MT7612U.

---

## Running it

```bash
sudo python3 mitm_lab.py
```

It needs root. Runtime files land in `/tmp/lab_ap_gui/`.

If the window does not open under `sudo` (`couldn't connect to display`), allow
root to reach your X session once, then relaunch:

```bash
xhost +SI:localuser:root
sudo python3 mitm_lab.py
```

---

## Using the interface

### 1. Setup Parameters

| Field | Meaning | Example |
|---|---|---|
| SSID (Fake) | Network name the AP broadcasts | `eduroam_lab` |
| Channel | 2.4 GHz channel, 1 to 14 | `6` |
| AP Interface | Wireless iface that becomes the AP | `wlan0` |
| Internet Iface | Upstream iface with real internet | `eth0` |
| AP IP | Gateway IP of the lab network | `192.168.50.1` |
| CIDR | Subnet size | `24` |
| DHCP End | Last octet of the pool's end address | `50` |
| DNS | DNS server handed to clients | `8.8.8.8` |

The pool runs from AP IP plus one up to the DHCP End address. With the defaults
that gives `192.168.50.2` through `192.168.50.50`, which keeps clients off the
gateway's own address. The form validates everything before it touches the
hardware.

### 2. MITM Tools

- Wireshark opens a live capture on the AP interface.
- TCPDump opens a terminal that writes to `/tmp/lab_ap_gui/lab_capture.pcap`.
- Bettercap (ARP) starts an ARP-spoof and sniff session against the subnet I
  configured.
- Open Monitor launches the web analyst console (see below) and opens it in a
  browser.
- Clear Log wipes the console and the on-disk log.

The Tkinter app is now purely the **controller**: stand up the AP, watch
clients, launch tools. All traffic analysis lives in the web Monitor.

---

## Monitor — the web analyst console

`ops_server.py` is a separate web console fed by a live capture on the AP
interface (which, as the gateway, sees every client's traffic). The Tkinter app
stays the control panel; the Monitor is where I actually analyse what I
intercept. It is split into a small `engine/` package:

- **capture** — streams `tshark -T ek` into normalised packets (live or
  real-pcap replay); a `dumpcap` ring-buffer records to `monitor.pcapng` for
  export and deep inspection.
- **state** — builds the live picture: flow/conversation table, per-device
  bandwidth, protocol stats, a packet ring, alerts, and the **correlation
  engine** — an `IP → host` map learned from observed DNS answers and TLS SNI,
  so a raw HTTPS flow to a bare IP gets truthfully labelled with the name the
  device actually resolved.
- **enrich** — for destinations we still couldn't name, a background worker
  adds offline GeoIP coordinates plus a reverse-DNS (PTR) and rdap/ASN owner
  lookup. Genuinely unknown IPs are left bare — nothing is invented.
- **server** — stdlib HTTP + Server-Sent Events; deltas stream at ~2 Hz.

**There is no demo feed.** With `--iface` it captures live and reports an
explicit `CAPTURE ERROR` in the UI if it can't; with `--pcap` it replays real
captured packets. If a flow can't be traced to a name, it stays a raw IP and is
never colour-highlighted or categorised.

### Views (left rail)

| View | Shows |
|---|---|
| Overview | throughput, protocol donut, category mix, top talkers, alerts |
| Flows | every conversation: client → server, proto, bytes ↑↓, packets, duration |
| Devices | per-device cards: MAC, inferred OS/apps, logins, bandwidth sparkline |
| DNS | resolved hosts → addresses, how each was learned (dns/sni/http/ptr/rdap) |
| TLS | JA3/JA4 client fingerprints per device + named SNI connections |
| HTTP | cleartext requests the AP can read, with credential/cookie flags |
| Packets | recent-frame ring; click a row for full dissection + hex dump |
| Geo | 3D globe with a glowing arc from the AP to every geolocated destination |

Export buttons (top right) download the current flows as CSV or the recorded
pcap.

### Setup

`./setup.sh` already handled all of this (tshark/dumpcap, the GeoIP reader, the
offline globe library, the GeoIP database, and capture privileges). When the
controller launches the Monitor it runs as root, so capture just works.

### Run it

```bash
python3 ops_server.py --iface wlan0 --subnet 192.168.50.0/24 --ap-ip 192.168.50.1
python3 ops_server.py --pcap /tmp/lab_ap_gui/monitor.pcapng   # replay a real capture
```

Then open `http://127.0.0.1:8777/`. The AP marker on the globe is geolocated
from the host's own public IP automatically.

---

## Can I run it in WSL?

The window opens in WSL, but the AP does not work there.

WSL2 is a lightweight VM behind a virtual NAT adapter. It never touches the
physical Wi-Fi radio and exposes no `wlan0`. `hostapd` needs a real wireless
interface in AP mode through the `nl80211` driver, and WSL2 has none. Passing a
USB dongle through `usbipd-win` does not fix it.

For UI testing in WSL, install `python3-tk` and run the script. The network
commands no-op or fail without harm. For real lab work I boot a native Kali or
Ubuntu install.

---

## Runtime files

Everything sits under `/tmp/lab_ap_gui/`:

- `hostapd.conf`, `dhcpd.conf`: generated configs
- `dhcpd.leases`: active leases
- `lab_ap.log`: full activity log, tailed by the GUI
- `lab_capture.pcap`: TCPDump output
- `monitor.pcapng`: Monitor's `dumpcap` ring-buffer recording (export + deep inspect)
- `ops_server.log`: Monitor engine log
- `pids/`: daemon PID files for clean shutdown
