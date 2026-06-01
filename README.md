# MITM Lab Controller

I built a single-file Tkinter front-end for running an Evil Twin access point on
Linux. It wires together `hostapd`, `dhcpd`, and `iptables` to stand up a fake
Wi-Fi AP, lease addresses to clients, and route their traffic upstream through
NAT so I can capture and study it. I use it to learn how man-in-the-middle
attacks actually work and to explain them.

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

```bash
sudo apt update
sudo apt install -y hostapd isc-dhcp-server iw iptables python3-tk
```

The MITM Tools buttons also want `wireshark`, `tcpdump`, `bettercap`, and the
`qterminal` terminal emulator.

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
NetworkManager or `wpa_supplicant` keep hold of the interface. Start now handles
this automatically: it stops NetworkManager, kills `wpa_supplicant`, runs
`rfkill unblock all`, and sets the regulatory domain before launching hostapd.

If you ever test hostapd by hand, run the same prep first:

```bash
sudo systemctl stop NetworkManager
sudo pkill wpa_supplicant
sudo rfkill unblock all
sudo iw reg set US
sudo ip link set wlan0 up
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
- Ops Dashboard launches the web command center (see below) and opens it in a
  browser.
- Clear Log wipes the console and the on-disk log.

### Intelligence tab

A second tab captures metadata on the AP interface with pyshark and surfaces it
live. Modern traffic is HTTPS, so I monitor behaviour, not content: which hosts
each device contacts (DNS + TLS SNI), color-coded by category (auth, tracking,
media, cdn). A Device Profiles panel infers each device's OS and apps from the
hostnames it reaches and flags login events. Needs `tshark` and `pyshark`.

---

## Ops Dashboard (the showcase view)

`ops_server.py` is a separate, futuristic web command center fed by the same
metadata. The Tkinter app stays the control panel; the dashboard is the screen
I present. A small stdlib HTTP server captures (or replays) traffic, enriches
each destination IP with offline GeoIP, and streams events to the browser over
Server-Sent Events. The page renders a rotating 3D globe (globe.gl) with a
glowing arc from the rogue AP to every destination's real location, a neon
packet feed, live device cards, and counters.

### One-time setup

```bash
pip install pyshark geoip2 --break-system-packages   # capture + GeoIP
bash web/fetch_libs.sh        # bundle the globe library locally (offline-safe)
bash download_geoip.sh        # free DB-IP City Lite database, no account
```

### Run it

```bash
python3 ops_server.py --iface wlan0     # live, alongside a running AP
python3 ops_server.py --pcap /tmp/lab_ap_gui/bettercap_sniff.pcap   # replay
python3 ops_server.py --demo            # synthetic feed, zero setup
```

Then open `http://127.0.0.1:8777/`. If pyshark or tshark are missing, the
server falls back to the demo feed automatically, so the dashboard always shows
activity — useful when live devices are quiet during a presentation. The arc
origin (the "home" point) is the `HOME` constant near the top of
`ops_server.py`; change its lat/lon to your location.

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
- `pids/`: daemon PID files for clean shutdown
