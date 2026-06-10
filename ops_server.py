#!/usr/bin/env python3
"""MITM Monitor — entrypoint for the passive analyst console.

Thin launcher around the `engine` package. Captures live on an interface (the
rogue AP's, so it sees every client's traffic) or replays a real pcap, builds a
live flow/device/intel picture, enriches destinations, and serves a multi-view
web console over HTTP + SSE.

There is NO synthetic/demo feed: with --iface it captures live and reports an
explicit error on failure; with --pcap it replays real captured packets.

Run:
  python3 ops_server.py --iface wlan0 --subnet 192.168.50.0/24 --ap-ip 192.168.50.1
  python3 ops_server.py --pcap /tmp/lab_ap_gui/monitor.pcapng

Open http://127.0.0.1:8777/ in a browser.
"""

from __future__ import annotations

import argparse

from engine import server


def main() -> None:
    ap = argparse.ArgumentParser(description="MITM passive monitor")
    ap.add_argument("--iface", help="capture live on this interface")
    ap.add_argument("--pcap", help="replay a real saved pcap instead of capturing")
    ap.add_argument("--subnet", help="AP subnet, e.g. 192.168.50.0/24 (scopes capture to clients)")
    ap.add_argument("--ap-ip", dest="ap_ip", help="AP/gateway IP (excluded as a client)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--no-ptr", action="store_true", help="disable reverse-DNS enrichment")
    ap.add_argument("--no-rdap", action="store_true", help="disable rdap/ASN-owner enrichment")
    args = ap.parse_args()
    server.run(args)


if __name__ == "__main__":
    main()
