"""Pure-logic tests for the monitor engine — run anywhere, no tshark needed.

    python -m pytest tests/         # or:  python tests/test_engine.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.capture import parse_ek_line
from engine.model import classify, match_apps, match_os
from engine.state import MonitorState


def _ek(layers: dict) -> str:
    return json.dumps({"timestamp": "1700000000000", "layers": layers})


DNS = _ek({
    "frame_number": ["10"], "frame_time_epoch": ["1700000000.123"],
    "frame_len": ["120"], "frame_protocols": ["eth:ethertype:ip:udp:dns"],
    "eth_src": ["aa:bb:cc:dd:ee:ff"], "ip_src": ["192.168.50.2"],
    "ip_dst": ["8.8.8.8"], "udp_srcport": ["54321"], "udp_dstport": ["53"],
    "_ws_col_Protocol": ["DNS"], "dns_qry_name": ["api.spotify.com"],
    "dns_a": ["35.186.224.25"],
})
TLS = _ek({
    "frame_number": ["11"], "frame_time_epoch": ["1700000001.0"],
    "frame_len": ["583"], "frame_protocols": ["eth:ethertype:ip:tcp:tls"],
    "ip_src": ["192.168.50.2"], "ip_dst": ["35.186.224.25"],
    "tcp_srcport": ["44512"], "tcp_dstport": ["443"],
    "_ws_col_Protocol": ["TLSv1.3"],
    "tls_handshake_extensions_server_name": ["api.spotify.com"],
})
HTTP_AUTH = _ek({
    "frame_number": ["12"], "frame_time_epoch": ["1700000002.0"],
    "frame_len": ["300"], "ip_src": ["192.168.50.3"], "ip_dst": ["93.184.216.34"],
    "tcp_srcport": ["51000"], "tcp_dstport": ["80"], "_ws_col_Protocol": ["HTTP"],
    "http_host": ["login.example.com"], "http_request_method": ["POST"],
    "http_request_uri": ["/auth"], "http_authorization": ["Basic dXNlcjpwYXNz"],
})


def test_parse_dns():
    p = parse_ek_line(DNS)
    assert p and p.dns_qry == "api.spotify.com"
    assert p.dns_answers == ["35.186.224.25"]
    assert p.l4 == "UDP" and p.dport == 53 and p.src == "192.168.50.2"


def test_parse_index_and_garbage():
    assert parse_ek_line('{"index":{"_index":"x"}}') is None
    assert parse_ek_line("") is None
    assert parse_ek_line("not json {") is None


def test_classification():
    assert classify("login.example.com") == "auth"
    assert classify("googleads.g.doubleclick.net") == "tracking"
    assert match_apps("api.spotify.com") == ["Spotify"]
    assert match_os("connectivitycheck.gstatic.com") == "Android"
    assert classify("104.18.0.1") == "other"  # bare IP: no fabricated category


def test_naming_engine_labels_raw_flow():
    """A TLS flow to a bare IP gets named once DNS/SNI is observed."""
    st = MonitorState(subnet="192.168.50.0/24", ap_ip="192.168.50.1")
    st.ingest(parse_ek_line(DNS))
    st.ingest(parse_ek_line(TLS))
    assert st.names["35.186.224.25"] == "api.spotify.com"
    snap = st.snapshot()
    flow = next(f for f in snap["flows"] if f["server"] == "35.186.224.25")
    assert flow["name"] == "api.spotify.com"
    assert flow["cat"] == "media"
    dev = next(d for d in snap["devices"] if d["ip"] == "192.168.50.2")
    assert "Spotify" in dev["apps"]
    assert dev["mac"] == "aa:bb:cc:dd:ee:ff"


def test_unnamed_flow_stays_raw():
    """No DNS/SNI seen → flow is left as a bare IP, uncategorised."""
    st = MonitorState(subnet="192.168.50.0/24", ap_ip="192.168.50.1")
    raw = _ek({"frame_number": ["1"], "frame_time_epoch": ["1700000003.0"],
               "frame_len": ["200"], "ip_src": ["192.168.50.4"],
               "ip_dst": ["203.0.113.9"], "tcp_srcport": ["40000"],
               "tcp_dstport": ["443"], "_ws_col_Protocol": ["TCP"]})
    st.ingest(parse_ek_line(raw))
    snap = st.snapshot()
    flow = next(f for f in snap["flows"] if f["server"] == "203.0.113.9")
    assert flow["name"] == "" and flow["cat"] == ""
    assert "203.0.113.9" in st.unnamed_dsts()


def test_cleartext_creds_alert():
    st = MonitorState(subnet="192.168.50.0/24", ap_ip="192.168.50.1")
    st.ingest(parse_ek_line(HTTP_AUTH))
    kinds = {a["kind"] for a in st.snapshot()["alerts"]}
    assert "cleartext_creds" in kinds


def test_bandwidth_and_direction():
    st = MonitorState(subnet="192.168.50.0/24", ap_ip="192.168.50.1")
    st.ingest(parse_ek_line(TLS))            # up from client
    snap = st.snapshot()
    dev = next(d for d in snap["devices"] if d["ip"] == "192.168.50.2")
    assert dev["up"] == 583 and dev["down"] == 0
    assert snap["stats"]["bytes"] == 583


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run()
