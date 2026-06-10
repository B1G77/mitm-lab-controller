"""Passive network-monitoring engine for the MITM lab.

Capture (tshark) → normalise → state (flows/devices/naming/stats/alerts) →
enrich (geo/ptr/rdap) → HTTP+SSE server. Live or real-pcap only; no synthetic
data. See engine.server.run().
"""
