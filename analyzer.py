from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _safe(value: Any, fallback: str = "-") -> str:
    return str(value) if value not in (None, "") else fallback


def packet_to_record(packet: Any, index: int) -> dict[str, Any]:
    """Convert a Scapy packet into the normalized shape used by the dashboard."""
    record: dict[str, Any] = {
        "no": index,
        "time": datetime.fromtimestamp(float(packet.time), tz=timezone.utc),
        "src": "-",
        "dst": "-",
        "protocol": "OTHER",
        "length": len(packet),
        "src_port": "-",
        "dst_port": "-",
        "info": packet.summary(),
    }

    if packet.haslayer("IP"):
        ip = packet["IP"]
        record["src"] = _safe(ip.src)
        record["dst"] = _safe(ip.dst)
        record["protocol"] = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.proto, f"IP/{ip.proto}")
    elif packet.haslayer("IPv6"):
        ip6 = packet["IPv6"]
        record["src"] = _safe(ip6.src)
        record["dst"] = _safe(ip6.dst)
        record["protocol"] = {6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(ip6.nh, f"IPv6/{ip6.nh}")
    elif packet.haslayer("ARP"):
        record["src"] = _safe(packet["ARP"].psrc)
        record["dst"] = _safe(packet["ARP"].pdst)
        record["protocol"] = "ARP"

    for layer_name in ("TCP", "UDP"):
        if packet.haslayer(layer_name):
            layer = packet[layer_name]
            record["src_port"] = int(layer.sport)
            record["dst_port"] = int(layer.dport)
            break

    return record


def read_capture(file_path: str | Path) -> list[dict[str, Any]]:
    """Read a pcap or pcapng file through Scapy."""
    from scapy.all import rdpcap

    packets = rdpcap(str(file_path))
    return [packet_to_record(packet, index) for index, packet in enumerate(packets, start=1)]


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    total_bytes = sum(int(record["length"]) for record in records)
    protocols = Counter(record["protocol"] for record in records)
    conversations = Counter(
        tuple(sorted((record["src"], record["dst"]))) for record in records if record["src"] != "-"
    )
    sources = Counter(record["src"] for record in records if record["src"] != "-")
    destinations = Counter(record["dst"] for record in records if record["dst"] != "-")
    return {
        "packets": len(records),
        "bytes": total_bytes,
        "protocols": protocols,
        "conversations": conversations,
        "sources": sources,
        "destinations": destinations,
    }


def demo_records() -> list[dict[str, Any]]:
    """Return deterministic traffic so the UI is useful before a capture is available."""
    rows = [
        ("10.0.0.24", "142.250.72.14", "TCP", 443, 51124, 1460, "TLS application data"),
        ("10.0.0.24", "1.1.1.1", "UDP", 53, 55120, 96, "DNS query A api.example.com"),
        ("10.0.0.24", "1.1.1.1", "UDP", 53, 55121, 178, "DNS response A api.example.com"),
        ("10.0.0.24", "52.96.12.8", "TCP", 443, 51125, 890, "TLS application data"),
        ("10.0.0.24", "10.0.0.1", "ICMP", "-", "-", 98, "Echo request"),
        ("10.0.0.1", "10.0.0.24", "ICMP", "-", "-", 98, "Echo reply"),
        ("10.0.0.24", "224.0.0.251", "UDP", 5353, 5353, 142, "mDNS query _services._dns-sd._udp.local"),
        ("10.0.0.24", "10.0.0.42", "TCP", 22, 49830, 128, "SSH handshake"),
    ]
    now = datetime.now(tz=timezone.utc)
    return [
        {
            "no": index,
            "time": now,
            "src": src,
            "dst": dst,
            "protocol": protocol,
            "length": length,
            "src_port": src_port,
            "dst_port": dst_port,
            "info": info,
        }
        for index, (src, dst, protocol, dst_port, src_port, length, info) in enumerate(rows, start=1)
    ]
