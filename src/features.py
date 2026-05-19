from __future__ import annotations
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

logger = logging.getLogger(__name__)

@dataclass
class FeatureBucket:
    packets: int = 0
    bytes_total: int = 0
    dst_ips: set = field(default_factory=set)
    dst_ports: set = field(default_factory=set)
    packet_sizes: list = field(default_factory=list)
    tcp_count: int = 0
    udp_count: int = 0
    dns_count: int = 0
    outbound: int = 0
    inbound: int = 0

def _window_key(timestamp, window_seconds):
    return int(timestamp // window_seconds)

def _bucket_to_row(device_ip, window_idx, b, window_seconds):
    window_start = datetime.fromtimestamp(window_idx * window_seconds, tz=timezone.utc)
    window_end   = datetime.fromtimestamp((window_idx + 1) * window_seconds, tz=timezone.utc)
    avg_pkt_size = sum(b.packet_sizes) / len(b.packet_sizes) if b.packet_sizes else 0.0
    total_proto  = b.tcp_count + b.udp_count
    tcp_ratio    = b.tcp_count / total_proto if total_proto > 0 else 0.0
    udp_ratio    = b.udp_count / total_proto if total_proto > 0 else 0.0
    out_in_ratio = b.outbound / max(b.inbound, 1)
    return {
        "device_ip": device_ip,
        "window_start": window_start,
        "window_end": window_end,
        "packet_count": b.packets,
        "byte_count": b.bytes_total,
        "unique_dst_ips": len(b.dst_ips),
        "unique_dst_ports": len(b.dst_ports),
        "avg_packet_size": round(avg_pkt_size, 2),
        "tcp_ratio": round(tcp_ratio, 4),
        "udp_ratio": round(udp_ratio, 4),
        "dns_count": b.dns_count,
        "outbound_inbound_ratio": round(out_in_ratio, 4),
    }

def extract_features(pcap_path, window_seconds=60, watched_devices=None):
    import pyshark
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(pcap_path)
    watched = set(watched_devices) if watched_devices else None
    buckets = defaultdict(lambda: defaultdict(FeatureBucket))
    capture = pyshark.FileCapture(str(pcap_path), keep_packets=False, tshark_path=r"D:\Wireshark\tshark.exe")
    try:
        for pkt in capture:
            try:
                if not hasattr(pkt, "ip"):
                    continue
                ts = float(pkt.sniff_timestamp)
                window_idx = _window_key(ts, window_seconds)
                src, dst, length = pkt.ip.src, pkt.ip.dst, int(pkt.length)
                for device_ip, is_src in ((src, True), (dst, False)):
                    if watched is not None and device_ip not in watched:
                        continue
                    b = buckets[device_ip][window_idx]
                    b.packets += 1
                    b.bytes_total += length
                    b.packet_sizes.append(length)
                    if is_src:
                        b.outbound += 1
                        b.dst_ips.add(dst)
                    else:
                        b.inbound += 1
                    if hasattr(pkt, "tcp"):
                        b.tcp_count += 1
                        if is_src:
                            try: b.dst_ports.add(int(pkt.tcp.dstport))
                            except: pass
                    elif hasattr(pkt, "udp"):
                        b.udp_count += 1
                        if is_src:
                            try: b.dst_ports.add(int(pkt.udp.dstport))
                            except: pass
                    if hasattr(pkt, "dns"):
                        b.dns_count += 1
            except AttributeError:
                continue
    finally:
        capture.close()
    rows = []
    for device_ip, windows in buckets.items():
        for window_idx, b in windows.items():
            rows.append(_bucket_to_row(device_ip, window_idx, b, window_seconds))
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(["device_ip", "window_start"]).reset_index(drop=True)
    return df

FEATURE_COLUMNS = [
    "packet_count", "byte_count", "unique_dst_ips", "unique_dst_ports",
    "avg_packet_size", "tcp_ratio", "udp_ratio", "dns_count",
    "outbound_inbound_ratio",
]
