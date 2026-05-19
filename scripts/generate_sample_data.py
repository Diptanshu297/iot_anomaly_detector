from __future__ import annotations
import argparse, logging, random, sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

PROFILES = {
    "camera": {
        "ip": "192.168.1.50",
        "cloud_servers": ["54.230.1.10", "52.84.150.20"],
        "dns_server": "8.8.8.8",
        "packets_per_minute": 240,
        "avg_payload_bytes": 800,
        "dns_per_minute": 2,
    },
    "thermostat": {
        "ip": "192.168.1.51",
        "cloud_servers": ["35.190.40.5"],
        "dns_server": "8.8.8.8",
        "packets_per_minute": 4,
        "avg_payload_bytes": 120,
        "dns_per_minute": 1,
    },
}

def _normal_packet(profile, ts, outbound):
    cloud = random.choice(profile["cloud_servers"])
    src, dst = (profile["ip"], cloud) if outbound else (cloud, profile["ip"])
    sport    = random.randint(40000, 60000) if outbound else 443
    dport    = 443 if outbound else random.randint(40000, 60000)
    size     = max(60, int(random.gauss(profile["avg_payload_bytes"], 100)))
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A") / Raw(b"x" * size)
    pkt.time = ts
    return pkt

def _dns_packet(profile, ts):
    pkt = (IP(src=profile["ip"], dst=profile["dns_server"])
           / UDP(sport=random.randint(40000, 60000), dport=53)
           / DNS(rd=1, qd=DNSQR(qname="api.example-cloud.com")))
    pkt.time = ts
    return pkt

def _attack_packet(profile, ts):
    target = (f"{random.randint(1,223)}.{random.randint(0,255)}."
              f"{random.randint(0,255)}.{random.randint(0,255)}")
    dport  = random.choice([23, 22, 2323, 80])
    pkt = (IP(src=profile["ip"], dst=target)
           / TCP(sport=random.randint(40000, 60000), dport=dport, flags="S")
           / Raw(b"x" * 40))
    pkt.time = ts
    return pkt

def generate(output_path, minutes, start_time, include_attack=False, attack_minutes=5):
    packets   = []
    start_ts  = start_time.timestamp()
    for second in range(minutes * 60):
        ts_base = start_ts + second
        for profile in PROFILES.values():
            rate = profile["packets_per_minute"] / 60.0
            n    = max(0, int(random.gauss(rate, rate * 0.3)))
            for _ in range(n):
                ts = ts_base + random.random()
                packets.append(_normal_packet(profile, ts, random.random() < 0.6))
            if random.random() < profile["dns_per_minute"] / 60.0:
                packets.append(_dns_packet(profile, ts_base + random.random()))
    if include_attack:
        camera       = PROFILES["camera"]
        attack_start = start_ts + (minutes - attack_minutes) * 60
        attack_end   = start_ts + minutes * 60
        for second in range(int(attack_end - attack_start)):
            for _ in range(50):
                packets.append(_attack_packet(camera, attack_start + second + random.random()))
        logger.info("Injected %d-minute attack burst", attack_minutes)
    packets.sort(key=lambda p: float(p.time))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    logger.info("Wrote %d packets to %s (%.1f MB)",
                len(packets), output_path, output_path.stat().st_size / 1024 / 1024)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes",        type=int,  default=30)
    ap.add_argument("--include-attack", action="store_true")
    ap.add_argument("--attack-minutes", type=int,  default=3)
    ap.add_argument("--output",         type=Path,
                    default=PROJECT_ROOT / "data" / "raw" / "synthetic.pcap")
    args = ap.parse_args()
    generate(
        output_path=args.output,
        minutes=args.minutes,
        start_time=datetime.utcnow() - timedelta(minutes=args.minutes),
        include_attack=args.include_attack,
        attack_minutes=args.attack_minutes,
    )

if __name__ == "__main__":
    main()
