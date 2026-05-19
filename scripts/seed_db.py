"""Seed a demo SQLite database for the dashboard.

Run from the project root:
    python scripts/seed_db.py

Creates 14 IoT devices (mix of nicknames), ~2 weeks of 60-second feature
windows per device, and anomalies sprinkled in for the worst offenders.
"""
from __future__ import annotations
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make project root importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config import load_config
from src.database import Database


random.seed(42)


DEVICES = [
    ("192.168.1.42",  "thermostat",   "compromised"),
    ("192.168.1.18",  "doorbell",     "normal"),
    ("192.168.1.87",  "router",       "suspicious"),
    ("192.168.1.55",  "tv",           "normal"),
    ("192.168.1.103", "printer",      "medium"),
    ("192.168.1.201", "cam-back",     "normal"),
    ("192.168.1.33",  "nas",          "normal"),
    ("192.168.1.77",  "speaker",      "normal"),
    ("192.168.1.12",  "lights-hub",   "normal"),
    ("192.168.1.99",  "fridge",       "normal"),
    ("192.168.1.145", "smart-lock",   "normal"),
    ("192.168.1.220", "cam-front",    "normal"),
    ("192.168.1.8",   "gateway",      "normal"),
    ("192.168.1.65",  "smart-plug",   "normal"),
]


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def gen_window(device_ip: str, profile: str, t0: datetime, is_anomaly: bool):
    """Generate one feature window. Returns (row_dict, anomaly_score_or_None)."""
    base = {
        "thermostat":  dict(pkt=1500, byte=900_000,  dst_ip=4, dst_p=8,  apsz=520, tcp=0.80, udp=0.15, dns=14, oi=1.2),
        "doorbell":    dict(pkt=400,  byte=120_000,  dst_ip=2, dst_p=4,  apsz=380, tcp=0.85, udp=0.10, dns=8,  oi=1.0),
        "router":      dict(pkt=3000, byte=2_400_000,dst_ip=8, dst_p=12, apsz=720, tcp=0.55, udp=0.40, dns=40, oi=0.8),
        "tv":          dict(pkt=4500, byte=3_600_000,dst_ip=6, dst_p=10, apsz=860, tcp=0.92, udp=0.05, dns=18, oi=1.8),
        "printer":     dict(pkt=200,  byte=80_000,   dst_ip=2, dst_p=3,  apsz=480, tcp=0.70, udp=0.25, dns=6,  oi=0.7),
        "cam-back":    dict(pkt=2200, byte=2_100_000,dst_ip=2, dst_p=4,  apsz=950, tcp=0.30, udp=0.65, dns=10, oi=2.2),
        "nas":         dict(pkt=1800, byte=1_400_000,dst_ip=3, dst_p=6,  apsz=780, tcp=0.95, udp=0.02, dns=4,  oi=0.5),
        "speaker":     dict(pkt=600,  byte=240_000,  dst_ip=3, dst_p=5,  apsz=450, tcp=0.75, udp=0.20, dns=12, oi=1.1),
        "lights-hub":  dict(pkt=350,  byte=95_000,   dst_ip=2, dst_p=4,  apsz=290, tcp=0.65, udp=0.30, dns=6,  oi=0.9),
        "fridge":      dict(pkt=200,  byte=60_000,   dst_ip=1, dst_p=2,  apsz=320, tcp=0.80, udp=0.15, dns=5,  oi=0.8),
        "smart-lock":  dict(pkt=120,  byte=40_000,   dst_ip=1, dst_p=2,  apsz=340, tcp=0.85, udp=0.10, dns=4,  oi=0.6),
        "cam-front":   dict(pkt=2100, byte=1_900_000,dst_ip=2, dst_p=4,  apsz=920, tcp=0.32, udp=0.62, dns=9,  oi=2.0),
        "gateway":     dict(pkt=5000, byte=3_800_000,dst_ip=12,dst_p=18, apsz=760, tcp=0.50, udp=0.45, dns=60, oi=0.9),
        "smart-plug":  dict(pkt=150,  byte=50_000,   dst_ip=1, dst_p=2,  apsz=330, tcp=0.78, udp=0.18, dns=5,  oi=0.7),
    }
    nickname = next((n for ip, n, _ in DEVICES if ip == device_ip), "thermostat")
    b = base.get(nickname, base["thermostat"])
    jitter = lambda v, j=0.15: max(0, int(v * (1 + random.uniform(-j, j))))
    jf = lambda v, j=0.10: max(0.0, v * (1 + random.uniform(-j, j)))

    # Default (normal) values; anomaly kinds override fields below.
    pkt   = jitter(b["pkt"])
    byts  = jitter(b["byte"])
    dst   = max(1, jitter(b["dst_ip"], 0.3))
    dst_p = max(1, jitter(b["dst_p"], 0.25))
    apsz  = jf(b["apsz"])
    tcp   = jf(b["tcp"], 0.06)
    udp   = jf(b["udp"], 0.10)
    dns   = max(0, jitter(b["dns"], 0.4))
    oi    = jf(b["oi"], 0.2)
    score = random.uniform(0.02, 0.28)

    if is_anomaly:
        kind = random.choice(["fanout", "dns", "udp", "payload"])
        if kind == "fanout":
            pkt = jitter(b["pkt"] * random.uniform(3, 6), 0.2)
            dst = max(b["dst_ip"], int(b["dst_ip"] * random.uniform(3, 5)))
            byts = jitter(b["byte"] * random.uniform(2, 4), 0.2)
            score = random.uniform(-0.45, -0.20)
        elif kind == "dns":
            pkt = jitter(b["pkt"] * random.uniform(2, 3))
            byts = jitter(b["byte"] * random.uniform(1.5, 2.5))
            dns = b["dns"] * random.randint(6, 10)
            score = random.uniform(-0.35, -0.18)
        elif kind == "udp":
            pkt = jitter(b["pkt"] * random.uniform(1.5, 2.5))
            byts = jitter(b["byte"] * random.uniform(1.5, 3))
            tcp = max(0.05, b["tcp"] * 0.4)
            udp = min(0.90, b["udp"] + 0.5)
            score = random.uniform(-0.30, -0.15)
        else:  # payload
            byts = jitter(b["byte"] * random.uniform(4, 8), 0.25)
            apsz = jf(b["apsz"] * 2.5, 0.2)
            score = random.uniform(-0.42, -0.16)

    row = {
        "device_ip": device_ip,
        "window_start": iso(t0),
        "window_end": iso(t0 + timedelta(seconds=60)),
        "packet_count": pkt,
        "byte_count": byts,
        "unique_dst_ips": dst,
        "unique_dst_ports": dst_p,
        "avg_packet_size": apsz,
        "tcp_ratio": tcp,
        "udp_ratio": udp,
        "dns_count": dns,
        "outbound_inbound_ratio": oi,
        "anomaly_score": score,
    }
    return row, (score if is_anomaly else None)


def main():
    cfg = load_config()
    db_path = cfg["database"]["path"]
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    # Wipe for a clean reseed
    if Path(db_path).exists():
        Path(db_path).unlink()
    db = Database(db_path)

    now = datetime.now(timezone.utc)
    window_count = 0
    anomaly_count = 0

    # Insert devices
    with db._conn() as c:
        for ip, nick, _ in DEVICES:
            first = now - timedelta(days=random.randint(20, 90))
            c.execute(
                "INSERT INTO devices (ip, first_seen, last_seen, nickname) "
                "VALUES (?, ?, ?, ?)",
                (ip, iso(first), iso(now), nick),
            )

    threshold = cfg["model"]["alert_threshold"]

    with db._conn() as c:
        # Generate ~14 days × 60min × ~12 windows/hr per device
        # but condense: ~600 windows per device spread across last 7 days.
        windows_per_device = 600
        for ip, nick, profile in DEVICES:
            for i in range(windows_per_device):
                # Spread across 14 days, denser recent
                age_hours = (1 - (i / windows_per_device) ** 1.5) * 14 * 24
                t = now - timedelta(hours=age_hours, minutes=random.uniform(0, 1))

                # Anomaly probability by profile
                p_anomaly = {
                    "compromised": 0.035 if age_hours < 18 else 0.005,
                    "suspicious":  0.015 if age_hours < 24 else 0.003,
                    "medium":      0.005,
                    "normal":      0.0008,
                }[profile]
                is_anom = random.random() < p_anomaly

                w, score = gen_window(ip, nick, t, is_anom)
                cur = c.execute("""
                    INSERT INTO feature_windows
                    (device_ip, window_start, window_end, packet_count, byte_count,
                     unique_dst_ips, unique_dst_ports, avg_packet_size, tcp_ratio,
                     udp_ratio, dns_count, outbound_inbound_ratio, anomaly_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    w["device_ip"], w["window_start"], w["window_end"],
                    w["packet_count"], w["byte_count"],
                    w["unique_dst_ips"], w["unique_dst_ports"],
                    w["avg_packet_size"], w["tcp_ratio"], w["udp_ratio"],
                    w["dns_count"], w["outbound_inbound_ratio"],
                    w["anomaly_score"],
                ))
                window_count += 1
                if is_anom and score is not None and score < threshold:
                    # severity
                    if score < threshold - 0.20: sev = "CRITICAL"
                    elif score < threshold - 0.05: sev = "HIGH"
                    elif score < threshold: sev = "MEDIUM"
                    else: sev = "LOW"
                    notes = _gen_note(score, w)
                    c.execute("""
                        INSERT INTO anomalies (device_ip, window_id, detected_at,
                                               score, severity, notes)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        w["device_ip"], cur.lastrowid, w["window_start"],
                        score, sev, notes,
                    ))
                    anomaly_count += 1

    # Add a few sample comments and one mute, so collab features have content
    with db._conn() as c:
        an = c.execute("SELECT id, device_ip FROM anomalies "
                       "ORDER BY id DESC LIMIT 5").fetchall()
        if an:
            db.add_comment(an[0]["id"], "sam@",
                           "Looks like the same shape as last Tuesday's false positive — was an OTA?")
            db.add_comment(an[0]["id"], "priya@",
                           "@sam doubt it — OTA never hits these 17 IPs. Pulled pcap; looks real.")
            db.add_comment(an[0]["id"], "sam@", "Agreed. Drafting writeup tonight.")
        # Sample mute
        db.add_action("192.168.1.103", "mute_1h", "kai@",
                      expires_at=iso(now + timedelta(hours=1)))

    print(f"✓ Seeded {db_path}")
    print(f"  {len(DEVICES)} devices · {window_count:,} windows · {anomaly_count} anomalies")
    print(f"  Threshold: {threshold:+.2f}")
    print(f"\nRun the dashboard with:\n  streamlit run src/dashboard.py")


def _gen_note(score: float, w: dict) -> str:
    notes_pool = [
        f"unusual outbound spike → {w['unique_dst_ips']} new dst IPs",
        f"DNS volume {w['dns_count']}× normal baseline",
        f"TCP/UDP ratio shifted to {w['tcp_ratio']:.2f}/{w['udp_ratio']:.2f}",
        f"packet count {w['packet_count']:,} (well above baseline)",
        f"large payload to unknown host, avg size {w['avg_packet_size']:.0f}B",
        f"sustained UDP fan-out, out/in {w['outbound_inbound_ratio']:.2f}",
    ]
    return random.choice(notes_pool)


if __name__ == "__main__":
    main()
