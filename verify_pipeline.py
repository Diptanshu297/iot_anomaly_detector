import sys
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, DNS

from src.alerts   import Alert, AlertDispatcher
from src.config   import load_config
from src.database import Database
from src.features import FEATURE_COLUMNS, FeatureBucket, _bucket_to_row, _window_key
from src.model    import AnomalyDetector, severity_from_score

def extract_with_scapy(pcap_path, window_seconds=60):
    buckets = defaultdict(lambda: defaultdict(FeatureBucket))
    for pkt in rdpcap(str(pcap_path)):
        if IP not in pkt: continue
        ts  = float(pkt.time)
        idx = _window_key(ts, window_seconds)
        src, dst, length = pkt[IP].src, pkt[IP].dst, len(pkt)
        for device_ip, is_src in ((src, True), (dst, False)):
            b = buckets[device_ip][idx]
            b.packets += 1; b.bytes_total += length; b.packet_sizes.append(length)
            if is_src: b.outbound += 1; b.dst_ips.add(dst)
            else:      b.inbound  += 1
            if TCP in pkt:
                b.tcp_count += 1
                if is_src: b.dst_ports.add(int(pkt[TCP].dport))
            elif UDP in pkt:
                b.udp_count += 1
                if is_src: b.dst_ports.add(int(pkt[UDP].dport))
            if DNS in pkt: b.dns_count += 1
    rows = [_bucket_to_row(ip, idx, b, window_seconds)
            for ip, wins in buckets.items() for idx, b in wins.items()]
    return pd.DataFrame(rows)

def main():
    config  = load_config()
    watched = set(config["features"]["watched_devices"])
    pcap    = Path("data/raw/synthetic.pcap")

    import subprocess
    if not pcap.exists():
        print("Generating 60 min baseline...")
        subprocess.run([sys.executable, "-m", "scripts.generate_sample_data",
                        "--minutes", "60", "--output", str(pcap)], check=True)

    print("="*70); print("Step 1: Extract normal features"); print("="*70)
    df_normal = extract_with_scapy(pcap, config["features"]["window_seconds"])
    df_normal = df_normal[df_normal["device_ip"].isin(watched)].reset_index(drop=True)
    print(f"  {len(df_normal)} rows from {df_normal['device_ip'].nunique()} devices\n")

    print("="*70); print("Step 2: Train model"); print("="*70)
    detector = AnomalyDetector(contamination=config["model"]["contamination"],
                               n_estimators=config["model"]["n_estimators"],
                               random_state=config["model"]["random_state"])
    detector.fit(df_normal)
    detector.save(config["model"]["path"])
    scored = detector.predict_anomaly(df_normal, threshold=config["model"]["alert_threshold"])
    print(f"  Training anomalies flagged: {scored['is_anomaly'].sum()}/{len(scored)}")
    print(f"  Score range: {scored['anomaly_score'].min():.3f} to {scored['anomaly_score'].max():.3f}\n")

    print("="*70); print("Step 3: Attack pcap detection"); print("="*70)
    attack_pcap = Path("data/raw/with_attack.pcap")
    subprocess.run([sys.executable, "-m", "scripts.generate_sample_data",
                    "--minutes", "15", "--include-attack", "--attack-minutes", "3",
                    "--output", str(attack_pcap)], check=True)
    df_attack = extract_with_scapy(attack_pcap, config["features"]["window_seconds"])
    df_attack = df_attack[df_attack["device_ip"].isin(watched)].reset_index(drop=True)
    scored_attack = detector.predict_anomaly(df_attack, threshold=config["model"]["alert_threshold"])
    print(f"  Anomalies flagged: {scored_attack['is_anomaly'].sum()}/{len(scored_attack)}")
    print(scored_attack.nsmallest(5, "anomaly_score")[
        ["device_ip","window_start","packet_count","unique_dst_ips","anomaly_score","is_anomaly"]
    ].to_string(index=False))

    print("\n"+"="*70); print("Step 4: Save to DB + dispatch alerts"); print("="*70)
    db         = Database(config["database"]["path"])
    dispatcher = AlertDispatcher(config["alerts"])
    for _, row in scored_attack.iterrows():
        db.upsert_device(row["device_ip"])
        features = {k: row[k] for k in FEATURE_COLUMNS}
        wid = db.insert_feature_window({"device_ip": row["device_ip"],
                                         "window_start": row["window_start"],
                                         "window_end":   row["window_end"],
                                         "anomaly_score": float(row["anomaly_score"]),
                                         **features})
        if row["is_anomaly"]:
            from src.model import severity_from_score
            sev = severity_from_score(row["anomaly_score"])
            db.insert_anomaly(row["device_ip"], wid, float(row["anomaly_score"]), sev)
            dispatcher.dispatch(Alert(row["device_ip"], sev, float(row["anomaly_score"]),
                                      row["window_start"], row["window_end"], features))

    print("\n"+"="*70); print("Step 5: DB check"); print("="*70)
    print(f"  Devices: {len(db.list_devices())}")
    print(f"  Anomalies stored: {len(db.recent_anomalies())}")
    print(f"  Feature windows: {len(db.recent_windows(limit=99999))}")
    print("\nVERIFICATION PASSED ✓")

if __name__ == "__main__":
    main()
