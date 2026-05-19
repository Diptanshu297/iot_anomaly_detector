import argparse, logging, sys, time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.alerts   import Alert, AlertDispatcher
from src.config   import load_config
from src.database import Database
from src.features import FEATURE_COLUMNS, extract_features
from src.model    import AnomalyDetector, severity_from_score

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("detect")

def _why(row):
    hints = []
    if row["unique_dst_ips"]   > 30:  hints.append(f"contacted {row['unique_dst_ips']} IPs")
    if row["unique_dst_ports"] > 15:  hints.append(f"hit {row['unique_dst_ports']} ports")
    if row["packet_count"]     > 5000: hints.append("packet burst")
    if row["outbound_inbound_ratio"] > 10: hints.append("heavy outbound")
    return "; ".join(hints) if hints else "model flagged behavioral shift"

def process_pcap(pcap_path, detector, db, dispatcher, config):
    threshold = config["model"]["alert_threshold"]
    watched   = config["features"].get("watched_devices") or None
    df = extract_features(pcap_path, window_seconds=config["features"]["window_seconds"],
                          watched_devices=watched)
    if df.empty:
        return 0
    df = detector.predict_anomaly(df, threshold=threshold)
    anomalies = 0
    for _, row in df.iterrows():
        ip = row["device_ip"]
        db.upsert_device(ip)
        features = {k: row[k] for k in FEATURE_COLUMNS}
        wid = db.insert_feature_window({
            "device_ip": ip,
            "window_start": row["window_start"],
            "window_end":   row["window_end"],
            "anomaly_score": float(row["anomaly_score"]),
            **features,
        })
        if row["is_anomaly"]:
            anomalies += 1
            sev   = severity_from_score(row["anomaly_score"])
            notes = _why(row)
            db.insert_anomaly(ip, wid, float(row["anomaly_score"]), sev, notes)
            dispatcher.dispatch(Alert(ip, sev, float(row["anomaly_score"]),
                                      row["window_start"], row["window_end"],
                                      features, notes))
    logger.info("%s -> %d windows, %d anomalies", pcap_path.name, len(df), anomalies)
    return anomalies

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--pcap", type=Path)
    args = ap.parse_args()

    config     = load_config()
    db         = Database(config["database"]["path"])
    dispatcher = AlertDispatcher(config["alerts"])
    detector   = AnomalyDetector()
    try:
        detector.load(config["model"]["path"])
    except FileNotFoundError:
        logger.error("No model found. Run: python -m scripts.train")
        sys.exit(1)

    if args.pcap:
        process_pcap(args.pcap, detector, db, dispatcher, config)
        return
    pcap_dir = Path(config["capture"]["output_dir"])
    seen = set()
    for pcap in sorted(pcap_dir.glob("*.pcap")):
        process_pcap(pcap, detector, db, dispatcher, config)
        seen.add(pcap)
    if args.once:
        return
    poll = max(5, config["capture"]["rotation_seconds"] // 2)
    logger.info("Watching %s for new pcaps. Ctrl-C to stop.", pcap_dir)
    while True:
        try:
            time.sleep(poll)
            for pcap in sorted(pcap_dir.glob("*.pcap")):
                if pcap in seen: continue
                if time.time() - pcap.stat().st_mtime < poll: continue
                process_pcap(pcap, detector, db, dispatcher, config)
                seen.add(pcap)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
