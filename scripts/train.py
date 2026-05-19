import argparse, logging, sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config   import load_config
from src.features import extract_features
from src.model    import AnomalyDetector

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", type=Path, default=None)
    args = ap.parse_args()

    config   = load_config()
    pcap_dir = args.pcap_dir or Path(config["capture"]["output_dir"])
    watched  = config["features"].get("watched_devices") or None
    pcaps    = sorted(pcap_dir.glob("*.pcap"))

    if not pcaps:
        logger.error("No .pcap files in %s. Run: python -m scripts.generate_sample_data", pcap_dir)
        sys.exit(1)

    frames = []
    for pcap in pcaps:
        logger.info("Extracting features from %s", pcap.name)
        df = extract_features(pcap, window_seconds=config["features"]["window_seconds"],
                              watched_devices=watched)
        if not df.empty:
            frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    logger.info("Total rows: %d across %d devices", len(combined), combined["device_ip"].nunique())

    detector = AnomalyDetector(
        contamination=config["model"]["contamination"],
        n_estimators=config["model"]["n_estimators"],
        random_state=config["model"]["random_state"],
    )
    detector.fit(combined)
    detector.save(config["model"]["path"])
    logger.info("Done. Model saved to %s", config["model"]["path"])

if __name__ == "__main__":
    main()
