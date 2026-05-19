# 🛡️ IoT Anomaly Detector

> Catch compromised smart devices on your network before they become weapons.

Built with **tshark** for packet capture, **Isolation Forest** (scikit-learn) for unsupervised ML anomaly detection, **SQLite** for storage, and **Streamlit** for a live security dashboard.

---

## The real-world problem

In October 2016, the **Mirai botnet** infected 600,000 IoT devices — cameras, DVRs, baby monitors — by guessing default passwords. It then commanded them all to flood a DNS provider simultaneously, taking down Twitter, Netflix, GitHub, and Reddit.

Every infected device showed obvious behavioral changes before the attack: sudden traffic spikes, contact with new IPs, port scanning activity. Nobody was watching.

**This project is what watching looks like.**

---

## How it works

```
Network traffic
      │
      ▼
 tshark capture
 (rolling 60s pcaps)
      │
      ▼
 Feature extraction
 (9 stats per device per window)
      │
      ▼
 Isolation Forest
 (unsupervised ML — no labels needed)
      │
      ▼
 Alert + Dashboard
 (console / file / Streamlit UI)
```

The system learns what each IoT device's **normal behavior** looks like, then flags windows where behavior suddenly changes — without needing any labeled attack examples.

---

## Why Isolation Forest?

Most security ML requires labeled training data ("here's an attack, here's normal traffic"). You almost certainly don't have that for your home devices.

Isolation Forest is **unsupervised** — it only needs to see normal traffic. It learns the shape of normality by building random binary trees. Normal points sit in dense regions and take many splits to isolate. Anomalous points sit on the edges and get isolated quickly.

**The anomaly score = how easy was this data point to isolate?**
- Score near `0.0` → normal
- Score below `-0.15` → suspicious
- Score below `-0.30` → critical

---

## Dashboard pages

| Page | What it shows |
|---|---|
| 📊 Overview | Active alert cards, anomaly feed, device × hour heatmap |
| 🎯 Device deep-dive | 4 charts per device, anomaly list, feature breakdown table |
| ∿ Anomaly timeline | Fleet swimlane view, severity filters, CSV export |
| 📡 Live monitor | Terminal-style live feed, per-device sparklines |
| ⚖ Compare | Side-by-side radar fingerprint of two devices |
| ⚙ Threshold tuner | Drag the threshold, preview would-be alerts live |

---

## Features extracted per device per window

| Feature | What it captures | Why it matters |
|---|---|---|
| `packet_count` | How chatty the device was | Sudden surges = attack or compromise |
| `byte_count` | Total data volume | Data exfiltration spikes here |
| `unique_dst_ips` | Distinct destination IPs | Botnets fan out; normal devices don't |
| `unique_dst_ports` | Distinct ports contacted | Port scanning leaves a fingerprint |
| `avg_packet_size` | Mean packet size | Scans use small packets; uploads use large ones |
| `tcp_ratio` | TCP traffic share | Sudden shift = unusual workload |
| `udp_ratio` | UDP traffic share | DDoS often uses UDP floods |
| `dns_count` | DNS queries made | DGA malware generates many lookups |
| `outbound_inbound_ratio` | Send vs receive skew | DDoS bots send far more than they receive |

All features are **protocol-agnostic** — no deep packet inspection, no decryption needed.

---

## Project structure

```
iot-anomaly-detector/
│
├── config.yaml                   ← all tunable settings
├── requirements.txt              ← Python dependencies
│
├── src/
│   ├── config.py                 ← YAML config loader
│   ├── capture.py                ← tshark wrapper (rolling pcaps)
│   ├── features.py               ← per-device feature extraction
│   ├── model.py                  ← Isolation Forest (train / score / save)
│   ├── database.py               ← SQLite (devices, windows, anomalies)
│   ├── alerts.py                 ← alert dispatch (console/file/email/webhook)
│   ├── actions.py                ← quarantine / mute / comment helpers
│   ├── ui.py                     ← shared Streamlit components & theme
│   ├── dashboard.py              ← main entry point
│   └── _pages/
│       ├── overview.py
│       ├── device.py
│       ├── timeline.py
│       ├── live.py
│       ├── compare.py
│       └── threshold.py
│
├── scripts/
│   ├── generate_sample_data.py   ← synthetic IoT pcaps for testing
│   ├── train.py                  ← train the baseline model
│   ├── detect.py                 ← live detection loop
│   └── seed_db.py                ← seed demo data into SQLite
│
├── data/
│   ├── raw/                      ← pcap files (auto-populated)
│   ├── models/                   ← saved model artifacts
│   └── anomaly.db                ← SQLite database (auto-created)
│
└── tests/
    └── test_features.py
```

---

## Prerequisites

- Python 3.10+
- [Wireshark / tshark](https://www.wireshark.org/download.html)
  - Windows: install to `D:\Wireshark` or `C:\Program Files\Wireshark`
  - Ubuntu: `sudo apt install tshark`
  - macOS: `brew install wireshark`
- [uv](https://astral.sh/uv) (recommended) or pip

---

## Installation

```bash
git clone https://github.com/yourname/iot-anomaly-detector
cd iot-anomaly-detector

# Create and activate virtual environment with uv
uv venv
source .venv/bin/activate        # Mac/Linux
.venv\Scripts\activate           # Windows PowerShell

# Install dependencies
uv pip install -r requirements.txt
```

---

## Quick start — synthetic data (no real network needed)

Test the full pipeline with fake IoT devices before pointing it at your real network.

```bash
# 1. Generate 60 minutes of normal traffic
python -m scripts.generate_sample_data --minutes 60

# 2. Train the model on that baseline
python -m scripts.train

# 3. Generate a pcap with a Mirai-style attack injected at the end
python -m scripts.generate_sample_data --minutes 30 --include-attack \
    --output data/raw/with_attack.pcap

# 4. Run detection on the attack pcap
python -m scripts.detect --pcap data/raw/with_attack.pcap

# 5. Seed the dashboard with realistic demo data (14 devices, 2 weeks)
python scripts/seed_db.py

# 6. Launch the dashboard
streamlit run src/dashboard.py
```

Open **http://localhost:8501** — you'll see 14 devices, anomaly charts, the attack windows flagged red, and all 6 dashboard pages working.

---

## Run on your real network

### Step 1 — Find your network interface
```bash
tshark -D
```
Pick your Wi-Fi or Ethernet interface name (e.g. `Wi-Fi`, `eth0`, `en0`).

### Step 2 — Configure
Edit `config.yaml`:
```yaml
capture:
  interface: "Wi-Fi"         # ← your interface here

features:
  watched_devices:
    - "192.168.1.50"         # ← your IoT device IPs
    - "192.168.1.51"
```

### Step 3 — Build a baseline (most important step)
```bash
# Capture normal traffic for at least a few hours
# Linux/Mac needs sudo; Windows needs Npcap installed
sudo python -m src.capture
```
Let it run for **at least 2 hours**. 24 hours is better. A week is excellent. The longer the baseline, the tighter the model's definition of "normal".

### Step 4 — Train
```bash
python -m scripts.train
```

### Step 5 — Detect + dashboard
```bash
# Terminal 1 — live detection loop
python -m scripts.detect

# Terminal 2 — dashboard
streamlit run src/dashboard.py
```

---

## Configuration reference

All settings live in `config.yaml`. The most important ones:

```yaml
capture:
  interface: "Wi-Fi"          # network interface to sniff
  rotation_seconds: 60        # new pcap file every N seconds

features:
  window_seconds: 60          # aggregate packets into N-second buckets
  watched_devices: []         # pin specific IPs; empty = watch everything

model:
  contamination: 0.01         # expected anomaly rate in training data (1%)
  alert_threshold: -0.15      # scores below this trigger alerts
                              # more negative = stricter

alerts:
  console: true               # print to terminal
  file: true                  # append to data/alerts.log
  email: false                # configure smtp_host / email_to to enable
  webhook: false              # set webhook_url to post to Slack etc.
```

### Tuning the threshold

After training, run detection on a sample pcap and check the score distribution. Then adjust:

| Situation | Action |
|---|---|
| Too many false alerts | Lower `alert_threshold` (e.g. `-0.20`) |
| Missing real anomalies | Raise `alert_threshold` (e.g. `-0.10`) |
| All normal traffic flagged | Increase baseline capture time and retrain |

The **Threshold tuner** page in the dashboard lets you drag the threshold and preview exactly how many alerts would fire — no config editing needed.

---

## Testing

```bash
python -m pytest tests/ -v
```

4 unit tests covering feature extraction logic — all should pass without tshark installed.

---

## Deployment options

| Option | Cost | Effort | Real capture? |
|---|---|---|---|
| Local (current) | Free | None | ✅ Yes |
| Streamlit Community Cloud | Free | Low | ❌ No |
| Railway / Render | Free tier | Low | ❌ No |
| VPS (DigitalOcean etc.) | ~$6/mo | Medium | ✅ Yes |
| Docker on home server | Hardware cost | Medium | ✅ Yes |
| Raspberry Pi | ~$35 one-time | Low | ✅ Yes (best option) |

For real IoT monitoring, a **Raspberry Pi 4** sitting on your home network is the sweet spot — always on, real traffic capture, $35 one-time cost.

---

## Production checklist

- [ ] Capture privileges: run tshark as a dedicated user with `cap_net_raw`, not root
- [ ] Storage rotation: cron job to delete pcaps older than 7 days
- [ ] Database: swap SQLite for PostgreSQL beyond ~50 devices
- [ ] Alerting: configure Slack webhook in `config.yaml`
- [ ] Model retraining: weekly retrain on last 7 days of confirmed-normal traffic
- [ ] HTTPS: put nginx in front of Streamlit with a TLS certificate
- [ ] Auth: add `streamlit-authenticator` if the dashboard is publicly reachable

---

## Tech stack

| Layer | Technology | Why |
|---|---|---|
| Packet capture | tshark (Wireshark CLI) | Headless, scriptable, production-grade |
| Packet parsing | pyshark / scapy | Python-native pcap reading |
| Feature engineering | pandas + numpy | Tabular window aggregation |
| ML model | scikit-learn IsolationForest | Unsupervised, no labels needed |
| Model storage | joblib | Fast serialization |
| Database | SQLite | Zero-config, file-based |
| Dashboard | Streamlit + Plotly | Web UI in pure Python |
| Config | PyYAML | Human-readable settings |

---

## Legal & ethical note

**Only capture traffic on networks you own or have explicit written permission to monitor.**

Capturing network traffic without authorization is illegal under the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent laws in most jurisdictions. This tool is for defending your own network.

---

## License

MIT — use freely, attribute kindly.
