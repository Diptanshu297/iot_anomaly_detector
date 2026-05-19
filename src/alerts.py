from __future__ import annotations
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

@dataclass
class Alert:
    device_ip: str
    severity: str
    score: float
    window_start: datetime
    window_end: datetime
    features: dict
    notes: str = ""

    def to_dict(self):
        d = asdict(self)
        d["window_start"] = self.window_start.isoformat()
        d["window_end"]   = self.window_end.isoformat()
        return d

class AlertDispatcher:
    def __init__(self, config):
        self.config = config
        self.log_path = Path(config.get("log_path", "data/alerts.log"))
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def dispatch(self, alert):
        if self.config.get("console", True):
            self._to_console(alert)
        if self.config.get("file", True):
            self._to_file(alert)

    def _to_console(self, alert):
        bar = "=" * 60
        print(f"\n{bar}")
        print(f"[ANOMALY] {alert.severity}  device={alert.device_ip}  score={alert.score:+.3f}")
        print(f"  window : {alert.window_start.isoformat()} -> {alert.window_end.isoformat()}")
        print(f"  packets={alert.features.get('packet_count')}  "
              f"bytes={alert.features.get('byte_count')}  "
              f"unique_dst_ips={alert.features.get('unique_dst_ips')}")
        if alert.notes:
            print(f"  notes  : {alert.notes}")
        print(bar)

    def _to_file(self, alert):
        with self.log_path.open("a") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")
