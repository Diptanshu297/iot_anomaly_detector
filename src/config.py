from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "model": {"alert_threshold": 0.05},
    "dashboard": {"refresh_seconds": 10, "live_refresh_seconds": 5},
    "database": {"path": "data/anomaly.db"},
}

def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out

def load_config(path: str | Path = "config.yaml") -> dict:
    p = Path(path)
    if not p.exists():
        return _deep_merge(DEFAULT_CONFIG, {})
    try:
        with open(p) as f:
            raw = yaml.safe_load(f) or {}
        if not isinstance(raw, dict):
            return _deep_merge(DEFAULT_CONFIG, {})
        return _deep_merge(DEFAULT_CONFIG, raw)
    except (yaml.YAMLError, OSError):
        return _deep_merge(DEFAULT_CONFIG, {})

def save_config(cfg: dict, path: str | Path = "config.yaml") -> None:
    with open(path, "w") as f:
        yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)