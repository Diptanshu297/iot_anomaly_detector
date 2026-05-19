"""IoT Anomaly Detector dashboard · main entry.

Run with:
    streamlit run src/dashboard.py
"""
from __future__ import annotations
import time
from datetime import datetime, timezone
from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config import load_config, save_config
from src.database import Database
from src.ui import (
    inject_css, badge_html, pulse_dot, relative_time,
    BG, SURFACE, BORDER, TEXT, TEXT_DIM,
    RED, ORANGE, YELLOW, GREEN, BLUE,
)
from src.actions import render_action_banners
from src._pages import overview, device, timeline, live, compare, threshold as thr_page


PAGES = [
    ("overview",  "📊  Overview",        "alerts + heatmap"),
    ("device",    "🎯  Device deep-dive", "single device"),
    ("timeline",  "∿  Anomaly timeline", "fleet swimlanes"),
    ("live",      "📡  Live monitor",     "5s · terminal"),
    ("compare",   "⚖  Compare",          "A vs B"),
    ("threshold", "⚙  Threshold tuner",  "feel the trade-off"),
]


def main():
    st.set_page_config(
        page_title="IoT Anomaly Detector",
        page_icon="📡",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_css()

    cfg = load_config()
    db_path = cfg["database"]["path"]
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    @st.cache_resource
    def get_db(path: str) -> Database:
        return Database(path)

    db = get_db(db_path)
    threshold = float(cfg["model"]["alert_threshold"])

    if "page" not in st.session_state:
        st.session_state["page"] = "overview"
    if "selected_device" not in st.session_state:
        st.session_state["selected_device"] = None

    _render_sidebar(db, cfg, threshold)

    try:
        active = db.active_actions()
        if active:
            render_action_banners(active)
    except Exception as e:
        st.warning(f"Couldn't load active actions: {e}")

    page = st.session_state["page"]

    def goto(p):
        st.session_state["page"] = p
        st.rerun()

    def open_device(ip):
        st.session_state["selected_device"] = ip
        goto("device")

    def drill_anomaly(anomaly_id):
        st.session_state["dev_selected_anomaly"] = anomaly_id
        anom = next((a for a in db.recent_anomalies(limit=200) if a["id"] == anomaly_id), None)
        if anom:
            open_device(anom["device_ip"])
        else:
            goto("device")

    def open_compare(ip):
        st.session_state["cmp_a"] = ip
        goto("compare")

    def save_threshold(new_value: float):
        cfg["model"]["alert_threshold"] = round(float(new_value), 3)
        save_config(cfg)

    try:
        if page == "overview":
            overview.render(db, threshold,
                            on_drill_anomaly=drill_anomaly,
                            on_open_device=open_device)
        elif page == "device":
            device.render(db, st.session_state.get("selected_device"),
                          threshold, on_open_compare=open_compare)
        elif page == "timeline":
            timeline.render(db, threshold, on_open_device=open_device)
        elif page == "live":
            live.render(db, threshold, on_open_device=open_device)
        elif page == "compare":
            compare.render(db, threshold)
        elif page == "threshold":
            thr_page.render(db, threshold, on_save_threshold=save_threshold)
        else:
            st.error(f"Unknown page: {page}")
    except Exception as e:
        st.error(f"Page error: {e}")
        st.exception(e)

    _auto_refresh(cfg, page)


def _render_sidebar(db: Database, cfg: dict, threshold: float) -> None:
    with st.sidebar:
        st.markdown("## 📡  IoT · Sentinel")

        try:
            devices = db.list_devices()
            total = db.total_windows()
            from datetime import timedelta
            since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
            counts = db.severity_counts(since_iso=since)
            active_count = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
        except Exception:
            devices, total, counts, active_count = [], 0, {}, 0

        live_master = st.session_state.setdefault("live_master", True)
        sev_color = RED if active_count else GREEN
        st.markdown(
            f"""<div class='card' style='border-color:{sev_color}'>
              <div style='display:flex;align-items:center;gap:8px'>
                {pulse_dot('CRITICAL' if active_count else 'LOW')}
                <span style='font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.5px'>
                  {'LIVE' if live_master else 'PAUSED'} · refresh {cfg['dashboard']['refresh_seconds']}s
                </span>
              </div>
              <div style='display:flex;justify-content:space-between;margin-top:8px;font-size:12px'>
                <span>devices</span>
                <span style='font-family:JetBrains Mono,monospace'>{len(devices)}</span>
              </div>
              <div style='display:flex;justify-content:space-between;font-size:12px'>
                <span>windows</span>
                <span style='font-family:JetBrains Mono,monospace'>{total:,}</span>
              </div>
              <div style='display:flex;justify-content:space-between;font-size:12px'>
                <span>open alerts · 24h</span>
                <span style='font-family:JetBrains Mono,monospace;color:{sev_color}'>{active_count}</span>
              </div>
            </div>""",
            unsafe_allow_html=True,
        )

        st.markdown("###### Navigate")
        for key, label, sub in PAGES:
            active_state = st.session_state["page"] == key
            if st.button(label, key=f"nav_{key}", use_container_width=True,
                         type=("primary" if active_state else "secondary")):
                st.session_state["page"] = key
                st.rerun()
            st.caption(sub)

        if st.session_state["page"] == "device":
            _render_device_selector(db, threshold)

        st.markdown("###### Refresh")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("⏸ Pause" if live_master else "▶ Resume", use_container_width=True):
                st.session_state["live_master"] = not live_master
                st.rerun()
        with c2:
            if st.button("↻ Now", use_container_width=True):
                st.rerun()

        rs = cfg["dashboard"]["refresh_seconds"]
        lr = cfg["dashboard"].get("live_refresh_seconds", 5)
        st.caption(f"Pages: every {rs}s · Live: every {lr}s")
        st.divider()
        st.caption(f"Threshold · {threshold:+.2f}")
        st.caption(f"DB · `{cfg['database']['path']}`")


def _render_device_selector(db: Database, threshold: float) -> None:
    devices = db.list_devices()
    if not devices:
        st.caption("no devices yet")
        return

    st.markdown("###### Select device")
    q = st.text_input("search", key="dev_search", placeholder="🔍 192.168 / nickname",
                      label_visibility="collapsed")
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    recent = db.anomalies_since(cutoff, limit=2000)
    hot_ips = {a["device_ip"] for a in recent}

    devices_sorted = sorted(devices, key=lambda d: (0 if d["ip"] in hot_ips else 1, d["ip"]))
    selected = st.session_state.get("selected_device")

    for d in devices_sorted:
        if q and q.lower() not in d["ip"].lower() and \
           q.lower() not in (d.get("nickname") or "").lower():
            continue
        hot = d["ip"] in hot_ips
        label = f"{'🔴' if hot else '🟢'}  {d['ip']}"
        if d.get("nickname"):
            label += f"  · {d['nickname']}"
        if st.button(label, key=f"sel_{d['ip']}", use_container_width=True,
                     type=("primary" if selected == d["ip"] else "secondary")):
            st.session_state["selected_device"] = d["ip"]
            st.rerun()


def _auto_refresh(cfg: dict, page: str) -> None:
    if not st.session_state.get("live_master", True):
        return
    delay = cfg["dashboard"].get("live_refresh_seconds", 5) if page == "live" \
            else cfg["dashboard"].get("refresh_seconds", 10)
    delay = max(1, int(delay))
    placeholder = st.empty()
    placeholder.caption(f"next refresh in {delay}s · pause in the sidebar")
    time.sleep(delay)
    st.rerun()


if __name__ == "__main__":
    main()