"""Live monitor page — LV-B "Terminal-first" variant.

Big terminal log dominates the left. Compact device strip on the right
with pulse + sparkline + last score.
"""
from __future__ import annotations
from datetime import datetime, timezone
import html
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.database import Database
from src.ui import (
    BG, SURFACE, BORDER, TEXT, TEXT_DIM,
    RED, ORANGE, YELLOW, GREEN, BLUE,
    SEVERITY_COLOR, pulse_dot, relative_time, plotly_theme, empty_state,
    badge_html,
)


def render(db: Database, threshold: float, on_open_device) -> None:
    devices  = db.list_devices()
    anomalies = db.recent_anomalies(limit=120)
    windows  = db.recent_windows(limit=300)
    active   = db.active_actions()

    # ── header strip ────────────────────────────────────────────────
    head_l, head_r = st.columns([3, 2])
    with head_l:
        st.markdown("### Watch room")
        st.caption("live tail · grep ready · pause master in sidebar")
    with head_r:
        last_score = None
        if windows:
            last_score = windows[0]["anomaly_score"]
        last_severity = "CRITICAL" if (last_score or 0) < threshold else "LOW"
        st.markdown(
            f"<div style='text-align:right'>"
            f"{pulse_dot(last_severity)}&nbsp;&nbsp;"
            f"<span style='font-family:JetBrains Mono,monospace;font-size:13px'>"
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</span>"
            f"<div style='color:var(--text-dim);font-size:11px;margin-top:2px'>"
            f"5s auto-refresh</div></div>",
            unsafe_allow_html=True,
        )

    # ── severity filter chips ───────────────────────────────────────
    flt = st.session_state.setdefault("live_filter",
                                       {"sev": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]})
    c1, c2, c3, c4, c5, _ = st.columns([1, 1, 1, 1, 1, 6])
    for col, name in zip([c1, c2, c3, c4, c5], ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]):
        with col:
            active_state = name in flt["sev"]
            if st.button(name.lower(), key=f"lv_flt_{name}", use_container_width=True,
                         type=("primary" if active_state else "secondary")):
                if active_state and len(flt["sev"]) > 1:
                    flt["sev"].remove(name)
                elif not active_state:
                    flt["sev"].append(name)
                st.rerun()

    if not devices:
        empty_state("💤", "No live windows",
                    "No traffic captured yet. Check the capture agent or your network.")
        return

    # ── main: terminal + device strip ───────────────────────────────
    left, right = st.columns([2, 1], gap="large")

    with left:
        _render_terminal(windows, anomalies, threshold, flt["sev"])

    with right:
        _render_device_strip(devices, windows, threshold, active, on_open_device)


def _render_terminal(windows, anomalies, threshold, severity_filter):
    """Big monospace log: window commits + anomaly fires, color-coded."""
    # Merge & sort by time, descending
    rows = []
    for a in anomalies:
        rows.append({
            "t": a["detected_at"],
            "sev": (a.get("severity") or "MEDIUM").upper(),
            "ip": a["device_ip"], "score": a["score"],
            "msg": a.get("notes") or "anomaly detected",
        })
    for w in windows[:60]:
        s = w["anomaly_score"]
        rows.append({
            "t": w["window_start"],
            "sev": "INFO",
            "ip": w["device_ip"], "score": s,
            "msg": "window committed",
        })
    rows.sort(key=lambda r: str(r["t"]), reverse=True)

    rows = [r for r in rows if r["sev"] in severity_filter][:120]

    if not rows:
        st.markdown("<div class='terminal'>no events match the filter.<br><span class='t-cursor'></span></div>",
                    unsafe_allow_html=True)
        return

    lines = []
    for r in rows:
        sev = r["sev"]
        css = {"CRITICAL": "t-crit", "HIGH": "t-high", "MEDIUM": "t-med",
               "LOW": "t-low", "INFO": "t-info"}[sev]
        t_str = ""
        ts = pd.to_datetime(r["t"], errors="coerce", utc=True)
        if pd.notna(ts):
            t_str = ts.strftime("%H:%M:%S")
        score = r["score"]
        score_str = f"{score:+.3f}" if score is not None else "—"
        msg = html.escape(str(r["msg"]))[:120]
        lines.append(
            f"<div><span class='t-meta'>{t_str}</span>"
            f" <span class='{css}'>[{sev:>8}]</span>"
            f" <span class='t-ip'>{r['ip']:<15}</span>"
            f" <span class='{css}'>score={score_str}</span>"
            f" <span style='color:#c5cbd2'>{msg}</span></div>"
        )

    st.markdown(
        f"<div class='terminal'>"
        f"<div style='color:#5a6473;border-bottom:1px solid var(--border);"
        f"padding-bottom:4px;margin-bottom:6px'>"
        f"$ tail -f anomaly.log  · live · {len(rows)} events"
        f"</div>"
        f"{''.join(lines)}"
        f"<span class='t-cursor'></span>"
        f"</div>",
        unsafe_allow_html=True,
    )


def _render_device_strip(devices, windows, threshold, active, on_open_device):
    """Compact rows: pulse + IP + sparkline + last score, sorted by threat."""
    st.markdown("###### Devices · sorted by threat")
    # Build score history per device
    df = pd.DataFrame(windows) if windows else pd.DataFrame()
    if df.empty:
        st.caption("waiting for windows…")
        return
    df["window_start"] = pd.to_datetime(df["window_start"], errors="coerce", utc=True)
    df = df.dropna(subset=["window_start"]).sort_values("window_start")

    rows = []
    for d in devices:
        sub = df[df["device_ip"] == d["ip"]].tail(20)
        if sub.empty:
            continue
        last_score = sub.iloc[-1]["anomaly_score"]
        sev_color = (RED if last_score < threshold - 0.20 else
                     ORANGE if last_score < threshold else
                     YELLOW if last_score < 0 else GREEN)
        sev_name = (
            "CRITICAL" if last_score < threshold - 0.20 else
            "HIGH"     if last_score < threshold else
            "MEDIUM"   if last_score < 0 else "LOW"
        )
        rows.append({
            "ip": d["ip"], "nick": d.get("nickname") or "",
            "score": last_score, "sev": sev_name, "sev_color": sev_color,
            "values": sub["anomaly_score"].tolist(),
            "last_seen": sub.iloc[-1]["window_start"],
            "action": active.get(d["ip"]),
        })
    rows.sort(key=lambda r: r["score"])

    for r in rows[:12]:
        with st.container(border=True):
            c1, c2, c3 = st.columns([1.7, 1.5, 1])
            with c1:
                action_chip = ""
                if r["action"]:
                    t = r["action"]["action_type"]
                    icon = "🔒" if t == "quarantine" else "🔕"
                    action_chip = f"<span class='chip' style='margin-left:6px'>{icon}</span>"
                st.markdown(
                    f"{pulse_dot(r['sev'])} &nbsp;"
                    f"<span style='font-family:JetBrains Mono,monospace;font-size:12px'>"
                    f"{r['ip']}</span>{action_chip}"
                    f"<div style='color:var(--text-dim);font-size:10.5px;margin-top:2px'>"
                    f"{r['nick']} · {relative_time(r['last_seen'])}</div>",
                    unsafe_allow_html=True,
                )
            with c2:
                fig = go.Figure()
                fig.add_hline(y=threshold, line=dict(color=RED, width=1, dash="dash"))
                xs = list(range(len(r["values"])))
                fig.add_trace(go.Scatter(
                    x=xs, y=r["values"], mode="lines+markers",
                    line=dict(color=r["sev_color"], width=1.4),
                    marker=dict(size=[5 if v < threshold else 3 for v in r["values"]],
                                color=[RED if v < threshold else r["sev_color"] for v in r["values"]]),
                    hovertemplate="%{y:.3f}<extra></extra>",
                ))
                fig.update_layout(
                    **plotly_theme(), height=44,
                    margin=dict(l=0, r=0, t=0, b=0),
                    xaxis=dict(visible=False), yaxis=dict(visible=False),
                    showlegend=False,
                )
                st.plotly_chart(fig, use_container_width=True, key=f"lv_spark_{r['ip']}")
            with c3:
                st.markdown(
                    f"<div style='text-align:right;font-family:JetBrains Mono,monospace;"
                    f"font-size:22px;font-weight:700;color:{r['sev_color']}'>"
                    f"{r['score']:+.2f}</div>",
                    unsafe_allow_html=True,
                )
                if st.button("inspect →", key=f"lv_open_{r['ip']}", use_container_width=True):
                    on_open_device(r["ip"])
