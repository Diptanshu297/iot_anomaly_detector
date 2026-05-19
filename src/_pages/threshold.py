"""Threshold tuner · feature ⑧.

Histogram of recent scores, draggable threshold via slider, live preview
of would-be alerts at any candidate threshold.
"""
from __future__ import annotations
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.database import Database
from src.config import save_config
from src.ui import (
    BG, SURFACE, BORDER, TEXT, TEXT_DIM,
    RED, ORANGE, YELLOW, GREEN, BLUE,
    plotly_theme, empty_state, badge_html, diverging_score_bar,
    severity_from_score,
)


PRESETS = [
    {"name": "Strict",         "val": -0.05, "desc": "find everything · many false positives"},
    {"name": "Default",        "val": -0.15, "desc": "balanced · shipping default"},
    {"name": "Loose",          "val": -0.30, "desc": "skip moderate · when on-call needs sleep"},
    {"name": "Critical-only",  "val": -0.40, "desc": "only the worst · paging threshold"},
]


def render(db: Database, current_threshold: float, on_save_threshold) -> None:
    st.markdown("### Threshold tuner")
    st.caption("drag the line · preview would-be alerts at any threshold")

    windows = db.recent_windows(limit=5000)
    if not windows:
        empty_state("📊", "Need windows", "No score data captured yet.")
        return

    df = pd.DataFrame(windows)
    if "anomaly_score" not in df:
        empty_state("📊", "Need scored windows", "anomaly_score not present yet.")
        return

    df["window_start"] = pd.to_datetime(df["window_start"], errors="coerce", utc=True)
    df = df.dropna(subset=["anomaly_score"])

    # ── slider ──────────────────────────────────────────────────────
    candidate = st.session_state.get("thr_candidate", current_threshold)

    s_col, p_col = st.columns([3, 2])
    with s_col:
        candidate = st.slider("candidate threshold", -0.50, 0.10,
                              float(candidate), 0.01,
                              key="thr_candidate", format="%.2f")
    with p_col:
        preset_cols = st.columns(len(PRESETS))
        for col, p in zip(preset_cols, PRESETS):
            with col:
                if st.button(p["name"], key=f"preset_{p['name']}",
                             use_container_width=True):
                    st.session_state["thr_candidate"] = p["val"]
                    st.rerun()

    # ── histogram ───────────────────────────────────────────────────
    bins = pd.cut(df["anomaly_score"], bins=40)
    hist = bins.value_counts().sort_index()
    centers = [(i.left + i.right) / 2 for i in hist.index]
    colors = [RED if c < candidate else GREEN for c in centers]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=centers, y=hist.values,
        marker=dict(color=colors, opacity=0.55,
                    line=dict(color=colors, width=1)),
        hovertemplate="score ~ %{x:.2f}<br>windows %{y}<extra></extra>",
        showlegend=False,
    ))
    fig.add_vline(x=candidate, line=dict(color=RED, width=2.4, dash="dash"),
                  annotation_text=f"{candidate:+.2f}",
                  annotation_position="top",
                  annotation_font=dict(color=RED, size=12))
    fig.add_vline(x=current_threshold, line=dict(color=TEXT_DIM, width=1, dash="dot"),
                  annotation_text=f"current {current_threshold:+.2f}",
                  annotation_position="bottom",
                  annotation_font=dict(color=TEXT_DIM, size=10))
    fig.update_layout(
        **plotly_theme(), height=280,
        xaxis=dict(title="anomaly score", range=[-0.55, 0.35]),
        yaxis=dict(title="windows"),
        bargap=0.04,
    )
    st.plotly_chart(fig, use_container_width=True, key="thr_hist")

    # ── stats at this threshold ─────────────────────────────────────
    would_alert = df[df["anomaly_score"] < candidate]
    pct = len(would_alert) / max(len(df), 1) * 100
    flagged_devices = would_alert["device_ip"].nunique() if not would_alert.empty else 0
    total_devices = df["device_ip"].nunique()

    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown(
            f"<div class='label' style='color:var(--text-dim);font-size:10px;text-transform:uppercase'>CANDIDATE</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:30px;font-weight:700;color:{RED}'>"
            f"{candidate:+.2f}</div>",
            unsafe_allow_html=True,
        )
    with s2:
        st.markdown(
            f"<div class='label' style='color:var(--text-dim);font-size:10px;text-transform:uppercase'>WOULD ALERT</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:30px;font-weight:700'>"
            f"{len(would_alert):,}</div>"
            f"<div style='color:var(--text-dim);font-size:11px'>windows · {pct:.1f}% of total</div>",
            unsafe_allow_html=True,
        )
    with s3:
        st.markdown(
            f"<div class='label' style='color:var(--text-dim);font-size:10px;text-transform:uppercase'>DEVICES FLAGGED</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:30px;font-weight:700'>"
            f"{flagged_devices}/{total_devices}</div>",
            unsafe_allow_html=True,
        )
    with s4:
        if st.button("💾 Save to config.yaml", type="primary", use_container_width=True,
                     disabled=(abs(candidate - current_threshold) < 1e-4)):
            on_save_threshold(candidate)
            st.success(f"Threshold saved: {candidate:+.2f}")
            st.rerun()
        if st.button("↺ Reset", use_container_width=True):
            st.session_state["thr_candidate"] = current_threshold
            st.rerun()

    # ── preview list ────────────────────────────────────────────────
    st.divider()
    st.markdown("###### Preview · would-be alerts at candidate threshold")
    if would_alert.empty:
        st.success("No windows would alert at this threshold.")
        return

    existing_anom_ids = {(a["device_ip"], a["window_id"])
                         for a in db.recent_anomalies(limit=5000)}

    preview = would_alert.sort_values("anomaly_score").head(40)
    for _, row in preview.iterrows():
        sev = severity_from_score(row["anomaly_score"], threshold=candidate)
        is_already = (row["device_ip"], row["id"]) in existing_anom_ids
        bg_style = "" if is_already else "background: rgba(34,197,94,0.08);"
        label = "already alerting" if is_already else "+ new at this threshold"
        label_color = TEXT_DIM if is_already else GREEN
        st.markdown(
            f"<div style='display:flex;gap:10px;align-items:center;padding:4px 6px;"
            f"{bg_style}border-radius:3px'>"
            f"<span style='width:90px'>{badge_html(sev)}</span>"
            f"<span style='font-family:JetBrains Mono,monospace;font-size:11.5px;width:120px'>{row['device_ip']}</span>"
            f"<span>{diverging_score_bar(row['anomaly_score'], threshold=candidate)}</span>"
            f"<span style='margin-left:auto;color:{label_color};font-size:11px'>{label}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )
