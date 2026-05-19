"""Compare two devices · feature ⑦."""
from __future__ import annotations
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.database import Database
from src.ui import (
    SURFACE, BORDER, TEXT, TEXT_DIM,
    RED, ORANGE, BLUE, PURPLE,
    plotly_theme, empty_state,
)

FEATURES = [
    ("packet_count",           "packets"),
    ("byte_count",             "bytes"),
    ("unique_dst_ips",         "unique dst"),
    ("unique_dst_ports",       "dst ports"),
    ("avg_packet_size",        "avg pkt sz"),
    ("tcp_ratio",              "tcp ratio"),
    ("udp_ratio",              "udp ratio"),
    ("dns_count",              "dns"),
    ("outbound_inbound_ratio", "out/in"),
]


def render(db: Database, threshold: float) -> None:
    st.markdown("### Compare two devices")
    st.caption("overlay fingerprints · is A acting like B?")

    devices = db.list_devices()
    if len(devices) < 2:
        empty_state("🧑‍🤝‍🧑", "Need at least 2 devices",
                    "Capture more devices, then come back.")
        return

    ips   = [d["ip"] for d in devices]
    pre_a = st.session_state.get("cmp_a", ips[0])
    pre_b = st.session_state.get("cmp_b", ips[1] if len(ips) > 1 else ips[0])

    c1, c2, c3 = st.columns([2, 2, 1])
    with c1:
        a_ip = st.selectbox("A (suspect)", ips,
                            index=ips.index(pre_a) if pre_a in ips else 0)
    with c2:
        b_ip = st.selectbox("B (baseline / peer)", ips,
                            index=ips.index(pre_b) if pre_b in ips else 0)
    with c3:
        st.caption("")
        st.caption("")
        if st.button("⇄ swap", use_container_width=True):
            st.session_state["cmp_a"], st.session_state["cmp_b"] = b_ip, a_ip
            st.rerun()

    if a_ip == b_ip:
        st.info("Pick two different devices to compare.")
        return

    a_w = pd.DataFrame(db.recent_windows(device_ip=a_ip, limit=200))
    b_w = pd.DataFrame(db.recent_windows(device_ip=b_ip, limit=200))
    if a_w.empty or b_w.empty:
        empty_state("📊", "Not enough data",
                    "One of the selected devices has no windows yet.")
        return

    a_w["window_start"] = pd.to_datetime(a_w["window_start"], errors="coerce", utc=True)
    b_w["window_start"] = pd.to_datetime(b_w["window_start"], errors="coerce", utc=True)

    a_stats     = {col: a_w[col].mean() for col, _ in FEATURES if col in a_w}
    b_stats     = {col: b_w[col].mean() for col, _ in FEATURES if col in b_w}
    norm_factor = {col: max(a_stats.get(col, 0), b_stats.get(col, 0), 1e-9) for col, _ in FEATURES}
    a_norm      = [a_stats.get(c, 0) / norm_factor[c] for c, _ in FEATURES]
    b_norm      = [b_stats.get(c, 0) / norm_factor[c] for c, _ in FEATURES]

    g1, g2 = st.columns([1, 1.4])

    with g1:
        st.markdown("###### Fingerprint overlay · 9 features")
        labels = [lbl for _, lbl in FEATURES]
        fig = go.Figure()
        fig.add_trace(go.Scatterpolar(
            r=b_norm + [b_norm[0]], theta=labels + [labels[0]],
            fill="toself", name=f"B · {b_ip}",
            line=dict(color=BLUE), fillcolor="rgba(59,130,246,0.20)",
        ))
        fig.add_trace(go.Scatterpolar(
            r=a_norm + [a_norm[0]], theta=labels + [labels[0]],
            fill="toself", name=f"A · {a_ip}",
            line=dict(color=RED, width=2), fillcolor="rgba(239,68,68,0.25)",
        ))
        theme = plotly_theme()
        theme.pop("xaxis", None)
        theme.pop("yaxis", None)
        theme.pop("legend", None)
        fig.update_layout(
            **theme,
            height=400,
            polar=dict(
                bgcolor=SURFACE,
                radialaxis=dict(visible=True, range=[0, 1.1],
                                gridcolor=BORDER,
                                tickfont=dict(color=TEXT_DIM, size=9)),
                angularaxis=dict(gridcolor=BORDER,
                                 tickfont=dict(color=TEXT_DIM, size=11)),
            ),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2),
        )
        st.plotly_chart(fig, use_container_width=True, key="cmp_radar")

    with g2:
        st.markdown("###### Score · both devices, last 200 windows")
        fig2 = go.Figure()
        fig2.add_hrect(y0=-1, y1=threshold, fillcolor=RED, opacity=0.08, line_width=0)
        fig2.add_hline(y=threshold, line=dict(color=RED, width=1.3, dash="dash"))
        fig2.add_trace(go.Scatter(
            x=b_w["window_start"], y=b_w["anomaly_score"],
            mode="lines", name=f"B · {b_ip}", line=dict(color=BLUE, width=1.5),
        ))
        fig2.add_trace(go.Scatter(
            x=a_w["window_start"], y=a_w["anomaly_score"],
            mode="lines", name=f"A · {a_ip}", line=dict(color=RED, width=1.8),
        ))
        theme2 = plotly_theme()
        theme2.pop("legend", None)
        fig2.update_layout(
            **theme2,
            height=320,
            legend=dict(orientation="h", yanchor="top", y=1.08, xanchor="right", x=1),
        )
        fig2.update_yaxes(title="anomaly score")
        fig2.update_xaxes(title="")

        # divergences
        divs = []
        for c, lbl in FEATURES:
            av, bv = a_stats.get(c, 0), b_stats.get(c, 0)
            if max(abs(av), abs(bv)) < 1e-9:
                continue
            ratio = (av + 1e-9) / (bv + 1e-9)
            divs.append((lbl, av, bv, ratio))
        divs.sort(key=lambda x: abs(x[3] - 1), reverse=True)
        st.plotly_chart(fig2, use_container_width=True, key="cmp_score")

        st.markdown("###### Biggest divergences")
        for lbl, av, bv, r in divs[:4]:
            color = RED if abs(r - 1) > 1.5 else ORANGE if abs(r - 1) > 0.5 else TEXT_DIM
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;font-size:12px'>"
                f"<span>{lbl}</span>"
                f"<span style='font-family:JetBrains Mono,monospace;color:{color}'>"
                f"A = {_fmt(av)} · B = {_fmt(bv)} · "
                f"<strong>{r:.2f}×</strong></span></div>",
                unsafe_allow_html=True,
            )

    st.divider()

    st.markdown("###### Feature-by-feature · mean over recent windows")
    cols = st.columns(3)
    for i, (c, lbl) in enumerate(FEATURES):
        with cols[i % 3]:
            av, bv = a_stats.get(c, 0), b_stats.get(c, 0)
            fig = go.Figure(data=[
                go.Bar(y=[f"A · {a_ip}"], x=[av], orientation="h",
                       marker=dict(color=RED), showlegend=False,
                       hovertemplate=f"{_fmt(av)}<extra></extra>"),
                go.Bar(y=[f"B · {b_ip}"], x=[bv], orientation="h",
                       marker=dict(color=BLUE), showlegend=False,
                       hovertemplate=f"{_fmt(bv)}<extra></extra>"),
            ])
            bar_theme = plotly_theme()
            bar_theme.pop("xaxis", None)
            bar_theme.pop("yaxis", None)
            fig.update_layout(
                **bar_theme,
                height=100,
                margin=dict(l=8, r=8, t=22, b=8),
                title=dict(text=lbl, font=dict(size=11, color=TEXT_DIM), x=0.01),
            )
            fig.update_yaxes(visible=False)
            fig.update_xaxes(showgrid=False, color=TEXT_DIM)
            st.plotly_chart(fig, use_container_width=True, key=f"cmp_bar_{c}")


def _fmt(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return "—"
    if abs(v) >= 1_000_000: return f"{v/1_000_000:.1f}M"
    if abs(v) >= 1_000:     return f"{v/1_000:.1f}k"
    if abs(v) < 1:          return f"{v:.3f}"
    return f"{v:.0f}"