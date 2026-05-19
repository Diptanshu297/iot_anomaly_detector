"""Anomaly timeline page — TL-D "Swimlanes" variant.

One row per device, anomalies as colored dots along a time axis.
Sidebar filters: severity, time range, devices. CSV export.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.database import Database
from src.ui import (
    BG, SURFACE, BORDER, TEXT, TEXT_DIM,
    RED, ORANGE, YELLOW, GREEN, BLUE, PURPLE,
    SEVERITY_COLOR, badge_html, diverging_score_bar,
    relative_time, plotly_theme, empty_state,
)


RANGE_DELTAS = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def render(db: Database, threshold: float, on_open_device) -> None:
    # ── filters ─────────────────────────────────────────────────────
    flt = st.session_state.setdefault("tl_filters", {
        "range": "24h", "sev": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "devices": [],
    })

    h_l, h_r = st.columns([3, 2])
    with h_l:
        st.markdown("### Anomaly timeline")
        st.caption(f"one row per device · threshold {threshold:+.2f}")
    with h_r:
        rng_cols = st.columns(4)
        for i, r in enumerate(["1h", "24h", "7d", "30d"]):
            with rng_cols[i]:
                if st.button(r, key=f"rng_{r}", use_container_width=True,
                             type=("primary" if flt["range"] == r else "secondary")):
                    flt["range"] = r
                    st.rerun()

    s_l, s_r = st.columns([3, 2])
    with s_l:
        sev_cols = st.columns(4)
        for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
            with sev_cols[i]:
                active = sev in flt["sev"]
                if st.button(sev, key=f"sev_{sev}", use_container_width=True,
                             type=("primary" if active else "secondary")):
                    if active and len(flt["sev"]) > 1:
                        flt["sev"].remove(sev)
                    elif not active:
                        flt["sev"].append(sev)
                    st.rerun()
    with s_r:
        devices = db.list_devices()
        flt["devices"] = st.multiselect(
            "Devices", options=[d["ip"] for d in devices],
            default=flt["devices"], placeholder="all devices",
            label_visibility="collapsed",
        )

    # ── load filtered data ─────────────────────────────────────────
    cutoff = datetime.now(timezone.utc) - RANGE_DELTAS[flt["range"]]
    cutoff_iso = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    anomalies = [
        a for a in db.anomalies_since(cutoff_iso, limit=5000)
        if (a.get("severity") or "").upper() in flt["sev"]
        and (not flt["devices"] or a["device_ip"] in flt["devices"])
    ]
    devices_to_show = (flt["devices"] or
                       sorted({a["device_ip"] for a in anomalies} |
                              {d["ip"] for d in devices[:14]}))
    windows = db.windows_since(cutoff_iso, limit=20000)

    if not anomalies and not windows:
        empty_state("🟢", "All quiet",
                    f"Zero anomalies in the last {flt['range']}. "
                    "Try extending the range or lowering the threshold.")
        return

    # ── the swimlane chart ──────────────────────────────────────────
    _render_swimlanes(devices_to_show, windows, anomalies, threshold, cutoff)

    st.divider()

    # ── bottom row: fleet insight · severity mix · export ──────────
    b1, b2, b3 = st.columns([1, 1, 1])

    with b1:
        st.markdown("###### Severity · this range")
        counts = _severity_counts(anomalies)
        _render_severity_pie(counts)

    with b2:
        st.markdown("###### Fleet insight")
        _render_fleet_insight(anomalies, threshold)

    with b3:
        st.markdown("###### Export")
        if anomalies:
            csv = pd.DataFrame(anomalies).to_csv(index=False).encode()
            st.download_button(
                "⤓ Download anomalies CSV", data=csv,
                file_name=f"anomalies_{flt['range']}.csv", mime="text/csv",
                use_container_width=True,
            )
        st.caption("Includes id, device_ip, window_id, detected_at, score, severity, notes.")

    # ── anomaly list with drill-down to device ─────────────────────
    st.divider()
    st.markdown(f"###### Anomalies · {len(anomalies)} in range")
    _render_anomaly_table(anomalies, threshold, on_open_device)


def _render_swimlanes(device_ips, windows, anomalies, threshold, cutoff):
    if not device_ips:
        empty_state("🚸", "No matching devices", "Try widening filters.")
        return

    fig = go.Figure()
    now = datetime.now(timezone.utc)

    # Background score traces per device — thin grey
    if windows:
        wdf = pd.DataFrame(windows)
        wdf["window_start"] = pd.to_datetime(wdf["window_start"], errors="coerce", utc=True)
        wdf = wdf.dropna(subset=["window_start"])
        for i, ip in enumerate(device_ips):
            sub = wdf[wdf["device_ip"] == ip].sort_values("window_start")
            if sub.empty:
                continue
            # normalize score to a small Y band around the lane center
            y_mid = i
            score = sub["anomaly_score"].clip(-0.5, 0.3)
            # below threshold dips DOWN; positive bumps slightly UP (subtle)
            offset = ((threshold - score) / 0.5).clip(0, 1) * 0.42 - 0.05
            fig.add_trace(go.Scatter(
                x=sub["window_start"],
                y=[y_mid + o for o in offset],
                mode="lines",
                line=dict(color="rgba(150,160,180,0.45)", width=1),
                hoverinfo="skip", showlegend=False,
            ))

    # Anomaly markers
    by_sev = {}
    for a in anomalies:
        sev = (a.get("severity") or "MEDIUM").upper()
        by_sev.setdefault(sev, []).append(a)

    for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        color = SEVERITY_COLOR.get(sev, ORANGE)
        xs, ys, hover = [], [], []
        for a in items:
            if a["device_ip"] not in device_ips:
                continue
            y_lane = device_ips.index(a["device_ip"])
            score = max(min(a["score"], 0.3), -0.5)
            offset = max(0, (threshold - score) / 0.5) * 0.42
            xs.append(pd.to_datetime(a["detected_at"], utc=True, errors="coerce"))
            ys.append(y_lane + offset)
            hover.append(
                f"<b>{a['device_ip']}</b><br>"
                f"{sev} · score {a['score']:+.3f}<br>"
                f"{a.get('notes','')[:80]}"
            )
        size = {"CRITICAL": 11, "HIGH": 9, "MEDIUM": 7, "LOW": 5}[sev]
        fig.add_trace(go.Scatter(
            x=xs, y=ys, mode="markers",
            marker=dict(size=size, color=color, opacity=0.85,
                        line=dict(width=1, color="rgba(0,0,0,0.4)")),
            name=sev, hovertext=hover, hovertemplate="%{hovertext}<extra></extra>",
        ))

    # "now" line
    fig.add_vline(x=now, line=dict(color=RED, width=1.2, dash="dash"),
                  annotation_text="now", annotation_position="top",
                  annotation_font=dict(color=RED, size=10))

    fig.update_layout(
        **plotly_theme(),
        height=max(360, 48 * len(device_ips) + 80),
        yaxis=dict(
            tickmode="array",
            tickvals=list(range(len(device_ips))),
            ticktext=device_ips,
            range=[-0.6, len(device_ips) - 0.4],
            autorange="reversed",
            gridcolor="rgba(0,0,0,0)",
            zeroline=False,
        ),
        xaxis=dict(range=[cutoff, now], title=""),
        legend=dict(orientation="h", yanchor="top", y=1.08, xanchor="right", x=1),
    )
    st.plotly_chart(fig, use_container_width=True, key="tl_swim")


def _severity_counts(anomalies):
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in anomalies:
        s = (a.get("severity") or "MEDIUM").upper()
        if s in out: out[s] += 1
    return out


def _render_severity_pie(counts):
    total = sum(counts.values())
    if total == 0:
        st.caption("none")
        return
    fig = go.Figure(data=go.Pie(
        labels=list(counts.keys()),
        values=list(counts.values()),
        marker=dict(colors=[SEVERITY_COLOR[k] for k in counts.keys()]),
        textinfo="label+value", textfont=dict(color=TEXT, size=11),
        hovertemplate="<b>%{label}</b><br>%{value}<extra></extra>",
        hole=0.45,
    ))
    fig.update_layout(
        **plotly_theme(), height=210, showlegend=False,
        margin=dict(l=8, r=8, t=10, b=8),
    )
    st.plotly_chart(fig, use_container_width=True, key="tl_pie")


def _render_fleet_insight(anomalies, threshold):
    if not anomalies:
        st.caption("nothing to summarize")
        return
    df = pd.DataFrame(anomalies)
    top = df.groupby("device_ip").size().sort_values(ascending=False)
    total = len(anomalies)
    if top.empty:
        st.caption("nothing to summarize")
        return
    leader = top.index[0]
    leader_pct = top.iloc[0] / total * 100
    crit = df[df["severity"].str.upper() == "CRITICAL"]
    devices_w_any = top.index.nunique()
    insights = []
    if leader_pct >= 30:
        insights.append(f"• <code>{leader}</code> owns {leader_pct:.0f}% of alerts. Quarantine first.")
    if not crit.empty:
        worst = crit.sort_values("score").iloc[0]
        insights.append(f"• Worst score in range: <span style='color:{RED}'>{worst['score']:+.2f}</span> on <code>{worst['device_ip']}</code>.")
    if devices_w_any == 1:
        insights.append("• Only one device firing — isolated, not systemic.")
    st.markdown(
        "<div style='font-size:13px;line-height:1.7'>" +
        "<br>".join(insights or ["• Activity distributed across the fleet."]) +
        "</div>",
        unsafe_allow_html=True,
    )


def _render_anomaly_table(anomalies, threshold, on_open_device):
    for a in anomalies[:80]:
        sev = (a.get("severity") or "MEDIUM").upper()
        with st.container():
            cols = st.columns([1.2, 1.4, 1, 2.2, 3, 0.8])
            with cols[0]:
                st.caption(relative_time(a["detected_at"]))
            with cols[1]:
                st.markdown(
                    f"<span style='font-family:JetBrains Mono,monospace;font-size:11.5px'>"
                    f"{a['device_ip']}</span>",
                    unsafe_allow_html=True,
                )
            with cols[2]:
                st.markdown(badge_html(sev), unsafe_allow_html=True)
            with cols[3]:
                st.markdown(diverging_score_bar(a["score"], threshold=threshold),
                            unsafe_allow_html=True)
            with cols[4]:
                st.caption((a.get("notes") or "")[:90])
            with cols[5]:
                if st.button("→", key=f"tl_drill_{a['id']}"):
                    on_open_device(a["device_ip"])
    if len(anomalies) > 80:
        st.caption(f"… and {len(anomalies) - 80} more in this range. Export CSV for the full set.")
