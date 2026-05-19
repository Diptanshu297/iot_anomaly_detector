"""Device deep-dive page — DEV-D "Split-screen" variant.

Left: device info card + 4 time-series charts (anomaly score, packets,
unique destinations, protocol mix).
Right: anomaly list (selectable) + feature breakdown table.
Selecting a right-side anomaly marks its window on every chart.
"""
from __future__ import annotations
from datetime import timedelta
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.database import Database
from src.ui import (
    BG, SURFACE, BORDER, TEXT, TEXT_DIM,
    RED, ORANGE, YELLOW, GREEN, BLUE, PURPLE,
    SEVERITY_COLOR, badge_html, diverging_score_bar, plotly_theme,
    relative_time, empty_state, severity_glyph,
)
from src.actions import quarantine_dialog, mute_button, release_button, add_comment_form


def render(db: Database, ip: str, threshold: float,
           on_open_compare) -> None:
    if not ip:
        empty_state("🎯", "No device selected",
                    "Pick a device in the sidebar to inspect its windows and anomalies.")
        return

    device = db.device(ip)
    if not device:
        empty_state("🤷", f"{ip} not in the devices table",
                    "It may have rolled out of retention, or never been observed.")
        return

    windows   = db.recent_windows(device_ip=ip, limit=300)
    anomalies = db.device_anomalies(ip, limit=200)
    active    = db.active_actions()

    _render_info_card(device, windows, anomalies, threshold, active.get(ip))
    _render_action_row(db, ip, active.get(ip), on_open_compare)

    if len(windows) < 5:
        st.divider()
        progress = min(len(windows) / 30, 1.0)
        empty_state("🧪", "Still learning",
                    f"<code>{ip}</code> has only <strong>{len(windows)}</strong> windows. "
                    "The detector needs ≥ 30 to stabilize its baseline.")
        st.progress(progress, text=f"{len(windows)} / 30 windows")
        return

    st.divider()
    sel_id = st.session_state.get("dev_selected_anomaly")

    left, right = st.columns([2, 1], gap="large")

    with left:
        df         = _windows_df(windows)
        baseline   = _baseline(df)
        selected_t = _selected_window_time(df, anomalies, sel_id)
        _render_charts(df, baseline, threshold, selected_t)

    with right:
        _render_anomaly_list(db, anomalies, threshold, sel_id)
        st.divider()
        _render_feature_table(windows[:10], baseline)


# ─── info card ──────────────────────────────────────────────────────
def _render_info_card(device, windows, anomalies, threshold, active_action):
    df         = _windows_df(windows) if windows else pd.DataFrame()
    last_score = df.iloc[0]["anomaly_score"] if not df.empty else None
    last_24h_anom = 0
    if anomalies:
        cutoff = pd.Timestamp.utcnow() - pd.Timedelta(hours=24)
        last_24h_anom = sum(
            1 for a in anomalies
            if pd.to_datetime(a["detected_at"], utc=True, errors="coerce") and
               pd.to_datetime(a["detected_at"], utc=True, errors="coerce") >= cutoff
        )
    if active_action and active_action["action_type"] == "quarantine":
        status, color = "QUARANTINED", RED
    elif last_24h_anom >= 3:
        status, color = "COMPROMISED", RED
    elif last_24h_anom >= 1:
        status, color = "SUSPICIOUS", ORANGE
    else:
        status, color = "CLEAN", GREEN

    cols = st.columns([2, 1.4, 1, 1, 1.2])
    with cols[0]:
        st.markdown(
            f"<div style='font-family:JetBrains Mono,monospace;font-size:18px'>"
            f"{device['ip']}</div>"
            f"<div style='color:var(--text-dim);font-size:12px'>"
            f"{device.get('nickname') or '—'}</div>",
            unsafe_allow_html=True,
        )
    with cols[1]:
        st.markdown(
            "<div style='color:var(--text-dim);font-size:10px;text-transform:uppercase'>FIRST · LAST SEEN</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:11.5px'>"
            f"{device.get('first_seen') or '—'}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:11.5px;color:var(--text-dim)'>"
            f"{relative_time(device.get('last_seen'))}</div>",
            unsafe_allow_html=True,
        )
    with cols[2]:
        st.markdown(
            "<div style='color:var(--text-dim);font-size:10px;text-transform:uppercase'>WINDOWS</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:22px;font-weight:700'>"
            f"{len(windows):,}</div>",
            unsafe_allow_html=True,
        )
    with cols[3]:
        st.markdown(
            "<div style='color:var(--text-dim);font-size:10px;text-transform:uppercase'>ANOMALIES</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:22px;font-weight:700;color:{RED}'>"
            f"{len(anomalies)}</div>"
            f"<div style='color:var(--text-dim);font-size:10px'>{last_24h_anom} in 24h</div>",
            unsafe_allow_html=True,
        )
    with cols[4]:
        st.markdown(
            f"<div style='text-align:right'>{badge_html(status)}</div>"
            f"<div style='text-align:right;color:var(--text-dim);font-size:10px;margin-top:4px'>"
            f"≥3 anom/h ⇒ COMPROMISED</div>",
            unsafe_allow_html=True,
        )


def _render_action_row(db, ip, active_action, on_open_compare):
    cols = st.columns([1.4, 1, 1, 1, 1.6])
    with cols[0]:
        if active_action and active_action["action_type"] == "quarantine":
            release_button(db, ip, key_prefix="dev_")
        else:
            if st.button("🔒 Quarantine", key=f"dev_qt_open_{ip}",
                         use_container_width=True, type="primary"):
                st.session_state[f"open_qt_{ip}"] = True
    with cols[1]:
        mute_button(db, ip, 1, key_prefix="dev_")
    with cols[2]:
        mute_button(db, ip, 24, key_prefix="dev_")
    with cols[3]:
        if st.button("⚖ Compare", key=f"dev_cmp_{ip}", use_container_width=True):
            on_open_compare(ip)
    with cols[4]:
        st.caption("Compare opens side-by-side with a peer device.")

    if st.session_state.get(f"open_qt_{ip}"):
        with st.expander("⚠ Confirm quarantine", expanded=True):
            quarantine_dialog(db, ip)


# ─── helpers ────────────────────────────────────────────────────────
def _windows_df(windows: list) -> pd.DataFrame:
    df = pd.DataFrame(windows)
    if df.empty:
        return df
    df["window_start"] = pd.to_datetime(df["window_start"], errors="coerce", utc=True)
    df = df.dropna(subset=["window_start"]).sort_values("window_start")
    return df


def _baseline(df: pd.DataFrame) -> dict:
    if df.empty:
        return {}
    normal = df[df["anomaly_score"] >= 0] if "anomaly_score" in df else df
    if normal.empty:
        normal = df
    stats = {}
    for col in ["packet_count", "byte_count", "unique_dst_ips", "unique_dst_ports",
                "avg_packet_size", "tcp_ratio", "udp_ratio", "dns_count",
                "outbound_inbound_ratio"]:
        if col in normal:
            stats[col] = (normal[col].mean(), normal[col].std() or 0)
    return stats


def _selected_window_time(df: pd.DataFrame, anomalies: list, sel_id):
    if not sel_id:
        return None
    target = next((a for a in anomalies if a["id"] == sel_id), None)
    if not target or df.empty:
        return None
    return pd.to_datetime(target["detected_at"], utc=True, errors="coerce")


# ─── charts ─────────────────────────────────────────────────────────
def _render_charts(df, baseline, threshold, selected_t):
    if df.empty:
        empty_state("📊", "No windows", "Nothing to plot yet.")
        return

    # Chart 1 — anomaly score
    fig1 = go.Figure()
    below_thr = df["anomaly_score"] < threshold
    fig1.add_hrect(y0=-1, y1=threshold, fillcolor=RED, opacity=0.08, line_width=0)
    fig1.add_hline(y=threshold, line=dict(color=RED, width=1.4, dash="dash"),
                   annotation_text=f"threshold {threshold:+.2f}",
                   annotation_position="top left",
                   annotation_font=dict(color=RED, size=10))
    fig1.add_trace(go.Scatter(
        x=df["window_start"], y=df["anomaly_score"],
        mode="lines+markers",
        line=dict(color=TEXT, width=1.6),
        marker=dict(size=5, color=[RED if b else GREEN for b in below_thr]),
        hovertemplate="%{x|%H:%M:%S}<br>score %{y:.3f}<extra></extra>",
    ))
    if selected_t is not None and not pd.isna(selected_t):
        fig1.add_vline(x=selected_t, line=dict(color=YELLOW, width=1.2, dash="dot"))
    fig1.update_layout(
        **plotly_theme(), height=200,
        title=dict(text="anomaly score · threshold dashed",
                   font=dict(size=12, color=TEXT_DIM), x=0.01),
    )
    fig1.update_yaxes(title="score")
    fig1.update_xaxes(title="")
    st.plotly_chart(fig1, use_container_width=True, key="dev_score")

    # Chart 2 — packet rate
    fig2 = go.Figure()
    if "packet_count" in baseline:
        mu, sd = baseline["packet_count"]
        fig2.add_hrect(y0=max(0, mu - 2 * sd), y1=mu + 2 * sd,
                       fillcolor=BLUE, opacity=0.10, line_width=0,
                       annotation_text="±2σ baseline",
                       annotation_position="top left",
                       annotation_font=dict(color=BLUE, size=10))
    fig2.add_trace(go.Scatter(
        x=df["window_start"], y=df["packet_count"],
        mode="lines+markers",
        line=dict(color=BLUE, width=1.6), marker=dict(size=4, color=BLUE),
        hovertemplate="%{x|%H:%M:%S}<br>%{y:,} packets<extra></extra>",
    ))
    if selected_t is not None and not pd.isna(selected_t):
        fig2.add_vline(x=selected_t, line=dict(color=YELLOW, width=1.2, dash="dot"))
    fig2.update_layout(
        **plotly_theme(), height=170,
        title=dict(text="packet rate", font=dict(size=12, color=TEXT_DIM), x=0.01),
    )
    fig2.update_yaxes(title="packets/min")
    fig2.update_xaxes(title="")
    st.plotly_chart(fig2, use_container_width=True, key="dev_packets")

    # Charts 3 + 4 side by side
    c1, c2 = st.columns(2)
    with c1:
        fig3 = go.Figure()
        thr_count = (baseline.get("unique_dst_ips", (0, 0))[0]
                     + 2 * baseline.get("unique_dst_ips", (0, 0))[1])
        hi = df["unique_dst_ips"] > thr_count
        fig3.add_trace(go.Scatter(
            x=df["window_start"], y=df["unique_dst_ips"],
            mode="lines+markers",
            line=dict(color=ORANGE, width=1.6),
            marker=dict(size=[6 if h else 3 for h in hi],
                        color=[RED if h else ORANGE for h in hi]),
            hovertemplate="%{x|%H:%M:%S}<br>%{y} unique dst IPs<extra></extra>",
        ))
        if selected_t is not None and not pd.isna(selected_t):
            fig3.add_vline(x=selected_t, line=dict(color=YELLOW, width=1.2, dash="dot"))
        fig3.update_layout(
            **plotly_theme(), height=170,
            title=dict(text="unique destination IPs",
                       font=dict(size=12, color=TEXT_DIM), x=0.01),
        )
        fig3.update_yaxes(title="dst IPs")
        fig3.update_xaxes(title="")
        st.plotly_chart(fig3, use_container_width=True, key="dev_dst")

    with c2:
        fig4 = go.Figure()
        fig4.add_trace(go.Scatter(
            x=df["window_start"], y=df["tcp_ratio"],
            mode="lines", stackgroup="one", line=dict(width=0, color=BLUE),
            fillcolor="rgba(59,130,246,0.5)", name="TCP",
            hovertemplate="%{x|%H:%M:%S}<br>TCP %{y:.2f}<extra></extra>",
        ))
        fig4.add_trace(go.Scatter(
            x=df["window_start"], y=df["udp_ratio"],
            mode="lines", stackgroup="one", line=dict(width=0, color=PURPLE),
            fillcolor="rgba(168,85,247,0.5)", name="UDP",
            hovertemplate="%{x|%H:%M:%S}<br>UDP %{y:.2f}<extra></extra>",
        ))
        if selected_t is not None and not pd.isna(selected_t):
            fig4.add_vline(x=selected_t, line=dict(color=YELLOW, width=1.2, dash="dot"))
        fig4.update_layout(
            **plotly_theme(), height=170,
            title=dict(text="protocol mix · TCP / UDP",
                       font=dict(size=12, color=TEXT_DIM), x=0.01),
        )
        fig4.update_yaxes(title="ratio", range=[0, 1.05])
        fig4.update_xaxes(title="")
        st.plotly_chart(fig4, use_container_width=True, key="dev_proto")


# ─── right-rail anomaly list (selectable) ───────────────────────────
def _render_anomaly_list(db, anomalies, threshold, sel_id):
    st.markdown(f"###### Device anomalies · {len(anomalies)} total")
    if not anomalies:
        st.success("No anomalies on record for this device.")
        return
    for a in anomalies[:25]:
        sev    = (a.get("severity") or "MEDIUM").upper()
        is_sel = a["id"] == sel_id
        with st.container(border=is_sel):
            # Time + severity on one line
            st.markdown(
                f"<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap'>"
                f"<span style='color:var(--text-dim);font-size:11px;min-width:70px'>"
                f"{relative_time(a['detected_at'])}</span>"
                f"{badge_html(sev)}"
                f"<span style='font-family:JetBrains Mono,monospace;font-size:11px;"
                f"color:{'var(--red)' if a['score'] < threshold else 'var(--text)'}'>"
                f"{a['score']:+.3f}</span>"
                f"<span style='color:var(--text-dim);font-size:11px;flex:1'>"
                f"{(a.get('notes') or '')[:40]}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )
            # Select button on its own line
            btn_label = "• selected" if is_sel else "select"
            if st.button(btn_label, key=f"sel_anom_{a['id']}",
                         type=("primary" if is_sel else "secondary")):
                st.session_state["dev_selected_anomaly"] = (None if is_sel else a["id"])
                st.rerun()

    if sel_id:
        st.markdown("###### Notes")
        cmts = db.comments_for(sel_id)
        for c in cmts:
            st.markdown(
                f"<div style='padding:6px 0;border-top:1px solid var(--border)'>"
                f"<span style='font-family:JetBrains Mono,monospace;font-size:11px'>{c['author']}</span>"
                f" · <span style='color:var(--text-dim);font-size:11px'>"
                f"{relative_time(c['created_at'])}</span>"
                f"<div style='font-size:13px;margin-top:2px'>{c['body']}</div></div>",
                unsafe_allow_html=True,
            )
        add_comment_form(db, sel_id)


# ─── feature breakdown table ────────────────────────────────────────
def _render_feature_table(windows, baseline):
    if not windows:
        return
    st.markdown("###### Last 10 windows · red = exceeds baseline")
    df   = pd.DataFrame(windows)
    cols = ["window_start", "packet_count", "byte_count", "unique_dst_ips",
            "unique_dst_ports", "avg_packet_size", "tcp_ratio", "udp_ratio",
            "dns_count", "outbound_inbound_ratio"]
    df = df[[c for c in cols if c in df.columns]].head(10).copy()
    df["window_start"] = pd.to_datetime(
        df["window_start"], errors="coerce", utc=True).dt.strftime("%H:%M:%S")

    def style_row(row):
        styles = [""] * len(row)
        for i, c in enumerate(df.columns):
            if c in baseline:
                mu, sd = baseline[c]
                if sd and abs(row[c] - mu) > 2 * sd:
                    styles[i] = f"background-color:rgba(239,68,68,0.18);color:{RED};font-weight:700"
        return styles

    styled = (df.style
              .apply(style_row, axis=1)
              .format({"packet_count": "{:,}", "byte_count": "{:,}",
                       "avg_packet_size": "{:.0f}",
                       "tcp_ratio": "{:.2f}", "udp_ratio": "{:.2f}",
                       "outbound_inbound_ratio": "{:.2f}"})
              .set_properties(**{"font-family": "JetBrains Mono, monospace",
                                 "font-size": "11px"}))
    st.dataframe(styled, use_container_width=True, height=300)