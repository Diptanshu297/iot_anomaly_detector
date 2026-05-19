"""Overview page — OV-C "Threat-first" variant.

Alerts dominate. KPIs are reduced to chips above the fold so active
incidents are the page. Heatmap (color + shape) is at the bottom.
"""
from __future__ import annotations
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.database import Database
from src.ui import (
    BG, SURFACE, BORDER, TEXT_DIM, RED, ORANGE, YELLOW, GREEN, BLUE,
    SEVERITY_COLOR, SEVERITY_GLYPH,
    badge_html, diverging_score_bar, pulse_dot, relative_time,
    plotly_theme, empty_state, big_number,
)


def _fetch(db: Database) -> dict:
    anomalies = db.recent_anomalies(limit=50)
    # Resolve all 'resolved' flags in one query
    resolved_ids: set[int] = set()
    try:
        with db._conn() as c:
            rows = c.execute(
                "SELECT DISTINCT anomaly_id FROM comments WHERE resolved = 1"
            ).fetchall()
            resolved_ids = {r["anomaly_id"] for r in rows}
    except Exception:
        pass
    return {
        "devices":   db.list_devices(),
        "anomalies": anomalies,
        "windows":   db.recent_windows(limit=500),
        "counts_24h": db.severity_counts(since_iso=
            (pd.Timestamp.utcnow() - pd.Timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")),
        "total_w":   db.total_windows(),
        "comments":  db.comment_counts(),
        "active":    db.active_actions(),
        "resolved":  resolved_ids,
    }


def render(db: Database, threshold: float, on_drill_anomaly, on_open_device) -> None:
    data = _fetch(db)

    # ── header strip · KPI chips ────────────────────────────────────
    counts = data["counts_24h"]
    total_anom_24h = sum(counts.values())
    crit_today = counts.get("CRITICAL", 0)

    head_l, head_r = st.columns([3, 2])
    with head_l:
        st.markdown("### Threats")
        st.caption("active alerts dominate · KPIs as chips")
    with head_r:
        chips_html = (
            f"<div style='display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap'>"
            f"<span class='chip'>{len(data['devices'])} devices</span>"
            f"<span class='chip'>{data['total_w']:,} windows</span>"
            f"<span class='chip' style='color:{'var(--red)' if total_anom_24h else 'var(--text-dim)'}'>"
            f"{total_anom_24h} anom · 24h</span>"
            f"<span class='chip' style='color:{'var(--red)' if crit_today else 'var(--text-dim)'}'>"
            f"{crit_today} CRIT today</span>"
            f"</div>"
        )
        st.markdown(chips_html, unsafe_allow_html=True)

    if not data["devices"]:
        empty_state("📡", "No devices yet",
                    "Point your capture agent at <code>data/anomaly.db</code>.<br>"
                    "Once windows arrive, this page will fill itself.",
                    actions=["📖 setup guide", "↻ check again"])
        return

    # ── active alert cards ──────────────────────────────────────────
    active = data["active"]
    open_alerts = [a for a in data["anomalies"] if a["id"] not in data["resolved"]][:3]
    if open_alerts:
        st.markdown("###### ACTIVE ALERTS · click to drill down")
        cols = st.columns(min(len(open_alerts), 3))
        for col, a in zip(cols, open_alerts):
            sev = (a.get("severity") or "MEDIUM").upper()
            color = SEVERITY_COLOR.get(sev, ORANGE)
            with col:
                with st.container(border=True):
                    h1, h2 = st.columns([3, 1])
                    with h1:
                        st.markdown(
                            f"{pulse_dot(sev)} &nbsp;{badge_html(sev)}",
                            unsafe_allow_html=True,
                        )
                    with h2:
                        st.markdown(
                            f"<div style='text-align:right;color:var(--text-dim);font-size:11px'>"
                            f"{relative_time(a['detected_at'])}</div>",
                            unsafe_allow_html=True,
                        )
                    st.markdown(
                        f"<div style='font-family:JetBrains Mono,monospace;font-size:14px;"
                        f"margin-top:6px'>{a['device_ip']}</div>",
                        unsafe_allow_html=True,
                    )
                    st.markdown(
                        f"<div style='font-family:JetBrains Mono,monospace;font-size:30px;"
                        f"font-weight:700;color:{color};line-height:1;margin-top:4px'>"
                        f"{a['score']:+.2f}</div>",
                        unsafe_allow_html=True,
                    )
                    st.caption(a.get("notes") or "—")
                    cb1, cb2 = st.columns(2)
                    with cb1:
                        if st.button("Inspect", key=f"insp_{a['id']}", use_container_width=True):
                            on_drill_anomaly(a["id"])
                    with cb2:
                        if st.button("Device →", key=f"dev_{a['id']}", use_container_width=True):
                            on_open_device(a["device_ip"])
    else:
        st.success("🟢 No open alerts. The fleet is quiet.")

    st.divider()

    # ── feed + heatmap ──────────────────────────────────────────────
    feed_col, hm_col = st.columns([1.4, 1])

    with feed_col:
        st.markdown("###### RECENT ANOMALIES · last 20")
        if not data["anomalies"]:
            empty_state("🟢", "No anomalies", "Last 24 hours, zero alerts.")
        else:
            comments = data["comments"]
            for a in data["anomalies"][:20]:
                sev = (a.get("severity") or "MEDIUM").upper()
                muted_or_qt = active.get(a["device_ip"])
                muted_badge = ""
                if muted_or_qt:
                    t = muted_or_qt["action_type"]
                    muted_badge = " <span class='chip' style='color:var(--orange)'>🔒 quarantined</span>" if t == "quarantine" else " <span class='chip'>🔕 muted</span>"
                note_badge = ""
                if a["id"] in comments:
                    note_badge = f" <span class='chip'>💬 {comments[a['id']]}</span>"
                row = st.container()
                with row:
                    c1, c2, c3, c4, c5, c6 = st.columns([1.2, 1.6, 1, 2.2, 0.7, 0.7])
                    with c1:
                        st.caption(relative_time(a["detected_at"]))
                    with c2:
                        st.markdown(
                            f"<span style='font-family:JetBrains Mono,monospace;font-size:11.5px'>"
                            f"{a['device_ip']}</span>{muted_badge}",
                            unsafe_allow_html=True,
                        )
                    with c3:
                        st.markdown(badge_html(sev), unsafe_allow_html=True)
                    with c4:
                        st.markdown(diverging_score_bar(a["score"], threshold=threshold),
                                    unsafe_allow_html=True)
                    with c5:
                        st.markdown(note_badge, unsafe_allow_html=True)
                    with c6:
                        if st.button("→", key=f"feed_{a['id']}"):
                            on_drill_anomaly(a["id"])
                # truncated note
                if a.get("notes"):
                    st.markdown(
                        f"<div style='color:var(--text-dim);font-size:11px;"
                        f"margin: -8px 0 6px 0;padding-left:8px'>{a['notes'][:80]}{'…' if len(a['notes']) > 80 else ''}</div>",
                        unsafe_allow_html=True,
                    )

    with hm_col:
        st.markdown("###### NETWORK ACTIVITY · device × hour")
        _render_heatmap(data["windows"], data["devices"])


def _render_heatmap(windows: list, devices: list) -> None:
    """Plotly heatmap with severity glyphs overlaid for a11y."""
    if not windows:
        empty_state("📊", "No windows yet", "Waiting for the capture agent.")
        return
    df = pd.DataFrame(windows)
    if df.empty or "anomaly_score" not in df:
        empty_state("📊", "No windows yet", "Waiting for the capture agent.")
        return
    df["window_start"] = pd.to_datetime(df["window_start"], errors="coerce", utc=True)
    df = df.dropna(subset=["window_start"])
    df["hour"] = df["window_start"].dt.hour
    pivot = df.pivot_table(index="device_ip", columns="hour",
                           values="anomaly_score", aggfunc="mean")
    pivot = pivot.reindex(columns=range(24))
    # severity glyph overlay
    glyph = pivot.applymap(_glyph_for_score)
    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=[f"{h:02d}" for h in pivot.columns],
        y=pivot.index,
        colorscale=[[0.0, RED], [0.3, ORANGE], [0.55, YELLOW], [0.75, GREEN], [1.0, GREEN]],
        zmin=-0.5, zmax=0.3, zmid=0,
        text=glyph.values, texttemplate="%{text}",
        textfont=dict(size=10, color="#111"),
        hovertemplate="<b>%{y}</b><br>hour %{x}:00<br>score %{z:.3f}<extra></extra>",
        colorbar=dict(title="score", thickness=10, tickfont=dict(color=TEXT_DIM)),
    ))
    fig.update_layout(
        **plotly_theme(),
        height=380,
        xaxis=dict(title="hour of day", side="bottom"),
        yaxis=dict(title=""),
    )
    st.plotly_chart(fig, use_container_width=True, key="ov_heatmap")
    # legend
    st.caption("✕ critical · ▲ high · ● medium · · normal")


def _glyph_for_score(v) -> str:
    if v is None or pd.isna(v): return ""
    if v < -0.20: return "✕"
    if v < -0.05: return "▲"
    if v < 0.05:  return "●"
    return ""
