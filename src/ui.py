from __future__ import annotations
import math
from datetime import datetime, timezone
from typing import Optional
import plotly.graph_objects as go
import streamlit as st

BG       = "#0e1117"
SURFACE  = "#1a1f2e"
BORDER   = "#2d3748"
TEXT     = "#e6e8eb"
TEXT_DIM = "#9aa0a6"
RED      = "#ef4444"
ORANGE   = "#f97316"
YELLOW   = "#eab308"
GREEN    = "#22c55e"
BLUE     = "#3b82f6"
PURPLE   = "#a855f7"

SEVERITY_COLOR = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN, "NORMAL": BLUE}
SEVERITY_GLYPH = {"CRITICAL": "✕", "HIGH": "▲", "MEDIUM": "●", "LOW": "·", "NORMAL": ""}

def severity_from_score(score: float, threshold: float = -0.15) -> str:
    if score < threshold - 0.20: return "CRITICAL"
    if score < threshold - 0.05: return "HIGH"
    if score < threshold:        return "MEDIUM"
    if score < 0:                return "LOW"
    return "NORMAL"

def parse_utc(s) -> Optional[datetime]:
    if not s: return None
    if isinstance(s, datetime): return s
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None

def relative_time(ts) -> str:
    dt = parse_utc(ts)
    if not dt: return "—"
    delta = (datetime.now(timezone.utc) - dt).total_seconds()
    if delta < 0:    return "in the future"
    if delta < 5:    return "just now"
    if delta < 60:   return f"{int(delta)}s ago"
    if delta < 3600: return f"{int(delta // 60)} min ago"
    if delta < 86400:
        h = int(delta // 3600)
        return f"{h} hr ago" if h > 1 else "1 hr ago"
    d = int(delta // 86400)
    return f"{d} days ago" if d > 1 else "1 day ago"

def inject_css() -> None:
    if st.session_state.get("_css_injected"): return
    st.session_state["_css_injected"] = True
    st.markdown(f"""
    <style>
      :root {{
        --bg: {BG}; --surface: {SURFACE}; --border: {BORDER};
        --text: {TEXT}; --text-dim: {TEXT_DIM};
        --red: {RED}; --orange: {ORANGE}; --yellow: {YELLOW};
        --green: {GREEN}; --blue: {BLUE}; --purple: {PURPLE};
      }}
      .main .block-container {{ padding-top: 1rem; max-width: 1500px; }}
      .stApp {{ background: var(--bg); }}
      [data-testid="stSidebar"] {{ background: #11151c; }}
      .sev-badge {{ display:inline-block; padding:2px 10px; border-radius:4px; font-size:10.5px;
        font-weight:700; letter-spacing:0.6px; text-transform:uppercase; line-height:1.4;
        font-family:'JetBrains Mono',ui-monospace,monospace; }}
      .sev-CRITICAL {{ background:rgba(239,68,68,0.16);  color:var(--red);    border:1px solid rgba(239,68,68,0.5); }}
      .sev-HIGH     {{ background:rgba(249,115,22,0.16); color:var(--orange); border:1px solid rgba(249,115,22,0.5); }}
      .sev-MEDIUM   {{ background:rgba(234,179,8,0.16);  color:var(--yellow); border:1px solid rgba(234,179,8,0.5); }}
      .sev-LOW      {{ background:rgba(34,197,94,0.16);  color:var(--green);  border:1px solid rgba(34,197,94,0.5); }}
      .sev-NORMAL   {{ background:rgba(59,130,246,0.16); color:var(--blue);   border:1px solid rgba(59,130,246,0.5); }}
      .pulse {{ position:relative; display:inline-block; width:10px; height:10px;
        border-radius:50%; vertical-align:middle; }}
      .pulse::after {{ content:''; position:absolute; inset:-3px; border-radius:50%;
        background:inherit; opacity:0.55; animation:pulse-ring 1.6s ease-out infinite; }}
      @keyframes pulse-ring {{ 0% {{ transform:scale(0.6); opacity:0.55; }} 100% {{ transform:scale(2.4); opacity:0; }} }}
      .pulse-red    {{ background:var(--red);    }}
      .pulse-orange {{ background:var(--orange); }}
      .pulse-yellow {{ background:var(--yellow); }}
      .pulse-green  {{ background:var(--green);  }}
      .pulse-blue   {{ background:var(--blue);   }}
      .card {{ background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:12px 14px; }}
      .card-alert {{ border-color:var(--red); box-shadow:0 0 0 1px rgba(239,68,68,0.3); }}
      .terminal {{ background:#0b0d10; border:1px solid var(--border); border-radius:4px;
        padding:10px 14px; font-family:'JetBrains Mono',ui-monospace,monospace; font-size:11.5px;
        color:#c5cbd2; line-height:1.55; overflow-x:auto; max-height:480px; overflow-y:auto; }}
      .terminal .t-meta {{ color:#5a6473; }}
      .terminal .t-crit {{ color:#ff6b5b; font-weight:700; }}
      .terminal .t-high {{ color:#ffa463; font-weight:700; }}
      .terminal .t-med  {{ color:#ffd966; }}
      .terminal .t-low  {{ color:#8de08d; }}
      .terminal .t-info {{ color:#93c5fd; }}
      .terminal .t-ip   {{ color:#93c5fd; }}
      .terminal .t-cursor::after {{ content:'▌'; color:#27c93f; animation:blink 1s steps(2) infinite; }}
      @keyframes blink {{ 50% {{ opacity:0; }} }}
      .empty {{ text-align:center; padding:60px 20px; color:var(--text-dim); }}
      .empty .emoji {{ font-size:56px; line-height:1; }}
      .empty .title {{ font-size:22px; color:var(--text); margin:14px 0 6px; font-weight:600; }}
      .banner-qt {{ background:rgba(239,68,68,0.1); border:1px solid var(--red); border-radius:4px;
        padding:10px 14px; display:flex; align-items:center; gap:12px; margin-bottom:12px; }}
      .banner-mute {{ background:rgba(234,179,8,0.1); border:1px solid var(--yellow); border-radius:4px;
        padding:10px 14px; display:flex; align-items:center; gap:12px; margin-bottom:12px; }}
      .chip {{ display:inline-block; padding:2px 8px; background:rgba(255,255,255,0.06);
        border-radius:10px; font-size:11px; color:var(--text-dim); }}
      .stat-strip {{ display:flex; gap:18px; flex-wrap:wrap; }}
      .stat-strip > div {{ min-width:80px; }}
      .stat-strip .label {{ font-size:10px; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.5px; }}
      .stat-strip .value {{ font-size:22px; font-weight:700; color:var(--text);
        font-family:'JetBrains Mono',ui-monospace,monospace; }}
    </style>
    """, unsafe_allow_html=True)

def plotly_theme() -> dict:
    return dict(
        paper_bgcolor=SURFACE,
        plot_bgcolor=SURFACE,
        font=dict(family="ui-sans-serif,-apple-system,system-ui", color=TEXT, size=11),
        margin=dict(l=42, r=14, t=28, b=34),
        hoverlabel=dict(bgcolor="#0b0d10", font=dict(color=TEXT, family="JetBrains Mono")),
    )

def badge_html(severity: str) -> str:
    sev = (severity or "NORMAL").upper()
    if sev not in SEVERITY_COLOR: sev = "NORMAL"
    glyph = SEVERITY_GLYPH.get(sev, "")
    g = f'<span style="margin-right:4px">{glyph}</span>' if glyph else ""
    return f'<span class="sev-badge sev-{sev}">{g}{sev}</span>'

def severity_glyph(severity: str) -> str:
    return SEVERITY_GLYPH.get((severity or "").upper(), "")

def diverging_score_bar(score: float, threshold: float = -0.15,
                        score_min: float = -0.5, score_max: float = 0.3) -> str:
    if score is None or (isinstance(score, float) and math.isnan(score)):
        return '<span style="color:var(--text-dim)">—</span>'
    rng = score_max - score_min
    zero_pct = (0 - score_min) / rng * 100
    thr_pct  = (threshold - score_min) / rng * 100
    width_pct = abs(score) / rng * 100
    if score < 0:
        fill = (f'<div style="position:absolute;right:{100-zero_pct}%;width:{width_pct}%;'
                f'top:2px;bottom:2px;background:var(--red);opacity:0.75"></div>')
    else:
        fill = (f'<div style="position:absolute;left:{zero_pct}%;width:{width_pct}%;'
                f'top:2px;bottom:2px;background:var(--green);opacity:0.7"></div>')
    return f"""
    <div style="position:relative;width:120px;height:14px;background:rgba(255,255,255,0.04);
                border-radius:2px;display:inline-block;vertical-align:middle">
      <div style="position:absolute;left:{thr_pct}%;top:0;bottom:0;width:1px;
                  background:var(--red);opacity:0.55"></div>
      <div style="position:absolute;left:{zero_pct}%;top:-2px;bottom:-2px;width:1.5px;
                  background:rgba(255,255,255,0.45)"></div>
      {fill}
    </div>
    <span style="margin-left:6px;font-family:'JetBrains Mono',monospace;font-size:11px;
                 color:{'var(--red)' if score < threshold else 'var(--text)'} ">
      {'+' if score >= 0 else ''}{score:.2f}
    </span>
    """

def pulse_dot(severity: str = "NORMAL") -> str:
    color_map = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"green","NORMAL":"blue"}
    klass = color_map.get((severity or "NORMAL").upper(), "blue")
    return f'<span class="pulse pulse-{klass}"></span>'

def empty_state(emoji: str, title: str, body: str = "", actions: list[str] = None) -> None:
    actions = actions or []
    chips = "".join(f'<span class="chip" style="margin:0 4px">{a}</span>' for a in actions)
    st.markdown(f"""
    <div class="empty">
      <div class="emoji">{emoji}</div>
      <div class="title">{title}</div>
      <div style="font-size:13px;line-height:1.5">{body}</div>
      <div style="margin-top:14px">{chips}</div>
    </div>
    """, unsafe_allow_html=True)

def big_number(value: str, label: str, color: str = TEXT, sub: str = "") -> str:
    return f"""
    <div>
      <div class="label" style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.5px">{label}</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:30px;font-weight:700;color:{color};line-height:1;margin-top:2px">{value}</div>
      {f'<div style="font-size:11px;color:var(--text-dim);margin-top:4px">{sub}</div>' if sub else ''}
    </div>
    """