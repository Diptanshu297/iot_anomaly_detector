from __future__ import annotations
from datetime import datetime, timedelta, timezone
import streamlit as st
from src.database import Database

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def quarantine_dialog(db: Database, ip: str, actor: str = "you@") -> None:
    st.markdown(f"<div style='color:var(--red);font-weight:700'>You are about to QUARANTINE {ip}</div>", unsafe_allow_html=True)
    st.caption("This will block outbound traffic at the gateway and keep capture alive for forensics.")
    typed = st.text_input(f"Type **{ip}** to confirm", key=f"qt_confirm_{ip}", placeholder=ip)
    col1, col2 = st.columns([1, 1])
    with col1:
        confirm = st.button(":red[🔒 Quarantine now]", key=f"qt_go_{ip}", disabled=typed != ip, use_container_width=True)
    with col2:
        cancel = st.button("Cancel", key=f"qt_cancel_{ip}", use_container_width=True)
    if confirm and typed == ip:
        db.add_action(ip, "quarantine", actor)
        st.session_state.pop(f"qt_confirm_{ip}", None)
        st.session_state.pop(f"open_qt_{ip}", None)
        st.success(f"Quarantined {ip}.")
        st.rerun()
    if cancel:
        st.session_state.pop(f"open_qt_{ip}", None)
        st.rerun()

def mute_button(db: Database, ip: str, hours: int, actor: str = "you@", key_prefix: str = "") -> None:
    if st.button(f"🔕 Mute {hours}h", key=f"{key_prefix}mute_{hours}_{ip}", use_container_width=True):
        expires = _iso(datetime.now(timezone.utc) + timedelta(hours=hours))
        db.add_action(ip, f"mute_{hours}h", actor, expires_at=expires)
        st.toast(f"Muted {ip} for {hours} hour{'s' if hours != 1 else ''}.")
        st.rerun()

def release_button(db: Database, ip: str, actor: str = "you@", key_prefix: str = "") -> None:
    if st.button("↻ Release", key=f"{key_prefix}rel_{ip}"):
        db.add_action(ip, "release", actor)
        st.toast(f"Released {ip}.")
        st.rerun()

def add_comment_form(db: Database, anomaly_id: int, actor: str = "you@") -> None:
    with st.form(f"comment_form_{anomaly_id}", clear_on_submit=True):
        body = st.text_area("Add a note", key=f"note_body_{anomaly_id}", height=70,
                            label_visibility="collapsed", placeholder="Add a note · @ to mention…")
        col1, col2, col3 = st.columns([1, 1, 4])
        with col1:
            submit = st.form_submit_button("Post")
        with col2:
            resolve = st.form_submit_button("✓ Resolve")
        with col3:
            st.caption("Notes persist in the comments table.")
        if submit and body.strip():
            db.add_comment(anomaly_id, actor, body.strip())
            st.rerun()
        if resolve:
            db.set_anomaly_resolved(anomaly_id, True)
            if body.strip():
                db.add_comment(anomaly_id, actor, body.strip())
            st.rerun()

def render_action_banners(active_actions: dict) -> None:
    quarantined = [a for a in active_actions.values() if a["action_type"] == "quarantine"]
    muted = [a for a in active_actions.values() if a["action_type"].startswith("mute_")]
    if quarantined:
        ips = ", ".join(a["device_ip"] for a in quarantined)
        st.markdown(f"<div class='banner-qt'>🔒 <strong>QUARANTINED</strong>: {ips}</div>", unsafe_allow_html=True)
    if muted:
        ips = ", ".join(f"{a['device_ip']} (until {a['expires_at']})" for a in muted)
        st.markdown(f"<div class='banner-mute'>🔕 <strong>MUTED</strong>: {ips}</div>", unsafe_allow_html=True)