"""
Cyber Threat Monitoring System — SOC Dashboard
SIH 2026 — Docker Backend Version
"""

from __future__ import annotations

import json
import socket
import time
from datetime import datetime
from typing import Any, Optional

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st
import streamlit.components.v1 as components

# ==========================================================================
# CONFIG
# ==========================================================================

DEFAULT_API_URL = "http://localhost:18000"
REQUEST_TIMEOUT = 4
CACHE_TTL = 3
GEO_CACHE_TTL = 3600

DEFAULT_HIGH_THRESHOLD = 70
DEFAULT_MED_THRESHOLD = 40

COLORS = {
    "bg_void": "#060a10",
    "bg_panel": "#0c131e",
    "bg_panel_alt": "#101a28",
    "grid": "#16222f",
    "cyan": "#2ee6d6",
    "red": "#ff3b5c",
    "amber": "#ffb020",
    "blue": "#4d8dff",
    "green": "#3ddc84",
    "text": "#e7f2f1",
    "text_dim": "#7c93a3",
}

SEV_COLOR = {"critical": COLORS["red"], "high": COLORS["red"], "medium": COLORS["amber"], "low": COLORS["blue"]}

st.set_page_config(
    page_title="Cyber Threat Monitoring — SOC",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded",
)

if "api_url" not in st.session_state:
    st.session_state.api_url = DEFAULT_API_URL
if "high_threshold" not in st.session_state:
    st.session_state.high_threshold = DEFAULT_HIGH_THRESHOLD
if "med_threshold" not in st.session_state:
    st.session_state.med_threshold = DEFAULT_MED_THRESHOLD
if "search_query" not in st.session_state:
    st.session_state.search_query = ""

# ==========================================================================
# STYLING
# ==========================================================================

st.markdown(
    f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    html, body, [class*="css"] {{
        font-family: 'JetBrains Mono', monospace;
    }}

    .stApp {{
        background:
            radial-gradient(circle at 15% 0%, rgba(46,230,214,0.06), transparent 40%),
            radial-gradient(circle at 85% 10%, rgba(255,59,92,0.05), transparent 35%),
            {COLORS['bg_void']};
    }}

    #MainMenu {{visibility: hidden;}}
    footer {{visibility: hidden;}}
    header[data-testid="stHeader"] {{background: transparent;}}

    h1, h2, h3 {{
        font-family: 'Space Grotesk', sans-serif !important;
        letter-spacing: 0.01em;
    }}

    .soc-title {{
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 700;
        font-size: 2.1rem;
        color: {COLORS['text']};
        margin-bottom: 0;
    }}
    .soc-subtitle {{
        color: {COLORS['text_dim']};
        font-size: 0.92rem;
        margin-top: 2px;
    }}

    .ticker-wrap {{
        width: 100%;
        overflow: hidden;
        background: {COLORS['bg_panel']};
        border: 1px solid {COLORS['grid']};
        border-radius: 8px;
        padding: 8px 0;
        margin-bottom: 1rem;
    }}
    .ticker-move {{
        display: inline-block;
        white-space: nowrap;
        animation: ticker-scroll 30s linear infinite;
        padding-left: 100%;
    }}
    @keyframes ticker-scroll {{
        0%   {{ transform: translateX(0); }}
        100% {{ transform: translateX(-100%); }}
    }}
    .ticker-item {{
        display: inline-block;
        margin-right: 3rem;
        font-size: 0.85rem;
        color: {COLORS['text']};
    }}

    .metric-card {{
        background: linear-gradient(160deg, {COLORS['bg_panel']} 0%, {COLORS['bg_panel_alt']} 100%);
        border: 1px solid {COLORS['grid']};
        border-left: 3px solid var(--accent, {COLORS['cyan']});
        border-radius: 10px;
        padding: 1rem 1.2rem;
    }}
    .metric-label {{
        font-size: 0.72rem;
        color: {COLORS['text_dim']};
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 0.35rem;
    }}
    .metric-value {{
        font-family: 'Space Grotesk', sans-serif;
        font-size: 2.1rem;
        font-weight: 700;
        color: {COLORS['text']};
    }}

    .status-dot {{
        height: 9px; width: 9px; border-radius: 50%;
        display: inline-block; margin-right: 6px;
    }}
    .status-online {{ background: {COLORS['green']}; box-shadow: 0 0 8px {COLORS['green']}; }}
    .status-offline {{ background: {COLORS['red']}; box-shadow: 0 0 8px {COLORS['red']}; }}

    .badge {{
        display: inline-block;
        padding: 2px 10px;
        border-radius: 10px;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.03em;
        color: #06090c;
    }}

    @keyframes pulse-glow {{
        0%   {{ box-shadow: 0 0 4px 0 rgba(255,59,92,0.5); }}
        50%  {{ box-shadow: 0 0 16px 4px rgba(255,59,92,0.75); }}
        100% {{ box-shadow: 0 0 4px 0 rgba(255,59,92,0.5); }}
    }}
    @keyframes slide-in {{
        from {{ transform: translateY(-14px); opacity: 0; }}
        to   {{ transform: translateY(0); opacity: 1; }}
    }}

    .alert-card {{
        background: {COLORS['bg_panel']};
        border: 1px solid {COLORS['grid']};
        border-left: 4px solid var(--accent, {COLORS['blue']});
        border-radius: 8px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.55rem;
        animation: slide-in 0.35s ease-out;
    }}
    .alert-card.critical {{ animation: slide-in 0.35s ease-out, pulse-glow 2.2s ease-in-out infinite; }}
    .alert-title {{ font-weight: 700; color: {COLORS['text']}; font-size: 0.95rem; }}
    .alert-meta {{ color: {COLORS['text_dim']}; font-size: 0.78rem; margin-top: 2px; }}

    table.soc-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    table.soc-table th {{
        text-align: left; padding: 8px 10px; border-bottom: 2px solid {COLORS['grid']};
        color: {COLORS['text_dim']}; text-transform: uppercase; font-size: 0.68rem; letter-spacing: 0.05em;
    }}
    table.soc-table td {{ padding: 7px 10px; border-bottom: 1px solid {COLORS['grid']}; color: {COLORS['text']}; }}
    table.soc-table tr:hover {{ background: {COLORS['bg_panel_alt']}; }}

    section[data-testid="stSidebar"] {{
        background: {COLORS['bg_panel']};
        border-right: 1px solid {COLORS['grid']};
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


def matrix_rain_background(height: int = 90) -> None:
    html = f"""
    <canvas id="matrixCanvas" style="width:100%; height:{height}px; display:block;
        background:{COLORS['bg_void']}; border:1px solid {COLORS['grid']}; border-radius:8px;"></canvas>
    <script>
    const canvas = document.getElementById('matrixCanvas');
    const ctx = canvas.getContext('2d');
    function resize() {{
        canvas.width = canvas.offsetWidth;
        canvas.height = {height};
    }}
    resize();
    window.addEventListener('resize', resize);
    const chars = "01アイウエオカキクケコ█▓▒░CYBERSOC";
    const fontSize = 13;
    let columns = Math.floor(canvas.width / fontSize);
    let drops = new Array(columns).fill(1);
    function draw() {{
        ctx.fillStyle = "rgba(6,10,16,0.18)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "{COLORS['cyan']}";
        ctx.font = fontSize + "px monospace";
        for (let i = 0; i < drops.length; i++) {{
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {{
                drops[i] = 0;
            }}
            drops[i]++;
        }}
    }}
    setInterval(draw, 60);
    </script>
    """
    components.html(html, height=height + 4)


# ==========================================================================
# API CLIENT
# ==========================================================================

class ApiError(Exception):
    pass


def _get(endpoint: str, params: Optional[dict] = None) -> Any:
    url = f"{st.session_state.api_url}{endpoint}"
    try:
        r = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError as exc:
        raise ApiError(f"Cannot reach backend at {st.session_state.api_url}.") from exc
    except requests.exceptions.Timeout as exc:
        raise ApiError(f"Request to {endpoint} timed out.") from exc
    except requests.exceptions.HTTPError as exc:
        raise ApiError(f"API error on {endpoint}: {exc}") from exc
    except ValueError as exc:
        raise ApiError(f"Invalid JSON from {endpoint}.") from exc


def update_alert_status(alert_id: Any, status: str) -> bool:
    url = f"{st.session_state.api_url}/alerts/{alert_id}"
    try:
        r = requests.put(url, json={"status": status}, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        st.toast(f"⚠️ Failed to update alert {alert_id}: {exc}", icon="⚠️")
        return False


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def fetch_events(api_url: str) -> pd.DataFrame:
    data = _get("/events")
    df = pd.DataFrame(data) if data else pd.DataFrame()
    if not df.empty and "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.sort_values("timestamp", ascending=False)
    return df


@st.cache_data(ttl=CACHE_TTL, show_spinner=False)
def fetch_alerts(api_url: str) -> pd.DataFrame:
    data = _get("/alerts")
    df = pd.DataFrame(data) if data else pd.DataFrame()
    if not df.empty and "created_at" in df.columns:
        df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce")
        df = df.sort_values("created_at", ascending=False)
    return df


def check_backend_health() -> bool:
    try:
        requests.get(f"{st.session_state.api_url}/events", timeout=2)
        return True
    except requests.exceptions.RequestException:
        return False


# ==========================================================================
# HELPERS
# ==========================================================================

def classify_severity(severity: str) -> str:
    if severity in ["critical", "high"]:
        return "critical"
    if severity == "medium":
        return "medium"
    return "low"


def badge_html(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color};">{text}</span>'


def metric_card(label: str, value: Any, accent: str, col) -> None:
    col.markdown(
        f"""
        <div class="metric-card" style="--accent:{accent};">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_table(df: pd.DataFrame) -> None:
    st.markdown(df.to_html(escape=False, index=False, classes="soc-table"), unsafe_allow_html=True)


def apply_search(df: pd.DataFrame, query: str, cols: list[str]) -> pd.DataFrame:
    if not query:
        return df
    query = query.lower()
    mask = pd.Series(False, index=df.index)
    for c in cols:
        if c in df.columns:
            mask = mask | df[c].astype(str).str.lower().str.contains(query, na=False)
    return df[mask]


def extract_payload_info(payload_str: str) -> dict:
    try:
        payload = json.loads(payload_str) if isinstance(payload_str, str) else payload_str
        if isinstance(payload, dict):
            return {
                "source_ip": payload.get("local_ip", payload.get("remote_ip", "?")),
                "destination": f"{payload.get('remote_ip', '?')}:{payload.get('remote_port', '?')}",
                "process": payload.get("process", "unknown"),
            }
    except:
        pass
    return {"source_ip": "?", "destination": "?", "process": "unknown"}


# ==========================================================================
# SIDEBAR
# ==========================================================================

with st.sidebar:
    st.markdown("## 🛰️ SOC Control")
    backend_ok = check_backend_health()
    dot = "status-online" if backend_ok else "status-offline"
    txt = "LIVE — backend connected" if backend_ok else "OFFLINE — backend unreachable"
    st.markdown(f'<span class="status-dot {dot}"></span>{txt}', unsafe_allow_html=True)
    st.caption(f"`{st.session_state.api_url}`")

    st.divider()
    auto_refresh = st.toggle("Live auto-refresh", value=True)
    refresh_interval = st.slider("Refresh interval (sec)", 2, 15, 3)

    st.divider()
    st.session_state.search_query = st.text_input(
        "🔎 Search (IP / domain / type)", value=st.session_state.search_query
    )

    st.divider()
    if st.button("🔄 Force refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.caption(f"Last sync: {datetime.now().strftime('%H:%M:%S')}")


# ==========================================================================
# HEADER
# ==========================================================================

st.markdown(
    '<div class="soc-title">🛡️ CYBER THREAT MONITORING SYSTEM</div>'
    '<div class="soc-subtitle">Behavioral anomaly detection · network telemetry · threat intelligence — SIH 2026</div>',
    unsafe_allow_html=True,
)
st.write("")
matrix_rain_background(height=70)

# ==========================================================================
# DATA FETCH
# ==========================================================================

try:
    events_df = fetch_events(st.session_state.api_url)
    alerts_df = fetch_alerts(st.session_state.api_url)
    fetch_error = None
except ApiError as exc:
    events_df, alerts_df = pd.DataFrame(), pd.DataFrame()
    fetch_error = str(exc)

if fetch_error:
    st.error(f"⚠️ {fetch_error}")
    st.stop()

# Process alerts
if not alerts_df.empty:
    alerts_df["severity_class"] = alerts_df.get("severity", "low").apply(classify_severity)
    if "status" not in alerts_df.columns:
        alerts_df["status"] = "open"
else:
    alerts_df["severity_class"] = pd.Series(dtype=str)

# Process events
if not events_df.empty and "payload" in events_df.columns:
    payload_info = events_df["payload"].apply(extract_payload_info)
    events_df["source_ip"] = payload_info.apply(lambda x: x["source_ip"])
    events_df["destination"] = payload_info.apply(lambda x: x["destination"])
    events_df["process"] = payload_info.apply(lambda x: x["process"])

# Apply search
events_view = apply_search(events_df, st.session_state.search_query, ["event_type", "source_ip", "destination", "payload"])
alerts_view = apply_search(alerts_df, st.session_state.search_query, ["reason", "severity", "status"])

# ==========================================================================
# LIVE TICKER
# ==========================================================================

if not alerts_view.empty:
    top_alerts = alerts_view.head(12)
    items = "".join(
        f'<span class="ticker-item">⚠ [{str(row.get("severity","low")).upper()}] '
        f'{row.get("reason","alert")[:50]} · status: {row.get("status","open")}</span>'
        for _, row in top_alerts.iterrows()
    )
    st.markdown(
        f'<div class="ticker-wrap"><div class="ticker-move">{items}{items}</div></div>',
        unsafe_allow_html=True,
    )

# ==========================================================================
# TABS
# ==========================================================================

tab_overview, tab_live, tab_map, tab_analytics, tab_settings = st.tabs(
    ["📊 Overview", "🟢 Live Feed", "🌍 Threat Map", "📈 Analytics", "⚙️ Settings"]
)

# --------------------------------------------------------------------------
# OVERVIEW
# --------------------------------------------------------------------------
with tab_overview:
    total_events = len(events_df)
    total_alerts = len(alerts_df)
    critical_count = int((alerts_df.get("severity_class") == "critical").sum()) if not alerts_df.empty else 0
    open_count = int((alerts_df.get("status") == "open").sum()) if not alerts_df.empty else 0

    c1, c2, c3, c4 = st.columns(4)
    metric_card("Total Events", f"{total_events:,}", COLORS["cyan"], c1)
    metric_card("Total Alerts", f"{total_alerts:,}", COLORS["blue"], c2)
    metric_card("Critical/High", f"{critical_count:,}", COLORS["red"], c3)
    metric_card("Open / New", f"{open_count:,}", COLORS["amber"], c4)

    st.write("")
    left, right = st.columns([2, 1])

    with left:
        st.subheader("Recent Critical & High-Risk Alerts")
        if alerts_view.empty:
            st.info("No alerts to display.")
        else:
            hot = alerts_view[alerts_view["severity_class"].isin(["critical"])].head(8)
            if hot.empty:
                st.success("No elevated-risk alerts right now.")
            for _, row in hot.iterrows():
                sev = row.get("severity", "low")
                accent = SEV_COLOR.get(sev, COLORS["blue"])
                css_class = "alert-card critical" if sev in ["critical", "high"] else "alert-card"
                st.markdown(
                    f"""
                    <div class="{css_class}" style="--accent:{accent};">
                        <div class="alert-title">{badge_html(sev.upper(), accent)} &nbsp; {row.get('reason','unknown')}</div>
                        <div class="alert-meta">
                            status: {row.get('status','open')} &nbsp;|&nbsp;
                            {row.get('created_at', '')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    with right:
        st.subheader("Alert Severity Breakdown")
        if alerts_view.empty or "severity" not in alerts_view.columns:
            st.info("No alert data.")
        else:
            counts = alerts_view["severity"].value_counts()
            fig = go.Figure(
                data=[go.Pie(labels=counts.index, values=counts.values, hole=0.55,
                              marker=dict(colors=[COLORS["cyan"], COLORS["red"], COLORS["amber"],
                                                   COLORS["blue"], COLORS["green"]], line=dict(color=COLORS["bg_void"], width=2)))]
            )
            fig.update_layout(
                margin=dict(t=10, b=10, l=10, r=10), height=300, showlegend=True,
                legend=dict(font=dict(color=COLORS["text_dim"], size=10)),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color=COLORS["text"]),
            )
            st.plotly_chart(fig, use_container_width=True)

# --------------------------------------------------------------------------
# LIVE FEED
# --------------------------------------------------------------------------
with tab_live:
    st.subheader("🟢 Live Event & Alert Stream")

    sev_filter = st.multiselect(
        "Filter by severity", options=["critical", "high", "medium", "low"],
        default=["critical", "high", "medium", "low"], key="live_sev_filter",
    )

    feed_alerts = alerts_view[alerts_view["severity"].isin(sev_filter)] if not alerts_view.empty else alerts_view

    col_alerts, col_events = st.columns(2)

    with col_alerts:
        st.markdown("**Alerts** (click to acknowledge / dismiss)")
        if feed_alerts.empty:
            st.info("No alerts match current filters.")
        else:
            for _, row in feed_alerts.head(30).iterrows():
                sev = row.get("severity", "low")
                accent = SEV_COLOR.get(sev, COLORS["blue"])
                css_class = "alert-card critical" if sev in ["critical", "high"] else "alert-card"
                aid = row.get("id")
                status = row.get("status", "open")
                reason = row.get("reason", "Unknown")
                with st.container():
                    st.markdown(
                        f"""
                        <div class="{css_class}" style="--accent:{accent};">
                            <div class="alert-title">{badge_html(sev.upper(), accent)} &nbsp; #{aid}</div>
                            <div class="alert-meta">
                                {reason[:80]}{'...' if len(reason) > 80 else ''} &nbsp;|&nbsp;
                                status: <b>{status}</b> &nbsp;|&nbsp; {row.get('created_at', '')}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    b1, b2 = st.columns(2)
                    if status == "open":
                        if b1.button("✅ Acknowledge", key=f"ack_{aid}", use_container_width=True):
                            if update_alert_status(aid, "acknowledged"):
                                st.cache_data.clear()
                                st.rerun()
                        if b2.button("🚫 Dismiss", key=f"dis_{aid}", use_container_width=True):
                            if update_alert_status(aid, "dismissed"):
                                st.cache_data.clear()
                                st.rerun()
                    else:
                        st.caption(f"Resolved — {status}")

    with col_events:
        st.markdown("**Raw Events**")
        if events_view.empty:
            st.info("No events match current filters.")
        else:
            ev_cols = [c for c in ["id", "event_type", "source_ip", "destination", "timestamp", "risk_score"] if c in events_view.columns]
            disp = events_view[ev_cols].head(30).copy()
            if "timestamp" in disp.columns:
                disp["timestamp"] = disp["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
            render_table(disp)

    st.divider()
    exp_col1, exp_col2 = st.columns(2)
    with exp_col1:
        if not alerts_view.empty:
            st.download_button(
                "⬇️ Export alerts (CSV)",
                data=alerts_view.to_csv(index=False).encode("utf-8"),
                file_name=f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
    with exp_col2:
        if not events_view.empty:
            st.download_button(
                "⬇️ Export events (CSV)",
                data=events_view.to_csv(index=False).encode("utf-8"),
                file_name=f"events_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )

# --------------------------------------------------------------------------
# THREAT MAP
# --------------------------------------------------------------------------
with tab_map:
    st.subheader("🌍 Geographic Threat Origins")
    st.caption("Network connections from events (internal IPs shown as LAN)")

    if events_view.empty or "source_ip" not in events_view.columns:
        st.info("No connection data to map.")
    else:
        ips = pd.unique(events_view["source_ip"].dropna())
        geo_rows = []
        for ip in ips[:40]:
            if ip.startswith(("127.", "::1", "192.168.", "10.")):
                geo_rows.append({"lat": 20.5937, "lon": 78.9629, "city": "Internal", "country": "LAN", "ip": ip})
            else:
                try:
                    resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("status") == "success":
                            geo_rows.append({
                                "lat": data.get("lat"),
                                "lon": data.get("lon"),
                                "city": data.get("city", "Unknown"),
                                "country": data.get("country", "Unknown"),
                                "ip": ip,
                            })
                except:
                    pass

        if not geo_rows:
            st.warning("Could not resolve any locations.")
        else:
            geo_df = pd.DataFrame(geo_rows)
            counts = geo_df.groupby(["lat", "lon", "city", "country"]).size().reset_index(name="count")
            fig_map = go.Figure(
                go.Scattergeo(
                    lat=counts["lat"], lon=counts["lon"],
                    text=counts.apply(lambda r: f"{r['city']}, {r['country']} — {r['count']} hit(s)", axis=1),
                    marker=dict(
                        size=(counts["count"] * 6 + 8).clip(upper=40),
                        color=COLORS["red"], opacity=0.75,
                        line=dict(width=1, color=COLORS["cyan"]),
                    ),
                )
            )
            fig_map.update_layout(
                geo=dict(
                    bgcolor="rgba(0,0,0,0)", landcolor=COLORS["bg_panel_alt"],
                    showocean=True, oceancolor=COLORS["bg_void"],
                    showcountries=True, countrycolor=COLORS["grid"],
                    showframe=False,
                ),
                margin=dict(t=10, b=10, l=10, r=10), height=480,
                paper_bgcolor="rgba(0,0,0,0)", font=dict(color=COLORS["text"]),
            )
            st.plotly_chart(fig_map, use_container_width=True)

    st.divider()
    st.subheader("🔗 Connection Network")
    st.caption("Nodes = IPs observed in events. Edges = connections.")

    if events_view.empty or "source_ip" not in events_view.columns:
        st.info("No connection data available.")
    else:
        edges = events_view[["source_ip", "destination"]].dropna().drop_duplicates().head(60)
        nodes = pd.unique(pd.concat([edges["source_ip"], edges["destination"]]))

        import math
        n = len(nodes)
        positions = {
            node: (math.cos(2 * math.pi * i / max(n, 1)), math.sin(2 * math.pi * i / max(n, 1)))
            for i, node in enumerate(nodes)
        }

        edge_x, edge_y = [], []
        for _, row in edges.iterrows():
            x0, y0 = positions.get(row["source_ip"], (0, 0))
            x1, y1 = positions.get(row["destination"], (0, 0))
            edge_x += [x0, x1, None]
            edge_y += [y0, y1, None]

        node_x = [positions.get(n, (0, 0))[0] for n in nodes]
        node_y = [positions.get(n, (0, 0))[1] for n in nodes]

        fig_net = go.Figure()
        fig_net.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines",
                                      line=dict(color=COLORS["grid"], width=1), hoverinfo="none"))
        fig_net.add_trace(go.Scatter(
            x=node_x, y=node_y, mode="markers+text", text=list(nodes), textposition="top center",
            textfont=dict(color=COLORS["text_dim"], size=9),
            marker=dict(size=16, color=COLORS["cyan"], line=dict(width=1, color=COLORS["bg_void"])),
        ))
        fig_net.update_layout(
            showlegend=False, height=480,
            xaxis=dict(visible=False), yaxis=dict(visible=False),
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_net, use_container_width=True)

# --------------------------------------------------------------------------
# ANALYTICS
# --------------------------------------------------------------------------
with tab_analytics:
    st.subheader("📈 Events Over Time")
    if events_view.empty or "timestamp" not in events_view.columns:
        st.info("No event data.")
    else:
        ts = events_view.dropna(subset=["timestamp"]).copy()
        ts["bucket"] = ts["timestamp"].dt.floor("min")
        series = ts.groupby("bucket").size().reset_index(name="count")
        fig_line = go.Figure(
            go.Scatter(x=series["bucket"], y=series["count"], mode="lines+markers",
                       line=dict(color=COLORS["cyan"], width=2), marker=dict(size=5),
                       fill="tozeroy", fillcolor="rgba(46,230,214,0.12)")
        )
        fig_line.update_layout(
            height=320, margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=COLORS["text"]),
            xaxis=dict(gridcolor=COLORS["grid"]), yaxis=dict(gridcolor=COLORS["grid"], title="events / min"),
        )
        st.plotly_chart(fig_line, use_container_width=True)

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Event Types")
        if events_view.empty or "event_type" not in events_view.columns:
            st.info("No event type data.")
        else:
            counts = events_view["event_type"].value_counts().head(10)
            fig_bar = go.Figure(
                go.Bar(x=counts.index, y=counts.values, marker_color=COLORS["cyan"])
            )
            fig_bar.update_layout(
                height=300, margin=dict(t=10, b=10, l=10, r=10),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color=COLORS["text"]),
                xaxis=dict(gridcolor=COLORS["grid"], tickangle=45), yaxis=dict(gridcolor=COLORS["grid"]),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

    with col_b:
        st.subheader("Alert Severity Distribution")
        if alerts_view.empty or "severity" not in alerts_view.columns:
            st.info("No severity data.")
        else:
            counts = alerts_view["severity"].value_counts()
            fig_pie = go.Figure(
                data=[go.Pie(labels=counts.index, values=counts.values, hole=0.5,
                              marker=dict(colors=[COLORS["red"], COLORS["amber"], COLORS["blue"], COLORS["green"]]))]
            )
            fig_pie.update_layout(
                margin=dict(t=10, b=10, l=10, r=10), height=300,
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color=COLORS["text"]),
            )
            st.plotly_chart(fig_pie, use_container_width=True)

# --------------------------------------------------------------------------
# SETTINGS
# --------------------------------------------------------------------------
with tab_settings:
    st.subheader("⚙️ Configuration")

    st.session_state.api_url = st.text_input("Backend API URL", value=st.session_state.api_url)

    st.divider()
    st.markdown("**About**")
    st.caption(
        "Cyber Threat Monitoring System — SIH 2026. Data sources: network traffic monitor, "
        "browser extension, file-system watcher, ML anomaly scorer, and threat-intel IoC checks. "
        "This dashboard is read-only against `/events` and `/alerts`, and writes only alert status "
        "updates via `PUT /alerts/{id}`."
    )

    if st.button("Clear cached data"):
        st.cache_data.clear()
        st.success("Cache cleared.")

# ==========================================================================
# AUTO-REFRESH LOOP
# ==========================================================================

if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()
