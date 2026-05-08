"""
frontend/dashboard.py - Streamlit SOC Dashboard for Log Analyzer.

Run with:
    streamlit run frontend/dashboard.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import requests
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
API_BASE = os.getenv("API_BASE", "http://localhost:8000")

st.set_page_config(
    page_title = "SOC Log Analyzer",
    page_icon  = "🛡️",
    layout     = "wide",
    initial_sidebar_state = "expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@400;600;700&display=swap');

  html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0b0f19;
    color: #e2e8f0;
  }
  .main { background-color: #0b0f19; }

  /* Metric cards */
  [data-testid="metric-container"] {
    background: rgba(30, 41, 59, 0.5);
    border: 1px solid rgba(148, 163, 184, 0.1);
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    backdrop-filter: blur(12px);
    transition: transform 0.2s;
  }
  [data-testid="metric-container"]:hover {
    transform: translateY(-2px);
    border-color: rgba(56, 189, 248, 0.3);
  }
  [data-testid="stMetricValue"] { color: #38bdf8; font-family: 'Share Tech Mono'; font-size: 2.5rem !important; font-weight: bold; }
  [data-testid="stMetricLabel"] { color: #94a3b8; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; font-size: 0.8rem; }

  /* Sidebar */
  [data-testid="stSidebar"] {
    background: #0f172a;
    border-right: 1px solid #1e293b;
  }
  [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
    color: #38bdf8;
    font-family: 'Share Tech Mono';
  }

  /* Section headers */
  h1 { color: #e0f2fe !important; font-family: 'Share Tech Mono' !important; font-weight: 700; }
  h2 { color: #f8fafc !important; font-weight: 600; }
  h3 { color: #cbd5e1 !important; font-weight: 600; }

  /* Alert badges */
  .badge-high   { background: rgba(220, 38, 38, 0.2); color: #fca5a5; border: 1px solid rgba(220, 38, 38, 0.5); padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }
  .badge-medium { background: rgba(217, 119, 6, 0.2); color: #fcd34d; border: 1px solid rgba(217, 119, 6, 0.5); padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }
  .badge-low    { background: rgba(22, 163, 74, 0.2); color: #86efac; border: 1px solid rgba(22, 163, 74, 0.5); padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }

  /* Alert card */
  .alert-card {
    background: rgba(30, 41, 59, 0.4);
    border-left: 4px solid #334155;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.8rem;
    font-family: 'Share Tech Mono';
    font-size: 0.85rem;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
  }
  .alert-card.high   { border-left-color: #ef4444; background: linear-gradient(90deg, rgba(239,68,68,0.05) 0%, rgba(30,41,59,0.4) 10%); }
  .alert-card.medium { border-left-color: #f59e0b; background: linear-gradient(90deg, rgba(245,158,11,0.05) 0%, rgba(30,41,59,0.4) 10%); }
  .alert-card.low    { border-left-color: #22c55e; background: linear-gradient(90deg, rgba(34,197,94,0.05) 0%, rgba(30,41,59,0.4) 10%); }

  /* Dataframe */
  .dataframe { background: #1e293b !important; color: #f8fafc !important; }

  /* Divider */
  hr { border-color: #1e293b; }

  /* Upload area */
  [data-testid="stFileUploader"] {
    background: rgba(30, 41, 59, 0.5);
    border: 2px dashed #475569;
    border-radius: 12px;
    padding: 2rem;
    transition: all 0.2s ease;
  }
  [data-testid="stFileUploader"]:hover {
    border-color: #38bdf8;
    background: rgba(30, 41, 59, 0.8);
  }

  /* Buttons */
  .stButton > button {
    background: linear-gradient(135deg, #0ea5e9 0%, #2563eb 100%);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 0.5rem 1rem;
    transition: all 0.2s;
  }
  .stButton > button:hover {
    background: linear-gradient(135deg, #38bdf8 0%, #3b82f6 100%);
    box-shadow: 0 4px 12px rgba(37,99,235,0.3);
    transform: translateY(-1px);
  }
  .stButton > button:active {
    transform: translateY(0);
  }

  /* Top bar */
  .top-bar {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem 0;
    border-bottom: 1px solid #1e293b;
    margin-bottom: 2rem;
  }
  .status-dot {
    width: 12px; height: 12px;
    background: #22c55e;
    border-radius: 50%;
    box-shadow: 0 0 12px #22c55e;
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1; transform: scale(1);} 50%{opacity:0.6; transform: scale(1.1);} }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def api_get(path: str, params: dict = None) -> dict | None:
    try:
        r = requests.get(f"{API_BASE}{path}", params=params, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        # Don't show the error immediately on health check to avoid scaring users if backend isn't up yet
        if path != "/health":
            st.error(f"API error [{path}]: {e}")
        return None


def severity_badge(sev: str) -> str:
    cls = sev.lower()
    return f'<span class="badge-{cls}">{sev}</span>'


def severity_color(sev: str) -> str:
    return {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#22c55e"}.get(sev, "#94a3b8")


def plotly_dark_layout(fig):
    fig.update_layout(
        paper_bgcolor = "rgba(0,0,0,0)",
        plot_bgcolor  = "rgba(0,0,0,0)",
        font          = dict(color="#e2e8f0", family="Inter"),
        margin        = dict(l=10, r=10, t=40, b=10),
        legend        = dict(bgcolor="rgba(30, 41, 59, 0.8)", bordercolor="rgba(148, 163, 184, 0.2)", borderwidth=1),
    )
    fig.update_xaxes(gridcolor="rgba(148, 163, 184, 0.1)", zerolinecolor="rgba(148, 163, 184, 0.1)")
    fig.update_yaxes(gridcolor="rgba(148, 163, 184, 0.1)", zerolinecolor="rgba(148, 163, 184, 0.1)")
    return fig


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("# 🛡️ SOC Analyzer")
    st.markdown("---")

    page = st.radio(
        "Navigation",
        ["📊 Dashboard", "🚨 Alerts", "📋 Log Explorer", "📤 Upload Logs", "📈 Reports"],
        label_visibility="collapsed",
    )

    st.markdown("---")

    # Health check
    health = api_get("/health")
    if health:
        st.success(f"API Online ✓")
    else:
        st.error("API Offline ✗")
        st.info(f"Start backend first:\n```bash\npython -m uvicorn backend.main:app --reload\n```")

    st.markdown("---")

    # Auto-refresh
    auto_refresh = st.checkbox("Auto-refresh (30s)", value=False)
    if auto_refresh:
        time.sleep(30)
        st.rerun()

    st.caption(f"Last updated: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

if page == "📊 Dashboard":
    st.markdown(
        '<div class="top-bar"><div class="status-dot"></div>'
        '<h1 style="margin:0">Security Operations Center</h1></div>',
        unsafe_allow_html=True,
    )

    if health:
        alert_summary = api_get("/alerts/summary") or {}
        log_stats     = api_get("/logs/stats")     or {}

        total_alerts   = alert_summary.get("total", 0)
        unresolved     = alert_summary.get("unresolved", 0)
        by_sev         = alert_summary.get("by_severity", {})
        total_logs     = log_stats.get("total_entries", 0)

        # ── KPI Row ────────────────────────────────────────────────────────────
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Logs",     f"{total_logs:,}")
        c2.metric("Total Alerts",   f"{total_alerts:,}")
        c3.metric("🔴 High",        f"{by_sev.get('HIGH', 0)}")
        c4.metric("🟡 Medium",      f"{by_sev.get('MEDIUM', 0)}")
        c5.metric("🟢 Low",         f"{by_sev.get('LOW', 0)}")

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Row 2: Alert breakdown + Top IPs ──────────────────────────────────
        col_left, col_right = st.columns([1, 1])

        with col_left:
            st.markdown("### 🔥 Alerts by Type")
            by_type = alert_summary.get("by_type", [])
            if by_type:
                df_type = pd.DataFrame(by_type).rename(columns={"type": "Alert Type", "count": "Count"})
                fig = px.bar(
                    df_type, x="Count", y="Alert Type", orientation="h",
                    color="Count", color_continuous_scale=["#0ea5e9", "#ef4444"],
                )
                plotly_dark_layout(fig)
                fig.update_coloraxes(showscale=False)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No alert data yet. Upload logs to begin analysis.")

        with col_right:
            st.markdown("### 🌐 Top Source IPs")
            top_ips = log_stats.get("top_ips", [])
            if top_ips:
                df_ips = pd.DataFrame(top_ips).rename(columns={"ip": "IP Address", "count": "Requests"})
                fig2 = px.bar(
                    df_ips, x="Requests", y="IP Address", orientation="h",
                    color="Requests", color_continuous_scale=["#0ea5e9", "#f59e0b"],
                )
                plotly_dark_layout(fig2)
                fig2.update_coloraxes(showscale=False)
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("No log data yet.")

        # ── Row 3: Status code pie + Engine split ─────────────────────────────
        col3, col4 = st.columns([1, 1])

        with col3:
            st.markdown("### 📡 HTTP Status Distribution")
            status_dist = log_stats.get("status_dist", [])
            if status_dist:
                df_status = pd.DataFrame(status_dist)
                df_status["status"] = df_status["status"].astype(str)
                color_map = {}
                for s in df_status["status"]:
                    if s.startswith("2"): color_map[s] = "#22c55e"
                    elif s.startswith("3"): color_map[s] = "#3b82f6"
                    elif s.startswith("4"): color_map[s] = "#f59e0b"
                    elif s.startswith("5"): color_map[s] = "#ef4444"
                    else: color_map[s] = "#94a3b8"
                fig3 = px.pie(
                    df_status, values="count", names="status",
                    color="status", color_discrete_map=color_map,
                    hole=0.5,
                )
                plotly_dark_layout(fig3)
                st.plotly_chart(fig3, use_container_width=True)
            else:
                st.info("No HTTP data yet.")

        with col4:
            st.markdown("### 🧠 Detection Engine Split")
            by_engine = alert_summary.get("by_engine", {})
            if by_engine:
                fig4 = go.Figure(go.Pie(
                    labels = list(by_engine.keys()),
                    values = list(by_engine.values()),
                    marker = dict(colors=["#0ea5e9", "#8b5cf6"]),
                    hole   = 0.5,
                    textinfo = "label+percent",
                ))
                plotly_dark_layout(fig4)
                st.plotly_chart(fig4, use_container_width=True)
            else:
                st.info("No alert engine data yet.")

        # ── Recent Alerts ──────────────────────────────────────────────────────
        st.markdown("### 🚨 Recent Alerts")
        recent = alert_summary.get("recent_alerts", [])
        if recent:
            for a in recent:
                sev = a.get("severity", "LOW")
                cls = sev.lower()
                ts  = a.get("timestamp", "")[:16].replace("T", " ")
                st.markdown(
                    f'<div class="alert-card {cls}">'
                    f'<b>{severity_badge(sev)}</b>&nbsp;&nbsp;'
                    f'<b style="color: #e2e8f0">{a.get("alert_type")}</b>'
                    f'<span style="float:right;color:#94a3b8">{ts}</span><br>'
                    f'<span style="color:#94a3b8">{a.get("source_ip")} &mdash; '
                    f'Score: <b style="color:#38bdf8">{a.get("risk_score", 0):.1f}</b></span><br>'
                    f'<span style="color: #cbd5e1">{a.get("description", "")[:120]}</span></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No alerts yet. Go to **Upload Logs** to start analysis.")
    else:
        st.warning("Backend API is offline. Start it to view dashboard data.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: ALERTS
# ══════════════════════════════════════════════════════════════════════════════

elif page == "🚨 Alerts":
    st.markdown("# 🚨 Alert Management")

    if not health:
        st.warning("Backend API is offline.")
    else:
        # Filters
        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            sev_filter = st.selectbox("Severity", ["All", "HIGH", "MEDIUM", "LOW"])
        with fcol2:
            res_filter = st.selectbox("Status", ["All", "Unresolved", "Resolved"])
        with fcol3:
            ip_filter = st.text_input("Source IP filter")

        params = {"limit": 200}
        if sev_filter != "All":    params["severity"] = sev_filter
        if res_filter == "Resolved":   params["resolved"] = True
        if res_filter == "Unresolved": params["resolved"] = False
        if ip_filter:              params["source_ip"] = ip_filter

        data = api_get("/alerts/", params) or {}
        alerts = data.get("alerts", [])

        st.markdown(f"**{data.get('total', 0)} total alerts** | showing {len(alerts)}")
        st.markdown("---")

        if alerts:
            for a in alerts:
                sev = a.get("severity", "LOW")
                cls = sev.lower()
                ts  = a.get("timestamp", "")[:19].replace("T", " ")
                res_icon = "✅" if a.get("resolved") else "⚠️"

                with st.expander(
                    f"{res_icon} [{sev}] {a.get('alert_type')} — {a.get('source_ip')} — {ts}"
                ):
                    cc1, cc2, cc3 = st.columns(3)
                    cc1.metric("Risk Score", f"{a.get('risk_score', 0):.1f}")
                    cc2.metric("Engine",     a.get("engine", "—"))
                    cc3.metric("Country",    a.get("country") or "N/A")
                    st.markdown(f"**Description:** {a.get('description')}")
                    if not a.get("resolved"):
                        if st.button(f"✅ Resolve #{a['id']}", key=f"res_{a['id']}"):
                            requests.patch(f"{API_BASE}/alerts/{a['id']}/resolve")
                            st.success("Resolved!")
                            st.rerun()
        else:
            st.info("No alerts match your filters.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: LOG EXPLORER
# ══════════════════════════════════════════════════════════════════════════════

elif page == "📋 Log Explorer":
    st.markdown("# 📋 Log Explorer")

    if not health:
        st.warning("Backend API is offline.")
    else:
        lcol1, lcol2, lcol3 = st.columns(3)
        with lcol1:
            type_filter = st.selectbox("Log Type", ["All", "apache", "ssh", "syslog"])
        with lcol2:
            ip_filter2 = st.text_input("Source IP")
        with lcol3:
            limit2 = st.slider("Rows to fetch", 20, 500, 100)

        params2 = {"limit": limit2}
        if type_filter != "All": params2["log_type"] = type_filter
        if ip_filter2:           params2["source_ip"] = ip_filter2

        data2 = api_get("/logs/", params2) or {}
        entries = data2.get("entries", [])

        st.markdown(f"**{data2.get('total', 0)} total entries** | displaying {len(entries)}")

        if entries:
            df = pd.DataFrame(entries)
            # Human-readable timestamp
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")

            # Colour status codes using proper styling mapping
            def style_status(val):
                if pd.isna(val) or val is None: return ""
                val = int(val) if str(val).isdigit() else 0
                if 200 <= val < 300: return "color: #22c55e"
                if 300 <= val < 400: return "color: #3b82f6"
                if 400 <= val < 500: return "color: #f59e0b"
                if 500 <= val < 600: return "color: #ef4444"
                return ""

            display_cols = [c for c in ["timestamp","source_ip","action","status","path","log_type","country"] if c in df.columns]
            
            # Use style.map instead of style.applymap for pandas >= 2.1.0
            styled_df = df[display_cols].style
            if "status" in df.columns:
                if hasattr(styled_df, 'map'):
                    styled_df = styled_df.map(style_status, subset=["status"])
                else:
                    styled_df = styled_df.applymap(style_status, subset=["status"])
            
            st.dataframe(
                styled_df,
                use_container_width=True,
                height=500,
            )

            # Timeline chart
            if "timestamp" in df.columns:
                st.markdown("### 📅 Log Timeline")
                df_t = df.copy()
                df_t["ts"] = pd.to_datetime(df_t["timestamp"])
                df_t["minute"] = df_t["ts"].dt.floor("min")
                timeline = df_t.groupby(["minute","log_type"]).size().reset_index(name="count")
                if not timeline.empty:
                    fig_t = px.line(
                        timeline, x="minute", y="count", color="log_type",
                        color_discrete_sequence=["#0ea5e9","#f59e0b","#22c55e"],
                    )
                    plotly_dark_layout(fig_t)
                    st.plotly_chart(fig_t, use_container_width=True)
        else:
            st.info("No log entries found. Try uploading a log file first.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: UPLOAD
# ══════════════════════════════════════════════════════════════════════════════

elif page == "📤 Upload Logs":
    st.markdown("# 📤 Upload Log File")
    st.markdown("""
    Upload an Apache access log, SSH auth log, or syslog file.
    The analyzer will automatically detect the format, parse entries,
    run rule-based and ML detection, and generate alerts.
    """)

    if not health:
        st.error("⚠️ Cannot upload logs while the Backend API is offline.")
    else:
        uploaded = st.file_uploader(
            "Drop a log file here",
            type=["log", "txt", "gz"],
            accept_multiple_files=False,
        )

        ucol1, ucol2 = st.columns(2)
        with ucol1:
            log_type_hint = st.selectbox(
                "Log Type (leave 'Auto' to detect)",
                ["Auto", "apache", "ssh", "syslog"],
            )
        with ucol2:
            enrich_geo = st.checkbox("GeoIP Enrichment", value=False,
                                      help="Slower but adds country/city data")

        # Quick-load sample files
        st.markdown("---")
        st.markdown("#### 📁 Or Load a Sample Dataset")
        scol1, scol2, scol3 = st.columns(3)

        for col, fname, label in [
            (scol1, "sample_apache.log", "🌐 Apache Logs"),
            (scol2, "sample_ssh.log",    "🔑 SSH Logs"),
            (scol3, "sample_syslog.log", "⚙️  Syslog"),
        ]:
            with col:
                if st.button(label, use_container_width=True):
                    sample_path = os.path.join(
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", fname,
                    )
                    if os.path.exists(sample_path):
                        with open(sample_path, "rb") as f:
                            files   = {"file": (fname, f, "text/plain")}
                            lt      = fname.split("_")[1].split(".")[0]
                            params3 = {"log_type": lt, "enrich_geo": False}
                            with st.spinner(f"Analyzing {fname}…"):
                                try:
                                    r = requests.post(
                                        f"{API_BASE}/logs/upload",
                                        files=files, params=params3, timeout=30,
                                    )
                                    result = r.json()
                                    if r.status_code == 200:
                                        st.success(
                                            f"✅ Parsed **{result['lines_parsed']}** lines | "
                                            f"**{result['alerts_generated']}** alerts generated"
                                        )
                                        st.json(result)
                                    else:
                                        st.error(f"Error: {result}")
                                except Exception as e:
                                    st.error(f"Request failed: {e}")
                    else:
                        st.warning(f"Sample file not found: {sample_path}")

        # Manual upload submission
        if uploaded:
            params4 = {"enrich_geo": enrich_geo}
            if log_type_hint != "Auto":
                params4["log_type"] = log_type_hint

            if st.button("🔍 Analyze File", type="primary", use_container_width=True):
                with st.spinner("Parsing and running detection engines…"):
                    try:
                        files = {"file": (uploaded.name, uploaded.getvalue(), "text/plain")}
                        r = requests.post(
                            f"{API_BASE}/logs/upload",
                            files=files, params=params4, timeout=60,
                        )
                        result = r.json()
                        if r.status_code == 200:
                            st.balloons()
                            st.success("Analysis complete!")
                            mcol1, mcol2, mcol3, mcol4 = st.columns(4)
                            mcol1.metric("Lines Parsed",  result.get("lines_parsed"))
                            mcol2.metric("Entries Saved", result.get("entries_saved"))
                            mcol3.metric("Alerts",        result.get("alerts_generated"))
                            mcol4.metric("Log Type",      result.get("log_type"))
                            st.json(result)
                        else:
                            st.error(f"Analysis failed: {result}")
                    except Exception as e:
                        st.error(f"Upload failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: REPORTS
# ══════════════════════════════════════════════════════════════════════════════

elif page == "📈 Reports":
    st.markdown("# 📈 Reports & Exports")

    if not health:
        st.warning("Backend API is offline.")
    else:
        rcol1, rcol2 = st.columns(2)

        with rcol1:
            st.markdown("### 📥 Export Alerts")
            st.markdown("Download all security alerts in your preferred format.")
            if st.button("⬇️ Download Alerts CSV", use_container_width=True):
                st.markdown(
                    f'<a href="{API_BASE}/reports/alerts/csv" target="_blank">'
                    f'Click here if download does not start automatically</a>',
                    unsafe_allow_html=True,
                )
                st.info(f"Open: {API_BASE}/reports/alerts/csv")

            if st.button("⬇️ Download Alerts PDF", use_container_width=True):
                st.info(f"Open: {API_BASE}/reports/alerts/pdf")

        with rcol2:
            st.markdown("### 📥 Export Log Entries")
            st.markdown("Download normalized log entries (last 5,000).")
            if st.button("⬇️ Download Logs CSV", use_container_width=True):
                st.info(f"Open: {API_BASE}/reports/logs/csv")

        st.markdown("---")
        st.markdown("### 🔗 API Endpoints")
        st.markdown(f"""
        | Endpoint | Description |
        |---|---|
        | `GET {API_BASE}/docs` | Interactive Swagger UI |
        | `POST {API_BASE}/logs/upload` | Upload & analyze a log file |
        | `GET {API_BASE}/logs/stats` | Aggregated log statistics |
        | `GET {API_BASE}/logs/stream` | SSE real-time log stream |
        | `GET {API_BASE}/alerts/` | List all alerts |
        | `GET {API_BASE}/alerts/summary` | Alert statistics |
        | `PATCH {API_BASE}/alerts/{{id}}/resolve` | Resolve an alert |
        | `GET {API_BASE}/reports/alerts/csv` | Export alerts as CSV |
        | `GET {API_BASE}/reports/alerts/pdf` | Export alerts as PDF |
        """)

        st.markdown("### 📡 Live Log Stream")
        if st.button("▶ Start Stream Preview"):
            placeholder = st.empty()
            try:
                import urllib.request
                url = f"{API_BASE}/logs/stream"
                lines = []
                with urllib.request.urlopen(url, timeout=10) as resp:
                    for raw in resp:
                        line = raw.decode("utf-8").strip()
                        if line.startswith("data:"):
                            try:
                                payload = json.loads(line[5:])
                                if payload.get("event") == "end":
                                    break
                                lines.append(
                                    f"{payload.get('timestamp','')[:19]} | "
                                    f"{payload.get('source_ip',''):>15} | "
                                    f"{payload.get('action',''):>8} | "
                                    f"{payload.get('status',''):>3}"
                                )
                                placeholder.code("\\n".join(lines[-20:]), language="")
                            except Exception:
                                pass
            except Exception as e:
                st.warning(f"Stream unavailable: {e}. Start the backend first.")
