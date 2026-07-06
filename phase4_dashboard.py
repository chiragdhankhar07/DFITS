"""
DFITS - Digital Forensic Intelligence & Timeline System
Phase 4: Streamlit Dashboard

Run:  streamlit run phase4_dashboard.py -- --db dfits_evidence.db

Install first:
    pip install streamlit plotly pandas
"""

import json
import sqlite3
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))
from phase1_parser    import parse_file, build_timeline, save_json
from phase2_timeline  import init_db, ingest_json, TimelineEngine
from phase3_detection import DetectionEngine, compute_case_score


# ─────────────────────────────────────────────
#  PAGE CONFIG  (must be first Streamlit call)
# ─────────────────────────────────────────────

st.set_page_config(
    page_title="DFITS — Digital Forensic Intelligence",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
#  CUSTOM CSS
# ─────────────────────────────────────────────

st.markdown("""
<style>
[data-testid="stSidebar"] { background: #0f1117; }
[data-testid="stSidebar"] * { color: #e0e0e0 !important; }

.alert-critical { border-left:4px solid #ef4444; background:#1c0a0a;
                  padding:12px 16px; border-radius:6px; margin-bottom:10px; }
.alert-high     { border-left:4px solid #f97316; background:#1c1008;
                  padding:12px 16px; border-radius:6px; margin-bottom:10px; }
.alert-medium   { border-left:4px solid #eab308; background:#1a1800;
                  padding:12px 16px; border-radius:6px; margin-bottom:10px; }
.alert-low      { border-left:4px solid #3b82f6; background:#080c1c;
                  padding:12px 16px; border-radius:6px; margin-bottom:10px; }

.alert-title  { font-size:15px; font-weight:600; color:#f0f0f0; margin-bottom:4px; }
.alert-meta   { font-size:12px; color:#9ca3af; margin-bottom:6px; }
.alert-desc   { font-size:13px; color:#d1d5db; margin-bottom:8px; }
.alert-action { font-size:12px; color:#93c5fd; font-style:italic; }
.ev-pill      { display:inline-block; background:#1f2937; color:#9ca3af;
                font-size:11px; padding:2px 8px; border-radius:10px;
                margin:2px; font-family:monospace; }

.risk-critical { background:linear-gradient(90deg,#7f1d1d,#1c0a0a);
                 border:1px solid #ef4444; padding:16px 24px;
                 border-radius:8px; text-align:center; }
.risk-high     { background:linear-gradient(90deg,#431407,#1c1008);
                 border:1px solid #f97316; padding:16px 24px;
                 border-radius:8px; text-align:center; }
.risk-medium   { background:linear-gradient(90deg,#422006,#1a1800);
                 border:1px solid #eab308; padding:16px 24px;
                 border-radius:8px; text-align:center; }
.risk-low      { background:linear-gradient(90deg,#1e3a5f,#080c1c);
                 border:1px solid #3b82f6; padding:16px 24px;
                 border-radius:8px; text-align:center; }
.risk-score   { font-size:48px; font-weight:800; color:#f9fafb; }
.risk-label   { font-size:14px; color:#9ca3af; margin-top:4px; }

[data-testid="metric-container"] {
  background:#1a1a2e; border-radius:8px;
  padding:12px; border:1px solid #2d2d4e;
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────

SEV_COLOR = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#3b82f6"}
SEV_ICON  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}
SRC_COLOR = {"log":"#6366f1","whatsapp":"#22c55e","browser":"#f59e0b","mobile":"#ec4899"}

# ─────────────────────────────────────────────
#  DB / ENGINE  (cached)
# ─────────────────────────────────────────────

@st.cache_resource
def get_connection(db_path: str):
    return init_db(db_path)


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def sev_badge(sev: str) -> str:
    c = SEV_COLOR.get(sev, "#6b7280")
    return (f'<span style="background:{c};color:#fff;font-size:11px;'
            f'padding:2px 8px;border-radius:10px;font-weight:600">{sev}</span>')


def render_alert_card(alert: dict):
    sev  = alert["severity"].lower()
    icon = SEV_ICON.get(alert["severity"], "⚪")
    ids  = " ".join(f'<span class="ev-pill">ID:{i}</span>'
                    for i in alert["evidence_ids"])
    snips = "".join(
        f'<div style="font-size:12px;color:#6b7280;font-family:monospace;'
        f'padding:2px 0 2px 8px;border-left:2px solid #374151;margin:2px 0">'
        f'{s[:90]}</div>'
        for s in alert["evidence_snippets"][:4]
    )
    action = (f'<div class="alert-action">⚡ {alert["recommendation"]}</div>'
              if alert.get("recommendation") else "")
    st.markdown(f"""
    <div class="alert-{sev}">
      <div class="alert-title">{icon} {alert['rule_id']} — {alert['rule_name']}</div>
      <div class="alert-meta">{sev_badge(alert['severity'])}
        &nbsp; Confidence: <b>{alert['confidence']}%</b>
        &nbsp;·&nbsp; {alert['detected_at'][:19]}</div>
      <div class="alert-desc">{alert['description']}</div>
      {snips}
      <div style="margin-top:8px">{ids}</div>
      {action}
    </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  CHARTS
# ─────────────────────────────────────────────

def _layout(fig, title, h=300):
    fig.update_layout(
        title=title, height=h,
        plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
        font_color="#e0e0e0",
        margin=dict(l=10, r=10, t=40, b=10),
    )
    fig.update_xaxes(gridcolor="#2d2d4e")
    fig.update_yaxes(gridcolor="#2d2d4e")
    return fig


def chart_timeline_scatter(df: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    if df.empty:
        return fig
    for src, grp in df[df["flagged"] == 0].groupby("source_type"):
        fig.add_trace(go.Scatter(
            x=grp["timestamp"], y=grp["source_type"],
            mode="markers", name=src,
            marker=dict(size=10, color=SRC_COLOR.get(src, "#9ca3af"),
                        opacity=0.8, symbol="circle"),
            text=grp["description"].str[:80],
            hovertemplate="<b>%{x}</b><br>%{text}<extra></extra>",
        ))
    flagged = df[df["flagged"] == 1]
    if not flagged.empty:
        fig.add_trace(go.Scatter(
            x=flagged["timestamp"], y=flagged["source_type"],
            mode="markers", name="⚠ Flagged",
            marker=dict(size=14, color="#ef4444", symbol="x",
                        line=dict(width=2, color="#ff0000")),
            text=flagged["event_type"] + ": " + flagged["description"].str[:60],
            hovertemplate="<b>FLAGGED %{x}</b><br>%{text}<extra></extra>",
        ))
    fig.update_layout(legend=dict(orientation="h", yanchor="bottom", y=1.02))
    return _layout(fig, "Event timeline — all sources", h=300)


def chart_density(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return go.Figure()
    d = df.copy()
    d["minute"] = d["timestamp"].dt.floor("min")
    den = d.groupby("minute").agg(count=("id","count"), flagged=("flagged","sum")).reset_index()
    colors = ["#ef4444" if f > 0 else "#6366f1" for f in den["flagged"]]
    fig = go.Figure(go.Bar(
        x=den["minute"], y=den["count"],
        marker_color=colors,
        hovertemplate="<b>%{x}</b><br>Events: %{y}<extra></extra>",
    ))
    return _layout(fig, "Activity density per minute  (red = flagged events)", h=240)


def chart_donut(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return go.Figure()
    counts = df["event_type"].value_counts().reset_index()
    counts.columns = ["event_type","count"]
    palette = ["#6366f1","#22c55e","#f59e0b","#ef4444","#ec4899",
               "#14b8a6","#8b5cf6","#f97316","#06b6d4","#84cc16","#e11d48"]
    fig = go.Figure(go.Pie(
        labels=counts["event_type"], values=counts["count"],
        hole=0.55, marker=dict(colors=palette[:len(counts)]),
        textinfo="label+percent",
        hovertemplate="<b>%{label}</b><br>Count: %{value}<extra></extra>",
    ))
    fig.update_layout(showlegend=False)
    return _layout(fig, "Event type distribution", h=320)


def chart_source_bar(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return go.Figure()
    c = df.groupby(["source_file","source_type"])["id"].count().reset_index()
    c.columns = ["source_file","source_type","count"]
    fig = go.Figure(go.Bar(
        x=c["count"], y=c["source_file"], orientation="h",
        marker_color=[SRC_COLOR.get(s,"#9ca3af") for s in c["source_type"]],
        text=c["count"], textposition="outside",
        hovertemplate="<b>%{y}</b><br>Events: %{x}<extra></extra>",
    ))
    return _layout(fig, "Events per evidence source", h=220)


def chart_gauge(score: dict) -> go.Figure:
    val   = score["risk_score"]
    level = score["risk_level"]
    color = SEV_COLOR.get(level, "#6b7280")
    fig   = go.Figure(go.Indicator(
        mode="gauge+number",
        value=val,
        title={"text":"Case Risk Score","font":{"color":"#e0e0e0","size":14}},
        number={"font":{"color":color,"size":48}},
        gauge={
            "axis":  {"range":[0,100],"tickcolor":"#e0e0e0","tickfont":{"color":"#e0e0e0"}},
            "bar":   {"color":color},
            "bgcolor":"#1a1a2e", "bordercolor":"#2d2d4e",
            "steps":[
                {"range":[0,30],  "color":"#0d1b2a"},
                {"range":[30,60], "color":"#1a1500"},
                {"range":[60,80], "color":"#1c1008"},
                {"range":[80,100],"color":"#1c0a0a"},
            ],
            "threshold":{"line":{"color":"#ef4444","width":3},"thickness":0.8,"value":val},
        },
    ))
    fig.update_layout(
        plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
        font_color="#e0e0e0", height=260,
        margin=dict(l=20,r=20,t=30,b=10),
    )
    return fig


# ─────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────

def render_sidebar(df: pd.DataFrame) -> dict:
    st.sidebar.markdown("## 🔍 DFITS")
    st.sidebar.markdown("*Digital Forensic Intelligence*")
    st.sidebar.markdown("---")

    st.sidebar.markdown("### 📁 Upload evidence")
    uploaded = st.sidebar.file_uploader(
        "Drop .log or WhatsApp .txt",
        type=["log","txt","csv"],
        accept_multiple_files=True,
        label_visibility="collapsed",
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🔎 Filters")

    sources    = ["All"] + (sorted(df["source_type"].unique()) if not df.empty else [])
    etypes     = ["All"] + (sorted(df["event_type"].unique())  if not df.empty else [])
    src_filter = st.sidebar.selectbox("Source type", sources)
    et_filter  = st.sidebar.selectbox("Event type",  etypes)
    flagged_only = st.sidebar.toggle("⚠ Flagged events only", value=False)

    if not df.empty:
        min_t = df["timestamp"].min().to_pydatetime()
        max_t = df["timestamp"].max().to_pydatetime()
        time_range = st.sidebar.slider(
            "Time window", min_value=min_t, max_value=max_t,
            value=(min_t, max_t), format="HH:mm",
        )
    else:
        time_range = (datetime.now() - timedelta(hours=1), datetime.now())

    st.sidebar.markdown("---")
    page = st.sidebar.radio(
        "Navigate",
        ["🏠 Overview","📊 Timeline","🚨 Alerts","🔬 Event Explorer"],
        label_visibility="collapsed",
    )

    return dict(page=page, src_filter=src_filter, et_filter=et_filter,
                flagged_only=flagged_only, time_range=time_range, uploaded=uploaded)


# ─────────────────────────────────────────────
#  PAGES
# ─────────────────────────────────────────────

def page_overview(df, alerts, score):
    st.title("🏠 Case Overview")

    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Total events",   len(df))
    c2.metric("Sources",        df["source_type"].nunique() if not df.empty else 0)
    c3.metric("Flagged events", int(df["flagged"].sum()) if not df.empty else 0)
    c4.metric("Alerts raised",  len(alerts))
    c5.metric("Risk score",     f"{score['risk_score']}/100")

    st.divider()

    col_g, col_b = st.columns(2)
    with col_g:
        st.plotly_chart(chart_gauge(score),
                        use_container_width=True, config={"displayModeBar":False})
    with col_b:
        st.markdown("#### Alert breakdown")
        bd = score["alert_breakdown"]
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            n   = bd.get(sev, 0)
            col = SEV_COLOR[sev]
            ico = SEV_ICON[sev]
            bar = int((n / max(len(alerts),1)) * 100)
            st.markdown(
                f'{ico} **{sev}** — {n}<div style="height:6px;background:{col};'
                f'width:{bar}%;border-radius:3px;margin-bottom:8px"></div>',
                unsafe_allow_html=True,
            )

    st.divider()

    col_d, col_s = st.columns([1.3,1])
    with col_d:
        st.plotly_chart(chart_donut(df),
                        use_container_width=True, config={"displayModeBar":False})
    with col_s:
        st.plotly_chart(chart_source_bar(df),
                        use_container_width=True, config={"displayModeBar":False})

    st.plotly_chart(chart_density(df),
                    use_container_width=True, config={"displayModeBar":False})

    critical = [a for a in alerts if a["severity"] == "CRITICAL"]
    if critical:
        st.markdown(f"#### 🔴 Critical alerts ({len(critical)})")
        for a in critical[:3]:
            render_alert_card(a)


def page_timeline(df):
    st.title("📊 Forensic Timeline")
    if df.empty:
        st.info("No events loaded.")
        return

    st.plotly_chart(chart_timeline_scatter(df),
                    use_container_width=True, config={"displayModeBar":False})
    st.plotly_chart(chart_density(df),
                    use_container_width=True, config={"displayModeBar":False})

    st.markdown("#### Cross-source correlation windows")
    st.caption("Windows where 2+ sources are active simultaneously")
    results = []
    evs = df.sort_values("timestamp").reset_index(drop=True)
    for _, anchor in evs.iterrows():
        we = anchor["timestamp"] + timedelta(seconds=300)
        w  = evs[(evs["timestamp"] >= anchor["timestamp"]) & (evs["timestamp"] <= we)]
        if w["source_type"].nunique() >= 2:
            results.append({
                "window_start": str(anchor["timestamp"])[:19],
                "events":       len(w),
                "sources":      ", ".join(w["source_type"].unique()),
                "event_types":  ", ".join(w["event_type"].unique()[:4]),
            })
    if results:
        st.dataframe(
            pd.DataFrame(results).drop_duplicates("window_start"),
            use_container_width=True, hide_index=True,
        )
    else:
        st.info("No cross-source windows found.")


def page_alerts(alerts, score):
    st.title("🚨 Detection Alerts")
    if not alerts:
        st.success("✅ No suspicious activity detected.")
        return

    level = score["risk_level"]
    css   = f"risk-{level.lower()}"
    st.markdown(f"""
    <div class="{css}">
      <div class="risk-score">{score['risk_score']} / 100</div>
      <div class="risk-label">{level} — {score['total_alerts']} alert(s) across {score['flagged_events']} evidence events</div>
    </div>""", unsafe_allow_html=True)

    st.divider()

    sev_f    = st.selectbox("Filter by severity", ["All","CRITICAL","HIGH","MEDIUM","LOW"])
    filtered = alerts if sev_f == "All" else [a for a in alerts if a["severity"] == sev_f]
    st.markdown(f"**Showing {len(filtered)} alert(s)**")
    for a in filtered:
        render_alert_card(a)


def page_explorer(df):
    st.title("🔬 Event Explorer")
    if df.empty:
        st.info("No events loaded.")
        return

    search = st.text_input("🔍 Search descriptions",
                            placeholder="e.g. USB, admin, Ahmed...")
    disp = df.copy()
    if search:
        disp = disp[disp["description"].str.contains(search, case=False, na=False)]

    cols = st.multiselect(
        "Columns",
        options=["id","timestamp","source_type","source_file",
                 "event_type","description","flagged","flag_reason"],
        default=["id","timestamp","source_type","event_type","description","flagged"],
    )

    def hl(row):
        if row.get("flagged",0) == 1:
            return ["background-color:rgba(239,68,68,0.12)"]*len(row)
        bg = {"log":"rgba(99,102,241,0.08)","whatsapp":"rgba(34,197,94,0.08)",
              "browser":"rgba(245,158,11,0.08)"}.get(str(row.get("source_type","")), "")
        return [f"background-color:{bg}"]*len(row)

    show = [c for c in cols if c in disp.columns]
    st.dataframe(disp[show].style.apply(hl, axis=1),
                 use_container_width=True, height=480, hide_index=True)
    st.caption(f"{len(disp)} events shown")

    csv = disp[show].to_csv(index=False)
    st.download_button(
        "⬇ Export filtered events as CSV", data=csv,
        file_name=f"dfits_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    db_path = "dfits_evidence.db"
    if "--" in sys.argv:
        idx    = sys.argv.index("--")
        p      = argparse.ArgumentParser()
        p.add_argument("--db", default="dfits_evidence.db")
        parsed, _ = p.parse_known_args(sys.argv[idx+1:])
        db_path   = parsed.db

    if not Path(db_path).exists():
        st.error(
            f"Database not found: `{db_path}`\n\n"
            "Run Phase 1 + 2 first:\n"
            "```\npython phase1_parser.py your.log chat.txt\n"
            "python phase2_timeline.py unified_events.json\n```"
        )
        st.stop()

    conn   = get_connection(db_path)
    engine = TimelineEngine(conn)

    df_full = engine.full_timeline()
    if not df_full.empty:
        df_full["timestamp"] = pd.to_datetime(df_full["timestamp"])

    opts = render_sidebar(df_full)

    # Handle uploads
    if opts["uploaded"]:
        import tempfile, os
        for uf in opts["uploaded"]:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=Path(uf.name).suffix
            ) as tmp:
                tmp.write(uf.read())
                tp = tmp.name
            evs = parse_file(tp)
            if evs:
                tj = tp + ".json"
                save_json(evs, tj)
                n = ingest_json(conn, tj)
                st.sidebar.success(f"✅ {uf.name} → {n} events ingested")
                os.unlink(tp); os.unlink(tj)
        engine  = TimelineEngine(conn)
        df_full = engine.full_timeline()
        if not df_full.empty:
            df_full["timestamp"] = pd.to_datetime(df_full["timestamp"])

    # Apply filters
    df = df_full.copy()
    if not df.empty:
        ts, te = opts["time_range"]
        df = df[(df["timestamp"] >= pd.Timestamp(ts)) &
                (df["timestamp"] <= pd.Timestamp(te))]
        if opts["src_filter"] != "All":
            df = df[df["source_type"] == opts["src_filter"]]
        if opts["et_filter"] != "All":
            df = df[df["event_type"] == opts["et_filter"]]
        if opts["flagged_only"]:
            df = df[df["flagged"] == 1]

    # Run detection (once per session, or on button press)
    if "alerts" not in st.session_state or st.sidebar.button("🔄 Re-run detection"):
        with st.spinner("Running detection rules..."):
            det = DetectionEngine(engine)
            st.session_state.alerts = det.run_all()
            st.session_state.score  = compute_case_score(st.session_state.alerts)

    alerts = st.session_state.get("alerts", [])
    score  = st.session_state.get("score", {
        "risk_score":0,"risk_level":"LOW",
        "alert_breakdown":{},"total_alerts":0,"flagged_events":0,
    })

    page = opts["page"]
    if   page == "🏠 Overview":       page_overview(df, alerts, score)
    elif page == "📊 Timeline":       page_timeline(df)
    elif page == "🚨 Alerts":         page_alerts(alerts, score)
    elif page == "🔬 Event Explorer": page_explorer(df)


if __name__ == "__main__":
    main()