from __future__ import annotations

import os
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer import demo_records, read_capture, summarize

st.set_page_config(page_title="Signal Trace", page_icon="◈", layout="wide", initial_sidebar_state="expanded")

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');
    :root { --ink: #17211b; --muted: #66736b; --mint: #b9f5d0; --lime: #d7f36b; --paper: #f4f6ee; --line: #d9e1d7; }
    html, body, [class*="css"] { font-family: 'Space Grotesk', sans-serif; color: var(--ink); }
    .stApp { background: var(--paper); }
    [data-testid="stSidebar"] { background: #17211b; border-right: 0; }
    [data-testid="stSidebar"] * { color: #edf7ee; }
    .brand { padding: 8px 0 30px; }
    .brand-mark { color: var(--lime); font-family: 'DM Mono'; font-size: 13px; letter-spacing: .18em; text-transform: uppercase; }
    .brand h1 { color: white; font-size: 26px; margin: 7px 0 5px; letter-spacing: -.04em; }
    .brand p { color: #aab8ad; font-size: 13px; margin: 0; line-height: 1.5; }
    .section-label { color: #809187; font-family: 'DM Mono'; font-size: 10px; letter-spacing: .14em; text-transform: uppercase; margin: 22px 0 8px; }
    .hero { border-bottom: 1px solid var(--line); padding: 15px 0 24px; margin-bottom: 23px; display: flex; align-items: end; justify-content: space-between; }
    .eyebrow { color: #4f785d; font-family: 'DM Mono'; font-size: 11px; letter-spacing: .14em; text-transform: uppercase; }
    .hero h2 { font-size: 36px; letter-spacing: -.06em; margin: 8px 0 4px; line-height: 1; }
    .hero p { color: var(--muted); margin: 0; }
    .status { background: var(--mint); border: 1px solid #91dbb1; border-radius: 999px; padding: 8px 13px; font-family: 'DM Mono'; font-size: 11px; white-space: nowrap; }
    .metric { background: white; border: 1px solid var(--line); padding: 17px 18px; min-height: 97px; }
    .metric-label { color: var(--muted); font-family: 'DM Mono'; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; }
    .metric-value { color: var(--ink); font-size: 27px; font-weight: 600; letter-spacing: -.05em; margin-top: 11px; }
    .metric-accent { color: #4b9c64; }
    .panel-title { font-size: 17px; font-weight: 600; margin: 23px 0 10px; }
    .small-note { color: var(--muted); font-size: 12px; }
    .mono { font-family: 'DM Mono'; }
    div[data-testid="stFileUploader"] { border: 1px dashed #60756a; border-radius: 2px; padding: 4px; }
    .stButton button { border-radius: 2px; border: 1px solid #587963; background: var(--lime); color: var(--ink); font-weight: 600; }
    .stButton button:hover { border-color: var(--ink); color: var(--ink); }
    [data-testid="stDataFrame"] { border: 1px solid var(--line); }
    </style>
    """,
    unsafe_allow_html=True,
)

if "records" not in st.session_state:
    st.session_state.records = demo_records()
    st.session_state.source = "demo capture"

with st.sidebar:
    st.markdown(
        '<div class="brand"><div class="brand-mark">◈ Signal Trace</div><h1>Traffic analyzer</h1><p>Inspect packet captures, surface conversations, and spot unusual protocol activity.</p></div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="section-label">Capture source</div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Upload a capture", type=["pcap", "pcapng", "cap"], label_visibility="collapsed")
    if uploaded is not None:
        if st.button("Analyze capture", width="stretch"):
            with st.spinner("Reading packets..."):
                suffix = os.path.splitext(uploaded.name)[1] or ".pcap"
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                    temp_file.write(uploaded.getbuffer())
                    temp_path = temp_file.name
                try:
                    st.session_state.records = read_capture(temp_path)
                    st.session_state.source = uploaded.name
                    st.success(f"Loaded {len(st.session_state.records):,} packets")
                except Exception as error:
                    st.error(f"Could not read capture: {error}")
                finally:
                    os.unlink(temp_path)
    if st.button("Load demo traffic", width="stretch"):
        st.session_state.records = demo_records()
        st.session_state.source = "demo capture"
        st.rerun()
    st.markdown('<div class="section-label">Filters</div>', unsafe_allow_html=True)
    protocols_available = sorted({record["protocol"] for record in st.session_state.records})
    selected_protocols = st.multiselect("Protocol", protocols_available, default=protocols_available)
    search = st.text_input("Search endpoints", placeholder="IP, host, or info", label_visibility="collapsed")
    st.markdown('<div class="section-label">Session</div>', unsafe_allow_html=True)
    st.markdown(f'<span class="small-note">Source: <span class="mono">{st.session_state.source}</span></span>', unsafe_allow_html=True)
    st.markdown('<div class="small-note" style="margin-top:10px">PCAP parsing uses Scapy. Live capture can be added with OS-level capture permissions.</div>', unsafe_allow_html=True)

records = [
    record for record in st.session_state.records
    if record["protocol"] in selected_protocols
    and (not search or search.lower() in str(record).lower())
]
stats = summarize(records)

st.markdown(
    f'<div class="hero"><div><div class="eyebrow">Network observability / packet view</div><h2>Trace the signal.</h2><p>Turn raw packets into a readable map of what is moving through your network.</p></div><div class="status">● ANALYSIS READY</div></div>',
    unsafe_allow_html=True,
)

metric_cols = st.columns(4)
metrics = [("Packets", f"{stats['packets']:,}"), ("Bytes inspected", f"{stats['bytes'] / 1024:.1f} KB"), ("Conversations", f"{len(stats['conversations']):,}"), ("Protocols", f"{len(stats['protocols']):,}")]
for column, (label, value) in zip(metric_cols, metrics):
    column.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value}</div></div>', unsafe_allow_html=True)

if not records:
    st.warning("No packets match the current filters.")
    st.stop()

tab_overview, tab_flows, tab_packets = st.tabs(["Overview", "Conversations", "Packet list"])
with tab_overview:
    chart_cols = st.columns([1, 1.45])
    with chart_cols[0]:
        st.markdown('<div class="panel-title">Protocol mix</div>', unsafe_allow_html=True)
        protocol_df = pd.DataFrame({"protocol": list(stats["protocols"].keys()), "packets": list(stats["protocols"].values())})
        fig = px.pie(protocol_df, names="protocol", values="packets", hole=.66, color_discrete_sequence=["#4b9c64", "#d7f36b", "#f3a45d", "#8bb8d9", "#b8a4df"])
        fig.update_layout(showlegend=True, margin=dict(l=0, r=0, t=0, b=0), height=280, paper_bgcolor="rgba(0,0,0,0)", font=dict(family="Space Grotesk", color="#17211b"), legend=dict(orientation="h", y=-.08))
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    with chart_cols[1]:
        st.markdown('<div class="panel-title">Top endpoints</div>', unsafe_allow_html=True)
        endpoint_rows = [{"endpoint": endpoint, "packets": count} for endpoint, count in (stats["sources"] + stats["destinations"]).most_common(8)]
        endpoint_df = pd.DataFrame(endpoint_rows)
        fig = px.bar(endpoint_df.sort_values("packets"), x="packets", y="endpoint", orientation="h", color="packets", color_continuous_scale=["#d7f36b", "#4b9c64"])
        fig.update_layout(coloraxis_showscale=False, margin=dict(l=0, r=0, t=0, b=0), height=280, paper_bgcolor="rgba(0,0,0,0)", font=dict(family="Space Grotesk", color="#17211b"), xaxis_title=None, yaxis_title=None)
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
with tab_flows:
    st.markdown('<div class="panel-title">Conversation volume</div><div class="small-note">Bidirectional endpoint pairs ranked by observed packets.</div>', unsafe_allow_html=True)
    flow_rows = [{"conversation": f"{pair[0]}  ↔  {pair[1]}", "packets": count} for pair, count in stats["conversations"].most_common()]
    st.dataframe(pd.DataFrame(flow_rows), width="stretch", hide_index=True, height=350)
with tab_packets:
    st.markdown('<div class="panel-title">Decoded packets</div>', unsafe_allow_html=True)
    packet_df = pd.DataFrame(records)[["no", "time", "src", "src_port", "dst", "dst_port", "protocol", "length", "info"]]
    packet_df.columns = ["#", "timestamp", "source", "sport", "destination", "dport", "protocol", "bytes", "details"]
    packet_df[["sport", "dport"]] = packet_df[["sport", "dport"]].astype(str)
    st.dataframe(packet_df, width="stretch", hide_index=True, height=460, column_config={"timestamp": st.column_config.DatetimeColumn(format="HH:mm:ss.SSS"), "bytes": st.column_config.NumberColumn(format="%d B")})
