"""
Project Hydra — Real-Time Intelligence Dashboard  (FR-03)
Reads from DynamoDB, shows threat metrics, attacker map, blacklist table.
"""

import os
import time
import boto3
import pandas as pd
import streamlit as st
import requests
from datetime import datetime

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title  = "⚡ Hydra — Threat Intelligence Dashboard",
    page_icon   = "🐍",
    layout      = "wide",
    initial_sidebar_state = "collapsed",
)

# ── Custom dark-hacker CSS ────────────────────────────────────────────────────
st.markdown("""
<style>
  /* Dark background */
  .stApp { background: #0a0a0f; color: #e0e0e0; }
  /* Metric cards */
  div[data-testid="metric-container"] {
    background: #12121a;
    border: 1px solid #1f3a5f;
    border-radius: 8px;
    padding: 16px;
  }
  div[data-testid="metric-container"] label { color: #5b9bd5 !important; font-size: 0.8rem; letter-spacing: 2px; }
  div[data-testid="metric-container"] div[data-testid="stMetricValue"] { color: #00ff88 !important; font-family: monospace; font-size: 2rem; }
  /* Buttons */
  .stButton button {
    background: #00ff88 !important; color: #000 !important;
    font-weight: bold; border-radius: 4px; border: none;
    letter-spacing: 1px;
  }
  /* Table */
  .dataframe { background: #12121a !important; color: #e0e0e0 !important; }
  /* Headers */
  h1,h2,h3 { color: #00ff88 !important; font-family: monospace; }
  /* Status badges */
  .badge-mal  { background:#ff4444; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.8rem; }
  .badge-prob { background:#f0a500; color:#000; padding:2px 8px; border-radius:4px; font-size:0.8rem; }
</style>
""", unsafe_allow_html=True)

# ── AWS connection (reads env vars set in Streamlit secrets) ──────────────────
@st.cache_resource(show_spinner=False)
def get_table():
    session = boto3.Session(
        aws_access_key_id     = st.secrets.get("AWS_ACCESS_KEY_ID",     os.getenv("AWS_ACCESS_KEY_ID")),
        aws_secret_access_key = st.secrets.get("AWS_SECRET_ACCESS_KEY", os.getenv("AWS_SECRET_ACCESS_KEY")),
        region_name           = st.secrets.get("AWS_REGION",            os.getenv("AWS_REGION", "us-east-1")),
    )
    ddb = session.resource("dynamodb")
    return ddb.Table(st.secrets.get("DYNAMODB_TABLE", os.getenv("DYNAMODB_TABLE", "Hydra_Vaccine_Hub")))

# ── Data fetch (FR-03: Scan) ──────────────────────────────────────────────────
def fetch_all_threats(table):
    items, last_key = [], None
    while True:
        kwargs = {}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp     = table.scan(**kwargs)
        items   += resp.get("Items", [])
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items

# ── IP Geo lookup (free, no key needed) ───────────────────────────────────────
@st.cache_data(ttl=3600)
def geo_lookup(ip: str):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if r.get("status") == "success":
            return r.get("country", "Unknown"), r.get("city", ""), float(r.get("lat", 0)), float(r.get("lon", 0))
    except Exception:
        pass
    return "Unknown", "", 0.0, 0.0

# ── Title bar ─────────────────────────────────────────────────────────────────
col_title, col_sync = st.columns([5, 1])
with col_title:
    st.markdown("# 🐍 HYDRA — Threat Intelligence Dashboard")
    st.markdown("`REAL-TIME DECEPTION NETWORK MONITOR`")
with col_sync:
    st.markdown("<br>", unsafe_allow_html=True)
    sync_clicked = st.button("🔄 SYNC", use_container_width=True)

st.markdown("---")

# ── Load data ─────────────────────────────────────────────────────────────────
try:
    table = get_table()
except Exception as e:
    st.error(f"❌ Cannot connect to AWS. Check your secrets: {e}")
    st.info("Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, DYNAMODB_TABLE in Streamlit secrets.")
    st.stop()

if sync_clicked:
    st.cache_data.clear()

with st.spinner("Pulling threat intelligence from Vaccine Hub..."):
    raw = fetch_all_threats(table)

if not raw:
    st.warning("⚠️ No threats captured yet. Share the honeypot URL to start trapping attackers.")
    st.code("Honeypot URL → check CloudFormation Outputs → HoneypotURL")
    st.stop()

# ── Build DataFrame ───────────────────────────────────────────────────────────
df = pd.DataFrame(raw)
df["visits"] = pd.to_numeric(df.get("visits", 1), errors="coerce").fillna(1).astype(int)
df["status"] = df["visits"].apply(lambda v: "MALICIOUS" if v >= 2 else "PROBER")

# Geo enrichment
if "country" not in df.columns:
    geo_data = [geo_lookup(ip) for ip in df["ip_address"]]
    df["country"] = [g[0] for g in geo_data]
    df["city"]    = [g[1] for g in geo_data]
    df["lat"]     = [g[2] for g in geo_data]
    df["lon"]     = [g[3] for g in geo_data]

# ── FR-03: Security Metrics ───────────────────────────────────────────────────
total_attackers  = df["ip_address"].nunique()
malicious_count  = (df["status"] == "MALICIOUS").sum()
prober_count     = (df["status"] == "PROBER").sum()
unique_countries = df["country"].nunique()

latest_ts = df["last_seen"].max() if "last_seen" in df.columns else df.get("captured_at", pd.Series()).max()

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("🎯 Unique Attackers",    total_attackers)
m2.metric("🔴 Malicious (2+ hits)", malicious_count)
m3.metric("🟡 Probers (1 hit)",     prober_count)
m4.metric("🌍 Countries Detected",  unique_countries)
m5.metric("🕐 Last Attack",         latest_ts[:19].replace("T", " ") if latest_ts else "—")

st.markdown("---")

# ── World Map ─────────────────────────────────────────────────────────────────
map_df = df.dropna(subset=["lat", "lon"])
map_df = map_df[(map_df["lat"] != 0) | (map_df["lon"] != 0)]

if not map_df.empty:
    st.markdown("### 🌍 Global Attacker Map")
    st.map(map_df[["lat", "lon"]], zoom=1, use_container_width=True)
    st.markdown("---")

# ── Blacklist Table (FR-03) ───────────────────────────────────────────────────
st.markdown("### 🚫 Blacklisted IP Registry")

cols_order = ["ip_address", "status", "visits", "country", "city",
              "node_id", "path", "captured_at", "last_seen", "user_agent"]
display_cols = [c for c in cols_order if c in df.columns]
display_df   = df[display_cols].copy()

# Colour-code status
def highlight_status(row):
    colour = "#3a0000" if row.get("status") == "MALICIOUS" else "#2a2500"
    return [f"background-color: {colour}"] * len(row)

st.dataframe(
    display_df.sort_values("visits", ascending=False)
              .reset_index(drop=True)
              .style.apply(highlight_status, axis=1),
    use_container_width=True,
    height=450,
)

# ── Node Activity Breakdown ────────────────────────────────────────────────────
if "node_id" in df.columns:
    st.markdown("---")
    st.markdown("### 🔗 Ghost Node Activity")
    node_stats = df.groupby("node_id").agg(
        Visitors   = ("ip_address", "count"),
        Malicious  = ("status", lambda x: (x == "MALICIOUS").sum()),
    ).reset_index()
    st.dataframe(node_stats, use_container_width=True)

# ── Footer ─────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    f"<small style='color:#444'>Last dashboard render: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC "
    f"| Hydra Cyber-Deception System | Free-Tier AWS</small>",
    unsafe_allow_html=True,
)
