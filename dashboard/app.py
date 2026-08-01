import streamlit as st
from mock_data import get_mock_alerts
import pandas as pd

st.set_page_config(
    page_title="NIDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
    <style>
        .critical { color: #DC2626; font-weight: bold; }
        .warning  { color: #D97706; font-weight: bold; }
        .normal   { color: #15803D; font-weight: bold; }
        .block-container { padding-top: 1rem; }
    </style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=60)
st.sidebar.title("NIDS")
st.sidebar.caption("Network Intrusion Detection System")
st.sidebar.divider()

mode = st.sidebar.radio("Mode", ["📂 PCAP Upload", "🔴 Live Capture"])
threshold = st.sidebar.slider("Confidence Threshold", 0.0, 1.0, 0.6, 0.05)
st.sidebar.divider()
st.sidebar.caption("BE Final Year Project 2026–27")

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ Network Intrusion Detection System")
st.caption("Real-time network threat detection powered by ML")
st.divider()

# ── Load mock alerts ──────────────────────────────────────────────────────────
alerts = get_mock_alerts()
df = pd.DataFrame(alerts)

# Filter by threshold
df = df[df["confidence"] >= threshold]

critical = df[df["severity"] == "Critical"]
warning  = df[df["severity"] == "Warning"]
normal   = df[df["severity"] == "Normal"]

# ── Summary Cards ─────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)

c1.metric("🔴 Critical",  len(critical), delta=None)
c2.metric("🟡 Warning",   len(warning),  delta=None)
c3.metric("🟢 Normal",    len(normal),   delta=None)
c4.metric("📦 Total Packets", "12,480",  delta=None)

st.divider()

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["🚨 Alert Feed", "📈 Timeline", "🔬 Model Comparison"])

# ── Tab 1: Alert Feed ─────────────────────────────────────────────────────────
with tab1:
    st.subheader("Live Alert Feed")

    if df.empty:
        st.info("No alerts above the confidence threshold.")
    else:
        for _, row in df.iterrows():
            color = "🔴" if row["severity"] == "Critical" else "🟡" if row["severity"] == "Warning" else "🟢"

            with st.expander(f"{color}  {row['attack_type']}  —  {int(row['confidence']*100)}% confidence  |  {row['timestamp']}"):
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown(f"**Attack Type:** `{row['attack_type']}`")
                    st.markdown(f"**Severity:** {row['severity']}")
                    st.markdown(f"**Source IP:** `{row['src_ip']}`")
                    st.markdown(f"**Destination IP:** `{row['dst_ip']}`")
                    st.markdown(f"**Port:** `{row['port']}`")

                with col2:
                    st.markdown("**Why it was flagged:**")
                    st.info(row["explanation"])
                    st.progress(row["confidence"], text=f"Confidence: {int(row['confidence']*100)}%")

# ── Tab 2: Timeline (placeholder) ────────────────────────────────────────────
with tab2:
    st.subheader("Attack Timeline")
    st.info("⏳ Timeline chart will be wired in Week 7 once live data is available.")

# ── Tab 3: Model Comparison (placeholder) ────────────────────────────────────
with tab3:
    st.subheader("Model Comparison — RF vs LSTM vs Ensemble")
    st.info("⏳ Model comparison will be added in Week 5 once all models are trained.")