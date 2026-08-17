import streamlit as st
import pandas as pd
from mock_data import get_mock_alerts

st.set_page_config(
    page_title="NIDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; }

    /* Severity badge styles */
    .badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 2px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 13px;
    }
    .badge-warning {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 2px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 13px;
    }
    .badge-normal {
        background-color: #DCFCE7;
        color: #15803D;
        padding: 2px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 13px;
    }

    /* Summary card borders */
    [data-testid="stMetric"] {
        border: 1px solid rgba(128,128,128,0.3);
        border-radius: 10px;
        padding: 12px 16px;
        background-color: rgba(128,128,128,0.08);
    }

    div[data-testid="stExpander"] {
        border: 1px solid #E5E7EB;
        border-radius: 8px;
        margin-bottom: 8px;
    }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ NIDS")
    st.caption("Network Intrusion Detection System")
    st.divider()

    mode = st.radio("**Select Mode**", ["📂 PCAP Upload", "🔴 Live Capture"])
    st.divider()

    threshold = st.slider(
        "**Confidence Threshold**",
        min_value=0.0,
        max_value=1.0,
        value=0.6,
        step=0.05,
        help="Alerts below this confidence score will be hidden"
    )

    st.caption(f"Showing alerts with confidence ≥ {int(threshold*100)}%")
    st.divider()

    severity_filter = st.multiselect(
        "**Filter by Severity**",
        options=["Critical", "Warning", "Normal"],
        default=["Critical", "Warning", "Normal"]
    )
    st.divider()

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ Network Intrusion Detection System")
st.caption("AI-powered real-time network threat detection with explainable alerts")
st.divider()

# ── PCAP Upload Mode ──────────────────────────────────────────────────────────
if mode == "📂 PCAP Upload":
    st.subheader("📂 Upload Network Traffic File")

    uploaded_file = st.file_uploader(
        "Upload a PCAP file to analyse",
        type=["pcap", "pcapng"],
        help="Upload a recorded network traffic file. The system will analyse it and display all detected threats."
    )

    if uploaded_file:
        st.success(f"✅ File uploaded: **{uploaded_file.name}** ({round(uploaded_file.size/1024, 1)} KB)")
        st.info("⏳ Processing will be connected to the backend in Week 7. Showing mock results for now.")
    else:
        st.info("👆 Upload a PCAP file above to start analysis. Using mock data for now.")

    st.divider()

# ── Live Capture Mode ─────────────────────────────────────────────────────────
elif mode == "🔴 Live Capture":
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader("🔴 Live Network Monitoring")
        st.caption("Monitoring live traffic from network interface")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        st.success("● Active")
    st.info("⏳ Live capture will be connected to backend in Week 7. Showing mock data for now.")
    st.divider()

# ── Load and filter alerts ────────────────────────────────────────────────────
alerts = get_mock_alerts()
df = pd.DataFrame(alerts)
df = df[df["confidence"] >= threshold]
df = df[df["severity"].isin(severity_filter)]

critical = df[df["severity"] == "Critical"]
warning  = df[df["severity"] == "Warning"]
normal   = df[df["severity"] == "Normal"]

# ── Summary Cards ─────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
c1.metric("🔴 Critical",        len(critical))
c2.metric("🟡 Warning",         len(warning))
c3.metric("🟢 Normal",          len(normal))
c4.metric("📦 Total Packets",   "12,480")
st.divider()

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["🚨 Alert Feed", "📈 Timeline", "🔬 Model Comparison"])

# ── Tab 1: Alert Feed ─────────────────────────────────────────────────────────
with tab1:
    st.subheader("Alert Feed")

    if df.empty:
        st.warning("No alerts match the current filters.")
    else:
        # Sort — Critical first
        order = {"Critical": 0, "Warning": 1, "Normal": 2}
        df_sorted = df.copy()
        df_sorted["order"] = df_sorted["severity"].map(order)
        df_sorted = df_sorted.sort_values("order").drop("order", axis=1)

        for _, row in df_sorted.iterrows():
            # Severity icon and colour
            if row["severity"] == "Critical":
                icon   = "🔴"
                border = "#DC2626"
            elif row["severity"] == "Warning":
                icon   = "🟡"
                border = "#D97706"
            else:
                icon   = "🟢"
                border = "#15803D"

            label = (
                f"{icon}  **{row['attack_type']}**"
                f"  —  {int(row['confidence']*100)}% confidence"
                f"  |  {row['timestamp']}"
                f"  |  {row['severity']}"
            )

            with st.expander(label):
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("**Traffic Details**")
                    st.markdown(f"- **Attack Type:** `{row['attack_type']}`")
                    st.markdown(f"- **Severity:** `{row['severity']}`")
                    st.markdown(f"- **Source IP:** `{row['src_ip']}`")
                    st.markdown(f"- **Destination IP:** `{row['dst_ip']}`")
                    st.markdown(f"- **Port:** `{row['port']}`")
                    st.markdown(f"- **Time:** `{row['timestamp']}`")

                with col2:
                    st.markdown("**Why it was flagged (SHAP)**")
                    st.info(f"💡 {row['explanation']}")
                    st.progress(
                        row["confidence"],
                        text=f"Model confidence: {int(row['confidence']*100)}%"
                    )

# ── Tab 2: Timeline ───────────────────────────────────────────────────────────
with tab2:
    st.subheader("Attack Timeline")
    st.info("⏳ Timeline chart coming in Week 7 once live data is connected.")

# ── Tab 3: Model Comparison ───────────────────────────────────────────────────
with tab3:
    st.subheader("Model Comparison — RF vs LSTM vs Ensemble")
    st.info("⏳ Model comparison coming in Week 5 once Member A's models are trained.")