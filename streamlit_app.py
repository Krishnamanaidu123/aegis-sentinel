import streamlit as st
import requests
import json
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="Aegis Sentinel", layout="wide", page_icon="🛡️")

# --- Sidebar: Ingest ---
st.sidebar.title("🛡️ Aegis Sentinel")
st.sidebar.markdown("---")
st.sidebar.header("📥 Ingest Log")

log_source = st.sidebar.radio("Log format", ["Syslog (raw)", "JSON"])

payload = {}
if log_source == "Syslog (raw)":
    raw_log = st.sidebar.text_area(
        "Paste syslog line",
        value="Oct 11 22:14:15 myhost sshd[1234]: Failed password for invalid user admin from 192.168.1.100"
    )
    if st.sidebar.button("🚀 Analyze", use_container_width=True):
        payload = {"raw": raw_log}
else:
    json_log = st.sidebar.text_area(
        "Paste JSON log",
        value='{"timestamp": "2025-01-01T12:00:00Z", "sourceIPAddress": "10.0.0.5", "user": "john_doe", "eventName": "ConsoleLogin"}'
    )
    if st.sidebar.button("🚀 Analyze", use_container_width=True):
        try:
            payload = json.loads(json_log)
        except:
            st.sidebar.error("Invalid JSON format")

# --- API Call ---
if payload:
    try:
        with st.spinner("🧠 AI is analyzing..."):
            response = requests.post("http://localhost:5000/analyze", json=payload, timeout=30)
            if response.status_code == 200:
                result = response.json()
                st.session_state["latest_result"] = result
                st.success("Analysis complete!")
            else:
                st.error(f"API error: {response.status_code} - {response.text}")
    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to Aegis API. Make sure `python app.py` is running.")
    except Exception as e:
        st.error(f"Error: {e}")

# --- Main Area: Tabs ---
tab1, tab2, tab3 = st.tabs(["📊 Latest Analysis", "📜 Alert History", "📖 About"])

with tab1:
    if "latest_result" in st.session_state:
        res = st.session_state["latest_result"]
        analysis = res.get("analysis", {})
        log = res.get("log", {})

        col1, col2 = st.columns([1, 1])
        with col1:
            st.subheader("📋 Log Entry")
            st.json(log)

        with col2:
            st.subheader("🤖 AI Verdict")
            suspicious = analysis.get("suspicious", False)
            confidence = analysis.get("confidence", 0)
            if suspicious:
                st.error(f"🚨 **Suspicious** (Confidence: {confidence}%)")
            else:
                st.success(f"✅ **Benign** (Confidence: {100-confidence}%)")

            st.markdown(f"**Explanation:** {analysis.get('explanation', 'N/A')}")

        st.subheader("📌 MITRE ATT&CK Mapping")
        mitre_details = analysis.get("mitre_details", [])
        if mitre_details:
            df = pd.DataFrame(mitre_details)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No MITRE techniques mapped.")

        st.subheader("🛠️ Recommended Response")
        st.info(analysis.get("response", "No specific response provided."))

        st.caption(f"Alert ID: {res.get('alert_id', 'N/A')}")

with tab2:
    st.subheader("📜 Recent Alerts (Last 100)")
    try:
        r = requests.get("http://localhost:5000/alerts", timeout=5)
        if r.status_code == 200:
            alerts = r.json()
            if alerts:
                # Convert to DataFrame for better display
                df_alerts = pd.DataFrame(alerts)
                # Select relevant columns
                display_cols = ["id", "timestamp", "source_ip", "user", "event_type", "suspicious", "confidence", "explanation"]
                df_display = df_alerts[display_cols].copy()
                df_display["suspicious"] = df_display["suspicious"].apply(lambda x: "🚨 Yes" if x else "✅ No")
                st.dataframe(df_display, use_container_width=True, height=400)

                # Expandable details
                st.subheader("🔍 Full Details")
                selected_id = st.selectbox("Select Alert ID to view full details", df_alerts["id"].tolist())
                if selected_id:
                    detail_r = requests.get(f"http://localhost:5000/alerts/{selected_id}")
                    if detail_r.status_code == 200:
                        st.json(detail_r.json())
            else:
                st.info("No alerts yet. Run some analyses!")
        else:
            st.error("Could not fetch alerts from API.")
    except:
        st.error("API unreachable. Is the Flask server running?")

with tab3:
    st.markdown("""
    ## 🛡️ Aegis Sentinel

    **AI-Powered SOC Log Analyzer**

    - **Detection**: Uses Google Gemini to detect suspicious activity.
    - **Mapping**: Automatically maps threats to MITRE ATT&CK.
    - **Response**: Provides actionable SOC playbook recommendations.
    - **Storage**: Saves all alerts to a local database for review.

    ### How to use:
    1. Paste a syslog line or JSON log in the sidebar.
    2. Click "Analyze".
    3. View the AI verdict, MITRE mapping, and response.
    4. Check the "Alert History" tab for past detections.

    ### Architecture:
    Log → Parser → Gemini AI → MITRE Enricher → DB → Dashboard
    """)

st.sidebar.markdown("---")
st.sidebar.caption("v1.0 | Built with ❤️ for SOC Teams")
