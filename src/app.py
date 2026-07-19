"""
app.py
Streamlit dashboard for AutoSOC -- Week 4 deliverable.

Lets you:
- Paste a raw alert (or pick one from the sample library)
- Run the 4-agent crew and watch each agent's output appear step by step
- See the final severity + proposed action
- Approve or Reject the proposed action (the human-in-the-loop gate)

Run with: streamlit run src/app.py
"""
import json
import re
from pathlib import Path

import streamlit as st

from crew import build_crew

DATA_DIR = Path(__file__).parent.parent / "data"
ALERTS_FILE = DATA_DIR / "sample_alerts.json"
DECISIONS_FILE = DATA_DIR / "approval_decisions.json"

AGENT_LABELS = [
    "🔎 Alert Parser",
    "🧠 Threat Intel Analyst",
    "⚖️ Triage Analyst",
    "🛡️ Response Planner",
]


def load_sample_alerts():
    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_severity(text: str) -> str:
    match = re.search(r"Severity:\s*(\w+)", text)
    return match.group(1) if match else "Unknown"


def severity_color(severity: str) -> str:
    return {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢",
    }.get(severity.lower(), "⚪")


def log_decision(alert_text: str, final_output: str, decision: str):
    existing = []
    if DECISIONS_FILE.exists():
        with open(DECISIONS_FILE, "r", encoding="utf-8") as f:
            existing = json.load(f)
    existing.append({
        "alert": alert_text,
        "crew_output": final_output,
        "decision": decision,
    })
    with open(DECISIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)


st.set_page_config(page_title="AutoSOC", page_icon="🛡️", layout="wide")

st.title("🛡️ AutoSOC — Agentic AI Threat Triage & Response")
st.caption(
    "Multi-agent SOC analyst: Alert Parser → Threat Intel Analyst → Triage Analyst → "
    "Response Planner. Grounded in MITRE ATT&CK via RAG. Every action requires human approval."
)

# ---- Alert input ----
col1, col2 = st.columns([3, 1])
with col1:
    alerts = load_sample_alerts()
    alert_options = {f"{a['id']} ({a['expected_label']})": a["raw_log"] for a in alerts}
    choice = st.selectbox("Pick a sample alert, or choose 'Custom' to paste your own:",
                           ["Custom"] + list(alert_options.keys()))

    if choice == "Custom":
        default_text = ""
    else:
        default_text = alert_options[choice]

    alert_text = st.text_area("Raw alert / log line", value=default_text, height=100)

with col2:
    st.write("")
    st.write("")
    run_button = st.button("🚀 Run Investigation", type="primary", use_container_width=True)

st.divider()

# ---- Run the crew and show live trace ----
if run_button and alert_text.strip():
    st.session_state["last_alert"] = alert_text

    with st.spinner("Agents investigating... this can take 20-60 seconds."):
        crew = build_crew(alert_text)
        result = crew.kickoff()

    st.session_state["last_result"] = result
    st.session_state["approved"] = None  # reset approval state for a new run

if "last_result" in st.session_state:
    result = st.session_state["last_result"]

    st.subheader("Agent Investigation Trace")
    tabs = st.tabs(AGENT_LABELS)
    for tab, task_output in zip(tabs, result.tasks_output):
        with tab:
            st.markdown(task_output.raw)

    st.divider()
    st.subheader("Final Incident Summary")

    final_text = result.raw
    severity = extract_severity(final_text)
    st.markdown(f"### {severity_color(severity)} Severity: {severity}")
    st.markdown(final_text)

    st.divider()
    st.subheader("🔒 Human Approval Gate")
    st.write("The Response Planner's recommended action is only a **proposal**. Nothing executes until approved here.")

    approved = st.session_state.get("approved")
    c1, c2, c3 = st.columns([1, 1, 3])
    with c1:
        if st.button("✅ Approve Action"):
            st.session_state["approved"] = "approved"
            log_decision(st.session_state["last_alert"], final_text, "approved")
    with c2:
        if st.button("❌ Reject Action"):
            st.session_state["approved"] = "rejected"
            log_decision(st.session_state["last_alert"], final_text, "rejected")

    if st.session_state.get("approved") == "approved":
        st.success("Action approved and logged. (Simulated -- no real system was touched.)")
    elif st.session_state.get("approved") == "rejected":
        st.warning("Action rejected and logged. Escalate to manual review instead.")
else:
    st.info("Pick a sample alert or paste your own, then click 'Run Investigation'.")
