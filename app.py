"""PhishGuard — Multi-Vector Phishing Detection System."""
from pathlib import Path
import json
import io
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay

from phishing.features import heuristic_indicators, FEATURE_NAMES
from phishing.model import load_model, predict_text
from phishing.mlops import get_mlops

ROOT = Path(__file__).resolve().parent
st.set_page_config(page_title="PhishGuard", layout="wide")

# Minimal, clean typography and styling
st.markdown("""
<style>
.block-container {padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1150px;}
.header-box {
    padding: 1.2rem 1.4rem;
    border-radius: 6px;
    background: #0f172a;
    border-left: 4px solid #2563eb;
    color: #f8fafc;
    margin-bottom: 1.5rem;
}
.header-box h2 {margin:0; font-size: 1.6rem; font-weight: 600; color: #f8fafc;}
.header-box p {color: #94a3b8; margin: 0.25rem 0 0 0; font-size: 0.9rem;}
.status-pill-danger {
    background-color: #ef4444; color: white;
    padding: 6px 14px; border-radius: 4px;
    font-weight: 600; font-size: 0.9rem; display: inline-block;
}
.status-pill-warning {
    background-color: #f59e0b; color: #0f172a;
    padding: 6px 14px; border-radius: 4px;
    font-weight: 600; font-size: 0.9rem; display: inline-block;
}
.status-pill-success {
    background-color: #10b981; color: white;
    padding: 6px 14px; border-radius: 4px;
    font-weight: 600; font-size: 0.9rem; display: inline-block;
}
</style>
<div class="header-box">
    <h2>PhishGuard: Multi-Vector Detection Engine</h2>
    <p>Local Offline Scanner | Calibrated Stacking Ensemble | Explainable AI</p>
</div>
""", unsafe_allow_html=True)

mlops = get_mlops()


@st.cache_resource
def get_bundle():
    return load_model()


try:
    bundle = get_bundle()
except Exception as exc:
    bundle = None
    st.error(f"Model bundle not found: {exc}")
    st.info("Run `python train_model.py` to compile the model.")

with st.sidebar:
    st.markdown("### View")
    view = st.radio(
        "Select Section",
        [
            "Scanner",
            "Batch Analysis",
            "Analytics & History"
        ],
        label_visibility="collapsed"
    )
    st.divider()
    st.caption("**Engine Details**")
    st.caption("Model: Calibrated Stacking (LR + RF + GBDT)")
    st.caption("Vectors: URL, Email")
    st.caption("Execution: 100% Offline")


# ==================== VIEW 1: SCANNER ====================
if view == "Scanner":
    st.markdown("#### Analyze Content")
    
    col_input, col_examples = st.columns([3, 1])
    with col_input:
        input_type = st.radio("Vector", ["URL", "Email"], horizontal=True)
    with col_examples:
        samples = {
            "URL": "http://secure-login.bank-update.xyz/verify-account?ref=urgent",
            "Email": "URGENT: Your account has been suspended. Confirm credentials at http://login.bank-update.xyz"
        }
        if st.button("Load Sample", use_container_width=True):
            st.session_state["target_text"] = samples[input_type]

    text = st.text_area(
        "Paste content to inspect",
        key="target_text",
        height=130,
        placeholder="Paste a URL or email text here (any format: body, headers, raw message)..."
    )
    
    btn_scan, btn_clear = st.columns([1, 4])
    with btn_scan:
        scan_clicked = st.button("Scan Now", type="primary", use_container_width=True, disabled=(bundle is None))
    with btn_clear:
        if st.button("Clear"):
            st.session_state["target_text"] = ""
            if "current_scan" in st.session_state:
                del st.session_state["current_scan"]
            st.rerun()

    if scan_clicked:
        if not text or not text.strip():
            st.warning("Please enter text to analyze.")
        else:
            with st.spinner("Scanning..."):
                res = predict_text(input_type, text, bundle=bundle, log_to_mlops=True)
                st.session_state["current_scan"] = res

    if "current_scan" in st.session_state:
        res = st.session_state["current_scan"]
        st.divider()

        # Verdict Header
        c1, c2, c3 = st.columns([2, 1, 1])
        with c1:
            if res["risk_percentage"] >= 70.0:
                st.markdown(f'<div class="status-pill-danger">[PHISHING] {res["verdict"]}</div>', unsafe_allow_html=True)
            elif res["risk_percentage"] >= 40.0:
                st.markdown(f'<div class="status-pill-warning">[SUSPICIOUS] {res["verdict"]}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="status-pill-success">[SAFE] {res["verdict"]}</div>', unsafe_allow_html=True)
        with c2:
            st.metric("Risk Score", f"{res['risk_percentage']}%")
        with c3:
            st.metric("Latency", f"{res['latency_ms']} ms")

        st.progress(res["risk_percentage"] / 100.0)

        # Key Reasons
        st.markdown("##### Detected Indicators")
        for indicator in res["tier3_heuristics"]:
            st.write(f"- {indicator}")

        # Feature Attribution Breakdown (Optional Drawer)
        with st.expander("Technical Feature Contributions (XAI)"):
            attributions = res["tier2_attributions"]
            if attributions:
                top_items = attributions[:6]
                feat_names = [item["feature"] for item in reversed(top_items)]
                feat_vals = [item["contribution"] for item in reversed(top_items)]
                bar_colors = ["#ef4444" if v > 0 else "#10b981" for v in feat_vals]

                fig, ax = plt.subplots(figsize=(6, 2.5))
                ax.barh(feat_names, feat_vals, color=bar_colors)
                ax.axvline(0, color="#94a3b8", linestyle="--", linewidth=0.8)
                ax.set_xlabel("Contribution")
                st.pyplot(fig)
                plt.close(fig)
            else:
                st.write("Neutral feature distribution.")

        # Analyst Feedback
        st.caption("Feedback:")
        fb1, fb2, _ = st.columns([1, 1, 3])
        with fb1:
            if st.button("Confirm Threat", use_container_width=True):
                mlops.record_feedback(res["scan_id"], res["input_type"], text, res["risk_score"], 1, "Analyst confirmed threat")
                st.success("Recorded.")
        with fb2:
            if st.button("Mark False Alarm", use_container_width=True):
                mlops.record_feedback(res["scan_id"], res["input_type"], text, res["risk_score"], 0, "Analyst marked safe")
                st.info("Recorded.")


# ==================== VIEW 2: BATCH ANALYSIS ====================
elif view == "Batch Analysis":
    st.markdown("#### Batch Scanner")
    st.caption("Upload a CSV or TXT file to scan multiple items simultaneously.")

    uploaded_file = st.file_uploader("Upload File", type=["csv", "txt"])

    if uploaded_file is not None:
        batch_items = []
        if uploaded_file.name.endswith(".csv"):
            df_in = pd.read_csv(uploaded_file)
            col_target = st.selectbox("Select column to scan", df_in.columns)
            batch_items = df_in[col_target].dropna().astype(str).tolist()
        else:
            raw_text = uploaded_file.read().decode("utf-8", errors="ignore")
            batch_items = [line.strip() for line in raw_text.splitlines() if line.strip()]

        st.write(f"Loaded **{len(batch_items)}** items.")
        batch_type = st.radio("Vector Type", ["URL", "Email"], horizontal=True, key="b_type")

        if st.button("Run Batch", type="primary", disabled=(bundle is None)):
            progress = st.progress(0.0)
            rows = []
            for i, item in enumerate(batch_items):
                try:
                    r = predict_text(batch_type, item, bundle=bundle, log_to_mlops=False)
                    rows.append({
                        "Content": item[:50] + "...",
                        "Verdict": r["verdict"],
                        "Risk Score": f"{r['risk_percentage']}%",
                        "Latency (ms)": r["latency_ms"]
                    })
                except Exception:
                    rows.append({"Content": item[:50], "Verdict": "ERROR", "Risk Score": "N/A", "Latency (ms)": 0})
                progress.progress((i + 1) / len(batch_items))

            df_out = pd.DataFrame(rows)
            st.dataframe(df_out, use_container_width=True, hide_index=True)

            csv_data = io.StringIO()
            df_out.to_csv(csv_data, index=False)
            st.download_button("Export CSV", data=csv_data.getvalue(), file_name="scan_results.csv", mime="text/csv")


# ==================== VIEW 3: ANALYTICS & HISTORY ====================
elif view == "Analytics & History":
    st.markdown("#### Analytics & Model Status")
    
    tab_history, tab_metrics, tab_drift = st.tabs(["Scan History", "Model Benchmark", "Drift Telemetry"])

    with tab_history:
        if mlops.history:
            df_hist = pd.DataFrame(mlops.history)[["timestamp", "input_type", "verdict", "risk_score", "latency_ms", "snippet"]]
            st.dataframe(df_hist, use_container_width=True, hide_index=True)
        else:
            st.write("No scan history logged.")

    with tab_metrics:
        eval_path = ROOT / "models" / "evaluation.json"
        if eval_path.exists():
            data = json.loads(eval_path.read_text(encoding="utf-8")).get("models", {})
            rows = []
            for name, m in data.items():
                rows.append({
                    "Model": name,
                    "Accuracy": f"{m['accuracy']:.3f}",
                    "Precision": f"{m['precision']:.3f}",
                    "Recall": f"{m['recall']:.3f}",
                    "F1": f"{m['f1']:.3f}",
                    "ROC-AUC": f"{m['roc_auc']:.3f}"
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

            # Confusion Matrix
            stack_m = data.get("Stacking Ensemble", list(data.values())[0])
            fig_cm, ax_cm = plt.subplots(figsize=(4, 3))
            ConfusionMatrixDisplay(
                confusion_matrix=pd.DataFrame(stack_m["confusion_matrix"]).to_numpy(),
                display_labels=["Safe", "Phish"]
            ).plot(ax=ax_cm, colorbar=False, values_format="d")
            st.pyplot(fig_cm)
            plt.close(fig_cm)
        else:
            st.write("Run `train_model.py` to view evaluation benchmarks.")

    with tab_drift:
        drift = mlops.get_drift_status()
        fb = mlops.get_feedback_metrics()

        d1, d2, d3 = st.columns(3)
        d1.metric("PSI Index", drift["psi"])
        d2.metric("Drift Status", "Stable" if not drift["drift_detected"] else "Drift Alert")
        d3.metric("Review Agreement", f"{fb['accuracy'] * 100:.0f}%")

        if drift["bin_details"]:
            st.caption("Distribution Bins")
            st.dataframe(pd.DataFrame(drift["bin_details"])[["bin", "expected_pct", "actual_pct", "psi_contribution"]], use_container_width=True, hide_index=True)
