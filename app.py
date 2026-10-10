from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
OUTPUT_DIR = ROOT / "outputs"
IMAGE_DIR = ROOT / "images"

st.set_page_config(
    page_title="P4 | AI Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ AI-Powered Network Intrusion Detection")
st.caption(
    "Security Operations Center dashboard · Hybrid Random Forest + Isolation Forest "
    "using the project's saved models"
)


def read_csv(path: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path) if path.exists() else pd.DataFrame()
    except (OSError, pd.errors.ParserError, UnicodeDecodeError):
        return pd.DataFrame()


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except (OSError, json.JSONDecodeError):
        return []


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    except OSError:
        return ""


@st.cache_resource
def load_detector_resources():
    # Import from the original project so the GUI uses its real feature engineering
    # and inference code rather than reimplementing the model pipeline.
    from src.preprocessor import NetworkTrafficPreprocessor
    from src.model_engine import HybridThreatDetector

    preprocessor = NetworkTrafficPreprocessor.load(str(MODEL_DIR / "preprocessor.joblib"))
    detector = HybridThreatDetector.load(str(MODEL_DIR))
    class_names = list(preprocessor.target_encoder.classes_)
    return preprocessor, detector, class_names


def run_project_command(args: list[str], label: str) -> tuple[int, str]:
    main_file = ROOT / "main.py"
    if not main_file.exists():
        return 2, "main.py was not found. Save app.py in the same folder as main.py."
    command = [sys.executable, str(main_file), *args]
    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60 * 30,
        )
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        return result.returncode, output.strip() or f"{label} finished without terminal output."
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        return 124, f"{label} exceeded the 30-minute timeout.\n{partial}"
    except OSError as exc:
        return 2, f"Could not launch {label}: {exc}"


def image_panel(filename: str, title: str, caption: str | None = None):
    path = IMAGE_DIR / filename
    if path.exists():
        st.subheader(title)
        st.image(str(path), use_container_width=True)
        if caption:
            st.caption(caption)
    else:
        st.info(f"'{filename}' has not been generated yet. Run the project pipeline to create it.")


def format_pct(value) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "—"


def analyze_flows(df: pd.DataFrame, preprocessor, detector, class_names) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()
    required = [
        "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "service", "flag", "duration", "src_bytes", "dst_bytes", "src_pkts",
        "dst_pkts", "failed_logins",
    ]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError("Missing required network flow columns: " + ", ".join(missing))

    # The label column, when present in the supplied demo CSV, is not used for inference.
    X = preprocessor.transform(df.copy())
    predictions = detector.predict_hybrid(X, class_names)
    result = df.copy()
    result["predicted_threat"] = [p["predicted_threat"] for p in predictions]
    result["confidence_pct"] = [round(float(p["confidence"]) * 100, 2) for p in predictions]
    result["anomaly_severity"] = [p["anomaly_severity_score"] for p in predictions]
    result["is_outlier"] = [p["is_outlier"] for p in predictions]
    result["detection_status"] = result["predicted_threat"].apply(
        lambda x: "NORMAL" if x == "BENIGN" else "ALERT"
    )
    return result


def build_manual_flow(preprocessor, protocol, service, flag, values) -> pd.DataFrame:
    return pd.DataFrame([{
        "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": values["src_ip"],
        "src_port": int(values["src_port"]),
        "dst_ip": values["dst_ip"],
        "dst_port": int(values["dst_port"]),
        "protocol": protocol,
        "service": service,
        "flag": flag,
        "duration": float(values["duration"]),
        "src_bytes": int(values["src_bytes"]),
        "dst_bytes": int(values["dst_bytes"]),
        "src_pkts": int(values["src_pkts"]),
        "dst_pkts": int(values["dst_pkts"]),
        "failed_logins": int(values["failed_logins"]),
    }])


with st.sidebar:
    st.header("Project controls")
    st.caption(f"Project root: {ROOT}")
    if st.button("↻ Refresh dashboard", use_container_width=True):
        st.cache_resource.clear()
        st.rerun()

    with st.expander("Run existing project commands"):
        st.warning(
            "These commands run the project's scripts locally. Training replaces the saved models; "
            "simulation rewrites the saved alert/report outputs."
        )
        if st.button("Run test-stream simulation", use_container_width=True):
            with st.spinner("Running main.py --simulate ..."):
                code, log = run_project_command(["--simulate"], "Simulation")
            st.session_state["last_command_log"] = log
            st.session_state["last_command_ok"] = code == 0
            st.cache_resource.clear()
            st.rerun()
        if st.button("Train and evaluate models", use_container_width=True):
            with st.spinner("Running main.py --train ..."):
                code, log = run_project_command(["--train"], "Training")
            st.session_state["last_command_log"] = log
            st.session_state["last_command_ok"] = code == 0
            st.cache_resource.clear()
            st.rerun()

    st.divider()
    st.subheader("File status")
    status_files = [
        ("Threat classifier", MODEL_DIR / "threat_classifier.joblib"),
        ("Anomaly detector", MODEL_DIR / "anomaly_detector.joblib"),
        ("Preprocessor", MODEL_DIR / "preprocessor.joblib"),
        ("Raw traffic data", DATA_DIR / "raw_network_traffic.csv"),
        ("Test stream", DATA_DIR / "test_stream.csv"),
        ("Security alerts", OUTPUT_DIR / "security_alerts.json"),
    ]
    for label, path in status_files:
        st.write(("✅ " if path.exists() else "⚪ ") + label)

if "last_command_log" in st.session_state:
    if st.session_state.get("last_command_ok"):
        st.success("Project command completed successfully.")
    else:
        st.error("Project command did not complete successfully. Inspect the log below.")
    with st.expander("Last command output", expanded=not st.session_state.get("last_command_ok", False)):
        st.code(st.session_state["last_command_log"], language="text")

raw_df = read_csv(DATA_DIR / "raw_network_traffic.csv")
stream_df = read_csv(DATA_DIR / "test_stream.csv")
alerts_data = read_json(OUTPUT_DIR / "security_alerts.json")
report_text = read_text(OUTPUT_DIR / "soc_incident_report.txt")
classification_report = read_text(OUTPUT_DIR / "classification_report.txt")

try:
    preprocessor, detector, class_names = load_detector_resources()
    model_error = None
except Exception as exc:
    preprocessor = detector = class_names = None
    model_error = str(exc)

if model_error:
    st.error(
        "The saved model/preprocessor could not be loaded. Confirm that the app.py file is in "
        "the P4 project root and that the model files exist. Details: " + model_error
    )
    st.stop()

alert_df = pd.DataFrame(alerts_data) if isinstance(alerts_data, list) else pd.DataFrame()
alert_count = len(alert_df)
critical_count = (
    int(alert_df["severity"].astype(str).str.upper().eq("CRITICAL").sum())
    if not alert_df.empty and "severity" in alert_df.columns else 0
)
attack_count = (
    int((alert_df["threat_classification"].astype(str) != "BENIGN").sum())
    if not alert_df.empty and "threat_classification" in alert_df.columns else 0
)

# The saved classification report is a precomputed project result. Do not present
# its perfect scores as a guarantee of real-world detection performance.
accuracy_line = next(
    (line.split(":", 1)[1].strip() for line in classification_report.splitlines()
     if line.strip().lower().startswith("accuracy:")),
    None,
)

k1, k2, k3, k4 = st.columns(4)
k1.metric("Traffic records", f"{len(raw_df):,}" if not raw_df.empty else "—")
k2.metric("Recorded alerts", f"{alert_count:,}")
k3.metric("Critical alerts", f"{critical_count:,}")
k4.metric("Known threat classes", str(max(0, len(class_names) - (1 if "BENIGN" in class_names else 0))))

if accuracy_line:
    st.caption(
        f"Saved offline evaluation report accuracy: {float(accuracy_line) * 100:.2f}% "
        "(from the project's existing report; performance on real networks may differ)."
    )

overview_tab, single_tab, stream_tab, alerts_tab, data_tab, reports_tab = st.tabs([
    "Overview", "Analyze one flow", "Test-stream analysis", "Security alerts",
    "Traffic data", "Reports & files"
])

with overview_tab:
    st.subheader("Security overview")
    top_left, top_right = st.columns(2)
    with top_left:
        image_panel("threat_distribution.png", "Threat category distribution")
        image_panel("confusion_matrix.png", "Model confusion matrix")
        image_panel("feature_importance.png", "Important network features")
    with top_right:
        image_panel("anomaly_scores.png", "Anomaly score distribution")
        image_panel("attack_timeline.png", "Recorded attack timeline")
    if not alert_df.empty:
        st.subheader("Latest recorded alerts")
        visible = [c for c in [
            "alert_id", "timestamp", "severity", "risk_score", "threat_classification",
            "source_ip", "destination_ip", "destination_port"
        ] if c in alert_df.columns]
        st.dataframe(alert_df[visible].head(10), use_container_width=True, hide_index=True)
    else:
        st.info("No saved security alerts were found yet. Run the project's simulation to generate them.")

with single_tab:
    st.subheader("Analyze an individual network flow")
    st.write(
        "Enter flow metadata and the model will apply the same saved preprocessing and hybrid "
        "classifier used by the original project. This form analyzes an example record; it does "
        "not capture traffic from a live network interface."
    )

    encoders = getattr(preprocessor, "label_encoders", {})
    protocols = list(encoders["protocol"].classes_) if "protocol" in encoders else ["TCP", "UDP", "ICMP"]
    services = list(encoders["service"].classes_) if "service" in encoders else ["http", "https", "dns", "ssh", "other"]
    flags = list(encoders["flag"].classes_) if "flag" in encoders else ["SF", "S0", "REJ", "RSTO", "RSTR", "SH"]

    with st.form("single_flow_form"):
        ip1, ip2 = st.columns(2)
        with ip1:
            src_ip = st.text_input("Source IP", value="192.168.1.45")
            src_port = st.number_input("Source port", min_value=0, max_value=65535, value=51515, step=1)
            protocol = st.selectbox("Protocol", protocols)
            service = st.selectbox("Service", services)
            flag = st.selectbox("Connection flag", flags)
            duration = st.number_input("Duration (seconds)", min_value=0.0, value=0.25, step=0.1, format="%.4f")
        with ip2:
            dst_ip = st.text_input("Destination IP", value="10.0.0.8")
            dst_port = st.number_input("Destination port", min_value=0, max_value=65535, value=22, step=1)
            src_bytes = st.number_input("Source bytes", min_value=0, value=1200, step=100)
            dst_bytes = st.number_input("Destination bytes", min_value=0, value=600, step=100)
            src_pkts = st.number_input("Source packets", min_value=0, value=12, step=1)
            dst_pkts = st.number_input("Destination packets", min_value=0, value=8, step=1)
            failed_logins = st.number_input("Failed logins", min_value=0, value=0, step=1)
        submitted = st.form_submit_button("Analyze network flow", type="primary", use_container_width=True)

    if submitted:
        try:
            manual_df = pd.DataFrame([{
                "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip, "src_port": int(src_port), "dst_ip": dst_ip,
                "dst_port": int(dst_port), "protocol": protocol, "service": service,
                "flag": flag, "duration": float(duration), "src_bytes": int(src_bytes),
                "dst_bytes": int(dst_bytes), "src_pkts": int(src_pkts), "dst_pkts": int(dst_pkts),
                "failed_logins": int(failed_logins),
            }])
            analyzed = analyze_flows(manual_df, preprocessor, detector, class_names)
            row = analyzed.iloc[0]
            threat = str(row["predicted_threat"])
            if threat == "BENIGN":
                st.success("Model classification: BENIGN")
            else:
                st.error(f"Model classification: {threat}")
            m1, m2, m3 = st.columns(3)
            m1.metric("Classifier confidence", f"{row['confidence_pct']:.2f}%")
            m2.metric("Anomaly severity", f"{row['anomaly_severity']:.1f}/100")
            m3.metric("Isolation Forest outlier", "Yes" if row["is_outlier"] else "No")
            st.dataframe(analyzed, use_container_width=True, hide_index=True)
            st.caption("Model output is decision support, not proof that a flow is safe or malicious.")
        except Exception as exc:
            st.error(f"Could not analyze this flow: {exc}")

with stream_tab:
    st.subheader("Analyze the included test stream")
    st.write(f"Test stream file: `{(DATA_DIR / 'test_stream.csv').relative_to(ROOT)}`")
    if stream_df.empty:
        st.warning("The test stream CSV is missing or empty.")
    else:
        st.write(f"Available flows: **{len(stream_df):,}**")
        max_rows = min(150, len(stream_df))
        row_limit = st.slider("Number of flows to analyze", min_value=1, max_value=max_rows, value=max_rows)
        if st.button("Run hybrid detection on selected flows", type="primary"):
            try:
                subset = stream_df.head(row_limit).copy()
                with st.spinner("Applying saved preprocessing, classifier, and anomaly detector..."):
                    analyzed = analyze_flows(subset, preprocessor, detector, class_names)
                st.session_state["p4_stream_analysis"] = analyzed
            except Exception as exc:
                st.error(f"Stream analysis failed: {exc}")

        analyzed = st.session_state.get("p4_stream_analysis")
        if isinstance(analyzed, pd.DataFrame) and not analyzed.empty:
            total = len(analyzed)
            flagged = int(analyzed["predicted_threat"].ne("BENIGN").sum())
            outliers = int(analyzed["is_outlier"].sum())
            a1, a2, a3 = st.columns(3)
            a1.metric("Analyzed flows", total)
            a2.metric("Flagged by classifier", flagged)
            a3.metric("Isolation Forest outliers", outliers)

            if "label" in analyzed.columns:
                actual = analyzed["label"].astype(str)
                predicted = analyzed["predicted_threat"].astype(str)
                comparable = ~predicted.eq("SUSPICIOUS_ZERO_DAY_ANOMALY")
                if comparable.any():
                    exact_accuracy = (actual[comparable] == predicted[comparable]).mean()
                    st.metric("Agreement with supplied demo labels", f"{exact_accuracy * 100:.2f}%")
                    st.caption(
                        "This is an offline comparison against labels in the bundled synthetic test stream, "
                        "not a real-world performance guarantee."
                    )

            threat_filter = st.multiselect(
                "Filter predicted classes",
                sorted(analyzed["predicted_threat"].astype(str).unique()),
                default=sorted(analyzed["predicted_threat"].astype(str).unique()),
                key="stream_threat_filter",
            )
            filtered = analyzed[analyzed["predicted_threat"].astype(str).isin(threat_filter)]
            display_cols = [c for c in [
                "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                "predicted_threat", "confidence_pct", "anomaly_severity", "is_outlier", "label"
            ] if c in filtered.columns]
            st.dataframe(filtered[display_cols], use_container_width=True, hide_index=True)
            st.download_button(
                "Download analyzed flows as CSV",
                data=analyzed.to_csv(index=False).encode("utf-8"),
                file_name="p4_analyzed_test_stream.csv",
                mime="text/csv",
            )
            counts = analyzed["predicted_threat"].value_counts().rename_axis("threat").to_frame("flows")
            st.bar_chart(counts)
        else:
            st.info("Select the number of flows and click **Run hybrid detection** to produce predictions.")

with alerts_tab:
    st.subheader("Security alert console")
    if alert_df.empty:
        st.info("No saved alerts were found in outputs/security_alerts.json.")
    else:
        sev_values = sorted(alert_df["severity"].dropna().astype(str).unique()) if "severity" in alert_df else []
        selected_sev = st.multiselect("Severity", sev_values, default=sev_values)
        threat_values = sorted(alert_df["threat_classification"].dropna().astype(str).unique()) if "threat_classification" in alert_df else []
        selected_threats = st.multiselect("Threat class", threat_values, default=threat_values)
        filtered_alerts = alert_df.copy()
        if "severity" in filtered_alerts:
            filtered_alerts = filtered_alerts[filtered_alerts["severity"].astype(str).isin(selected_sev)]
        if "threat_classification" in filtered_alerts:
            filtered_alerts = filtered_alerts[filtered_alerts["threat_classification"].astype(str).isin(selected_threats)]

        display_cols = [c for c in [
            "alert_id", "timestamp", "severity", "risk_score", "threat_classification",
            "confidence_score", "anomaly_severity", "source_ip", "source_port",
            "destination_ip", "destination_port", "protocol"
        ] if c in filtered_alerts.columns]
        st.dataframe(filtered_alerts[display_cols], use_container_width=True, hide_index=True)

        if "severity" in filtered_alerts.columns and not filtered_alerts.empty:
            st.subheader("Alert severity distribution")
            st.bar_chart(filtered_alerts["severity"].value_counts())
        if "mitre_attack" in filtered_alerts.columns and not filtered_alerts.empty:
            st.subheader("Selected alert details")
            options = filtered_alerts["alert_id"].astype(str).tolist() if "alert_id" in filtered_alerts else []
            if options:
                chosen_id = st.selectbox("Choose an alert", options)
                chosen = filtered_alerts[filtered_alerts["alert_id"].astype(str) == chosen_id].iloc[0].to_dict()
                mitre = chosen.get("mitre_attack", {})
                if isinstance(mitre, dict):
                    st.write("**MITRE tactic:**", mitre.get("tactic", "Unknown"))
                    st.write("**Technique:**", mitre.get("technique", "Unknown"), f"({mitre.get('technique_id', 'N/A')})")
                st.write("**Recommended SOC action:**", chosen.get("soc_recommended_action", "Review the flow and follow local incident procedures."))
                st.json(chosen)

        st.download_button(
            "Download filtered alerts as JSON",
            data=json.dumps(filtered_alerts.to_dict(orient="records"), indent=2, default=str).encode("utf-8"),
            file_name="p4_filtered_security_alerts.json",
            mime="application/json",
        )

with data_tab:
    st.subheader("Network traffic dataset")
    if raw_df.empty:
        st.warning("Raw network traffic CSV is missing or empty.")
    else:
        st.write(f"Rows: **{len(raw_df):,}** · Columns: **{len(raw_df.columns)}**")
        if "label" in raw_df:
            st.subheader("Dataset class distribution")
            st.bar_chart(raw_df["label"].value_counts())
        if "protocol" in raw_df:
            st.subheader("Protocol distribution")
            st.bar_chart(raw_df["protocol"].value_counts())
        if "dst_port" in raw_df:
            st.subheader("Most frequent destination ports")
            st.bar_chart(raw_df["dst_port"].value_counts().head(15))
        st.dataframe(raw_df.head(500), use_container_width=True, hide_index=True)
        st.download_button(
            "Download raw traffic CSV",
            data=raw_df.to_csv(index=False).encode("utf-8"),
            file_name="raw_network_traffic.csv",
            mime="text/csv",
        )

with reports_tab:
    st.subheader("Existing project reports")
    if classification_report:
        with st.expander("Classification report", expanded=False):
            st.code(classification_report, language="text")
            st.download_button(
                "Download classification report",
                classification_report.encode("utf-8"),
                "classification_report.txt",
                "text/plain",
            )
    else:
        st.info("outputs/classification_report.txt was not found.")
    if report_text:
        with st.expander("SOC incident report", expanded=True):
            st.code(report_text, language="text")
            st.download_button(
                "Download SOC incident report",
                report_text.encode("utf-8"),
                "soc_incident_report.txt",
                "text/plain",
            )
    else:
        st.info("outputs/soc_incident_report.txt was not found.")

    st.subheader("Project files")
    rows = []
    for name, path in [
        ("Threat classifier", MODEL_DIR / "threat_classifier.joblib"),
        ("Anomaly detector", MODEL_DIR / "anomaly_detector.joblib"),
        ("Preprocessor", MODEL_DIR / "preprocessor.joblib"),
        ("Raw network traffic", DATA_DIR / "raw_network_traffic.csv"),
        ("Test stream", DATA_DIR / "test_stream.csv"),
        ("Classification report", OUTPUT_DIR / "classification_report.txt"),
        ("Security alerts", OUTPUT_DIR / "security_alerts.json"),
        ("SOC incident report", OUTPUT_DIR / "soc_incident_report.txt"),
    ]:
        rows.append({"Artifact": name, "Relative path": str(path.relative_to(ROOT)), "Status": "Available" if path.exists() else "Missing"})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

st.divider()
st.caption(
    "This dashboard uses the project's bundled data and saved models. It does not capture packets from "
    "a live network interface, block traffic, or perform automatic remediation."
)
