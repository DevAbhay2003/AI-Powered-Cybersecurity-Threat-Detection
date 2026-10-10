"""
Real-time Virtual Cyber Attack Simulation Engine
Simulates enterprise network packet flows, passes them through the hybrid AI
threat detection engine, triggers instant SOC alerts, and records incident audits.
"""

import os
import time
import pandas as pd
from src.data_generator import generate_stream_simulation_batch
from src.preprocessor import NetworkTrafficPreprocessor
from src.model_engine import HybridThreatDetector
from src.alert_engine import SOCAlertEngine, BOLD, GREEN, RESET, CYAN, YELLOW
from src.visualizer import SecurityVisualizer

def run_simulation(stream_path="data/test_stream.csv", delay_seconds=0.03):
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}    STARTING AI-POWERED CYBERSECURITY THREAT DETECTION SIMULATION      {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")
    
    if not os.path.exists(stream_path):
        print(f"[*] Simulation stream not found. Generating new realistic attack batch...")
        generate_stream_simulation_batch(num_records=150, output_path=stream_path)
        
    df_stream = pd.read_csv(stream_path)
    print(f"[+] Loaded simulation stream with {len(df_stream)} network flow records.")
    
    # Load Preprocessor and Models
    try:
        preprocessor = NetworkTrafficPreprocessor.load("models/preprocessor.joblib")
        detector = HybridThreatDetector.load("models/")
    except Exception as e:
        print(f"[!] Error loading models: {e}")
        print("[!] Please run model training first: python main.py --train")
        return
        
    alert_engine = SOCAlertEngine(log_output_path="outputs/security_alerts.json")
    visualizer = SecurityVisualizer(output_dir="images")
    
    class_names = list(preprocessor.target_encoder.classes_)
    
    # Transform features
    X_stream = preprocessor.transform(df_stream)
    predictions = detector.predict_hybrid(X_stream, class_names)
    
    threat_count = 0
    benign_count = 0
    
    print(f"[*] Streaming network flows into AI Detection Pipeline...\n")
    
    for i, (idx, row) in enumerate(df_stream.iterrows()):
        pred = predictions[i]
        flow_dict = row.to_dict()
        
        if pred["predicted_threat"] == "BENIGN":
            benign_count += 1
            # Print subtle dot or log periodically for benign
            if benign_count % 15 == 0:
                print(f" {GREEN}[+] [BENIGN FLOW MONITORED]{RESET} {flow_dict['src_ip']} -> {flow_dict['dst_ip']}:{flow_dict['dst_port']} (Normal baseline traffic)")
        else:
            threat_count += 1
            alert = alert_engine.generate_alert(flow_dict, pred)
            if alert:
                alert_engine.print_terminal_alert(alert)
                
        if delay_seconds > 0:
            time.sleep(delay_seconds)
            
    # Persist and summarize
    alert_engine.save_alerts_to_disk()
    alert_engine.generate_incident_summary("outputs/soc_incident_report.txt")
    
    if alert_engine.alerts_history:
        visualizer.plot_attack_timeline(alert_engine.alerts_history, "attack_timeline.png")
        
    print(f"\n{BOLD}{GREEN}========================================================================{RESET}")
    print(f"{BOLD}{GREEN}                      SIMULATION RUN COMPLETE                          {RESET}")
    print(f"{BOLD}{GREEN}========================================================================{RESET}")
    print(f" [+] Total Packets Analyzed : {len(df_stream)}")
    print(f" [+] Benign Flows Verified  : {benign_count}")
    print(f" [+] Cyber Threats Blocked  : {threat_count}")
    print(f" [+] Security Alerts Logged : outputs/security_alerts.json")
    print(f" [+] SOC Incident Report    : outputs/soc_incident_report.txt")
    print(f" [+] Attack Timeline Graph  : images/attack_timeline.png\n")

if __name__ == "__main__":
    run_simulation(delay_seconds=0.01)
