"""
Security Operations Center (SOC) Alert Engine & Incident Response System
Maps detected cyber threats to MITRE ATT&CK tactics, calculates risk scores,
triggers defensive playbooks, and outputs SIEM-compliant event structures.
"""

import json
import os
from datetime import datetime

MITRE_ATTACK_MAPPING = {
    "DOS_SYN_FLOOD": {
        "tactic": "Impact (TA0040)",
        "technique": "Network Denial of Service: Direct Network Flood",
        "technique_id": "T1498.001",
        "default_severity": "HIGH",
        "recommended_action": "Apply edge firewall rate-limiting, activate SYN Proxy / TCP SYN Cookies, null-route offending external IP."
    },
    "PORT_SCAN": {
        "tactic": "Reconnaissance (TA0043) / Discovery (TA0007)",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "default_severity": "MEDIUM",
        "recommended_action": "Blacklist probing IP on boundary firewall, inspect host logs for follow-up exploitation attempts."
    },
    "BRUTE_FORCE_SSH": {
        "tactic": "Credential Access (TA0006)",
        "technique": "Brute Force: Password Guessing",
        "technique_id": "T1110.001",
        "default_severity": "HIGH",
        "recommended_action": "Trigger fail2ban IP jail, enforce multi-factor authentication (MFA), disable password authentication for SSH."
    },
    "DATA_EXFILTRATION": {
        "tactic": "Exfiltration (TA0010)",
        "technique": "Exfiltration Over Asymmetric Encrypted Channel",
        "technique_id": "T1048.003",
        "default_severity": "CRITICAL",
        "recommended_action": "IMMEDIATELY isolate endpoint from internal LAN, terminate active TCP socket, initiate forensic memory triage."
    },
    "SUSPICIOUS_ZERO_DAY_ANOMALY": {
        "tactic": "Defense Evasion (TA0005) / Initial Access",
        "technique": "Abnormal Network Traffic Baseline Deviation",
        "technique_id": "T1204 / Unclassified",
        "default_severity": "HIGH",
        "recommended_action": "Route session to honeynet/sandbox, perform deep packet inspection (DPI), capture full PCAP for threat hunting."
    }
}

# ANSI Color Codes for SOC Terminal Highlighting
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"

class SOCAlertEngine:
    def __init__(self, log_output_path="outputs/security_alerts.json"):
        self.log_output_path = log_output_path
        self.alerts_history = []
        os.makedirs(os.path.dirname(log_output_path), exist_ok=True)

    def calculate_risk_score(self, threat_type: str, confidence: float, anomaly_score: float) -> int:
        """Computes composite incident risk score (0 - 100)."""
        base_weights = {
            "DATA_EXFILTRATION": 90,
            "DOS_SYN_FLOOD": 80,
            "BRUTE_FORCE_SSH": 75,
            "SUSPICIOUS_ZERO_DAY_ANOMALY": 70,
            "PORT_SCAN": 50,
            "BENIGN": 5
        }
        base = base_weights.get(threat_type, 40)
        risk = (base * 0.6) + (confidence * 20) + (anomaly_score * 0.2)
        return int(min(100, max(0, risk)))

    def generate_alert(self, flow_record: dict, prediction_result: dict) -> dict:
        """
        Creates a structured incident alert compliant with SIEM formats.
        """
        threat_type = prediction_result["predicted_threat"]
        if threat_type == "BENIGN":
            return None  # No alert for normal operations
            
        mitre_info = MITRE_ATTACK_MAPPING.get(threat_type, {
            "tactic": "Unknown",
            "technique": "Unknown",
            "technique_id": "T0000",
            "default_severity": "LOW",
            "recommended_action": "Review telemetry."
        })
        
        confidence = prediction_result["confidence"]
        anomaly_sev = prediction_result["anomaly_severity_score"]
        risk_score = self.calculate_risk_score(threat_type, confidence, anomaly_sev)
        
        severity = mitre_info["default_severity"]
        if risk_score >= 85:
            severity = "CRITICAL"
        elif risk_score >= 70:
            severity = "HIGH"
        elif risk_score >= 45:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        alert_event = {
            "alert_id": f"SOC-SEC-{len(self.alerts_history) + 1001}",
            "timestamp": flow_record.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "severity": severity,
            "risk_score": risk_score,
            "threat_classification": threat_type,
            "confidence_score": round(confidence * 100, 2),
            "anomaly_severity": anomaly_sev,
            "source_ip": flow_record.get("src_ip", "0.0.0.0"),
            "source_port": int(flow_record.get("src_port", 0)),
            "destination_ip": flow_record.get("dst_ip", "0.0.0.0"),
            "destination_port": int(flow_record.get("dst_port", 0)),
            "protocol": flow_record.get("protocol", "TCP"),
            "mitre_attack": {
                "tactic": mitre_info["tactic"],
                "technique": mitre_info["technique"],
                "technique_id": mitre_info["technique_id"]
            },
            "soc_recommended_action": mitre_info["recommended_action"]
        }
        
        self.alerts_history.append(alert_event)
        return alert_event

    def print_terminal_alert(self, alert: dict):
        """Prints a colorized SOC analyst alert to standard output."""
        sev = alert["severity"]
        sev_color = RED if sev in ["CRITICAL", "HIGH"] else (YELLOW if sev == "MEDIUM" else BLUE)
        
        print(f"\n{BOLD}{sev_color}+==================================================================================+{RESET}")
        print(f"{BOLD}{sev_color}| [!] SOC SECURITY ALERT: {alert['alert_id']} | SEVERITY: {alert['severity']:<8} | RISK: {alert['risk_score']}/100 |{RESET}")
        print(f"{BOLD}{sev_color}+==================================================================================+{RESET}")
        print(f" {CYAN}[>] Time:{RESET}       {alert['timestamp']}  |  {CYAN}Protocol:{RESET} {alert['protocol']}")
        print(f" {CYAN}[>] Source:{RESET}     {alert['source_ip']}:{alert['source_port']}  -->  {CYAN}Target:{RESET} {alert['destination_ip']}:{alert['destination_port']}")
        print(f" {CYAN}[>] Threat:{RESET}     {BOLD}{alert['threat_classification']}{RESET} (Confidence: {alert['confidence_score']}%, Anomaly Sev: {alert['anomaly_severity']})")
        print(f" {CYAN}[>] MITRE:{RESET}      {alert['mitre_attack']['technique_id']} - {alert['mitre_attack']['technique']} [{alert['mitre_attack']['tactic']}]")
        print(f" {YELLOW}[!] Action:{RESET}     {alert['soc_recommended_action']}")
        print(f"{BOLD}----------------------------------------------------------------------------------{RESET}")

    def save_alerts_to_disk(self):
        """Persists all triggered alerts to JSON log file."""
        with open(self.log_output_path, "w") as f:
            json.dump(self.alerts_history, f, indent=4)
        print(f"[+] Total {len(self.alerts_history)} security alerts saved to: {self.log_output_path}")

    def generate_incident_summary(self, summary_path="outputs/soc_incident_report.txt"):
        """Generates human-readable SOC incident summary report."""
        if not self.alerts_history:
            return
            
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        total_alerts = len(self.alerts_history)
        sev_counts = {}
        threat_counts = {}
        
        for a in self.alerts_history:
            s = a["severity"]
            t = a["threat_classification"]
            sev_counts[s] = sev_counts.get(s, 0) + 1
            threat_counts[t] = threat_counts.get(t, 0) + 1
            
        report_lines = [
            "=" * 70,
            "              SECURITY OPERATIONS CENTER (SOC) INCIDENT REPORT",
            "=" * 70,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Threats Intercepted: {total_alerts}",
            "",
            "1. ALERT SEVERITY DISTRIBUTION:",
            "-" * 40
        ]
        for s, count in sorted(sev_counts.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"   - {s:<12}: {count} events ({count/total_alerts*100:.1f}%)")
            
        report_lines.extend([
            "",
            "2. ATTACK VECTOR BREAKDOWN:",
            "-" * 40
        ])
        for t, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"   - {t:<28}: {count} events")
            
        report_lines.extend([
            "",
            "3. TOP MALICIOUS OFFENDING IPs:",
            "-" * 40
        ])
        src_ips = {}
        for a in self.alerts_history:
            ip = a["source_ip"]
            src_ips[ip] = src_ips.get(ip, 0) + 1
        for ip, cnt in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            report_lines.append(f"   - {ip:<20}: {cnt} malicious connections")
            
        report_lines.extend([
            "",
            "=" * 70,
            "END OF SOC INCIDENT REPORT",
            "=" * 70
        ])
        
        with open(summary_path, "w") as f:
            f.write("\n".join(report_lines))
        print(f"[+] SOC Incident Summary written to: {summary_path}")
