"""
Network Traffic Data Generator & Loader
Simulates realistic enterprise network flow logs reflecting benign operations
and multi-vector cyber attacks (DoS SYN Flood, Port Scan, SSH Brute Force, Exfiltration).
"""

import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

ATTACK_TYPES = [
    "BENIGN",
    "DOS_SYN_FLOOD",
    "PORT_SCAN",
    "BRUTE_FORCE_SSH",
    "DATA_EXFILTRATION"
]

PROTOCOLS = ["TCP", "UDP", "ICMP"]
TCP_FLAGS = ["SF", "S0", "REJ", "RSTO", "RSTR", "SH"]
SERVICES = ["http", "https", "dns", "ssh", "smtp", "ftp", "mysql", "rdp", "other"]

def generate_benign_flow(base_time):
    proto = random.choices(["TCP", "UDP"], weights=[0.75, 0.25])[0]
    service = random.choices(
        ["https", "http", "dns", "ssh", "mysql"],
        weights=[0.50, 0.25, 0.15, 0.05, 0.05]
    )[0]
    
    port_map = {"https": 443, "http": 80, "dns": 53, "ssh": 22, "mysql": 3306}
    dst_port = port_map.get(service, random.randint(1024, 65535))
    src_port = random.randint(30000, 65000)
    
    duration = float(np.random.exponential(scale=1.5))
    src_bytes = int(np.random.normal(loc=1200, scale=400))
    dst_bytes = int(np.random.normal(loc=4500, scale=1500))
    src_pkts = max(1, int(np.random.normal(loc=12, scale=4)))
    dst_pkts = max(1, int(np.random.normal(loc=18, scale=6)))
    
    src_bytes = max(64, src_bytes)
    dst_bytes = max(64, dst_bytes)
    failed_logins = 0
    flag = "SF" if proto == "TCP" else "SF"
    
    src_ip = f"192.168.1.{random.randint(10, 150)}"
    dst_ip = random.choice([
        "10.0.0.5", "10.0.0.8", "142.250.190.46", "151.101.1.140", "1.1.1.1"
    ])
    
    return {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": proto,
        "service": service,
        "flag": flag,
        "duration": round(duration, 4),
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "src_pkts": src_pkts,
        "dst_pkts": dst_pkts,
        "failed_logins": failed_logins,
        "label": "BENIGN"
    }

def generate_dos_flow(base_time, attacker_ip=None):
    attacker_ip = attacker_ip or f"203.0.113.{random.randint(5, 99)}"
    target_ip = "10.0.0.5" # Enterprise Web Server
    dst_port = random.choice([80, 443])
    src_port = random.randint(1024, 65535)
    
    duration = round(float(np.random.uniform(0.001, 0.05)), 4)
    src_bytes = random.randint(40, 60) # SYN packet payload size
    dst_bytes = 0 # No response completed
    src_pkts = random.randint(50, 200)
    dst_pkts = 0
    failed_logins = 0
    flag = "S0" # SYN received without ACK (Half-open connection)
    
    return {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": attacker_ip,
        "src_port": src_port,
        "dst_ip": target_ip,
        "dst_port": dst_port,
        "protocol": "TCP",
        "service": "http" if dst_port == 80 else "https",
        "flag": flag,
        "duration": duration,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "src_pkts": src_pkts,
        "dst_pkts": dst_pkts,
        "failed_logins": failed_logins,
        "label": "DOS_SYN_FLOOD"
    }

def generate_port_scan_flow(base_time, attacker_ip=None, target_port=None):
    attacker_ip = attacker_ip or f"198.51.100.{random.randint(2, 50)}"
    target_ip = "10.0.0.8" # Enterprise Core Switch / Server
    dst_port = target_port if target_port else random.choice([
        21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080
    ])
    src_port = random.randint(40000, 60000)
    
    duration = round(float(np.random.uniform(0.001, 0.1)), 4)
    src_bytes = random.randint(40, 70)
    dst_bytes = random.choice([0, 40])
    src_pkts = random.randint(1, 3)
    dst_pkts = random.choice([0, 1])
    failed_logins = 0
    flag = random.choice(["REJ", "S0", "RSTO"])
    
    return {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": attacker_ip,
        "src_port": src_port,
        "dst_ip": target_ip,
        "dst_port": dst_port,
        "protocol": "TCP",
        "service": "other",
        "flag": flag,
        "duration": duration,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "src_pkts": src_pkts,
        "dst_pkts": dst_pkts,
        "failed_logins": failed_logins,
        "label": "PORT_SCAN"
    }

def generate_ssh_brute_force_flow(base_time, attacker_ip=None):
    attacker_ip = attacker_ip or f"185.220.101.{random.randint(10, 80)}"
    target_ip = "10.0.0.20" # Enterprise Jumpbox / Bastion Server
    dst_port = 22
    src_port = random.randint(35000, 55000)
    
    duration = round(float(np.random.uniform(0.5, 3.0)), 4)
    src_bytes = random.randint(700, 1800)
    dst_bytes = random.randint(600, 1500)
    src_pkts = random.randint(10, 25)
    dst_pkts = random.randint(8, 20)
    failed_logins = random.randint(3, 12) # Key indicator
    flag = "SF"
    
    return {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": attacker_ip,
        "src_port": src_port,
        "dst_ip": target_ip,
        "dst_port": dst_port,
        "protocol": "TCP",
        "service": "ssh",
        "flag": flag,
        "duration": duration,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "src_pkts": src_pkts,
        "dst_pkts": dst_pkts,
        "failed_logins": failed_logins,
        "label": "BRUTE_FORCE_SSH"
    }

def generate_exfiltration_flow(base_time, compromised_internal_ip=None):
    compromised_ip = compromised_internal_ip or f"192.168.1.{random.randint(50, 70)}"
    c2_ip = f"45.33.32.{random.randint(10, 90)}" # External Command & Control server
    dst_port = random.choice([443, 8443, 4444])
    src_port = random.randint(45000, 65000)
    
    duration = round(float(np.random.uniform(20.0, 120.0)), 4) # Long persistent connection
    src_bytes = int(np.random.normal(loc=850000, scale=120000)) # Massive outbound upload
    dst_bytes = int(np.random.normal(loc=1200, scale=300))     # Small inbound ACKs
    src_pkts = random.randint(600, 2000)
    dst_pkts = random.randint(200, 700)
    failed_logins = 0
    flag = "SF"
    
    return {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": compromised_ip,
        "src_port": src_port,
        "dst_ip": c2_ip,
        "dst_port": dst_port,
        "protocol": "TCP",
        "service": "https" if dst_port in [443, 8443] else "other",
        "flag": flag,
        "duration": duration,
        "src_bytes": max(50000, src_bytes),
        "dst_bytes": max(500, dst_bytes),
        "src_pkts": src_pkts,
        "dst_pkts": dst_pkts,
        "failed_logins": failed_logins,
        "label": "DATA_EXFILTRATION"
    }

def generate_network_traffic_dataset(num_records=10000, output_path="data/raw_network_traffic.csv"):
    """
    Synthesizes a realistic, benchmark-grade enterprise network flow dataset.
    Class distribution:
      - 70% Benign
      - 12% DoS SYN Flood
      - 10% Port Scan
      - 5% SSH Brute Force
      - 3% Data Exfiltration (Zero-Day style Anomaly)
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    print(f"[*] Generating {num_records} synthetic enterprise network telemetry records...")
    start_time = datetime.now() - timedelta(hours=24)
    records = []
    
    weights = [0.70, 0.12, 0.10, 0.05, 0.03]
    categories = ATTACK_TYPES
    
    for i in range(num_records):
        curr_time = start_time + timedelta(seconds=int(i * 8.64))
        choice = random.choices(categories, weights=weights)[0]
        
        if choice == "BENIGN":
            rec = generate_benign_flow(curr_time)
        elif choice == "DOS_SYN_FLOOD":
            rec = generate_dos_flow(curr_time)
        elif choice == "PORT_SCAN":
            rec = generate_port_scan_flow(curr_time)
        elif choice == "BRUTE_FORCE_SSH":
            rec = generate_ssh_brute_force_flow(curr_time)
        elif choice == "DATA_EXFILTRATION":
            rec = generate_exfiltration_flow(curr_time)
        
        records.append(rec)
        
    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    print(f"[+] Dataset successfully created and saved to: {output_path}")
    print(f"[+] Class distribution:\n{df['label'].value_counts(normalize=True).mul(100).round(2)}%")
    return df

def generate_stream_simulation_batch(num_records=150, output_path="data/test_stream.csv"):
    """Generates an evaluation stream containing a coordinated multi-stage cyber assault."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    start_time = datetime.now()
    records = []
    
    # Sequence of attack simulation:
    # 1. Benign background
    # 2. Port scan reconnaissance
    # 3. SSH Brute Force credential cracking
    # 4. Data Exfiltration
    # 5. Volumetric DoS flood to mask activities
    
    attacker_ext = "194.26.29.11"
    compromised_host = "192.168.1.45"
    
    for i in range(num_records):
        t = start_time + timedelta(seconds=i * 2)
        if i < 40:
            rec = generate_benign_flow(t)
        elif i < 70:
            rec = generate_port_scan_flow(t, attacker_ip=attacker_ext)
        elif i < 100:
            rec = generate_ssh_brute_force_flow(t, attacker_ip=attacker_ext)
        elif i < 115:
            rec = generate_exfiltration_flow(t, compromised_internal_ip=compromised_host)
        elif i < 140:
            rec = generate_dos_flow(t, attacker_ip="185.190.140.22")
        else:
            rec = generate_benign_flow(t)
            
        records.append(rec)
        
    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    print(f"[+] Simulation stream generated with {num_records} flow records -> {output_path}")
    return df

if __name__ == "__main__":
    generate_network_traffic_dataset(num_records=12000, output_path="data/raw_network_traffic.csv")
    generate_stream_simulation_batch(num_records=150, output_path="data/test_stream.csv")
