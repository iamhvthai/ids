"""
Snort3 Agent — Simulation Mode
Gửi Snort3-style alerts tới Flask server dựa trên dữ liệu CSV có sẵn.
"""
import time
import json
import random
import requests
import pandas as pd
from datetime import datetime
from pathlib import Path

SERVER_URL = "http://127.0.0.1:5000"
ALERT_ENDPOINT = f"{SERVER_URL}/api/snort/alert"
DATA_FILE = Path(__file__).parent / "data" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
DELAY_SECONDS = 1.5

LABEL_TO_TYPE = {
    'ddos': 'DDoS', 'dos': 'DoS', 'portscan': 'PortScan',
    'brute force': 'BruteForce', 'ftp-patator': 'BruteForce', 'ssh-patator': 'BruteForce',
    'bot': 'Bot', 'web attack': 'WebAttack', 'infiltration': 'Bot',
}

SAMPLE_ALERTS = [
    {"msg": "HTTP Flood Attack detected", "sid": 1000001, "priority": 1},
    {"msg": "TCP SYN Flood detected", "sid": 1000003, "priority": 1},
    {"msg": "UDP Flood detected", "sid": 1000005, "priority": 1},
    {"msg": "Slowloris Attack detected", "sid": 1000010, "priority": 1},
    {"msg": "TCP Port Scan detected", "sid": 1000020, "priority": 2},
    {"msg": "TCP SYN Stealth Scan", "sid": 1000022, "priority": 2},
    {"msg": "SSH Brute Force detected", "sid": 1000030, "priority": 1},
    {"msg": "RDP Brute Force detected", "sid": 1000033, "priority": 1},
    {"msg": "Botnet C&C Beacon detected", "sid": 1000041, "priority": 1},
    {"msg": "SQL Injection Attempt", "sid": 1000050, "priority": 1},
    {"msg": "XSS Attempt detected", "sid": 1000051, "priority": 1},
    {"msg": "Path Traversal Attempt", "sid": 1000053, "priority": 1},
]

print("=" * 50)
print("  Snort3 Agent — Simulation Mode")
print(f"  Target: {ALERT_ENDPOINT}")
print("=" * 50)

try:
    print(f"[1] Loading dataset: {DATA_FILE.name}...")
    df = pd.read_csv(DATA_FILE, low_memory=False)
    df.columns = df.columns.str.strip()
    attack_df = df[~df['Label'].str.contains('BENIGN', na=False)].sample(100)
    print(f"    -> Loaded {len(attack_df)} attack samples for simulation.")
except Exception as e:
    print(f"[!] Error: {e}")
    exit(1)

print("[2] Starting Snort3 alert simulation...\n")

for idx, (_, row) in enumerate(attack_df.iterrows()):
    raw_label = str(row.get('Label', '')).strip()
    attack_type = 'Unknown'
    for key, val in LABEL_TO_TYPE.items():
        if key.lower() in raw_label.lower():
            attack_type = val
            break

    src_port = int(row.get('Source Port', 0)) if pd.notna(row.get('Source Port', 0)) else random.randint(1024, 65535)
    dst_port = int(row.get('Destination Port', 80)) if pd.notna(row.get('Destination Port', 80)) else 80
    src_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"

    sample = random.choice(SAMPLE_ALERTS)

    alert = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": "192.168.1.100",
        "dst_port": dst_port,
        "protocol": "TCP",
        "type": attack_type,
        "msg": sample["msg"],
        "sid": sample["sid"],
        "priority": sample["priority"],
        "source": "snort3_sim",
    }

    try:
        res = requests.post(ALERT_ENDPOINT, json=alert, timeout=2)
        if res.status_code == 200:
            icon = "🚨" if attack_type != "BENIGN" else "✅"
            print(f"{icon} [{idx+1:02d}] {attack_type:12s} -> {alert['msg']} (sid:{alert['sid']})")
        else:
            print(f"⚠️  Server returned {res.status_code}")
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to server. Is Flask app running?")
        break
    except Exception as e:
        print(f"❌ Error: {e}")

    time.sleep(DELAY_SECONDS)

print("\n✅ Simulation finished.")
