"""
Snort3 Bridge Module
Manages Snort3 Docker container, reads alerts, and forwards to Flask dashboard.
"""
import os
import json
import time
import threading
import subprocess
import requests
from pathlib import Path
from datetime import datetime
from collections import deque

BASE_DIR = Path(__file__).resolve().parent.parent
SNORT3_DIR = BASE_DIR / "snort3"
LOG_FILE = SNORT3_DIR / "logs" / "alert.json"
DOCKER_COMPOSE = SNORT3_DIR / "docker-compose.yml"

SERVER_URL = "http://127.0.0.1:5000"
ALERT_ENDPOINT = f"{SERVER_URL}/api/snort/alert"

SNORT_BINARY = "/home/snorty/snort3/bin/snort"
SNORT_CONFIG = "/home/snorty/snort3/etc/snort/snort.lua"

RULE_CLASSIFICATION_MAP = {
    1000001: ("DDoS", "HTTP Flood Attack"),
    1000002: ("DDoS", "HTTPS Flood Attack"),
    1000003: ("DDoS", "TCP SYN Flood"),
    1000004: ("DDoS", "ICMP Flood"),
    1000005: ("DDoS", "UDP Flood"),
    1000010: ("DoS", "Slowloris Attack"),
    1000011: ("DoS", "HTTP Slow Read"),
    1000012: ("DoS", "TCP Connection Exhaustion"),
    1000020: ("PortScan", "TCP Port Scan"),
    1000021: ("PortScan", "UDP Port Scan"),
    1000022: ("PortScan", "TCP SYN Stealth Scan"),
    1000030: ("BruteForce", "SSH Brute Force"),
    1000031: ("BruteForce", "FTP Brute Force"),
    1000032: ("BruteForce", "MySQL Brute Force"),
    1000033: ("BruteForce", "RDP Brute Force"),
    1000040: ("Bot", "IRC C&C Traffic"),
    1000041: ("Bot", "HTTP C&C Beacon"),
    1000042: ("Bot", "Botnet DNS Query"),
    1000050: ("WebAttack", "SQL Injection Attempt"),
    1000051: ("WebAttack", "XSS Attempt"),
    1000052: ("WebAttack", "SQL Injection Over HTTPS"),
    1000053: ("WebAttack", "Path Traversal Attempt"),
    1000054: ("WebAttack", "Command Injection"),
}

SIMULATION_DATA_PATH = BASE_DIR / "data"


class SnortBridge:
    def __init__(self):
        self.container_name = "snort3_ids"
        self.running = False
        self.monitoring = False
        self.alert_history = deque(maxlen=200)
        self._monitor_thread = None
        self._last_position = 0
        self.process = None
        self.simulation_mode = False

    # ── Docker Management ──────────────────────────────────────────────
    def start_container(self):
        try:
            subprocess.run(
                ["docker-compose", "-f", str(DOCKER_COMPOSE), "up", "-d"],
                check=True, capture_output=True, text=True
            )
            self.running = True
            return True, "Snort3 container started"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to start: {e.stderr}"

    def stop_container(self):
        try:
            subprocess.run(
                ["docker-compose", "-f", str(DOCKER_COMPOSE), "down"],
                check=True, capture_output=True, text=True
            )
            self.running = False
            return True, "Snort3 container stopped"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to stop: {e.stderr}"

    def container_status(self):
        try:
            result = subprocess.run(
                ["docker", "ps", "--filter", f"name={self.container_name}",
                 "--format", "{{.Status}}"],
                check=True, capture_output=True, text=True
            )
            status = result.stdout.strip()
            self.running = bool(status)
            return self.running, status if status else "Not running"
        except subprocess.CalledProcessError as e:
            return False, f"Docker error: {e.stderr}"

    # ── Snort3 PCAP Analysis ───────────────────────────────────────────
    def analyze_pcap(self, pcap_path):
        pcap_name = Path(pcap_path).name
        container_path = f"/pcap/{pcap_name}"
        cmd = [
            "docker", "exec", self.container_name,
            SNORT_BINARY, "-c", SNORT_CONFIG,
            "-r", container_path,
            "-A", "json",
            "-l", "/var/log/snort",
            "--plugin-path",
            "/home/snorty/snort3/lib/snort_extra:/home/snorty/snort3/lib/snort_extra/extra"
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            return True, f"Analysis complete for {pcap_name}"
        except subprocess.CalledProcessError as e:
            return False, f"Analysis failed: {e.stderr}"
        except subprocess.TimeoutExpired:
            return False, "Analysis timed out"

    # ── Alert Monitoring ───────────────────────────────────────────────
    def start_monitoring(self, endpoint=None):
        if self.monitoring:
            return False, "Already monitoring"
        self.monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, args=(endpoint or ALERT_ENDPOINT,), daemon=True
        )
        self._monitor_thread.start()
        return True, "Monitoring started"

    def stop_monitoring(self):
        self.monitoring = False
        return True, "Monitoring stopped"

    def _monitor_loop(self, endpoint):
        while self.monitoring:
            if not LOG_FILE.exists():
                time.sleep(1)
                continue
            try:
                with open(LOG_FILE, "r") as f:
                    f.seek(self._last_position)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        alert = self._parse_alert(line)
                        if alert:
                            self.alert_history.appendleft(alert)
                            self._forward_alert(alert, endpoint)
                    self._last_position = f.tell()
            except Exception as e:
                print(f"[SnortBridge] Monitor error: {e}")
            time.sleep(0.5)

    def _parse_alert(self, line):
        try:
            data = json.loads(line)
            sid = data.get("sid", 0)
            classification = RULE_CLASSIFICATION_MAP.get(sid, ("Unknown", data.get("msg", "Unknown")))
            alert = {
                "timestamp": data.get("timestamp", datetime.now().isoformat()),
                "src_ip": data.get("src_addr", "unknown"),
                "src_port": data.get("src_port", 0),
                "dst_ip": data.get("dst_addr", "unknown"),
                "dst_port": data.get("dst_port", 0),
                "protocol": data.get("proto", "unknown").upper(),
                "type": classification[0],
                "msg": data.get("msg", classification[1]),
                "sid": sid,
                "priority": data.get("priority", 5),
                "source": "snort3",
            }
            return alert
        except json.JSONDecodeError:
            return None

    def _forward_alert(self, alert, endpoint):
        try:
            requests.post(endpoint, json=alert, timeout=2)
        except requests.exceptions.ConnectionError:
            pass
        except Exception as e:
            print(f"[SnortBridge] Forward error: {e}")

    def get_recent_alerts(self, limit=50, alert_type=None):
        if alert_type and alert_type != "ALL":
            return [a for a in self.alert_history if a["type"] == alert_type][:limit]
        return list(self.alert_history)[:limit]

    # ── Simulation Mode ────────────────────────────────────────────────
    def start_simulation(self, csv_path=None, endpoint=None):
        self.simulation_mode = True
        self._sim_thread = threading.Thread(
            target=self._simulation_loop,
            args=(csv_path, endpoint or ALERT_ENDPOINT),
            daemon=True
        )
        self._sim_thread.start()
        return True, "Simulation started"

    def stop_simulation(self):
        self.simulation_mode = False
        return True, "Simulation stopped"

    def _simulation_loop(self, csv_path, endpoint):
        if csv_path is None:
            csv_path = SIMULATION_DATA_PATH / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
        import pandas as pd
        try:
            df = pd.read_csv(csv_path, low_memory=False)
            df.columns = df.columns.str.strip()
            attack_samples = df[~df['Label'].str.contains('BENIGN', na=False)].sample(50)
            label_to_type = {
                'DDOS': 'DDoS', 'DDoS': 'DDoS',
                'DoS': 'DoS', 'DOS': 'DoS',
                'PortScan': 'PortScan',
                'Brute Force': 'BruteForce', 'FTP-Patator': 'BruteForce', 'SSH-Patator': 'BruteForce',
                'Bot': 'Bot',
                'Web Attack': 'WebAttack', 'WebAttack': 'WebAttack',
                'Infiltration': 'Bot',
            }
            for _, row in attack_samples.iterrows():
                if not self.simulation_mode:
                    break
                raw_label = str(row.get('Label', 'BENIGN')).strip()
                attack_type = 'Unknown'
                for key, val in label_to_type.items():
                    if key.lower() in raw_label.lower():
                        attack_type = val
                        break
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": f"10.0.{hash(str(row.get('Destination Port', 80))) % 255}.{hash(str(row.get('Flow Duration', 0))) % 255}",
                    "src_port": int(row.get('Source Port', 0)) if pd.notna(row.get('Source Port', 0)) else 0,
                    "dst_ip": "192.168.1.100",
                    "dst_port": int(row.get('Destination Port', 80)) if pd.notna(row.get('Destination Port', 80)) else 80,
                    "protocol": "TCP",
                    "type": attack_type,
                    "msg": f"{attack_type} traffic detected by Snort3",
                    "sid": 0,
                    "priority": 1,
                    "source": "snort3_sim",
                }
                self.alert_history.appendleft(alert)
                self._forward_alert(alert, endpoint)
                time.sleep(1.5)
        except Exception as e:
            print(f"[SnortBridge] Simulation error: {e}")


# Singleton
bridge = SnortBridge()
