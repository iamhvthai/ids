"""
Snort3 Remote Sensor
Deploy on remote machines to collect network traffic and forward alerts
to the central IDS Dashboard server.

Usage:
  python snort_sensor.py --server http://192.168.1.100:5000
  python snort_sensor.py --server http://192.168.1.100:5000 --watch /var/log/snort/alert.json

Modes:
  watch   Watch Snort3 alert JSON file & forward to server
  agent   Read local CSV data and send as Snort3 alerts periodically
  pcap    Analyze PCAP files with Snort3 and forward results
"""
import os
import sys
import json
import time
import uuid
import socket
import threading
import argparse
import requests
from pathlib import Path
from datetime import datetime
from collections import deque

LABEL_TO_TYPE = {
    'ddos': 'DDoS', 'dos': 'DoS', 'portscan': 'PortScan',
    'brute force': 'BruteForce', 'ftp-patator': 'BruteForce', 'ssh-patator': 'BruteForce',
    'bot': 'Bot', 'web attack': 'WebAttack', 'infiltration': 'Bot',
}


class RemoteSensor:
    def __init__(self, server_url, sensor_id=None, name=None):
        self.server_url = server_url.rstrip("/")
        self.sensor_id = sensor_id or str(uuid.uuid4())[:8]
        self.name = name or f"Sensor-{self.sensor_id}"
        self.hostname = socket.gethostname()
        self.running = False
        self._send_queue = deque(maxlen=500)
        self._queue_worker = None
        self._hb_worker = None
        self._stats = {"sent": 0, "failed": 0, "queued": 0}
        self.session = requests.Session()

    # ── API ────────────────────────────────────────────────────────────
    def _post(self, endpoint, data):
        url = f"{self.server_url}{endpoint}"
        data["sensor_id"] = self.sensor_id
        data["sensor_name"] = self.name
        data["sensor_hostname"] = self.hostname
        try:
            res = self.session.post(url, json=data, timeout=5)
            if res.status_code == 200:
                self._stats["sent"] += 1
                return True
            else:
                self._stats["failed"] += 1
                return False
        except requests.exceptions.ConnectionError:
            self._stats["failed"] += 1
            self._send_queue.append(data)
            self._stats["queued"] = len(self._send_queue)
            return False
        except Exception:
            self._stats["failed"] += 1
            return False

    def send_alert(self, alert):
        return self._post("/api/snort/alert", alert)

    def send_heartbeat(self):
        hb = {
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "stats": self._stats,
            "type": "heartbeat",
            "msg": f"Sensor {self.name} alive",
        }
        return self._post("/api/snort/alert", hb)

    # ── Queue Worker ───────────────────────────────────────────────────
    def _queue_loop(self):
        while self.running:
            if self._send_queue:
                data = self._send_queue[0]
                url = f"{self.server_url}/api/snort/alert"
                try:
                    res = self.session.post(url, json=data, timeout=5)
                    if res.status_code == 200:
                        self._send_queue.popleft()
                        self._stats["sent"] += 1
                        self._stats["queued"] = len(self._send_queue)
                    else:
                        time.sleep(5)
                except Exception:
                    time.sleep(5)
            else:
                time.sleep(2)

    # ── Heartbeat ──────────────────────────────────────────────────────
    def _heartbeat_loop(self):
        while self.running:
            self.send_heartbeat()
            time.sleep(30)

    # ── Watch Mode: tail Snort3 alert.json ──────────────────────────────
    def start_watch(self, alert_path, alert_type_filter=None):
        self.running = True
        self._start_workers()
        print(f"[Sensor:{self.name}] Watching: {alert_path}")
        path = Path(alert_path)
        if not path.parent.exists():
            print(f"[!] Directory {path.parent} does not exist. Creating...")
            path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.touch()

        last_pos = 0
        while self.running:
            try:
                with open(path, "r") as f:
                    f.seek(last_pos)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        alert = self._parse_snort_alert(line)
                        if alert and (not alert_type_filter or alert.get("type") == alert_type_filter):
                            self.send_alert(alert)
                            print(f"  -> {alert.get('type','?')}: {alert.get('msg','')}")
                    last_pos = f.tell()
            except Exception as e:
                print(f"[!] Watch error: {e}")
            time.sleep(1)

    def _parse_snort_alert(self, line):
        try:
            data = json.loads(line)
            return {
                "timestamp": data.get("timestamp", datetime.now().isoformat()),
                "src_ip": data.get("src_addr", "unknown"),
                "src_port": data.get("src_port", 0),
                "dst_ip": data.get("dst_addr", "unknown"),
                "dst_port": data.get("dst_port", 0),
                "protocol": data.get("proto", "unknown").upper(),
                "type": self._classify_sid(data.get("sid", 0)),
                "msg": data.get("msg", "Snort3 alert"),
                "sid": data.get("sid", 0),
                "priority": data.get("priority", 5),
                "source": "snort3_remote",
            }
        except json.JSONDecodeError:
            return None

    def _classify_sid(self, sid):
        if 1000001 <= sid <= 1000005: return "DDoS"
        if 1000010 <= sid <= 1000012: return "DoS"
        if 1000020 <= sid <= 1000022: return "PortScan"
        if 1000030 <= sid <= 1000033: return "BruteForce"
        if 1000040 <= sid <= 1000042: return "Bot"
        if 1000050 <= sid <= 1000054: return "WebAttack"
        return "Unknown"

    # ── Agent Mode: simulate from CSV ──────────────────────────────────
    def start_agent(self, csv_path, delay=2.0):
        self.running = True
        self._start_workers()
        print(f"[Sensor:{self.name}] Agent mode: {csv_path}")
        try:
            import pandas as pd
            df = pd.read_csv(csv_path, low_memory=False)
            df.columns = df.columns.str.strip()
            if 'Label' in df.columns:
                attack_df = df[~df['Label'].str.contains('BENIGN', na=False)].sample(min(200, len(df)))
            else:
                attack_df = df.sample(100)
        except Exception as e:
            print(f"[!] Error loading CSV: {e}")
            return

        for _, row in attack_df.iterrows():
            if not self.running:
                break
            raw_label = str(row.get('Label', '')).strip()
            attack_type = 'Unknown'
            for key, val in LABEL_TO_TYPE.items():
                if key in raw_label.lower():
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
                "msg": f"{attack_type} traffic detected by sensor {self.name}",
                "sid": 0,
                "priority": 1,
                "source": "snort3_sensor",
            }
            self.send_alert(alert)
            print(f"  [{attack_type:12s}] -> {alert['src_ip']}:{alert['src_port']}")
            time.sleep(delay)

    # ── PCAP Mode ──────────────────────────────────────────────────────
    def start_pcap_analysis(self, pcap_path, snort_config=None):
        self.running = True
        self._start_workers()
        print(f"[Sensor:{self.name}] Analyzing PCAP: {pcap_path}")
        pcap = Path(pcap_path)
        if not pcap.exists():
            print(f"[!] PCAP not found: {pcap_path}")
            return
        print("[!] PCAP mode requires Snort3 installed on this machine.")
        print("    Run with --watch to read Snort3 output instead.")
        time.sleep(2)

    # ── Lifecycle ──────────────────────────────────────────────────────
    def _start_workers(self):
        self._queue_worker = threading.Thread(target=self._queue_loop, daemon=True)
        self._queue_worker.start()
        self._hb_worker = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._hb_worker.start()

    def stop(self):
        self.running = False
        print(f"\n[Sensor:{self.name}] Stopping...")
        print(f"  Sent: {self._stats['sent']}, Failed: {self._stats['failed']}, Queued: {len(self._send_queue)}")


def main():
    parser = argparse.ArgumentParser(description="Snort3 Remote Sensor")
    parser.add_argument("--server", default="http://127.0.0.1:5000", help="Central IDS server URL")
    parser.add_argument("--id", dest="sensor_id", help="Sensor ID (auto-generated if omitted)")
    parser.add_argument("--name", default=None, help="Human-readable sensor name")
    parser.add_argument("--watch", metavar="FILE", help="Watch Snort3 alert.json file")
    parser.add_argument("--agent", metavar="CSV", help="Agent mode from CSV data")
    parser.add_argument("--pcap", metavar="PCAP", help="Analyze PCAP file")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between alerts (agent mode)")
    parser.add_argument("--type", dest="alert_type", help="Filter: DDoS, DoS, PortScan, etc.")
    args = parser.parse_args()

    sensor = RemoteSensor(
        server_url=args.server,
        sensor_id=args.sensor_id,
        name=args.name or f"{socket.gethostname()}-{uuid.uuid4().hex[:4]}",
    )

    print("=" * 50)
    print(f"  Snort3 Remote Sensor")
    print(f"  Name:   {sensor.name}")
    print(f"  ID:     {sensor.sensor_id}")
    print(f"  Host:   {sensor.hostname}")
    print(f"  Server: {args.server}")
    print("=" * 50)

    try:
        if args.watch:
            sensor.start_watch(args.watch, args.alert_type)
        elif args.agent:
            sensor.start_agent(args.agent, args.delay)
        elif args.pcap:
            sensor.start_pcap_analysis(args.pcap)
        else:
            parser.print_help()
            print("\n[!] Use --agent with a CSV file to test, or --watch with Snort3 alert.json")
    except KeyboardInterrupt:
        sensor.stop()
    except Exception as e:
        print(f"[!] Error: {e}")
        sensor.stop()


if __name__ == "__main__":
    main()
