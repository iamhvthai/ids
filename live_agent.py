"""
Live Network Agent — captures real-time traffic from the target machine
and sends network flow features to the central IDS server for ML prediction.

Usage:
  python live_agent.py                           # localhost
  python live_agent.py --server http://192.168.1.100:5000
  python live_agent.py --interval 3.0 --interface "Wi-Fi"
"""
import os
import re
import time
import json
import socket
import struct
import platform
import argparse
import subprocess
import threading
import requests
from datetime import datetime

SERVER_URL = "http://127.0.0.1:5000"
MONITOR_ENDPOINT = "/api/monitor"
INTERVAL = 2.0  # seconds between samples
SYSTEM = platform.system().lower()

# All 40 features the model expects (matches feature_names.pkl exactly)
FEATURE_DEFAULTS = {
    "Destination Port_Raw": 0,
    "Subflow Fwd Bytes": 0,
    "is_http": 0,
    "Fwd Packet Length Max": 1500,
    "port_mod_1000": 0,
    "Average Packet Size": 500,
    "Init_Win_bytes_backward": 65535,
    "Total Length of Bwd Packets": 0,
    "Fwd Packet Length Mean": 500,
    "Destination Port": 0,
    "Packet Length Variance": 90000,
    "flow_byte_ratio": 1.0,
    "Bwd Packet Length Mean": 400,
    "Flow IAT Max": 0,
    "Bwd Header Length": 20,
    "Init_Win_bytes_forward": 65535,
    "Packet Length Std": 300,
    "Flow Duration": 2000000,
    "Bwd Packets/s": 0,
    "Flow IAT Std": 0,
    "Fwd IAT Std": 0,
    "Fwd Header Length.1": 20,
    "Fwd IAT Mean": 0,
    "flow_pkt_ratio": 1.0,
    "Flow Bytes/s": 0,
    "Flow Packets/s": 0,
    "Bwd IAT Max": 0,
    "Flow IAT Mean": 0,
    "min_seg_size_forward": 0,
    "act_data_pkt_fwd": 0,
    "Bwd IAT Std": 0,
    "Bwd IAT Mean": 0,
    "Bwd IAT Total": 0,
    "Bwd Packet Length Min": 0,
    "Bwd IAT Min": 0,
    "Active Mean": 0,
    "Fwd IAT Min": 0,
    "Min Packet Length": 40,
    "is_ftp": 0,
    "Active Max": 0,
}


class LiveAgent:
    def __init__(self, server_url, interface=None, interval=2.0):
        self.server_url = server_url.rstrip("/")
        self.interface = interface or self._detect_interface()
        self.interval = interval
        self.hostname = socket.gethostname()
        self.running = False

        # Previous sample counters for delta calculation
        self._prev = {"bytes": 0, "packets": 0, "time": 0}
        self._stats = {"sent": 0, "failed": 0}

    def _detect_interface(self):
        if SYSTEM == "windows":
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'}).Name"],
                capture_output=True, text=True
            )
            interfaces = result.stdout.strip().split("\n")
            return interfaces[0].strip() if interfaces[0].strip() else "Wi-Fi"
        return "eth0"

    def _get_interface_stats(self):
        """Get bytes/packets from the active interface."""
        if SYSTEM == "windows":
            try:
                cmd = (
                    f'(Get-NetAdapterStatistics -Name "{self.interface}" '
                    f'| Select-Object ReceivedBytes, SentBytes, ReceivedPackets, SentPackets '
                    f'| ConvertTo-Json)'
                )
                result = subprocess.run(
                    ["powershell", "-Command", cmd],
                    capture_output=True, text=True, timeout=5
                )
                data = json.loads(result.stdout)
                total_bytes = data.get("ReceivedBytes", 0) + data.get("SentBytes", 0)
                total_packets = data.get("ReceivedPackets", 0) + data.get("SentPackets", 0)
                return total_bytes, total_packets
            except Exception:
                return 0, 0
        elif SYSTEM == "linux":
            try:
                with open(f"/sys/class/net/{self.interface}/statistics/rx_bytes") as f:
                    rx_b = int(f.read().strip())
                with open(f"/sys/class/net/{self.interface}/statistics/tx_bytes") as f:
                    tx_b = int(f.read().strip())
                with open(f"/sys/class/net/{self.interface}/statistics/rx_packets") as f:
                    rx_p = int(f.read().strip())
                with open(f"/sys/class/net/{self.interface}/statistics/tx_packets") as f:
                    tx_p = int(f.read().strip())
                return rx_b + tx_b, rx_p + tx_p
            except Exception:
                return 0, 0
        return 0, 0

    def _get_tcp_connections(self):
        """Get active TCP connections summary."""
        connections = {"total": 0, "established": 0, "syn_sent": 0, "ports": [], "flags": {"syn": 0, "ack": 0, "rst": 0}}
        if SYSTEM == "windows":
            try:
                result = subprocess.run(
                    ["netstat", "-n"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split("\n"):
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        state = parts[-1] if parts[-1] in ("ESTABLISHED", "SYN_SENT",
                                                           "TIME_WAIT", "CLOSE_WAIT", "LISTENING") else ""
                        if state == "ESTABLISHED":
                            connections["established"] += 1
                        if state == "SYN_SENT":
                            connections["syn_sent"] += 1
                            connections["flags"]["syn"] += 1
                        connections["total"] += 1
                        try:
                            addr = parts[1].rsplit(":", 1)
                            port = int(addr[1])
                            connections["ports"].append(port)
                        except (ValueError, IndexError):
                            pass
            except Exception:
                pass
        elif SYSTEM == "linux":
            try:
                with open("/proc/net/tcp") as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            state = int(parts[3], 16)
                            if state == 0x01:
                                connections["established"] += 1
                            connections["total"] += 1
                            addr = parts[1].split(":")
                            try:
                                connections["ports"].append(int(addr[1], 16))
                            except (ValueError, IndexError):
                                pass
            except Exception:
                pass
        return connections

    def _build_features(self):
        """Build feature vector from live network measurements."""
        now = time.time()
        total_bytes, total_packets = self._get_interface_stats()
        tcp = self._get_tcp_connections()

        # Calculate rates since last sample
        db = 0
        dp = 0
        if self._prev["time"] > 0:
            dt = now - self._prev["time"]
            db = max(0, total_bytes - self._prev["bytes"])
            dp = max(0, total_packets - self._prev["packets"])

            # Skip first sample (no delta)
            if dt > 0 and dp > 0:
                bytes_per_sec = db / dt
                pkts_per_sec = dp / dt
            else:
                bytes_per_sec = 0
                pkts_per_sec = 0
        else:
            bytes_per_sec = 0
            pkts_per_sec = 0

        # Derive port from actual connections
        dst_port = 0
        if tcp["ports"]:
            dst_port = max(set(tcp["ports"]), key=tcp["ports"].count)

        # Average packet size
        avg_pkt_size = bytes_per_sec / max(pkts_per_sec, 0.01)

        features = dict(FEATURE_DEFAULTS)
        total_fwd_pkts = int(dp / 2) if dp else 0
        total_bwd_pkts = int(dp / 2) if dp else 0
        total_fwd_bytes = int(db / 2) if db else 0
        total_bwd_bytes = int(db / 2) if db else 0
        fwd_pkts_s = round(pkts_per_sec / 2, 2)
        bwd_pkts_s = round(pkts_per_sec / 2, 2)

        features.update({
            "Destination Port": dst_port,
            "Destination Port_Raw": dst_port,
            "Flow Duration": int(self.interval * 1_000_000),
            "Flow Bytes/s": round(bytes_per_sec, 2),
            "Flow Packets/s": round(pkts_per_sec, 2),
            "Average Packet Size": round(avg_pkt_size, 2),
            "Flow IAT Mean": round(1_000_000 / max(pkts_per_sec, 0.01), 2),
            "Total Length of Bwd Packets": total_bwd_bytes,
            "Fwd Packets/s": fwd_pkts_s,
            "Bwd Packets/s": bwd_pkts_s,
            "Init_Win_bytes_forward": 65535 if tcp["established"] > 5 else 0,
            "Init_Win_bytes_backward": 65535 if tcp["established"] > 5 else 0,
            "is_http": 1 if dst_port == 80 else 0,
            "is_ftp": 1 if dst_port == 21 else 0,
            "port_mod_1000": dst_port % 1000,
            "flow_byte_ratio": round(total_fwd_bytes / max(total_bwd_bytes, 1), 2),
            "flow_pkt_ratio": round(total_fwd_pkts / max(total_bwd_pkts, 1), 2),
            "Packet Length Variance": round(avg_pkt_size ** 2, 2),
            "Bwd Packet Length Min": round(avg_pkt_size * 0.5, 2),
        })

        self._prev = {"bytes": total_bytes, "packets": total_packets, "time": now}
        return features

    def send_sample(self):
        features = self._build_features()
        payload = {
            "timestamp": datetime.now().isoformat(),
            "features": features,
            "hostname": self.hostname,
            "interface": self.interface,
        }
        try:
            res = requests.post(
                f"{self.server_url}{MONITOR_ENDPOINT}",
                json=payload, timeout=5
            )
            if res.status_code == 200:
                data = res.json()
                self._stats["sent"] += 1
                if data.get("status") == "success":
                    pred = data["result"]["prediction"]
                    conf = data["result"]["confidence"]
                    icon = "🚨" if pred != "BENIGN" else "✅"
                    print(f"{icon} [{self._stats['sent']:04d}] {pred:12s} ({conf}%) "
                          f"| pkts/s:{features['Flow Packets/s']:>8.1f} "
                          f"| bytes/s:{features['Flow Bytes/s']:>10.1f}")
            else:
                self._stats["failed"] += 1
                print(f"⚠️  Server error: {res.status_code}")
        except requests.exceptions.ConnectionError:
            self._stats["failed"] += 1
            print(f"❌ Cannot reach server at {self.server_url}")
            time.sleep(5)
        except Exception as e:
            self._stats["failed"] += 1
            print(f"❌ Error: {e}")

    def run(self):
        self.running = True
        # Warm up — first sample establishes baseline
        self._get_interface_stats()
        self._get_tcp_connections()
        self._prev["time"] = time.time()

        print(f"  Host:      {self.hostname}")
        print(f"  Interface: {self.interface}")
        print(f"  Server:    {self.server_url}")
        print(f"  Interval:  {self.interval}s")
        print("─" * 50)

        while self.running:
            self.send_sample()
            time.sleep(self.interval)

    def stop(self):
        self.running = False
        print(f"\nStopped. Sent: {self._stats['sent']}, Failed: {self._stats['failed']}")


def main():
    parser = argparse.ArgumentParser(description="Live Network Agent for IDS")
    parser.add_argument("--server", default="http://127.0.0.1:5000", help="IDS server URL")
    parser.add_argument("--interface", help="Network interface name")
    parser.add_argument("--interval", type=float, default=2.0, help="Sampling interval (seconds)")
    args = parser.parse_args()

    agent = LiveAgent(args.server, args.interface, args.interval)
    print("=" * 50)
    print("  Live Network Agent")
    print("  Real-time traffic capture for ML prediction")
    print("=" * 50)

    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
