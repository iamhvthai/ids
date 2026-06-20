"""
Live Network Agent — captures real-time traffic from the target machine
and sends network flow features to the central IDS server for ML prediction.

Usage:
  python live_agent.py                           # localhost
  python live_agent.py --server http://192.168.1.100:5000
  python live_agent.py --interval 3.0 --interface "Wi-Fi"
"""
import sys
import os

# Prevent console encoding crashes on Windows
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(errors='replace')
    except Exception:
        pass
import time
import json
import socket
import platform
import argparse
import subprocess
import threading
import base64
import requests
from datetime import datetime

SERVER_URL = "http://127.0.0.1:5000"
MONITOR_ENDPOINT = "/api/monitor"
HEARTBEAT_ENDPOINT = "/api/agents/heartbeat"
SCREEN_ENDPOINT = "/api/agents/screen"
INTERVAL = 2.0  # seconds between samples
SYSTEM = platform.system().lower()
FEATURE_METADATA = {}
FEATURE_METADATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "feature_metadata.json")
if os.path.exists(FEATURE_METADATA_PATH):
    try:
        with open(FEATURE_METADATA_PATH) as _f:
            FEATURE_METADATA = json.load(_f)
    except Exception:
        FEATURE_METADATA = {}

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import mss
    import mss.tools
    HAS_MSS = True
except ImportError:
    HAS_MSS = False

# Feature defaults; aligned dynamically with feature_metadata.json when available.
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
        self.agent_id = f"agent-{self.hostname}-{os.getpid()}"
        self.running = False

        # Previous sample counters for delta calculation
        self._prev = {"bytes": 0, "packets": 0, "time": 0}
        self._stats = {"sent": 0, "failed": 0}
        self._heartbeat_count = 0
        self.feature_metadata = FEATURE_METADATA
        self.feature_names = self.feature_metadata.get("feature_names") or list(FEATURE_DEFAULTS.keys())
        self.binary_features = set(self.feature_metadata.get("binary_features", [])) or {
            f for f in self.feature_names if f.startswith("is_") or f == "port_mod_1000"
        }

    def _detect_interface(self):
        if SYSTEM == "windows":
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-NetAdapter -Physical | Where-Object Status -eq 'Up').Name"],
                capture_output=True, text=True
            )
            interfaces = [i.strip() for i in result.stdout.strip().split("\n") if i.strip()]
            return interfaces[0] if interfaces else "WiFi"
        return "eth0"

    def _get_interface_stats(self):
        """Get bytes/packets from the active interface."""
        if SYSTEM == "windows":
            try:
                cmd = (
                    f'(Get-NetAdapterStatistics -Name "{self.interface}" '
                    f'| Select-Object ReceivedBytes, SentBytes, '
                    f'ReceivedPackets, SentPackets, '
                    f'ReceivedUnicastPackets, ReceivedMulticastPackets, ReceivedBroadcastPackets, '
                    f'SentUnicastPackets, SentMulticastPackets, SentBroadcastPackets '
                    f'| ConvertTo-Json)'
                )
                result = subprocess.run(
                    ["powershell", "-Command", cmd],
                    capture_output=True, text=True, timeout=5
                )
                data = json.loads(result.stdout)
                
                def safe_get(key):
                    val = data.get(key)
                    return int(val) if val is not None else 0

                total_bytes = safe_get("ReceivedBytes") + safe_get("SentBytes")
                
                rx_pkts = safe_get("ReceivedPackets")
                if rx_pkts == 0:
                    rx_pkts = safe_get("ReceivedUnicastPackets") + safe_get("ReceivedMulticastPackets") + safe_get("ReceivedBroadcastPackets")
                
                tx_pkts = safe_get("SentPackets")
                if tx_pkts == 0:
                    tx_pkts = safe_get("SentUnicastPackets") + safe_get("SentMulticastPackets") + safe_get("SentBroadcastPackets")
                    
                total_packets = rx_pkts + tx_pkts
                return total_bytes, total_packets
            except Exception as e:
                if not hasattr(self, "_stats_error_logged"):
                    print(f"\n⚠️  [WARN] Failed to get stats for interface '{self.interface}': {e}")
                    self._stats_error_logged = True
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

    def _get_system_info(self):
        info = {
            "hostname": self.hostname,
            "os": f"{platform.system()} {platform.release()}",
            "cpu": 0,
            "memory": 0,
            "disk": 0,
            "uptime": 0,
            "processes": [],
            "connections": [],
        }
        if HAS_PSUTIL:
            try:
                info["cpu"] = round(psutil.cpu_percent(interval=0.5), 1)
                mem = psutil.virtual_memory()
                info["memory"] = round(mem.percent, 1)
                dsk = psutil.disk_usage("/")
                info["disk"] = round(dsk.percent, 1)
                info["uptime"] = int(time.time() - psutil.boot_time())
                proc_list = []
                for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                    try:
                        proc_list.append(p.info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                info["processes"] = sorted(proc_list, key=lambda x: x.get("cpu_percent", 0), reverse=True)[:20]
            except Exception:
                pass

        try:
            tcp = self._get_tcp_connections()
            info["connections"] = [
                {"total": tcp["total"], "established": tcp["established"],
                 "syn_sent": tcp["syn_sent"], "ports": tcp["ports"][:50]}
            ]
        except Exception:
            pass

        return info

    def _capture_screen(self):
        if not HAS_MSS:
            return None
        try:
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                sct_img = sct.grab(monitor)
                png = mss.tools.to_png(sct_img.rgb, sct_img.size)
                b64 = base64.b64encode(png).decode("utf-8")
                return b64
        except Exception:
            return None

    def send_heartbeat(self):
        info = self._get_system_info()
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "os": info["os"],
            "cpu": info["cpu"],
            "memory": info["memory"],
            "disk": info["disk"],
            "uptime": info["uptime"],
            "processes": info["processes"],
            "connections": info["connections"],
            "timestamp": datetime.now().isoformat(),
            "source": "live_agent",
        }
        try:
            res = requests.post(
                f"{self.server_url}{HEARTBEAT_ENDPOINT}",
                json=payload, timeout=5
            )
            if res.status_code == 200:
                self._heartbeat_count += 1
                print(f"[HB] Heartbeat #{self._heartbeat_count} — CPU:{info['cpu']}% MEM:{info['memory']}%")
        except Exception:
            pass

    def send_screenshot(self):
        b64 = self._capture_screen()
        if not b64:
            return
        payload = {
            "agent_id": self.agent_id,
            "image": b64,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            requests.post(
                f"{self.server_url}{SCREEN_ENDPOINT}",
                json=payload, timeout=10
            )
            print(f"[SCR] Screenshot sent")
        except Exception:
            pass

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

        # Send initial heartbeat
        self.send_heartbeat()
        heartbeat_interval = max(self.interval * 5, 15)
        screen_interval = max(self.interval * 15, 60)
        last_hb = time.time()
        last_scr = time.time()

        while self.running:
            self.send_sample()

            now = time.time()
            if now - last_hb >= heartbeat_interval:
                self.send_heartbeat()
                last_hb = now
            if now - last_scr >= screen_interval:
                t = threading.Thread(target=self.send_screenshot, daemon=True)
                t.start()
                last_scr = now

            time.sleep(self.interval)

    def register_email(self, email):
        """Register email with server to receive anomaly alerts."""
        try:
            res = requests.post(
                f"{self.server_url}/api/register-email",
                json={"email": email, "hostname": self.hostname, "agent_id": self.agent_id},
                timeout=5
            )
            if res.status_code == 200:
                print(f"  Email registered: {email}")
                return True
            else:
                print(f"  Email registration failed: {res.text}")
                return False
        except Exception as e:
            print(f"  Email registration error: {e}")
            return False

    def stop(self):
        self.running = False
        print(f"\nStopped. Sent: {self._stats['sent']}, Failed: {self._stats['failed']}")


def main():
    parser = argparse.ArgumentParser(description="Live Network Agent for IDS")
    parser.add_argument("--server", default="http://127.0.0.1:5000", help="IDS server URL")
    parser.add_argument("--interface", help="Network interface name")
    parser.add_argument("--interval", type=float, default=2.0, help="Sampling interval (seconds)")
    parser.add_argument("--email", help="Email address for alert notifications")
    args = parser.parse_args()

    email = args.email
    if not email:
        inp = input("Enter email for alerts (or press Enter to skip): ").strip()
        if inp:
            email = inp

    agent = LiveAgent(args.server, args.interface, args.interval)
    print("=" * 50)
    print("  Live Network Agent")
    print("  Real-time traffic capture for ML prediction")
    print("=" * 50)

    if email:
        agent.register_email(email)

    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
