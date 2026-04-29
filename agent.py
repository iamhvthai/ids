import time
import json
import random
import requests
import pandas as pd
from datetime import datetime

# ============================================================
# CẤU HÌNH AGENT
# ============================================================
SERVER_URL = "http://127.0.0.1:5000/api/monitor"
DATA_FILE  = "data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" # File dùng để mô phỏng
DELAY_SECONDS = 0.5 # Tốc độ gửi (giây/luồng)

print("=" * 50)
print("  🛡️ IDS Agent - Real-time Traffic Monitor")
print(f"  Target Server: {SERVER_URL}")
print("=" * 50)

# 1. Đọc file CSV
try:
    print(f"[1] Loading dataset for simulation: {DATA_FILE}...")
    df = pd.read_csv(DATA_FILE, low_memory=False)
    df.columns = df.columns.str.strip()
    
    # Lấy ra vài dòng Normal và vài dòng Attack để demo có kết quả đa dạng
    normal_df = df[df['Label'].str.contains('BENIGN', na=False)].sample(50)
    attack_df = df[~df['Label'].str.contains('BENIGN', na=False)].sample(50)
    
    # Trộn lại và xáo trộn
    demo_df = pd.concat([normal_df, attack_df]).sample(frac=1).reset_index(drop=True)
    print(f"    -> Loaded {len(demo_df)} mixed flows (Normal & Attack) for simulation.")
except Exception as e:
    print(f"[!] Error loading data: {e}")
    exit(1)

# 2. Vòng lặp gửi dữ liệu liên tục
print("[2] Starting Real-time monitoring simulation...\n")

for index, row in demo_df.iterrows():
    # Trích xuất toàn bộ feature của luồng mạng này
    features = {col: float(val) for col, val in row.items() if col != 'Label' and pd.notna(val) and not isinstance(val, str)}
    
    payload = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "features": features
    }

    try:
        # Gửi dữ liệu tới Máy chủ IDS
        res = requests.post(SERVER_URL, json=payload, timeout=2)
        
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                result = data["result"]
                pred = result["prediction"]
                conf = result["confidence"]
                
                # Hiển thị log trên console của máy đích
                if pred != "BENIGN":
                    print(f"🚨 [ALERT] Sent Flow {index+1:02d} -> Server detected: {pred} ({conf}%)")
                else:
                    print(f"✅ [ OK  ] Sent Flow {index+1:02d} -> Server detected: {pred}")
        else:
            print(f"⚠️ [WARN] Server returned status {res.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ [ERROR] Could not connect to server. Is Flask app running?")
        break
    except Exception as e:
        print(f"❌ [ERROR] {e}")

    # Chờ trước khi gửi gói tiếp theo (mô phỏng real-time)
    time.sleep(DELAY_SECONDS)

print("\n🎉 Simulation finished.")
