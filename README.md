# IDS — Intrusion Detection System

Hệ thống phát hiện xâm nhập mạng kết hợp **Machine Learning (Random Forest)** và **Snort3 (Signature-based)** với dashboard real-time.

## Kiến trúc tổng thể

```
┌─── MÁY CHỦ (SERVER) ───────────────────────────────────────────────────────┐
│                                                                             │
│  app.py ── Flask + Socket.IO ── Dashboard (http://0.0.0.0:5000)            │
│    ├── POST /api/monitor      ← nhận features từ máy đích, predict ML       │
│    ├── POST /api/snort/alert  ← nhận alert từ Snort3 sensor                │
│    ├── POST /api/predict      ← dự đoán thủ công                           │
│    ├── GET  /api/snort/sensors← danh sách sensor đang kết nối              │
│    └── Socket.IO              ← đẩy alert real-time xuống dashboard         │
│                                                                             │
│  models/ ── random_forest.pkl ── scaler.pkl ── feature_names.pkl            │
│                                                                             │
│  Snort3 (Docker) ── optional, chạy cùng server để phân tích PCAP           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─── MÁY ĐÍCH (TARGET 1) ────────────────────────────────────────────────────┐
│                                                                             │
│  live_agent.py ── Mỗi 2s:                                                  │
│    ├── Capture interface bytes/s, packets/s                                │
│    ├── netstat: TCP connections, SYN/ACK/RST flags                         │
│    ├── Build 40 features → POST /api/monitor                               │
│    └── Random Forest predict → alert nếu phát hiện tấn công                │
│                                                                             │
│  snort_sensor.py ── (nếu có cài Snort3)                                    │
│    └── Watch alert.json → POST /api/snort/alert                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─── MÁY ĐÍCH (TARGET 2, 3, ...) ────────────────────────────────────────────┐
│  Tương tự target 1, mỗi máy gửi về cùng server                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Yêu cầu

### Máy chủ
- **Python 3.10+**
- **Docker Desktop** (nếu dùng Snort3)
- **pip packages:** flask, flask-socketio, eventlet, numpy, joblib, requests, pandas

### Máy đích
- **Python 3.10+**
- **pip packages:** requests, pandas
- (Không cần Docker, không cần model ML — chỉ gửi dữ liệu về server)

---

## 1. Cài đặt máy chủ (Server)

### Bước 1: Cài dependencies

```bash
cd dacn1_ids
pip install -r requirements.txt
```

Nếu chưa có `requirements.txt`:

```bash
pip install flask flask-socketio eventlet numpy joblib requests pandas
```

### Bước 2: Train model (nếu chưa có)

```bash
python src/train.py
```

### Bước 3: Chạy server

```bash
python app.py
```

Server chạy tại **http://0.0.0.0:5000**

### Bước 4: (Optional) Chạy Snort3

```bash
cd snort3
docker-compose up -d
```

---

## 2. Cài đặt máy đích (Target)

### Bước 1: Copy file agent

Copy `live_agent.py` và `snort_sensor.py` sang máy đích.

> Chỉ cần 2 file này + thư viện requests. Không cần toàn bộ project.

### Bước 2: Cài dependencies

```bash
pip install requests pandas
```

### Bước 3: Chạy live agent

```bash
# Cơ bản — kết nối tới server
python live_agent.py --server http://192.168.1.100:5000

# Tùy chỉnh interval (mặc định 2s)
python live_agent.py --server http://192.168.1.100:5000 --interval 3

# Chỉ định interface (mặc định tự động detect)
python live_agent.py --server http://192.168.1.100:5000 --interface "Ethernet"
```

> **Lưu ý firewall:** Mở port 5000 trên máy chủ để máy đích có thể gửi dữ liệu về.

### Bước 4: (Optional) Chạy Snort3 sensor

Nếu máy đích có cài Snort3:

```bash
# Watch mode — theo dõi alert.json và forward về server
python snort_sensor.py --server http://192.168.1.100:5000 --watch /var/log/snort/alert.json

# Agent mode — giả lập từ CSV (nếu không có Snort3)
python snort_sensor.py --server http://192.168.1.100:5000 --agent sample.csv
```

---

## 3. Dashboard

Mở trình duyệt: **http://<server_ip>:5000**

### Các section trên dashboard:

| Section | Hiển thị |
|---------|----------|
| **Dataset Overview** | Thông tin dataset |
| **Model Comparison** | Accuracy, F1 của KNN / RF / SVM |
| **Performance Charts** | Biểu đồ so sánh |
| **Real-time Monitoring** | ML predictions từ máy đích (LIVE badge + hostname) |
| **Snort3 IDS Alerts** | Snort3 alerts + filter theo loại tấn công |
| **Live Prediction** | Dự đoán thủ công |
| **Sensor Grid** | Danh sách sensor đang kết nối + trạng thái alive/dead |

---

## 4. Các tùy chọn nâng cao

### Thêm nhiều máy đích

```bash
# Trên mỗi máy đích, chạy live_agent trỏ về cùng server
python live_agent.py --server http://<SERVER_IP>:5000
```

### Chạy Snort3 cùng server để phân tích PCAP

```bash
cd snort3
docker-compose up -d        # Start Snort3 monitoring

# Copy PCAP vào thư mục pcap/
# Snort3 sẽ tự động phân tích và ghi alert vào logs/alert.json
```

### Test với dữ liệu mẫu (không cần máy đích thật)

```bash
# Giả lập ML prediction từ CSV
python agent.py

# Giả lập Snort3 alerts
python snort_agent.py
```

---

## 5. File cấu hình chính

| File | Mục đích |
|------|----------|
| `app.py` | Flask server + WebSocket + API endpoints |
| `live_agent.py` | Thu thập network real-time từ máy đích, gửi về server |
| `snort_sensor.py` | Remote sensor, watch/forward Snort3 alerts |
| `snort_agent.py` | Giả lập Snort3 alerts từ CSV |
| `agent.py` | Giả lập ML prediction từ CSV |
| `snort3/docker-compose.yml` | Docker Compose cho Snort3 |
| `snort3/config/local.rules` | 23 luật Snort3 cho DDoS, DoS, PortScan... |
| `snort3/config/snort.lua` | Snort3 config với JSON output |
| `src/snort_bridge.py` | Python bridge quản lý Snort3 container |

## 6. Troubleshooting

**Máy đích không kết nối được server:**
```bash
# Kiểm tra firewall trên server (Windows):
netsh advfirewall firewall add rule name="IDS Port 5000" dir=in action=allow protocol=TCP localport=5000

# Kiểm tra kết nối từ máy đích:
curl http://192.168.1.100:5000/api/status
```

**Live agent báo lỗi interface:**
```bash
# Liệt kê interface trên Windows:
powershell "Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} | Select-Object Name"

# Chạy với đúng tên interface:
python live_agent.py --interface "Wi-Fi"
```
