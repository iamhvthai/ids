"""
Flask Web Application — Intrusion Detection System Dashboard
Routes:
  GET  /              → Dashboard (index.html)
  GET  /api/results   → JSON kết quả so sánh model
  POST /api/predict   → Dự đoán từ input thủ công
  GET  /api/status    → Kiểm tra trạng thái model
"""

import os
import json
import numpy as np
import joblib
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.path.join(BASE_DIR, "models")

app = Flask(__name__)
# Khởi tạo SocketIO, cho phép CORS từ mọi nguồn (dễ test)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# ── Load models & scaler khi khởi động ──────────────────────────────────────
def load_models():
    models  = {}
    scaler  = None
    results = []
    fe_names = []

    try:
        scaler   = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
        fe_names = joblib.load(os.path.join(MODEL_DIR, "feature_names.pkl"))

        for name, fname in [
            ("KNN",           "knn.pkl"),
            ("Random Forest", "random_forest.pkl"),
            ("SVM (Linear)",  "svm_linear.pkl"),
        ]:
            path = os.path.join(MODEL_DIR, fname)
            if os.path.exists(path):
                models[name] = joblib.load(path)

        rpath = os.path.join(MODEL_DIR, "results.json")
        if os.path.exists(rpath):
            with open(rpath) as f:
                results = json.load(f)

    except Exception as e:
        print(f"[WARN] Could not load models: {e}")

    return models, scaler, results, fe_names


MODELS, SCALER, RESULTS, FEATURE_NAMES = load_models()

# Load label map dynamically from label_encoder
try:
    _le = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
    LABEL_MAP = {i: name for i, name in enumerate(_le.classes_)}
except Exception:
    LABEL_MAP = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L", 4: "U2R"}

# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/results")
def api_results():
    if not RESULTS:
        return jsonify({"error": "Models not trained yet. Run src/train.py first."}), 503
    return jsonify(RESULTS)


@app.route("/api/status")
def api_status():
    return jsonify({
        "models_loaded" : list(MODELS.keys()),
        "scaler_loaded" : SCALER is not None,
        "results_ready" : len(RESULTS) > 0,
        "feature_count" : len(FEATURE_NAMES),
    })


@app.route("/api/predict", methods=["POST"])
def api_predict():
    if SCALER is None or not MODELS:
        return jsonify({"error": "Models not loaded. Please train first."}), 503

    data = request.get_json(force=True)
    selected = data.get("model", "Random Forest")
    features = data.get("features", {})

    # Xây dựng vector feature theo đúng thứ tự
    try:
        vec = np.array([[float(features.get(f, 0)) for f in FEATURE_NAMES]])
        vec_scaled = SCALER.transform(vec)
    except Exception as e:
        return jsonify({"error": f"Feature error: {str(e)}"}), 400

    results = {}
    for name, model in MODELS.items():
        pred = model.predict(vec_scaled)[0]
        label = LABEL_MAP.get(int(pred), "Unknown")
        # Lấy probability nếu có
        prob = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(vec_scaled)[0]
            prob  = round(float(max(proba)) * 100, 2)
        results[name] = {"label": label, "confidence": prob}

    # Kết quả của model được chọn
    chosen = results.get(selected, list(results.values())[0] if results else {})
    return jsonify({
        "selected_model" : selected,
        "prediction"     : chosen.get("label"),
        "confidence"     : chosen.get("confidence"),
        "all_results"    : results,
    })


@app.route("/api/monitor", methods=["POST"])
def api_monitor():
    """
    Endpoint dành cho agent.py gửi data lên liên tục.
    """
    if SCALER is None or "Random Forest" not in MODELS:
        return jsonify({"error": "Models not loaded."}), 503

    data = request.get_json(force=True)
    features = data.get("features", {})
    source_ip = request.remote_addr # IP của máy đích gửi đến

    try:
        vec = np.array([[float(features.get(f, 0)) for f in FEATURE_NAMES]])
        vec_scaled = SCALER.transform(vec)
        
        # Dùng Random Forest làm model chính để realtime monitoring (vì độ chính xác cao và nhanh)
        model = MODELS["Random Forest"]
        pred = model.predict(vec_scaled)[0]
        label = LABEL_MAP.get(int(pred), "Unknown")
        
        prob = 0
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(vec_scaled)[0]
            prob = round(float(max(proba)) * 100, 2)
        
        # Trả về kết quả phân tích
        result = {
            "source_ip": source_ip,
            "prediction": label,
            "confidence": prob,
            "timestamp": data.get("timestamp", "Now")
        }

        # NẾU PHÁT HIỆN BẤT THƯỜNG (!= BENIGN), GỬI QUA WEB SOCKET NGAY LẬP TỨC
        if label != "BENIGN":
            socketio.emit('new_alert', result)
        else:
            # Gửi traffic bình thường (tuỳ chọn, có thể bỏ để tránh spam web)
            socketio.emit('normal_traffic', result)

        return jsonify({"status": "success", "result": result})

    except Exception as e:
        print(f"Monitor error: {e}")
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    print("=" * 50)
    print("  IDS Web Dashboard (Real-time SocketIO)")
    print("  http://127.0.0.1:5000")
    print("=" * 50)
    if not MODELS:
        print("[WARN] No models found. Run 'python src/train.py' first!")
    
    # Dùng socketio.run thay vì app.run
    socketio.run(app, debug=True, port=5000, host='0.0.0.0')
