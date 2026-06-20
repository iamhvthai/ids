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
import time
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import numpy as np
import joblib
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from src.snort_bridge import bridge as snort_bridge

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.path.join(BASE_DIR, "models")

# ── Email alert configuration ─────────────────────────────────────────────────
# Priority: email_config.json > environment variables
SMTP_SERVER   = ""
SMTP_PORT     = 587
SMTP_USERNAME = ""
SMTP_PASSWORD = ""
SMTP_SENDER   = ""
SMTP_USE_TLS  = True

_config_path = os.path.join(BASE_DIR, "email_config.json")
if os.path.exists(_config_path):
    try:
        with open(_config_path) as _f:
            _cfg = json.load(_f)
        SMTP_SERVER   = _cfg.get("smtp_server", "")
        SMTP_PORT     = int(_cfg.get("smtp_port", 587))
        SMTP_USERNAME = _cfg.get("username", "")
        SMTP_PASSWORD = _cfg.get("password", "")
        SMTP_SENDER   = _cfg.get("sender", SMTP_USERNAME)
        SMTP_USE_TLS  = _cfg.get("use_tls", True)
    except Exception as _e:
        print(f"[EMAIL] Failed to load email_config.json: {_e}")

# Environment variables override file config
SMTP_SERVER   = os.environ.get("SMTP_SERVER", SMTP_SERVER)
SMTP_PORT     = int(os.environ.get("SMTP_PORT", SMTP_PORT))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", SMTP_USERNAME)
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", SMTP_PASSWORD)
SMTP_SENDER   = os.environ.get("SMTP_SENDER", SMTP_USERNAME)
SMTP_USE_TLS  = os.environ.get("SMTP_USE_TLS", str(SMTP_USE_TLS)).lower() == "true"

# Store registered emails: sensor_id -> email
REGISTERED_EMAILS = {}
# Rate limit: last email sent time per sensor and alert category
_LAST_EMAIL_TIME = {}
# Resource alert thresholds (percent)
CPU_ALERT_THRESHOLD = float(os.environ.get("CPU_ALERT_THRESHOLD", "85"))
MEMORY_ALERT_THRESHOLD = float(os.environ.get("MEMORY_ALERT_THRESHOLD", "85"))
DISK_ALERT_THRESHOLD = float(os.environ.get("DISK_ALERT_THRESHOLD", "90"))

app = Flask(__name__)
# Khởi tạo SocketIO, cho phép CORS từ mọi nguồn (dễ test)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

def _can_send_email(sensor_key, alert_type, cooldown_seconds=300):
    now = time.time()
    last_time = _LAST_EMAIL_TIME.get((sensor_key, alert_type), 0)
    if now - last_time < cooldown_seconds:
        return False
    _LAST_EMAIL_TIME[(sensor_key, alert_type)] = now
    return True


def _send_email(recipient_email, subject, body, sensor_key, alert_type, cooldown_seconds=300):
    if not SMTP_SERVER or not SMTP_USERNAME or not SMTP_PASSWORD:
        print("[EMAIL] SMTP not configured - set SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD env vars")
        return False

    if not _can_send_email(sensor_key, alert_type, cooldown_seconds):
        return False

    msg = MIMEMultipart()
    msg["From"] = SMTP_SENDER
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        if SMTP_USE_TLS:
            server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[EMAIL] Alert sent to {recipient_email} ({alert_type})")
        return True
    except Exception as e:
        print(f"[EMAIL] Failed to send ({alert_type}): {e}")
        return False


def send_email_alert(recipient_email, alert_data):
    """Send anomaly alert email to the registered recipient."""
    sensor_key = alert_data.get("source_ip") or alert_data.get("src_ip") or "unknown"
    subject = f"[IDS Alert] {alert_data.get('prediction', 'Anomaly')} detected on {alert_data.get('hostname', 'unknown')}"
    body = (
        f"🚨 INTRUSION DETECTION ALERT 🚨\n\n"
        f"Time:       {alert_data.get('timestamp', 'now')}\n"
        f"Host:       {alert_data.get('hostname', 'unknown')} ({alert_data.get('source_ip', 'unknown')})\n"
        f"Detection:  {alert_data.get('prediction', 'Unknown')}\n"
        f"Confidence: {alert_data.get('confidence', 'N/A')}%\n\n"
        f"This is an automated alert from your IDS system.\n"
    )
    return _send_email(recipient_email, subject, body, sensor_key, "anomaly")


def send_resource_alert(recipient_email, alert_data):
    sensor_key = alert_data.get("sensor_key") or alert_data.get("hostname") or "unknown"
    resource = alert_data.get("resource", "resource")
    value = alert_data.get("value", 0)
    threshold = alert_data.get("threshold", 0)
    subject = f"[IDS Alert] {resource.upper()} threshold exceeded on {alert_data.get('hostname', 'unknown')}"
    body = (
        f"⚠️ RESOURCE ALERT ⚠️\n\n"
        f"Time:       {alert_data.get('timestamp', 'now')}\n"
        f"Host:       {alert_data.get('hostname', 'unknown')} ({alert_data.get('source_ip', 'unknown')})\n"
        f"Resource:   {resource.upper()}\n"
        f"Value:      {value}%\n"
        f"Threshold:  {threshold}%\n\n"
        f"This is an automated resource alert from your IDS system.\n"
    )
    return _send_email(recipient_email, subject, body, sensor_key, f"resource:{resource}")


# ── Load models & scaler khi khởi động ──────────────────────────────────────
def load_models():
    models  = {}
    scaler  = None
    results = []
    fe_names = []
    pt = None          # power_transformer
    pre_pt_scaler = None  # MinMaxScaler trước power transform
    model_classes = {}

    try:
        scaler   = joblib.load(os.path.join(MODEL_DIR, "scaler_before_smote.pkl"))
        fe_names = joblib.load(os.path.join(MODEL_DIR, "feature_names.pkl"))

        for name, fname in [
            ("KNN",           "knn.pkl"),
            ("Random Forest", "random_forest.pkl"),
            ("SVM (Linear)",  "svm_linear.pkl"),
        ]:
            path = os.path.join(MODEL_DIR, fname)
            if os.path.exists(path):
                model = joblib.load(path)
                models[name] = model
                model_classes[name] = list(getattr(model, "classes_", []))

        rpath = os.path.join(MODEL_DIR, "results.json")
        if os.path.exists(rpath):
            with open(rpath) as f:
                results = json.load(f)

        pt_path = os.path.join(MODEL_DIR, "power_transformer.pkl")
        if os.path.exists(pt_path):
            pt = joblib.load(pt_path)
        pre_scaler_path = os.path.join(MODEL_DIR, "power_transformer_pre_scaler.pkl")
        if os.path.exists(pre_scaler_path):
            pre_pt_scaler = joblib.load(pre_scaler_path)

    except Exception as e:
        print(f"[WARN] Could not load models: {e}")

    return models, scaler, results, fe_names, pt, pre_pt_scaler, model_classes


MODELS, SCALER, RESULTS, FEATURE_NAMES, POWER_TRANSFORMER, PRE_PT_SCALER, MODEL_CLASSES = load_models()

# Load feature metadata if available (authoritative transform flags)
FEATURE_METADATA = {}
_metadata_path = os.path.join(MODEL_DIR, "feature_metadata.json")
if os.path.exists(_metadata_path):
    try:
        with open(_metadata_path) as _f:
            FEATURE_METADATA = json.load(_f)
    except Exception as _e:
        print(f"[WARN] Could not load feature_metadata.json: {_e}")

# Binary features (không áp dụng Power Transform)
def _get_binary_feature_names(names):
    return {f for f in names if f.startswith('is_') or f == 'port_mod_1000'}

BINARY_FEATURES = set(FEATURE_METADATA.get("binary_features", [])) or _get_binary_feature_names(FEATURE_NAMES)


def _preprocess_features(features_dict):
    """Apply full transform pipeline: PowerTransform → StandardScaler."""
    vec = np.array([[float(features_dict.get(f, 0)) for f in FEATURE_NAMES]], dtype=np.float64)

    if POWER_TRANSFORMER is not None and PRE_PT_SCALER is not None:
        continuous_idx = [i for i, f in enumerate(FEATURE_NAMES) if f not in BINARY_FEATURES]
        if continuous_idx:
            cont_vals = vec[:, continuous_idx]
            cont_scaled = PRE_PT_SCALER.transform(cont_vals)
            cont_transformed = POWER_TRANSFORMER.transform(cont_scaled)
            vec[:, continuous_idx] = cont_transformed

    return SCALER.transform(vec)

# Load label map dynamically from label_encoder
try:
    _le = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
    LABEL_MAP = {i: name for i, name in enumerate(_le.classes_)}
except Exception:
    LABEL_MAP = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L", 4: "U2R"}

# Load pre-SMOTE class weights (for threshold calibration)
_cw_path = os.path.join(MODEL_DIR, "class_weights.npy")
CLASS_WEIGHTS = np.load(_cw_path) if os.path.exists(_cw_path) else None
print(f"Class weights loaded: {CLASS_WEIGHTS is not None}")


def _ensemble_predict(vec_scaled):
    """Soft voting ensemble with class alignment across models."""
    aligned_probs = []
    for name, model in MODELS.items():
        if not hasattr(model, "predict_proba"):
            continue
        try:
            probs = model.predict_proba(vec_scaled)[0]
            model_classes = MODEL_CLASSES.get(name) or list(getattr(model, "classes_", []))
            if model_classes and len(model_classes) <= len(LABEL_MAP):
                aligned = np.zeros(len(LABEL_MAP), dtype=np.float64)
                for cls_idx, cls in enumerate(model_classes):
                    if 0 <= int(cls) < len(LABEL_MAP):
                        aligned[int(cls)] = probs[cls_idx]
                aligned_probs.append(aligned)
            else:
                aligned_probs.append(np.asarray(probs, dtype=np.float64))
        except Exception:
            pass

    if not aligned_probs:
        return None, None

    avg_probs = np.mean(aligned_probs, axis=0)
    if avg_probs.shape[0] != len(LABEL_MAP):
        return None, None

    calibrated_probs = avg_probs.copy()
    if CLASS_WEIGHTS is not None and len(CLASS_WEIGHTS) == len(avg_probs):
        calibrated_probs = calibrated_probs * CLASS_WEIGHTS

    pred_idx = int(np.argmax(calibrated_probs))
    label = LABEL_MAP.get(pred_idx, "Unknown")
    confidence = round(float(avg_probs[pred_idx]) * 100, 2)
    return label, confidence

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
        "ensemble_ready" : len(MODELS) >= 3,
        "class_weights_loaded" : CLASS_WEIGHTS is not None,
        "scaler_loaded" : SCALER is not None,
        "power_transform_ready" : POWER_TRANSFORMER is not None and PRE_PT_SCALER is not None,
        "results_ready" : len(RESULTS) > 0,
        "feature_count" : len(FEATURE_NAMES),
    })


@app.route("/api/register-email", methods=["POST"])
def api_register_email():
    """Register an email address to receive alerts from an agent."""
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip()
    hostname = data.get("hostname", "unknown")
    sensor_id = data.get("agent_id") or f"live-{request.remote_addr}"

    if not email or "@" not in email:
        return jsonify({"status": "error", "message": "Invalid email address"}), 400

    REGISTERED_EMAILS[sensor_id] = email
    print(f"[EMAIL] Registered {email} for sensor {sensor_id} ({hostname})")
    return jsonify({"status": "success", "message": "Email registered for alerts", "sensor_id": sensor_id})


@app.route("/api/predict", methods=["POST"])
def api_predict():
    if SCALER is None or not MODELS:
        return jsonify({"error": "Models not loaded. Please train first."}), 503

    data = request.get_json(force=True)
    selected = data.get("model", "Ensemble")
    features = data.get("features", {})

    try:
        vec_scaled = _preprocess_features(features)
    except Exception as e:
        return jsonify({"error": f"Feature error: {str(e)}"}), 400

    selected = selected if selected in MODELS or selected == "Ensemble" else "Ensemble"

    results = {}
    for name, model in MODELS.items():
        pred = model.predict(vec_scaled)[0]
        label = LABEL_MAP.get(int(pred), "Unknown")
        prob = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(vec_scaled)[0]
            prob  = round(float(max(proba)) * 100, 2)
        results[name] = {"label": label, "confidence": prob, "class_index": int(pred)}

    # Ensemble (soft voting + class-weight calibration)
    ensemble_label, ensemble_conf = _ensemble_predict(vec_scaled)
    if ensemble_label:
        results["Ensemble"] = {"label": ensemble_label, "confidence": ensemble_conf}

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
    if SCALER is None or not MODELS:
        return jsonify({"error": "Models not loaded."}), 503

    data = request.get_json(force=True)
    features = data.get("features", {})
    source_ip = request.remote_addr
    hostname = data.get("hostname", source_ip)
    sensor_id = data.get("agent_id") or f"live-{source_ip}"

    try:
        vec_scaled = _preprocess_features(features)

        label, prob = _ensemble_predict(vec_scaled)
        pred_idx = None
        if label is None:
            model = MODELS["Random Forest"]
            pred = model.predict(vec_scaled)[0]
            pred_idx = int(pred)
            label = LABEL_MAP.get(pred_idx, "Unknown")
            prob = 0
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(vec_scaled)[0]
                prob = round(float(max(proba)) * 100, 2)

        result = {
            "source_ip": source_ip,
            "src_ip": source_ip,
            "prediction": label,
            "confidence": prob,
            "class_index": pred_idx,
            "timestamp": data.get("timestamp", "Now"),
            "hostname": hostname,
            "source": "live_agent",
        }

        _update_sensor({
            "sensor_id": sensor_id,
            "sensor_name": hostname,
            "sensor_hostname": hostname,
            "timestamp": data.get("timestamp", time.time()),
            "type": "agent",
            "source": "live_agent",
        })

        _register_agent({
            "agent_id": sensor_id,
            "hostname": hostname,
            "source": "live_agent",
        })

        if label != "BENIGN":
            socketio.emit('new_alert', result)
            email = REGISTERED_EMAILS.get(sensor_id) or REGISTERED_EMAILS.get(f"live-{source_ip}")
            if email:
                threading.Thread(target=send_email_alert, args=(email, result), daemon=True).start()
        else:
            socketio.emit('normal_traffic', result)

        return jsonify({"status": "success", "result": result})

    except Exception as e:
        print(f"Monitor error: {e}")
        return jsonify({"error": str(e)}), 400


# ── Snort3 Routes ──────────────────────────────────────────────────────────────
SNORT_ALERTS = []       # In-memory alert store
SENSORS = {}            # sensor_id -> last heartbeat info


def _update_sensor(data):
    sid = data.get("sensor_id")
    if not sid:
        return
    SENSORS[sid] = {
        "sensor_id": sid,
        "name": data.get("sensor_name", sid),
        "hostname": data.get("sensor_hostname", "unknown"),
        "last_seen": time.time(),
        "last_alert": data.get("timestamp", time.time()),
        "type": data.get("type", "unknown"),
        "source": data.get("source", "unknown"),
    }

@app.route("/api/snort/status")
def snort_status():
    running, detail = snort_bridge.container_status()
    return jsonify({
        "running": running,
        "detail": detail,
        "alert_count": len(SNORT_ALERTS),
        "simulation": snort_bridge.simulation_mode,
    })

@app.route("/api/snort/start", methods=["POST"])
def snort_start():
    success, msg = snort_bridge.start_container()
    return jsonify({"success": success, "message": msg})

@app.route("/api/snort/stop", methods=["POST"])
def snort_stop():
    if snort_bridge.simulation_mode:
        snort_bridge.stop_simulation()
    success, msg = snort_bridge.stop_container()
    return jsonify({"success": success, "message": msg})

@app.route("/api/snort/alert", methods=["POST"])
def snort_alert():
    alert = request.get_json(force=True)
    alert["received_at"] = time.time()
    _update_sensor(alert)

    # Heartbeat-only alerts don't go to main alert list
    if alert.get("type") == "heartbeat":
        return jsonify({"status": "ok", "sensor_known": True})

    SNORT_ALERTS.insert(0, alert)
    if len(SNORT_ALERTS) > 500:
        SNORT_ALERTS.pop()
    socketio.emit("snort_alert", alert)
    return jsonify({"status": "ok"})

@app.route("/api/snort/alerts")
def snort_alerts():
    alert_type = request.args.get("type", "ALL")
    limit = int(request.args.get("limit", 50))
    if alert_type and alert_type != "ALL":
        filtered = [a for a in SNORT_ALERTS if a.get("type") == alert_type]
    else:
        filtered = SNORT_ALERTS
    return jsonify(filtered[:limit])

@app.route("/api/snort/simulate", methods=["POST"])
def snort_simulate():
    data = request.get_json(force=True) or {}
    csv_path = data.get("csv_path")
    success, msg = snort_bridge.start_simulation(csv_path=csv_path)
    return jsonify({"success": success, "message": msg})

@app.route("/api/snort/sensors")
def snort_sensors():
    now = time.time()
    active = []
    for sid, info in SENSORS.items():
        alive = (now - info["last_seen"]) < 60
        active.append({**info, "alive": alive})
    return jsonify(active)

@app.route("/api/snort/simulate/stop", methods=["POST"])
def snort_simulate_stop():
    success, msg = snort_bridge.stop_simulation()
    return jsonify({"success": success, "message": msg})


# ── Agent Monitoring ─────────────────────────────────────────────────────────
AGENTS = {}
AGENT_SCREENSHOTS = {}

def _register_agent(data):
    agent_id = data.get("agent_id", f"agent-{request.remote_addr}")
    now = time.time()
    if agent_id not in AGENTS:
        AGENTS[agent_id] = {
            "agent_id": agent_id,
            "ip": request.remote_addr,
            "hostname": data.get("hostname", "unknown"),
            "os": data.get("os", "unknown"),
            "first_seen": now,
            "last_seen": now,
            "cpu": data.get("cpu", 0),
            "memory": data.get("memory", 0),
            "disk": data.get("disk", 0),
            "uptime": data.get("uptime", 0),
            "connections": data.get("connections", []),
            "processes": data.get("processes", []),
            "source": data.get("source", "agent"),
            "alive": True,
        }
    else:
        AGENTS[agent_id].update({
            "last_seen": now,
            "ip": request.remote_addr,
            "hostname": data.get("hostname", AGENTS[agent_id]["hostname"]),
            "os": data.get("os", AGENTS[agent_id]["os"]),
            "cpu": data.get("cpu", AGENTS[agent_id].get("cpu", 0)),
            "memory": data.get("memory", AGENTS[agent_id].get("memory", 0)),
            "disk": data.get("disk", AGENTS[agent_id].get("disk", 0)),
            "uptime": data.get("uptime", AGENTS[agent_id].get("uptime", 0)),
            "connections": data.get("connections", AGENTS[agent_id].get("connections", [])),
            "processes": data.get("processes", AGENTS[agent_id].get("processes", [])),
            "alive": True,
        })
    socketio.emit("agent_update", {"agent_id": agent_id, **AGENTS[agent_id]})
    return agent_id


def _notify_resource_alerts(agent_payload):
    hostname = agent_payload.get("hostname", "unknown")
    source_ip = agent_payload.get("ip", "unknown")
    sensor_key = agent_payload.get("agent_id") or hostname or source_ip
    email = REGISTERED_EMAILS.get(sensor_key) or REGISTERED_EMAILS.get(f"live-{source_ip}")
    if not email:
        return

    timestamp = datetime.now().isoformat()
    checks = [
        ("cpu", agent_payload.get("cpu", 0), CPU_ALERT_THRESHOLD),
        ("memory", agent_payload.get("memory", 0), MEMORY_ALERT_THRESHOLD),
        ("disk", agent_payload.get("disk", 0), DISK_ALERT_THRESHOLD),
    ]
    for resource, value, threshold in checks:
        try:
            value_f = float(value)
        except (TypeError, ValueError):
            continue
        if value_f >= threshold:
            payload = {
                "sensor_key": sensor_key,
                "hostname": hostname,
                "source_ip": source_ip,
                "resource": resource,
                "value": round(value_f, 2),
                "threshold": threshold,
                "timestamp": timestamp,
            }
            threading.Thread(target=send_resource_alert, args=(email, payload), daemon=True).start()

@app.route("/api/agents/heartbeat", methods=["POST"])
def api_agent_heartbeat():
    data = request.get_json(force=True)
    agent_id = _register_agent(data)
    _notify_resource_alerts({"agent_id": agent_id, **data, "ip": request.remote_addr})
    return jsonify({"status": "ok", "agent_id": agent_id})

@app.route("/api/agents/screen", methods=["POST"])
def api_agent_screen():
    data = request.get_json(force=True)
    agent_id = data.get("agent_id")
    image_b64 = data.get("image")
    if agent_id and image_b64:
        AGENT_SCREENSHOTS[agent_id] = {
            "image": image_b64,
            "timestamp": time.time(),
        }
        socketio.emit("agent_screen_update", {"agent_id": agent_id, "timestamp": time.time()})
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "Missing agent_id or image"}), 400

@app.route("/api/agents")
def api_agents():
    now = time.time()
    result = []
    for aid, info in AGENTS.items():
        alive = (now - info["last_seen"]) < 120
        result.append({**info, "alive": alive})
    return jsonify(result)

@app.route("/api/agents/<agent_id>")
def api_agent_detail(agent_id):
    info = AGENTS.get(agent_id)
    if not info:
        return jsonify({"error": "Agent not found"}), 404
    now = time.time()
    alive = (now - info["last_seen"]) < 120
    return jsonify({**info, "alive": alive})

@app.route("/api/agents/<agent_id>/screen")
def api_agent_screen_get(agent_id):
    shot = AGENT_SCREENSHOTS.get(agent_id)
    if not shot:
        return jsonify({"error": "No screenshot available"}), 404
    return jsonify(shot)

@app.route("/api/agents/<agent_id>/connections")
def api_agent_connections(agent_id):
    info = AGENTS.get(agent_id)
    if not info:
        return jsonify({"error": "Agent not found"}), 404
    return jsonify({"connections": info.get("connections", []), "timestamp": info.get("last_seen")})

@app.route("/api/agents/<agent_id>/info")
def api_agent_info(agent_id):
    info = AGENTS.get(agent_id)
    if not info:
        return jsonify({"error": "Agent not found"}), 404
    return jsonify({
        "hostname": info.get("hostname"),
        "ip": info.get("ip"),
        "os": info.get("os"),
        "cpu": info.get("cpu"),
        "memory": info.get("memory"),
        "disk": info.get("disk"),
        "uptime": info.get("uptime"),
        "processes": info.get("processes", []),
        "first_seen": info.get("first_seen"),
        "last_seen": info.get("last_seen"),
        "source": info.get("source"),
    })


if __name__ == "__main__":
    print("=" * 50)
    print("  IDS Web Dashboard (Real-time SocketIO)")
    print("  http://127.0.0.1:5000")
    print("  Snort3 Integration Active")
    print("=" * 50)
    if not MODELS:
        print("[WARN] No models found. Run 'python src/train.py' first!")
    
    # Dùng socketio.run thay vì app.run
    socketio.run(app, debug=True, port=5000, host='0.0.0.0')
